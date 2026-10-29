# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The environment a CI runner is launched in, and where the runner tests may run.

WHY THIS EXISTS
---------------
The runner tests run under ``uv run``, so their own environment has the test
virtualenv's ``bin`` first on PATH, and that ``bin`` holds an ``ash``: the editable one
of the checkout. act in host mode and Jenkins' ``sh`` steps pass their environment to
the pipeline's steps, so a pipeline that scans before it installs, or whose PATH line
is broken, would find that ``ash`` and pass. So
tests/integration/docs/ci_runners/env.py builds each runner's environment from nothing:
a fresh HOME, a fixed system PATH after the runner tools' directory, LANG, and only
what that runner needs (JAVA_HOME for Jenkinsfile Runner, ImageOS and ImageVersion for
the setup actions under act, one ASH_TOOL_DOWNLOAD_CACHE for the job). The runner is
started as ``env -i`` with exactly that. The CI side plants a second control: an
``ash`` first on the outer PATH that touches a sentinel file, which must never appear.

The runner tests are opt-in, behind the ``ci_runner`` marker and --run-ci-runners, and
refuse to run anywhere but a GitHub-hosted runner unless DOCTEST_CI_RUNNERS_ANYWHERE=1:
the CodeBuild agent and ``circleci local execute`` mount the Docker socket into a
container. With the flag given, any other host is an error, not a skip, so a run that
was meant to test the pipelines cannot pass by testing none.
"""

from __future__ import annotations

import ast
import ctypes
import errno
import importlib
import importlib.util
import os
import re
import subprocess
import sys
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_RUNNERS = REPO_ROOT / "tests" / "integration" / "docs" / "ci_runners"
PACKAGE = "_ash_ci_runners"
LEG_RUNNERS = (
    "act",
    "gitlab-ci-local",
    "jenkinsfile-runner-lts",
    "jenkinsfile-runner-bundled",
    "codebuild-agent",
    "circleci",
)
ALLOWED_KEYS = frozenset(
    {
        "HOME",
        "PATH",
        "LANG",
        "JAVA_HOME",
        "ImageOS",
        "ImageVersion",
        "ASH_TOOL_DOWNLOAD_CACHE",
    }
)
#: What the outer environment of a test run holds that must not reach a pipeline.
POISON = {
    "VIRTUAL_ENV": "/work/repo/.venv",
    "UV_CACHE_DIR": "/home/runner/.cache/uv",
    "UV_TOOL_DIR": "/home/runner/.local/share/uv/tools",
    "UV_TOOL_BIN_DIR": "/home/runner/.local/bin",
    "PYTHONPATH": "/work/repo",
    "GITHUB_PATH": "/home/runner/work/_temp/_runner_file_commands/add_path",
    "GITHUB_TOKEN": "s",
}
OUTER = {
    **POISON,
    "PATH": "/work/repo/.venv/bin:/home/runner/.local/bin:/opt/poison/bin:/usr/bin:/bin",
    "HOME": "/home/runner",
    "LANG": "C.UTF-8",
    "ImageOS": "ubuntu24",
    "ImageVersion": "20261005.1.0",
    "JAVA_HOME": "/usr/lib/jvm/temurin-17-jdk-amd64",
    "JAVA_HOME_11_X64": "/usr/lib/jvm/temurin-11-jdk-amd64",
    "JAVA_HOME_21_X64": "/usr/lib/jvm/temurin-21-jdk-amd64",
    "GITHUB_ACTIONS": "true",
    "RUNNER_ENVIRONMENT": "github-hosted",
}


def _module(stem: str):
    if PACKAGE not in sys.modules:
        init = CI_RUNNERS / "__init__.py"
        if not init.is_file():
            pytest.fail("missing tests/integration/docs/ci_runners/__init__.py")
        spec = importlib.util.spec_from_file_location(
            PACKAGE, init, submodule_search_locations=[str(CI_RUNNERS)]
        )
        assert spec and spec.loader
        package = importlib.util.module_from_spec(spec)
        sys.modules[PACKAGE] = package
        spec.loader.exec_module(package)
    if not (CI_RUNNERS / f"{stem}.py").is_file():
        pytest.fail(f"missing tests/integration/docs/ci_runners/{stem}.py")
    return importlib.import_module(f"{PACKAGE}.{stem}")


def _api(stem: str, name: str):
    module = _module(stem)
    if not hasattr(module, name):
        pytest.fail(f"tests/integration/docs/ci_runners/{stem}.py defines no {name}")
    return getattr(module, name)


def _launch_env(tmp_path: Path, runner: str, java: str | None = None, outer=None):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return _api("env", "launch_env")(
        runner,
        home=home,
        runner_bin=tmp_path / "ci-runner-bin",
        tool_cache=tmp_path / "tool-cache",
        outer=OUTER if outer is None else outer,
        java=java,
    )


JAVA = {"jenkinsfile-runner-lts": "21", "jenkinsfile-runner-bundled": "11"}


@pytest.mark.unit
@pytest.mark.parametrize("runner", LEG_RUNNERS)
def test_the_launch_environment_is_built_from_nothing(tmp_path, runner):
    system_path = _api("env", "SYSTEM_PATH")
    env = _launch_env(tmp_path, runner, JAVA.get(runner))
    assert set(env) <= ALLOWED_KEYS, (
        f"keys no runner needs: {sorted(set(env) - ALLOWED_KEYS)}"
    )
    assert env["HOME"] == str(tmp_path / "home")
    assert env["PATH"] == f"{tmp_path / 'ci-runner-bin'}{os.pathsep}{system_path}"
    assert env["LANG"] == "C.UTF-8"
    assert env["ASH_TOOL_DOWNLOAD_CACHE"] == str(tmp_path / "tool-cache")
    for name, value in POISON.items():
        assert name not in env
        if len(value) > 3:
            assert all(value not in v for v in env.values()), f"{name}'s value got in"
    assert ".venv" not in env["PATH"] and "/opt/poison/bin" not in env["PATH"]


@pytest.mark.unit
def test_the_system_path_is_fixed_and_holds_no_virtualenv():
    system_path = _api("env", "SYSTEM_PATH")
    entries = system_path.split(os.pathsep)
    assert entries and all(entry.startswith("/") for entry in entries), system_path
    assert "/usr/bin" in entries and "/bin" in entries
    assert not any(".venv" in entry or "uv" in entry.split("/") for entry in entries)


@pytest.mark.unit
def test_act_gets_the_runner_image_variables_the_setup_actions_read(tmp_path):
    env = _launch_env(tmp_path, "act")
    assert env["ImageOS"] == OUTER["ImageOS"]
    assert env["ImageVersion"] == OUTER["ImageVersion"]
    assert "JAVA_HOME" not in env


@pytest.mark.unit
@pytest.mark.parametrize("runner,java", sorted(JAVA.items()))
def test_jenkinsfile_runner_gets_the_java_its_core_needs(tmp_path, runner, java):
    env = _launch_env(tmp_path, runner, java)
    assert env["JAVA_HOME"] == OUTER[f"JAVA_HOME_{java}_X64"]
    assert "ImageOS" not in env


@pytest.mark.unit
def test_a_missing_java_is_an_error_naming_the_variable(tmp_path):
    outer = {k: v for k, v in OUTER.items() if k != "JAVA_HOME_11_X64"}
    with pytest.raises(ValueError, match="JAVA_HOME_11_X64"):
        _launch_env(tmp_path, "jenkinsfile-runner-bundled", "11", outer)


@pytest.mark.unit
def test_home_must_be_fresh(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".ash").mkdir()
    with pytest.raises(ValueError, match="HOME"):
        _launch_env(tmp_path, "act")


@pytest.mark.unit
def test_the_runner_is_started_with_env_i_and_exactly_its_environment(tmp_path):
    launch_argv = _api("env", "launch_argv")
    env = _launch_env(tmp_path, "act")
    argv = launch_argv(env, ["act", "pull_request", "--json"])
    assert argv[:2] == ["env", "-i"]
    assert argv[-3:] == ["act", "pull_request", "--json"]
    assert sorted(argv[2:-3]) == sorted(f"{k}={v}" for k, v in env.items())


@pytest.mark.integration
@pytest.mark.skipif(
    sys.platform == "win32", reason="the runners run on Linux; env -i is POSIX"
)
def test_the_launched_process_sees_only_that_environment(tmp_path):
    """The argv, run: nothing of this test process's environment gets through."""
    launch_argv = _api("env", "launch_argv")
    env = _launch_env(tmp_path, "gitlab-ci-local")
    result = subprocess.run(
        launch_argv(env, ["/usr/bin/env"]),
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, **POISON},
    )
    seen = dict(
        line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
    )
    assert seen == env


def _refused_prctl(option, argument):
    raise OSError(errno.EINVAL, os.strerror(errno.EINVAL))


def _marking_runner(tmp_path: Path) -> tuple[Path, Path]:
    """A runner that leaves a file behind if it ever starts, and that file."""
    ran = tmp_path / "ran"
    runner = tmp_path / "runner"
    runner.write_text(f"#!/bin/sh\n: > '{ran}'\n", encoding="utf-8")
    runner.chmod(0o755)
    return runner, ran


def _launch_marking_runner(env, tmp_path: Path, runner: Path) -> int:
    return env.launch(
        {"PATH": "/usr/bin:/bin"},
        [str(runner)],
        cwd=tmp_path,
        log=tmp_path / "logs" / "runner.log",
    )


@pytest.mark.unit
def test_a_launch_where_the_test_process_cannot_be_a_subreaper_is_refused(
    tmp_path, monkeypatch
):
    """A launch finds what it started below the test process, its child subreaper.
    Where the test process cannot become one (any host but Linux, or a prctl that
    fails), the launch is refused before the runner starts; it never runs without
    that net. On Linux the failure is simulated; elsewhere it is the host's own."""
    env = _module("env")
    if sys.platform.startswith("linux"):
        monkeypatch.setattr(env, "_prctl", _refused_prctl, raising=False)
    runner, ran = _marking_runner(tmp_path)
    with pytest.raises(_api("env", "LaunchCleanupFailed"), match="subreaper"):
        _launch_marking_runner(env, tmp_path, runner)
    assert not ran.exists(), "the runner started"


@pytest.mark.unit
def test_a_host_that_is_not_linux_is_refused_before_any_library_is_loaded(
    tmp_path, monkeypatch
):
    """The refusal anywhere but Linux comes from the platform check, before ctypes
    loads any library, so it is the same refusal on every host."""
    env = _module("env")

    def no_library(*args, **kwargs):
        raise AssertionError("a library was loaded before the platform was checked")

    monkeypatch.setattr(env, "sys", types.SimpleNamespace(platform="win32"))
    monkeypatch.setattr(env.ctypes, "CDLL", no_library)
    runner, ran = _marking_runner(tmp_path)
    with pytest.raises(_api("env", "LaunchCleanupFailed"), match="subreaper.*win32"):
        _launch_marking_runner(env, tmp_path, runner)
    assert not ran.exists(), "the runner started"


@pytest.mark.integration
@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="anywhere but Linux the subreaper refusal comes first",
)
def test_a_launch_where_there_is_no_proc_to_read_is_refused(tmp_path, monkeypatch):
    """A launch finds what it started in /proc. Where the test process cannot read its
    own entry there, the launch is refused before the runner starts, the subreaper
    setting is put back, and the next launch is not held up by the refused one."""
    env = _module("env")
    before = _subreaper_flag()
    monkeypatch.setattr(env, "_proc_stat", lambda pid: None)
    runner, ran = _marking_runner(tmp_path)
    with pytest.raises(_api("env", "LaunchCleanupFailed"), match="/proc"):
        _launch_marking_runner(env, tmp_path, runner)
    assert not ran.exists(), "the runner started"
    assert _subreaper_flag() == before
    monkeypatch.undo()
    assert _launch_marking_runner(env, tmp_path, runner) == 0
    assert ran.exists()


def _subreaper_flag() -> int:
    """Whether this process is a child subreaper, from prctl(PR_GET_CHILD_SUBREAPER)."""
    libc = ctypes.CDLL(None, use_errno=True)
    value = ctypes.c_int(-1)
    unused = ctypes.c_ulong(0)
    result = libc.prctl(ctypes.c_int(37), ctypes.byref(value), unused, unused, unused)
    assert result == 0, os.strerror(ctypes.get_errno())
    return value.value


@pytest.mark.unit
def test_the_host_refusal_says_the_docker_daemon_must_not_be_shared():
    """Each launch removes every container the daemon gained while it ran, so a
    machine given DOCTEST_CI_RUNNERS_ANYWHERE=1 must have a daemon of its own."""
    problem = _api("env", "host_problem")({})
    assert problem and "Docker daemon" in problem and "shared" in problem, problem


# ---------------------------------------------------------------------------
# The poisoned outer ash
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.skipif(
    sys.platform == "win32", reason="the runners run on Linux; ash is a sh script"
)
def test_the_poisoned_ash_touches_its_sentinel_and_the_check_sees_it(tmp_path):
    write_poisoned_ash = _api("env", "write_poisoned_ash")
    poisoned_ash_problem = _api("env", "poisoned_ash_problem")
    bin_dir = tmp_path / "poison-bin"
    sentinel = tmp_path / "sentinel" / "outer-ash-ran"
    ash = write_poisoned_ash(bin_dir, sentinel)
    assert ash == bin_dir / "ash" and os.access(ash, os.X_OK)
    assert poisoned_ash_problem(sentinel) is None, "no sentinel, no problem"
    subprocess.run(
        [str(ash), "scan", "--mode", "local"],
        check=False,
        env={"PATH": "/usr/bin:/bin"},
    )
    assert sentinel.exists(), "running the poisoned ash leaves the sentinel"
    problem = poisoned_ash_problem(sentinel)
    assert isinstance(problem, str) and str(sentinel) in problem


# ---------------------------------------------------------------------------
# Only on a GitHub-hosted runner, and an error elsewhere
# ---------------------------------------------------------------------------

HOSTED = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
REFUSED = [
    {},
    {"GITHUB_ACTIONS": "true", "ACT": "true"},
    {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"},
    {**HOSTED, "ACT": "true"},
    {"GITHUB_ACTIONS": "false", "RUNNER_ENVIRONMENT": "github-hosted"},
    {"DOCTEST_CI_RUNNERS_ANYWHERE": "0"},
    {"DOCTEST_CI_RUNNERS_ANYWHERE": "true"},
]


@pytest.mark.unit
def test_the_runner_tests_run_on_a_github_hosted_runner_or_with_the_override():
    host_problem = _api("env", "host_problem")
    require = _api("env", "require_github_hosted")
    for environ in (HOSTED, {"DOCTEST_CI_RUNNERS_ANYWHERE": "1"}):
        assert host_problem(environ) is None
        require(environ)


@pytest.mark.unit
@pytest.mark.parametrize("environ", REFUSED)
def test_anywhere_else_is_an_error_and_not_a_skip(environ):
    host_problem = _api("env", "host_problem")
    require = _api("env", "require_github_hosted")
    error = _api("env", "NotOnAGitHubHostedRunner")
    assert issubclass(error, RuntimeError)
    assert not issubclass(error, (pytest.skip.Exception, pytest.xfail.Exception))
    problem = host_problem(environ)
    assert isinstance(problem, str) and "DOCTEST_CI_RUNNERS_ANYWHERE=1" in problem
    with pytest.raises(error):
        require(environ)


# ---------------------------------------------------------------------------
# Opt-in: the marker, the flag, and what the flag selects
# ---------------------------------------------------------------------------

RUNNER_TESTS = (
    REPO_ROOT / "tests" / "integration" / "docs" / "test_docs_ci_runners.py",
    REPO_ROOT / "tests" / "integration" / "docs" / "test_docs_ci_runners_can_fail.py",
)


@pytest.mark.unit
def test_the_ci_runner_marker_is_selected_by_its_flag():
    tree = ast.parse((REPO_ROOT / "tests" / "conftest.py").read_text(encoding="utf-8"))
    markers = next(
        (
            ast.literal_eval(node.value)
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(
                getattr(t, "id", None) == "_RUNTIME_SNAPSHOT_MARKERS"
                for t in node.targets
            )
        ),
        None,
    )
    assert isinstance(markers, dict), (
        "tests/conftest.py has no _RUNTIME_SNAPSHOT_MARKERS"
    )
    assert markers.get("ci_runner") == "--run-ci-runners", (
        "tests/conftest.py's _RUNTIME_SNAPSHOT_MARKERS needs "
        f'"ci_runner": "--run-ci-runners"; it holds {markers}'
    )


@pytest.mark.unit
@pytest.mark.parametrize("path", RUNNER_TESTS, ids=[p.name for p in RUNNER_TESTS])
def test_each_runner_test_module_is_marked_ci_runner(path):
    if not path.is_file():
        pytest.fail(f"missing {path.relative_to(REPO_ROOT).as_posix()}")
    text = path.read_text(encoding="utf-8")
    assert re.search(
        r"^pytestmark\s*=.*pytest\.mark\.ci_runner\b", text, re.MULTILINE
    ), f"{path.name} must set pytestmark = pytest.mark.ci_runner at module level"


def _collect(*flags: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-o",
            "addopts=",
            "-p",
            "no:cacheprovider",
            "--collect-only",
            "-q",
            str(RUNNER_TESTS[0]),
            *flags,
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
        # As a host the runs refuse, so a host check at collection fails this test.
        env={k: v for k, v in os.environ.items() if k not in HOSTED and k != "ACT"}
        | {"DOCTEST_CI_RUNNERS_ANYWHERE": "0"},
    )


@pytest.mark.integration
def test_the_flag_collects_one_test_per_census_block_and_without_it_none():
    """Collection only: nothing runs, so the host check does not apply."""
    if not RUNNER_TESTS[0].is_file():
        pytest.fail(f"missing {RUNNER_TESTS[0].relative_to(REPO_ROOT).as_posix()}")
    checks = sys.modules.get("_ash_docs_checks")
    if checks is None:
        if str(REPO_ROOT) not in sys.path:
            sys.path.insert(0, str(REPO_ROOT))
        spec = importlib.util.spec_from_file_location(
            "_ash_docs_checks", REPO_ROOT / "scripts" / "docs_checks.py"
        )
        assert spec and spec.loader
        checks = importlib.util.module_from_spec(spec)
        sys.modules["_ash_docs_checks"] = checks
        spec.loader.exec_module(checks)
    gate_spec = importlib.util.spec_from_file_location(
        "_ash_docs_gate_for_runner", REPO_ROOT / "scripts" / "verify_docs_freshness.py"
    )
    gate = sys.modules.get("_ash_docs_gate_for_runner")
    if gate is None:
        assert gate_spec and gate_spec.loader
        gate = importlib.util.module_from_spec(gate_spec)
        sys.modules["_ash_docs_gate_for_runner"] = gate
        gate_spec.loader.exec_module(gate)
    if not hasattr(checks, "ci_runner_census"):
        pytest.fail("scripts/docs_checks.py defines no ci_runner_census")
    census = checks.ci_runner_census(
        checks.load_pages(gate.collect_md_files(), gate.REPO_ROOT)
    )
    expected = sum(len(entries) for entries in census.legs.values())

    selected = _collect("--run-integration", "--run-ci-runners")
    assert selected.returncode == 0, selected.stdout[-2000:] + selected.stderr[-2000:]
    ids = [line for line in selected.stdout.splitlines() if "::" in line]
    assert len(ids) == expected, (
        f"{len(ids)} tests collected for {expected} census blocks"
    )

    unselected = _collect("--run-integration")
    assert not [line for line in unselected.stdout.splitlines() if "::" in line]
    assert f"{expected} deselected" in unselected.stdout, unselected.stdout[-2000:]
