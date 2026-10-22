# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What every unit test runs under: the tool guard and HOME check of tests/unit/conftest.py.

The check runs at teardown, and a test cannot see its own teardown fail, so the
conftest's wiring is checked in a pytest run of its own: it runs
unit_tool_guard_probe.py, whose tests each do one thing the check has to pass or
fail, through the real tests/conftest.py and tests/unit/conftest.py.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.utils.tool_guard import GUARDED_TOOLS

pytest_plugins = ["pytester"]

REPO_ROOT = Path(__file__).resolve().parents[2]
PROBE = REPO_ROOT / "tests" / "unit" / "unit_tool_guard_probe.py"

#: How a refusing stand-in (``_probe_environment``) exits.
REFUSED = 97

#: Host programs that run a guarded tool's code under another name, refused too.
TOOL_ALIASES = ("pysemgrep", "bandit-baseline", "detect-secrets-hook", "cfn-lint")

#: Where uv and the XDG-following tools write. Each has to be inside the test's own
#: HOME, or a real tool run writes outside it and the HOME check sees nothing: CI and
#: developers set UV_TOOL_DIR and UV_CACHE_DIR, and uv reads XDG_STATE_HOME.
TOOL_LOCATIONS = (
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "UV_TOOL_DIR",
    "UV_CACHE_DIR",
)

#: The probe's tests the check fails, each with what its message has to name.
FAILED_BY_THE_CHECK = {
    "test_fails_asking_a_stand_in_to_run": "started a tool: ['semgrep scan']",
    "test_fails_starting_a_tool_by_its_path": "zq-host/uv tool list (not through",
    "test_fails_starting_a_tool_found_past_the_stand_ins": "uv tool list (not through",
    "test_fails_running_a_tools_module": "-m uv.no_such_module (not through",
    "test_fails_leaving_a_tools_file_in_home": "['.semgrep/settings.yml']",
    "test_fails_leaving_a_uv_cache_in_home": "CACHEDIR.TAG']",
    "test_fails_leaving_a_file_in_ashs_bin_directory": "['.ash/bin/semgrep']",
    # A listed module without a reason is refused too; the refusal's own tests are
    # in tests/utils/test_tool_guard.py, since the probe cannot be listed.
    "test_fails_opting_out_unlisted": "is not one of the modules allowed",
    "test_fails_marked_real_home_unlisted": "is marked real_home",
    "test_fails_swallowing_a_home_rule_refusal": "broke the HOME rule: os.posix_spawn",
    # The SIGTERM handler's plain-pid mirror, with the planted id: the message
    # names the stale entry the die-now kill would have aimed at a reused pid.
    "test_fails_leaving_a_pid_in_the_die_now_mirror": (
        "mirrors with no registered child behind them: [1073741835]"
    ),
}
PASSED_BY_THE_CHECK = (
    "test_passes_running_git_a_shell_and_its_own_fake",
    "test_passes_a_version_probe_the_stand_in_answers",
    "test_passes_leaving_only_ashs_own_state",
    # Runs after the planted mirror leak: the check cleared what it failed.
    "test_passes_with_the_die_now_mirrors_empty_after_the_leak_was_cleared",
)


def test_every_tool_location_is_inside_the_tests_home():
    home = Path(os.environ["HOME"])

    outside = {
        name: os.environ.get(name)
        for name in TOOL_LOCATIONS
        if name not in os.environ or not Path(os.environ[name]).is_relative_to(home)
    }

    assert outside == {}, (home, outside)


def test_the_tool_guard_is_installed():
    from tests.utils import tool_guard

    assert tool_guard._ACTIVE is not None


def _semgrep_in(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    tool = directory / "semgrep"
    tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    tool.chmod(0o755)
    return tool


def _normalized_roots(roots) -> set:
    return {
        os.path.normcase(form)
        for root in roots
        for form in (os.path.abspath(root), os.path.realpath(root))
    }


def test_the_guards_own_directories_are_the_runs_own_by_the_home_rule(
    _unit_tool_guard, tmp_path_factory
):
    """The guard's own directories are basetemp and the session temp directory, as
    the HOME rule counts them (tool_guard.run_own_directories): one definition of
    what the run's own directories leave out."""
    from tests.utils.tool_guard import run_own_directories

    basetemp = tmp_path_factory.getbasetemp()
    own = run_own_directories(basetemp)

    assert own == [basetemp, Path(os.environ["TMPDIR"])]
    assert set(_unit_tool_guard.guard._own_roots) == _normalized_roots(own)


@pytest.mark.skipif(sys.platform == "win32", reason="a POSIX executable")
def test_a_host_tool_under_the_shared_temp_root_is_still_a_tool_start(
    _unit_tool_guard, tmp_path_factory
):
    """The HOME rule also counts the temp directories the run started with and
    pytest's temp root as the run's own, and on a usual run that is /tmp. A test
    makes no program there, only under basetemp or the session directory, so for
    the tool guard a semgrep found there by its path is the host's: a tool start."""
    import tempfile

    from tests.utils.home_rule import loaded_conftest

    conftest = loaded_conftest()
    shared_roots = {
        *conftest._pre_session_temp_env().values(),
        os.environ["PYTEST_DEBUG_TEMPROOT"],
    }
    basetemp = tmp_path_factory.getbasetemp()
    for root in sorted(shared_roots):
        host = Path(tempfile.mkdtemp(prefix="ash-host-tool-", dir=root))
        try:
            tool = _semgrep_in(host)
            for own in (basetemp, Path(os.environ["TMPDIR"])):
                assert not tool.resolve().is_relative_to(own.resolve()), (tool, own)

            assert _unit_tool_guard.guard._runs_a_guarded_tool(
                str(tool), [str(tool)], "", None
            ), tool
        finally:
            shutil.rmtree(host)


@pytest.mark.skipif(sys.platform == "win32", reason="a POSIX executable")
def test_a_temp_directory_in_the_developers_ash_is_not_the_tests_own(
    monkeypatch, tmp_path
):
    """The HOME rule's exclusion, taken by the tool guard: a TMPDIR inside the
    developer's ~/.ash, where the default bin directory and the receipts are, is
    not the run's own, so a semgrep there is a tool start even when it is under
    the run's basetemp or session directory."""
    from tests.utils.home_rule import loaded_conftest
    from tests.utils.tool_guard import ToolGuard, run_own_directories

    developer = tmp_path / "developer"
    in_dot_ash = developer / ".ash" / "tmp"
    basetemp = in_dot_ash / "pytest-of-developer" / "pytest-0"
    session = in_dot_ash / "ash-pytest-session"
    basetemp.mkdir(parents=True)
    tool = _semgrep_in(session / "tools")
    record = loaded_conftest()._DEVELOPER_HOME_ENV

    monkeypatch.setenv(record, json.dumps({"env": {}, "home": str(tmp_path / "other")}))
    assert basetemp in run_own_directories(basetemp, str(session))

    monkeypatch.setenv(record, json.dumps({"env": {}, "home": str(developer)}))
    own = run_own_directories(basetemp, str(session))

    assert own == []
    guard = ToolGuard(tmp_path / "guard-bin", own_directories=own)
    assert guard._runs_a_guarded_tool(str(tool), [str(tool)], "", None)


def _probe_environment(tmp_path: Path) -> dict[str, str]:
    """What the probe's pytest is started with: it reaches no real tool and no real
    home, even when the guard or the wiring under test is broken.

    The child's guard puts its stand-ins first on PATH, and its tests/conftest.py
    gives each test a home of its own. A fault in either, which is what the probe is
    there to show, takes that away, and with it the child ran the host's semgrep
    (``--version``, then ``semgrep scan``), and its uv cache case aimed at the
    developer's uv cache. So, around whatever the child's conftests do:

    - a refusing stand-in for each guarded tool, and for each of ``TOOL_ALIASES``,
      is first on PATH: it writes its call to ``refused.log`` and exits ``REFUSED``,
      running nothing. The child's guard puts its own ahead of these. After them
      come this interpreter's directory, /usr/bin and /bin, for git and sh, and no
      directory of the user's own tools, so a tool the host keeps there under
      another name is not reached either;
    - HOME, USERPROFILE, the XDG directories and uv's are in a home under
      *tmp_path*, and the developer record the child's conftest reads
      (``ASH_TEST_DEVELOPER_HOME``) names another, so what that conftest takes for
      the developer's home, ``real_home`` and the uv cache it pins are scratch too.
    """
    refusing = tmp_path / "refusing"
    refusing.mkdir()
    refused_log = tmp_path / "refused.log"
    for name in (*GUARDED_TOOLS, *TOOL_ALIASES):
        stand_in = refusing / name
        stand_in.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' \"{name} $*\" >> {shlex.quote(str(refused_log))}\n"
            f"echo 'refused: {name} is not run here' >&2\n"
            f"exit {REFUSED}\n",
            encoding="utf-8",
        )
        stand_in.chmod(0o755)
    homes = {}
    for which in ("outer", "developer"):
        home = tmp_path / f"{which}-home"
        homes[which] = {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "XDG_DATA_HOME": str(home / ".local" / "share"),
            "XDG_STATE_HOME": str(home / ".local" / "state"),
            "UV_TOOL_DIR": str(home / ".local" / "share" / "uv" / "tools"),
            "UV_CACHE_DIR": str(home / ".cache" / "uv"),
        }
        home.mkdir()
    developer = {"env": homes["developer"], "home": homes["developer"]["HOME"]}
    return {
        **homes["outer"],
        "PATH": os.pathsep.join(
            [str(refusing), str(Path(sys.executable).parent), "/usr/bin", "/bin"]
        ),
        "ASH_TEST_DEVELOPER_HOME": json.dumps(developer),
    }


@pytest.mark.skipif(sys.platform == "win32", reason="the stand-ins are sh scripts")
def test_the_probe_child_reaches_no_real_tool_and_no_real_home(tmp_path):
    env = _probe_environment(tmp_path)
    search_path = env.pop("PATH")
    developer = json.loads(env.pop("ASH_TEST_DEVELOPER_HOME"))

    assert search_path.split(os.pathsep)[1:] == [
        str(Path(sys.executable).parent),
        "/usr/bin",
        "/bin",
    ], search_path
    for name in (*GUARDED_TOOLS, *TOOL_ALIASES):
        found = shutil.which(name, path=search_path)
        assert found == str(tmp_path / "refusing" / name), (name, found)
    answer = subprocess.run(
        [str(tmp_path / "refusing" / "semgrep"), "--version"],
        capture_output=True,
        text=True,
    )
    assert (answer.returncode, answer.stdout) == (REFUSED, ""), answer
    assert (tmp_path / "refused.log").read_text() == "semgrep --version\n"
    assert set(env) >= {*TOOL_LOCATIONS, "HOME", "USERPROFILE"}, env
    locations = {
        **env,
        **{f"developer {name}": value for name, value in developer["env"].items()},
        "developer home": developer["home"],
    }
    # By name: the locations are an environment's values.
    outside = sorted(
        name
        for name, value in locations.items()
        if not Path(value).is_relative_to(tmp_path)
    )
    assert outside == [], outside


@pytest.mark.skipif(
    sys.platform == "win32", reason="the probe's programs are sh scripts"
)
def test_the_check_fails_each_test_that_starts_a_tool_or_leaves_its_files(
    pytester, monkeypatch, tmp_path
):
    # A program named uv outside the child run's own directories, standing for the
    # host's: it does nothing. The directory's name shares no 12-character
    # fragment with PROBE_OUTSIDE_UV_FILE's value or the run's home paths, so
    # the child conftest's fragment redaction leaves it readable in the
    # check's message (a directory named "outside" was masked to <value>
    # through those fragments' windows).
    outside = tmp_path / "zq-host"
    outside.mkdir()
    real_uv = outside / "uv"
    real_uv.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    real_uv.chmod(0o755)
    # Its path goes to the probe in a file: the child runs under the root conftest,
    # which redacts each environment value from its reports, and the check's
    # message for a tool started by its path names this one.
    where = tmp_path / "outside-uv-path"
    where.write_text(str(real_uv), encoding="utf-8")
    monkeypatch.setenv("PROBE_OUTSIDE_UV_FILE", str(where))
    for name, value in _probe_environment(tmp_path).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv(
        "PYTHONPATH",
        os.pathsep.join(p for p in (str(REPO_ROOT), os.environ.get("PYTHONPATH")) if p),
    )
    # A child that inherited these would act as an xdist worker of this run.
    for name in [n for n in os.environ if n.startswith("PYTEST_XDIST_")]:
        monkeypatch.delenv(name)

    result = pytester.runpytest_subprocess(
        str(PROBE),
        "-o",
        "addopts=",
        "-p",
        "no:cacheprovider",
        "-p",
        "no:randomly",
        "-n",
        "0",
        "-rA",
    )

    output = result.stdout.str()
    sections = _error_sections(output)
    # The check fails a test at its setup (the opt-out) or teardown, as an error.
    assert result.parseoutcomes().get("failed", 0) == 0, output[-6000:]
    assert sorted(sections) == sorted(FAILED_BY_THE_CHECK), output[-6000:]
    for name, named in FAILED_BY_THE_CHECK.items():
        assert named in sections[name], (name, named, sections[name][-3000:])
    # -rA's summary names each passed test, by its path from the child's directory.
    passed = {
        line.rsplit("::", 1)[1]
        for line in output.splitlines()
        if line.startswith("PASSED ") and f"{PROBE.name}::" in line
    }
    assert set(PASSED_BY_THE_CHECK) <= passed, (passed, output[-6000:])
    # The child's own stand-ins answered every call by name; none got past them.
    refused_log = tmp_path / "refused.log"
    assert not refused_log.exists(), refused_log.read_text()


def _error_sections(output: str) -> dict[str, str]:
    """Each test's ``ERROR at setup of`` or ``ERROR at teardown of`` section, by name.

    A section runs to the next one or to the next ``=`` banner.
    """
    sections: dict[str, list[str]] = {}
    current = None
    for line in output.splitlines():
        if line.startswith("_") and " ERROR at " in line:
            current = line.strip("_ ").split(" of ", 1)[1]
            sections[current] = []
        elif line.startswith("="):
            current = None
        elif current is not None:
            sections[current].append(line)
    return {name: "\n".join(lines) for name, lines in sections.items()}
