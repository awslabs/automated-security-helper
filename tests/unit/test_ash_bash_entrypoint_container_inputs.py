"""What the bash entrypoint ``./ash`` hands to the OCI runner.

The same three properties tests/unit/interactions/test_container_build_and_mount_inputs.py
holds the Python runner to, for the shell wrapper:

- the source directory is mounted at ``/src`` read-only, wherever the output
  directory is, including the default ``.ash/ash_output`` inside it;
- the image is built from the Dockerfile beside the script, with that directory as
  the build context, never from the scanned project in the working directory;
- the build target is the one requested, ``non-root`` without a request, whatever
  CI variables are set.

The real script runs against a fake OCI runner that records each invocation, so
the assertions are on the command lines the wrapper assembled.
"""

import os
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ASH_SCRIPT = REPO_ROOT / "ash"

pytestmark = [
    # The same three guards as test_ash_bash_entrypoint_build_failure.py. Each one
    # states its own reason, so a skipped run says why in the report.
    pytest.mark.skipif(
        os.name == "nt",
        reason=(
            "Windows: bash on a Windows runner is the WSL launcher stub, not a POSIX "
            "shell, and Windows users run ASH through utils/ash_helpers.ps1 instead "
            "of ./ash"
        ),
    ),
    pytest.mark.skipif(
        shutil.which("bash") is None,
        reason="no bash on PATH: ./ash is a bash script and cannot run without it",
    ),
    pytest.mark.skipif(
        not ASH_SCRIPT.is_file(),
        reason=(
            "./ash is not in this tree: an installed-package layout ships the Python "
            "CLI only, so there is no wrapper to run"
        ),
    ),
]

# Writes each invocation's arguments, NUL-separated, to the next numbered file in
# $FAKE_RUNNER_LOG_DIR, and succeeds. The wrapper calls the runner sequentially.
FAKE_RUNNER = """#!/bin/bash
count=$(find "$FAKE_RUNNER_LOG_DIR" -type f | wc -l)
printf '%s\\0' "$@" > "$FAKE_RUNNER_LOG_DIR/$(printf '%03d' "$count")"
exit 0
"""

#: Environment that would change the wrapper's commands if the suite itself runs in
#: a CI job that exported it.
_SCRUBBED_ENV = (
    "CI",
    "IsCI",
    "ISCI",
    "CODEBUILD_BUILD_ID",
    "ASH_IMAGE_NAME",
    "OCI_RUNNER",
    "OCI_RUNNER_WRAPPER",
    "ASH_BASE_OCI_LAYOUT",
    "ASH_BASE_IMAGE_OVERRIDE",
    "DOCKER_EXTRA_ARGS",
    "ASH_CONFIG",
)


@pytest.fixture
def fake_runner(tmp_path):
    runner = tmp_path / "bin" / "fake-oci-runner"
    runner.parent.mkdir()
    runner.write_text(FAKE_RUNNER)
    runner.chmod(runner.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    log_dir = tmp_path / "runner-calls"
    log_dir.mkdir()
    return runner, log_dir


@pytest.fixture
def project(tmp_path):
    """A scanned project that carries its own Dockerfile and pyproject.toml."""
    root = tmp_path / "project"
    root.mkdir()
    (root / "Dockerfile").write_text("FROM scratch AS non-root\nFROM scratch AS ci\n")
    (root / "pyproject.toml").write_text("[project]\nname = 'scanned'\n")
    return root


def _run_ash_status(
    fake_runner, cwd: Path, args: List[str], extra_env: Optional[Dict[str, str]] = None
):
    """Run ./ash against the fake runner: (returncode, stdout and stderr, calls)."""
    runner, log_dir = fake_runner
    env = {k: v for k, v in os.environ.items() if k not in _SCRUBBED_ENV}
    env.update(
        {"OCI_RUNNER": str(runner), "FAKE_RUNNER_LOG_DIR": str(log_dir)},
    )
    env.update(extra_env or {})
    result = subprocess.run(  # nosec B603 B607 — fixed script path, list args, no shell
        ["bash", str(ASH_SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=str(cwd),
        env=env,
        timeout=180,
        check=False,
    )
    calls = []
    for record in sorted(log_dir.iterdir()):
        calls.append(record.read_bytes().decode().split("\0")[:-1])
    return result.returncode, result.stdout + result.stderr, calls


def run_ash(
    fake_runner, cwd: Path, args: List[str], extra_env: Optional[Dict[str, str]] = None
) -> List[List[str]]:
    returncode, output, calls = _run_ash_status(fake_runner, cwd, args, extra_env)
    assert returncode == 0, output
    return calls


def _only(calls: List[List[str]], subcommand: str) -> List[str]:
    matching = [call for call in calls if call and call[0] == subcommand]
    assert len(matching) == 1, f"expected one `{subcommand}` call, got {calls}"
    return matching[0]


def _flag(call: List[str], flag: str) -> str:
    values = [call[i + 1] for i, arg in enumerate(call[:-1]) if arg == flag]
    assert len(values) == 1, f"expected one {flag} in {call}"
    return values[0]


def _mount(call: List[str], destination: str) -> Dict[str, Optional[str]]:
    found = []
    for i, arg in enumerate(call[:-1]):
        if arg != "--mount":
            continue
        options: Dict[str, Optional[str]] = {}
        for part in call[i + 1].split(","):
            key, sep, value = part.partition("=")
            options[key] = value if sep else None
        if options.get("destination") == destination:
            found.append(options)
    assert len(found) == 1, f"expected one mount at {destination} in {call}"
    return found[0]


class TestTheSourceIsMountedReadOnly:
    @pytest.mark.parametrize(
        "layout",
        ["default-output", "output-inside-source", "sibling-sharing-the-prefix"],
    )
    def test_the_source_mount_is_read_only(
        self, layout, fake_runner, project, tmp_path
    ):
        if layout == "default-output":
            # No flags: the source is the working directory and the output is
            # .ash/ash_output inside it.
            args: List[str] = ["--no-build"]
        elif layout == "output-inside-source":
            args = [
                "--no-build",
                "--source-dir",
                str(project),
                "--output-dir",
                str(project / "reports"),
            ]
        else:
            args = [
                "--no-build",
                "--source-dir",
                str(project),
                "--output-dir",
                str(tmp_path / "project-out"),
            ]

        calls = run_ash(fake_runner, project, args)

        src = _mount(_only(calls, "run"), "/src")
        assert Path(str(src["source"])).resolve() == project.resolve()
        assert "readonly" in src, f"/src is writable: {src}"

    def test_the_source_mount_is_read_only_with_output_outside(
        self, fake_runner, project, tmp_path
    ):
        """Control: an output directory outside the source already gets a read-only /src."""
        output = tmp_path / "elsewhere" / "out"
        calls = run_ash(
            fake_runner,
            project,
            ["--no-build", "--source-dir", str(project), "--output-dir", str(output)],
        )

        run = _only(calls, "run")
        assert "readonly" in _mount(run, "/src")
        out = _mount(run, "/out")
        assert Path(str(out["source"])).resolve() == output.resolve()
        assert "readonly" not in out


class TestTheImageIsBuiltFromTheScriptsDockerfile:
    def test_a_project_dockerfile_in_the_cwd_is_not_built(self, fake_runner, project):
        """Control: the wrapper already builds the Dockerfile beside itself."""
        calls = run_ash(fake_runner, project, ["--no-run"])

        build = _only(calls, "build")
        assert Path(_flag(build, "--file")).resolve() == (REPO_ROOT / "Dockerfile")
        assert Path(build[-1]).resolve() == REPO_ROOT


class TestTheBuildTargetIsTheOneRequested:
    @pytest.mark.parametrize(
        ("name", "value"),
        [("CI", "true"), ("CI", "false"), ("CODEBUILD_BUILD_ID", "project:build-1")],
    )
    def test_ci_variables_do_not_change_the_target(
        self, name, value, fake_runner, project
    ):
        """Control: the wrapper already builds non-root unless asked otherwise."""
        calls = run_ash(fake_runner, project, ["--no-run"], {name: value})

        assert _flag(_only(calls, "build"), "--target") == "non-root"

    def test_an_explicit_ci_target_is_built(self, fake_runner, project):
        """Control."""
        calls = run_ash(fake_runner, project, ["--no-run", "--build-target", "ci"])

        assert _flag(_only(calls, "build"), "--target") == "ci"


def _inner_args(call: List[str]) -> List[str]:
    """The arguments the wrapper hands the ``ash`` inside the image."""
    return call[call.index("ash") + 1 :]


class TestTheConfigIsReadableInsideTheContainer:
    """``--config`` (or ``ASH_CONFIG``) names a host file; the container sees it
    only through a mount. The host path itself used to be passed through, which
    names nothing inside, so the scan ran with its defaults."""

    def test_a_config_inside_the_source_is_read_through_the_source_mount(
        self, fake_runner, project
    ):
        (project / ".ash").mkdir()
        (project / ".ash" / "strict.yaml").write_text("project_name: p\n")

        rc, err, calls = _run_ash_status(
            fake_runner, project, ["--no-build", "--config", ".ash/strict.yaml"]
        )

        assert rc == 0, err
        run = _only(calls, "run")
        assert _flag(_inner_args(run), "--config") == "/src/.ash/strict.yaml"
        assert run.count("--mount") == 2

    @pytest.mark.parametrize(
        "how", ["--config <path>", "--config=<path>", "ASH_CONFIG"]
    )
    def test_a_config_outside_the_source_is_mounted_read_only(
        self, how, fake_runner, project, tmp_path
    ):
        config = tmp_path / "operator" / "ash.yaml"
        config.parent.mkdir()
        config.write_text("project_name: p\n")
        if how == "--config <path>":
            args, env = ["--no-build", "--config", str(config)], None
        elif how == "--config=<path>":
            args, env = ["--no-build", f"--config={config}"], None
        else:
            args, env = ["--no-build"], {"ASH_CONFIG": str(config)}

        rc, err, calls = _run_ash_status(fake_runner, project, args, env)

        assert rc == 0, err
        run = _only(calls, "run")
        inner = _flag(_inner_args(run), "--config")
        assert inner == "/ash-config/ash.yaml"
        mount = _mount(run, inner)
        assert Path(str(mount["source"])) == config.resolve()
        assert "readonly" in mount, f"the config mount is writable: {mount}"
        assert str(config) not in _inner_args(run)

    @pytest.mark.parametrize("value", ["missing.yaml", ""], ids=["missing", "empty"])
    def test_an_unreadable_config_is_refused_before_anything_runs(
        self, value, fake_runner, project
    ):
        rc, err, calls = _run_ash_status(fake_runner, project, ["--config", value])

        assert rc == 3
        assert calls == [], f"the runner was called: {calls}"
        assert "Config file not found" in err

    def test_a_build_without_a_run_does_not_need_the_config(self, fake_runner, project):
        """Control: ``--no-run`` scans nothing."""
        rc, err, calls = _run_ash_status(
            fake_runner, project, ["--no-run", "--config", "missing.yaml"]
        )

        assert rc == 0, err
        assert [call[0] for call in calls] == ["build"]


class TestAPathTheMountCannotCarryIsRefused:
    """A comma, a double quote or a line break in a mounted path refuses the run.

    ``--mount`` is read as comma-separated fields, so a comma in a host path starts a
    field of its own (``x,readonly=false``), a double quote starts CSV quoting, and a
    line break ends the argument. The wrapper refuses with exit 3 before it builds or
    runs anything.
    """

    @pytest.mark.parametrize(
        "name",
        ["x,readonly=false", 'x"y', "x\ny", "x\ry"],
        ids=["comma", "double-quote", "line-feed", "carriage-return"],
    )
    @pytest.mark.parametrize("which", ["source", "output", "config"])
    def test_it_is_refused_before_anything_runs(
        self, name, which, fake_runner, project, tmp_path
    ):
        odd = tmp_path / name
        odd.mkdir()
        args = ["--source-dir", str(project), "--output-dir", str(tmp_path / "out")]
        if which == "source":
            args[1] = str(odd)
        elif which == "output":
            args[3] = str(odd)
        else:
            (odd / "ash.yaml").write_text("project_name: p\n")
            args += ["--config", str(odd / "ash.yaml")]

        rc, output, calls = _run_ash_status(fake_runner, project, args)

        assert rc == 3, output
        assert calls == [], f"the runner was called: {calls}"
        assert "--mount" in output

    def test_ordinary_punctuation_still_runs(self, fake_runner, tmp_path):
        """Control."""
        source = tmp_path / "with space; and (parens)"
        source.mkdir()

        rc, output, calls = _run_ash_status(
            fake_runner, source, ["--no-build", "--output-dir", str(tmp_path / "out")]
        )

        assert rc == 0, output
        assert [call[0] for call in calls] == ["run"]


class TestAConfigTheScannedRepositoryWroteKeepsItsLimits:
    """A config inside the scanned checkout but outside the source directory.

    The scan inside the container sees it at /ash-config, outside its own tree, so
    the wrapper tells it the file belongs to the scanned repository, as a local scan
    of that checkout would treat it.
    """

    @pytest.fixture
    def checkout(self, tmp_path):
        root = tmp_path / "repo"
        (root / ".git").mkdir(parents=True)
        (root / "services" / "api").mkdir(parents=True)
        (root / "ci").mkdir()
        return root

    def test_a_config_elsewhere_in_the_checkout_is_marked(self, fake_runner, checkout):
        (checkout / "ci" / "ash.yaml").write_text("project_name: p\n")

        rc, output, calls = _run_ash_status(
            fake_runner,
            checkout / "services" / "api",
            ["--no-build", "--config", str(checkout / "ci" / "ash.yaml")],
        )

        assert rc == 0, output
        assert "--config-from-scanned-repository" in _inner_args(_only(calls, "run"))

    def test_a_config_outside_the_checkout_is_not_marked(
        self, fake_runner, checkout, tmp_path
    ):
        """Control."""
        (tmp_path / "operator").mkdir()
        (tmp_path / "operator" / "ash.yaml").write_text("project_name: p\n")

        rc, output, calls = _run_ash_status(
            fake_runner,
            checkout / "services" / "api",
            ["--no-build", "--config", str(tmp_path / "operator" / "ash.yaml")],
        )

        assert rc == 0, output
        inner = _inner_args(_only(calls, "run"))
        assert "--config-from-scanned-repository" not in inner
        assert _flag(inner, "--config") == "/ash-config/ash.yaml"
