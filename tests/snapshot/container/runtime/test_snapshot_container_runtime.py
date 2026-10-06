# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ASH prints and exits with when a real container runtime runs its image.

Deselected by default (tests/conftest.py). The scan-validation legs that build the
image run this module with ``--run-container-snapshots`` right after their scan,
under docker, podman and finch, so every one of those legs compares against the
same snapshots. Locally: build the image, then

    ASH_IMAGE_NAME=<tag> OCI_RUNNER=docker \\
        pytest tests/snapshot/container/runtime/test_snapshot_container_runtime.py \\
        --run-container-snapshots --no-cov -n 0

Inputs: ``OCI_RUNNER`` (default ``docker``), ``OCI_RUNNER_WRAPPER`` (``sudo`` for
finch in CI) and ``ASH_IMAGE_NAME`` (default ``automated-security-helper:ci``, which
is what every CI leg builds). ``pwsh`` must be on PATH for the PowerShell wrapper
tests; it is on the hosted Linux runners these legs use.

A scan through the image prints the inner ASH's whole log first, and that log
carries timings and tool-install chatter that differ on every run. What the user
reads as the result is what the host prints after the container exits, so for
``ash --mode container`` the snapshot keeps the host's output from its first line
after the container: "Container execution failed with code N" or, for status 0,
the "ASH Scan Completed" banner. The wrappers print the inner ASH directly, so
for them the snapshot keeps the exit status and the last line printed: the inner
verdict for ./ash, the status Invoke-ASH returns for the PowerShell one. Only
bandit is selected: its version is fixed when the image is built, and the
fixture's two bandit findings are the same on every architecture. grype and
semgrep read advisory and rule data that changes daily.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess  # nosec B404 - running the real OCI runner is the point of this module
from pathlib import Path

import pytest

from tests.snapshot.support.normalize import REPO_ROOT, pinned_terminal_env

pytestmark = [
    pytest.mark.container_runtime,
    # The host prints "ASH Scan Completed in <duration>" from its own wall clock.
    pytest.mark.snapshot_masking(mask_durations=True),
]

IMAGE = os.environ.get("ASH_IMAGE_NAME") or "automated-security-helper:ci"
RUNNER = os.environ.get("OCI_RUNNER") or "docker"
RUNNER_PREFIX = [
    *shlex.split(os.environ.get("OCI_RUNNER_WRAPPER", "")),
    RUNNER,
]

#: The host's first line after the container exits, whichever applies.
_HOST_RESUMES = ("Container execution failed with code", "=== ASH Scan Completed")

BAD_CONFIG = "project_name: bad\nglobal_settings:\n  severity_threshold: NOT_A_LEVEL\n"


def _in_image(*command: str) -> dict:
    """Run ``command`` inside the image, with the snapshot terminal's environment."""
    env_args = [
        arg
        for name, value in pinned_terminal_env().items()
        for arg in ("-e", f"{name}={value}")
    ]
    result = subprocess.run(  # nosec B603 - runner and image come from the CI leg
        [*RUNNER_PREFIX, "run", "--rm", *env_args, IMAGE, *command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
        check=False,
    )
    return {"exit_code": result.returncode, "stdout": result.stdout}


def _host_output_after_container(stdout: str) -> str:
    lines = stdout.splitlines()
    for index, line in enumerate(lines):
        if any(marker in line for marker in _HOST_RESUMES):
            return "\n".join(lines[index:]) + "\n"
    raise AssertionError(
        "the host printed nothing after the container exited:\n" + stdout
    )


def _last_line(text: str) -> str:
    return next((line for line in reversed(text.splitlines()) if line.strip()), "")


def _first_line(text: str) -> str:
    """PowerShell's error record after its first line is a source excerpt whose layout
    depends on the pwsh version and console width, so only the message is kept."""
    return next((line for line in text.splitlines() if line.strip()), "")


@pytest.fixture(autouse=True)
def _wide(monkeypatch):
    # The summary prints absolute host paths, whose length is the machine's.
    monkeypatch.setenv("COLUMNS", "1000")


def test_ash_version_in_image(snapshot):
    assert _in_image("ash", "--version") == snapshot


def test_build_image_help_in_image(text_snapshot):
    result = _in_image("ash", "build-image", "--help")
    assert result["exit_code"] == 0
    assert result["stdout"] == text_snapshot("txt")


def test_container_scan_of_the_fixture(run_cli, snapshot, fixture_repo, local_checkout):
    result = run_cli(
        [
            "scan",
            "--mode",
            "container",
            "--no-build",
            "--build-target",
            "ci",
            "--no-progress",
            "--source-dir",
            "src",
            "--output-dir",
            "out",
            "--scanners",
            "bandit",
        ]
    )
    assert {
        "exit_code": result["exit_code"],
        "host_output_after_container": _host_output_after_container(result["stdout"]),
    } == snapshot


def test_container_exit_status_for_an_invalid_config(
    run_cli, snapshot, fixture_repo, local_checkout
):
    (fixture_repo / ".ash" / ".ash.yaml").write_text(BAD_CONFIG, encoding="utf-8")
    result = run_cli(
        [
            "scan",
            "--mode",
            "container",
            "--no-build",
            "--build-target",
            "ci",
            "--no-progress",
            "--source-dir",
            "src",
            "--output-dir",
            "out",
        ]
    )
    assert {
        "exit_code": result["exit_code"],
        "host_output_after_container": _host_output_after_container(result["stdout"]),
    } == snapshot


def _wrapper_env() -> dict[str, str]:
    env = {**os.environ, "OCI_RUNNER": RUNNER}
    if ":" in IMAGE:
        env["ASH_IMAGE_NAME"] = IMAGE
    return env


def test_bash_wrapper_scan_of_the_fixture(snapshot, fixture_repo, in_tmp):
    result = subprocess.run(  # nosec B603 - the repository's own wrapper, list args
        [
            "bash",
            str(REPO_ROOT / "ash"),
            "--no-build",
            "--build-target",
            "ci",
            "--source-dir",
            "src",
            "--output-dir",
            "out",
            "--scanners",
            "bandit",
            "--no-progress",
        ],
        cwd=in_tmp,
        env=_wrapper_env(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=600,
        check=False,
    )
    assert {
        "exit_code": result.returncode,
        "announced_the_run": "Running ASH scan using built image..." in result.stdout,
        "last_line": _last_line(result.stdout),
    } == snapshot


def _pwsh(script: str, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    pwsh = shutil.which("pwsh")
    assert pwsh, "pwsh is not on PATH; the PowerShell wrapper cannot be run here"
    helpers = (REPO_ROOT / "utils" / "ash_helpers.ps1").as_posix()
    return subprocess.run(  # nosec B603 - fixed interpreter, script built here
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", f". '{helpers}'; {script}"],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=600,
        check=False,
    )


def test_powershell_wrapper_scan_of_the_fixture(snapshot, fixture_repo, in_tmp):
    # Invoke-ASH ends with `return $exitCode`, so the status is written to the output
    # stream after the container's own output, and the caller reads the process
    # status from $LASTEXITCODE. Assigning the call (`$rc = Invoke-ASH ...`) captures
    # every line the container printed along with it, and `exit $rc` then exits 0.
    result = _pwsh(
        "Invoke-ASH -NoBuild -BuildTarget ci -SourceDir src -OutputDir out "
        "-OCIRunner $env:OCI_RUNNER -Scanners bandit; exit $LASTEXITCODE",
        in_tmp,
        _wrapper_env(),
    )
    assert {
        "exit_code": result.returncode,
        "announced_the_run": "Running ASH scan using built image..." in result.stdout,
        "last_line": _last_line(result.stdout),
    } == snapshot


def test_powershell_wrapper_without_a_runner(snapshot, in_tmp):
    (in_tmp / "src").mkdir()
    env = {**_wrapper_env(), "ASH_OCI_RUNNER": "no-such-oci-runner"}
    result = _pwsh(
        "Invoke-ASH -NoBuild -SourceDir src -OutputDir out; exit $LASTEXITCODE",
        in_tmp,
        env,
    )
    assert {
        "exit_code": result.returncode,
        "first_error_line": _first_line(result.stderr),
    } == snapshot


def test_powershell_wrapper_default_runner_discovery(snapshot, fixture_repo, in_tmp):
    # No -OCIRunner and no ASH_OCI_RUNNER. Invoke-ASH tries docker, finch, nerdctl
    # and podman in turn, and every leg running this has at least one of them;
    # -NoRun stops before it would be used, so the record is the same on all. The
    # parameter is a [string] defaulting to $env:ASH_OCI_RUNNER, which PowerShell
    # binds as "" rather than $null; the wrapper treats that empty value as unset.
    env = _wrapper_env()
    env.pop("ASH_OCI_RUNNER", None)
    result = _pwsh(
        "Invoke-ASH -NoBuild -NoRun -SourceDir src -OutputDir out; "
        "exit [int]$LASTEXITCODE",
        in_tmp,
        env,
    )
    assert {
        "exit_code": result.returncode,
        "first_error_line": _first_line(result.stderr),
    } == snapshot
