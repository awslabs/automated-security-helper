# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the repository's ``./ash`` bash wrapper prints, and the status it exits with.

The real script runs under bash with a fake OCI runner: a shell script that records
each call, prints a canned line and exits with a chosen status. Runner discovery
then exercises the script's own ``command -v`` chain, and the build and run
statuses go through its own exit-code handling. The fake runner's path, the
caller's UID/GID and ``BUILD_DATE`` are the only values that differ between machines,
and none of them is printed except the runner path, which is fixed here.

No container runtime is needed, but the module carries ``container_runtime`` so it
runs in the scan-validation legs (tests/conftest.py deselects it elsewhere). ./ash is
a POSIX script: Windows users invoke ASH through utils/ash_helpers.ps1, and ``bash``
on a Windows runner is the WSL launcher stub. DEVELOPMENT.md forbids skipping a
snapshot test on some platforms, so instead of a Windows skip in the unit-test legs
these run on the Linux legs that use ./ash. The PowerShell wrapper's output is in
test_snapshot_container_runtime.py, in the same legs.
"""

from __future__ import annotations

import shutil
import stat
import subprocess  # nosec B404 - running the repository's own wrapper script is the point
from pathlib import Path

import pytest

from tests.snapshot.support.normalize import REPO_ROOT

ASH_SCRIPT = REPO_ROOT / "ash"

pytestmark = pytest.mark.container_runtime

#: The utilities ./ash calls besides bash builtins and the runner.
_TOOLS = ("dirname", "basename", "mkdir", "id", "date", "cat")

FAKE_RUNNER = """#!/bin/bash
echo "fake-oci-runner $1" >> "$FAKE_RUNNER_LOG"
case "$1" in
  build)
    if [ "${FAKE_BUILD_EXIT:-0}" != 0 ]; then
      echo 'Error: building at STEP "RUN grype --version": exit status 127' >&2
    fi
    exit "${FAKE_BUILD_EXIT:-0}"
    ;;
  run)
    echo "(container output)"
    exit "${FAKE_RUN_EXIT:-0}"
    ;;
esac
"""


@pytest.fixture
def bare_path(tmp_path: Path) -> Path:
    """A PATH holding only the tools ./ash needs, so no real runner is found on it."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in _TOOLS:
        found = shutil.which(tool)
        assert found, f"{tool} is not installed; ./ash needs it"
        (bin_dir / tool).symlink_to(found)
    return bin_dir


@pytest.fixture
def fake_runner(bare_path: Path) -> Path:
    runner = bare_path / "docker"
    runner.write_text(FAKE_RUNNER, encoding="utf-8")
    runner.chmod(runner.stat().st_mode | stat.S_IXUSR)
    return runner


@pytest.fixture
def run_wrapper(tmp_path: Path, bare_path: Path):
    bash = shutil.which("bash")
    assert bash, "the wrapper under test is a bash script"
    log = tmp_path / "runner.log"
    (tmp_path / "src").mkdir()

    def _run(*args: str, **env: str) -> dict:
        result = subprocess.run(  # nosec B603 - fixed interpreter and script, list args
            [
                bash,
                str(ASH_SCRIPT),
                "--source-dir",
                "src",
                "--output-dir",
                "out",
                *args,
            ],
            cwd=tmp_path,
            env={
                "PATH": str(bare_path),
                "HOME": str(tmp_path),
                "FAKE_RUNNER_LOG": str(log),
                **env,
            },
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        return {
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "runner_calls": log.read_text(encoding="utf-8").splitlines()
            if log.exists()
            else [],
        }

    return _run


def test_no_runner_found(run_wrapper, snapshot):
    assert run_wrapper() == snapshot


def test_failed_build_stops_before_the_run(run_wrapper, snapshot, fake_runner):
    assert run_wrapper(FAKE_BUILD_EXIT="3") == snapshot


@pytest.mark.parametrize("status", [0, 2, 125])
def test_run_status_is_the_wrapper_status(status, run_wrapper, snapshot, fake_runner):
    assert run_wrapper("--no-build", FAKE_RUN_EXIT=str(status)) == snapshot


def test_malformed_base_oci_layout(run_wrapper, snapshot, fake_runner):
    assert run_wrapper(ASH_BASE_OCI_LAYOUT="/layouts/base") == snapshot


def test_base_image_override_is_announced(run_wrapper, snapshot, fake_runner):
    assert (
        run_wrapper("--no-run", ASH_BASE_IMAGE_OVERRIDE="mirror.example/python:3.12")
        == snapshot
    )
