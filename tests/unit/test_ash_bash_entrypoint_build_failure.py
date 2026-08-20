"""The bash entrypoint must not continue after a failed container build.

`./ash` does not run under `set -e`, and it used to ignore the build's exit
status entirely. Two consequences, the second worse than the first:

1. In CI the run step then cannot find the image locally, tries to pull it from
   docker.io and quay.io, and fails with "reading manifest ci in docker.io/..."
   and exit 125 -- a registry error that says nothing about the build step that
   actually broke. Observed 2026-08-20: a transient
   "curl: (35) Recv failure: Connection reset by peer" while fetching grype's
   installer killed the build at `RUN grype --version`, and the reported error
   was about docker.io.
2. Locally, where an image from an earlier build usually *does* exist, the run
   succeeds against the stale image and `./ash` exits 0. A failed build then
   reports success, having scanned with an out-of-date toolchain.

These tests drive the real script with a fake OCI runner, because the bug lives
in the shell control flow rather than in anything importable.
"""

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ASH_SCRIPT = REPO_ROOT / "ash"

pytestmark = [
    pytest.mark.skipif(
        shutil.which("bash") is None, reason="the entrypoint under test is bash"
    ),
    pytest.mark.skipif(
        not ASH_SCRIPT.is_file(),
        reason="repository ash entrypoint not present (installed-package layout)",
    ),
]

# Mimics a real build failure: the runner fails on `build` and records anything
# else it is asked to do, so a test can tell whether the run step was reached.
FAKE_RUNNER = """#!/bin/bash
if [ "$1" = "build" ]; then
  echo 'Error: building at STEP "RUN grype --version": exit status 127' >&2
  exit 1
fi
echo "FAKE-RUNNER-INVOKED-WITH: $*"
exit 0
"""


@pytest.fixture
def failing_runner(tmp_path):
    runner = tmp_path / "fake-oci-runner"
    runner.write_text(FAKE_RUNNER)
    runner.chmod(runner.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    return runner


def run_ash(failing_runner, tmp_path):
    source_dir = tmp_path / "src"
    source_dir.mkdir(exist_ok=True)
    return subprocess.run(  # nosec B603 B607 — fixed script path, list args, no shell
        [
            "bash",
            str(ASH_SCRIPT),
            "--source-dir",
            str(source_dir),
            "--output-dir",
            str(tmp_path / "out"),
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env={**os.environ, "OCI_RUNNER": str(failing_runner)},
        timeout=180,
        check=False,
    )


def test_failed_build_exits_non_zero(failing_runner, tmp_path):
    """The headline bug: a failed build used to exit 0."""
    result = run_ash(failing_runner, tmp_path)
    assert result.returncode != 0, (
        "a failed container build must not report success; exiting 0 here means "
        "a stale local image would be scanned and the failure hidden"
    )


def test_failed_build_does_not_reach_the_run_step(failing_runner, tmp_path):
    """Reaching the run step is what turns a build error into a registry error."""
    result = run_ash(failing_runner, tmp_path)
    combined = result.stdout + result.stderr
    assert "FAKE-RUNNER-INVOKED-WITH: run" not in combined
    assert "Running ASH scan using built image" not in combined


def test_failed_build_says_the_build_failed(failing_runner, tmp_path):
    """The message has to name the build, or the next reader debugs the registry."""
    result = run_ash(failing_runner, tmp_path)
    combined = result.stdout + result.stderr
    assert "failed to build image" in combined
    # The underlying runner output must still be visible above it.
    assert "RUN grype --version" in combined
