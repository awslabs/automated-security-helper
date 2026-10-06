# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression test: ``Invoke-ASH`` without ``-OCIRunner`` discovers a runner on PATH.

``-OCIRunner`` is a ``[string]`` parameter defaulting to ``$env:ASH_OCI_RUNNER``.
With that variable unset PowerShell binds ``""``, not ``$null``, so the
``$null -ne $OCIRunner`` test always chose the one-element list ``@("")``,
``Get-Command`` rejected the empty name, and every call that did not name a runner
failed with "Unable to resolve an OCI_RUNNER". An empty value now falls back to
discovery, as the bash wrapper's ``${OCI_RUNNER:-$(command -v ...)}`` does.

Executed under ``pwsh`` rather than asserted as text, because the defect is in how
PowerShell binds the parameter, which no reading of the script shows. Skipped only
on a developer machine without ``pwsh``; in CI a missing ``pwsh`` fails the test.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404 - running pwsh against the wrapper is the point of this test
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS = REPO_ROOT / "utils" / "ash_helpers.ps1"
PWSH = shutil.which("pwsh")

_IN_CI = "true" in (os.environ.get("CI"), os.environ.get("GITHUB_ACTIONS"))


@pytest.fixture(autouse=True)
def _require_pwsh():
    """Skip only on a developer machine without pwsh; in CI a missing pwsh is a failure.

    Every hosted runner image ships pwsh, so its absence in CI means the runner
    changed and this regression test would otherwise stop running unnoticed.
    """
    if PWSH is None:
        if _IN_CI:
            pytest.fail("pwsh is not on PATH; CI runners must run this regression test")
        pytest.skip("pwsh is not on PATH (local run only; CI fails instead)")


def _invoke(tmp_path: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    assert PWSH is not None
    (tmp_path / "src").mkdir(exist_ok=True)
    # 'Stop' so that an error which sets no $LASTEXITCODE (a parameter that fails
    # validation, say) ends the process non-zero instead of falling through to
    # `exit 0`, which would read as a pass.
    script = (
        f"$ErrorActionPreference = 'Stop'; . '{HELPERS.as_posix()}'; "
        "Invoke-ASH -NoBuild -NoRun -SourceDir src -OutputDir out -Verbose; "
        "exit [int]$LASTEXITCODE"
    )
    return subprocess.run(  # nosec B603 - fixed interpreter, script built here
        [PWSH, "-NoProfile", "-NonInteractive", "-Command", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )


@pytest.fixture
def path_with_only_docker(tmp_path) -> str:
    """A PATH whose only OCI runner is a stand-in ``docker`` that does nothing."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    if os.name == "nt":
        # Get-Command resolves "docker" through PATHEXT, so a .cmd stands in on Windows.
        (bin_dir / "docker.cmd").write_text("@exit /b 0\r\n", encoding="utf-8")
    else:
        runner = bin_dir / "docker"
        runner.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        runner.chmod(0o755)
    assert PWSH is not None
    return os.pathsep.join([bin_dir.as_posix(), Path(PWSH).resolve().parent.as_posix()])


def test_unset_ash_oci_runner_falls_back_to_discovery(tmp_path, path_with_only_docker):
    env = {k: v for k, v in os.environ.items() if k not in ("ASH_OCI_RUNNER", "PATH")}
    env["PATH"] = path_with_only_docker

    result = _invoke(tmp_path, env)

    assert "Unable to resolve an OCI_RUNNER" not in result.stderr, result.stderr
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Resolved OCI_RUNNER to: docker" in result.stdout + result.stderr


def test_empty_ash_oci_runner_falls_back_to_discovery(tmp_path, path_with_only_docker):
    env = {k: v for k, v in os.environ.items() if k != "PATH"}
    env["ASH_OCI_RUNNER"] = ""
    env["PATH"] = path_with_only_docker

    result = _invoke(tmp_path, env)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Resolved OCI_RUNNER to: docker" in result.stdout + result.stderr


def test_a_named_runner_that_is_absent_is_still_refused(
    tmp_path, path_with_only_docker
):
    env = {k: v for k, v in os.environ.items() if k != "PATH"}
    env["ASH_OCI_RUNNER"] = "no-such-oci-runner"
    env["PATH"] = path_with_only_docker

    result = _invoke(tmp_path, env)

    assert result.returncode == 1
    assert "Unable to resolve an OCI_RUNNER" in result.stderr
