# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression test: ``Invoke-ASH`` without ``-OCIRunner`` discovers a runner on PATH.

``-OCIRunner`` is a ``[string]`` parameter defaulting to ``$env:OCI_RUNNER`` (it read
``$env:ASH_OCI_RUNNER`` when this test was written; see
``test_powershell_wrapper_matches_ash.py`` for that rename).
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

from tests.utils.pwsh_env import inherited_env, scratch_home

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS = REPO_ROOT / "utils" / "ash_helpers.ps1"
PWSH = shutil.which("pwsh")


@pytest.fixture(autouse=True)
def _require_pwsh(in_ci: bool):
    """Skip only on a developer machine without pwsh; in CI a missing pwsh is a failure.

    Every hosted runner image ships pwsh, so its absence in CI means the runner
    changed and this regression test would otherwise stop running unnoticed.
    """
    if PWSH is None:
        if in_ci:
            pytest.fail("pwsh is not on PATH; CI runners must run this regression test")
        pytest.skip("pwsh is not on PATH (local run only; CI fails instead)")


def _invoke(tmp_path: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    assert PWSH is not None
    (tmp_path / "src").mkdir(exist_ok=True)
    # A HOME and XDG directories of the test's own, with telemetry and update checks
    # off: pwsh writes caches under them and phones home otherwise.
    env = {**env, **scratch_home(tmp_path)}
    # 'Stop' so that an error which sets no $LASTEXITCODE (a parameter that fails
    # validation, say) ends the process non-zero instead of falling through to
    # `exit 0`, which would read as a pass. The HOME line is what
    # test_pwsh_runs_with_a_home_of_the_tests_own reads.
    script = (
        f"$ErrorActionPreference = 'Stop'; Write-Output \"pwsh HOME: $HOME\"; "
        f". '{HELPERS.as_posix()}'; "
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
    """A PATH whose only OCI runner is a stand-in ``docker`` that does nothing.

    pwsh's own directory is not on it on POSIX, because it can hold a real runner
    (/usr/bin does on many hosts), and a wrapper that ignored the runner a test named
    would then find that one. A link to pwsh in a directory of its own stands in. The
    fixture fails rather than return a PATH on which any real runner resolves.
    """
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
    if os.name == "nt":
        pwsh_dir = Path(PWSH).resolve().parent
    else:
        pwsh_dir = tmp_path / "pwsh-bin"
        pwsh_dir.mkdir()
        (pwsh_dir / "pwsh").symlink_to(Path(PWSH).resolve())
    path = os.pathsep.join([bin_dir.as_posix(), pwsh_dir.as_posix()])
    for name in ("finch", "docker", "nerdctl", "podman"):
        found = shutil.which(name, path=path)
        if found is not None and Path(found).parent != bin_dir:
            pytest.fail(f"a real {name} is reachable on the test PATH: {found}")
    return path


def _env(path: str, **overrides: str) -> dict[str, str]:
    """The developer's environment without the runner variables or a shell startup
    file, on ``path``."""
    return {
        **inherited_env("OCI_RUNNER", "ASH_OCI_RUNNER", "PATH"),
        "PATH": path,
        **overrides,
    }


def test_pwsh_runs_with_a_home_of_the_tests_own(tmp_path, path_with_only_docker):
    result = _invoke(tmp_path, _env(path_with_only_docker))
    assert f"pwsh HOME: {tmp_path / 'pwsh-home'}" in result.stdout.splitlines(), (
        result.stdout
    )


def test_unset_oci_runner_falls_back_to_discovery(tmp_path, path_with_only_docker):
    env = _env(path_with_only_docker)

    result = _invoke(tmp_path, env)

    assert "Unable to resolve an OCI_RUNNER" not in result.stderr, result.stderr
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Resolved OCI_RUNNER to: docker" in result.stdout + result.stderr


def test_empty_oci_runner_falls_back_to_discovery(tmp_path, path_with_only_docker):
    env = _env(path_with_only_docker, OCI_RUNNER="")

    result = _invoke(tmp_path, env)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Resolved OCI_RUNNER to: docker" in result.stdout + result.stderr


def test_a_named_runner_that_is_absent_is_still_refused(
    tmp_path, path_with_only_docker
):
    env = _env(path_with_only_docker, OCI_RUNNER="no-such-oci-runner")

    result = _invoke(tmp_path, env)

    assert result.returncode == 1
    assert "Unable to resolve an OCI_RUNNER" in result.stderr
