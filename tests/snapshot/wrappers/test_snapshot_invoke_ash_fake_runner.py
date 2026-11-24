# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ``Invoke-ASH`` hands to the container runner, and what it returns, on every OS.

``utils/ash_helpers.ps1`` has no real-runtime scan leg on Windows: hosted
``windows-latest`` runners cannot run Linux containers, and ASH's image is one. This
module runs the real helper end to end up to that boundary instead. ``Invoke-ASH``
runs under real ``pwsh`` against the recording stand-ins for finch, docker, nerdctl and
podman that ``tests/unit/test_powershell_wrapper_matches_ash.py`` defines (a PowerShell
function is found by ``Get-Command`` before any program on PATH, on every platform),
and the snapshots pin what crosses the boundary (the build and run commands, the
``-e`` pairs, the mounts) and what comes back (``$LASTEXITCODE``, throw rather than
exit, the announcement, the error text).

It needs no container runtime, so it is not marked ``container_runtime`` and is not
deselected: it runs in the normal test tiers on every unit and integration leg, the
Windows ones included. There is one snapshot per test, shared by Linux, macOS and
Windows (DEVELOPMENT.md, "Snapshot tests": no platform skips, no per-runner
snapshots), so a divergence in command assembly on one OS fails that OS's leg by
name. Two things make that hold:

* every input whose default depends on the platform is passed explicitly: the build
  target (``ci`` on Windows, ``non-root`` elsewhere), the container UID and GID
  (looked up on Unix, absent on Windows) and the runner;
* every value that depends on the machine is normalized before the comparison: the
  absolute paths by the suite's normalizer in every spelling, the day's
  ``BUILD_DATE_EPOCH`` by :func:`_without_the_build_date`, and the console size the
  wrapper forwards by :func:`_without_the_terminal_size`.

Regenerate with ``pytest tests/snapshot/wrappers -n 0 --run-integration
--snapshot-update`` on any host with ``pwsh`` 7 on PATH. ``--run-integration`` is
required: the module is marked ``integration``, and without the flag every test is
skipped, so nothing is written. The fake-runner helpers are
imported from the parity suite; moving them to ``tests/utils`` is the cleanup once the
open changes to that file have landed.
"""

from __future__ import annotations

import os
import re

import pytest

from tests.snapshot.support.powershell import error_message
from tests.unit.test_powershell_wrapper_matches_ash import (
    PWSH,
    _build_call,
    _invoke,
    _run_call,
    _run_env,
    _run_script,
)

pytestmark = pytest.mark.integration

#: Whether a CI runner started pytest. Read at import, during collection: the snapshot
#: conftest's autouse fixture deletes CI and GITHUB_ACTIONS from ``os.environ`` before
#: any other fixture body runs, so a read inside a fixture would always see them unset.
_IN_CI = any(
    os.environ.get(name, "").strip().lower() not in ("", "false", "0")
    for name in ("CI", "GITHUB_ACTIONS")
)

#: Two inputs that read the base image from the environment of whoever runs the test.
#: A CI leg that prepulled a base image sets them; an empty value is unset to pwsh.
_NO_BASE_IMAGE_OVERRIDES = {"ASH_BASE_OCI_LAYOUT": "", "ASH_BASE_IMAGE_OVERRIDE": ""}


@pytest.fixture(autouse=True)
def _require_pwsh() -> None:
    # The parity suite's gate does not travel across modules. The snapshot fixtures
    # unset CI, so the decision uses the import-time read above, not os.environ now.
    if PWSH is None:
        if _IN_CI:
            pytest.fail("pwsh is not on PATH; CI runners must run these tests")
        pytest.skip("pwsh is not on PATH (local run only; CI fails instead)")


def _without_the_build_date(argv: list[str]) -> list[str]:
    """``BUILD_DATE_EPOCH`` is UTC midnight of the day the test runs."""
    return [re.sub(r"(BUILD_DATE_EPOCH=)\d+", r"\1<epoch>", arg) for arg in argv]


def _without_the_terminal_size(argv: list[str]) -> list[str]:
    """The wrapper hands the container the console's size, which is the machine's."""
    return [re.sub(r"^(COLUMNS|LINES)=(-?\d+)?$", r"\1=<size>", arg) for arg in argv]


def test_invoke_ash_scan_command_assembly_is_the_same_on_every_os(snapshot, tmp_path):
    result, calls = _invoke(
        tmp_path,
        "Invoke-ASH -SourceDir src -OutputDir out -BuildTarget ci "
        "-ContainerUID 1500 -ContainerGID 1500 -OCIRunner docker -Scanners bandit",
        **_NO_BASE_IMAGE_OVERRIDES,
    )
    run_call = _without_the_terminal_size(_run_call(result, calls))
    assert {
        "exit_code": result.returncode,
        "announced_the_run": "Running ASH scan using built image..." in result.stdout,
        "build_argv": _without_the_build_date(_build_call(result, calls)),
        "run_argv": run_call,
        "run_env": _run_env(run_call),
    } == snapshot


def test_invoke_ash_without_a_runner(snapshot, tmp_path):
    # OCI_RUNNER names nothing that resolves, and -NoBuild -NoRun stop the wrapper
    # before it would use anything else. The refusal is thrown, not exited, so it
    # ends this script and not a caller's session.
    result, calls = _invoke(
        tmp_path,
        "Invoke-ASH -NoBuild -NoRun -SourceDir src -OutputDir out",
        OCI_RUNNER="no-such-oci-runner",
        **_NO_BASE_IMAGE_OVERRIDES,
    )
    assert calls == []
    assert {
        "exit_code": result.returncode,
        "error_message": error_message(result.stderr),
    } == snapshot


def test_invoke_ash_default_runner_discovery(snapshot, tmp_path):
    # No -OCIRunner, no OCI_RUNNER and no ASH_OCI_RUNNER. The stand-ins make the
    # discovery deterministic: the first element of the run command is the runner
    # the wrapper chose, finch first as ./ash and the CLI do.
    result, calls = _invoke(
        tmp_path,
        "Invoke-ASH -NoBuild -SourceDir src -OutputDir out",
        **_NO_BASE_IMAGE_OVERRIDES,
    )
    assert {
        "exit_code": result.returncode,
        "chosen_runner": _run_call(result, calls)[0],
    } == snapshot


def test_a_failed_build_exits_with_the_builds_code(snapshot, tmp_path):
    # The build stand-in exits 1. The wrapper throws, so the script ends with the
    # error and the run stand-in is never called.
    result, calls = _run_script(
        tmp_path,
        "$rc = Invoke-ASH -SourceDir src -OutputDir out -BuildTarget ci "
        "-ContainerUID 1500 -ContainerGID 1500 -OCIRunner docker\n"
        "exit [int]$LASTEXITCODE\n",
        build_exit=1,
        **_NO_BASE_IMAGE_OVERRIDES,
    )
    assert {
        "exit_code": result.returncode,
        "runner_commands": [call[1] for call in calls],
        "error_message": error_message(result.stderr),
    } == snapshot
