# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Code that reads a run's result checks its flags before its exit code.

Why this file exists
--------------------
A run whose output ASH could not record keeps the tool's own exit code, with
``post_run_error`` and the error. When that code is 0, a reader that looks only at
the code takes the run for a clean one. ASH stopped some tools while they ran, and
those have no code at all. Three readers of ``run_command`` did that:

- ``ash dependencies install``'s command runner returned the code, so a 0 read as
  an install that worked, and a missing code reached its caller as None;
- the scanner inventory's version probe took the output of such a run as the
  tool's version;
- the container runner's buildx probe took such a run as buildx being there.

Each reader here answers what a failed run gives it, whatever the code says. The
controls show the clean case still works.
"""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import PostRunErrorProcess

#: What ASH says when it could not record a run's output.
_NOT_RECORDED = "ASH could not record the output of tool: No space left on device"


def _not_recorded(args, code, stdout: str = "") -> PostRunErrorProcess:
    """A run whose output ASH could not record, with the tool's own ``code``."""
    return PostRunErrorProcess(args, code, stdout, "", error=_NOT_RECORDED)


# -- ash dependencies install's command runner --------------------------------------


@pytest.mark.parametrize(
    "code", [pytest.param(0, id="tool-exited-0"), pytest.param(None, id="no-code")]
)
def test_the_dependency_installer_fails_a_run_ash_could_not_record(code):
    """The install command's run is no success, and the answer is a number."""
    from automated_security_helper.cli import dependencies

    with patch.object(
        subprocess_utils,
        "run_command",
        side_effect=lambda *a, **k: _not_recorded(k.get("args", ["tool"]), code),
    ):
        answer = dependencies.run_command(["pip", "install", "tool"])

    assert isinstance(answer, int) and not isinstance(answer, bool), answer
    assert answer != 0, answer


def test_control_the_dependency_installer_passes_a_clean_run():
    from automated_security_helper.cli import dependencies

    with patch.object(
        subprocess_utils,
        "run_command",
        return_value=subprocess.CompletedProcess(["pip"], 0, "", ""),
    ):
        assert dependencies.run_command(["pip", "install", "tool"]) == 0


# -- the scanner inventory's version probe ------------------------------------------


def _probed_version(result) -> object:
    from automated_security_helper.core import scanner_inventory

    with (
        patch.object(subprocess_utils, "find_executable", return_value="/opt/tool"),
        patch.object(subprocess_utils, "run_command", return_value=result),
    ):
        return scanner_inventory._probe_tool_version("tool")


def test_the_version_probe_takes_no_version_from_a_run_ash_could_not_record():
    assert _probed_version(_not_recorded(["/opt/tool"], 0, "tool 1.2.3\n")) is None


def test_control_the_version_probe_reads_a_clean_runs_version():
    clean = subprocess.CompletedProcess(["/opt/tool"], 0, "tool 1.2.3\n", "")

    assert _probed_version(clean) == "1.2.3"


# -- the container runner's buildx probe --------------------------------------------


def _buildx_found(monkeypatch, result) -> bool:
    from automated_security_helper.interactions import run_ash_container

    monkeypatch.setattr(run_ash_container, "_BUILDX_SUPPORT_CACHE", {})
    with patch.object(subprocess_utils, "run_command", return_value=result):
        return run_ash_container._runner_supports_buildx("/opt/docker")


def test_the_buildx_probe_finds_no_buildx_in_a_run_ash_could_not_record(monkeypatch):
    assert _buildx_found(monkeypatch, _not_recorded(["/opt/docker"], 0)) is False


def test_control_the_buildx_probe_finds_buildx_in_a_clean_run(monkeypatch):
    clean = subprocess.CompletedProcess(["/opt/docker"], 0, "", "")

    assert _buildx_found(monkeypatch, clean) is True
