# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The directory tool claims the runner's ownership of the entry before it touches the directory.

``mcp_scan_directory`` registered the scan, created its output directory, set
the previous results aside and started the runner's task, and only the runner,
once its task first ran, marked the entry as having a runner (``has_runner``).
A progress poll in between read a PENDING entry with no runner, which the
registry closes from the results file (``check_scan_progress``), and the file
was gone or unreadable because the previous results had just been set aside:
the scan was closed FAILED before it ran. The tool now records the claim as
soon as the registry holds the scan, so a poll in that window reads a scan in
progress, and every way out of the tool that leaves no runner to settle the
entry (an output directory that cannot be created, a task that cannot start or
never runs) marks the runner done, so the entry does not keep its directory for
the server's life (``occupies_its_directory``).
"""

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.utils.log import ASHLogger
from tests.utils.scan_task_stubs import end_the_scans_scope_as_its_task_would

pytestmark = pytest.mark.unit

_TOOLS = "automated_security_helper.cli.mcp_tools"
_RESULTS = "ash_aggregated_results.json"


def _a_start_that_never_runs(scan_id, runner, **_start_options):
    # The task never runs: the window between the tool's return and the
    # runner's first step, held open. The scope ends as the task's completion
    # would end it.
    runner.close()
    end_the_scans_scope_as_its_task_would()


def _the_only_scan(registry):
    scans = registry.list_scans()
    if len(scans) != 1:
        raise RuntimeError(("control: expected one registered scan", scans))
    return registry.get_scan(scans[0]["scan_id"])


def test_a_poll_before_the_runner_starts_reads_a_scan_in_progress(
    tmp_path, monkeypatch
):
    """Red at the base: with previous results set aside and no runner yet, the
    poll closed the PENDING entry FAILED from the unreadable results file."""
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    output = tmp_path / ".ash" / "ash_output"
    output.mkdir(parents=True)
    (output / _RESULTS).write_text("{not results")
    registry = ScanRegistry()

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        patch(f"{_TOOLS}._start_scan_task", side_effect=_a_start_that_never_runs),
    ):
        started = asyncio.run(
            mcp_tools.mcp_scan_directory(str(tmp_path), clean_output=True)
        )
        if started.get("success") is not True:
            raise RuntimeError(("control: the scan did not start", started))
        entry = _the_only_scan(registry)
        progress = registry.check_scan_progress(started["scan_id"])

    assert entry.has_runner is True, "the tool did not claim the runner"
    assert entry.status == MCScanStatus.PENDING, (
        "the poll closed the scan before its runner ran",
        entry.status,
        entry.error_message,
    )
    assert progress["status"] == "pending", progress
    assert progress["is_complete"] is False, progress


def test_an_unmakeable_output_directory_leaves_no_claim_behind(tmp_path, monkeypatch):
    """The claim is made before the directory is created, so the refusal that
    follows a directory that cannot be made marks the runner done: the entry
    is closed and does not hold its directory."""
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    registry = ScanRegistry()
    real_mkdir = Path.mkdir

    def an_unmakeable_output(self, *args, **kwargs):
        if self.name == "ash_output":
            raise OSError(13, "denied by policy")
        return real_mkdir(self, *args, **kwargs)

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        patch(f"{_TOOLS}._start_scan_task", side_effect=_a_start_that_never_runs),
        patch.object(Path, "mkdir", an_unmakeable_output),
    ):
        refused = asyncio.run(mcp_tools.mcp_scan_directory(str(tmp_path)))
    entry = _the_only_scan(registry)

    if refused.get("success") is not False:
        raise RuntimeError(("control: the scan was not refused", refused))
    assert entry.status == MCScanStatus.FAILED, entry.status
    assert entry.runner_done.is_set(), "the refused scan never marked its runner done"
    assert not entry.occupies_its_directory(), "the scan still holds its directory"


def test_a_task_that_cannot_start_leaves_no_claim_behind(tmp_path, monkeypatch):
    """The give-back of a registered scan whose task could not be started marks
    the runner done too, so the claim made at registration does not hold the
    directory."""
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    registry = ScanRegistry()

    def a_start_that_fails(scan_id, runner, **_start_options):
        runner.close()
        raise RuntimeError("the task could not be started")

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        patch(f"{_TOOLS}._start_scan_task", side_effect=a_start_that_fails),
    ):
        failed = asyncio.run(mcp_tools.mcp_scan_directory(str(tmp_path)))
    entry = _the_only_scan(registry)

    if failed.get("success") is not False:
        raise RuntimeError(("control: the start did not fail", failed))
    assert entry.status == MCScanStatus.FAILED, entry.status
    assert entry.runner_done.is_set(), "the failed start never marked its runner done"
    assert not entry.occupies_its_directory(), "the scan still holds its directory"
