# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The coverage a single scan stores names no server process id to a remote caller.

A scanner whose tool ASH could not end ends the scan incomplete, and the
reason names the tool's process id (``could_not_stop_default``). The cancel
warning withholds that id from a network transport, and the workspace tool's
projection and stored coverage withhold it from a remote caller
(``subprocess_utils.without_process_ids``), but the single scan's runner stored
the coverage as the exit carried it, so a later ``get_scan_progress`` by a
remote client read a server-side pid it cannot act on. The runner now stores
the rows as the caller may see them: a remote caller's coverage carries the
reason without its pid, a local caller's keeps it.

Driven through the real runner with only ``run_ash_scan`` replaced by an exit
for incomplete coverage, so the close travels the production arms into the
registry entry.
"""

import asyncio
from pathlib import Path

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import sandbox
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)

pytestmark = pytest.mark.unit

REASON = "bandit's tool was still running after the scan ended (pid 4242)"


def _a_complete_result() -> AshAggregatedResults:
    # Every expected scanner ran, so the facts assessed from the results name
    # no gap and the close keeps the exit's own payload, which carries the row.
    model = AshAggregatedResults()
    model.scanner_results = {
        "bandit": ScannerTargetStatusInfo(status=ScannerStatus.PASSED)
    }
    model.metadata.expected_scanners = ["bandit"]
    return model


class _AnIncompletenessWithAnOddRow(ras.ScanIncompleteness):
    """The payload of a tool that outlived the scan, with a row that is no mapping."""

    def to_payload(self):
        payload = super().to_payload()
        payload["could_not_stop"] = [*payload["could_not_stop"], REASON]
        return payload


def _close_a_scan_whose_tool_could_not_stop(
    tmp_path: Path, *, remote: bool, odd_row: bool = False
):
    source = tmp_path / "proj"
    source.mkdir()
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )
    incompleteness_type = (
        _AnIncompletenessWithAnOddRow if odd_row else ras.ScanIncompleteness
    )

    def a_scan_whose_tool_could_not_stop(**_options):
        raise ras.ScanIncompleteExit(
            incompleteness_type(could_not_stop=(("bandit", REASON),)),
            _a_complete_result(),
        )

    with (
        pytest.MonkeyPatch.context() as patch,
    ):
        patch.setattr(ras, "run_ash_scan", a_scan_whose_tool_could_not_stop)
        patch.setattr(mcp_tools, "get_scan_registry", lambda: registry)
        patch.setattr(sandbox, "caller_is_remote", lambda session_id: remote)
        asyncio.run(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(source),
                output_dir=str(output),
                severity_threshold=None,
            )
        )
    return registry.get_scan(scan_id)


def test_a_remote_callers_stored_coverage_names_the_tool_and_not_its_pid(tmp_path):
    entry = _close_a_scan_whose_tool_could_not_stop(tmp_path, remote=True)

    assert entry.status == MCScanStatus.INCOMPLETE, (entry.status, entry.error_message)
    assert entry.coverage["could_not_stop"] == [
        {
            "scanner": "bandit",
            "reason": "bandit's tool was still running after the scan ended",
        }
    ], entry.coverage


def test_a_local_callers_stored_coverage_keeps_the_pid(tmp_path):
    entry = _close_a_scan_whose_tool_could_not_stop(tmp_path, remote=False)

    assert entry.status == MCScanStatus.INCOMPLETE, (entry.status, entry.error_message)
    assert entry.coverage["could_not_stop"] == [
        {"scanner": "bandit", "reason": REASON}
    ], entry.coverage


def test_a_row_that_cannot_be_redacted_does_not_leave_the_entry_running(tmp_path):
    """Red at the base: the redaction ran outside the close's guard, so a row that
    is no mapping raised out of the settle step and the entry stayed running.
    The close now stores the rows without their reasons, the gap still counted,
    and no process id reaches the entry."""
    entry = _close_a_scan_whose_tool_could_not_stop(tmp_path, remote=True, odd_row=True)

    assert entry.status == MCScanStatus.INCOMPLETE, (entry.status, entry.error_message)
    assert entry.coverage["could_not_stop"] == [
        {"scanner": "bandit"},
        {"scanner": "unknown"},
    ], entry.coverage
    assert "4242" not in str(entry.coverage), entry.coverage
