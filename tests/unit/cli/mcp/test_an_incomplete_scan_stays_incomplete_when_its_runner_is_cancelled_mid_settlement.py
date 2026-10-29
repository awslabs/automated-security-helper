# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan that kept its results keeps the status those results earned.

The scan's thread settles the previous results in two steps: under
``settle_decision`` it decides the scan has results of its own and marks it so,
then it drops the previous scan's results (disk work) and ends. A runner failure
that arrives between the mark and the end closes the entry from the mark.

The mark is set for every ending that has results of its own: a clean return, an
exit 0, and an exit for incomplete coverage. The close from the mark has to
record which of them it was. A scan that ended for incomplete coverage is closed
``incomplete`` with its coverage gap; one that returned or exited 0 is closed
``completed``.

The window is held open deterministically: the drop of the previous results
waits on an event the test releases after the runner has been cancelled.

Every cell is DISARMED: the scan is a stand-in defined in this file, the output
directory is the cell's own tmp_path, and the drop and the restore are the real
ones over an empty previous-results area. No scanner or network is involved.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.resource_management.scan_tracking import (
    assess_coverage,
    coverage_has_gap,
)
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from tests.utils.drop_window import TheDropWindow

pytestmark = pytest.mark.unit

_TOOLS = "automated_security_helper.cli.mcp_tools"
#: How long a held drop waits before it gives up: far past any cell, so a cell
#: that fails early cannot leave a thread behind for long.
HOLD_SECONDS = 30.0


def _the_incompleteness() -> "ras.ScanIncompleteness":
    return ras.ScanIncompleteness(
        scanners=(("bandit", "ERROR"),), observed=(("bandit", "ERROR"),)
    )


async def _cancel_the_runner_inside_the_drop(tmp_path: Path, monkeypatch, run: Any):
    """Run the real runner over ``run``, cancel its task while the drop of the
    previous results is held open, then let the drop finish.

    Returns the registry entry once the scan's thread has settled, with the
    status, error and cancel-event state read while the drop was still held.
    """
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    output_dir = tmp_path / ".ash" / "ash_output"
    output_dir.mkdir(parents=True)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(tmp_path), output_directory=str(output_dir)
    )
    window = TheDropWindow(HOLD_SECONDS)
    with (
        patch.object(ras, "run_ash_scan", run),
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        window.patches[0],
        window.patches[1],
    ):
        runner = asyncio.create_task(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(tmp_path),
                output_dir=str(output_dir),
                severity_threshold=None,
            )
        )
        entry = registry.get_scan(scan_id)
        assert entry is not None
        try:
            assert await asyncio.to_thread(window.entered.wait, HOLD_SECONDS), (
                "control: the previous results' drop never began"
            )
            runner.cancel()
            await asyncio.wait([runner], timeout=HOLD_SECONDS)
            during = (
                entry.status,
                entry.error_message,
                entry.cancel_event.is_set(),
                entry.coverage,
            )
        finally:
            window.release.set()
        assert await asyncio.to_thread(entry.runner_done.wait, HOLD_SECONDS), (
            "control: the scan's thread never settled"
        )
    return entry, runner, window, during


@pytest.mark.asyncio
async def test_an_incomplete_scan_cancelled_inside_the_drop_is_closed_incomplete(
    tmp_path, monkeypatch
):
    """The scan exits for incomplete coverage, its thread marks it as one with
    results and starts dropping the previous results, and the loop cancels the
    runner task. The close from the mark records the outcome the thread
    decided: incomplete, with the coverage payload the exit carried. The results
    here are empty, so they name no gap and the exit's own reasons are what is
    recorded; the next test gives the exit results that do name a gap."""
    incompleteness = _the_incompleteness()

    def a_scan_that_exits_incomplete(*args: Any, **kwargs: Any) -> None:
        raise ras.ScanIncompleteExit(incompleteness, AshAggregatedResults())

    entry, runner, window, during = await _cancel_the_runner_inside_the_drop(
        tmp_path, monkeypatch, a_scan_that_exits_incomplete
    )
    status, error, event_set, coverage = during

    # Controls: the drop ran once, was in progress when the runner was
    # cancelled, and nothing was put back; the runner task ended cancelled.
    assert len(window.drops) == 1, window.drops
    assert window.restores == [], window.restores
    assert runner.cancelled(), runner
    assert status == MCScanStatus.INCOMPLETE, (status, error)
    assert coverage == incompleteness.to_payload(), coverage
    assert error is None, error
    assert event_set is False, event_set
    assert entry.status == MCScanStatus.INCOMPLETE, entry.status


@pytest.mark.asyncio
async def test_an_incomplete_scan_whose_results_name_a_gap_records_the_assessed_coverage(
    tmp_path, monkeypatch
):
    """The same cancellation over an exit whose results name a gap: the coverage
    recorded is the facts assessed from those results, not the exit's own reasons.
    Together with the test above this tells "assess from the results, fall back to
    the exit" from "record the exit's payload"."""
    incompleteness = _the_incompleteness()
    results = AshAggregatedResults()
    results.scanner_results = {
        "grype": ScannerTargetStatusInfo(status=ScannerStatus.MISSING)
    }
    results.metadata.expected_scanners = ["grype"]
    assessed = assess_coverage(results)[1]
    assert coverage_has_gap(assessed), "control: these results name no gap"
    assert assessed != incompleteness.to_payload()

    def a_scan_that_exits_incomplete(*args: Any, **kwargs: Any) -> None:
        raise ras.ScanIncompleteExit(incompleteness, results)

    entry, runner, window, during = await _cancel_the_runner_inside_the_drop(
        tmp_path, monkeypatch, a_scan_that_exits_incomplete
    )
    status, error, event_set, coverage = during

    assert len(window.drops) == 1 and window.restores == [], window.drops
    assert runner.cancelled(), runner
    assert status == MCScanStatus.INCOMPLETE, (status, error)
    assert coverage == assessed, coverage
    assert entry.coverage == assessed, entry.coverage


@pytest.mark.asyncio
async def test_a_scan_that_exited_zero_cancelled_inside_the_drop_stays_completed(
    tmp_path, monkeypatch
):
    """Control for the cell above: the same cancellation over a scan that
    exited 0 is closed completed with no coverage gap attached, so recording the
    outcome does not turn every marked scan incomplete."""

    def a_scan_that_exits_zero(*args: Any, **kwargs: Any) -> None:
        raise SystemExit(0)

    entry, runner, window, during = await _cancel_the_runner_inside_the_drop(
        tmp_path, monkeypatch, a_scan_that_exits_zero
    )
    status, error, event_set, coverage = during

    assert len(window.drops) == 1, window.drops
    assert window.restores == [], window.restores
    assert runner.cancelled(), runner
    assert status == MCScanStatus.COMPLETED, (status, error)
    assert coverage is None, coverage
    assert error is None, error
    assert event_set is False, event_set
