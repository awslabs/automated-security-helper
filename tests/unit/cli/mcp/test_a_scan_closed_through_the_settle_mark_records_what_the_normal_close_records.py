# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One scan, one record, whichever path closes the entry.

What the code does, by path
---------------------------
A scan whose thread has kept its results is closed on one of two paths:

* the runner's own close, when the thread returns and the loop resumes the runner;
* the close through the settle mark, when the runner fails (the loop cancelling
  its task) after the thread decided the scan has results and before the
  previous results' drop ends.

Both record the same three facts from the same scan: the status, the coverage
payload and the severity threshold the findings were judged by. The facts are
worked out once, on the scan's thread, when the thread decides, and both closes
read them. Before, the close through the mark recorded the exit's own payload
for an incomplete scan, where the runner's close prefers the coverage facts it
assesses from the results, and recorded no coverage and no threshold for a
completed one.

How the cells work
------------------
Each cell runs the same stand-in scan twice through the real runner: once left
alone, and once with its task cancelled while the drop of the previous results is
held open. The two entries are compared, so the cell holds whichever rule the
runner's own close follows. Every cell is DISARMED: the scan is a stand-in
defined in this file, the output directory is the cell's own tmp_path, and the
drop and the restore are the real ones over an empty previous-results area.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable, NamedTuple, Optional, Tuple
from unittest.mock import patch

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
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

_TOOLS = "automated_security_helper.cli.mcp_tools"
HOLD_SECONDS = 30.0
THRESHOLD = "HIGH"


def _results(*, missing: bool) -> AshAggregatedResults:
    """Results with scanners in them, and a config that names a threshold.

    With ``missing`` a selected scanner did not run, so the coverage facts name a
    gap. The gate is off, so a scan that simply returns these is completed with
    the gap reported, as an operator who accepted it would see.
    """
    model = AshAggregatedResults()
    model.scanner_results = {
        "bandit": ScannerTargetStatusInfo(status=ScannerStatus.PASSED),
        "grype": ScannerTargetStatusInfo(
            status=ScannerStatus.MISSING if missing else ScannerStatus.PASSED
        ),
    }
    model.metadata.expected_scanners = ["bandit", "grype"]
    model.ash_config = AshConfig(
        fail_on_incomplete_scanners=False,
        global_settings={"severity_threshold": THRESHOLD},
    )
    return model


class _Closed(NamedTuple):
    """What a run left: the entry, and for a cancelled run what it held mid-drop."""

    entry: Any
    #: (status, coverage, severity threshold) read while the drop of the previous
    #: results was still held open, so the entry can only have been closed by the
    #: close through the mark; None for a run that was left alone.
    during: Optional[Tuple[Any, Any, Any]]


async def _the_entry_after(
    tmp_path: Path,
    monkeypatch,
    run: Callable[..., Any],
    *,
    cancelled_in_the_drop: bool,
    name: str,
) -> _Closed:
    """Run ``run`` as the scan through the real runner and return its entry.

    A cancelled run also returns what the entry held before the drop was released,
    and asserts that the runner task ended cancelled. A run left alone asserts that
    its runner ended without an error.
    """
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    project = tmp_path / name
    output_dir = project / ".ash" / "ash_output"
    output_dir.mkdir(parents=True)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(project), output_directory=str(output_dir)
    )
    window = TheDropWindow(HOLD_SECONDS)
    entered, release = window.entered, window.release

    patches = [
        patch.object(ras, "run_ash_scan", run),
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
    ]
    if cancelled_in_the_drop:
        patches.extend(window.patches)
    entry = registry.get_scan(scan_id)
    assert entry is not None
    for manager in patches:
        manager.start()
    try:
        runner = asyncio.create_task(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(project),
                output_dir=str(output_dir),
                severity_threshold=None,
            )
        )
        during: Optional[Tuple[Any, Any, Any]] = None
        if cancelled_in_the_drop:
            try:
                assert await asyncio.to_thread(entered.wait, HOLD_SECONDS), (
                    "control: the previous results' drop never began"
                )
                runner.cancel()
                await asyncio.wait([runner], timeout=HOLD_SECONDS)
                # Read before the drop is released: nothing the thread does after
                # the drop has run, so the entry holds what the close through the
                # mark recorded.
                during = (entry.status, entry.coverage, entry.severity_threshold)
            finally:
                release.set()
        else:
            await asyncio.wait([runner], timeout=HOLD_SECONDS)
        assert await asyncio.to_thread(entry.runner_done.wait, HOLD_SECONDS), (
            "control: the scan's thread never settled"
        )
        if cancelled_in_the_drop:
            assert runner.cancelled(), "control: the runner task was not cancelled"
        else:
            # Raises what the runner raised, so a crash in its own close fails here
            # and not as a status that happens to match.
            runner.result()
    finally:
        release.set()
        for manager in reversed(patches):
            manager.stop()
    return _Closed(entry, during)


@pytest.mark.asyncio
async def test_a_completed_scan_closed_through_the_mark_records_its_coverage_and_threshold(
    tmp_path, monkeypatch
):
    results = _results(missing=True)

    def a_scan_that_returns_its_results(*args: Any, **kwargs: Any) -> Any:
        return results

    alone_run = await _the_entry_after(
        tmp_path,
        monkeypatch,
        a_scan_that_returns_its_results,
        cancelled_in_the_drop=False,
        name="alone",
    )
    cancelled_run = await _the_entry_after(
        tmp_path,
        monkeypatch,
        a_scan_that_returns_its_results,
        cancelled_in_the_drop=True,
        name="cancelled",
    )
    alone, cancelled = alone_run.entry, cancelled_run.entry

    # Controls: what the runner's own close records is the assessed facts and the
    # threshold, and they name the gap.
    assert alone.status == MCScanStatus.COMPLETED, alone.status
    assert alone.coverage == assess_coverage(results)[1]
    assert alone.coverage["incomplete_scanners"], alone.coverage
    assert alone.severity_threshold == THRESHOLD, alone.severity_threshold
    # The close through the mark records the same, and had already done so while the
    # drop was held: the runner's own close never ran for this entry.
    assert cancelled_run.during == (
        alone.status,
        alone.coverage,
        alone.severity_threshold,
    ), cancelled_run.during
    assert cancelled.status == MCScanStatus.COMPLETED, cancelled.status
    assert cancelled.coverage == alone.coverage
    assert cancelled.severity_threshold == alone.severity_threshold


@pytest.mark.asyncio
async def test_an_incomplete_scan_closed_through_the_mark_records_the_coverage_the_runner_does(
    tmp_path, monkeypatch
):
    results = _results(missing=True)
    results.ash_config = AshConfig(global_settings={"severity_threshold": THRESHOLD})
    # The exit's own reasons differ from the facts assessed from the results, so a
    # close that records the exit's payload is told from one that assesses.
    exit_reasons = ras.ScanIncompleteness(
        scanners=(("bandit", "ERROR"),), observed=(("bandit", "ERROR"),)
    )

    def a_scan_that_exits_incomplete(*args: Any, **kwargs: Any) -> Any:
        raise ras.ScanIncompleteExit(exit_reasons, results)

    alone_run = await _the_entry_after(
        tmp_path,
        monkeypatch,
        a_scan_that_exits_incomplete,
        cancelled_in_the_drop=False,
        name="alone",
    )
    cancelled_run = await _the_entry_after(
        tmp_path,
        monkeypatch,
        a_scan_that_exits_incomplete,
        cancelled_in_the_drop=True,
        name="cancelled",
    )
    alone, cancelled = alone_run.entry, cancelled_run.entry

    assert alone.status == MCScanStatus.INCOMPLETE, alone.status
    assert alone.coverage == assess_coverage(results)[1]
    assert alone.coverage != exit_reasons.to_payload()
    assert alone.severity_threshold == THRESHOLD, alone.severity_threshold
    assert cancelled_run.during == (
        alone.status,
        alone.coverage,
        alone.severity_threshold,
    ), cancelled_run.during
    assert cancelled.status == MCScanStatus.INCOMPLETE, cancelled.status
    assert cancelled.coverage == alone.coverage
    assert cancelled.severity_threshold == alone.severity_threshold


@pytest.mark.asyncio
async def test_an_incomplete_scan_whose_results_show_no_gap_records_the_exits_reasons(
    tmp_path, monkeypatch
):
    """The coverage of an incomplete scan is the facts assessed from its results
    when they name a gap, and the exit's own reasons when they do not: the exit code
    was decided on those reasons, so they are never empty. Both closes follow that
    rule. The sibling test for a runner cancelled mid-settlement uses results with
    nothing in them, which is this case."""
    results = _results(missing=False)
    results.ash_config = AshConfig(global_settings={"severity_threshold": THRESHOLD})
    assert not coverage_has_gap(assess_coverage(results)[1]), (
        "control: these results name a gap"
    )
    exit_reasons = ras.ScanIncompleteness(
        scanners=(("bandit", "ERROR"),), observed=(("bandit", "ERROR"),)
    )

    def a_scan_that_exits_incomplete(*args: Any, **kwargs: Any) -> Any:
        raise ras.ScanIncompleteExit(exit_reasons, results)

    alone_run = await _the_entry_after(
        tmp_path,
        monkeypatch,
        a_scan_that_exits_incomplete,
        cancelled_in_the_drop=False,
        name="alone",
    )
    cancelled_run = await _the_entry_after(
        tmp_path,
        monkeypatch,
        a_scan_that_exits_incomplete,
        cancelled_in_the_drop=True,
        name="cancelled",
    )
    alone, cancelled = alone_run.entry, cancelled_run.entry

    assert alone.status == MCScanStatus.INCOMPLETE, alone.status
    assert alone.coverage == exit_reasons.to_payload(), alone.coverage
    assert cancelled_run.during == (
        alone.status,
        alone.coverage,
        alone.severity_threshold,
    ), cancelled_run.during
    assert cancelled.coverage == alone.coverage


@pytest.mark.asyncio
async def test_a_scan_that_exited_zero_records_the_same_either_way(
    tmp_path, monkeypatch
):
    """Control: an exit 0 carries no results model, so there is no coverage and no
    threshold to record on either path."""

    def a_scan_that_exits_zero(*args: Any, **kwargs: Any) -> Any:
        raise SystemExit(0)

    alone_run = await _the_entry_after(
        tmp_path,
        monkeypatch,
        a_scan_that_exits_zero,
        cancelled_in_the_drop=False,
        name="alone",
    )
    cancelled_run = await _the_entry_after(
        tmp_path,
        monkeypatch,
        a_scan_that_exits_zero,
        cancelled_in_the_drop=True,
        name="cancelled",
    )
    alone, cancelled = alone_run.entry, cancelled_run.entry

    assert cancelled_run.during is not None
    assert cancelled_run.during[0] == MCScanStatus.COMPLETED, cancelled_run.during
    assert alone.status == MCScanStatus.COMPLETED, alone.status
    assert cancelled.status == MCScanStatus.COMPLETED, cancelled.status
    assert alone.coverage is None and cancelled.coverage is None
    assert alone.severity_threshold == cancelled.severity_threshold
