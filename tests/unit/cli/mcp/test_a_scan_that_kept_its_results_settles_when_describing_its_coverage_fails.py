# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan that kept its results is settled even when describing its coverage raises.

What the code does, by path
---------------------------
When ``run_ash_scan`` ends with results in hand (a return, an exit 0, or
``ScanIncompleteExit``), the scan's thread works out how the entry will be closed
(``_close_for``: status, coverage payload, severity threshold) before it takes
the settle decision, and then drops the previous scan's results. ``_close_for`` is
documented never to raise, but it reads the exit's ``to_payload()`` and the
judged threshold without a guard of their own.

Before the guard, an error from either left the thread's settle step half done:
the mark was never set, the previous results were neither dropped nor put back,
and the error replaced the scan's own ending. The runner then took it for a
failure and closed a scan that had results on disk as failed.

Now ``_close_for`` catches the error and falls back to the status and no threshold,
once, for every caller. A
completed scan carries no coverage, and ``check_scan_progress`` assesses the
results file for the coverage the entry lacks. An incomplete one carries the gap
named by the exit's own scanner rows, because the registry refuses to close a scan
as incomplete with no gap attached. The scan is settled as one with results and
the previous results are dropped.

The same function is called a second time, from the runner's arms, for a scan whose
thread did not settle it as one with results: its cancel event was set before the
thread decided, so the thread put the previous results back and recorded no close.
Those calls were not guarded. A raise from the ``ScanIncompleteExit`` arm escaped the
task, which is a fire-and-forget task, and left the entry running; a raise from the
return arm was caught as a runner failure and closed a scan that had ended normally
as failed. ``_close_for`` is documented never to raise, so it now carries the guard
itself, and every caller is covered.

How the tests work
------------------
Each runs the real runner (``_run_scan_async``) over a stand-in scan. The drop and
the restore of the previous results are the real ones over an empty
previous-results area, recorded. Everything is DISARMED: the output directory is
the test's own tmp_path, and no scanner, network or real scan runs.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, List, Tuple
from unittest.mock import patch

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.core.previous_results import PreviousResults
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.core.resource_management.scan_tracking import (
    coverage_has_gap,
)
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

_TOOLS = "automated_security_helper.cli.mcp_tools"
HOLD_SECONDS = 30.0
# The threshold the entry is registered with. ``finish_scan`` replaces it only with a
# judged threshold, so a close that carries none leaves this one in place; it is not
# the registry's default, so a close that wrote a threshold of its own shows.
REGISTERED_THRESHOLD = "LOW"

EXIT_REASONS = ras.ScanIncompleteness(
    scanners=(("bandit", "ERROR"),), observed=(("bandit", "ERROR"),)
)


async def _run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scan: Any,
    *,
    cancel_during_the_scan: bool = False,
) -> Tuple[Any, List[PreviousResults], List[PreviousResults]]:
    """Run ``scan`` as the scan through the real runner.

    With ``cancel_during_the_scan`` the entry's cancel event is set as the scan
    starts, so the thread does not settle the scan as one with results: it puts the
    previous results back and records no close, and the runner works the close out
    itself.

    Returns the registry entry, the ``PreviousResults`` whose drop ran and the ones
    whose restore ran.
    """
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    project = tmp_path / "project"
    output_dir = project / ".ash" / "ash_output"
    output_dir.mkdir(parents=True)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(project),
        output_directory=str(output_dir),
        severity_threshold=REGISTERED_THRESHOLD,
    )
    entry = registry.get_scan(scan_id)
    assert entry is not None

    drops: List[PreviousResults] = []
    restores: List[PreviousResults] = []
    real_discard = PreviousResults.discard
    real_restore = PreviousResults.restore

    def a_drop_that_is_recorded(this: PreviousResults) -> None:
        drops.append(this)
        return real_discard(this)

    def a_restore_that_is_recorded(this: PreviousResults) -> None:
        restores.append(this)
        return real_restore(this)

    def the_scan_after_a_cancel(*args: Any, **kwargs: Any) -> Any:
        entry.cancel_event.set()
        return scan(*args, **kwargs)

    with (
        patch.object(
            ras,
            "run_ash_scan",
            the_scan_after_a_cancel if cancel_during_the_scan else scan,
        ),
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch.object(PreviousResults, "discard", a_drop_that_is_recorded),
        patch.object(PreviousResults, "restore", a_restore_that_is_recorded),
    ):
        runner = asyncio.create_task(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(project),
                output_dir=str(output_dir),
                severity_threshold=None,
            )
        )
        await asyncio.wait([runner], timeout=HOLD_SECONDS)
        assert runner.done(), "control: the runner never ended"
        runner.result()
        assert await asyncio.to_thread(entry.runner_done.wait, HOLD_SECONDS), (
            "control: the scan's thread never settled"
        )
    return entry, drops, restores


def _a_planted_failure(*args: Any, **kwargs: Any) -> Any:
    raise RuntimeError("a planted failure while describing the coverage")


def _assert_the_gap_is_the_exits_rows(coverage: Any) -> None:
    """The coverage names EXIT_REASONS' scanner, in the shape a client reads a gap in."""
    assert coverage is not None, "the entry carries no coverage"
    assert coverage_has_gap(coverage), coverage
    assert [row["scanner"] for row in coverage["incomplete_scanners"]] == ["bandit"], (
        coverage
    )


@pytest.mark.asyncio
async def test_an_exit_for_incomplete_coverage_whose_payload_cannot_be_built(
    tmp_path, monkeypatch
):
    """``to_payload`` raises on the exit. The scan has results, so it is closed as
    incomplete (not as failed), with the gap named by the exit's own scanner rows:
    the registry refuses an incomplete scan that carries no gap. The previous
    results are dropped, not restored."""
    monkeypatch.setattr(ras.ScanIncompleteness, "to_payload", _a_planted_failure)

    def a_scan_that_exits_incomplete(*args: Any, **kwargs: Any) -> Any:
        raise ras.ScanIncompleteExit(EXIT_REASONS, AshAggregatedResults())

    entry, drops, restores = await _run(
        tmp_path, monkeypatch, a_scan_that_exits_incomplete
    )

    assert entry.status == MCScanStatus.INCOMPLETE, (entry.status, entry.error_message)
    _assert_the_gap_is_the_exits_rows(entry.coverage)
    assert len(drops) == 1 and restores == [], (drops, restores)


@pytest.mark.asyncio
async def test_an_exit_for_incomplete_coverage_whose_severity_threshold_cannot_be_judged(
    tmp_path, monkeypatch
):
    """The judged threshold raises for a scan that exited for incomplete coverage.
    Working out the close fails as a whole, so the scan is closed as incomplete with
    the gap named by the exit's own rows and no judged threshold, and the previous
    results are dropped."""
    monkeypatch.setattr(mcp_tools, "_judged_threshold", _a_planted_failure)

    def a_scan_that_exits_incomplete(*args: Any, **kwargs: Any) -> Any:
        raise ras.ScanIncompleteExit(EXIT_REASONS, AshAggregatedResults())

    entry, drops, restores = await _run(
        tmp_path, monkeypatch, a_scan_that_exits_incomplete
    )

    assert entry.status == MCScanStatus.INCOMPLETE, (entry.status, entry.error_message)
    _assert_the_gap_is_the_exits_rows(entry.coverage)
    assert entry.severity_threshold == REGISTERED_THRESHOLD, entry.severity_threshold
    assert len(drops) == 1 and restores == [], (drops, restores)


@pytest.mark.asyncio
async def test_a_return_whose_severity_threshold_cannot_be_judged(
    tmp_path, monkeypatch
):
    """The judged threshold raises for a scan that returned its results: the scan
    is closed as completed with no judged threshold, so the entry keeps the one it
    was registered with, and the previous results are dropped."""
    monkeypatch.setattr(mcp_tools, "_judged_threshold", _a_planted_failure)

    def a_scan_that_returns_its_results(*args: Any, **kwargs: Any) -> Any:
        return AshAggregatedResults()

    entry, drops, restores = await _run(
        tmp_path, monkeypatch, a_scan_that_returns_its_results
    )

    assert entry.status == MCScanStatus.COMPLETED, (entry.status, entry.error_message)
    assert entry.severity_threshold == REGISTERED_THRESHOLD, entry.severity_threshold
    assert len(drops) == 1 and restores == [], (drops, restores)


@pytest.mark.asyncio
async def test_an_exit_zero_whose_severity_threshold_cannot_be_judged(
    tmp_path, monkeypatch
):
    """The same for a scan that exits 0: it has results of its own, so it is
    completed and the previous results are dropped."""
    monkeypatch.setattr(mcp_tools, "_judged_threshold", _a_planted_failure)

    def a_scan_that_exits_zero(*args: Any, **kwargs: Any) -> Any:
        raise SystemExit(0)

    entry, drops, restores = await _run(tmp_path, monkeypatch, a_scan_that_exits_zero)

    assert entry.status == MCScanStatus.COMPLETED, (entry.status, entry.error_message)
    assert len(drops) == 1 and restores == [], (drops, restores)


@pytest.mark.asyncio
async def test_a_scan_with_nothing_to_describe_is_settled_as_before(
    tmp_path, monkeypatch
):
    """Control, no planted failure: the exit's own payload is recorded as the
    coverage and the previous results are dropped."""

    def a_scan_that_exits_incomplete(*args: Any, **kwargs: Any) -> Any:
        raise ras.ScanIncompleteExit(EXIT_REASONS, AshAggregatedResults())

    entry, drops, restores = await _run(
        tmp_path, monkeypatch, a_scan_that_exits_incomplete
    )

    assert entry.status == MCScanStatus.INCOMPLETE, (entry.status, entry.error_message)
    assert entry.coverage == EXIT_REASONS.to_payload(), entry.coverage
    assert len(drops) == 1 and restores == [], (drops, restores)


@pytest.mark.asyncio
async def test_an_exit_for_incomplete_coverage_that_was_not_settled_still_closes_the_entry(
    tmp_path, monkeypatch
):
    """Fails on a ``_close_for`` that raises in the ``ScanIncompleteExit`` arm of
    the runner: that call is made for a scan whose thread recorded no close (its
    cancel event was set), nothing guarded it, and the error left the task with the
    entry still running. The entry is closed as incomplete with the gap named by the
    exit's own scanner rows (the registry refuses an incomplete scan that carries no
    gap, and a close with none made the runner's own ``finish_scan`` raise), the
    previous results are put back (not dropped), and the task ends normally."""
    monkeypatch.setattr(ras.ScanIncompleteness, "to_payload", _a_planted_failure)

    def a_scan_that_exits_incomplete(*args: Any, **kwargs: Any) -> Any:
        raise ras.ScanIncompleteExit(EXIT_REASONS, AshAggregatedResults())

    entry, drops, restores = await _run(
        tmp_path,
        monkeypatch,
        a_scan_that_exits_incomplete,
        cancel_during_the_scan=True,
    )

    assert entry.status == MCScanStatus.INCOMPLETE, (entry.status, entry.error_message)
    _assert_the_gap_is_the_exits_rows(entry.coverage)
    assert drops == [] and len(restores) == 1, (drops, restores)


@pytest.mark.asyncio
async def test_a_return_that_was_not_settled_whose_threshold_cannot_be_judged(
    tmp_path, monkeypatch
):
    """The same call in the return arm: a scan that returned its results but whose
    thread recorded no close is closed as completed with no judged threshold, so the
    entry keeps the one it was registered with (as the settled return above). Fails
    on a ``_close_for`` that raises there: the error was taken for a runner failure
    and closed the scan as failed."""
    monkeypatch.setattr(mcp_tools, "_judged_threshold", _a_planted_failure)

    def a_scan_that_returns_its_results(*args: Any, **kwargs: Any) -> Any:
        return AshAggregatedResults()

    entry, drops, restores = await _run(
        tmp_path,
        monkeypatch,
        a_scan_that_returns_its_results,
        cancel_during_the_scan=True,
    )

    assert entry.status == MCScanStatus.COMPLETED, (entry.status, entry.error_message)
    assert entry.severity_threshold == REGISTERED_THRESHOLD, entry.severity_threshold
    assert drops == [] and len(restores) == 1, (drops, restores)


@pytest.mark.asyncio
async def test_a_scan_that_was_not_settled_and_has_nothing_to_describe_is_closed_as_before(
    tmp_path, monkeypatch
):
    """Control, no planted failure: the exit's own payload is recorded as the
    coverage of a scan the thread did not settle, and the previous results are put
    back."""

    def a_scan_that_exits_incomplete(*args: Any, **kwargs: Any) -> Any:
        raise ras.ScanIncompleteExit(EXIT_REASONS, AshAggregatedResults())

    entry, drops, restores = await _run(
        tmp_path,
        monkeypatch,
        a_scan_that_exits_incomplete,
        cancel_during_the_scan=True,
    )

    assert entry.status == MCScanStatus.INCOMPLETE, (entry.status, entry.error_message)
    assert entry.coverage == EXIT_REASONS.to_payload(), entry.coverage
    assert drops == [] and len(restores) == 1, (drops, restores)
