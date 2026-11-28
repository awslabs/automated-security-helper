# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A runner failure that comes after the scan kept its results does not fail it.

The scan's thread decides that the scan has results of its own, marks it so,
then drops the previous scan's results (disk work) and only then ends. The
runner's own failure arms are closers of the entry: one that runs before the
decision closes the entry failed and sets the cancel event, which the decision
then reads, so the previous results are put back; one that runs after it finds
the mark set and closes the entry completed, because the scan's results are on
disk and the previous ones are already gone.

The decision and an arm's check-then-close share one lock
(``settle_decision`` in ``mcp_tools._run_scan``), so the two orders are the only
ones. The window is held open deterministically: the previous results' drop
waits on an event the test releases after the arm has run.

A scan that exited for incomplete coverage keeps its results the same way, with one
difference the last two cells pin. The registry refuses to close an incomplete scan
with no gap attached, so a close that cannot carry the scan's own gap is made again
with the gap that names nothing (one ``unknown`` incomplete scanner), not with the
status alone, and a close that raises in the runner's incomplete-coverage arm reaches
the failure arm instead of escaping the task. A close that fails because of its
severity threshold, not its coverage, keeps the coverage: it is made again without the
threshold before the gap that names nothing, or the status alone, is used.

Every cell is DISARMED: the scan is a stand-in that writes a results file into
the cell's own tmp_path, no real scanner or network is involved, and the drop
and the restore are the real ones over an empty previous-results area.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli import mcp_server, mcp_tools
from automated_security_helper.core.resource_management import scan_registry
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.core.resource_management.scan_tracking import (
    coverage_has_gap,
)
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.log import ASH_LOGGER
from tests.utils.drop_window import TheDropWindow
from tests.utils.tasks import drain as _drain
from tests.utils.tasks import drain_clean

pytestmark = pytest.mark.unit

_LAUNCHER = "automated_security_helper.interactions.run_ash_scan.run_ash_scan"
#: How long a held drop or a waiting scan stand-in waits before it gives up:
#: far past any cell, so a cell that fails early cannot leave a thread behind
#: for long.
HOLD_SECONDS = 30.0
RESULTS_FILE = "ash_aggregated_results.json"


@pytest.fixture(autouse=True)
def isolated_mcp_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp.sessions import (
        reset_default_registry_for_tests,
    )

    monkeypatch.setattr(scan_registry, "_scan_registry", ScanRegistry())
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    reset_default_registry_for_tests()
    for name in ("ASH_MCP_ALLOWED_CONFIG_ROOTS", "ASH_MCP_TRANSPORT", "ASH_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "allowed"))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    (tmp_path / "allowed").mkdir()
    monkeypatch.setattr(mcp_server, "monitor_scan_progress", AsyncMock())
    yield
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    reset_default_registry_for_tests()


def _ctx() -> MagicMock:
    ctx = MagicMock(spec=Context)
    ctx.headers = {}
    return ctx


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "allowed" / "project"
    project.mkdir(parents=True)
    (project / "app.py").write_text("x = 1\n", encoding="utf-8")
    return project


def _write_results(output_dir: str) -> None:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    (output / RESULTS_FILE).write_text(
        json.dumps({"scanner_results": {}, "metadata": {}}), encoding="utf-8"
    )


def _a_scan_that_writes_its_results(**kwargs: Any) -> None:
    _write_results(kwargs["output_dir"])
    return None


def _the_runner_task_of(scan_id: str) -> "asyncio.Task[None]":
    """The runner task the tool started for ``scan_id``."""
    tasks = [task for task, owner in mcp_tools._scan_tasks.items() if owner == scan_id]
    assert len(tasks) == 1, tasks
    return tasks[0]


async def _wait_for_the_other_tasks() -> None:
    """Let every other task end, however it ends, bounded."""
    await _drain(timeout=HOLD_SECONDS, return_exceptions=True)


#: An exit for incomplete coverage whose own reasons name ``bandit``.
INCOMPLETE_REASONS = ras.ScanIncompleteness(
    scanners=(("bandit", "ERROR"),), observed=(("bandit", "ERROR"),)
)
#: The keys every coverage payload carries.
PAYLOAD_KEYS = set(ras.ScanIncompleteness().to_payload())


def _a_scan_that_exits_incomplete(**kwargs: Any) -> None:
    _write_results(kwargs["output_dir"])
    raise ras.ScanIncompleteExit(INCOMPLETE_REASONS, AshAggregatedResults())


def _names(coverage: Any, scanner: str) -> bool:
    """Whether ``coverage`` lists ``scanner`` among its incomplete scanners."""
    if not isinstance(coverage, dict):
        return False
    return any(
        isinstance(row, dict) and row.get("scanner") == scanner
        for row in coverage.get("incomplete_scanners") or ()
    )


def _is_the_unknown_gap(coverage: Any) -> bool:
    """Whether ``coverage`` is the gap that names nothing: every key of the payload,
    one incomplete scanner named ``unknown``, and nothing else."""
    if not isinstance(coverage, dict) or set(coverage) != PAYLOAD_KEYS:
        return False
    rest = PAYLOAD_KEYS - {"incomplete_scanners", "no_scanner_ran"}
    return (
        [row.get("scanner") for row in coverage["incomplete_scanners"]] == ["unknown"]
        and coverage["no_scanner_ran"] is False
        and all(coverage[key] == [] for key in rest)
    )


def _refuse_the_scans_own_gap(monkeypatch: pytest.MonkeyPatch, closes: list) -> None:
    """Make every close that carries the scan's own gap (it names ``bandit``) raise.

    A stand-in for a close that fails because of what it carries. A close with any
    other coverage, or with none, reaches the real registry. Every close is recorded
    in ``closes`` as (status, coverage).
    """
    real_finish = ScanRegistry.finish_scan

    def a_close_that_cannot_carry_the_scans_gap(
        self: ScanRegistry, scan_id: str, status: MCScanStatus, *args: Any, **kw: Any
    ) -> bool:
        coverage = kw.get("coverage")
        closes.append((status, coverage))
        if _names(coverage, "bandit"):
            raise RuntimeError("a planted failure of the close")
        return real_finish(self, scan_id, status, *args, **kw)

    monkeypatch.setattr(
        ScanRegistry, "finish_scan", a_close_that_cannot_carry_the_scans_gap
    )


#: The threshold the planted judge returns: a string, so every close carries one.
JUDGED_THRESHOLD = "HIGH"


def _a_scan_that_returns_its_results(**kwargs: Any) -> AshAggregatedResults:
    _write_results(kwargs["output_dir"])
    return AshAggregatedResults()


def _refuse_every_close_that_carries_a_threshold(
    monkeypatch: pytest.MonkeyPatch, closes: list
) -> None:
    """Make every close that carries a severity threshold raise.

    A stand-in for a registry that refuses the threshold rather than the coverage. A
    close with no threshold reaches the real registry. Every close is recorded in
    ``closes`` as (status, whether its coverage names ``bandit``, its threshold).
    """
    real_finish = ScanRegistry.finish_scan

    def a_close_that_cannot_carry_a_threshold(
        self: ScanRegistry, scan_id: str, status: MCScanStatus, *args: Any, **kw: Any
    ) -> bool:
        threshold = kw.get("severity_threshold")
        closes.append((status, _names(kw.get("coverage"), "bandit"), threshold))
        if threshold is not None:
            raise RuntimeError("a planted failure of the close")
        return real_finish(self, scan_id, status, *args, **kw)

    monkeypatch.setattr(
        ScanRegistry, "finish_scan", a_close_that_cannot_carry_a_threshold
    )


@pytest.mark.asyncio
async def test_the_loop_cancelling_the_runner_inside_the_drop_leaves_the_scan_completed(
    tmp_path, monkeypatch
):
    """The runner task is cancelled (the loop shutting down after a slow stop)
    after the thread decided the scan has results and before the drop of the
    previous results ends. The runner's failure arm finds the mark set: the scan
    has its own results on disk, so the entry is closed completed and the cancel
    event is left alone, not closed failed with "ended without a result"."""
    window = TheDropWindow(HOLD_SECONDS).install(monkeypatch)
    monkeypatch.setattr(_LAUNCHER, _a_scan_that_writes_its_results)
    project = _project(tmp_path)
    ctx = _ctx()

    begun = await mcp_server.run_ash_scan(ctx, source_dir=str(project))
    assert begun["success"] is True, begun
    scan_id = begun["scan_id"]
    runner = _the_runner_task_of(scan_id)
    try:
        assert await asyncio.to_thread(window.entered.wait, HOLD_SECONDS), (
            "control: the previous results' drop never began"
        )
        runner.cancel()
        await asyncio.wait([runner], timeout=HOLD_SECONDS)
        during = scan_registry.get_scan_registry().get_scan(scan_id)
        status_during = during.status.value if during is not None else None
        error_during = during.error_message if during is not None else None
        event_set_during = during.cancel_event.is_set() if during is not None else None
    finally:
        window.release.set()
    assert during is not None
    assert await asyncio.to_thread(during.runner_done.wait, HOLD_SECONDS), (
        "control: the scan's thread never settled"
    )
    await _wait_for_the_other_tasks()
    progress = await mcp_server.get_scan_progress(ctx, scan_id)

    # Controls: the drop ran once and was in progress when the runner was
    # cancelled, and the runner task ended cancelled.
    assert len(window.drops) == 1, window.drops
    assert window.restores == [], window.restores
    assert runner.cancelled(), runner
    assert status_during == MCScanStatus.COMPLETED.value, (status_during, error_during)
    assert error_during is None, error_during
    assert event_set_during is False, event_set_during
    assert progress.get("status") == "completed", progress
    assert (project / ".ash" / "ash_output" / RESULTS_FILE).is_file(), progress


@pytest.mark.asyncio
async def test_a_failing_close_of_a_scan_that_had_results_leaves_it_completed(
    tmp_path, monkeypatch
):
    """The thread returned with the mark set and the runner's close of the
    finished scan raises. The runner's error arm finds the mark set and closes
    the entry completed; it does not record "Error executing scan" for a scan
    whose results are on disk."""
    monkeypatch.setattr(_LAUNCHER, _a_scan_that_writes_its_results)
    real_finish = ScanRegistry.finish_scan
    closes: list = []

    def a_close_that_raises_once(
        self: ScanRegistry, scan_id: str, status: MCScanStatus, *args: Any, **kw: Any
    ) -> bool:
        # The runner's close of a finished scan passes the coverage keyword;
        # the failure arm's close does not.
        closes.append((status, "coverage" in kw))
        if status == MCScanStatus.COMPLETED and "coverage" in kw:
            raise RuntimeError("a planted failure of the close")
        return real_finish(self, scan_id, status, *args, **kw)

    monkeypatch.setattr(ScanRegistry, "finish_scan", a_close_that_raises_once)
    project = _project(tmp_path)
    ctx = _ctx()

    begun = await mcp_server.run_ash_scan(ctx, source_dir=str(project))
    assert begun["success"] is True, begun
    scan_id = begun["scan_id"]
    await _wait_for_the_other_tasks()
    progress = await mcp_server.get_scan_progress(ctx, scan_id)
    entry = scan_registry.get_scan_registry().get_scan(scan_id)

    assert (MCScanStatus.COMPLETED, True) in closes, closes
    assert entry is not None
    assert entry.status == MCScanStatus.COMPLETED, (entry.status, entry.error_message)
    assert entry.error_message is None, entry.error_message
    assert progress.get("status") == "completed", progress


@pytest.mark.asyncio
async def test_a_close_that_fails_twice_with_its_coverage_is_made_once_more_without_it(
    tmp_path, monkeypatch, caplog
):
    """The runner's close of a finished scan raises because of what it carries (the
    coverage or the severity threshold), so the close through the mark, which carries
    the same two values, raises too. The entry still ends completed: the failure arm
    closes it a third time with the status alone and logs what the record lacks.
    A fallback that repeated the failing call would leave the entry running."""
    monkeypatch.setattr(_LAUNCHER, _a_scan_that_writes_its_results)
    real_finish = ScanRegistry.finish_scan
    closes: list = []

    def a_close_that_cannot_carry_its_coverage(
        self: ScanRegistry, scan_id: str, status: MCScanStatus, *args: Any, **kw: Any
    ) -> bool:
        closes.append((status, "coverage" in kw))
        if "coverage" in kw:
            raise RuntimeError("a planted failure of the close")
        return real_finish(self, scan_id, status, *args, **kw)

    monkeypatch.setattr(
        ScanRegistry, "finish_scan", a_close_that_cannot_carry_its_coverage
    )
    project = _project(tmp_path)
    ctx = _ctx()

    with caplog.at_level(logging.WARNING, logger=ASH_LOGGER.name):
        begun = await mcp_server.run_ash_scan(ctx, source_dir=str(project))
        assert begun["success"] is True, begun
        scan_id = begun["scan_id"]
        await _wait_for_the_other_tasks()
    progress = await mcp_server.get_scan_progress(ctx, scan_id)
    entry = scan_registry.get_scan_registry().get_scan(scan_id)

    # The runner's close, the close through the mark, then the close without them.
    assert closes.count((MCScanStatus.COMPLETED, True)) == 2, closes
    assert closes.count((MCScanStatus.COMPLETED, False)) == 1, closes
    assert entry is not None
    assert entry.status == MCScanStatus.COMPLETED, (entry.status, entry.error_message)
    assert entry.error_message is None, entry.error_message
    assert progress.get("status") == "completed", progress
    said = [
        record.getMessage()
        for record in caplog.records
        if scan_id in record.getMessage() and "coverage" in record.getMessage()
    ]
    assert said, [record.getMessage() for record in caplog.records]


@pytest.mark.asyncio
async def test_the_loop_cancelling_the_runner_before_the_decision_still_fails_the_scan(
    tmp_path, monkeypatch
):
    """Control for the cells above: the runner task is cancelled while the scan
    is still running, before any decision. No mark is set, so the entry is closed
    failed with its reason, the cancel event is set under the lock, and the
    thread then puts the previous results back."""
    window = TheDropWindow(HOLD_SECONDS).install(monkeypatch)
    started = threading.Event()
    go_on = threading.Event()

    def a_scan_that_waits(**kwargs: Any) -> None:
        started.set()
        go_on.wait(timeout=HOLD_SECONDS)
        _write_results(kwargs["output_dir"])
        return None

    monkeypatch.setattr(_LAUNCHER, a_scan_that_waits)
    project = _project(tmp_path)
    ctx = _ctx()

    begun = await mcp_server.run_ash_scan(ctx, source_dir=str(project))
    assert begun["success"] is True, begun
    scan_id = begun["scan_id"]
    runner = _the_runner_task_of(scan_id)
    entry = scan_registry.get_scan_registry().get_scan(scan_id)
    assert entry is not None
    try:
        assert await asyncio.to_thread(started.wait, HOLD_SECONDS), (
            "control: the scan never started"
        )
        runner.cancel()
        await asyncio.wait([runner], timeout=HOLD_SECONDS)
        status_during = entry.status.value
        error_during = entry.error_message
        event_set_during = entry.cancel_event.is_set()
    finally:
        go_on.set()
    assert await asyncio.to_thread(entry.runner_done.wait, HOLD_SECONDS), (
        "control: the scan's thread never settled"
    )
    await _wait_for_the_other_tasks()

    assert runner.cancelled(), runner
    assert status_during == MCScanStatus.FAILED.value, status_during
    assert "ended without a result" in (error_during or ""), error_during
    assert event_set_during is True, event_set_during
    assert window.drops == [], window.drops
    assert len(window.restores) == 1, window.restores


@pytest.mark.asyncio
async def test_the_loop_cancelling_an_incomplete_scans_runner_inside_the_drop_leaves_it_incomplete(
    tmp_path, monkeypatch
):
    """The incomplete-coverage counterpart of the first cell, with the close through
    the mark failing because of the gap it carries. The runner task is cancelled
    after the thread decided the scan has results and before the drop of the previous
    results ends, so the failure arm finds the mark set and closes the entry with the
    thread's close, which raises here. It is closed once more with the gap that names
    nothing, so the entry ends incomplete and the task ends cancelled. Before, that
    second close carried the status alone, the registry refused an incomplete scan
    with no gap, and the error replaced the cancellation with the entry still RUNNING."""
    window = TheDropWindow(HOLD_SECONDS).install(monkeypatch)
    monkeypatch.setattr(_LAUNCHER, _a_scan_that_exits_incomplete)
    closes: list = []
    _refuse_the_scans_own_gap(monkeypatch, closes)
    project = _project(tmp_path)
    ctx = _ctx()

    begun = await mcp_server.run_ash_scan(ctx, source_dir=str(project))
    assert begun["success"] is True, begun
    scan_id = begun["scan_id"]
    runner = _the_runner_task_of(scan_id)
    try:
        assert await asyncio.to_thread(window.entered.wait, HOLD_SECONDS), (
            "control: the previous results' drop never began"
        )
        runner.cancel()
        await asyncio.wait([runner], timeout=HOLD_SECONDS)
        during = scan_registry.get_scan_registry().get_scan(scan_id)
        status_during = during.status.value if during is not None else None
        error_during = during.error_message if during is not None else None
        coverage_during = during.coverage if during is not None else None
        event_set_during = during.cancel_event.is_set() if during is not None else None
    finally:
        window.release.set()
    assert during is not None
    assert await asyncio.to_thread(during.runner_done.wait, HOLD_SECONDS), (
        "control: the scan's thread never settled"
    )
    await _wait_for_the_other_tasks()

    # Controls: the drop ran once and was in progress when the runner was cancelled.
    assert len(window.drops) == 1, window.drops
    assert window.restores == [], window.restores
    # The close through the mark carried the scan's own gap; the one after it, the
    # gap that names nothing.
    assert [_names(coverage, "bandit") for _, coverage in closes] == [True, False], (
        closes
    )
    assert _is_the_unknown_gap(closes[-1][1]), closes
    assert runner.cancelled(), runner
    assert status_during == MCScanStatus.INCOMPLETE.value, (status_during, error_during)
    assert error_during is None, error_during
    assert coverage_has_gap(coverage_during), coverage_during
    assert _is_the_unknown_gap(coverage_during), coverage_during
    assert event_set_during is False, event_set_during


@pytest.mark.asyncio
async def test_an_incomplete_close_that_fails_with_its_gap_is_made_again_with_the_unknown_gap(
    tmp_path, monkeypatch, caplog
):
    """The incomplete-coverage counterpart of the cell that closes a completed scan a
    third time. The runner's close of a scan that exited for incomplete coverage
    raises because of the gap it carries, and the close through the mark, which
    carries the same gap, raises too. The entry still ends incomplete, with the gap
    that names nothing, and the runner's task ends without an error: the registry
    refuses an incomplete scan with no gap, so the status-only close a completed scan
    gets would raise as well. Before, the runner's close raised out of the
    incomplete-coverage arm, which no arm catches, and the entry stayed RUNNING."""
    monkeypatch.setattr(_LAUNCHER, _a_scan_that_exits_incomplete)
    closes: list = []
    _refuse_the_scans_own_gap(monkeypatch, closes)
    project = _project(tmp_path)
    ctx = _ctx()

    with caplog.at_level(logging.WARNING, logger=ASH_LOGGER.name):
        begun = await mcp_server.run_ash_scan(ctx, source_dir=str(project))
        assert begun["success"] is True, begun
        scan_id = begun["scan_id"]
        # Raises when a task ended with an exception: the runner's must end cleanly.
        await drain_clean()
    entry = scan_registry.get_scan_registry().get_scan(scan_id)

    # The runner's close, the close through the mark, then the close with the gap
    # that names nothing.
    assert [_names(coverage, "bandit") for _, coverage in closes] == [
        True,
        True,
        False,
    ], closes
    assert _is_the_unknown_gap(closes[-1][1]), closes
    assert entry is not None
    assert entry.status == MCScanStatus.INCOMPLETE, (entry.status, entry.error_message)
    assert entry.error_message is None, entry.error_message
    assert coverage_has_gap(entry.coverage), entry.coverage
    assert _is_the_unknown_gap(entry.coverage), entry.coverage
    said = [
        record.getMessage()
        for record in caplog.records
        if scan_id in record.getMessage() and "coverage" in record.getMessage()
    ]
    assert said, [record.getMessage() for record in caplog.records]
    # The branch's own words: the gap that names nothing is what the record holds.
    assert any("one unknown scanner" in line for line in said), said


@pytest.mark.asyncio
async def test_an_incomplete_close_that_fails_with_its_threshold_is_made_again_with_the_unknown_gap(
    tmp_path, monkeypatch, caplog
):
    """The runner's close of a scan that exited for incomplete coverage and the close
    through the mark both carry the judged severity threshold and raise. The close
    after them is the one every failed close of an incomplete scan gets: the gap that
    names nothing, and no threshold, so the entry ends incomplete and keeps the
    threshold it was registered with. Fails before the fix: a close with the scan's own
    gap and no threshold came first, and the stand-in, which refuses only a close that
    carries a threshold, recorded it."""
    monkeypatch.setattr(_LAUNCHER, _a_scan_that_exits_incomplete)
    judged: list = []

    def a_judge(results: Any) -> str:
        judged.append(results)
        return JUDGED_THRESHOLD

    monkeypatch.setattr(mcp_tools, "_judged_threshold", a_judge)
    closes: list = []
    _refuse_every_close_that_carries_a_threshold(monkeypatch, closes)
    project = _project(tmp_path)
    ctx = _ctx()

    with caplog.at_level(logging.WARNING, logger=ASH_LOGGER.name):
        begun = await mcp_server.run_ash_scan(ctx, source_dir=str(project))
        assert begun["success"] is True, begun
        scan_id = begun["scan_id"]
        # Raises when a task ended with an exception: the runner's must end cleanly.
        await drain_clean()
    entry = scan_registry.get_scan_registry().get_scan(scan_id)

    # The runner's close and the close through the mark carry the threshold; the one
    # after them carries the gap that names nothing and no threshold.
    assert closes == [
        (MCScanStatus.INCOMPLETE, True, JUDGED_THRESHOLD),
        (MCScanStatus.INCOMPLETE, True, JUDGED_THRESHOLD),
        (MCScanStatus.INCOMPLETE, False, None),
    ], closes
    assert len(judged) == 1, judged
    assert entry is not None
    assert entry.status == MCScanStatus.INCOMPLETE, (entry.status, entry.error_message)
    assert entry.error_message is None, entry.error_message
    assert _is_the_unknown_gap(entry.coverage), entry.coverage
    assert entry.severity_threshold != JUDGED_THRESHOLD, entry.severity_threshold
    said = [
        record.getMessage()
        for record in caplog.records
        if scan_id in record.getMessage()
    ]
    assert any("one unknown scanner" in line for line in said), said
    assert not any("without its severity threshold" in line for line in said), said


@pytest.mark.asyncio
async def test_a_completed_close_that_fails_with_its_threshold_is_made_again_with_the_status_alone(
    tmp_path, monkeypatch
):
    """The completed counterpart: the runner's close and the close through the mark of a
    scan that returned its results both carry the judged severity threshold and raise.
    The close after them is the one every failed close of a completed scan gets, with
    the status alone, so the entry records no coverage and keeps the threshold it was
    registered with. Fails before the fix: a close with the coverage and no threshold
    came first, and the stand-in, which refuses only a close that carries a threshold,
    recorded the coverage."""
    monkeypatch.setattr(_LAUNCHER, _a_scan_that_returns_its_results)
    judged: list = []

    def a_judge(results: Any) -> str:
        judged.append(results)
        return JUDGED_THRESHOLD

    monkeypatch.setattr(mcp_tools, "_judged_threshold", a_judge)
    closes: list = []
    _refuse_every_close_that_carries_a_threshold(monkeypatch, closes)
    project = _project(tmp_path)
    ctx = _ctx()

    begun = await mcp_server.run_ash_scan(ctx, source_dir=str(project))
    assert begun["success"] is True, begun
    scan_id = begun["scan_id"]
    await drain_clean()
    entry = scan_registry.get_scan_registry().get_scan(scan_id)

    assert [threshold for _, _, threshold in closes] == [
        JUDGED_THRESHOLD,
        JUDGED_THRESHOLD,
        None,
    ], closes
    assert len(judged) == 1, judged
    assert entry is not None
    assert entry.status == MCScanStatus.COMPLETED, (entry.status, entry.error_message)
    assert entry.error_message is None, entry.error_message
    assert entry.coverage is None, entry.coverage
    assert entry.severity_threshold != JUDGED_THRESHOLD, entry.severity_threshold
