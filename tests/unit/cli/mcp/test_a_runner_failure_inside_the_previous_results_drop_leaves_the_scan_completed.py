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
from automated_security_helper.utils.log import ASH_LOGGER
from tests.utils.drop_window import TheDropWindow
from tests.utils.tasks import drain as _drain

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
