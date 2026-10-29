# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan timeout and the scan thread's settle decision are ordered.

The scan's thread decides, under ``settle_decision``, whether the scan has
results of its own, marks it so, and only then drops the previous scan's results.
The timeout closes the entry as failed and sets the cancel event the decision
reads. Two orders are possible and each has one outcome:

- The timer runs first. It closes the entry and sets the event in one step under
  the lock, so the decision reads the entry closed and the event set, and the
  previous results are put back.
- The decision runs first. The mark is set, the scan's results are on disk and
  the previous ones are going away, so the timer leaves the entry for the runner
  to close as completed.

Both cells hold the window with events. The first waits for the timer through a
recorded call of the reason builder, which the timer makes first.

Every cell is DISARMED: the scan is a stand-in defined in this file, the output
directory is the cell's own tmp_path, and the drop and the restore are the real
ones over an empty previous-results area. No scanner or network is involved.
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.core.previous_results import PreviousResults
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.utils.log import ASHLogger

_TOOLS = "automated_security_helper.cli.mcp_tools"
#: How long a held step waits before it gives up: far past any cell, so a cell
#: that fails early cannot leave a thread behind for long.
HOLD_SECONDS = 30.0
#: How long the timer's close waits for the scan thread's decision to show
#: itself. Where the two are ordered, the decision cannot show itself until the
#: close is done, so this is the wait the ordering costs, not a race margin.
ORDERING_WAIT_SECONDS = 0.5
#: The limit of the cell where the decision must come first: far past the
#: moment a returning stand-in reaches its decision, so the timer cannot fall
#: due before it on a loaded host.
LATE_TIMER_SECONDS = 1.0
#: The limit of the cell where the timer must come first: the stand-in waits
#: for the timer's close, so any limit works.
EARLY_TIMER_SECONDS = 0.05


def _output_dir(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    output_dir = tmp_path / ".ash" / "ash_output"
    output_dir.mkdir(parents=True)
    return output_dir


@pytest.mark.asyncio
async def test_a_timer_firing_inside_the_drop_leaves_the_scan_completed(
    tmp_path, monkeypatch
):
    """The scan returns, its thread marks it as one with results and starts the
    drop of the previous results, and the scan timer falls due while the drop is
    held open. The entry is not closed failed as timed out: the cancel event is
    left alone and, once the drop ends, the runner closes the scan completed."""
    output_dir = _output_dir(tmp_path, monkeypatch)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(tmp_path), output_directory=str(output_dir)
    )
    entered = threading.Event()
    release = threading.Event()
    timer_fired = threading.Event()
    drops: list = []
    restores: list = []
    real_discard = PreviousResults.discard
    real_restore = PreviousResults.restore
    real_reason = mcp_tools._scan_timeout_reason

    def a_drop_held_open(this: PreviousResults) -> None:
        drops.append(this)
        entered.set()
        release.wait(timeout=HOLD_SECONDS)
        return real_discard(this)

    def a_restore_that_is_recorded(this: PreviousResults) -> None:
        restores.append(this)
        return real_restore(this)

    def a_reason_that_notes_the_timer(*args: Any, **kwargs: Any) -> str:
        timer_fired.set()
        return real_reason(*args, **kwargs)

    def a_scan_that_returns(*args: Any, **kwargs: Any) -> None:
        return None

    with (
        patch.object(ras, "run_ash_scan", a_scan_that_returns),
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._scan_timeout_reason", a_reason_that_notes_the_timer),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        patch.object(PreviousResults, "discard", a_drop_held_open),
        patch.object(PreviousResults, "restore", a_restore_that_is_recorded),
    ):
        runner = asyncio.create_task(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(tmp_path),
                output_dir=str(output_dir),
                severity_threshold=None,
                scan_timeout_seconds=LATE_TIMER_SECONDS,
            )
        )
        entry = registry.get_scan(scan_id)
        assert entry is not None
        try:
            assert await asyncio.to_thread(entered.wait, HOLD_SECONDS), (
                "control: the previous results' drop never began"
            )
            assert await asyncio.to_thread(timer_fired.wait, HOLD_SECONDS), (
                "control: the scan timer never fell due"
            )
            # Let the loop run the rest of the timer's callback.
            await asyncio.sleep(0)
            status_during = entry.status
            error_during = entry.error_message
            event_during = entry.cancel_event.is_set()
        finally:
            release.set()
        await asyncio.wait([runner], timeout=HOLD_SECONDS)

    assert runner.done() and not runner.cancelled(), runner
    assert len(drops) == 1, drops
    assert restores == [], restores
    assert status_during != MCScanStatus.FAILED, (status_during, error_during)
    assert event_during is False, event_during
    assert entry.status == MCScanStatus.COMPLETED, (entry.status, entry.error_message)
    assert entry.error_message is None, entry.error_message


@pytest.mark.asyncio
async def test_a_timer_that_closes_the_scan_sets_the_event_before_the_decision(
    tmp_path, monkeypatch
):
    """The timer falls due while the scan runs. Its close of the entry and its
    set of the cancel event are one step: the scan thread, which returns the
    moment the entry is closed, cannot decide in between and read the event
    clear. It reads the event set, so the previous results are put back and not
    dropped, and the entry stays failed as timed out."""
    output_dir = _output_dir(tmp_path, monkeypatch)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(tmp_path), output_directory=str(output_dir)
    )
    closed = threading.Event()
    the_decision_acted = threading.Event()
    drops: list = []
    restores: list = []
    real_discard = PreviousResults.discard
    real_restore = PreviousResults.restore
    real_finish = ScanRegistry.finish_scan

    def a_drop_that_is_recorded(this: PreviousResults) -> None:
        drops.append(this)
        the_decision_acted.set()
        return real_discard(this)

    def a_restore_that_is_recorded(this: PreviousResults) -> None:
        restores.append(this)
        the_decision_acted.set()
        return real_restore(this)

    def a_close_that_waits_for_the_decision(
        self: ScanRegistry, sid: str, status: MCScanStatus, *args: Any, **kw: Any
    ) -> bool:
        closed_now = real_finish(self, sid, status, *args, **kw)
        if closed_now and status == MCScanStatus.FAILED:
            # The entry is closed; the cancel event is not yet set. The scan
            # thread, released by `closed`, decides now unless the close and
            # the event are one step under the decision's lock.
            closed.set()
            the_decision_acted.wait(timeout=ORDERING_WAIT_SECONDS)
        return closed_now

    def a_scan_that_returns_once_the_entry_is_closed(*args: Any, **kwargs: Any) -> None:
        closed.wait(timeout=HOLD_SECONDS)
        return None

    with (
        patch.object(ras, "run_ash_scan", a_scan_that_returns_once_the_entry_is_closed),
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        patch.object(PreviousResults, "discard", a_drop_that_is_recorded),
        patch.object(PreviousResults, "restore", a_restore_that_is_recorded),
        patch.object(ScanRegistry, "finish_scan", a_close_that_waits_for_the_decision),
    ):
        await mcp_tools._run_scan_async(
            scan_id=scan_id,
            directory_path=str(tmp_path),
            output_dir=str(output_dir),
            severity_threshold=None,
            scan_timeout_seconds=EARLY_TIMER_SECONDS,
        )
        entry = registry.get_scan(scan_id)
        assert entry is not None
        assert await asyncio.to_thread(entry.runner_done.wait, HOLD_SECONDS), (
            "control: the scan's thread never settled"
        )

    assert closed.is_set(), "control: the timer never closed the entry"
    assert entry.status == MCScanStatus.FAILED, (entry.status, entry.error_message)
    assert "exceeded the server's" in (entry.error_message or ""), entry.error_message
    assert entry.cancel_event.is_set() is True
    assert drops == [], drops
    assert len(restores) == 1, restores
