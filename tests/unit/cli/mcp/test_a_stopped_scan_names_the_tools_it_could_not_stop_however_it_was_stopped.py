# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan the server stopped keeps the tools its stop could not end, however it was stopped.

``cancel_scan`` is one stop. The scan timeout is another: ``_stop_at_timeout``
closes the entry FAILED with the timeout as its reason and then sets the cancel
event, and a cancelled runner task does the same through
``_close_after_the_runner_failed(stop_the_scan=True)``. The tools a stop could
not end are recorded on the scan's cancel event (core/cancellation.py). They
reached the entry only through the runner's ``except ScanCancelled`` arm, which
a cancelled task never runs, and through ``record_cancel_outcome``, which
admitted a CANCELLED entry alone: a timed-out scan whose tool kept running read
back as a plain timeout, and a cancelled task's scan recorded nothing at all.
The thread that runs the scan now records the outcome itself, before it lets the
directory go, and the registry admits every entry the server stopped.

The runner is driven for real over a stand-in scan that does, on its thread,
what the real stop does around it: for the timeout it closes the entry as the
timer does and records one tool on the scan's own cancel event; for the
cancelled task it waits to be stopped, then records the tool. Every test is
disarmed: the scan is the stand-in defined here, the output directory is the
test's own tmp_path, and no process is started.
"""

from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import sandbox
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.core.cancellation import (
    ScanCancelled,
    current_cancel_event,
    raise_if_cancelled,
)
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.interactions import run_ash_scan as ras

pytestmark = pytest.mark.unit

_TOOLS = "automated_security_helper.cli.mcp_tools"
#: Far past any test, so a test that fails early cannot leave a thread behind.
SETTLE_SECONDS = 30.0
TIMEOUT_REASON = "Scan exceeded the server's limit and was cancelled"


def _registered(tmp_path: Path, monkeypatch) -> tuple[ScanRegistry, str, Path]:
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    output_dir = tmp_path / ".ash" / "ash_output"
    output_dir.mkdir(parents=True)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(tmp_path), output_directory=str(output_dir)
    )
    return registry, scan_id, output_dir


def _stop_as_the_timer_does(registry: ScanRegistry, scan_id: str) -> None:
    """What _stop_at_timeout does from the loop: the entry closed FAILED with
    the timeout's reason, then the cancel event set."""
    assert registry.finish_scan(scan_id, MCScanStatus.FAILED, TIMEOUT_REASON) is True
    registry.get_scan(scan_id).cancel_event.set()


def _a_scanner_tool_that_would_not_end(tool: str, pid: int) -> None:
    """What the subprocess layer does for a child the stop could not end: it
    records the tool on the scan's cancel event, and the scan's next check
    raises with the record."""
    event = current_cancel_event()
    assert event is not None, "control: the stand-in ran outside the scan's scope"
    event.note_could_not_stop(tool, pid)
    raise_if_cancelled()
    raise AssertionError("control: the scan was not stopped")


async def _run_to_the_end(registry: ScanRegistry, scan_id: str, stand_in, run) -> Any:
    with (
        patch.object(ras, "run_ash_scan", stand_in),
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
    ):
        outcome = await run()
        entry = registry.get_scan(scan_id)
        assert entry is not None
        assert await asyncio.to_thread(entry.runner_done.wait, SETTLE_SECONDS), (
            "control: the scan's thread never settled"
        )
    return outcome


@pytest.mark.asyncio
async def test_a_timed_out_scan_names_the_tool_the_stop_could_not_end(
    tmp_path, monkeypatch
):
    """Red at the base: the entry was FAILED, record_cancel_outcome turned it
    away, and the client read a timeout with no word of the tool still running."""
    registry, scan_id, output_dir = _registered(tmp_path, monkeypatch)

    def a_scan_the_timer_stops(*args: Any, **kwargs: Any) -> None:
        _stop_as_the_timer_does(registry, scan_id)
        _a_scanner_tool_that_would_not_end("bandit", 4242)

    async def run() -> None:
        await mcp_tools._run_scan_async(
            scan_id=scan_id,
            directory_path=str(tmp_path),
            output_dir=str(output_dir),
            severity_threshold=None,
        )

    await _run_to_the_end(registry, scan_id, a_scan_the_timer_stops, run)

    entry = registry.get_scan(scan_id)
    assert entry.status == MCScanStatus.FAILED, (entry.status, entry.error_message)
    assert entry.error_message == TIMEOUT_REASON
    assert any("bandit" in w and "4242" in w for w in entry.warnings), entry.warnings
    assert entry.could_not_stop == (("bandit", 4242),)
    progress = registry.check_scan_progress(scan_id)
    assert any("bandit" in w for w in progress["warnings"]), progress


@pytest.mark.asyncio
async def test_a_scan_whose_task_was_cancelled_names_the_tool(tmp_path, monkeypatch):
    """The runner's task is cancelled while the scan runs: the arm closes the
    entry FAILED and sets the cancel event, and the thread runs on until the
    stop. Its ScanCancelled reaches no task, so the thread itself is the only
    place the outcome can be recorded.

    Red at the base: nothing recorded it, and the entry read as a plain failure."""
    registry, scan_id, output_dir = _registered(tmp_path, monkeypatch)
    thread_started = threading.Event()
    seen: Dict[str, Any] = {}

    def a_scan_that_outlives_its_task(*args: Any, **kwargs: Any) -> None:
        thread_started.set()
        event = current_cancel_event()
        deadline = time.monotonic() + SETTLE_SECONDS
        while not event.is_set() and time.monotonic() < deadline:
            time.sleep(0.02)
        seen["stopped"] = event.is_set()
        _a_scanner_tool_that_would_not_end("semgrep", 4343)

    async def run() -> None:
        task = asyncio.ensure_future(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(tmp_path),
                output_dir=str(output_dir),
                severity_threshold=None,
            )
        )
        assert await asyncio.to_thread(thread_started.wait, SETTLE_SECONDS), (
            "control: the scan's thread never started"
        )
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    await _run_to_the_end(registry, scan_id, a_scan_that_outlives_its_task, run)

    assert seen.get("stopped") is True, (
        "control: the cancelled task did not stop the scan"
    )
    entry = registry.get_scan(scan_id)
    assert entry.status == MCScanStatus.FAILED, (entry.status, entry.error_message)
    assert any("semgrep" in w and "4343" in w for w in entry.warnings), entry.warnings
    assert entry.could_not_stop == (("semgrep", 4343),)


@pytest.mark.asyncio
async def test_on_a_network_transport_the_warning_names_the_tool_not_its_pid(
    tmp_path, monkeypatch
):
    """A remote client is told which tool is still running, not a server-side
    process id it can neither act on nor should learn; the entry keeps the pair
    and the server's log names it."""
    registry, scan_id, output_dir = _registered(tmp_path, monkeypatch)
    monkeypatch.setattr(sandbox, "transport_is_networked", lambda: True)

    def a_scan_the_timer_stops(*args: Any, **kwargs: Any) -> None:
        _stop_as_the_timer_does(registry, scan_id)
        _a_scanner_tool_that_would_not_end("bandit", 4242)

    async def run() -> None:
        await mcp_tools._run_scan_async(
            scan_id=scan_id,
            directory_path=str(tmp_path),
            output_dir=str(output_dir),
            severity_threshold=None,
        )

    await _run_to_the_end(registry, scan_id, a_scan_the_timer_stops, run)

    entry = registry.get_scan(scan_id)
    warnings = [w for w in entry.warnings if "bandit" in w]
    assert warnings, entry.warnings
    assert all("4242" not in w for w in warnings), warnings
    assert entry.could_not_stop == (("bandit", 4242),)


@pytest.mark.asyncio
async def test_pairs_carried_by_the_exception_alone_are_recorded(tmp_path, monkeypatch):
    """A raise site may build the ScanCancelled with its own pairs and note
    nothing on the cancel event (scanner_executor's union of a pool's cancels
    does; so does a stand-in). The record reads both.

    Red at the round's earlier tips: the thread read the event alone and the
    arm no longer recorded, so a pair that rode the exception was dropped
    (the venue read it on the neighbor module's cancelled-entry id)."""
    registry, scan_id, output_dir = _registered(tmp_path, monkeypatch)

    def a_scan_cancelled_with_a_pair_on_the_exception(*a: Any, **k: Any) -> None:
        assert registry.cancel_scan(scan_id) is True
        raise ScanCancelled(
            "the scan was cancelled", could_not_stop=(("semgrep", 7777),)
        )

    async def run() -> None:
        await mcp_tools._run_scan_async(
            scan_id=scan_id,
            directory_path=str(tmp_path),
            output_dir=str(output_dir),
            severity_threshold=None,
        )

    await _run_to_the_end(
        registry, scan_id, a_scan_cancelled_with_a_pair_on_the_exception, run
    )

    entry = registry.get_scan(scan_id)
    assert entry.status == MCScanStatus.CANCELLED
    assert any("semgrep" in w and "7777" in w for w in entry.warnings), entry.warnings
    assert entry.could_not_stop == (("semgrep", 7777),)


@pytest.mark.asyncio
async def test_a_record_step_that_raises_still_lets_the_directory_go(
    tmp_path, monkeypatch
):
    """The record runs in the scan thread's finally ahead of runner_done. A
    raise out of it must not skip runner_done: the entry would then hold its
    directory for the server's life and refuse every rescan and cleanup.

    Red at the base of this commit: the record call sat before runner_done with
    no guard, so the raise propagated and runner_done stayed clear."""
    registry, scan_id, output_dir = _registered(tmp_path, monkeypatch)

    def a_registry_whose_record_step_breaks(*args: Any, **kwargs: Any) -> bool:
        raise RuntimeError("the record step broke")

    monkeypatch.setattr(
        registry, "record_cancel_outcome", a_registry_whose_record_step_breaks
    )

    def a_scan_the_timer_stops(*args: Any, **kwargs: Any) -> None:
        _stop_as_the_timer_does(registry, scan_id)
        _a_scanner_tool_that_would_not_end("bandit", 4242)

    async def run() -> None:
        await mcp_tools._run_scan_async(
            scan_id=scan_id,
            directory_path=str(tmp_path),
            output_dir=str(output_dir),
            severity_threshold=None,
        )

    await _run_to_the_end(registry, scan_id, a_scan_the_timer_stops, run)

    entry = registry.get_scan(scan_id)
    assert entry.runner_done.is_set(), (
        "runner_done stayed clear after the record step raised"
    )
    assert entry.status == MCScanStatus.FAILED
    # Nothing was recorded, so nothing holds the directory.
    assert entry.could_not_stop == ()
    assert entry.occupies_its_directory() is False


@pytest.mark.asyncio
async def test_a_stop_that_ended_every_tool_adds_no_warning(tmp_path, monkeypatch):
    """Control: a timeout with nothing left running stays a plain timeout."""
    registry, scan_id, output_dir = _registered(tmp_path, monkeypatch)

    def a_scan_the_timer_stops_cleanly(*args: Any, **kwargs: Any) -> None:
        _stop_as_the_timer_does(registry, scan_id)
        raise_if_cancelled()
        raise AssertionError("control: the scan was not stopped")

    async def run() -> None:
        await mcp_tools._run_scan_async(
            scan_id=scan_id,
            directory_path=str(tmp_path),
            output_dir=str(output_dir),
            severity_threshold=None,
        )

    await _run_to_the_end(registry, scan_id, a_scan_the_timer_stops_cleanly, run)

    entry = registry.get_scan(scan_id)
    assert entry.status == MCScanStatus.FAILED
    assert entry.warnings == [], entry.warnings
    assert entry.could_not_stop == ()
