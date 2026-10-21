# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A cancelled scan runner leaves no profile snapshot and no open entry.

The runner copies the session's trusted profile for the scan and reads the
copy's environment values on a worker thread, awaiting the thread from the
event loop. The runner's task can be cancelled while that read runs -- the
server's shutdown cancels every in-flight runner -- and a cancel there must
settle the registry entry, because an entry left PENDING reads as a scan that
never ends, and discard the copy, which select_profile never writes and
nothing else removes.

Driven end to end through the directory tool against a real session sandbox
(the delivered config is the client's by the sandbox's own classification,
the profile is bound through the profile registry), with only
``run_ash_scan`` replaced.
"""

import asyncio
import threading
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import profile_registry
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.utils.log import ASHLogger
from tests.utils.mcp_sessions import a_session_with_a_bound_profile

_TOOLS = "automated_security_helper.cli.mcp_tools"
_MGMT = "automated_security_helper.core.resource_management.scan_management"


def _a_session_with_a_bound_profile(tmp_path, monkeypatch, session_id):
    """A real session sandbox with a delivered config and a bound profile."""
    target, delivered, _profile, config_dir = a_session_with_a_bound_profile(
        tmp_path / "ws", monkeypatch, session_id
    )
    return target, delivered, config_dir


def _snapshot_leftovers(config_dir: Path) -> List[str]:
    return sorted(
        p.name for p in config_dir.iterdir() if p.name.startswith(".ash-scan-")
    )


def test_a_runner_cancelled_at_the_snapshot_read_settles_and_discards(
    tmp_path, monkeypatch
):
    """Cancel the runner's task while the profile snapshot's values are read.

    The copy is on disk at that moment and the scan has not started. The
    runner must still close its entry -- the reason names the cancellation --
    and remove the copy; the scan stand-in must never run.
    """
    session_id = "cancel-at-read-session"
    target, delivered, config_dir = _a_session_with_a_bound_profile(
        tmp_path, monkeypatch, session_id
    )
    entered, release, finished = (
        threading.Event(),
        threading.Event(),
        threading.Event(),
    )
    real_read = mcp_tools._profile_environment_values

    def a_read_that_blocks(*args, **kwargs):
        entered.set()
        release.wait(30)
        try:
            return real_read(*args, **kwargs)
        finally:
            finished.set()

    monkeypatch.setattr(mcp_tools, "_profile_environment_values", a_read_that_blocks)
    registry = ScanRegistry()
    seen: Dict[str, Any] = {}

    def a_run_that_must_not_start(*args, **kwargs):
        seen["ran"] = True
        raise RuntimeError("the tool crashed")

    async def start_cancel_and_wait():
        started = await mcp_tools.mcp_scan_directory(
            str(target), config_path=str(delivered), session_id=session_id
        )
        if not await asyncio.to_thread(entered.wait, 30):
            raise RuntimeError("control: the read was never entered")
        tasks = [
            t
            for t, s in list(mcp_tools._scan_tasks.items())
            if s == started.get("scan_id")
        ]
        if len(tasks) != 1:
            raise RuntimeError(("control: not one runner task", tasks))
        tasks[0].cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        # The runner's own cleanup has run; only now may the read finish, so
        # the cell separates the runner's discard from the thread's.
        release.set()
        await asyncio.to_thread(finished.wait, 30)
        return started, tasks[0]

    try:
        with (
            patch.object(ras, "run_ash_scan", a_run_that_must_not_start),
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(f"{_MGMT}.get_scan_registry", return_value=registry),
            patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        ):
            started, task = asyncio.run(start_cancel_and_wait())
    finally:
        profile_registry.clear_session_state(session_id)

    entry = registry.get_scan(started["scan_id"])
    # Controls: the cancel landed at the read, before the scan could start.
    assert task.cancelled(), task
    assert "ran" not in seen, seen
    # The entry is settled: a client polling it is told the scan ended, not
    # left watching a pending entry whose runner is gone.
    assert entry.status == MCScanStatus.FAILED, (entry.status, entry.error_message)
    assert "without a result" in (entry.error_message or ""), entry.error_message
    # The copy the runner took does not outlive the runner.
    assert _snapshot_leftovers(config_dir) == [], _snapshot_leftovers(config_dir)


def test_a_runner_cancelled_while_its_scan_runs_discards_after_the_thread(
    tmp_path, monkeypatch
):
    """Cancel the runner's task while the scan itself runs on its thread.

    Cancelling the task does not stop the thread, and the scan may yet load
    its copy of the profile: the copy must still be there while the thread
    runs, and gone once the thread ends -- the thread's own cleanup is what
    discards it on this path.
    """
    session_id = "cancel-mid-scan-session"
    target, delivered, config_dir = _a_session_with_a_bound_profile(
        tmp_path, monkeypatch, session_id
    )
    entered, release = threading.Event(), threading.Event()
    seen: Dict[str, Any] = {}

    def a_run_that_waits(*args, **kwargs):
        seen["trusted"] = kwargs.get("trusted_config_path")
        seen["copy_on_disk"] = Path(kwargs["trusted_config_path"]).is_file()
        entered.set()
        release.wait(30)
        raise RuntimeError("the tool crashed")

    registry = ScanRegistry()

    async def start_cancel_and_release():
        started = await mcp_tools.mcp_scan_directory(
            str(target), config_path=str(delivered), session_id=session_id
        )
        if not await asyncio.to_thread(entered.wait, 30):
            raise RuntimeError("control: the scan never started")
        tasks = [
            t
            for t, s in list(mcp_tools._scan_tasks.items())
            if s == started.get("scan_id")
        ]
        if len(tasks) != 1:
            raise RuntimeError(("control: not one runner task", tasks))
        tasks[0].cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        # The task is gone but the scan thread still runs: the copy it may
        # yet load must still be there.
        seen["after_cancel"] = _snapshot_leftovers(config_dir)
        release.set()
        return started

    try:
        with (
            patch.object(ras, "run_ash_scan", a_run_that_waits),
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(f"{_MGMT}.get_scan_registry", return_value=registry),
            patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        ):
            # asyncio.run's close waits for the default executor, so the scan
            # thread has ended, and run its cleanup, when this returns.
            asyncio.run(start_cancel_and_release())
    finally:
        profile_registry.clear_session_state(session_id)

    # Controls: the scan was running on its copy when the cancel landed.
    assert seen.get("copy_on_disk"), seen
    assert Path(seen["trusted"]).name.startswith(".ash-scan-"), seen
    assert seen["after_cancel"], (
        "the copy was gone while the scan thread still ran",
        seen,
    )
    assert _snapshot_leftovers(config_dir) == [], _snapshot_leftovers(config_dir)


def test_a_runner_cancelled_while_the_copy_is_written_leaves_no_snapshot(
    tmp_path, monkeypatch
):
    """Cancel the runner's task while the copy itself is being written.

    Cancelling the task never stops the worker thread the copy is written
    on: the runner's own cleanup can run while the file exists but before
    the worker has recorded it. Whichever side finishes last must discard
    the copy -- a file recorded after the runner's cleanup ran is otherwise
    discarded by nothing, and sits beside the session's config for good.
    """
    session_id = "cancel-mid-write-session"
    target, delivered, config_dir = _a_session_with_a_bound_profile(
        tmp_path, monkeypatch, session_id
    )
    created, release = threading.Event(), threading.Event()
    real_snapshot = mcp_tools._snapshot_profile_for_scan

    def a_copy_that_blocks_before_it_is_recorded(profile, scan_id, *args, **kwargs):
        # The real copy is on disk when this returns control to the cell:
        # the block stands in for the window between the file's creation
        # and the worker recording its path.
        snapshot = real_snapshot(profile, scan_id, *args, **kwargs)
        created.set()
        release.wait(30)
        return snapshot

    monkeypatch.setattr(
        mcp_tools,
        "_snapshot_profile_for_scan",
        a_copy_that_blocks_before_it_is_recorded,
    )
    registry = ScanRegistry()
    seen: Dict[str, Any] = {}

    def a_run_that_must_not_start(*args, **kwargs):
        seen["ran"] = True
        raise RuntimeError("the tool crashed")

    async def start_cancel_and_release():
        started = await mcp_tools.mcp_scan_directory(
            str(target), config_path=str(delivered), session_id=session_id
        )
        if not await asyncio.to_thread(created.wait, 30):
            raise RuntimeError("control: the copy was never written")
        tasks = [
            t
            for t, s in list(mcp_tools._scan_tasks.items())
            if s == started.get("scan_id")
        ]
        if len(tasks) != 1:
            raise RuntimeError(("control: not one runner task", tasks))
        tasks[0].cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        # The runner's cleanup has run; the copy is still unrecorded on the
        # blocked worker. Control: the file survived that cleanup, which is
        # the window under test.
        seen["after_runner_cleanup"] = _snapshot_leftovers(config_dir)
        release.set()
        return started, tasks[0]

    try:
        with (
            patch.object(ras, "run_ash_scan", a_run_that_must_not_start),
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(f"{_MGMT}.get_scan_registry", return_value=registry),
            patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        ):
            # asyncio.run's close waits for the default executor, so the
            # worker thread has finished -- and recorded or discarded its
            # copy -- when this returns.
            started, task = asyncio.run(start_cancel_and_release())
    finally:
        profile_registry.clear_session_state(session_id)

    entry = registry.get_scan(started["scan_id"])
    # Controls: the cancel landed while the copy was written, before the
    # scan could start.
    assert task.cancelled(), task
    assert "ran" not in seen, seen
    assert entry.status == MCScanStatus.FAILED, (entry.status, entry.error_message)
    assert "without a result" in (entry.error_message or ""), entry.error_message
    # Whichever side ran last, the copy does not outlive the runner.
    assert _snapshot_leftovers(config_dir) == [], _snapshot_leftovers(config_dir)
