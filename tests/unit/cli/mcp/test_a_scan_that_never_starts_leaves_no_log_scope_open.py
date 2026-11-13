# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan's run log scope closes on every ending, and not before its last line.

The directory scan tool opens the scan's run log scope before it registers the
scan, and the runner task and the thread the scan runs on write to it. While a
scope the server opened is open, a line logged outside every scan reaches no
run's handlers (utils/log.py), so one left open holds that for the rest of the
process; one closed while the scan's thread still writes loses the end of that
scan's ash.log. The cells end a scan every way it can end before it runs: a
runner cancelled before the event loop first ran it (as the server's stop
does to a scan still queued), a scan the registry refuses, a scan the registry
no longer knows, a start that fails after the registration, a runner that fails to join the scope, a
scan whose job is still queued for a thread when its task is cancelled; and a
scan whose task is cancelled while its thread runs on.
"""

import asyncio
import threading
from contextlib import suppress
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.utils import log as ash_log
from automated_security_helper.utils.log import ASHLogger
from tests.utils.tasks import drain_clean

pytestmark = pytest.mark.unit

_TOOLS = "automated_security_helper.cli.mcp_tools"
_RUN_ASH_SCAN = "automated_security_helper.interactions.run_ash_scan.run_ash_scan"


def _new_tasks(earlier):
    # Only this call's task: another test's stand-in may still be listed.
    return [task for task in mcp_tools._scan_tasks if task not in earlier]


def test_a_scan_whose_runner_never_starts_leaves_no_log_scope_open(
    tmp_path, monkeypatch
):
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    registry = MagicMock(spec=ScanRegistry)
    registry.register_scan.return_value = "scan-1"
    before = set(ash_log._ACTIVE_RUN_LOG_SCOPES)
    started = []

    async def a_runner_that_would_wait(**kwargs):
        started.append(True)
        await asyncio.Event().wait()

    async def start_then_stop():
        earlier = set(mcp_tools._scan_tasks)
        answer = await mcp_tools.mcp_scan_directory(str(tmp_path))
        held = set(ash_log._ACTIVE_RUN_LOG_SCOPES) - before
        # Cancelled before the loop ever ran it: its own cleanup never runs.
        tasks = _new_tasks(earlier)
        for task in tasks:
            task.cancel()
        # The cancel is the test's own: the runner never ran, so a
        # CancelledError is the one outcome these tasks are meant to have.
        await drain_clean(tasks=tasks, expected=(asyncio.CancelledError,))
        return answer, held, tasks

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        patch(f"{_TOOLS}._run_scan_async", a_runner_that_would_wait),
    ):
        answer, held, tasks = asyncio.run(start_then_stop())

    # Controls: the scan was started and its runner task never ran.
    if not (answer.get("success") is True and len(tasks) == 1 and len(held) == 1):
        raise RuntimeError(("control: the scan did not start", answer, tasks, held))
    if started:
        raise RuntimeError("control: the runner ran before it was cancelled")
    assert set(ash_log._ACTIVE_RUN_LOG_SCOPES) == before, (
        "the scan's log scope is still open"
    )
    assert not (held & set(ash_log._HOSTED_RUN_LOG_SCOPES)), (
        "the scan still counts as a scan the server runs"
    )


def test_a_scan_the_registry_no_longer_knows_leaves_no_log_scope_open(
    tmp_path, monkeypatch
):
    """The runner returns at once for a scan id the registry does not hold."""
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    registry = MagicMock(spec=ScanRegistry)
    registry.register_scan.return_value = "scan-1"
    registry.get_scan.return_value = None
    before = set(ash_log._ACTIVE_RUN_LOG_SCOPES)

    async def start_and_drain():
        earlier = set(mcp_tools._scan_tasks)
        answer = await mcp_tools.mcp_scan_directory(str(tmp_path))
        held = set(ash_log._ACTIVE_RUN_LOG_SCOPES) - before
        tasks = _new_tasks(earlier)
        await drain_clean(tasks=tasks)
        return answer, held, tasks

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
    ):
        answer, held, tasks = asyncio.run(start_and_drain())

    if not (answer.get("success") is True and len(tasks) == 1 and len(held) == 1):
        raise RuntimeError(("control: the scan did not start", answer, tasks, held))
    if not registry.get_scan.called:
        raise RuntimeError("control: the runner never asked the registry")
    assert set(ash_log._ACTIVE_RUN_LOG_SCOPES) == before, (
        "the scan's log scope is still open"
    )


def test_a_scan_the_registry_refuses_leaves_no_log_scope_open(tmp_path, monkeypatch):
    """The registry refuses the scan, as it does one past the concurrency
    limit: the tool answers the refusal, and the scope it opened before the
    registration is closed and gone from the caller's context."""
    from automated_security_helper.core.resource_management.exceptions import (
        MCPResourceError,
    )

    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    registry = MagicMock(spec=ScanRegistry)
    registry.register_scan.side_effect = MCPResourceError("too many scans")
    before = set(ash_log._ACTIVE_RUN_LOG_SCOPES)

    async def start():
        earlier = set(mcp_tools._scan_tasks)
        answer = await mcp_tools.mcp_scan_directory(str(tmp_path))
        return answer, ash_log.current_run_log_scope(), _new_tasks(earlier)

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
    ):
        answer, scope_after, tasks = asyncio.run(start())

    if answer.get("success") is not False or tasks:
        raise RuntimeError(("control: the scan was not refused", answer, tasks))
    if not registry.register_scan.called:
        raise RuntimeError("control: the registry was never asked")
    assert scope_after is None, "the caller's context still holds the scan's scope"
    assert set(ash_log._ACTIVE_RUN_LOG_SCOPES) == before, (
        "the scan's log scope is still open"
    )


def test_a_start_that_fails_after_the_registration_leaves_no_log_scope_open(
    tmp_path, monkeypatch
):
    """The previous results cannot be set aside for a reason the tool does not
    answer as a warning: the tool answers the error, and the scope it opened is
    closed and gone from the caller's context."""
    from automated_security_helper.core.previous_results import PreviousResults

    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    registry = MagicMock(spec=ScanRegistry)
    registry.register_scan.return_value = "scan-1"
    before = set(ash_log._ACTIVE_RUN_LOG_SCOPES)

    async def start():
        earlier = set(mcp_tools._scan_tasks)
        answer = await mcp_tools.mcp_scan_directory(str(tmp_path), clean_output=True)
        return answer, ash_log.current_run_log_scope(), _new_tasks(earlier)

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        patch.object(
            PreviousResults, "set_aside", side_effect=ValueError("not set aside")
        ),
    ):
        answer, scope_after, tasks = asyncio.run(start())

    if answer.get("success") is not False or tasks:
        raise RuntimeError(("control: the start did not fail", answer, tasks))
    if not registry.register_scan.called:
        raise RuntimeError("control: the scan was never registered")
    assert scope_after is None, "the caller's context still holds the scan's scope"
    assert set(ash_log._ACTIVE_RUN_LOG_SCOPES) == before, (
        "the scan's log scope is still open"
    )


def test_a_runner_that_cannot_join_its_scope_leaves_no_scan_running(
    tmp_path, monkeypatch
):
    """Joining the scope is part of the runner's work, so its failure closes
    the entry as every other failure does, and never leaves it RUNNING."""
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    registry = ScanRegistry()
    before = set(ash_log._ACTIVE_RUN_LOG_SCOPES)

    async def start_and_drain():
        earlier = set(mcp_tools._scan_tasks)
        answer = await mcp_tools.mcp_scan_directory(str(tmp_path), clean_output=False)
        tasks = _new_tasks(earlier)
        await drain_clean(tasks=tasks)
        return answer, tasks

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        patch(
            f"{_TOOLS}.begin_run_log_scope",
            side_effect=RuntimeError("the scope could not be joined"),
        ),
    ):
        answer, tasks = asyncio.run(start_and_drain())

    if answer.get("success") is not True or len(tasks) != 1:
        raise RuntimeError(("control: the scan did not start", answer, tasks))
    entry = registry.get_scan(answer["scan_id"])
    assert entry.status != MCScanStatus.RUNNING, "the entry reads as running forever"
    assert entry.runner_done.is_set(), "the runner never said it was done"
    assert set(ash_log._ACTIVE_RUN_LOG_SCOPES) == before, (
        "the scan's log scope is still open"
    )


def test_a_scan_whose_thread_never_starts_leaves_no_log_scope_open(
    tmp_path, monkeypatch
):
    """The runner ran and its scan job was still queued when its task was
    cancelled: the executor drops the job, so the thread that would have let go
    of the scope never runs, and the task lets go for it."""
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    registry = ScanRegistry()
    before = set(ash_log._ACTIVE_RUN_LOG_SCOPES)

    async def start_queue_then_cancel():
        loop = asyncio.get_running_loop()
        queued = asyncio.Event()
        run_in_executor = loop.run_in_executor

        def never_runs(executor, func, *args):
            # Only the scan's own job: the tool's checks run on threads too.
            if not (
                args and getattr(args[0], "__name__", "") == "_scan_under_session_lock"
            ):
                return run_in_executor(executor, func, *args)
            queued.set()
            return loop.create_future()

        monkeypatch.setattr(loop, "run_in_executor", never_runs)
        earlier = set(mcp_tools._scan_tasks)
        answer = await mcp_tools.mcp_scan_directory(str(tmp_path), clean_output=False)
        (task,) = _new_tasks(earlier)
        await asyncio.wait_for(queued.wait(), timeout=30)
        held = set(ash_log._ACTIVE_RUN_LOG_SCOPES) - before
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        return answer, held

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
    ):
        answer, held = asyncio.run(start_queue_then_cancel())

    if not (answer.get("success") is True and len(held) == 1):
        raise RuntimeError(("control: the scan was not queued", answer, held))
    entry = registry.get_scan(answer["scan_id"])
    if not entry.runner_done.is_set():
        raise RuntimeError("control: the task did not settle for the thread")
    assert set(ash_log._ACTIVE_RUN_LOG_SCOPES) == before, (
        "the scan's log scope is still open"
    )


def test_a_cancelled_scans_thread_keeps_its_log_scope_until_it_ends(
    tmp_path, monkeypatch
):
    """Cancelling the runner's task does not stop the thread the scan runs on:
    it runs on until the cancel event stops it, and its last lines are the
    scan's. The scope stays open until that thread ends, and closes then."""
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    registry = ScanRegistry()
    before = set(ash_log._ACTIVE_RUN_LOG_SCOPES)
    thread_started = threading.Event()
    let_thread_finish = threading.Event()
    seen = {}

    def a_scan_that_outlives_its_task(**kwargs):
        thread_started.set()
        let_thread_finish.wait(30)
        scope = ash_log.current_run_log_scope()
        seen["scope"] = scope
        seen["open_at_its_last_line"] = scope in ash_log._ACTIVE_RUN_LOG_SCOPES
        return None

    async def start_cancel_then_finish():
        earlier = set(mcp_tools._scan_tasks)
        answer = await mcp_tools.mcp_scan_directory(str(tmp_path), clean_output=False)
        (task,) = _new_tasks(earlier)
        await asyncio.to_thread(thread_started.wait, 30)
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        let_thread_finish.set()
        entry = registry.get_scan(answer["scan_id"])
        await asyncio.to_thread(entry.runner_done.wait, 30)
        return answer, entry

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        patch(_RUN_ASH_SCAN, a_scan_that_outlives_its_task),
    ):
        answer, entry = asyncio.run(start_cancel_then_finish())

    if not (thread_started.is_set() and entry.runner_done.is_set() and seen):
        raise RuntimeError(("control: the scan's thread did not run", seen))
    if entry.status != MCScanStatus.FAILED:
        raise RuntimeError(("control: the task was not cancelled", entry.status))
    assert seen["scope"] is not None, "the scan's thread ran outside its scope"
    assert seen["open_at_its_last_line"], (
        "the scope closed while the scan's thread still wrote to it"
    )
    assert set(ash_log._ACTIVE_RUN_LOG_SCOPES) == before, (
        "the scan's log scope is still open after its thread ended"
    )
