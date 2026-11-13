# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan whose task is cancelled before its runner ran closes its entry.

The directory tool registers the scan, claims the entry for its runner
(``has_runner``) and starts the runner as a task. A task cancelled before the
loop first ran it runs no line of its coroutine, its ``finally`` included, so
nothing the runner would have released is released by the runner: the tool
hands ``_start_scan_task`` an ``if_never_run`` callback for that case, and the
callback closes the entry as a scan that did not start and marks the runner
done. Without it the entry stays PENDING with a runner that will never come,
and it holds its directory and a ``max_concurrent_scans`` slot for the life of
the server.

The other tests of the start replace ``_start_scan_task`` with a stand-in that
accepts ``if_never_run`` and drops it, so none of them reaches this path. This
one starts the scan through the real ``_start_scan_task`` and cancels the task
before the loop gets to it.
"""

import asyncio
import time
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.utils.log import ASHLogger

pytestmark = pytest.mark.unit

_TOOLS = "automated_security_helper.cli.mcp_tools"
_WAIT_SECONDS = 10.0


async def _until(condition) -> bool:
    deadline = time.monotonic() + _WAIT_SECONDS
    while not condition():
        if time.monotonic() > deadline:
            return False
        await asyncio.sleep(0.01)
    return True


def test_a_task_cancelled_before_its_runner_ran_closes_the_entry(tmp_path, monkeypatch):
    """Red without the ``if_never_run`` callback: the entry stays PENDING with a
    runner that never comes, and the directory stays occupied."""
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    registry = ScanRegistry()
    real_start = mcp_tools._start_scan_task
    tasks = []

    def start_then_cancel_before_the_loop_runs_it(scan_id, runner, **options):
        real_start(scan_id, runner, **options)
        for task, owner in list(mcp_tools._scan_tasks.items()):
            if owner == scan_id:
                tasks.append(task)
                task.cancel()

    async def start_and_wait_for_the_end_of_the_task():
        started = await mcp_tools.mcp_scan_directory(str(tmp_path))
        entry = (
            registry.get_scan(started["scan_id"]) if started.get("success") else None
        )
        ended = entry is not None and await _until(entry.runner_done.is_set)
        return started, entry, ended

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        patch(
            f"{_TOOLS}._start_scan_task",
            side_effect=start_then_cancel_before_the_loop_runs_it,
        ),
    ):
        started, entry, ended = asyncio.run(start_and_wait_for_the_end_of_the_task())

    # Controls: the scan started, and its task was cancelled before it ran.
    assert started.get("success") is True, started
    assert len(tasks) == 1, "control: the scan's task was not found"
    assert tasks[0].cancelled(), "control: the task was not cancelled"
    assert entry is not None

    assert ended, (
        "the runner was never marked done: the entry still holds its directory"
    )
    assert entry.status is MCScanStatus.FAILED, entry.status
    assert "could not be started" in (entry.error_message or ""), entry.error_message
    assert not entry.occupies_its_directory()
    # The slot and the directory are free: a registration at a limit of one,
    # for the same directory, is admitted.
    assert registry.register_scan(
        directory_path=str(tmp_path),
        output_directory=str(tmp_path / ".ash" / "ash_output"),
        max_active=1,
    )
