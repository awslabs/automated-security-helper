# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan task's starter reads for itself whether the runner ran.

``_start_scan_task`` gives back what a runner never took (the PENDING entry,
the session claim, the count) when the task is cancelled before the loop first
ran it. Whether the runner ran used to be a marker the caller allocated and had
to pass twice, to the runner (which set it) and to the starter (which read it);
a caller that passed it to the starter alone would have had the callback
release, a second time, everything a runner that did run released itself, and
a caller that passed it to neither got no give-back at all. The starter now
marks the start itself, through a wrapper that runs before the runner's first
line.
"""

from __future__ import annotations

import asyncio
from typing import List

import pytest

from automated_security_helper.cli import mcp_tools

pytestmark = pytest.mark.unit


def _task_of(scan_id: str) -> asyncio.Task:
    tasks = [t for t, sid in list(mcp_tools._scan_tasks.items()) if sid == scan_id]
    assert len(tasks) == 1, tasks
    return tasks[0]


@pytest.mark.asyncio
async def test_a_task_cancelled_before_it_ran_gives_back_what_the_runner_never_took():
    """Red at the base: with no marker handed in, the starter registered no
    give-back, so a cancel before the first step released nothing."""
    body: List[str] = []
    released: List[str] = []

    async def runner() -> None:
        body.append("ran")

    mcp_tools._start_scan_task(
        "never-ran", runner(), if_never_run=lambda: released.append("released")
    )
    task = _task_of("never-ran")
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    # Done callbacks run on the loop after the task settles.
    await asyncio.sleep(0)

    assert task.cancelled(), task
    assert body == [], body
    assert released == ["released"], released
    assert task not in mcp_tools._scan_tasks


@pytest.mark.asyncio
async def test_a_runner_that_ran_is_not_given_back_for():
    """Control: a runner that ran a line released what it held itself, so the
    give-back must not run, whether the runner returned or raised."""
    body: List[str] = []
    released: List[str] = []

    async def returns() -> None:
        body.append("returned")

    async def raises() -> None:
        body.append("raised")
        raise RuntimeError("the runner failed on its own")

    mcp_tools._start_scan_task(
        "returned", returns(), if_never_run=lambda: released.append("returned")
    )
    mcp_tools._start_scan_task(
        "raised", raises(), if_never_run=lambda: released.append("raised")
    )
    await asyncio.gather(
        _task_of("returned"), _task_of("raised"), return_exceptions=True
    )
    await asyncio.sleep(0)

    assert body == ["returned", "raised"], body
    assert released == [], released
