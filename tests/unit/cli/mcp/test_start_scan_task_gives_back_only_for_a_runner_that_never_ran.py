# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``_start_scan_task`` gives back a scan's holdings only when its runner never ran.

``if_never_run`` releases what the runner's own ``finally`` would have released
(the claim, the count, the PENDING entry) for a task that ended before the loop
ran a line of the runner. A runner that began releases all of that itself, so a
task that ends by an exception or by a cancel after it began must not be given
back a second time: the claim would be released twice, and the entry closed as a
scan that did not start when it had run.

Whether the runner began is read from a marker the wrapper sets before the
runner's first line, so every task that ended after it carries the marker, however
it ended. These tests pin that for the two ways a begun runner ends other than
by returning, beside the case the callback exists for.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable, List

import pytest

from automated_security_helper.cli import mcp_tools

pytestmark = pytest.mark.unit

SCAN_ID = "scan-under-test"


def _task_of(scan_id: str) -> "asyncio.Task[None]":
    return next(
        task for task, owner in mcp_tools._scan_tasks.items() if owner == scan_id
    )


def _run(scenario: Callable[[List[str]], Any]) -> List[str]:
    """Run ``scenario`` on a fresh loop; return what ``if_never_run`` was asked."""
    given_back: List[str] = []
    asyncio.run(scenario(given_back))
    return given_back


def test_a_runner_that_failed_after_it_began_is_not_given_back() -> None:
    ended: List[Any] = []

    async def scenario(given_back: List[str]) -> None:
        async def runner() -> None:
            raise RuntimeError("the scan failed after it began")

        mcp_tools._start_scan_task(
            SCAN_ID, runner(), if_never_run=lambda: given_back.append(SCAN_ID)
        )
        task = _task_of(SCAN_ID)
        await asyncio.wait([task])
        await asyncio.sleep(0)
        ended.append(task.exception())

    given_back = _run(scenario)

    # Control: the task did end by the runner's own exception.
    assert isinstance(ended[0], RuntimeError), ended
    assert given_back == [], given_back


def test_a_runner_cancelled_after_it_began_is_not_given_back() -> None:
    ended: List[bool] = []

    async def scenario(given_back: List[str]) -> None:
        async def runner() -> None:
            await asyncio.sleep(60)

        mcp_tools._start_scan_task(
            SCAN_ID, runner(), if_never_run=lambda: given_back.append(SCAN_ID)
        )
        task = _task_of(SCAN_ID)
        # The loop runs the task to its first suspension: the runner has begun.
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.wait([task])
        await asyncio.sleep(0)
        ended.append(task.cancelled())

    given_back = _run(scenario)

    # Control: the task ended by the cancel.
    assert ended == [True], ended
    assert given_back == [], given_back


def test_a_task_cancelled_before_the_loop_ran_it_is_given_back_once() -> None:
    async def scenario(given_back: List[str]) -> None:
        async def runner() -> None:
            raise AssertionError("the runner must not run")

        mcp_tools._start_scan_task(
            SCAN_ID, runner(), if_never_run=lambda: given_back.append(SCAN_ID)
        )
        task = _task_of(SCAN_ID)
        task.cancel()
        await asyncio.wait([task])
        await asyncio.sleep(0)

    given_back = _run(scenario)

    assert given_back == [SCAN_ID], given_back
