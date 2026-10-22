# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Pin what tests.utils.tasks.drain does when one of the other tasks raises."""

from __future__ import annotations

import asyncio

import pytest

from tests.utils.tasks import drain


async def _fails() -> None:
    raise ValueError("the failing task")


def test_drain_is_fail_fast_by_default():
    """The first failure reaches the caller while the healthy task still runs."""

    async def scenario() -> bool:
        release = asyncio.Event()

        async def healthy() -> None:
            await release.wait()

        healthy_task = asyncio.create_task(healthy())
        asyncio.create_task(_fails())
        with pytest.raises(ValueError, match="the failing task"):
            await drain()
        still_running = not healthy_task.done()
        release.set()
        await healthy_task
        return still_running

    assert asyncio.run(scenario()) is True


def test_drain_with_return_exceptions_waits_for_every_task():
    """A failure is swallowed and the healthy task is waited for to the end."""

    async def scenario():
        failed = asyncio.Event()
        finished = []

        async def fails_after_signal() -> None:
            failed.set()
            raise ValueError("the failing task")

        async def healthy() -> None:
            await failed.wait()
            await asyncio.sleep(0)
            finished.append("healthy")

        healthy_task = asyncio.create_task(healthy())
        failing_task = asyncio.create_task(fails_after_signal())
        result = await drain(return_exceptions=True)
        return result, finished, healthy_task, failing_task

    result, finished, healthy_task, failing_task = asyncio.run(scenario())
    assert result is None
    assert finished == ["healthy"]
    assert healthy_task.done() and healthy_task.exception() is None
    assert isinstance(failing_task.exception(), ValueError)
