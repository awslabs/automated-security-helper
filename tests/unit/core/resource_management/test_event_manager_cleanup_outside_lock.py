# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""unregister_subscription runs a cleanup to completion, outside the manager's lock.

Two mechanisms, each pinned against the behavior it replaced:

* A cleanup callable that was not a coroutine function but returned an
  awaitable (a plain function returning a coroutine, a bound method wrapped by
  a decorator) was called and its awaitable dropped, so the cleanup never ran
  and the unregistration reported success.
* The cleanup was awaited while the manager's non-reentrant ``asyncio.Lock``
  was held, so a cleanup that called back into the manager deadlocked, and a
  slow cleanup stalled every other caller for its duration.
"""

import asyncio
import inspect

import pytest

from automated_security_helper.core.resource_management.event_manager import (
    EventSubscriptionManager,
)

pytestmark = pytest.mark.unit


async def _register(manager, subscription_id, cleanup_func, scan_id=None):
    await manager.register_subscription(
        subscription_id=subscription_id,
        event_type="scan_progress",
        handler=lambda event: None,
        cleanup_func=cleanup_func,
        scan_id=scan_id,
    )


class TestAnAwaitableReturnedByACleanupIsAwaited:
    @pytest.mark.asyncio
    async def test_a_plain_function_returning_a_coroutine_runs_to_completion(self):
        manager = EventSubscriptionManager()
        ran = []

        async def really_clean_up():
            ran.append("ran")

        def cleanup():  # not a coroutine function; returns one
            return really_clean_up()

        assert not inspect.iscoroutinefunction(cleanup)
        await _register(manager, "sub", cleanup)

        assert await manager.unregister_subscription("sub") is True
        assert ran == ["ran"]

    @pytest.mark.asyncio
    async def test_a_failure_inside_the_returned_coroutine_is_recorded(self):
        manager = EventSubscriptionManager()

        async def really_clean_up():
            raise RuntimeError("cleanup failed late")

        await _register(manager, "sub", lambda: really_clean_up())

        assert await manager.unregister_subscription("sub") is False
        errors = manager.get_cleanup_errors()
        assert len(errors) == 1
        assert "cleanup failed late" in errors[0]["error"]
        assert manager.get_subscription_info("sub") is None

    @pytest.mark.asyncio
    async def test_a_synchronous_cleanup_still_runs(self):
        manager = EventSubscriptionManager()
        ran = []
        await _register(manager, "sub", lambda: ran.append("ran"))

        assert await manager.unregister_subscription("sub") is True
        assert ran == ["ran"]


class TestTheScanScopedCleanupRunsEachCleanupTheSameWay:
    """cleanup_subscriptions_by_scan runs every cleanup through
    unregister_subscription; both fixes are pinned through that path too."""

    @pytest.mark.asyncio
    async def test_a_re_entrant_cleanup_does_not_deadlock_the_scan_cleanup(self):
        manager = EventSubscriptionManager()
        await _register(manager, "other", None, scan_id="scan-1")

        async def cleanup():
            # Would wait on the manager's lock forever if that were still held.
            await manager.unregister_subscription("other")

        await _register(manager, "sub", cleanup, scan_id="scan-1")

        results = await asyncio.wait_for(
            manager.cleanup_subscriptions_by_scan("scan-1"), 5
        )

        assert results["total_subscriptions"] == 2
        assert results["successful_cleanups"] + results["failed_cleanups"] == 2
        assert results["errors"] == []
        assert manager.get_subscriptions_by_scan("scan-1") == []
        assert manager.get_subscription_info("sub") is None
        assert manager.get_subscription_info("other") is None

    @pytest.mark.asyncio
    async def test_a_cleanup_returning_a_coroutine_runs_to_completion(self):
        manager = EventSubscriptionManager()
        ran = []

        async def really_clean_up():
            ran.append("ran")

        await _register(manager, "sub", lambda: really_clean_up(), scan_id="scan-1")

        results = await manager.cleanup_subscriptions_by_scan("scan-1")

        assert results == {
            "scan_id": "scan-1",
            "total_subscriptions": 1,
            "successful_cleanups": 1,
            "failed_cleanups": 0,
            "errors": [],
        }
        assert ran == ["ran"]


class TestTheCleanupRunsOutsideTheLock:
    @pytest.mark.asyncio
    async def test_a_cleanup_that_calls_back_into_the_manager_does_not_deadlock(
        self,
    ):
        manager = EventSubscriptionManager()
        await _register(manager, "other", None, scan_id="scan-1")

        async def cleanup():
            # Would wait on the manager's lock forever if that were still held.
            await manager.unregister_subscription("other")

        await _register(manager, "sub", cleanup, scan_id="scan-1")

        result = await asyncio.wait_for(manager.unregister_subscription("sub"), 5)

        assert result is True
        assert manager.get_subscription_info("sub") is None
        assert manager.get_subscription_info("other") is None

    @pytest.mark.asyncio
    async def test_a_slow_cleanup_does_not_stall_other_callers(self):
        """The other caller is tried only once the slow cleanup has started, so
        the test measures the lock being free DURING the cleanup. One
        sleep(0) assumed the slow task had reached the cleanup, which held
        only while unregister_subscription had no await before its lock."""
        manager = EventSubscriptionManager()
        release = asyncio.Event()
        started = asyncio.Event()

        async def slow_cleanup():
            started.set()
            await release.wait()

        await _register(manager, "slow", slow_cleanup)
        await _register(manager, "quick", None)

        slow = asyncio.create_task(manager.unregister_subscription("slow"))
        try:
            await asyncio.wait_for(started.wait(), 1)
            # Another caller gets through while the slow cleanup is running.
            assert await asyncio.wait_for(manager.unregister_subscription("quick"), 1)
            assert not slow.done()
        finally:
            release.set()

        assert await asyncio.wait_for(slow, 1) is True

    @pytest.mark.asyncio
    async def test_the_subscription_is_gone_before_its_cleanup_runs(self):
        manager = EventSubscriptionManager()
        seen = []

        def cleanup():
            seen.append(manager.get_subscription_info("sub"))

        await _register(manager, "sub", cleanup)

        await manager.unregister_subscription("sub")

        assert seen == [None]
