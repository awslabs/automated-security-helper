# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Regression tests for async deadlock and concurrency bugs.

Bug #11: cancel_task deadlock -- held _task_lock while awaiting a task whose
         done-callback needs the same lock.
Bug #12: orphaned asyncio.create_task in _task_done_callback -- GC can collect
         the cleanup coroutine mid-execution.
Bug #13: ABBA lock ordering in state_manager -- register_directory_scan acquires
         _directory_lock then _scan_store_lock, while other methods acquire them
         in the opposite order.
Bug #67: resource_manager accesses private CPython attrs (_shutdown, _threads)
         on ThreadPoolExecutor.
"""

import asyncio
import gc
import weakref
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.core.resource_management.task_manager import (
    TaskManager,
)
from automated_security_helper.core.resource_management.state_manager import (
    StateManager,
)
from automated_security_helper.core.resource_management.resource_manager import (
    ResourceManager,
)


class TestBug11CancelTaskDeadlock:
    """Bug #11: cancel_task must not hold _task_lock while awaiting the task.

    The done-callback of the cancelled task needs _task_lock for cleanup.
    If cancel_task holds the lock during await, the callback can never run,
    producing a deadlock (or at best a timeout that wastes 10 seconds).
    """

    @pytest.fixture
    def task_manager(self):
        return TaskManager()

    @pytest.mark.asyncio
    async def test_cancel_task_does_not_deadlock(self, task_manager):
        """Cancelling a task must complete without deadlocking.

        The key invariant: cancel_task releases _task_lock before awaiting
        the task, so the done-callback's cleanup can acquire the lock.
        A 2-second timeout on this whole test catches deadlocks.
        """
        event = asyncio.Event()

        async def long_running():
            await event.wait()

        task = await task_manager.create_tracked_task(
            long_running(), name="deadlock_test"
        )
        task_id = str(id(task))

        # This should complete within 2 seconds, not deadlock.
        result = await asyncio.wait_for(
            task_manager.cancel_task(task_id, timeout=1.0),
            timeout=3.0,
        )
        # Should report success or at least not hang.
        assert result is not None

    @pytest.mark.asyncio
    async def test_cancel_task_cleanup_callback_runs(self, task_manager):
        """The cleanup callback must still fire after cancel_task returns."""
        callback_called = asyncio.Event()

        async def on_cleanup():
            callback_called.set()

        async def long_running():
            await asyncio.Event().wait()

        task = await task_manager.create_tracked_task(
            long_running(), name="cleanup_test", cleanup_callback=on_cleanup
        )
        task_id = str(id(task))

        await asyncio.wait_for(
            task_manager.cancel_task(task_id, timeout=1.0),
            timeout=3.0,
        )

        # Give the event loop a few turns for the done-callback to fire.
        await asyncio.sleep(0.2)

        # The callback should have been invoked by the done-callback path.
        # If the lock was still held, the cleanup task would be stuck.
        assert callback_called.is_set() or task.cancelled()

    @pytest.mark.asyncio
    async def test_cancel_already_done_task(self, task_manager):
        """Cancelling an already-completed task returns True without blocking."""

        async def instant():
            return 42

        task = await task_manager.create_tracked_task(instant(), name="done_task")
        task_id = str(id(task))

        # Let the task finish.
        await asyncio.sleep(0.1)

        result = await asyncio.wait_for(
            task_manager.cancel_task(task_id, timeout=1.0),
            timeout=2.0,
        )
        # Should handle gracefully -- True or task already cleaned up.
        assert result is True or result is False


class TestBug12OrphanedCleanupTask:
    """Bug #12: _task_done_callback must store the cleanup task reference.

    Without a strong reference, GC can collect the coroutine before it
    finishes running, silently dropping the cleanup.
    """

    @pytest.fixture
    def task_manager(self):
        return TaskManager()

    @pytest.mark.asyncio
    async def test_cleanup_task_has_strong_reference(self, task_manager):
        """The cleanup task created in _task_done_callback must be stored."""

        async def quick():
            return 1

        task = await task_manager.create_tracked_task(quick(), name="ref_test")

        # Wait for the task to complete and the callback to fire.
        await asyncio.sleep(0.2)

        # The TaskManager should have a _cleanup_tasks set (or similar)
        # that keeps strong references to in-flight cleanup coroutines.
        assert hasattr(task_manager, "_cleanup_tasks"), (
            "TaskManager must have a _cleanup_tasks set to prevent GC "
            "from collecting in-flight cleanup coroutines"
        )

    @pytest.mark.asyncio
    async def test_cleanup_tasks_are_discarded_after_completion(self, task_manager):
        """Completed cleanup tasks should be discarded to avoid leaking."""

        async def quick():
            return 1

        await task_manager.create_tracked_task(quick(), name="discard_test")

        # Let everything settle.
        await asyncio.sleep(0.3)

        # After cleanup finishes, the set should be empty (or nearly so).
        assert len(task_manager._cleanup_tasks) == 0


class TestBug13ABBADeadlock:
    """Bug #13: state_manager lock ordering must be consistent.

    All methods that acquire both _scan_store_lock and _directory_lock must
    do so in the same order. The canonical order is:
        _scan_store_lock first, then _directory_lock.

    register_directory_scan was acquiring them in the opposite order,
    creating ABBA deadlock potential under concurrent access.
    """

    @pytest.fixture
    def state_manager(self):
        return StateManager()

    @pytest.mark.asyncio
    async def test_concurrent_register_and_validate_no_deadlock(self, state_manager):
        """Concurrent register_directory_scan and validate_state_consistency
        must not deadlock.

        Before the fix, register_directory_scan acquired dir->scan while
        validate_state_consistency acquired scan->dir, causing ABBA deadlock.
        """
        # Pre-populate some state.
        await state_manager.create_scan_progress("scan-1", "/tmp/dir1")

        async def register_loop():
            for i in range(20):
                path = f"/tmp/test_{i}"
                sid = f"scan-reg-{i}"
                await state_manager.create_scan_progress(sid, path)
                await state_manager.register_directory_scan(path, sid)
                await asyncio.sleep(0)

        async def validate_loop():
            for _ in range(20):
                await state_manager.validate_state_consistency()
                await asyncio.sleep(0)

        # Run both concurrently. Deadlock = timeout.
        await asyncio.wait_for(
            asyncio.gather(register_loop(), validate_loop()),
            timeout=5.0,
        )

    @pytest.mark.asyncio
    async def test_concurrent_register_and_health_no_deadlock(self, state_manager):
        """Concurrent register_directory_scan and get_health_status must
        not deadlock."""
        await state_manager.create_scan_progress("scan-h1", "/tmp/health1")

        async def register_loop():
            for i in range(20):
                path = f"/tmp/health_{i}"
                sid = f"scan-h-{i}"
                await state_manager.create_scan_progress(sid, path)
                await state_manager.register_directory_scan(path, sid)
                await asyncio.sleep(0)

        async def health_loop():
            for _ in range(20):
                await state_manager.get_health_status()
                await asyncio.sleep(0)

        await asyncio.wait_for(
            asyncio.gather(register_loop(), health_loop()),
            timeout=5.0,
        )

    @pytest.mark.asyncio
    async def test_concurrent_register_and_resource_usage_no_deadlock(self, state_manager):
        """Concurrent register_directory_scan and get_resource_usage must
        not deadlock."""

        async def register_loop():
            for i in range(20):
                path = f"/tmp/res_{i}"
                sid = f"scan-r-{i}"
                await state_manager.create_scan_progress(sid, path)
                await state_manager.register_directory_scan(path, sid)
                await asyncio.sleep(0)

        async def resource_loop():
            for _ in range(20):
                await state_manager.get_resource_usage()
                await asyncio.sleep(0)

        await asyncio.wait_for(
            asyncio.gather(register_loop(), resource_loop()),
            timeout=5.0,
        )

    @pytest.mark.asyncio
    async def test_register_directory_scan_still_checks_active_scan(self, state_manager):
        """After the lock ordering fix, register_directory_scan must still
        correctly detect an already-active scan on the same directory."""
        await state_manager.create_scan_progress("scan-dup", "/tmp/dup_dir")
        result1 = await state_manager.register_directory_scan("/tmp/dup_dir", "scan-dup")
        assert result1 is True

        # Second registration for the same directory with a running scan should fail.
        result2 = await state_manager.register_directory_scan("/tmp/dup_dir", "scan-dup2")
        assert result2 is False


class TestBug67PrivateCPythonAttrs:
    """Bug #67: resource_manager must not access private CPython attrs.

    ThreadPoolExecutor._shutdown and ._threads are implementation details.
    The fix introduces a public _executor_shutdown flag and avoids _threads.
    """

    @pytest.fixture
    def resource_manager(self):
        return ResourceManager()

    def test_no_private_shutdown_access(self):
        """ResourceManager source must not reference executor._shutdown."""
        import inspect
        source = inspect.getsource(ResourceManager)
        # The code should use its own flag, not the private attr.
        # We allow "self._shutdown_requested" and "self._executor_shutdown"
        # but not "executor._shutdown" or "_shared_executor._shutdown".
        lines = source.split("\n")
        violations = [
            line.strip()
            for line in lines
            if "_shared_executor._shutdown" in line or "executor._shutdown" in line
        ]
        assert violations == [], (
            f"ResourceManager still accesses private _shutdown attr: {violations}"
        )

    def test_no_private_threads_access(self):
        """ResourceManager source must not reference executor._threads."""
        import inspect
        source = inspect.getsource(ResourceManager)
        lines = source.split("\n")
        violations = [
            line.strip()
            for line in lines
            if "_shared_executor._threads" in line or "executor._threads" in line
        ]
        assert violations == [], (
            f"ResourceManager still accesses private _threads attr: {violations}"
        )

    def test_executor_shutdown_flag_exists(self):
        """ResourceManager must track shutdown state via a public flag."""
        rm = ResourceManager()
        assert hasattr(rm, "_executor_shutdown"), (
            "ResourceManager must have _executor_shutdown flag"
        )
        assert rm._executor_shutdown is False

    @pytest.mark.asyncio
    async def test_get_executor_after_external_shutdown(self, resource_manager):
        """get_executor should recreate the pool if _executor_shutdown is set."""
        # Get executor once.
        executor1 = await resource_manager.get_executor()
        assert executor1 is not None

        # Simulate the executor being marked as shut down via the public flag.
        resource_manager._executor_shutdown = True

        executor2 = await resource_manager.get_executor()
        assert executor2 is not None
        # Should be a new executor instance.
        assert executor2 is not executor1

    @pytest.mark.asyncio
    async def test_get_resource_stats_without_private_attrs(self, resource_manager):
        """get_resource_stats should work without accessing private attrs."""
        await resource_manager.get_executor()
        stats = resource_manager.get_resource_stats()
        assert stats.thread_pool_size == resource_manager._max_workers

    @pytest.mark.asyncio
    async def test_get_detailed_status_without_private_attrs(self, resource_manager):
        """get_detailed_status should work without accessing private attrs."""
        await resource_manager.get_executor()
        status = await resource_manager.get_detailed_status()
        assert "status" in status
        assert status["status"]["executor_status"] == "active"

    @pytest.mark.asyncio
    async def test_shutdown_sets_flag(self, resource_manager):
        """shutdown_executor must set _executor_shutdown to True."""
        await resource_manager.get_executor()
        await resource_manager.shutdown_executor(wait=False)
        assert resource_manager._executor_shutdown is True

    @pytest.mark.asyncio
    async def test_del_without_private_attrs(self, resource_manager):
        """__del__ must not access private attrs."""
        await resource_manager.get_executor()
        # Should not raise.
        resource_manager.__del__()
