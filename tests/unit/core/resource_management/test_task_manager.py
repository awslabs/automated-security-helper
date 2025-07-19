# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for TaskManager class."""

import asyncio
import pytest

from automated_security_helper.core.resource_management.task_manager import (
    TaskManager,
)
from automated_security_helper.core.resource_management.exceptions import (
    TaskManagementError,
)


class TestTaskManager:
    """Test cases for TaskManager class."""

    @pytest.fixture
    def task_manager(self):
        """Create a TaskManager instance for testing."""
        return TaskManager()

    @pytest.mark.asyncio
    async def test_create_tracked_task_success(self, task_manager):
        """Test successful task creation and tracking."""

        async def dummy_coro():
            await asyncio.sleep(0.1)
            return "success"

        task = await task_manager.create_tracked_task(
            dummy_coro(), name="test_task", scan_id="scan_123"
        )

        assert task is not None
        assert task.get_name() == "test_task"
        assert task_manager.get_task_count() == 1

        # Wait for task completion
        result = await task
        assert result == "success"

        # Give time for cleanup callback
        await asyncio.sleep(0.1)
        assert task_manager.get_task_count() == 0

    @pytest.mark.asyncio
    async def test_create_tracked_task_auto_name(self, task_manager):
        """Test task creation with automatic name generation."""

        async def dummy_coro():
            return "success"

        task = await task_manager.create_tracked_task(dummy_coro())

        assert task is not None
        assert task.get_name() == "task_1"
        assert task_manager.get_task_count() == 1

        await task
        await asyncio.sleep(0.1)  # Allow cleanup

    @pytest.mark.asyncio
    async def test_create_tracked_task_with_cleanup_callback(self, task_manager):
        """Test task creation with cleanup callback."""
        cleanup_called = False

        def cleanup_callback():
            nonlocal cleanup_called
            cleanup_called = True

        async def dummy_coro():
            return "success"

        task = await task_manager.create_tracked_task(
            dummy_coro(), cleanup_callback=cleanup_callback
        )

        await task
        await asyncio.sleep(0.1)  # Allow cleanup callback to execute

        assert cleanup_called

    @pytest.mark.asyncio
    async def test_create_tracked_task_with_async_cleanup_callback(self, task_manager):
        """Test task creation with async cleanup callback."""
        cleanup_called = False

        async def async_cleanup_callback():
            nonlocal cleanup_called
            cleanup_called = True

        async def dummy_coro():
            return "success"

        task = await task_manager.create_tracked_task(
            dummy_coro(), cleanup_callback=async_cleanup_callback
        )

        await task
        await asyncio.sleep(0.1)  # Allow cleanup callback to execute

        assert cleanup_called

    @pytest.mark.asyncio
    async def test_task_exception_handling(self, task_manager):
        """Test handling of task exceptions."""

        async def failing_coro():
            raise ValueError("Test error")

        task = await task_manager.create_tracked_task(
            failing_coro(), name="failing_task"
        )

        with pytest.raises(ValueError, match="Test error"):
            await task

        # Give time for cleanup
        await asyncio.sleep(0.1)
        assert task_manager.get_task_count() == 0

    @pytest.mark.asyncio
    async def test_cancel_task_success(self, task_manager):
        """Test successful task cancellation."""

        async def long_running_coro():
            await asyncio.sleep(10)  # Long running task
            return "completed"

        task = await task_manager.create_tracked_task(
            long_running_coro(), name="long_task"
        )

        task_id = str(id(task))

        # Cancel the task
        success = await task_manager.cancel_task(task_id, timeout=1.0)
        assert success

        # Verify task was cancelled
        with pytest.raises(asyncio.CancelledError):
            await task

    @pytest.mark.asyncio
    async def test_cancel_nonexistent_task(self, task_manager):
        """Test cancelling a non-existent task."""
        success = await task_manager.cancel_task("nonexistent_id")
        assert not success

    @pytest.mark.asyncio
    async def test_cancel_tasks_by_scan_id(self, task_manager):
        """Test cancelling tasks by scan ID."""

        async def long_running_coro():
            await asyncio.sleep(10)
            return "completed"

        # Create tasks with same scan ID
        task1 = await task_manager.create_tracked_task(
            long_running_coro(), name="task1", scan_id="scan_123"
        )
        task2 = await task_manager.create_tracked_task(
            long_running_coro(), name="task2", scan_id="scan_123"
        )
        task3 = await task_manager.create_tracked_task(
            long_running_coro(), name="task3", scan_id="scan_456"
        )

        assert task_manager.get_task_count() == 3

        # Cancel tasks for scan_123
        cancelled_tasks = await task_manager.cancel_tasks_by_scan_id("scan_123")

        assert len(cancelled_tasks) == 2
        assert "task1" in cancelled_tasks
        assert "task2" in cancelled_tasks

        # Verify tasks were cancelled
        with pytest.raises(asyncio.CancelledError):
            await task1
        with pytest.raises(asyncio.CancelledError):
            await task2

        # task3 should still be running
        assert not task3.cancelled()

        # Clean up remaining task
        await task_manager.cancel_task(str(id(task3)))

    @pytest.mark.asyncio
    async def test_cancel_all_tasks(self, task_manager):
        """Test cancelling all active tasks."""

        async def long_running_coro():
            await asyncio.sleep(10)
            return "completed"

        # Create multiple tasks
        tasks = []
        for i in range(3):
            task = await task_manager.create_tracked_task(
                long_running_coro(), name=f"task_{i}"
            )
            tasks.append(task)

        assert task_manager.get_task_count() == 3

        # Cancel all tasks
        cancelled_tasks = await task_manager.cancel_all_tasks()

        assert len(cancelled_tasks) == 3

        # Verify all tasks were cancelled
        for task in tasks:
            with pytest.raises(asyncio.CancelledError):
                await task

    @pytest.mark.asyncio
    async def test_get_task_info(self, task_manager):
        """Test getting task information."""

        async def dummy_coro():
            await asyncio.sleep(0.1)
            return "success"

        task = await task_manager.create_tracked_task(
            dummy_coro(), name="info_task", scan_id="scan_789"
        )

        task_id = str(id(task))
        task_info = task_manager.get_task_info(task_id)

        assert task_info is not None
        assert task_info["name"] == "info_task"
        assert task_info["scan_id"] == "scan_789"
        assert task_info["task_id"] == task_id
        assert not task_info["done"]
        assert not task_info["cancelled"]

        await task
        await asyncio.sleep(0.1)  # Allow cleanup

    @pytest.mark.asyncio
    async def test_get_tasks_by_scan_id(self, task_manager):
        """Test getting tasks by scan ID."""

        async def dummy_coro():
            await asyncio.sleep(0.1)
            return "success"

        # Create tasks with different scan IDs
        task1 = await task_manager.create_tracked_task(
            dummy_coro(), name="task1", scan_id="scan_123"
        )
        task2 = await task_manager.create_tracked_task(
            dummy_coro(), name="task2", scan_id="scan_123"
        )
        task3 = await task_manager.create_tracked_task(
            dummy_coro(), name="task3", scan_id="scan_456"
        )

        # Get tasks for scan_123
        scan_123_tasks = task_manager.get_tasks_by_scan_id("scan_123")
        assert len(scan_123_tasks) == 2

        task_names = [task["name"] for task in scan_123_tasks]
        assert "task1" in task_names
        assert "task2" in task_names

        # Get tasks for scan_456
        scan_456_tasks = task_manager.get_tasks_by_scan_id("scan_456")
        assert len(scan_456_tasks) == 1
        assert scan_456_tasks[0]["name"] == "task3"

        # Wait for tasks to complete
        await asyncio.gather(task1, task2, task3)
        await asyncio.sleep(0.1)  # Allow cleanup

    @pytest.mark.asyncio
    async def test_wait_for_completion_success(self, task_manager):
        """Test waiting for all tasks to complete successfully."""

        async def short_coro():
            await asyncio.sleep(0.1)
            return "success"

        # Create multiple short tasks
        tasks = []
        for i in range(3):
            task = await task_manager.create_tracked_task(short_coro())
            tasks.append(task)

        # Wait for completion
        success = await task_manager.wait_for_completion(timeout=5.0)
        assert success

        # Verify all tasks completed
        for task in tasks:
            assert task.done()

    @pytest.mark.asyncio
    async def test_wait_for_completion_timeout(self, task_manager):
        """Test timeout when waiting for task completion."""

        async def long_coro():
            await asyncio.sleep(10)
            return "success"

        task = await task_manager.create_tracked_task(long_coro())

        # Wait with short timeout
        success = await task_manager.wait_for_completion(timeout=0.1)
        assert not success

        # Clean up
        await task_manager.cancel_task(str(id(task)))

    @pytest.mark.asyncio
    async def test_cleanup_callback_exception_handling(self, task_manager):
        """Test handling of exceptions in cleanup callbacks."""

        def failing_cleanup():
            raise RuntimeError("Cleanup failed")

        async def dummy_coro():
            return "success"

        task = await task_manager.create_tracked_task(
            dummy_coro(), cleanup_callback=failing_cleanup
        )

        # Task should complete despite cleanup failure
        result = await task
        assert result == "success"

        await asyncio.sleep(0.1)  # Allow cleanup attempt
        # Should not raise exception, just log it

    @pytest.mark.asyncio
    async def test_get_all_tasks_info(self, task_manager):
        """Test getting information about all tasks."""

        async def dummy_coro():
            await asyncio.sleep(0.1)
            return "success"

        # Create multiple tasks
        tasks = []
        for i in range(3):
            task = await task_manager.create_tracked_task(
                dummy_coro(), name=f"task_{i}", scan_id=f"scan_{i}"
            )
            tasks.append(task)

        all_tasks_info = task_manager.get_all_tasks_info()
        assert len(all_tasks_info) == 3

        # Verify task information
        task_names = [info["name"] for info in all_tasks_info]
        assert "task_0" in task_names
        assert "task_1" in task_names
        assert "task_2" in task_names

        # Wait for completion
        await asyncio.gather(*tasks)
        await asyncio.sleep(0.1)  # Allow cleanup

    @pytest.mark.asyncio
    async def test_concurrent_task_creation(self, task_manager):
        """Test concurrent task creation and tracking."""

        async def dummy_coro():
            await asyncio.sleep(0.1)
            return "success"

        # Create tasks concurrently
        tasks = await asyncio.gather(
            *[
                task_manager.create_tracked_task(
                    dummy_coro(),
                    name=f"concurrent_task_{i}",
                    scan_id=f"scan_{i % 2}",  # Alternate between two scan IDs
                )
                for i in range(10)
            ]
        )

        assert len(tasks) == 10
        assert task_manager.get_task_count() == 10

        # Wait for all tasks to complete
        await asyncio.gather(*tasks)
        await asyncio.sleep(0.2)  # Allow cleanup

        assert task_manager.get_task_count() == 0

    @pytest.mark.asyncio
    async def test_concurrent_task_cancellation(self, task_manager):
        """Test concurrent task cancellation operations."""

        async def long_running_coro():
            await asyncio.sleep(5)
            return "completed"

        # Create multiple long-running tasks
        tasks = []
        for i in range(5):
            task = await task_manager.create_tracked_task(
                long_running_coro(), name=f"long_task_{i}", scan_id="concurrent_scan"
            )
            tasks.append(task)

        assert task_manager.get_task_count() == 5

        # Cancel tasks concurrently
        cancel_operations = [
            task_manager.cancel_task(str(id(task)), timeout=1.0) for task in tasks
        ]

        results = await asyncio.gather(*cancel_operations)
        assert all(results)  # All cancellations should succeed

        # Verify all tasks were cancelled
        for task in tasks:
            assert task.cancelled()

    @pytest.mark.asyncio
    async def test_task_timeout_handling(self, task_manager):
        """Test timeout handling during task cancellation."""

        async def unresponsive_coro():
            # Simulate a task that doesn't respond to cancellation quickly
            try:
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                # Simulate slow cleanup
                await asyncio.sleep(2)
                raise

        task = await task_manager.create_tracked_task(
            unresponsive_coro(), name="unresponsive_task"
        )

        task_id = str(id(task))

        # Try to cancel with short timeout
        success = await task_manager.cancel_task(task_id, timeout=0.5)

        # The task should be cancelled successfully since asyncio handles cancellation quickly
        # The timeout is for waiting for the task to complete after cancellation
        assert success

        # Verify task was cancelled
        assert task.cancelled()

    @pytest.mark.asyncio
    async def test_error_scenarios_during_task_creation(self, task_manager):
        """Test error handling during task creation."""
        # Test with invalid coroutine
        with pytest.raises(TaskManagementError):
            await task_manager.create_tracked_task(
                "not_a_coroutine",  # Invalid coroutine
                name="invalid_task",
            )

    @pytest.mark.asyncio
    async def test_resource_cleanup_on_manager_shutdown(self, task_manager):
        """Test proper resource cleanup when manager shuts down."""

        async def long_running_coro():
            await asyncio.sleep(10)
            return "completed"

        # Create multiple tasks
        tasks = []
        for i in range(3):
            task = await task_manager.create_tracked_task(
                long_running_coro(), name=f"shutdown_task_{i}"
            )
            tasks.append(task)

        assert task_manager.get_task_count() == 3

        # Simulate manager shutdown by cancelling all tasks
        cancelled_tasks = await task_manager.cancel_all_tasks(timeout=2.0)

        assert len(cancelled_tasks) == 3

        # Verify all tasks were cancelled
        for task in tasks:
            assert task.cancelled()

        # Give time for cleanup
        await asyncio.sleep(0.1)
        assert task_manager.get_task_count() == 0

    @pytest.mark.asyncio
    async def test_task_counter_increment(self, task_manager):
        """Test that task counter increments correctly."""

        async def dummy_coro():
            return "success"

        # Create tasks without names to test auto-naming
        task1 = await task_manager.create_tracked_task(dummy_coro())
        task2 = await task_manager.create_tracked_task(dummy_coro())
        task3 = await task_manager.create_tracked_task(dummy_coro())

        assert task1.get_name() == "task_1"
        assert task2.get_name() == "task_2"
        assert task3.get_name() == "task_3"

        await asyncio.gather(task1, task2, task3)
        await asyncio.sleep(0.1)  # Allow cleanup

    @pytest.mark.asyncio
    async def test_get_health_status(self, task_manager):
        """Test health status reporting."""
        # Test with no tasks
        health = await task_manager.get_health_status()
        assert health["status"] == "healthy"
        assert health["active_tasks"] == 0
        assert health["is_healthy"] is True

        async def dummy_coro():
            await asyncio.sleep(0.1)
            return "success"

        # Create some tasks
        tasks = []
        for i in range(5):
            task = await task_manager.create_tracked_task(dummy_coro())
            tasks.append(task)

        health = await task_manager.get_health_status()
        assert health["active_tasks"] == 5
        assert health["status"] == "healthy"
        assert health["is_healthy"] is True

        await asyncio.gather(*tasks)
        await asyncio.sleep(0.1)  # Allow cleanup

    @pytest.mark.asyncio
    async def test_get_resource_usage(self, task_manager):
        """Test resource usage statistics."""

        async def dummy_coro():
            await asyncio.sleep(0.1)
            return "success"

        # Create tasks with different scan IDs
        tasks = []
        for i in range(6):
            scan_id = f"scan_{i % 3}"  # 3 different scan IDs
            task = await task_manager.create_tracked_task(dummy_coro(), scan_id=scan_id)
            tasks.append(task)

        usage = await task_manager.get_resource_usage()
        assert usage["total_tasks"] == 6
        assert len(usage["tasks_by_scan"]) == 3
        assert usage["tasks_by_scan"]["scan_0"] == 2
        assert usage["tasks_by_scan"]["scan_1"] == 2
        assert usage["tasks_by_scan"]["scan_2"] == 2
        assert (
            abs(usage["memory_estimate_mb"] - 0.6) < 0.001
        )  # 6 * 0.1 with floating point tolerance

        await asyncio.gather(*tasks)
        await asyncio.sleep(0.1)  # Allow cleanup

    @pytest.mark.asyncio
    async def test_task_done_callback_error_handling(self, task_manager):
        """Test error handling in task done callback."""

        async def dummy_coro():
            return "success"

        # Create task that will complete normally
        task = await task_manager.create_tracked_task(dummy_coro())

        # Wait for completion
        await task
        await asyncio.sleep(0.1)  # Allow cleanup callback

        # Task should be cleaned up despite any potential callback issues
        assert task_manager.get_task_count() == 0

    @pytest.mark.asyncio
    async def test_multiple_scan_id_operations(self, task_manager):
        """Test operations with multiple scan IDs."""

        async def long_running_coro():
            await asyncio.sleep(5)
            return "completed"

        # Create tasks for multiple scans
        scan_a_tasks = []
        scan_b_tasks = []

        for i in range(3):
            task_a = await task_manager.create_tracked_task(
                long_running_coro(), name=f"scan_a_task_{i}", scan_id="scan_a"
            )
            task_b = await task_manager.create_tracked_task(
                long_running_coro(), name=f"scan_b_task_{i}", scan_id="scan_b"
            )
            scan_a_tasks.append(task_a)
            scan_b_tasks.append(task_b)

        assert task_manager.get_task_count() == 6

        # Cancel only scan_a tasks
        cancelled_a = await task_manager.cancel_tasks_by_scan_id("scan_a")
        assert len(cancelled_a) == 3

        # Verify scan_a tasks are cancelled but scan_b tasks are still running
        for task in scan_a_tasks:
            assert task.cancelled()

        for task in scan_b_tasks:
            assert not task.cancelled()

        # Clean up remaining tasks
        await task_manager.cancel_all_tasks()

    @pytest.mark.asyncio
    async def test_task_info_after_completion(self, task_manager):
        """Test task info retrieval after task completion."""

        async def dummy_coro():
            await asyncio.sleep(0.1)
            return "success"

        task = await task_manager.create_tracked_task(
            dummy_coro(), name="completed_task"
        )

        task_id = str(id(task))

        # Get info while running
        info_running = task_manager.get_task_info(task_id)
        assert info_running is not None
        assert not info_running["done"]

        # Wait for completion
        await task

        # Get info after completion (before cleanup)
        info_completed = task_manager.get_task_info(task_id)
        if info_completed:  # May be None if cleanup already happened
            assert info_completed["done"]

        await asyncio.sleep(0.1)  # Allow cleanup

    @pytest.mark.asyncio
    async def test_empty_scan_id_cancellation(self, task_manager):
        """Test cancellation with non-existent scan ID."""
        cancelled_tasks = await task_manager.cancel_tasks_by_scan_id("nonexistent_scan")
        assert len(cancelled_tasks) == 0

    @pytest.mark.asyncio
    async def test_task_creation_with_none_values(self, task_manager):
        """Test task creation with None values for optional parameters."""

        async def dummy_coro():
            return "success"

        task = await task_manager.create_tracked_task(
            dummy_coro(),
            name=None,  # Should auto-generate
            scan_id=None,  # Should be None
            cleanup_callback=None,  # Should be None
        )

        assert task.get_name() == "task_1"

        task_id = str(id(task))
        info = task_manager.get_task_info(task_id)
        assert info["scan_id"] is None

        await task
        await asyncio.sleep(0.1)  # Allow cleanup
