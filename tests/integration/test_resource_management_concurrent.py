# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for resource management concurrent operations."""

import asyncio
import pytest
import time
from unittest.mock import MagicMock

from automated_security_helper.core.resource_management.resource_manager import (
    ResourceManager,
)
from automated_security_helper.core.resource_management.event_manager import (
    EventSubscriptionManager,
)
from automated_security_helper.core.resource_management.state_manager import (
    StateManager,
)
from automated_security_helper.core.resource_management.task_manager import TaskManager
from automated_security_helper.core.resource_management.exceptions import (
    ResourceExhaustionError,
)


class TestConcurrentScanOperations:
    """Integration tests for concurrent scan operations with resource sharing."""

    @pytest.fixture
    def resource_manager(self):
        """Create a ResourceManager for testing."""
        return ResourceManager(max_workers=4, max_concurrent_scans=3)

    @pytest.fixture
    def event_manager(self):
        """Create an EventSubscriptionManager for testing."""
        return EventSubscriptionManager()

    @pytest.fixture
    def state_manager(self):
        """Create a StateManager for testing."""
        return StateManager()

    @pytest.fixture
    def task_manager(self):
        """Create a TaskManager for testing."""
        return TaskManager()

    @pytest.mark.asyncio
    async def test_multiple_simultaneous_scans_with_resource_sharing(
        self, resource_manager, event_manager, state_manager
    ):
        """Test multiple simultaneous scans with resource sharing."""

        async def simulate_scan(scan_id: str):
            """Simulate a scan operation."""
            try:
                # Acquire operation slot
                slot_acquired = await resource_manager.acquire_operation_slot()
                if not slot_acquired:
                    return {
                        "scan_id": scan_id,
                        "status": "rejected",
                        "reason": "no_slots",
                    }

                # Get shared executor
                executor = await resource_manager.get_executor()

                # Register event subscription
                handler = MagicMock()
                await event_manager.register_subscription(
                    subscription_id=f"sub_{scan_id}",
                    event_type="scan_progress",
                    handler=handler,
                    scan_id=scan_id,
                )

                # Set scan state
                await state_manager.set_state(f"scan_{scan_id}_status", "running")

                # Simulate work using shared executor
                def cpu_work():
                    """Simulate CPU-intensive work."""
                    time.sleep(0.1)  # Simulate work
                    return f"scan_{scan_id}_result"

                # Submit work to shared thread pool
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(executor, cpu_work)

                # Update state
                await state_manager.set_state(f"scan_{scan_id}_status", "completed")

                # Cleanup
                await event_manager.unregister_subscription(f"sub_{scan_id}")
                await resource_manager.release_operation_slot()

                return {
                    "scan_id": scan_id,
                    "status": "completed",
                    "result": result,
                    "executor_id": id(executor),
                }

            except Exception as e:
                # Ensure cleanup on error
                try:
                    await event_manager.unregister_subscription(f"sub_{scan_id}")
                    await resource_manager.release_operation_slot()
                except Exception:
                    pass  # Ignore cleanup errors

                return {"scan_id": scan_id, "status": "error", "error": str(e)}

        # Start multiple concurrent scans
        scan_tasks = [simulate_scan(f"scan_{i}") for i in range(5)]
        results = await asyncio.gather(*scan_tasks)

        # Analyze results
        completed_scans = [r for r in results if r["status"] == "completed"]

        # Should have some completed scans (up to max_concurrent_scans)
        assert len(completed_scans) <= resource_manager._max_concurrent_scans
        assert len(completed_scans) > 0

        # All completed scans should use the same executor (resource sharing)
        if len(completed_scans) > 1:
            executor_ids = [r["executor_id"] for r in completed_scans]
            assert len(set(executor_ids)) == 1  # All should use same executor

        # Verify resource cleanup
        stats = resource_manager.get_resource_stats()
        assert stats.active_scans == 0

        # Verify event cleanup
        all_subscriptions = event_manager.get_all_subscriptions()
        assert len(all_subscriptions) == 0

    @pytest.mark.asyncio
    async def test_state_consistency_across_concurrent_operations(self, state_manager):
        """Test state consistency under concurrent operations."""

        async def concurrent_state_operations(operation_id: int):
            """Perform concurrent state operations."""
            results = []

            # Set initial state
            key = "shared_counter"
            await state_manager.set_state(key, 0)

            # Perform multiple increments
            for i in range(10):
                current = await state_manager.get_state(key, 0)
                new_value = current + 1
                await state_manager.set_state(key, new_value)
                results.append(new_value)

                # Small delay to increase chance of race conditions
                await asyncio.sleep(0.001)

            return results

        # Run concurrent operations
        tasks = [concurrent_state_operations(i) for i in range(5)]
        await asyncio.gather(*tasks)

        # Verify final state
        final_value = await state_manager.get_state("shared_counter", 0)

        # Due to race conditions, final value might be less than expected
        # but should be at least the number of operations from one task
        assert final_value >= 10
        assert final_value <= 50  # Maximum possible if no race conditions

    @pytest.mark.asyncio
    async def test_resource_cleanup_after_scan_completion_or_failure(
        self, resource_manager, event_manager, task_manager
    ):
        """Test resource cleanup after scan completion or failure."""

        async def scan_with_failure(scan_id: str, should_fail: bool = False):
            """Simulate scan that may fail."""
            # Acquire resources
            await resource_manager.acquire_operation_slot()
            await resource_manager.get_executor()

            handler = MagicMock()
            await event_manager.register_subscription(
                subscription_id=f"sub_{scan_id}",
                event_type="scan_progress",
                handler=handler,
                scan_id=scan_id,
            )

            # Create a task
            async def scan_work():
                if should_fail:
                    raise RuntimeError(f"Scan {scan_id} failed")
                await asyncio.sleep(0.1)
                return f"result_{scan_id}"

            task_id = await task_manager.create_task(
                task_id=f"task_{scan_id}", coro=scan_work(), timeout=5.0
            )

            try:
                # Wait for task completion
                result = await task_manager.wait_for_task(task_id)

                # Cleanup on success
                await event_manager.unregister_subscription(f"sub_{scan_id}")
                await resource_manager.release_operation_slot()

                return {"scan_id": scan_id, "status": "success", "result": result}

            except Exception as e:
                # Cleanup on failure
                await event_manager.unregister_subscription(f"sub_{scan_id}")
                await resource_manager.release_operation_slot()

                return {"scan_id": scan_id, "status": "failed", "error": str(e)}

        # Run scans with some failures
        scan_tasks = [
            scan_with_failure("scan_1", False),  # Success
            scan_with_failure("scan_2", True),  # Failure
            scan_with_failure("scan_3", False),  # Success
            scan_with_failure("scan_4", True),  # Failure
        ]

        await asyncio.gather(*scan_tasks, return_exceptions=True)

        # Verify cleanup regardless of success/failure
        stats = resource_manager.get_resource_stats()
        assert stats.active_scans == 0

        subscriptions = event_manager.get_all_subscriptions()
        assert len(subscriptions) == 0

        # Verify task cleanup
        active_tasks = await task_manager.get_active_tasks()
        assert len(active_tasks) == 0

    @pytest.mark.asyncio
    async def test_system_behavior_under_high_concurrent_load(
        self, resource_manager, event_manager, state_manager
    ):
        """Test system behavior under high concurrent load."""

        async def high_load_operation(op_id: int):
            """Simulate high-load operation."""
            start_time = time.time()

            try:
                # Try to acquire resources
                slot_acquired = await resource_manager.acquire_operation_slot()
                if not slot_acquired:
                    return {
                        "op_id": op_id,
                        "status": "rejected",
                        "duration": time.time() - start_time,
                    }

                # Register event subscription
                handler = MagicMock()
                await event_manager.register_subscription(
                    subscription_id=f"load_sub_{op_id}",
                    event_type="load_test",
                    handler=handler,
                )

                # Perform state operations
                await state_manager.set_state(f"load_op_{op_id}", "running")

                # Get shared executor and do work
                executor = await resource_manager.get_executor()

                def cpu_intensive_work():
                    # Simulate CPU work
                    total = 0
                    for i in range(1000):
                        total += i * i
                    return total

                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(executor, cpu_intensive_work)

                # Update state
                await state_manager.set_state(f"load_op_{op_id}", "completed")

                # Cleanup
                await event_manager.unregister_subscription(f"load_sub_{op_id}")
                await resource_manager.release_operation_slot()

                return {
                    "op_id": op_id,
                    "status": "completed",
                    "result": result,
                    "duration": time.time() - start_time,
                }

            except Exception as e:
                # Cleanup on error
                try:
                    await event_manager.unregister_subscription(f"load_sub_{op_id}")
                    await resource_manager.release_operation_slot()
                except Exception:
                    pass

                return {
                    "op_id": op_id,
                    "status": "error",
                    "error": str(e),
                    "duration": time.time() - start_time,
                }

        # Create high load with many concurrent operations
        num_operations = 20
        load_tasks = [high_load_operation(i) for i in range(num_operations)]

        start_time = time.time()
        results = await asyncio.gather(*load_tasks)
        total_duration = time.time() - start_time

        # Analyze results
        completed = [r for r in results if r["status"] == "completed"]
        errors = [r for r in results if r["status"] == "error"]

        # Should have some completed operations
        assert len(completed) > 0

        # Should respect concurrency limits
        assert len(completed) <= resource_manager._max_concurrent_scans

        # System should remain stable (no errors due to resource issues)
        assert len(errors) == 0

        # Verify final cleanup
        stats = resource_manager.get_resource_stats()
        assert stats.active_scans == 0

        subscriptions = event_manager.get_all_subscriptions()
        assert len(subscriptions) == 0

        # Performance check - operations should complete in reasonable time
        assert total_duration < 30.0  # Should complete within 30 seconds

    @pytest.mark.asyncio
    async def test_resource_exhaustion_handling(self, resource_manager):
        """Test handling of resource exhaustion scenarios."""

        async def long_running_operation(op_id: int):
            """Simulate long-running operation that holds resources."""
            slot_acquired = await resource_manager.acquire_operation_slot()
            if not slot_acquired:
                return {"op_id": op_id, "status": "rejected"}

            try:
                await resource_manager.get_executor()

                # Hold resources for a while
                await asyncio.sleep(0.5)

                await resource_manager.release_operation_slot()
                return {"op_id": op_id, "status": "completed"}

            except ResourceExhaustionError:
                await resource_manager.release_operation_slot()
                return {"op_id": op_id, "status": "exhausted"}
            except Exception as e:
                await resource_manager.release_operation_slot()
                return {"op_id": op_id, "status": "error", "error": str(e)}

        # Start operations that will exhaust resources
        max_concurrent = resource_manager._max_concurrent_scans

        # Start more operations than the limit
        tasks = [long_running_operation(i) for i in range(max_concurrent + 3)]
        results = await asyncio.gather(*tasks)

        # Analyze results
        completed = [r for r in results if r["status"] == "completed"]
        rejected = [r for r in results if r["status"] == "rejected"]

        # Should have exactly max_concurrent completed operations
        assert len(completed) == max_concurrent

        # Remaining should be rejected
        assert len(rejected) == 3

        # Verify cleanup
        stats = resource_manager.get_resource_stats()
        assert stats.active_scans == 0

    @pytest.mark.asyncio
    async def test_event_subscription_cleanup_under_load(self, event_manager):
        """Test event subscription cleanup under high load."""

        async def subscription_lifecycle(sub_id: int):
            """Test subscription creation and cleanup."""
            handler = MagicMock()
            cleanup_func = MagicMock()

            # Register subscription
            success = await event_manager.register_subscription(
                subscription_id=f"load_sub_{sub_id}",
                event_type="load_test",
                handler=handler,
                cleanup_func=cleanup_func,
                scan_id=f"load_scan_{sub_id % 5}",  # Group into 5 scans
            )

            if not success:
                return {"sub_id": sub_id, "status": "registration_failed"}

            # Simulate some work
            await asyncio.sleep(0.01)

            # Unregister subscription
            cleanup_success = await event_manager.unregister_subscription(
                f"load_sub_{sub_id}"
            )

            return {
                "sub_id": sub_id,
                "status": "completed",
                "cleanup_success": cleanup_success,
            }

        # Create many concurrent subscriptions
        num_subscriptions = 50
        tasks = [subscription_lifecycle(i) for i in range(num_subscriptions)]
        results = await asyncio.gather(*tasks)

        # All should complete successfully
        completed = [r for r in results if r["status"] == "completed"]
        assert len(completed) == num_subscriptions

        # All should have successful cleanup
        successful_cleanups = [r for r in completed if r["cleanup_success"]]
        assert len(successful_cleanups) == num_subscriptions

        # Verify no subscriptions remain
        remaining_subscriptions = event_manager.get_all_subscriptions()
        assert len(remaining_subscriptions) == 0

        # Verify statistics
        stats = event_manager.get_subscription_statistics()
        assert stats["total_subscriptions"] == 0

    @pytest.mark.asyncio
    async def test_mixed_resource_operations_integration(
        self, resource_manager, event_manager, state_manager, task_manager
    ):
        """Test integration of all resource management components under mixed load."""

        async def mixed_operation(op_id: int):
            """Operation that uses all resource management components."""
            operation_type = op_id % 3  # Three types of operations

            try:
                # Common setup
                slot_acquired = await resource_manager.acquire_operation_slot()
                if not slot_acquired:
                    return {"op_id": op_id, "status": "no_slot"}

                handler = MagicMock()
                await event_manager.register_subscription(
                    subscription_id=f"mixed_sub_{op_id}",
                    event_type=f"mixed_type_{operation_type}",
                    handler=handler,
                    scan_id=f"mixed_scan_{op_id % 3}",
                )

                await state_manager.set_state(f"mixed_op_{op_id}", "running")

                if operation_type == 0:
                    # CPU-intensive operation
                    executor = await resource_manager.get_executor()

                    def cpu_work():
                        return sum(i * i for i in range(1000))

                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(executor, cpu_work)

                elif operation_type == 1:
                    # Task-based operation
                    async def async_work():
                        await asyncio.sleep(0.1)
                        return f"async_result_{op_id}"

                    task_id = await task_manager.create_task(
                        task_id=f"mixed_task_{op_id}", coro=async_work(), timeout=5.0
                    )
                    result = await task_manager.wait_for_task(task_id)

                else:
                    # State-heavy operation
                    for i in range(10):
                        await state_manager.set_state(f"mixed_counter_{op_id}_{i}", i)

                    result = await state_manager.get_state(f"mixed_counter_{op_id}_9")

                # Update final state
                await state_manager.set_state(f"mixed_op_{op_id}", "completed")

                # Cleanup
                await event_manager.unregister_subscription(f"mixed_sub_{op_id}")
                await resource_manager.release_operation_slot()

                return {
                    "op_id": op_id,
                    "type": operation_type,
                    "status": "completed",
                    "result": result,
                }

            except Exception as e:
                # Cleanup on error
                try:
                    await event_manager.unregister_subscription(f"mixed_sub_{op_id}")
                    await resource_manager.release_operation_slot()
                except Exception:
                    pass

                return {
                    "op_id": op_id,
                    "type": operation_type,
                    "status": "error",
                    "error": str(e),
                }

        # Run mixed operations concurrently
        num_operations = 15
        tasks = [mixed_operation(i) for i in range(num_operations)]
        results = await asyncio.gather(*tasks)

        # Analyze results by type
        type_0_results = [r for r in results if r.get("type") == 0]
        type_1_results = [r for r in results if r.get("type") == 1]
        type_2_results = [r for r in results if r.get("type") == 2]

        # Should have operations of each type
        assert len(type_0_results) > 0
        assert len(type_1_results) > 0
        assert len(type_2_results) > 0

        # Most should complete successfully
        completed = [r for r in results if r["status"] == "completed"]
        assert len(completed) >= num_operations // 2

        # Verify final cleanup across all components
        resource_stats = resource_manager.get_resource_stats()
        assert resource_stats.active_scans == 0

        event_subscriptions = event_manager.get_all_subscriptions()
        assert len(event_subscriptions) == 0

        active_tasks = await task_manager.get_active_tasks()
        assert len(active_tasks) == 0

        # State manager should still have the final states
        # (this is expected as states persist until explicitly cleared)
