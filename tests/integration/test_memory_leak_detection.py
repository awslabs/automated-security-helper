# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Load tests for memory leak detection in resource management."""

import asyncio
import gc
import pytest
import time
import os
from typing import List, Dict, Any
from unittest.mock import MagicMock

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

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
from automated_security_helper.core.resource_management.monitoring import (
    ResourceMonitor,
)


class MemoryTracker:
    """Helper class to track memory usage during tests."""

    def __init__(self):
        self.measurements: List[Dict[str, Any]] = []
        if PSUTIL_AVAILABLE:
            self.process = psutil.Process(os.getpid())
        else:
            self.process = None
        self.initial_memory = self.get_memory_mb()

    def get_memory_mb(self) -> float:
        """Get current memory usage in MB."""
        if PSUTIL_AVAILABLE and self.process:
            return self.process.memory_info().rss / (1024 * 1024)
        else:
            # Fallback: return a mock value that increases slightly over time
            # This allows tests to run even without psutil
            return 100.0 + len(self.measurements) * 0.1

    def record_measurement(self, label: str) -> Dict[str, Any]:
        """Record a memory measurement."""
        current_memory = self.get_memory_mb()
        measurement = {
            "label": label,
            "memory_mb": current_memory,
            "delta_mb": current_memory - self.initial_memory,
            "timestamp": time.time(),
        }
        self.measurements.append(measurement)
        return measurement

    def get_memory_growth(self) -> float:
        """Get total memory growth since start."""
        return self.get_memory_mb() - self.initial_memory

    def get_peak_memory(self) -> float:
        """Get peak memory usage recorded."""
        if not self.measurements:
            return self.initial_memory
        return max(m["memory_mb"] for m in self.measurements)


@pytest.mark.slow
class TestMemoryLeakDetection:
    """Load tests for detecting memory leaks in resource management."""

    @pytest.fixture
    def memory_tracker(self):
        """Create a memory tracker for the test."""
        return MemoryTracker()

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
    async def test_extended_operation_periods_with_resource_monitoring(
        self, memory_tracker, resource_manager, event_manager, state_manager
    ):
        """Test extended operation periods with resource monitoring."""

        async def simulate_long_running_operations():
            """Simulate long-running operations that could cause memory leaks."""
            operations_completed = 0

            for cycle in range(10):  # 10 cycles of operations
                memory_tracker.record_measurement(f"cycle_{cycle}_start")

                # Batch of concurrent operations
                async def single_operation(op_id: int):
                    # Acquire resources
                    slot_acquired = await resource_manager.acquire_operation_slot()
                    if not slot_acquired:
                        return {"status": "rejected"}

                    try:
                        # Get executor
                        executor = await resource_manager.get_executor()

                        # Register event subscription
                        handler = MagicMock()
                        await event_manager.register_subscription(
                            subscription_id=f"long_sub_{cycle}_{op_id}",
                            event_type="long_operation",
                            handler=handler,
                            scan_id=f"long_scan_{cycle}",
                        )

                        # Set state
                        await state_manager.set_state(
                            f"long_op_{cycle}_{op_id}", "running"
                        )

                        # Simulate work
                        def cpu_work():
                            return sum(i * i for i in range(100))

                        loop = asyncio.get_event_loop()
                        result = await loop.run_in_executor(executor, cpu_work)

                        # Update state
                        await state_manager.set_state(
                            f"long_op_{cycle}_{op_id}", "completed"
                        )

                        # Cleanup
                        await event_manager.unregister_subscription(
                            f"long_sub_{cycle}_{op_id}"
                        )
                        await resource_manager.release_operation_slot()

                        return {"status": "completed", "result": result}

                    except Exception as e:
                        # Cleanup on error
                        try:
                            await event_manager.unregister_subscription(
                                f"long_sub_{cycle}_{op_id}"
                            )
                            await resource_manager.release_operation_slot()
                        except Exception:
                            pass
                        return {"status": "error", "error": str(e)}

                # Run batch of operations
                batch_size = 5
                tasks = [single_operation(i) for i in range(batch_size)]
                results = await asyncio.gather(*tasks)

                completed = len([r for r in results if r["status"] == "completed"])
                operations_completed += completed

                memory_tracker.record_measurement(f"cycle_{cycle}_end")

                # Force garbage collection
                gc.collect()

                # Small delay between cycles
                await asyncio.sleep(0.1)

            return operations_completed

        # Run the long operations
        total_completed = await simulate_long_running_operations()

        # Final memory measurement
        memory_tracker.record_measurement("final")

        # Verify operations completed
        assert total_completed > 0

        # Check for memory leaks
        memory_growth = memory_tracker.get_memory_growth()
        memory_tracker.get_peak_memory()

        # Memory growth should be reasonable (less than 50MB for this test)
        assert memory_growth < 50.0, f"Excessive memory growth: {memory_growth:.2f}MB"

        # Verify resource cleanup
        resource_stats = resource_manager.get_resource_stats()
        assert resource_stats.active_scans == 0

        event_subscriptions = event_manager.get_all_subscriptions()
        assert len(event_subscriptions) == 0

        print(
            f"Test completed: {total_completed} operations, {memory_growth:.2f}MB growth"
        )

    @pytest.mark.asyncio
    async def test_resource_accumulation_detection_over_time(
        self, memory_tracker, resource_manager, event_manager, task_manager
    ):
        """Test resource accumulation detection over time."""

        resource_counts = []

        async def create_and_abandon_resources(iteration: int):
            """Create resources and intentionally abandon some to test detection."""

            # Create multiple subscriptions
            subscriptions_created = []
            for i in range(5):
                sub_id = f"accum_sub_{iteration}_{i}"
                handler = MagicMock()

                success = await event_manager.register_subscription(
                    subscription_id=sub_id,
                    event_type="accumulation_test",
                    handler=handler,
                    scan_id=f"accum_scan_{iteration}",
                )

                if success:
                    subscriptions_created.append(sub_id)

            # Create tasks
            tasks_created = []
            for i in range(3):

                async def dummy_task():
                    await asyncio.sleep(0.01)
                    return f"task_result_{iteration}_{i}"

                task_id = f"accum_task_{iteration}_{i}"
                task_created = await task_manager.create_task(
                    task_id=task_id, coro=dummy_task(), timeout=5.0
                )

                if task_created:
                    tasks_created.append(task_id)

            # Intentionally clean up only some resources (simulate partial cleanup)
            cleanup_ratio = 0.7  # Clean up 70% of resources

            # Cleanup some subscriptions
            subs_to_cleanup = int(len(subscriptions_created) * cleanup_ratio)
            for sub_id in subscriptions_created[:subs_to_cleanup]:
                await event_manager.unregister_subscription(sub_id)

            # Wait for some tasks to complete
            for task_id in tasks_created[: int(len(tasks_created) * cleanup_ratio)]:
                try:
                    await task_manager.wait_for_task(task_id)
                except Exception:
                    pass  # Ignore task errors

            # Record resource counts
            event_stats = event_manager.get_subscription_statistics()
            active_tasks = await task_manager.get_active_tasks()

            resource_count = {
                "iteration": iteration,
                "subscriptions": event_stats["total_subscriptions"],
                "active_tasks": len(active_tasks),
                "memory_mb": memory_tracker.get_memory_mb(),
            }
            resource_counts.append(resource_count)

            return resource_count

        # Run multiple iterations to accumulate resources
        for iteration in range(15):
            memory_tracker.record_measurement(f"iteration_{iteration}_start")

            resource_count = await create_and_abandon_resources(iteration)

            memory_tracker.record_measurement(f"iteration_{iteration}_end")

            # Force garbage collection
            gc.collect()

            print(
                f"Iteration {iteration}: {resource_count['subscriptions']} subs, "
                f"{resource_count['active_tasks']} tasks, "
                f"{resource_count['memory_mb']:.1f}MB"
            )

        # Analyze resource accumulation
        initial_subs = resource_counts[0]["subscriptions"]
        final_subs = resource_counts[-1]["subscriptions"]

        initial_tasks = resource_counts[0]["active_tasks"]
        final_tasks = resource_counts[-1]["active_tasks"]

        # Check for resource accumulation (should not grow indefinitely)
        subscription_growth = final_subs - initial_subs
        task_growth = final_tasks - initial_tasks

        # Some accumulation is expected due to partial cleanup, but should be bounded
        assert subscription_growth < 20, (
            f"Excessive subscription accumulation: {subscription_growth}"
        )
        assert task_growth < 10, f"Excessive task accumulation: {task_growth}"

        # Memory growth should be reasonable
        memory_growth = memory_tracker.get_memory_growth()
        assert memory_growth < 100.0, f"Excessive memory growth: {memory_growth:.2f}MB"

        print(
            f"Resource accumulation test completed: "
            f"{subscription_growth} sub growth, {task_growth} task growth, "
            f"{memory_growth:.2f}MB memory growth"
        )

    @pytest.mark.asyncio
    async def test_system_stability_under_sustained_load(
        self,
        memory_tracker,
        resource_manager,
        event_manager,
        state_manager,
        task_manager,
    ):
        """Test system stability under sustained load."""

        start_time = time.time()
        operation_count = 0
        error_count = 0

        async def sustained_load_operation(op_id: int):
            """Single operation in sustained load test."""
            nonlocal operation_count, error_count

            try:
                # Acquire resources
                slot_acquired = await resource_manager.acquire_operation_slot()
                if not slot_acquired:
                    return {"status": "no_slot"}

                # Register event subscription
                handler = MagicMock()
                await event_manager.register_subscription(
                    subscription_id=f"sustained_sub_{op_id}",
                    event_type="sustained_load",
                    handler=handler,
                    scan_id=f"sustained_scan_{op_id % 5}",  # Group into 5 scans
                )

                # Set state
                await state_manager.set_state(f"sustained_op_{op_id}", "running")

                # Create and execute task
                async def work_task():
                    # Simulate variable work
                    work_amount = (op_id % 10) + 1
                    total = sum(i for i in range(work_amount * 10))
                    await asyncio.sleep(0.001)  # Small async delay
                    return total

                task_id = f"sustained_task_{op_id}"
                await task_manager.create_task(
                    task_id=task_id, coro=work_task(), timeout=2.0
                )

                result = await task_manager.wait_for_task(task_id)

                # Update state
                await state_manager.set_state(f"sustained_op_{op_id}", "completed")

                # Cleanup
                await event_manager.unregister_subscription(f"sustained_sub_{op_id}")
                await resource_manager.release_operation_slot()

                operation_count += 1
                return {"status": "completed", "result": result}

            except Exception as e:
                error_count += 1
                # Cleanup on error
                try:
                    await event_manager.unregister_subscription(
                        f"sustained_sub_{op_id}"
                    )
                    await resource_manager.release_operation_slot()
                except Exception:
                    pass
                return {"status": "error", "error": str(e)}

        # Run sustained load for a period of time
        load_duration = 10.0  # 10 seconds of sustained load
        operation_id = 0

        while time.time() - start_time < load_duration:
            # Start batch of concurrent operations
            batch_size = 3
            tasks = []

            for _ in range(batch_size):
                tasks.append(sustained_load_operation(operation_id))
                operation_id += 1

            # Wait for batch to complete
            await asyncio.gather(*tasks, return_exceptions=True)

            # Periodic memory measurement
            if operation_id % 20 == 0:
                memory_tracker.record_measurement(f"sustained_op_{operation_id}")

                # Force garbage collection periodically
                if operation_id % 50 == 0:
                    gc.collect()

            # Small delay between batches
            await asyncio.sleep(0.01)

        # Final measurements
        end_time = time.time()
        total_duration = end_time - start_time
        memory_tracker.record_measurement("sustained_final")

        # Verify system stability
        operations_per_second = operation_count / total_duration
        error_rate = error_count / max(operation_count + error_count, 1)
        memory_growth = memory_tracker.get_memory_growth()

        # System should maintain reasonable performance
        assert operations_per_second > 5.0, (
            f"Low throughput: {operations_per_second:.2f} ops/sec"
        )

        # Error rate should be low
        assert error_rate < 0.1, f"High error rate: {error_rate:.2%}"

        # Memory growth should be bounded
        assert memory_growth < 150.0, f"Excessive memory growth: {memory_growth:.2f}MB"

        # Verify final resource cleanup
        resource_stats = resource_manager.get_resource_stats()
        assert resource_stats.active_scans == 0

        event_subscriptions = event_manager.get_all_subscriptions()
        assert len(event_subscriptions) == 0

        active_tasks = await task_manager.get_active_tasks()
        assert len(active_tasks) == 0

        print(
            f"Sustained load test completed: {operation_count} ops in {total_duration:.1f}s "
            f"({operations_per_second:.1f} ops/sec), {error_rate:.2%} error rate, "
            f"{memory_growth:.2f}MB growth"
        )

    @pytest.mark.asyncio
    async def test_cleanup_effectiveness_under_stress_conditions(
        self, memory_tracker, resource_manager, event_manager, state_manager
    ):
        """Test cleanup effectiveness under stress conditions."""

        stress_cycles = 20
        resources_per_cycle = 10

        async def stress_cycle(cycle_id: int):
            """Single stress cycle that creates and cleans up resources."""

            # Create many resources quickly
            subscriptions = []
            states = []

            for i in range(resources_per_cycle):
                # Create subscription
                sub_id = f"stress_sub_{cycle_id}_{i}"
                handler = MagicMock()

                success = await event_manager.register_subscription(
                    subscription_id=sub_id,
                    event_type="stress_test",
                    handler=handler,
                    scan_id=f"stress_scan_{cycle_id}",
                )

                if success:
                    subscriptions.append(sub_id)

                # Create state
                state_key = f"stress_state_{cycle_id}_{i}"
                await state_manager.set_state(state_key, f"value_{i}")
                states.append(state_key)

                # Acquire resource slot
                await resource_manager.acquire_operation_slot()

            # Simulate some work
            await asyncio.sleep(0.01)

            # Rapid cleanup
            cleanup_tasks = []

            # Cleanup subscriptions
            for sub_id in subscriptions:
                cleanup_tasks.append(event_manager.unregister_subscription(sub_id))

            # Release resource slots
            for _ in range(len(subscriptions)):
                cleanup_tasks.append(resource_manager.release_operation_slot())

            # Execute all cleanups concurrently
            await asyncio.gather(*cleanup_tasks, return_exceptions=True)

            # Record metrics
            event_stats = event_manager.get_subscription_statistics()
            resource_stats = resource_manager.get_resource_stats()

            return {
                "cycle_id": cycle_id,
                "subscriptions_remaining": event_stats["total_subscriptions"],
                "active_scans": resource_stats.active_scans,
                "memory_mb": memory_tracker.get_memory_mb(),
            }

        # Run stress cycles
        cycle_results = []

        for cycle in range(stress_cycles):
            memory_tracker.record_measurement(f"stress_cycle_{cycle}_start")

            result = await stress_cycle(cycle)
            cycle_results.append(result)

            memory_tracker.record_measurement(f"stress_cycle_{cycle}_end")

            # Force garbage collection every few cycles
            if cycle % 5 == 0:
                gc.collect()

            print(
                f"Stress cycle {cycle}: {result['subscriptions_remaining']} subs remaining, "
                f"{result['active_scans']} active scans, {result['memory_mb']:.1f}MB"
            )

        # Analyze cleanup effectiveness
        final_result = cycle_results[-1]
        memory_growth = memory_tracker.get_memory_growth()

        # Cleanup should be effective - minimal resources should remain
        assert final_result["subscriptions_remaining"] < 5, (
            f"Poor cleanup: {final_result['subscriptions_remaining']} subscriptions remaining"
        )

        assert final_result["active_scans"] == 0, (
            f"Poor cleanup: {final_result['active_scans']} active scans remaining"
        )

        # Memory growth should be reasonable despite stress
        assert memory_growth < 80.0, (
            f"Excessive memory growth under stress: {memory_growth:.2f}MB"
        )

        # Verify final system state
        event_subscriptions = event_manager.get_all_subscriptions()
        assert len(event_subscriptions) < 5, (
            "Too many subscriptions remaining after stress test"
        )

        resource_stats = resource_manager.get_resource_stats()
        assert resource_stats.active_scans == 0, (
            "Active scans remaining after stress test"
        )

        print(
            f"Stress test completed: {memory_growth:.2f}MB growth, "
            f"{len(event_subscriptions)} subscriptions remaining"
        )

    @pytest.mark.asyncio
    async def test_memory_leak_detection_with_monitoring(
        self, memory_tracker, resource_manager, event_manager
    ):
        """Test memory leak detection using the monitoring system."""

        # Create a resource monitor
        monitor = ResourceMonitor()

        # Start monitoring
        await monitor.start_monitoring()

        try:
            # Run operations that could potentially leak memory
            leak_test_cycles = 25

            for cycle in range(leak_test_cycles):
                memory_tracker.record_measurement(f"leak_test_cycle_{cycle}")

                # Create resources
                subscriptions = []
                for i in range(8):
                    sub_id = f"leak_test_sub_{cycle}_{i}"
                    handler = MagicMock()

                    success = await event_manager.register_subscription(
                        subscription_id=sub_id,
                        event_type="leak_test",
                        handler=handler,
                        scan_id=f"leak_scan_{cycle}",
                    )

                    if success:
                        subscriptions.append(sub_id)

                # Acquire resource slots
                slots_acquired = 0
                for _ in range(3):
                    if await resource_manager.acquire_operation_slot():
                        slots_acquired += 1

                # Simulate work
                await asyncio.sleep(0.005)

                # Cleanup (with occasional "leaks" - incomplete cleanup)
                cleanup_ratio = (
                    0.9 if cycle % 10 != 0 else 0.7
                )  # Occasional incomplete cleanup

                subs_to_cleanup = int(len(subscriptions) * cleanup_ratio)
                for sub_id in subscriptions[:subs_to_cleanup]:
                    await event_manager.unregister_subscription(sub_id)

                slots_to_release = int(slots_acquired * cleanup_ratio)
                for _ in range(slots_to_release):
                    await resource_manager.release_operation_slot()

                # Get monitoring data
                if cycle % 5 == 0:
                    monitor_data = await monitor.get_current_metrics()
                    print(
                        f"Cycle {cycle}: Memory {monitor_data.get('memory_usage_mb', 0):.1f}MB, "
                        f"Active scans {monitor_data.get('active_scans', 0)}"
                    )

            # Final monitoring check
            final_metrics = await monitor.get_current_metrics()
            memory_tracker.record_measurement("leak_test_final")

            # Analyze for memory leaks
            memory_growth = memory_tracker.get_memory_growth()
            peak_memory = memory_tracker.get_peak_memory()

            # Check monitoring data for trends
            monitoring_memory = final_metrics.get("memory_usage_mb", 0)
            active_scans = final_metrics.get("active_scans", 0)

            # Memory growth should be bounded
            assert memory_growth < 120.0, (
                f"Potential memory leak detected: {memory_growth:.2f}MB growth"
            )

            # Active scans should be minimal (some may remain due to simulated incomplete cleanup)
            assert active_scans < 5, f"Too many active scans: {active_scans}"

            # Verify monitoring detected reasonable resource usage
            assert monitoring_memory > 0, "Monitoring failed to detect memory usage"

            print(
                f"Memory leak detection test completed: {memory_growth:.2f}MB growth, "
                f"peak {peak_memory:.1f}MB, {active_scans} active scans"
            )

        finally:
            # Stop monitoring
            await monitor.stop_monitoring()

    def test_memory_measurement_accuracy(self, memory_tracker):
        """Test that memory measurements are accurate and consistent."""

        # Take initial measurement
        initial = memory_tracker.record_measurement("initial")

        # Allocate some memory
        large_data = []
        for i in range(1000):
            large_data.append([j for j in range(100)])  # ~100KB per iteration

        # Measure after allocation
        after_alloc = memory_tracker.record_measurement("after_allocation")

        # Memory should have increased
        growth = after_alloc["memory_mb"] - initial["memory_mb"]
        assert growth > 5.0, f"Memory allocation not detected: {growth:.2f}MB"

        # Clear the data
        large_data.clear()
        del large_data
        gc.collect()

        # Measure after cleanup
        after_cleanup = memory_tracker.record_measurement("after_cleanup")

        # Memory should have decreased (though may not return to initial due to fragmentation)
        cleanup_reduction = after_alloc["memory_mb"] - after_cleanup["memory_mb"]
        assert cleanup_reduction > 0, (
            f"Memory cleanup not detected: {cleanup_reduction:.2f}MB"
        )

        print(
            f"Memory measurement test: {growth:.2f}MB allocated, "
            f"{cleanup_reduction:.2f}MB freed"
        )
