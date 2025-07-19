# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for ResourceManager class."""

import asyncio
import pytest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch, MagicMock

from automated_security_helper.core.resource_management.resource_manager import (
    ResourceManager,
    ResourceStats,
)
from automated_security_helper.core.resource_management.exceptions import (
    ResourceExhaustionError,
    MCPResourceError,
)


class TestResourceManager:
    """Test cases for ResourceManager class."""

    @pytest.fixture
    def resource_manager(self):
        """Create a ResourceManager instance for testing."""
        return ResourceManager(max_workers=2, max_concurrent_scans=2)

    @pytest.mark.asyncio
    async def test_get_executor_creates_new(self, resource_manager):
        """Test that get_executor creates a new ThreadPoolExecutor."""
        executor = await resource_manager.get_executor()

        assert isinstance(executor, ThreadPoolExecutor)
        assert executor._max_workers == 2
        assert "ash_mcp_worker" in executor._thread_name_prefix

    @pytest.mark.asyncio
    async def test_get_executor_reuses_existing(self, resource_manager):
        """Test that get_executor reuses existing ThreadPoolExecutor."""
        executor1 = await resource_manager.get_executor()
        executor2 = await resource_manager.get_executor()

        assert executor1 is executor2

    @pytest.mark.asyncio
    async def test_get_executor_recreates_after_shutdown(self, resource_manager):
        """Test that get_executor recreates executor after shutdown."""
        executor1 = await resource_manager.get_executor()

        # Shutdown the executor
        await resource_manager.shutdown_executor(wait=False)

        # Reset shutdown flag to allow new executor creation
        resource_manager._shutdown_requested = False

        # Get executor again should create new one
        executor2 = await resource_manager.get_executor()

        assert executor1 is not executor2
        assert isinstance(executor2, ThreadPoolExecutor)

    @pytest.mark.asyncio
    async def test_acquire_operation_slot_success(self, resource_manager):
        """Test successful operation slot acquisition."""
        success1 = await resource_manager.acquire_operation_slot()
        assert success1

        success2 = await resource_manager.acquire_operation_slot()
        assert success2

    @pytest.mark.asyncio
    async def test_acquire_operation_slot_limit_reached(self, resource_manager):
        """Test operation slot acquisition when limit is reached."""
        # Acquire maximum slots
        success1 = await resource_manager.acquire_operation_slot()
        success2 = await resource_manager.acquire_operation_slot()
        assert success1 and success2

        # Try to acquire one more (should fail)
        success3 = await resource_manager.acquire_operation_slot()
        assert not success3

    @pytest.mark.asyncio
    async def test_release_operation_slot(self, resource_manager):
        """Test operation slot release."""
        # Acquire slots
        await resource_manager.acquire_operation_slot()
        await resource_manager.acquire_operation_slot()

        # Try to acquire another (should fail)
        success = await resource_manager.acquire_operation_slot()
        assert not success

        # Release one slot
        await resource_manager.release_operation_slot()

        # Now should be able to acquire
        success = await resource_manager.acquire_operation_slot()
        assert success

    @pytest.mark.asyncio
    async def test_get_executor_with_resource_exhaustion(self, resource_manager):
        """Test get_executor when resource limits are exceeded."""
        # Fill up operation slots
        await resource_manager.acquire_operation_slot()
        await resource_manager.acquire_operation_slot()

        # Try to get executor when at limit
        with pytest.raises(ResourceExhaustionError) as exc_info:
            await resource_manager.get_executor()

        assert "Maximum concurrent operations" in str(exc_info.value)
        assert exc_info.value.context["active_operations"] == 2

    @pytest.mark.asyncio
    async def test_get_executor_after_shutdown_requested(self, resource_manager):
        """Test get_executor after shutdown is requested."""
        # Request shutdown
        resource_manager._shutdown_requested = True

        with pytest.raises(MCPResourceError, match="ResourceManager is shutting down"):
            await resource_manager.get_executor()

    @pytest.mark.asyncio
    async def test_shutdown_executor_success(self, resource_manager):
        """Test successful executor shutdown."""
        # Create executor
        executor = await resource_manager.get_executor()
        assert not executor._shutdown

        # Shutdown
        await resource_manager.shutdown_executor(wait=False)

        assert executor._shutdown
        assert resource_manager._shutdown_requested

    @pytest.mark.asyncio
    async def test_shutdown_executor_with_wait(self, resource_manager):
        """Test executor shutdown with wait."""
        # Create executor
        await resource_manager.get_executor()

        # Shutdown with wait
        await resource_manager.shutdown_executor(wait=True, timeout=1.0)

        assert resource_manager._shutdown_requested

    @pytest.mark.asyncio
    async def test_shutdown_executor_no_executor(self, resource_manager):
        """Test shutdown when no executor exists."""
        # Should not raise exception
        await resource_manager.shutdown_executor()
        assert resource_manager._shutdown_requested

    def test_get_resource_stats_basic(self, resource_manager):
        """Test basic resource statistics."""
        stats = resource_manager.get_resource_stats()

        assert isinstance(stats, ResourceStats)
        assert stats.active_scans == 0
        assert stats.thread_pool_size == 2
        assert stats.thread_pool_active == 0
        assert stats.uptime_seconds > 0

    @pytest.mark.asyncio
    async def test_get_resource_stats_with_active_executor(self, resource_manager):
        """Test resource statistics with active executor."""
        # Create executor
        await resource_manager.get_executor()

        stats = resource_manager.get_resource_stats()
        assert stats.thread_pool_size == 2

    def test_resource_stats_is_healthy(self):
        """Test ResourceStats is_healthy method."""
        # Healthy stats
        healthy_stats = ResourceStats(
            active_tasks=1,
            active_scans=1,
            thread_pool_size=4,
            thread_pool_active=2,  # 50% utilization
            memory_usage_mb=500,  # 500MB
            uptime_seconds=3600,
        )
        assert healthy_stats.is_healthy()

        # Unhealthy stats - high thread utilization
        unhealthy_threads = ResourceStats(
            active_tasks=1,
            active_scans=1,
            thread_pool_size=4,
            thread_pool_active=4,  # 100% utilization
            memory_usage_mb=500,
            uptime_seconds=3600,
        )
        assert not unhealthy_threads.is_healthy()

        # Unhealthy stats - high memory usage
        unhealthy_memory = ResourceStats(
            active_tasks=1,
            active_scans=1,
            thread_pool_size=4,
            thread_pool_active=2,
            memory_usage_mb=1500,  # 1.5GB
            uptime_seconds=3600,
        )
        assert not unhealthy_memory.is_healthy()

    def test_is_healthy(self, resource_manager):
        """Test ResourceManager is_healthy method."""
        # Should be healthy initially
        assert resource_manager.is_healthy()

    @pytest.mark.asyncio
    async def test_get_detailed_status(self, resource_manager):
        """Test getting detailed status information."""
        status = await resource_manager.get_detailed_status()

        assert "resource_stats" in status
        assert "limits" in status
        assert "status" in status

        assert status["limits"]["max_workers"] == 2
        assert status["limits"]["max_concurrent_scans"] == 2
        assert status["status"]["executor_status"] == "not_created"
        assert not status["status"]["shutdown_requested"]

    @pytest.mark.asyncio
    async def test_get_detailed_status_with_executor(self, resource_manager):
        """Test detailed status with active executor."""
        # Create executor
        await resource_manager.get_executor()

        status = await resource_manager.get_detailed_status()
        assert status["status"]["executor_status"] == "active"

    @pytest.mark.asyncio
    async def test_enforce_resource_limits_normal(self, resource_manager):
        """Test resource limit enforcement under normal conditions."""
        actions = await resource_manager.enforce_resource_limits()
        assert len(actions) == 0  # No actions needed

    @pytest.mark.asyncio
    async def test_enforce_resource_limits_high_operations(self, resource_manager):
        """Test resource limit enforcement with high operations."""
        # Fill operation slots
        await resource_manager.acquire_operation_slot()
        await resource_manager.acquire_operation_slot()

        actions = await resource_manager.enforce_resource_limits()
        assert len(actions) == 1
        assert "Maximum concurrent operations reached" in actions[0]

    @pytest.mark.asyncio
    async def test_enforce_resource_limits_high_thread_utilization(
        self, resource_manager
    ):
        """Test resource limit enforcement with high thread utilization."""
        # Create executor and mock high utilization
        executor = await resource_manager.get_executor()

        # Mock threads to simulate high utilization
        mock_threads = [MagicMock() for _ in range(4)]  # More than max_workers
        for thread in mock_threads:
            thread.is_alive.return_value = True

        with patch.object(executor, "_threads", mock_threads):
            actions = await resource_manager.enforce_resource_limits()
            assert len(actions) == 1
            assert "High thread pool utilization" in actions[0]

    @pytest.mark.asyncio
    async def test_concurrent_executor_access(self, resource_manager):
        """Test concurrent access to executor."""

        async def get_executor_task():
            return await resource_manager.get_executor()

        # Run multiple concurrent get_executor calls
        tasks = [get_executor_task() for _ in range(5)]
        executors = await asyncio.gather(*tasks)

        # All should return the same executor instance
        first_executor = executors[0]
        for executor in executors[1:]:
            assert executor is first_executor

    def test_destructor_cleanup(self, resource_manager):
        """Test that destructor properly cleans up resources."""
        # Create executor
        asyncio.run(resource_manager.get_executor())

        # Manually call destructor
        resource_manager.__del__()

        # Should not raise exception

    @pytest.mark.asyncio
    async def test_shared_thread_pool_lifecycle_comprehensive(self, resource_manager):
        """Test comprehensive shared thread pool lifecycle management."""
        # Initially no executor
        assert resource_manager._shared_executor is None

        # Create executor
        executor1 = await resource_manager.get_executor()
        assert resource_manager._shared_executor is executor1
        assert not executor1._shutdown

        # Reuse same executor
        executor2 = await resource_manager.get_executor()
        assert executor1 is executor2

        # Shutdown executor
        await resource_manager.shutdown_executor(wait=False)
        assert executor1._shutdown
        assert resource_manager._shutdown_requested

        # Reset shutdown flag for testing recreation
        resource_manager._shutdown_requested = False

        # Create new executor after shutdown
        executor3 = await resource_manager.get_executor()
        assert executor3 is not executor1
        assert not executor3._shutdown

    @pytest.mark.asyncio
    async def test_thread_pool_reuse_across_operations(self, resource_manager):
        """Test thread pool reuse across multiple operations."""
        # Simulate multiple operations using the same thread pool
        executors = []

        for i in range(5):
            # Acquire operation slot
            success = await resource_manager.acquire_operation_slot()
            if success:
                executor = await resource_manager.get_executor()
                executors.append(executor)
                await resource_manager.release_operation_slot()

        # All executors should be the same instance
        first_executor = executors[0]
        for executor in executors[1:]:
            assert executor is first_executor

    @pytest.mark.asyncio
    async def test_shutdown_and_cleanup_procedures(self, resource_manager):
        """Test comprehensive shutdown and cleanup procedures."""
        # Create executor and acquire operation slots
        executor = await resource_manager.get_executor()
        await resource_manager.acquire_operation_slot()

        # Test shutdown without wait
        await resource_manager.shutdown_executor(wait=False)
        assert executor._shutdown
        assert resource_manager._shutdown_requested

        # Test that new operations are rejected after shutdown
        with pytest.raises(MCPResourceError, match="ResourceManager is shutting down"):
            await resource_manager.get_executor()

        # Reset for testing shutdown with wait
        resource_manager._shutdown_requested = False
        resource_manager._shared_executor = None

        # Create new executor
        executor2 = await resource_manager.get_executor()

        # Test shutdown with wait and timeout
        await resource_manager.shutdown_executor(wait=True, timeout=1.0)
        assert executor2._shutdown

    @pytest.mark.asyncio
    async def test_error_handling_during_executor_creation(self, resource_manager):
        """Test error handling during executor creation."""
        # Mock ThreadPoolExecutor to raise exception
        with patch(
            "automated_security_helper.core.resource_management.resource_manager.ThreadPoolExecutor"
        ) as mock_executor:
            mock_executor.side_effect = RuntimeError("Failed to create thread pool")

            with pytest.raises(MCPResourceError, match="Failed to create thread pool"):
                await resource_manager.get_executor()

    @pytest.mark.asyncio
    async def test_executor_recreation_after_unexpected_shutdown(
        self, resource_manager
    ):
        """Test executor recreation after unexpected shutdown."""
        # Create executor
        executor1 = await resource_manager.get_executor()

        # Simulate unexpected shutdown
        executor1.shutdown(wait=False)

        # Getting executor again should create new one
        executor2 = await resource_manager.get_executor()
        assert executor2 is not executor1
        assert not executor2._shutdown

    def test_resource_stats_edge_cases(self):
        """Test ResourceStats edge cases."""
        # Test with zero thread pool size
        stats = ResourceStats(
            active_tasks=0,
            active_scans=0,
            thread_pool_size=0,
            thread_pool_active=0,
            memory_usage_mb=100,
            uptime_seconds=3600,
        )
        assert stats.is_healthy()  # Should handle division by zero

        # Test boundary conditions
        boundary_stats = ResourceStats(
            active_tasks=0,
            active_scans=0,
            thread_pool_size=10,
            thread_pool_active=8,  # Exactly 80% utilization
            memory_usage_mb=1000,  # Exactly at limit
            uptime_seconds=3600,
        )
        assert boundary_stats.is_healthy()

    @pytest.mark.asyncio
    async def test_health_check_with_exceptions(self, resource_manager):
        """Test health check behavior when exceptions occur."""
        # Mock get_resource_stats to raise exception
        with patch.object(
            resource_manager,
            "get_resource_stats",
            side_effect=RuntimeError("Stats error"),
        ):
            is_healthy = resource_manager.is_healthy()
            assert not is_healthy  # Should return False on exception

    @pytest.mark.asyncio
    async def test_operation_slot_management_edge_cases(self, resource_manager):
        """Test operation slot management edge cases."""
        # Test releasing more slots than acquired
        await resource_manager.release_operation_slot()  # Should not crash

        # Verify count doesn't go negative
        stats = resource_manager.get_resource_stats()
        assert stats.active_scans >= 0

        # Test acquiring maximum slots
        for _ in range(resource_manager._max_concurrent_scans):
            success = await resource_manager.acquire_operation_slot()
            assert success

        # Next acquisition should fail
        success = await resource_manager.acquire_operation_slot()
        assert not success

    @pytest.mark.asyncio
    async def test_shutdown_timeout_handling(self, resource_manager):
        """Test shutdown timeout handling."""
        # Create executor
        await resource_manager.get_executor()

        # Test shutdown with very short timeout
        await resource_manager.shutdown_executor(wait=True, timeout=0.001)
        assert resource_manager._shutdown_requested

    @pytest.mark.asyncio
    async def test_resource_manager_state_consistency(self, resource_manager):
        """Test resource manager state consistency under various operations."""
        # Test initial state
        assert resource_manager._active_operations == 0
        assert not resource_manager._shutdown_requested
        assert resource_manager._shared_executor is None

        # Acquire slots and verify state
        await resource_manager.acquire_operation_slot()
        assert resource_manager._active_operations == 1

        # Create executor and verify state
        executor = await resource_manager.get_executor()
        assert resource_manager._shared_executor is executor

        # Shutdown and verify state
        await resource_manager.shutdown_executor(wait=False)
        assert resource_manager._shutdown_requested
        assert executor._shutdown

    @pytest.mark.asyncio
    async def test_thread_pool_active_count_calculation(self, resource_manager):
        """Test thread pool active count calculation."""
        # Create executor
        executor = await resource_manager.get_executor()

        # Mock threads with different states
        mock_threads = []
        for i in range(3):
            thread = MagicMock()
            thread.is_alive.return_value = i < 2  # First 2 are alive
            mock_threads.append(thread)

        with patch.object(executor, "_threads", mock_threads):
            stats = resource_manager.get_resource_stats()
            assert stats.thread_pool_active == 2

        # Test with exception during thread counting
        with patch.object(executor, "_threads", side_effect=Exception("Thread error")):
            stats = resource_manager.get_resource_stats()
            assert stats.thread_pool_active == 0

    @pytest.mark.asyncio
    async def test_enforce_resource_limits_exception_handling(self, resource_manager):
        """Test exception handling in resource limit enforcement."""
        # Mock get_resource_stats to raise exception
        with patch.object(
            resource_manager,
            "get_resource_stats",
            side_effect=RuntimeError("Stats error"),
        ):
            actions = await resource_manager.enforce_resource_limits()
            assert len(actions) == 1
            assert "Error checking resource limits" in actions[0]

    def test_resource_manager_initialization_parameters(self):
        """Test ResourceManager initialization with various parameters."""
        # Test with custom parameters
        rm = ResourceManager(max_workers=8, max_concurrent_scans=5)
        assert rm._max_workers == 8
        assert rm._max_concurrent_scans == 5

        # Test default parameters
        rm_default = ResourceManager()
        assert rm_default._max_workers == 4
        assert rm_default._max_concurrent_scans == 3

    @pytest.mark.asyncio
    async def test_resource_cleanup_on_multiple_shutdowns(self, resource_manager):
        """Test resource cleanup behavior with multiple shutdown calls."""
        # Create executor
        await resource_manager.get_executor()

        # Call shutdown multiple times
        await resource_manager.shutdown_executor(wait=False)
        await resource_manager.shutdown_executor(wait=False)  # Should not crash

        # Verify state
        assert resource_manager._shutdown_requested
        assert resource_manager._shared_executor is None
