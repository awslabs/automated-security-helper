# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Resource management for MCP server shared resources.

This module provides the ResourceManager class for managing shared resources
like thread pools, with lifecycle tracking and monitoring capabilities.
"""

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from automated_security_helper.core.resource_management.exceptions import (
    ResourceExhaustionError,
    MCPResourceError,
)
from automated_security_helper.utils.log import ASH_LOGGER


@dataclass
class ResourceStats:
    """Resource utilization statistics."""

    active_tasks: int
    active_scans: int
    thread_pool_size: int
    thread_pool_active: int
    memory_usage_mb: float
    uptime_seconds: float

    def is_healthy(self) -> bool:
        """Check if resource usage is within healthy limits."""
        # Define health thresholds
        max_thread_utilization = 0.8  # 80% of thread pool
        max_memory_mb = 1000  # 1GB memory limit

        thread_utilization = (
            self.thread_pool_active / self.thread_pool_size
            if self.thread_pool_size > 0
            else 0
        )

        return (
            thread_utilization <= max_thread_utilization
            and self.memory_usage_mb <= max_memory_mb
        )


class ResourceManager:
    """Manages shared resources with lifecycle tracking.

    This class provides centralized management of shared resources like
    thread pools, preventing resource exhaustion and enabling efficient
    resource reuse across scan operations.
    """

    def __init__(self, max_workers: int = 4, max_concurrent_scans: int = 3):
        """Initialize the ResourceManager.

        Args:
            max_workers: Maximum number of worker threads
            max_concurrent_scans: Maximum number of concurrent scans
        """
        self._max_workers = max_workers
        self._max_concurrent_scans = max_concurrent_scans
        self._shared_executor: Optional[ThreadPoolExecutor] = None
        self._resource_lock = asyncio.Lock()
        self._active_operations = 0
        self._logger = ASH_LOGGER
        self._start_time = time.time()
        self._shutdown_requested = False

    async def get_executor(self) -> ThreadPoolExecutor:
        """Get or create shared thread pool executor.

        Returns:
            The shared ThreadPoolExecutor instance

        Raises:
            ResourceExhaustionError: If resource limits are exceeded
            MCPResourceError: If executor creation fails
        """
        async with self._resource_lock:
            if self._shutdown_requested:
                raise MCPResourceError("ResourceManager is shutting down")

            # Check concurrent operation limits
            if self._active_operations >= self._max_concurrent_scans:
                raise ResourceExhaustionError(
                    f"Maximum concurrent operations ({self._max_concurrent_scans}) exceeded",
                    context={
                        "active_operations": self._active_operations,
                        "max_concurrent": self._max_concurrent_scans,
                    },
                )

            # Create executor if it doesn't exist
            if self._shared_executor is None:
                try:
                    self._shared_executor = ThreadPoolExecutor(
                        max_workers=self._max_workers,
                        thread_name_prefix="ash_mcp_worker",
                    )
                    self._logger.info(
                        f"Created shared thread pool with {self._max_workers} workers"
                    )
                except Exception as e:
                    self._logger.error(
                        f"Failed to create thread pool executor: {str(e)}"
                    )
                    raise MCPResourceError(
                        f"Failed to create thread pool: {str(e)}",
                        context={"max_workers": self._max_workers},
                    )

            # Check if executor is still healthy
            if self._shared_executor._shutdown:
                self._logger.warning("Thread pool executor was shutdown, recreating")
                try:
                    self._shared_executor = ThreadPoolExecutor(
                        max_workers=self._max_workers,
                        thread_name_prefix="ash_mcp_worker",
                    )
                except Exception as e:
                    raise MCPResourceError(f"Failed to recreate thread pool: {str(e)}")

            return self._shared_executor

    async def acquire_operation_slot(self) -> bool:
        """Acquire a slot for a new operation.

        Returns:
            True if slot was acquired, False if limit reached
        """
        async with self._resource_lock:
            if self._active_operations >= self._max_concurrent_scans:
                return False

            self._active_operations += 1
            self._logger.debug(
                f"Acquired operation slot ({self._active_operations}/{self._max_concurrent_scans})"
            )
            return True

    async def release_operation_slot(self) -> None:
        """Release an operation slot."""
        async with self._resource_lock:
            if self._active_operations > 0:
                self._active_operations -= 1
                self._logger.debug(
                    f"Released operation slot ({self._active_operations}/{self._max_concurrent_scans})"
                )

    async def shutdown_executor(self, wait: bool = True, timeout: float = 30.0) -> None:
        """Shutdown shared thread pool.

        Args:
            wait: Whether to wait for running tasks to complete
            timeout: Maximum time to wait for shutdown
        """
        async with self._resource_lock:
            self._shutdown_requested = True

            if self._shared_executor is None:
                self._logger.debug("No thread pool executor to shutdown")
                return

            self._logger.info("Shutting down shared thread pool executor")

            try:
                # Shutdown the executor
                self._shared_executor.shutdown(wait=False)

                if wait:
                    # Wait for completion in a separate thread to avoid blocking
                    def wait_for_shutdown():
                        try:
                            # Use a loop to implement timeout
                            start_time = time.time()
                            while time.time() - start_time < timeout:
                                if self._shared_executor._threads:
                                    time.sleep(0.1)
                                else:
                                    break
                            else:
                                self._logger.warning(
                                    f"Thread pool shutdown timed out after {timeout}s"
                                )
                        except Exception as e:
                            self._logger.error(
                                f"Error during thread pool shutdown: {str(e)}"
                            )

                    # Run shutdown wait in thread pool (if available) or new thread
                    try:
                        loop = asyncio.get_event_loop()
                        await loop.run_in_executor(None, wait_for_shutdown)
                    except Exception as e:
                        self._logger.error(
                            f"Error waiting for thread pool shutdown: {str(e)}"
                        )

                self._shared_executor = None
                self._logger.info("Thread pool executor shutdown completed")

            except Exception as e:
                self._logger.error(
                    f"Error shutting down thread pool executor: {str(e)}"
                )
                raise MCPResourceError(f"Failed to shutdown thread pool: {str(e)}")

    def get_resource_stats(self) -> ResourceStats:
        """Get current resource utilization statistics.

        Returns:
            ResourceStats object with current statistics
        """
        # Get memory usage (basic implementation)
        memory_mb = 0.0

        # Get thread pool stats
        thread_pool_size = self._max_workers
        thread_pool_active = 0

        if self._shared_executor and not self._shared_executor._shutdown:
            try:
                # Count active threads
                thread_pool_active = len(
                    [t for t in self._shared_executor._threads if t.is_alive()]
                )
            except Exception:
                thread_pool_active = 0

        # Calculate uptime and ensure it's at least a small positive value for cross-platform compatibility
        uptime = time.time() - self._start_time
        uptime = max(uptime, 0.001)

        return ResourceStats(
            active_tasks=0,  # This would be provided by TaskManager
            active_scans=self._active_operations,
            thread_pool_size=thread_pool_size,
            thread_pool_active=thread_pool_active,
            memory_usage_mb=memory_mb,
            uptime_seconds=uptime,
        )

    def is_healthy(self) -> bool:
        """Check if resource manager is in a healthy state.

        Returns:
            True if healthy, False otherwise
        """
        try:
            stats = self.get_resource_stats()
            return stats.is_healthy()
        except Exception as e:
            self._logger.error(f"Error checking resource health: {str(e)}")
            return False

    async def get_detailed_status(self) -> Dict[str, Any]:
        """Get detailed status information.

        Returns:
            Dictionary with detailed status information
        """
        stats = self.get_resource_stats()

        executor_status = "not_created"
        if self._shared_executor:
            if self._shared_executor._shutdown:
                executor_status = "shutdown"
            else:
                executor_status = "active"

        return {
            "resource_stats": {
                "active_scans": stats.active_scans,
                "thread_pool_size": stats.thread_pool_size,
                "thread_pool_active": stats.thread_pool_active,
                "memory_usage_mb": stats.memory_usage_mb,
                "uptime_seconds": stats.uptime_seconds,
            },
            "limits": {
                "max_workers": self._max_workers,
                "max_concurrent_scans": self._max_concurrent_scans,
            },
            "status": {
                "executor_status": executor_status,
                "shutdown_requested": self._shutdown_requested,
                "is_healthy": stats.is_healthy(),
            },
        }

    async def enforce_resource_limits(self) -> List[str]:
        """Enforce resource limits and return any actions taken.

        Returns:
            List of enforcement actions taken
        """
        actions = []

        try:
            stats = self.get_resource_stats()

            # Check memory usage
            if stats.memory_usage_mb > 1000:  # 1GB limit
                actions.append(
                    f"High memory usage detected: {stats.memory_usage_mb:.1f}MB"
                )
                # Could implement memory cleanup here

            # Check thread pool utilization
            if stats.thread_pool_size > 0:
                utilization = stats.thread_pool_active / stats.thread_pool_size
                if utilization > 0.9:  # 90% utilization
                    actions.append(f"High thread pool utilization: {utilization:.1%}")

            # Check active operations
            if self._active_operations >= self._max_concurrent_scans:
                actions.append(
                    f"Maximum concurrent operations reached: {self._active_operations}"
                )

        except Exception as e:
            self._logger.error(f"Error enforcing resource limits: {str(e)}")
            actions.append(f"Error checking resource limits: {str(e)}")

        return actions

    def __del__(self):
        """Cleanup on object destruction."""
        if self._shared_executor and not self._shared_executor._shutdown:
            try:
                self._shared_executor.shutdown(wait=False)
            except Exception:
                pass  # Ignore errors during cleanup
