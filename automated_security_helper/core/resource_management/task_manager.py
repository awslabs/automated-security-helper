# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Task management for MCP server resource management.

This module provides the TaskManager class for tracking and managing async tasks
with automatic cleanup, cancellation support, and timeout handling.
"""

import asyncio
from datetime import datetime
from typing import Dict, Any, Optional, List, Callable, Coroutine
from dataclasses import dataclass

from automated_security_helper.core.resource_management.exceptions import (
    TaskManagementError,
)
from automated_security_helper.utils.log import ASH_LOGGER


@dataclass
class TaskInfo:
    """Information about a tracked task."""

    task: asyncio.Task
    name: str
    created_at: datetime
    scan_id: Optional[str] = None
    cleanup_callback: Optional[Callable] = None


class TaskManager:
    """Manages async task lifecycle with automatic cleanup.

    This class provides centralized management of async tasks with automatic
    tracking, cleanup, and cancellation support. It addresses the memory leak
    issues caused by untracked async tasks in the MCP server.
    """

    def __init__(self, max_tasks: int = 20):
        """Initialize the TaskManager.

        Args:
            max_tasks: Maximum number of concurrent tasks allowed
        """
        self._active_tasks: Dict[str, TaskInfo] = {}
        self._task_lock = asyncio.Lock()
        self._logger = ASH_LOGGER
        self._task_counter = 0
        self._max_tasks = max_tasks

    async def create_tracked_task(
        self,
        coro: Coroutine,
        name: Optional[str] = None,
        scan_id: Optional[str] = None,
        cleanup_callback: Optional[Callable] = None,
    ) -> asyncio.Task:
        """Create and track an async task with automatic cleanup.

        Args:
            coro: The coroutine to execute
            name: Optional name for the task
            scan_id: Optional scan ID associated with the task
            cleanup_callback: Optional callback to execute on task completion

        Returns:
            The created and tracked asyncio.Task

        Raises:
            TaskManagementError: If task creation fails
        """
        async with self._task_lock:
            try:
                # Check task limit
                active_count = len(
                    [
                        info
                        for info in self._active_tasks.values()
                        if not info.task.done()
                    ]
                )
                if active_count >= self._max_tasks:
                    raise TaskManagementError(
                        f"Maximum concurrent tasks ({self._max_tasks}) exceeded",
                        context={
                            "active_tasks": active_count,
                            "max_tasks": self._max_tasks,
                        },
                    )

                # Generate task name if not provided
                if name is None:
                    self._task_counter += 1
                    name = f"task_{self._task_counter}"

                # Create the task
                task = asyncio.create_task(coro, name=name)

                # Create task info
                task_info = TaskInfo(
                    task=task,
                    name=name,
                    created_at=datetime.now(),
                    scan_id=scan_id,
                    cleanup_callback=cleanup_callback,
                )

                # Store task info
                task_id = id(task)
                self._active_tasks[str(task_id)] = task_info

                # Add done callback for automatic cleanup
                task.add_done_callback(self._task_done_callback)

                self._logger.debug(
                    f"Created tracked task '{name}' (ID: {task_id}, scan_id: {scan_id})"
                )

                return task

            except Exception as e:
                self._logger.error(f"Failed to create tracked task '{name}': {str(e)}")
                raise TaskManagementError(
                    f"Failed to create tracked task: {str(e)}",
                    context={"task_name": name, "scan_id": scan_id},
                )

    def _task_done_callback(self, task: asyncio.Task) -> None:
        """Callback executed when a tracked task completes.

        This method handles automatic cleanup and logging for completed tasks.
        It runs synchronously and schedules async cleanup operations.

        Args:
            task: The completed task
        """
        task_id = str(id(task))

        # Schedule async cleanup
        asyncio.create_task(self._cleanup_completed_task(task_id, task))

    async def _cleanup_completed_task(self, task_id: str, task: asyncio.Task) -> None:
        """Clean up a completed task.

        Args:
            task_id: The task ID
            task: The completed task
        """
        async with self._task_lock:
            task_info = self._active_tasks.pop(task_id, None)

            if task_info is None:
                self._logger.warning(
                    f"Task {task_id} not found in active tasks during cleanup"
                )
                return

            # Log task completion
            if task.cancelled():
                self._logger.debug(f"Task '{task_info.name}' was cancelled")
            elif task.exception():
                exception = task.exception()
                self._logger.error(
                    f"Task '{task_info.name}' failed with exception: {str(exception)}",
                    exc_info=exception,
                )
            else:
                self._logger.debug(f"Task '{task_info.name}' completed successfully")

            # Execute cleanup callback if provided
            if task_info.cleanup_callback:
                try:
                    if asyncio.iscoroutinefunction(task_info.cleanup_callback):
                        await task_info.cleanup_callback()
                    else:
                        task_info.cleanup_callback()
                except Exception as e:
                    self._logger.error(
                        f"Cleanup callback failed for task '{task_info.name}': {str(e)}"
                    )

    async def cancel_task(self, task_id: str, timeout: float = 10.0) -> bool | None:
        """Cancel a specific task by ID.

        Args:
            task_id: The task ID to cancel
            timeout: Timeout for waiting for cancellation

        Returns:
            True if task was cancelled successfully, False otherwise
        """
        async with self._task_lock:
            task_info = self._active_tasks.get(task_id)
            if task_info is None:
                self._logger.warning(f"Task {task_id} not found for cancellation")
                return False

            task = task_info.task
            if task.done():
                self._logger.debug(f"Task '{task_info.name}' already completed")
                return True

            # Cancel the task
            task.cancel()

            try:
                # Wait for cancellation with timeout
                await asyncio.wait_for(task, timeout=timeout)
            except asyncio.CancelledError:
                self._logger.debug(f"Task '{task_info.name}' cancelled successfully")
                return True
            except asyncio.TimeoutError:
                self._logger.warning(
                    f"Task '{task_info.name}' cancellation timed out after {timeout}s"
                )
                return False
            except Exception as e:
                self._logger.error(
                    f"Unexpected error during task cancellation: {str(e)}"
                )
                return False

    async def cancel_tasks_by_scan_id(
        self, scan_id: str, timeout: float = 30.0
    ) -> List[str]:
        """Cancel all tasks associated with a specific scan ID.

        Args:
            scan_id: The scan ID
            timeout: Total timeout for all cancellations

        Returns:
            List of task names that were cancelled
        """
        cancelled_tasks = []

        async with self._task_lock:
            # Find tasks for this scan
            tasks_to_cancel = [
                (task_id, task_info)
                for task_id, task_info in self._active_tasks.items()
                if task_info.scan_id == scan_id and not task_info.task.done()
            ]

        if not tasks_to_cancel:
            self._logger.debug(f"No active tasks found for scan_id: {scan_id}")
            return cancelled_tasks

        # Cancel tasks with individual timeouts
        individual_timeout = (
            timeout / len(tasks_to_cancel) if tasks_to_cancel else timeout
        )

        for task_id, task_info in tasks_to_cancel:
            try:
                success = await self.cancel_task(task_id, individual_timeout)
                if success:
                    cancelled_tasks.append(task_info.name)
            except Exception as e:
                self._logger.error(
                    f"Error cancelling task '{task_info.name}': {str(e)}"
                )

        self._logger.info(
            f"Cancelled {len(cancelled_tasks)} tasks for scan_id: {scan_id}"
        )
        return cancelled_tasks

    async def cancel_all_tasks(self, timeout: float = 30.0) -> List[str]:
        """Cancel all active tasks with timeout.

        Args:
            timeout: Total timeout for all cancellations

        Returns:
            List of task names that were cancelled
        """
        cancelled_tasks = []

        async with self._task_lock:
            # Get all active tasks
            tasks_to_cancel = [
                (task_id, task_info)
                for task_id, task_info in self._active_tasks.items()
                if not task_info.task.done()
            ]

        if not tasks_to_cancel:
            self._logger.debug("No active tasks to cancel")
            return cancelled_tasks

        self._logger.info(f"Cancelling {len(tasks_to_cancel)} active tasks")

        # Cancel tasks with individual timeouts
        individual_timeout = (
            timeout / len(tasks_to_cancel) if tasks_to_cancel else timeout
        )

        for task_id, task_info in tasks_to_cancel:
            try:
                success = await self.cancel_task(task_id, individual_timeout)
                if success:
                    cancelled_tasks.append(task_info.name)
            except Exception as e:
                self._logger.error(
                    f"Error cancelling task '{task_info.name}': {str(e)}"
                )

        self._logger.info(f"Cancelled {len(cancelled_tasks)} tasks")
        return cancelled_tasks

    def get_task_count(self) -> int:
        """Get current active task count.

        Returns:
            Number of active tasks
        """
        return len(self._active_tasks)

    def get_task_info(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific task.

        Args:
            task_id: The task ID

        Returns:
            Task information dictionary or None if not found
        """
        task_info = self._active_tasks.get(task_id)
        if task_info is None:
            return None

        return {
            "task_id": task_id,
            "name": task_info.name,
            "created_at": task_info.created_at.isoformat(),
            "scan_id": task_info.scan_id,
            "done": task_info.task.done(),
            "cancelled": task_info.task.cancelled(),
        }

    def get_all_tasks_info(self) -> List[Dict[str, Any]]:
        """Get information about all tracked tasks.

        Returns:
            List of task information dictionaries
        """
        return [self.get_task_info(task_id) for task_id in self._active_tasks.keys()]

    def get_tasks_by_scan_id(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get all tasks associated with a specific scan ID.

        Args:
            scan_id: The scan ID

        Returns:
            List of task information dictionaries
        """
        return [
            self.get_task_info(task_id)
            for task_id, task_info in self._active_tasks.items()
            if task_info.scan_id == scan_id
        ]

    async def wait_for_completion(self, timeout: Optional[float] = None) -> bool:
        """Wait for all active tasks to complete.

        Args:
            timeout: Optional timeout in seconds

        Returns:
            True if all tasks completed, False if timeout occurred
        """
        async with self._task_lock:
            active_tasks = [
                task_info.task
                for task_info in self._active_tasks.values()
                if not task_info.task.done()
            ]

        if not active_tasks:
            return True

        try:
            await asyncio.wait_for(
                asyncio.gather(*active_tasks, return_exceptions=True), timeout=timeout
            )
            return True
        except asyncio.TimeoutError:
            self._logger.warning(
                f"Timeout waiting for {len(active_tasks)} tasks to complete"
            )
            return False
        except Exception as e:
            self._logger.error(f"Error waiting for task completion: {str(e)}")
            return False

    async def get_health_status(self) -> Dict[str, Any]:
        """Get health status of the task manager.

        Returns:
            Dictionary with health status information
        """
        async with self._task_lock:
            active_count = len(self._active_tasks)
            completed_count = sum(
                1 for info in self._active_tasks.values() if info.task.done()
            )
            failed_count = sum(
                1
                for info in self._active_tasks.values()
                if info.task.done() and info.task.exception()
            )
            cancelled_count = sum(
                1
                for info in self._active_tasks.values()
                if info.task.done() and info.task.cancelled()
            )

            # Calculate health status
            is_healthy = active_count < 20  # Threshold for too many active tasks
            status = "healthy" if is_healthy else "warning"

            return {
                "status": status,
                "active_tasks": active_count,
                "completed_tasks": completed_count,
                "failed_tasks": failed_count,
                "cancelled_tasks": cancelled_count,
                "is_healthy": is_healthy,
                "details": {
                    "task_counter": self._task_counter,
                    "oldest_task": min(
                        (info.created_at for info in self._active_tasks.values()),
                        default=None,
                    ).isoformat()
                    if self._active_tasks
                    else None,
                },
            }

    async def get_resource_usage(self) -> Dict[str, Any]:
        """Get resource usage statistics.

        Returns:
            Dictionary with resource usage information
        """
        async with self._task_lock:
            tasks_by_scan = {}
            tasks_by_status = {
                "running": 0,
                "completed": 0,
                "failed": 0,
                "cancelled": 0,
            }

            for task_info in self._active_tasks.values():
                # Group by scan ID
                scan_id = task_info.scan_id or "unknown"
                if scan_id not in tasks_by_scan:
                    tasks_by_scan[scan_id] = 0
                tasks_by_scan[scan_id] += 1

                # Group by status
                if task_info.task.done():
                    if task_info.task.cancelled():
                        tasks_by_status["cancelled"] += 1
                    elif task_info.task.exception():
                        tasks_by_status["failed"] += 1
                    else:
                        tasks_by_status["completed"] += 1
                else:
                    tasks_by_status["running"] += 1

            return {
                "total_tasks": len(self._active_tasks),
                "tasks_by_scan": tasks_by_scan,
                "tasks_by_status": tasks_by_status,
                "memory_estimate_mb": len(self._active_tasks) * 0.1,  # Rough estimate
            }
