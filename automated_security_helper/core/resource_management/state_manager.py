# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
State management for MCP server resource management.

This module provides the StateManager class for thread-safe management of
global scan state, preventing race conditions and ensuring data consistency.
"""

import asyncio
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict

from automated_security_helper.core.resource_management.exceptions import (
    StateManagementError,
)
from automated_security_helper.utils.log import ASH_LOGGER


@dataclass
class ScanProgressData:
    """Enhanced scan progress data model."""

    scan_id: str
    status: str
    directory_path: str
    start_time: datetime
    end_time: Optional[datetime] = None
    current_phase: str = "initializing"
    progress: float = 0.0
    error: Optional[str] = None
    results: Optional[Dict[str, Any]] = None
    task_id: Optional[str] = None
    # Additional fields for MCP compatibility
    current_scanner: Optional[str] = None
    scanners_running: List[str] | None = None
    scanners_completed: List[str] | None = None
    scanners_failed: List[str] | None = None
    findings: List[Dict[str, Any]] | None = None
    total_scanners: int = 0
    severity_threshold: str = "MEDIUM"
    config_path: Optional[str] = None
    warnings: List[str] | None = None

    def __post_init__(self):
        """Initialize list fields if None."""
        if self.scanners_running is None:
            self.scanners_running = []
        if self.scanners_completed is None:
            self.scanners_completed = []
        if self.scanners_failed is None:
            self.scanners_failed = []
        if self.findings is None:
            self.findings = []
        if self.warnings is None:
            self.warnings = []

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        # Convert datetime objects to ISO format strings
        if self.start_time:
            data["start_time"] = self.start_time.isoformat()
        if self.end_time:
            data["end_time"] = self.end_time.isoformat()
        return data


class StateManager:
    """Thread-safe management of global scan state.

    This class provides centralized, thread-safe management of scan progress
    and directory registration state, preventing race conditions that can
    cause data corruption in concurrent scan operations.
    """

    def __init__(self):
        """Initialize the StateManager."""
        self._scan_progress_store: Dict[str, ScanProgressData] = {}
        self._active_scans_by_directory: Dict[str, str] = {}
        self._scan_store_lock = asyncio.Lock()
        self._directory_lock = asyncio.Lock()
        self._logger = ASH_LOGGER

    async def update_scan_progress(self, scan_id: str, updates: Dict[str, Any]) -> bool:
        """Thread-safe scan progress update.

        Args:
            scan_id: The scan ID to update
            updates: Dictionary of updates to apply

        Returns:
            True if update was successful, False otherwise

        Raises:
            StateManagementError: If update fails
        """
        async with self._scan_store_lock:
            try:
                if scan_id not in self._scan_progress_store:
                    self._logger.warning(
                        f"Scan ID {scan_id} not found for progress update"
                    )
                    return False

                scan_data = self._scan_progress_store[scan_id]

                # Apply updates to scan data
                for key, value in updates.items():
                    if hasattr(scan_data, key):
                        setattr(scan_data, key, value)
                    else:
                        self._logger.warning(
                            f"Unknown scan progress field '{key}' for scan {scan_id}"
                        )

                # Update timestamp for tracking
                if "status" in updates and updates["status"] in [
                    "completed",
                    "failed",
                    "cancelled",
                ]:
                    scan_data.end_time = datetime.now()

                self._logger.debug(
                    f"Updated scan progress for {scan_id}: {list(updates.keys())}"
                )
                return True

            except Exception as e:
                self._logger.error(
                    f"Failed to update scan progress for {scan_id}: {str(e)}"
                )
                raise StateManagementError(
                    f"Failed to update scan progress: {str(e)}",
                    context={"scan_id": scan_id, "updates": updates},
                )

    async def create_scan_progress(
        self, scan_id: str, directory_path: str, task_id: Optional[str] = None
    ) -> bool:
        """Create new scan progress entry.

        Args:
            scan_id: The scan ID
            directory_path: Path being scanned
            task_id: Optional associated task ID

        Returns:
            True if creation was successful, False if scan already exists

        Raises:
            StateManagementError: If creation fails
        """
        async with self._scan_store_lock:
            try:
                if scan_id in self._scan_progress_store:
                    self._logger.warning(f"Scan ID {scan_id} already exists")
                    return False

                scan_data = ScanProgressData(
                    scan_id=scan_id,
                    status="initializing",
                    directory_path=directory_path,
                    start_time=datetime.now(),
                    task_id=task_id,
                )

                self._scan_progress_store[scan_id] = scan_data

                self._logger.debug(f"Created scan progress for {scan_id}")
                return True

            except Exception as e:
                self._logger.error(
                    f"Failed to create scan progress for {scan_id}: {str(e)}"
                )
                raise StateManagementError(
                    f"Failed to create scan progress: {str(e)}",
                    context={"scan_id": scan_id, "directory_path": directory_path},
                )

    async def get_scan_progress(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Thread-safe scan progress retrieval.

        Args:
            scan_id: The scan ID to retrieve

        Returns:
            Scan progress dictionary or None if not found
        """
        async with self._scan_store_lock:
            scan_data = self._scan_progress_store.get(scan_id)
            if scan_data is None:
                return None

            return scan_data.to_dict()

    async def get_all_scan_progress(self) -> Dict[str, Dict[str, Any]]:
        """Get all scan progress data.

        Returns:
            Dictionary mapping scan IDs to progress data
        """
        async with self._scan_store_lock:
            return {
                scan_id: scan_data.to_dict()
                for scan_id, scan_data in self._scan_progress_store.items()
            }

    async def get_all_scan_ids(self) -> List[str]:
        """Get all scan IDs.

        Returns:
            List of all scan IDs
        """
        async with self._scan_store_lock:
            return list(self._scan_progress_store.keys())

    async def remove_scan_progress(self, scan_id: str) -> bool:
        """Remove scan progress entry.

        Args:
            scan_id: The scan ID to remove

        Returns:
            True if removal was successful, False if scan not found
        """
        async with self._scan_store_lock:
            if scan_id in self._scan_progress_store:
                del self._scan_progress_store[scan_id]
                self._logger.debug(f"Removed scan progress for {scan_id}")
                return True
            return False

    async def register_directory_scan(self, directory_path: str, scan_id: str) -> bool:
        """Thread-safe directory scan registration.

        Args:
            directory_path: Path to register
            scan_id: Scan ID to associate with the path

        Returns:
            True if registration successful, False if directory already has active scan

        Raises:
            StateManagementError: If registration fails
        """
        async with self._directory_lock:
            try:
                # Check if directory already has an active scan
                existing_scan_id = self._active_scans_by_directory.get(directory_path)
                if existing_scan_id:
                    # Check if the existing scan is still active
                    async with self._scan_store_lock:
                        existing_scan = self._scan_progress_store.get(existing_scan_id)
                        if existing_scan and existing_scan.status not in [
                            "completed",
                            "failed",
                            "cancelled",
                        ]:
                            self._logger.warning(
                                f"Directory {directory_path} already has active scan: {existing_scan_id}"
                            )
                            return False
                        else:
                            # Clean up stale registration
                            self._logger.debug(
                                f"Cleaning up stale directory registration for {directory_path}"
                            )

                # Register the directory
                self._active_scans_by_directory[directory_path] = scan_id
                self._logger.debug(
                    f"Registered directory scan: {directory_path} -> {scan_id}"
                )
                return True

            except Exception as e:
                self._logger.error(
                    f"Failed to register directory scan for {directory_path}: {str(e)}"
                )
                raise StateManagementError(
                    f"Failed to register directory scan: {str(e)}",
                    context={"directory_path": directory_path, "scan_id": scan_id},
                )

    async def unregister_directory_scan(
        self, directory_path: str, scan_id: str
    ) -> bool:
        """Thread-safe directory scan cleanup.

        Args:
            directory_path: Path to unregister
            scan_id: Expected scan ID (for verification)

        Returns:
            True if unregistration successful, False if not found or mismatch
        """
        async with self._directory_lock:
            existing_scan_id = self._active_scans_by_directory.get(directory_path)

            if existing_scan_id is None:
                self._logger.debug(
                    f"No directory registration found for {directory_path}"
                )
                return False

            if existing_scan_id != scan_id:
                self._logger.warning(
                    f"Directory scan ID mismatch for {directory_path}: "
                    f"expected {scan_id}, found {existing_scan_id}"
                )
                return False

            del self._active_scans_by_directory[directory_path]
            self._logger.debug(f"Unregistered directory scan: {directory_path}")
            return True

    async def get_directory_scan(self, directory_path: str) -> Optional[str]:
        """Get the scan ID for a directory.

        Args:
            directory_path: Path to check

        Returns:
            Scan ID if found, None otherwise
        """
        async with self._directory_lock:
            return self._active_scans_by_directory.get(directory_path)

    async def get_all_directory_scans(self) -> Dict[str, str]:
        """Get all directory scan registrations.

        Returns:
            Dictionary mapping directory paths to scan IDs
        """
        async with self._directory_lock:
            return self._active_scans_by_directory.copy()

    async def cleanup_completed_scans(self, max_age_hours: int = 24) -> int:
        """Clean up old completed scan data.

        Args:
            max_age_hours: Maximum age in hours for completed scans

        Returns:
            Number of scans cleaned up
        """
        cleanup_count = 0
        cutoff_time = datetime.now().timestamp() - (max_age_hours * 3600)

        async with self._scan_store_lock:
            scans_to_remove = []

            for scan_id, scan_data in self._scan_progress_store.items():
                # Only clean up completed scans
                if scan_data.status in ["completed", "failed", "cancelled"]:
                    # Check age based on end_time or start_time
                    check_time = scan_data.end_time or scan_data.start_time
                    if check_time.timestamp() < cutoff_time:
                        scans_to_remove.append(scan_id)

            # Remove old scans
            for scan_id in scans_to_remove:
                del self._scan_progress_store[scan_id]
                cleanup_count += 1

        # Clean up corresponding directory registrations
        async with self._directory_lock:
            directories_to_remove = []
            for directory_path, scan_id in self._active_scans_by_directory.items():
                if scan_id in scans_to_remove:
                    directories_to_remove.append(directory_path)

            for directory_path in directories_to_remove:
                del self._active_scans_by_directory[directory_path]

        if cleanup_count > 0:
            self._logger.info(f"Cleaned up {cleanup_count} old scan records")

        return cleanup_count

    def get_state_statistics(self) -> Dict[str, Any]:
        """Get current state statistics.

        Returns:
            Dictionary with state statistics
        """
        return {
            "total_scans": len(self._scan_progress_store),
            "active_directory_registrations": len(self._active_scans_by_directory),
            "scan_status_counts": self._get_scan_status_counts(),
        }

    def _get_scan_status_counts(self) -> Dict[str, int]:
        """Get counts of scans by status.

        Returns:
            Dictionary mapping status to count
        """
        status_counts = {}
        for scan_data in self._scan_progress_store.values():
            status = scan_data.status
            status_counts[status] = status_counts.get(status, 0) + 1
        return status_counts

    def get_active_scan_count(self) -> int:
        """Get the count of active scans.

        Returns:
            Number of active scans
        """
        active_count = 0
        for scan_data in self._scan_progress_store.values():
            if scan_data.status not in ["completed", "failed", "cancelled"]:
                active_count += 1
        return active_count

    async def validate_state_consistency(self) -> List[str]:
        """Validate state consistency and return any issues found.

        Returns:
            List of consistency issues found
        """
        issues = []

        async with self._scan_store_lock:
            async with self._directory_lock:
                # Check for directory registrations without corresponding scan data
                for directory_path, scan_id in self._active_scans_by_directory.items():
                    if scan_id not in self._scan_progress_store:
                        issues.append(
                            f"Directory registration {directory_path} -> {scan_id} "
                            f"has no corresponding scan data"
                        )

                # Check for active scans with stale directory registrations
                for scan_id, scan_data in self._scan_progress_store.items():
                    if scan_data.status not in ["completed", "failed", "cancelled"]:
                        # This is an active scan, check if directory is registered
                        directory_scan_id = self._active_scans_by_directory.get(
                            scan_data.directory_path
                        )
                        if directory_scan_id != scan_id:
                            issues.append(
                                f"Active scan {scan_id} for {scan_data.directory_path} "
                                f"has inconsistent directory registration"
                            )

        return issues

    async def get_health_status(self) -> Dict[str, Any]:
        """Get health status of the state manager.

        Returns:
            Dictionary with health status information
        """
        # Check for consistency issues first (this acquires its own locks)
        consistency_issues = await self.validate_state_consistency()

        async with self._scan_store_lock:
            async with self._directory_lock:
                total_scans = len(self._scan_progress_store)
                active_directories = len(self._active_scans_by_directory)

                # Calculate health status
                has_issues = len(consistency_issues) > 0
                too_many_scans = total_scans > 100  # Threshold for too many scans

                if has_issues:
                    status = "critical"
                elif too_many_scans:
                    status = "warning"
                else:
                    status = "healthy"

                is_healthy = status == "healthy"

                # Get scan status distribution
                status_counts = self._get_scan_status_counts()

                return {
                    "status": status,
                    "total_scans": total_scans,
                    "active_directories": active_directories,
                    "consistency_issues": len(consistency_issues),
                    "consistency_details": consistency_issues,
                    "scan_status_counts": status_counts,
                    "is_healthy": is_healthy,
                    "details": {
                        "oldest_scan": (
                            min(
                                (
                                    scan_data.start_time
                                    for scan_data in self._scan_progress_store.values()
                                ),
                                default=None,
                            ).isoformat()
                            if self._scan_progress_store
                            else None
                        ),
                        "newest_scan": (
                            max(
                                (
                                    scan_data.start_time
                                    for scan_data in self._scan_progress_store.values()
                                ),
                                default=None,
                            ).isoformat()
                            if self._scan_progress_store
                            else None
                        ),
                    },
                }

    async def get_resource_usage(self) -> Dict[str, Any]:
        """Get resource usage statistics.

        Returns:
            Dictionary with resource usage information
        """
        async with self._scan_store_lock:
            async with self._directory_lock:
                # Calculate memory usage estimate
                scan_data_size = (
                    len(self._scan_progress_store) * 2
                )  # ~2KB per scan estimate
                directory_data_size = (
                    len(self._active_scans_by_directory) * 0.5
                )  # ~0.5KB per directory
                total_memory_kb = scan_data_size + directory_data_size

                # Get scan duration statistics
                now = datetime.now()
                active_scan_durations = []
                completed_scan_durations = []

                for scan_data in self._scan_progress_store.values():
                    if (
                        scan_data.status in ["completed", "failed", "cancelled"]
                        and scan_data.end_time
                    ):
                        duration = (
                            scan_data.end_time - scan_data.start_time
                        ).total_seconds()
                        completed_scan_durations.append(duration)
                    elif scan_data.status not in ["completed", "failed", "cancelled"]:
                        duration = (now - scan_data.start_time).total_seconds()
                        active_scan_durations.append(duration)

                return {
                    "memory_usage_kb": total_memory_kb,
                    "memory_usage_mb": total_memory_kb / 1024,
                    "scan_data_count": len(self._scan_progress_store),
                    "directory_registrations": len(self._active_scans_by_directory),
                    "active_scan_durations": {
                        "count": len(active_scan_durations),
                        "average_seconds": (
                            sum(active_scan_durations) / len(active_scan_durations)
                            if active_scan_durations
                            else 0
                        ),
                        "max_seconds": (
                            max(active_scan_durations) if active_scan_durations else 0
                        ),
                    },
                    "completed_scan_durations": {
                        "count": len(completed_scan_durations),
                        "average_seconds": (
                            sum(completed_scan_durations)
                            / len(completed_scan_durations)
                            if completed_scan_durations
                            else 0
                        ),
                        "max_seconds": (
                            max(completed_scan_durations)
                            if completed_scan_durations
                            else 0
                        ),
                    },
                }
