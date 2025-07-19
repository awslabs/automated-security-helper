#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Scan registry and management components for ASH MCP server.

This module provides classes and functions for managing scan metadata and tracking
active scans. It implements a thread-safe registry to track active scans and
provides functions for listing, cancelling, and cleaning up scans.
"""

import os
import signal
import uuid
from datetime import datetime
from enum import Enum
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional, Any

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_tracking import (
    check_scan_completion,
    create_scan_progress_from_files,
)
from automated_security_helper.utils.log import ASH_LOGGER


class ScanStatus(Enum):
    """Status of a scan."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanRegistryEntry:
    """Entry in the scan registry."""

    def __init__(
        self,
        scan_id: str,
        directory_path: str,
        output_directory: str,
        severity_threshold: str = "MEDIUM",
        config_path: Optional[str] = None,
    ):
        """
        Initialize a scan registry entry.

        Args:
            scan_id: Unique identifier for the scan
            directory_path: Path to the directory being scanned
            output_directory: Path to the output directory for scan results
            severity_threshold: Minimum severity threshold for findings
            config_path: Optional path to ASH configuration file
        """
        self.scan_id = scan_id
        self.directory_path = directory_path
        self.output_directory = output_directory
        self.start_time = datetime.now()
        self.end_time: Optional[datetime] = None
        self.status = ScanStatus.PENDING
        self.severity_threshold = severity_threshold
        self.config_path = config_path
        self.process_id: Optional[int] = None
        self.error_message: Optional[str] = None
        self.warnings: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the entry to a dictionary for serialization.

        Returns:
            Dictionary representation of the entry
        """
        return {
            "scan_id": self.scan_id,
            "directory_path": self.directory_path,
            "output_directory": self.output_directory,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "status": self.status.value,
            "severity_threshold": self.severity_threshold,
            "config_path": self.config_path,
            "process_id": self.process_id,
            "error_message": self.error_message,
            "warnings": self.warnings,
        }

    def mark_running(self, process_id: Optional[int] = None) -> None:
        """
        Mark the scan as running.

        Args:
            process_id: Optional process ID of the scan process
        """
        self.status = ScanStatus.RUNNING
        self.process_id = process_id

    def mark_completed(self) -> None:
        """Mark the scan as completed."""
        self.status = ScanStatus.COMPLETED
        self.end_time = datetime.now()

    def mark_failed(self, error_message: str) -> None:
        """
        Mark the scan as failed.

        Args:
            error_message: Error message explaining the failure
        """
        self.status = ScanStatus.FAILED
        self.end_time = datetime.now()
        self.error_message = error_message

    def mark_cancelled(self) -> None:
        """Mark the scan as cancelled."""
        self.status = ScanStatus.CANCELLED
        self.end_time = datetime.now()

    def add_warning(self, warning: str) -> None:
        """
        Add a warning message to the scan.

        Args:
            warning: Warning message to add
        """
        self.warnings.append(warning)

    def is_active(self) -> bool:
        """
        Check if the scan is active.

        Returns:
            True if the scan is pending or running, False otherwise
        """
        return self.status in [ScanStatus.PENDING, ScanStatus.RUNNING]


class ScanRegistry:
    """Thread-safe registry for tracking active scans."""

    def __init__(self):
        """Initialize the scan registry."""
        self._registry: Dict[str, ScanRegistryEntry] = {}
        self._registry_lock = Lock()
        self._logger = ASH_LOGGER

    def register_scan(
        self,
        directory_path: str,
        output_directory: str,
        severity_threshold: str = "MEDIUM",
        config_path: Optional[str] = None,
        scan_id: Optional[str] = None,
    ) -> str:
        """
        Register a new scan in the registry.

        Args:
            directory_path: Path to the directory being scanned
            output_directory: Path to the output directory for scan results
            severity_threshold: Minimum severity threshold for findings
            config_path: Optional path to ASH configuration file
            scan_id: Optional scan ID to use (generated if not provided)

        Returns:
            Scan ID for the registered scan

        Raises:
            MCPResourceError: If the scan cannot be registered
        """
        from automated_security_helper.core.resource_management.error_handling import (
            validate_directory_path,
            validate_severity_threshold,
            validate_config_path,
            ErrorCategory,
        )

        # Validate input parameters before acquiring lock
        dir_error = validate_directory_path(directory_path)
        if dir_error:
            raise dir_error

        output_dir_error = validate_directory_path(output_directory)
        if output_dir_error:
            raise output_dir_error

        severity_error = validate_severity_threshold(severity_threshold)
        if severity_error:
            raise severity_error

        if config_path:
            config_error = validate_config_path(config_path)
            if config_error:
                raise config_error

        with self._registry_lock:
            # Generate a scan ID if not provided
            if scan_id is None:
                scan_id = str(uuid.uuid4())
            elif not isinstance(scan_id, str) or not scan_id:
                raise MCPResourceError(
                    f"Invalid scan ID: {scan_id}. Must be a non-empty string.",
                    context={
                        "scan_id": scan_id,
                        "error_category": ErrorCategory.INVALID_PARAMETER.value,
                    },
                )

            # Check if scan ID already exists
            if scan_id in self._registry:
                raise MCPResourceError(
                    f"Scan ID {scan_id} already exists in registry",
                    context={
                        "scan_id": scan_id,
                        "error_category": ErrorCategory.INVALID_PARAMETER.value,
                        "suggestions": [
                            "Use a different scan ID",
                            "Check if you're trying to register the same scan twice",
                            "Use the existing scan ID to check progress or results",
                        ],
                    },
                )

            # Check if there's already an active scan for this directory
            for entry in self._registry.values():
                if entry.directory_path == directory_path and entry.is_active():
                    raise MCPResourceError(
                        f"Directory {directory_path} already has an active scan",
                        context={
                            "directory_path": directory_path,
                            "scan_id": entry.scan_id,
                            "error_category": ErrorCategory.RESOURCE_EXHAUSTED.value,
                            "suggestions": [
                                "Wait for the existing scan to complete",
                                "Cancel the existing scan if it's no longer needed",
                                "Use a different directory for the new scan",
                            ],
                        },
                    )

            # Create and register the scan entry
            try:
                entry = ScanRegistryEntry(
                    scan_id=scan_id,
                    directory_path=directory_path,
                    output_directory=output_directory,
                    severity_threshold=severity_threshold,
                    config_path=config_path,
                )
                self._registry[scan_id] = entry
                self._logger.info(
                    f"Registered scan {scan_id} for directory {directory_path}"
                )

                return scan_id
            except Exception as e:
                # Handle unexpected errors during entry creation
                self._logger.error(
                    f"Error creating scan registry entry: {str(e)}", exc_info=True
                )
                raise MCPResourceError(
                    f"Failed to register scan: {str(e)}",
                    context={
                        "directory_path": directory_path,
                        "output_directory": output_directory,
                        "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                    },
                )

    def get_scan(self, scan_id: str) -> Optional[ScanRegistryEntry]:
        """
        Get a scan entry by ID.

        Args:
            scan_id: ID of the scan to retrieve

        Returns:
            Scan registry entry or None if not found
        """
        with self._registry_lock:
            return self._registry.get(scan_id)

    def get_scan_by_directory(self, directory_path: str) -> Optional[ScanRegistryEntry]:
        """
        Get the active scan for a directory.

        Args:
            directory_path: Path to the directory

        Returns:
            Active scan registry entry or None if not found
        """
        with self._registry_lock:
            for entry in self._registry.values():
                if entry.directory_path == directory_path and entry.is_active():
                    return entry
            return None

    def update_scan_status(
        self, scan_id: str, status: ScanStatus, error_message: Optional[str] = None
    ) -> bool:
        """
        Update the status of a scan.

        Args:
            scan_id: ID of the scan to update
            status: New status for the scan
            error_message: Optional error message for failed scans

        Returns:
            True if the scan was updated, False if not found
        """
        with self._registry_lock:
            entry = self._registry.get(scan_id)
            if entry is None:
                return False

            if status == ScanStatus.RUNNING:
                entry.mark_running()
            elif status == ScanStatus.COMPLETED:
                entry.mark_completed()
            elif status == ScanStatus.FAILED:
                entry.mark_failed(error_message or "Unknown error")
            elif status == ScanStatus.CANCELLED:
                entry.mark_cancelled()

            self._logger.info(f"Updated scan {scan_id} status to {status.value}")
            return True

    def list_scans(
        self, active_only: bool = False, directory_path: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        List scans in the registry.

        Args:
            active_only: If True, only list active scans
            directory_path: Optional directory path to filter by

        Returns:
            List of scan entries as dictionaries
        """
        with self._registry_lock:
            result = []
            for entry in self._registry.values():
                if active_only and not entry.is_active():
                    continue
                if directory_path and entry.directory_path != directory_path:
                    continue
                result.append(entry.to_dict())
            return result

    def cancel_scan(self, scan_id: str) -> bool:
        """
        Cancel a scan.

        Args:
            scan_id: ID of the scan to cancel

        Returns:
            True if the scan was cancelled, False if not found or already completed

        Raises:
            MCPResourceError: If the scan cannot be cancelled
        """
        with self._registry_lock:
            entry = self._registry.get(scan_id)
            if entry is None:
                return False

            if not entry.is_active():
                # Scan is already completed, failed, or cancelled
                return False

            # Try to terminate the process if we have a process ID
            if entry.process_id:
                try:
                    os.kill(entry.process_id, signal.SIGTERM)
                    self._logger.info(
                        f"Sent SIGTERM to process {entry.process_id} for scan {scan_id}"
                    )
                except ProcessLookupError:
                    self._logger.warning(
                        f"Process {entry.process_id} for scan {scan_id} not found"
                    )
                except PermissionError:
                    self._logger.error(
                        f"Permission denied when trying to terminate process {entry.process_id}"
                    )
                    raise MCPResourceError(
                        f"Permission denied when trying to terminate process {entry.process_id}",
                        context={"scan_id": scan_id, "process_id": entry.process_id},
                    )
                except OSError as e:
                    self._logger.error(
                        f"Error terminating process {entry.process_id}: {str(e)}"
                    )
                    raise MCPResourceError(
                        f"Error terminating process {entry.process_id}: {str(e)}",
                        context={"scan_id": scan_id, "process_id": entry.process_id},
                    )

            # Mark the scan as cancelled
            entry.mark_cancelled()
            self._logger.info(f"Cancelled scan {scan_id}")
            return True

    def cleanup_scan(self, scan_id: str) -> bool:
        """
        Remove a scan from the registry.

        Args:
            scan_id: ID of the scan to remove

        Returns:
            True if the scan was removed, False if not found
        """
        with self._registry_lock:
            if scan_id in self._registry:
                del self._registry[scan_id]
                self._logger.info(f"Removed scan {scan_id} from registry")
                return True
            return False

    def cleanup_completed_scans(self, max_age_hours: int = 24) -> int:
        """
        Clean up old completed scans from the registry.

        Args:
            max_age_hours: Maximum age in hours for completed scans

        Returns:
            Number of scans cleaned up
        """
        with self._registry_lock:
            now = datetime.now()
            cutoff_time = now.timestamp() - (max_age_hours * 3600)
            scans_to_remove = []

            for scan_id, entry in self._registry.items():
                if not entry.is_active():
                    # Check if the scan is old enough to be removed
                    end_time = entry.end_time or entry.start_time
                    if end_time.timestamp() < cutoff_time:
                        scans_to_remove.append(scan_id)

            # Remove the old scans
            for scan_id in scans_to_remove:
                del self._registry[scan_id]

            if scans_to_remove:
                self._logger.info(
                    f"Cleaned up {len(scans_to_remove)} old scans from registry"
                )

            return len(scans_to_remove)

    def get_active_scan_count(self) -> int:
        """
        Get the number of active scans.

        Returns:
            Number of active scans
        """
        with self._registry_lock:
            return sum(1 for entry in self._registry.values() if entry.is_active())

    def get_scan_count(self) -> int:
        """
        Get the total number of scans in the registry.

        Returns:
            Total number of scans
        """
        with self._registry_lock:
            return len(self._registry)

    def get_scan_status_counts(self) -> Dict[str, int]:
        """
        Get counts of scans by status.

        Returns:
            Dictionary mapping status values to counts
        """
        with self._registry_lock:
            counts = {status.value: 0 for status in ScanStatus}
            for entry in self._registry.values():
                counts[entry.status.value] += 1
            return counts

    def check_scan_progress(self, scan_id: str) -> Dict[str, Any]:
        """
        Check the progress of a scan.

        Args:
            scan_id: ID of the scan to check

        Returns:
            Dictionary with scan progress information

        Raises:
            MCPResourceError: If the scan is not found or output directory is invalid
        """
        from automated_security_helper.core.resource_management.error_handling import (
            validate_scan_id,
            validate_directory_path,
            ErrorCategory,
        )

        # Validate scan ID before acquiring lock
        error = validate_scan_id(scan_id)
        if error:
            raise error

        with self._registry_lock:
            entry = self._registry.get(scan_id)
            if entry is None:
                raise MCPResourceError(
                    f"Scan {scan_id} not found in registry",
                    context={
                        "scan_id": scan_id,
                        "error_category": ErrorCategory.SCAN_NOT_FOUND.value,
                        "suggestions": [
                            "Check that the scan ID is correct",
                            "Verify that the scan exists in the registry",
                            "The scan may have been cleaned up if it was completed a long time ago",
                        ],
                    },
                )

            # Convert output directory to Path
            output_dir = Path(entry.output_directory)

            # Validate output directory using our enhanced validation
            error = validate_directory_path(output_dir)
            if error:
                # Add scan context to the error
                error.context["scan_id"] = scan_id
                raise error

            try:
                # Check if scan has completed based on file existence
                is_complete = check_scan_completion(output_dir)
                if is_complete and entry.status != ScanStatus.COMPLETED:
                    # Update scan status to completed
                    entry.mark_completed()

                # Create scan progress object from files
                scan_progress = create_scan_progress_from_files(scan_id, output_dir)

                # If scan is marked as completed in the registry, ensure it's also completed in the progress object
                if (
                    entry.status == ScanStatus.COMPLETED
                    and scan_progress.status != "completed"
                ):
                    scan_progress.mark_completed()

                # Convert scan progress to dictionary
                progress_dict = scan_progress.to_dict()

                # Combine registry entry information with progress info
                result = {
                    "scan_id": scan_id,
                    "directory_path": entry.directory_path,
                    "output_directory": str(output_dir),
                    "start_time": entry.start_time.isoformat(),
                    "end_time": entry.end_time.isoformat() if entry.end_time else None,
                    "status": entry.status.value,
                    "severity_threshold": entry.severity_threshold,
                    "config_path": entry.config_path,
                    "warnings": entry.warnings,
                    "error_message": entry.error_message,
                    "is_complete": entry.status == ScanStatus.COMPLETED
                    or scan_progress.is_complete,
                    "completed_scanners": scan_progress.completed_scanners,
                    "total_scanners": scan_progress.total_scanners,
                    "total_findings": scan_progress.total_findings,
                    "severity_counts": scan_progress.severity_counts,
                    "scanners": progress_dict.get("scanners", {}),
                }

                return result

            except Exception as e:
                # Handle unexpected errors during progress checking
                if isinstance(e, MCPResourceError):
                    # If it's already an MCPResourceError, just add scan context if needed
                    if "scan_id" not in e.context:
                        e.context["scan_id"] = scan_id
                    raise e
                else:
                    # Wrap other exceptions in MCPResourceError
                    self._logger.error(
                        f"Error checking scan progress: {str(e)}", exc_info=True
                    )
                    raise MCPResourceError(
                        f"Failed to check scan progress: {str(e)}",
                        context={
                            "scan_id": scan_id,
                            "directory_path": entry.directory_path,
                            "output_directory": str(output_dir),
                            "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                            "error_type": type(e).__name__,
                            "error_message": str(e),
                        },
                    )


# Create a global instance of the scan registry
_scan_registry = ScanRegistry()


def get_scan_registry() -> ScanRegistry:
    """
    Get the global scan registry instance.

    Returns:
        Global scan registry instance
    """
    return _scan_registry
