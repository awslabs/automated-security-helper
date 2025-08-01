#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Scan management functions for ASH MCP server.

This module provides functions for managing scans, including listing active scans,
cancelling scans, and cleaning up completed scans. It builds on the scan registry
to provide a higher-level interface for scan management.
"""

import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_registry import (
    get_scan_registry,
)
from automated_security_helper.utils.log import ASH_LOGGER


# Configure module logger
_logger = ASH_LOGGER


async def list_active_scans() -> List[Dict[str, Any]]:
    """
    List all active scans.

    Returns:
        List of active scan information dictionaries
    """
    registry = get_scan_registry()
    return registry.list_scans(active_only=True)


async def list_all_scans() -> List[Dict[str, Any]]:
    """
    List all scans, including completed ones.

    Returns:
        List of all scan information dictionaries
    """
    registry = get_scan_registry()
    return registry.list_scans()


async def cancel_scan(scan_id: str) -> Dict[str, Any]:
    """
    Cancel a running scan.

    Args:
        scan_id: ID of the scan to cancel

    Returns:
        Dictionary with cancellation result information

    Raises:
        MCPResourceError: If the scan cannot be cancelled
    """
    from automated_security_helper.core.resource_management.error_handling import (
        validate_scan_id,
        ErrorCategory,
        create_error_response,
    )

    # Validate scan ID
    error = validate_scan_id(scan_id)
    if error:
        return create_error_response(
            error=error,
            operation="cancel_scan",
            suggestions=[
                "Check that the scan ID is correct",
                "Verify that the scan exists in the registry",
                "Ensure the scan ID format is valid",
            ],
        )

    registry = get_scan_registry()

    # Get scan information before cancellation
    entry = registry.get_scan(scan_id)
    if entry is None:
        error = MCPResourceError(
            f"Scan {scan_id} not found",
            context={
                "scan_id": scan_id,
                "error_category": ErrorCategory.SCAN_NOT_FOUND.value,
            },
        )
        return create_error_response(
            error=error,
            operation="cancel_scan",
            suggestions=[
                "Check that the scan ID is correct",
                "Verify that the scan exists in the registry",
                "The scan may have been cleaned up if it was completed a long time ago",
            ],
        )

    # Check if scan is already completed
    if not entry.is_active():
        return {
            "success": False,
            "scan_id": scan_id,
            "message": f"Scan is already in {entry.status.value} state and cannot be cancelled",
            "status": entry.status.value,
            "suggestions": [
                "No action needed as the scan is already completed/failed/cancelled",
                "Use get_scan_results to retrieve results if the scan is completed",
                "Start a new scan if needed",
            ],
        }

    try:
        # Try to cancel the scan
        success = registry.cancel_scan(scan_id)

        if success:
            return {
                "success": True,
                "scan_id": scan_id,
                "message": "Scan cancelled successfully",
                "status": "cancelled",
                "timestamp": datetime.now().isoformat(),
            }
        else:
            return {
                "success": False,
                "scan_id": scan_id,
                "message": "Failed to cancel scan",
                "status": entry.status.value,
                "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                "suggestions": [
                    "The scan may have completed or failed during cancellation attempt",
                    "Check scan status using get_scan_progress",
                    "Try again if the scan is still active",
                ],
            }
    except MCPResourceError as e:
        # Handle specific MCPResourceError with enhanced context
        return create_error_response(
            error=e,
            operation="cancel_scan",
            suggestions=[
                "Check if you have permission to cancel the scan",
                "Verify that the scan process is still running",
                "The scan may have completed or failed during cancellation attempt",
            ],
        )
    except Exception as e:
        # Handle unexpected errors
        _logger.error(
            f"Unexpected error cancelling scan {scan_id}: {str(e)}", exc_info=True
        )
        return create_error_response(
            error=MCPResourceError(
                f"Unexpected error cancelling scan: {str(e)}",
                context={
                    "scan_id": scan_id,
                    "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                },
            ),
            operation="cancel_scan",
        )


async def cleanup_scan_resources(
    scan_id: str, remove_output: bool = False
) -> Dict[str, Any]:
    """
    Clean up resources associated with a scan.

    Args:
        scan_id: ID of the scan to clean up
        remove_output: If True, also remove output files

    Returns:
        Dictionary with cleanup result information

    Raises:
        MCPResourceError: If the scan cannot be cleaned up
    """
    from automated_security_helper.core.resource_management.error_handling import (
        validate_scan_id,
        ErrorCategory,
        create_error_response,
    )

    # Validate scan ID
    error = validate_scan_id(scan_id)
    if error:
        return create_error_response(
            error=error,
            operation="cleanup_scan_resources",
            suggestions=[
                "Check that the scan ID is correct",
                "Verify that the scan exists in the registry",
                "Ensure the scan ID format is valid",
            ],
        )

    registry = get_scan_registry()

    # Get scan information before cleanup
    entry = registry.get_scan(scan_id)
    if entry is None:
        error = MCPResourceError(
            f"Scan {scan_id} not found",
            context={
                "scan_id": scan_id,
                "error_category": ErrorCategory.SCAN_NOT_FOUND.value,
            },
        )
        return create_error_response(
            error=error,
            operation="cleanup_scan_resources",
            suggestions=[
                "Check that the scan ID is correct",
                "Verify that the scan exists in the registry",
                "The scan may have been cleaned up already",
            ],
        )

    try:
        # Check if scan is still active
        if entry.is_active():
            # Try to cancel the scan first
            try:
                cancel_result = await cancel_scan(scan_id)
                if not cancel_result.get("success", False):
                    _logger.warning(
                        f"Failed to cancel scan {scan_id} during cleanup: {cancel_result.get('message', 'Unknown error')}"
                    )
            except Exception as e:
                _logger.warning(
                    f"Failed to cancel scan {scan_id} during cleanup: {str(e)}"
                )

        # Remove output files if requested
        removed_output = False
        output_dir_error = None
        if remove_output and entry.output_directory:
            try:
                output_dir = Path(entry.output_directory)
                if output_dir.exists() and output_dir.is_dir():
                    shutil.rmtree(output_dir)
                    removed_output = True
            except PermissionError as e:
                output_dir_error = (
                    f"Permission denied: Cannot remove output directory: {str(e)}"
                )
                _logger.error(
                    f"Permission denied: Cannot remove output directory for scan {scan_id}: {str(e)}"
                )
            except FileNotFoundError:
                # This is not an error, just means the directory was already removed
                removed_output = True
            except Exception as e:
                output_dir_error = f"Failed to remove output directory: {str(e)}"
                _logger.error(
                    f"Failed to remove output directory for scan {scan_id}: {str(e)}"
                )

        # Remove scan from registry
        removed_from_registry = registry.cleanup_scan(scan_id)

        result = {
            "success": removed_from_registry,
            "scan_id": scan_id,
            "removed_output": removed_output,
            "removed_from_registry": removed_from_registry,
            "message": "Scan resources cleaned up successfully"
            if removed_from_registry
            else "Failed to clean up scan resources",
            "timestamp": datetime.now().isoformat(),
        }

        # Add output directory error if there was one
        if output_dir_error:
            result["output_dir_error"] = output_dir_error
            result["warnings"] = [
                "Output directory could not be removed, but scan was removed from registry"
            ]

        return result

    except Exception as e:
        # Handle unexpected errors
        _logger.error(
            f"Unexpected error cleaning up scan {scan_id}: {str(e)}", exc_info=True
        )
        return create_error_response(
            error=MCPResourceError(
                f"Unexpected error cleaning up scan: {str(e)}",
                context={
                    "scan_id": scan_id,
                    "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                },
            ),
            operation="cleanup_scan_resources",
        )


async def cleanup_old_scans(
    max_age_hours: int = 24, remove_output: bool = False
) -> Dict[str, Any]:
    """
    Clean up old completed scans.

    Args:
        max_age_hours: Maximum age in hours for completed scans
        remove_output: If True, also remove output files

    Returns:
        Dictionary with cleanup result information
    """
    registry = get_scan_registry()

    # Get list of all scans before cleanup
    all_scans = registry.list_scans()

    # Find old scans that should be cleaned up
    now = datetime.now()
    cutoff_time = now.timestamp() - (max_age_hours * 3600)
    scans_to_cleanup = []

    for scan in all_scans:
        if scan["status"] in ["completed", "failed", "cancelled"]:
            end_time_str = scan.get("end_time") or scan.get("start_time")
            if end_time_str:
                try:
                    end_time = datetime.fromisoformat(end_time_str)
                    if end_time.timestamp() < cutoff_time:
                        scans_to_cleanup.append(scan["scan_id"])
                except (ValueError, TypeError):
                    _logger.warning(
                        f"Invalid timestamp format for scan {scan['scan_id']}"
                    )

    # Clean up each old scan
    cleaned_up_scans = []
    failed_cleanups = []

    for scan_id in scans_to_cleanup:
        try:
            result = await cleanup_scan_resources(scan_id, remove_output)
            if result["success"]:
                cleaned_up_scans.append(scan_id)
            else:
                failed_cleanups.append(scan_id)
        except Exception as e:
            _logger.error(f"Error cleaning up scan {scan_id}: {str(e)}")
            failed_cleanups.append(scan_id)

    return {
        "success": len(failed_cleanups) == 0,
        "cleaned_up_count": len(cleaned_up_scans),
        "failed_count": len(failed_cleanups),
        "cleaned_up_scans": cleaned_up_scans,
        "failed_cleanups": failed_cleanups,
        "message": f"Cleaned up {len(cleaned_up_scans)} old scans, {len(failed_cleanups)} failed",
    }


async def get_scan_statistics() -> Dict[str, Any]:
    """
    Get statistics about scans.

    Returns:
        Dictionary with scan statistics
    """
    registry = get_scan_registry()

    return {
        "total_scans": registry.get_scan_count(),
        "active_scans": registry.get_active_scan_count(),
        "status_counts": registry.get_scan_status_counts(),
        "timestamp": datetime.now().isoformat(),
    }


async def check_scan_exists(scan_id: str) -> bool:
    """
    Check if a scan exists in the registry.

    Args:
        scan_id: ID of the scan to check

    Returns:
        True if the scan exists, False otherwise
    """
    registry = get_scan_registry()
    return registry.get_scan(scan_id) is not None


async def get_scan_by_directory(directory_path: str) -> Optional[Dict[str, Any]]:
    """
    Get the active scan for a directory.

    Args:
        directory_path: Path to the directory

    Returns:
        Scan information dictionary or None if not found
    """
    registry = get_scan_registry()
    entry = registry.get_scan_by_directory(directory_path)
    if entry:
        return entry.to_dict()
    return None


async def check_scan_progress(scan_id: str) -> Dict[str, Any]:
    """
    Check the progress of a scan.

    Args:
        scan_id: ID of the scan to check

    Returns:
        Dictionary with scan progress information

    Raises:
        MCPResourceError: If the scan is not found
    """
    from automated_security_helper.core.resource_management.error_handling import (
        validate_scan_id,
        ErrorCategory,
        create_error_response,
    )

    # Validate scan ID
    error = validate_scan_id(scan_id)
    if error:
        return create_error_response(
            error=error,
            operation="check_scan_progress",
            suggestions=[
                "Check that the scan ID is correct",
                "Verify that the scan exists in the registry",
                "Ensure the scan ID format is valid",
            ],
        )

    try:
        registry = get_scan_registry()
        return registry.check_scan_progress(scan_id)
    except MCPResourceError as e:
        # Add operation context to the error
        return create_error_response(error=e, operation="check_scan_progress")
    except Exception as e:
        # Handle unexpected errors
        _logger.error(
            f"Unexpected error checking scan progress for {scan_id}: {str(e)}",
            exc_info=True,
        )
        return create_error_response(
            error=MCPResourceError(
                f"Unexpected error checking scan progress: {str(e)}",
                context={
                    "scan_id": scan_id,
                    "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                },
            ),
            operation="check_scan_progress",
        )
