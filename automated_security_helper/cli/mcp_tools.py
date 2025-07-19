#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
MCP tools for ASH security scanning.

This module provides MCP tools for security scanning with file-based tracking
of scan progress and completion. It implements a more reliable approach to
track scan progress than event-based tracking.
"""

import asyncio
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Any

from automated_security_helper.core.resource_management.scan_registry import (
    get_scan_registry,
    ScanStatus,
)
from automated_security_helper.core.resource_management.scan_tracking import (
    get_scan_results_with_error_handling,
)
from automated_security_helper.core.resource_management.scan_management import (
    list_active_scans,
    cancel_scan,
    check_scan_progress,
)
from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
    create_error_response,
)
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.log import ASH_LOGGER

# Configure module logger (without affecting global logging)
# The MCP logging patch will ensure this logger is properly isolated
_logger = ASH_LOGGER


async def mcp_scan_directory(
    directory_path: str,
    severity_threshold: str = "MEDIUM",
    config_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Start a security scan with file-based progress tracking.

    This tool starts a scan in the background and returns immediately with a scan_id.
    Use get_scan_progress to track progress and get_scan_results for final results.

    The scan progress is tracked by monitoring the existence of result files in the
    output directory, providing a more reliable approach than event-based tracking.

    Args:
        directory_path: Path to the directory to scan
        severity_threshold: Minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL)
        config_path: Optional path to ASH configuration file

    Returns:
        Dictionary with scan ID and status information
    """
    from automated_security_helper.core.resource_management.error_handling import (
        validate_directory_path,
        validate_severity_threshold,
        validate_config_path,
    )

    # Validate directory path
    dir_error = validate_directory_path(directory_path)
    if dir_error:
        return create_error_response(
            error=dir_error,
            operation="scan_directory",
            suggestions=[
                "Check that the directory exists and is accessible",
                "Verify that the path is correct",
                "Ensure you have appropriate permissions to access the directory",
            ],
        )

    # Validate severity threshold
    severity_error = validate_severity_threshold(severity_threshold)
    if severity_error:
        return create_error_response(
            error=severity_error,
            operation="scan_directory",
            suggestions=[
                "Valid severity thresholds are: LOW, MEDIUM, HIGH, CRITICAL",
                "Check the spelling and case of the severity threshold",
            ],
        )

    # Validate config path if provided
    if config_path:
        config_error = validate_config_path(config_path)
        if config_error:
            return create_error_response(
                error=config_error,
                operation="scan_directory",
                suggestions=[
                    "Check that the configuration file exists and is accessible",
                    "Verify that the path is correct",
                    "Ensure the file has a valid extension (.yaml, .yml, or .json)",
                ],
            )

    try:
        # Create a unique scan ID
        scan_id = str(uuid.uuid4())

        # Create output directory path
        directory_path_obj = Path(directory_path)
        output_dir = directory_path_obj / ".ash" / "ash_output"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Register the scan in the registry
        registry = get_scan_registry()
        scan_id = registry.register_scan(
            directory_path=str(directory_path_obj),
            output_directory=str(output_dir),
            severity_threshold=severity_threshold,
            config_path=config_path,
            scan_id=scan_id,
        )

        # Start the scan process asynchronously
        asyncio.create_task(
            _run_scan_async(
                scan_id=scan_id,
                directory_path=str(directory_path_obj),
                output_dir=str(output_dir),
                severity_threshold=severity_threshold,
                config_path=config_path,
            )
        )

        # Return scan ID and initial status with standardized format
        return {
            "success": True,
            "operation": "scan_directory",
            "scan_id": scan_id,
            "status": "pending",
            "directory_path": str(directory_path_obj),
            "output_directory": str(output_dir),
            "severity_threshold": severity_threshold,
            "config_path": config_path,
            "start_time": datetime.now().isoformat(),
            "message": "Scan started successfully. Use get_scan_progress to track progress.",
        }

    except MCPResourceError as e:
        # Handle specific MCPResourceError with enhanced context
        return create_error_response(
            error=e,
            operation="scan_directory",
            suggestions=[
                "Check that the directory exists and is accessible",
                "Verify that the severity threshold is valid",
                "Ensure the configuration file is valid if provided",
            ],
        )
    except Exception as e:
        # Handle unexpected errors
        _logger.error(f"Unexpected error starting scan: {str(e)}", exc_info=True)
        return create_error_response(
            error=MCPResourceError(
                f"Unexpected error starting scan: {str(e)}",
                context={
                    "directory_path": directory_path,
                    "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                },
            ),
            operation="scan_directory",
        )


async def _run_scan_async(
    scan_id: str,
    directory_path: str,
    output_dir: str,
    severity_threshold: str,
    config_path: Optional[str] = None,
) -> None:
    """
    Run an ASH scan asynchronously.

    This function runs the scan using direct Python calls to the ASH functionality
    and updates the scan registry with the scan status.

    Args:
        scan_id: ID of the scan
        directory_path: Path to the directory to scan
        output_dir: Path to the output directory
        severity_threshold: Minimum severity threshold
        config_path: Optional path to ASH configuration file
    """
    from automated_security_helper.core.enums import AshLogLevel, RunMode
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    registry = get_scan_registry()
    entry = registry.get_scan(scan_id)
    if not entry:
        _logger.error(f"Scan {scan_id} not found in registry")
        return

    try:
        # Mark the scan as running
        registry.update_scan_status(scan_id, ScanStatus.RUNNING)

        # Log the scan start
        _logger.info(
            f"Starting scan process for scan {scan_id} in directory {directory_path}"
        )

        # Run the scan using direct Python calls
        try:
            # Create a task to run the scan in a separate thread to avoid blocking
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: run_ash_scan(
                    source_dir=directory_path,
                    output_dir=output_dir,
                    config=config_path,
                    mode=RunMode.local,
                    log_level=AshLogLevel.INFO,
                    fail_on_findings=False,  # Don't exit on findings
                    show_summary=False,  # Don't show summary
                ),
            )

            # Update scan status based on result
            registry.update_scan_status(scan_id, ScanStatus.COMPLETED)
            _logger.info(f"Scan {scan_id} completed successfully")

        except Exception as e:
            # Handle scan execution errors
            error_message = f"Error executing scan: {str(e)}"
            registry.update_scan_status(scan_id, ScanStatus.FAILED, error_message)
            _logger.error(f"Scan {scan_id} failed: {error_message}")
            return

    except Exception as e:
        # Handle unexpected errors
        error_message = f"Unexpected error running scan: {str(e)}"
        registry.update_scan_status(scan_id, ScanStatus.FAILED, error_message)
        _logger.error(error_message, exc_info=True)


async def mcp_get_scan_progress(scan_id: str) -> Dict[str, Any]:
    """
    Get current progress and partial results for a running scan using file-based tracking.

    This tool checks for the existence of result files to determine scan progress,
    providing a more reliable approach than event-based tracking.

    Args:
        scan_id: The scan ID returned from scan_directory

    Returns:
        Dictionary with scan progress information
    """
    from automated_security_helper.core.resource_management.error_handling import (
        validate_scan_id,
    )

    try:
        # Validate scan ID
        error = validate_scan_id(scan_id)
        if error:
            return create_error_response(
                error=error,
                operation="get_scan_progress",
                suggestions=[
                    "Check that the scan ID is correct",
                    "Verify that the scan exists in the registry",
                    "Ensure the scan ID format is valid",
                ],
            )

        # Check scan progress using the scan management function
        progress_info = await check_scan_progress(scan_id)

        # Add timestamp and operation to the response for consistency
        progress_info["timestamp"] = datetime.now().isoformat()
        progress_info["operation"] = "get_scan_progress"

        return progress_info

    except MCPResourceError as e:
        # Handle specific MCPResourceError with enhanced context
        return create_error_response(
            error=e,
            operation="get_scan_progress",
            suggestions=[
                "Check that the scan ID is correct",
                "Verify that the scan exists in the registry",
                "Ensure the scan was started correctly",
            ],
        )
    except Exception as e:
        # Handle unexpected errors
        _logger.error(
            f"Unexpected error getting scan progress: {str(e)}", exc_info=True
        )
        return create_error_response(
            error=MCPResourceError(
                f"Unexpected error getting scan progress: {str(e)}",
                context={
                    "scan_id": scan_id,
                    "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                },
            ),
            operation="get_scan_progress",
        )


async def mcp_get_scan_results(output_dir: str) -> Dict[str, Any]:
    """
    Get final results for a completed scan using file-based tracking.

    IMPORTANT: Always use an absolute path for the output_dir parameter.
    Relative paths will not work correctly due to the MCP server's working directory.

    This tool checks for the existence of the aggregated results file to determine
    if the scan has completed, and then parses the results file to extract findings.
    It provides a more reliable approach than event-based tracking.

    Args:
        output_dir: ABSOLUTE path to the scan output directory
                   (e.g., '/Users/username/project/dir/.ash/ash_output')

    Returns:
        Dictionary with scan results information
    """
    from automated_security_helper.core.resource_management.error_handling import (
        validate_directory_path,
    )

    try:
        # Validate that the path is absolute
        if not Path(output_dir).is_absolute():
            return create_error_response(
                error=MCPResourceError(
                    "Absolute path required: The output_dir parameter must be an absolute path",
                    context={
                        "output_dir": output_dir,
                        "error_category": ErrorCategory.INVALID_PARAMETER.value,
                    },
                ),
                operation="get_scan_results",
                suggestions=[
                    "Use an absolute path starting with '/' for the output_dir parameter",
                    "Example: '/Users/username/project/dir/.ash/ash_output'",
                    "Relative paths will not work correctly due to the MCP server's working directory",
                ],
            )

        # Use the output_dir directly since it's absolute
        resolved_output_dir = Path(output_dir)

        # Log the resolved path for debugging
        _logger.info(f"Using absolute output directory: {resolved_output_dir}")

        # Validate that the directory exists and is accessible
        error = validate_directory_path(resolved_output_dir)
        if error:
            return create_error_response(
                error=error,
                operation="get_scan_results",
                suggestions=[
                    "Check that the output directory exists",
                    "Verify that the path is correct",
                    "Ensure you have appropriate permissions to access the directory",
                ],
            )

        # Get scan results with error handling
        results = get_scan_results_with_error_handling(resolved_output_dir)

        # Add timestamp and operation to the response for consistency
        if isinstance(results, dict):
            if "timestamp" not in results:
                results["timestamp"] = datetime.now().isoformat()
            results["operation"] = "get_scan_results"

        return results

    except Exception as e:
        # Handle unexpected errors
        _logger.error(f"Unexpected error getting scan results: {str(e)}", exc_info=True)
        return create_error_response(
            error=MCPResourceError(
                f"Unexpected error getting scan results: {str(e)}",
                context={
                    # "scan_id": scan_id,
                    "cwd": str(Path.cwd()),
                    "output_dir": output_dir,
                    "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                },
            ),
            operation="get_scan_results",
        )


async def mcp_list_active_scans() -> Dict[str, Any]:
    """
    List all active and recent scans with their current status using file-based tracking.

    This tool uses the scan registry to list all active and recent scans,
    providing more reliable information than event-based tracking.

    Returns:
        Dictionary with information about all scans in the registry
    """
    try:
        # Get active scans from the scan management function
        active_scans = await list_active_scans()

        # Get all scans (including completed ones)
        registry = get_scan_registry()
        all_scans = registry.list_scans()

        # Get scan statistics
        stats = {
            "total_scans": registry.get_scan_count(),
            "active_scans": registry.get_active_scan_count(),
            "status_counts": registry.get_scan_status_counts(),
        }

        # Return standardized successful response
        return {
            "success": True,
            "active_scans": active_scans,
            "all_scans": all_scans,
            "stats": stats,
            "timestamp": datetime.now().isoformat(),
            "operation": "list_active_scans",
        }

    except Exception as e:
        # Handle unexpected errors
        _logger.error(f"Unexpected error listing active scans: {str(e)}", exc_info=True)
        return create_error_response(
            error=MCPResourceError(
                f"Unexpected error listing active scans: {str(e)}",
                context={
                    "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                },
            ),
            operation="list_active_scans",
        )


async def mcp_cancel_scan(scan_id: str) -> Dict[str, Any]:
    """
    Cancel a running scan and clean up its resources using file-based tracking.

    This tool uses the scan registry to cancel a scan and clean up its resources,
    providing a more reliable approach than event-based tracking.

    Args:
        scan_id: The scan ID to cancel

    Returns:
        Dictionary with cancellation result information
    """
    from automated_security_helper.core.resource_management.error_handling import (
        validate_scan_id,
    )

    try:
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

        # Cancel the scan using the scan management function
        result = await cancel_scan(scan_id)

        # Add timestamp and operation to the response for consistency
        if isinstance(result, dict):
            if "timestamp" not in result:
                result["timestamp"] = datetime.now().isoformat()
            if "operation" not in result:
                result["operation"] = "cancel_scan"

        return result

    except Exception as e:
        # Handle unexpected errors
        _logger.error(f"Unexpected error cancelling scan: {str(e)}", exc_info=True)
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


async def mcp_check_installation() -> Dict[str, Any]:
    """
    Check if ASH is properly installed and ready to use.

    Returns:
        Dictionary with installation status information
    """
    try:
        # Get ASH version
        version = get_ash_version()

        # Check if ASH is available using direct Python calls
        try:
            # We already have the version from get_ash_version()
            ash_command_available = True
            ash_command_output = f"ASH version {version}"
        except Exception:
            ash_command_available = False
            ash_command_output = ""

        return {
            "success": True,
            "installed": True,
            "version": version,
            "ash_command_available": ash_command_available,
            "ash_command_output": ash_command_output,
            "timestamp": datetime.now().isoformat(),
        }

    except Exception as e:
        # Handle unexpected errors
        _logger.error(
            f"Unexpected error checking installation: {str(e)}", exc_info=True
        )
        return create_error_response(
            error=MCPResourceError(
                f"Unexpected error checking installation: {str(e)}",
                context={
                    "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "installed": False,
                },
            ),
            operation="check_installation",
            suggestions=[
                "Check that ASH is installed correctly",
                "Verify that the ASH command is available in your PATH",
                "Try reinstalling ASH",
            ],
        )
