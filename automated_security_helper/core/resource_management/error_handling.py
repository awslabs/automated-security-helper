#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Comprehensive error handling utilities for ASH MCP server.

This module provides utilities for handling errors in file operations,
validating input parameters, and creating meaningful error messages for
various failure scenarios.
"""

import json
import os
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.utils.log import ASH_LOGGER


# Configure module logger
_logger = ASH_LOGGER


class ErrorCategory(Enum):
    """Categories of errors for better error handling and reporting."""

    FILE_NOT_FOUND = "file_not_found"
    PERMISSION_DENIED = "permission_denied"
    INVALID_FORMAT = "invalid_format"
    INVALID_PARAMETER = "invalid_parameter"
    INVALID_PATH = "invalid_path"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    OPERATION_TIMEOUT = "operation_timeout"
    SCAN_NOT_FOUND = "scan_not_found"
    SCAN_INCOMPLETE = "scan_incomplete"
    UNEXPECTED_ERROR = "unexpected_error"


def safe_read_json_file(
    file_path: Union[str, Path], required: bool = True
) -> Tuple[Optional[Dict[str, Any]], Optional[MCPResourceError]]:
    """
    Safely read a JSON file with comprehensive error handling.

    Args:
        file_path: Path to the JSON file
        required: If True, raise an error if the file doesn't exist

    Returns:
        Tuple of (parsed_json, error)
        If successful, error will be None
        If failed, parsed_json will be None and error will contain the error information
    """
    try:
        path_obj = Path(file_path)

        # Check if file exists
        if not path_obj.exists():
            if required:
                error = MCPResourceError(
                    f"File not found: {path_obj}",
                    context={
                        "cwd": str(Path.cwd()),
                        "file_path": str(path_obj),
                        "error_category": ErrorCategory.FILE_NOT_FOUND.value,
                    },
                )
                return None, error
            else:
                return None, None

        # Check if it's a file
        if not path_obj.is_file():
            error = MCPResourceError(
                f"Path is not a file: {path_obj}",
                context={
                    "cwd": str(Path.cwd()),
                    "file_path": str(path_obj),
                    "error_category": ErrorCategory.INVALID_PATH.value,
                },
            )
            return None, error

        # Check if file is readable
        if not os.access(path_obj, os.R_OK):
            error = MCPResourceError(
                f"Permission denied: Cannot read file {path_obj}",
                context={
                    "cwd": str(Path.cwd()),
                    "file_path": str(path_obj),
                    "error_category": ErrorCategory.PERMISSION_DENIED.value,
                },
            )
            return None, error

        # Read and parse the file
        with open(path_obj, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                return data, None
            except json.JSONDecodeError as e:
                error = MCPResourceError(
                    f"Invalid JSON format in file {path_obj}: {str(e)}",
                    context={
                        "cwd": str(Path.cwd()),
                        "file_path": str(path_obj),
                        "error_category": ErrorCategory.INVALID_FORMAT.value,
                        "json_error": str(e),
                        "error_line": e.lineno,
                        "error_column": e.colno,
                    },
                )
                return None, error

    except Exception as e:
        error = MCPResourceError(
            f"Unexpected error reading file {file_path}: {str(e)}",
            context={
                "cwd": str(Path.cwd()),
                "file_path": str(file_path),
                "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                "error_type": type(e).__name__,
                "error_message": str(e),
            },
        )
        return None, error


def safe_write_json_file(
    file_path: Union[str, Path], data: Dict[str, Any]
) -> Optional[MCPResourceError]:
    """
    Safely write a JSON file with comprehensive error handling.

    Args:
        file_path: Path to the JSON file
        data: Data to write to the file

    Returns:
        None if successful, MCPResourceError if failed
    """
    try:
        path_obj = Path(file_path)

        # Ensure parent directory exists
        parent_dir = path_obj.parent
        if not parent_dir.exists():
            try:
                parent_dir.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                return MCPResourceError(
                    f"Permission denied: Cannot create directory {parent_dir}",
                    context={
                        "cwd": str(Path.cwd()),
                        "directory_path": str(parent_dir),
                        "error_category": ErrorCategory.PERMISSION_DENIED.value,
                    },
                )
            except Exception as e:
                return MCPResourceError(
                    f"Failed to create directory {parent_dir}: {str(e)}",
                    context={
                        "cwd": str(Path.cwd()),
                        "directory_path": str(parent_dir),
                        "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                    },
                )

        # Check if parent directory is writable
        if not os.access(parent_dir, os.W_OK):
            return MCPResourceError(
                f"Permission denied: Cannot write to directory {parent_dir}",
                context={
                    "cwd": str(Path.cwd()),
                    "directory_path": str(parent_dir),
                    "error_category": ErrorCategory.PERMISSION_DENIED.value,
                },
            )

        # Write the file
        try:
            with open(path_obj, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            return None
        except PermissionError:
            return MCPResourceError(
                f"Permission denied: Cannot write to file {path_obj}",
                context={
                    "cwd": str(Path.cwd()),
                    "file_path": str(path_obj),
                    "error_category": ErrorCategory.PERMISSION_DENIED.value,
                },
            )
        except TypeError as e:
            return MCPResourceError(
                f"Invalid data format for JSON serialization: {str(e)}",
                context={
                    "cwd": str(Path.cwd()),
                    "file_path": str(path_obj),
                    "error_category": ErrorCategory.INVALID_FORMAT.value,
                    "error_message": str(e),
                },
            )

    except Exception as e:
        return MCPResourceError(
            f"Unexpected error writing file {file_path}: {str(e)}",
            context={
                "cwd": str(Path.cwd()),
                "file_path": str(file_path),
                "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                "error_type": type(e).__name__,
                "error_message": str(e),
            },
        )


def validate_directory_path(
    directory_path: Union[str, Path],
) -> Optional[MCPResourceError]:
    """
    Validate a directory path with comprehensive error handling.

    Args:
        directory_path: Path to validate

    Returns:
        None if valid, MCPResourceError if invalid
    """
    # First try the path as provided
    path_obj = Path(directory_path)
    try:
        # Check if path exists and is a directory
        if path_obj.exists() and path_obj.is_dir():
            return None  # Path is valid
    except Exception as e:
        return MCPResourceError(
            f"Unexpected error validating directory path {directory_path}: {str(e)}",
            context={
                "cwd": str(Path.cwd()),
                "directory_path": str(directory_path),
                "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                "error_type": type(e).__name__,
                "error_message": str(e),
            },
        )

    # If the path doesn't exist as provided, try relative to current directory
    if not path_obj.is_absolute():
        rel_path_obj = Path.cwd() / directory_path
        try:
            if rel_path_obj.exists() and rel_path_obj.is_dir():
                return None  # Relative path is valid
        except Exception as e:
            return MCPResourceError(
                f"Unexpected error validating directory path {directory_path}: {str(e)}",
                context={
                    "cwd": str(Path.cwd()),
                    "directory_path": str(directory_path),
                    "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                },
            )

    # If we get here, the path is not valid
    return MCPResourceError(
        f"Directory not found or not a directory: {directory_path}",
        context={
            "cwd": str(Path.cwd()),
            "directory_path": str(directory_path),
            "error_category": ErrorCategory.FILE_NOT_FOUND.value,
        },
    )


def validate_scan_id(scan_id: str) -> Optional[MCPResourceError]:
    """
    Validate a scan ID with comprehensive error handling.

    Args:
        scan_id: Scan ID to validate

    Returns:
        None if valid, MCPResourceError if invalid
    """
    if not scan_id:
        return MCPResourceError(
            "Scan ID cannot be empty",
            context={"error_category": ErrorCategory.INVALID_PARAMETER.value},
        )

    if not isinstance(scan_id, str):
        return MCPResourceError(
            f"Scan ID must be a string, got {type(scan_id).__name__}",
            context={
                "error_category": ErrorCategory.INVALID_PARAMETER.value,
                "parameter_type": type(scan_id).__name__,
            },
        )

    # Additional validation could be added here if needed
    # For example, checking if the scan ID matches a specific format

    return None


def validate_severity_threshold(severity_threshold: str) -> Optional[MCPResourceError]:
    """
    Validate a severity threshold with comprehensive error handling.

    Args:
        severity_threshold: Severity threshold to validate

    Returns:
        None if valid, MCPResourceError if invalid
    """
    valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    if not severity_threshold:
        return MCPResourceError(
            "Severity threshold cannot be empty",
            context={"error_category": ErrorCategory.INVALID_PARAMETER.value},
        )

    if not isinstance(severity_threshold, str):
        return MCPResourceError(
            f"Severity threshold must be a string, got {type(severity_threshold).__name__}",
            context={
                "error_category": ErrorCategory.INVALID_PARAMETER.value,
                "parameter_type": type(severity_threshold).__name__,
            },
        )

    if severity_threshold.upper() not in valid_severities:
        return MCPResourceError(
            f"Invalid severity threshold: '{severity_threshold}'. Must be one of: {', '.join(valid_severities)}",
            context={
                "error_category": ErrorCategory.INVALID_PARAMETER.value,
                "valid_values": valid_severities,
            },
        )

    return None


def validate_config_path(
    config_path: Optional[Union[str, Path]],
) -> Optional[MCPResourceError]:
    """
    Validate a configuration file path with comprehensive error handling.

    Args:
        config_path: Path to the configuration file, or None

    Returns:
        None if valid or None, MCPResourceError if invalid
    """
    if config_path is None:
        return None

    try:
        path_obj = (
            Path(config_path)
            if Path(config_path).is_absolute()
            else Path.cwd().joinpath(config_path)
        )

        # Check if file exists
        if not path_obj.exists():
            return MCPResourceError(
                f"Configuration file not found: {path_obj}",
                context={
                    "config_path": str(path_obj),
                    "error_category": ErrorCategory.FILE_NOT_FOUND.value,
                },
            )

        # Check if it's a file
        if not path_obj.is_file():
            return MCPResourceError(
                f"Configuration path is not a file: {path_obj}",
                context={
                    "config_path": str(path_obj),
                    "error_category": ErrorCategory.INVALID_PATH.value,
                },
            )

        # Check if file is readable
        if not os.access(path_obj, os.R_OK):
            return MCPResourceError(
                f"Permission denied: Cannot read configuration file {path_obj}",
                context={
                    "config_path": str(path_obj),
                    "error_category": ErrorCategory.PERMISSION_DENIED.value,
                },
            )

        # Validate file extension
        valid_extensions = [".yaml", ".yml", ".json"]
        if not any(str(path_obj).lower().endswith(ext) for ext in valid_extensions):
            return MCPResourceError(
                f"Invalid configuration file extension: {path_obj}. Supported extensions: {', '.join(valid_extensions)}",
                context={
                    "config_path": str(path_obj),
                    "error_category": ErrorCategory.INVALID_FORMAT.value,
                    "valid_extensions": valid_extensions,
                },
            )

        return None

    except Exception as e:
        return MCPResourceError(
            f"Unexpected error validating configuration path {config_path}: {str(e)}",
            context={
                "config_path": str(config_path),
                "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                "error_type": type(e).__name__,
                "error_message": str(e),
            },
        )


def validate_scan_parameters(
    directory_path: Union[str, Path],
    severity_threshold: str = "MEDIUM",
    config_path: Optional[Union[str, Path]] = None,
) -> Tuple[bool, List[MCPResourceError]]:
    """
    Validate scan parameters with comprehensive error handling.

    Args:
        directory_path: Path to the directory to scan
        severity_threshold: Minimum severity threshold
        config_path: Optional path to ASH configuration file

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    # Validate directory path
    dir_error = validate_directory_path(directory_path)
    if dir_error:
        errors.append(dir_error)

    # Validate severity threshold
    severity_error = validate_severity_threshold(severity_threshold)
    if severity_error:
        errors.append(severity_error)

    # Validate configuration path if provided
    if config_path:
        config_error = validate_config_path(config_path)
        if config_error:
            errors.append(config_error)

    return len(errors) == 0, errors


def check_file_exists(file_path: Union[str, Path]) -> bool:
    """
    Check if a file exists with error handling.

    Args:
        file_path: Path to the file

    Returns:
        True if the file exists, False otherwise
    """
    try:
        path_obj = (
            Path(file_path)
            if Path(file_path).is_absolute()
            else Path.cwd().joinpath(file_path)
        )
        return path_obj.exists() and path_obj.is_file()
    except Exception as e:
        _logger.warning(f"Error checking if file exists {file_path}: {str(e)}")
        return False


def check_directory_exists(directory_path: Union[str, Path]) -> bool:
    """
    Check if a directory exists with error handling.

    Args:
        directory_path: Path to the directory

    Returns:
        True if the directory exists, False otherwise
    """
    try:
        path_obj = (
            Path(directory_path)
            if Path(directory_path).is_absolute()
            else Path.cwd().joinpath(directory_path)
        )
        return path_obj.exists() and path_obj.is_dir()
    except Exception as e:
        _logger.warning(
            f"Error checking if directory exists {directory_path}: {str(e)}"
        )
        return False


def create_error_response(
    error: Union[MCPResourceError, Exception],
    operation: str,
    suggestions: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Create a standardized error response for API operations.

    Args:
        error: The error that occurred
        operation: The operation that was being performed
        suggestions: Optional list of suggestions for resolving the error

    Returns:
        Standardized error response dictionary
    """
    # Extract error category if available
    error_category = "unexpected_error"
    context = {}

    if isinstance(error, MCPResourceError) and hasattr(error, "context"):
        context = error.context
        error_category = context.get("error_category", "unexpected_error")

    # Generate default suggestions based on error category
    if suggestions is None:
        suggestions = _get_default_suggestions(error_category)

    return {
        "success": False,
        "operation": operation,
        "error": str(error),
        "error_type": type(error).__name__,
        "error_category": error_category,
        "context": context,
        "suggestions": suggestions,
        "timestamp": None,  # Will be set by caller if needed
    }


def _get_default_suggestions(error_category: str) -> List[str]:
    """
    Get default suggestions based on error category.

    Args:
        error_category: The category of the error

    Returns:
        List of suggestions
    """
    default_suggestions = {
        ErrorCategory.FILE_NOT_FOUND.value: [
            "Check that the file or directory exists",
            "Verify the path is correct",
            "Ensure the file has not been moved or deleted",
        ],
        ErrorCategory.PERMISSION_DENIED.value: [
            "Check file and directory permissions",
            "Ensure the user has appropriate access rights",
            "Verify ownership of the file or directory",
        ],
        ErrorCategory.INVALID_FORMAT.value: [
            "Check the file format and structure",
            "Ensure the file is properly formatted JSON/YAML",
            "Validate the file against the expected schema",
        ],
        ErrorCategory.INVALID_PARAMETER.value: [
            "Check the parameter values provided",
            "Ensure all required parameters are provided",
            "Verify parameter types and formats",
        ],
        ErrorCategory.INVALID_PATH.value: [
            "Verify the path is correct and properly formatted",
            "Check for invalid characters or syntax in the path",
            "Ensure the path points to the correct type (file/directory)",
        ],
        ErrorCategory.RESOURCE_EXHAUSTED.value: [
            "Check system resources (memory, disk space)",
            "Reduce the number of concurrent operations",
            "Wait and try again later",
        ],
        ErrorCategory.OPERATION_TIMEOUT.value: [
            "Check if the operation is still running",
            "Increase the timeout value if possible",
            "Verify system performance and resource availability",
        ],
        ErrorCategory.SCAN_NOT_FOUND.value: [
            "Verify the scan ID is correct",
            "Check if the scan has been cleaned up or expired",
            "Ensure the scan was properly registered",
        ],
        ErrorCategory.SCAN_INCOMPLETE.value: [
            "Wait for the scan to complete",
            "Check for errors in the scan process",
            "Verify the scan is still running",
        ],
        ErrorCategory.UNEXPECTED_ERROR.value: [
            "Check logs for additional information",
            "Verify system stability and resource availability",
            "Report the issue if it persists",
        ],
    }

    return default_suggestions.get(
        error_category,
        [
            "Check logs for additional information",
            "Verify input parameters and system state",
            "Report the issue if it persists",
        ],
    )
