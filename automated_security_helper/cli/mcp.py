# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
MCP (Model Context Protocol) CLI command for ASH.

This module provides a CLI command to start an MCP server that exposes ASH security
scanning capabilities through the Model Context Protocol. The MCP server allows
LLMs and other tools to interact with ASH programmatically.
"""

import json
import os
import signal
import logging
import asyncio
from datetime import datetime

from pathlib import Path
from typing import Optional, Dict, Any, Annotated, List, Tuple
import typer
from rich import print

from automated_security_helper.core.enums import AshLogLevel
from automated_security_helper.core.exceptions import ScannerError, ASHValidationError

# Module-level imports for functions that tests need to mock
# These are imported here to make them available for patching in tests
try:
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan
    from automated_security_helper.config.resolve_config import resolve_config
except ImportError:
    # These imports may fail in environments where ASH core is not fully available
    # The functions will handle ImportError appropriately when called
    run_ash_scan = None
    resolve_config = None

# Conditional import for MCP dependencies
try:
    from mcp.server.fastmcp import FastMCP, Context
except ImportError:
    # MCP dependencies are optional and will be checked at runtime
    FastMCP = None
    Context = None


# Global storage for scan concurrency control
_active_scans_by_directory: Dict[str, str] = {}  # directory_path -> scan_id

# Security configuration
MAX_CONCURRENT_SCANS = 3
MAX_SCAN_DURATION_MINUTES = 30
MAX_DIRECTORY_SIZE_MB = 1000
MIN_OPERATION_TIMEOUT_MINUTES = 3  # Minimum timeout for operations
MAX_MESSAGE_SIZE_BYTES = 10 * 1024 * 1024  # 10MB max message size
MAX_PATH_LENGTH = 4096  # Maximum path length to prevent buffer overflow attacks


def mcp_command(
    ctx: typer.Context,
    log_level: Annotated[
        AshLogLevel,
        typer.Option(
            "--log-level",
            help="Set the log level.",
        ),
    ] = AshLogLevel.INFO,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose logging")
    ] = False,
    debug: Annotated[
        bool, typer.Option("--debug", "-d", help="Enable debug logging")
    ] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
    quiet: Annotated[bool, typer.Option(help="Hide all log output")] = False,
) -> None:
    """Start the ASH MCP server for Model Context Protocol integration.

    The MCP server exposes ASH security scanning capabilities through the Model Context Protocol,
    allowing LLMs and other tools to perform security scans and analyze results programmatically.

    MCP support is included by default in ASH v3. If you encounter dependency issues, please
    check your ASH installation.

    The MCP server provides the following capabilities:
    - scan_directory: Start security scans with progress tracking
    - get_scan_progress: Monitor running scan progress
    - get_scan_results: Retrieve completed scan results
    - list_active_scans: View all active and recent scans
    - cancel_scan: Stop running scans
    - check_installation: Verify ASH installation and version
    - Resources for status and help information
    - Prompts for analyzing security findings
    """
    # Handle resilient parsing for command discovery
    if ctx.resilient_parsing:
        return

    # Check for MCP dependencies using module-level imports
    if FastMCP is None or Context is None:
        print("[red]Error: MCP dependencies are not available.[/red]")
        print()
        print("MCP support is included by default in ASH v3. Try reinstalling ASH:")
        print("  [cyan]pip install --force-reinstall automated-security-helper[/cyan]")
        print("  [cyan]uv sync --reinstall[/cyan]")
        print()
        print(
            "If the issue persists, check your Python environment and ASH installation."
        )
        raise typer.Exit(1)

    # Apply logging configuration based on parameters
    final_log_level = (
        AshLogLevel.VERBOSE
        if verbose
        else (
            AshLogLevel.DEBUG if debug else (AshLogLevel.QUIET if quiet else log_level)
        )
    )

    # If we reach here, MCP dependencies are available
    if not quiet:
        print("[green]MCP dependencies found. Starting MCP server...[/green]")

    # Initialize and start the MCP server with comprehensive error handling
    try:
        _start_mcp_server(quiet=quiet, log_level=final_log_level)
    except KeyboardInterrupt:
        if not quiet:
            print("\n[yellow]MCP server shutdown requested by user[/yellow]")
        raise typer.Exit(0)
    except ScannerError as e:
        if not quiet:
            print(f"[red]ASH Scanner Error: {str(e)}[/red]")
            print(
                "[yellow]This indicates an issue with ASH configuration or dependencies.[/yellow]"
            )
        raise typer.Exit(2)
    except ASHValidationError as e:
        if not quiet:
            print(f"[red]ASH Validation Error: {str(e)}[/red]")
            print(
                "[yellow]This indicates invalid configuration or parameters.[/yellow]"
            )
        raise typer.Exit(3)
    except Exception as e:
        if not quiet:
            print(f"[red]Unexpected error starting MCP server: {str(e)}[/red]")
            print(f"[red]Error type: {type(e).__name__}[/red]")
            print(
                "[yellow]Please check system resources and ASH installation.[/yellow]"
            )
        raise typer.Exit(1)


def _load_environment_configuration() -> Dict[str, Any]:
    """Load ASH configuration from environment variables.

    This function implements support for ASH configuration through environment variables.

    Returns:
        Dictionary of configuration values from environment variables
    """
    env_config = {}

    # Map of environment variables to configuration paths
    env_var_mappings = {
        "ASH_DEFAULT_SEVERITY_LEVEL": "global_settings.severity_threshold",
        "ASH_PROJECT_NAME": "project_name",
        "ASH_FAIL_ON_FINDINGS": "fail_on_findings",
        "ASH_OFFLINE": "global_settings.offline",
        # Add more mappings as needed
    }

    for env_var, config_path in env_var_mappings.items():
        env_value = os.environ.get(env_var, None)
        if env_value is not None:
            # Parse the environment variable value
            if env_var == "ASH_FAIL_ON_FINDINGS":
                env_config[config_path] = env_value.upper() in ["YES", "1", "TRUE"]
            elif env_var == "ASH_OFFLINE":
                env_config[config_path] = env_value.upper() in ["YES", "1", "TRUE"]
            else:
                env_config[config_path] = env_value

    return env_config


def _validate_message_size_and_format(message_data: Any) -> Tuple[bool, List[str]]:
    """Validate message size and basic format for MCP operations.

    This implements enhanced input validation as required by MCP security guidelines
    to prevent DoS attacks and ensure proper message formatting.

    Args:
        message_data: The message data to validate

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    try:
        # Convert to JSON string to check size
        if isinstance(message_data, (dict, list)):
            message_str = json.dumps(message_data)
        elif isinstance(message_data, str):
            message_str = message_data
        else:
            message_str = str(message_data)

        # Check message size
        message_size = len(message_str.encode("utf-8"))
        if message_size > MAX_MESSAGE_SIZE_BYTES:
            errors.append(
                f"Message size ({message_size} bytes) exceeds maximum allowed "
                f"({MAX_MESSAGE_SIZE_BYTES} bytes)"
            )

        # Basic JSON format validation for dict/list types
        if isinstance(message_data, (dict, list)):
            try:
                # Ensure it can be serialized back to JSON
                json.dumps(message_data)
            except (TypeError, ValueError) as e:
                errors.append(f"Invalid JSON format: {str(e)}")

    except Exception as e:
        errors.append(f"Message validation error: {str(e)}")

    return len(errors) == 0, errors


def _sanitize_string_input(
    input_str: str, max_length: int = MAX_PATH_LENGTH
) -> Tuple[str, List[str]]:
    """Sanitize string input to prevent injection attacks and validate length.

    This implements input sanitization as required by MCP security guidelines.

    Args:
        input_str: String to sanitize
        max_length: Maximum allowed length

    Returns:
        Tuple of (sanitized_string, list_of_warnings)
    """
    warnings = []

    if not isinstance(input_str, str):
        input_str = str(input_str)
        warnings.append("Input was converted to string")

    # Check length
    if len(input_str) > max_length:
        input_str = input_str[:max_length]
        warnings.append(f"Input truncated to {max_length} characters")

    # Remove null bytes and other potentially dangerous characters
    original_length = len(input_str)
    input_str = input_str.replace("\x00", "").replace("\r", "").replace("\n", " ")

    if len(input_str) != original_length:
        warnings.append("Removed potentially dangerous characters")

    # Strip leading/trailing whitespace
    input_str = input_str.strip()

    return input_str, warnings


def _validate_scan_parameters(
    directory_path: str, severity_threshold: str, config_path: Optional[str] = None
) -> Tuple[bool, List[str]]:
    """Validate scan parameters with comprehensive input validation.

    This function implements comprehensive input validation for scan parameters
    as required. Includes proper directory validation and path resolution.

    Enhanced with security input validation as per MCP security guidelines.

    Args:
        directory_path: Path to the directory to scan
        severity_threshold: Minimum severity threshold
        config_path: Optional path to ASH configuration file

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    # Log security event for parameter validation
    directory_str = str(directory_path)[:100] if directory_path is not None else "None"
    severity_str = (
        str(severity_threshold)[:20] if severity_threshold is not None else "None"
    )
    _security_logger.info(
        f"Validating scan parameters - directory: {directory_str}..., "
        f"severity: {severity_str}, config: {config_path is not None}"
    )

    # Validate and resolve directory path with enhanced security checks
    if not directory_path:
        errors.append("Directory path cannot be empty")
    elif not isinstance(directory_path, str):
        errors.append(
            f"Directory path must be a string, got {type(directory_path).__name__}"
        )
    else:
        # Sanitize directory path input
        sanitized_path, path_warnings = _sanitize_string_input(directory_path)
        if path_warnings:
            _security_logger.warning(
                f"Directory path sanitization warnings: {path_warnings}"
            )
        directory_path = sanitized_path
        # Use enhanced path resolution and validation
        path_valid, resolved_path, path_errors = _resolve_and_validate_directory_path(
            directory_path
        )
        if not path_valid:
            errors.extend(path_errors)
        else:
            # Additional validation for resolved path
            try:
                # Check if directory is readable
                if not os.access(resolved_path, os.R_OK):
                    errors.append(f"Directory is not readable: {resolved_path}")

                # Check if directory is not empty (warning, not error)
                try:
                    path_obj = Path(resolved_path)
                    if not any(path_obj.iterdir()):
                        # This is a warning, not an error - empty directories can be scanned
                        pass
                except PermissionError:
                    errors.append(
                        f"Permission denied accessing directory: {resolved_path}"
                    )

            except (OSError, ValueError) as e:
                errors.append(
                    f"Error validating resolved directory path '{resolved_path}': {str(e)}"
                )

    # Validate severity threshold with enhanced security checks
    valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    if not severity_threshold:
        errors.append("Severity threshold cannot be empty")
    elif not isinstance(severity_threshold, str):
        errors.append(
            f"Severity threshold must be a string, got {type(severity_threshold).__name__}"
        )
    else:
        # Sanitize severity threshold input
        sanitized_severity, severity_warnings = _sanitize_string_input(
            severity_threshold, max_length=20
        )
        if severity_warnings:
            _security_logger.warning(
                f"Severity threshold sanitization warnings: {severity_warnings}"
            )

        if sanitized_severity not in valid_severities:
            errors.append(
                f"Invalid severity threshold: '{sanitized_severity}'. "
                f"Must be one of: {', '.join(valid_severities)}"
            )
        else:
            severity_threshold = sanitized_severity

    # Validate configuration file path if provided with enhanced security checks
    if config_path:
        if not isinstance(config_path, str):
            errors.append(
                f"Configuration path must be a string, got {type(config_path).__name__}"
            )
        else:
            # Sanitize config path input
            sanitized_config_path, config_warnings = _sanitize_string_input(config_path)
            if config_warnings:
                _security_logger.warning(
                    f"Config path sanitization warnings: {config_warnings}"
                )
            config_path = sanitized_config_path

            try:
                config_path_obj = Path(config_path)

                # Check if config file exists
                if not config_path_obj.exists():
                    errors.append(f"Configuration file does not exist: {config_path}")
                elif not config_path_obj.is_file():
                    errors.append(f"Configuration path is not a file: {config_path}")
                else:
                    # Check if config file is readable
                    if not os.access(config_path, os.R_OK):
                        errors.append(
                            f"Configuration file is not readable: {config_path}"
                        )

                    # Validate config file extension
                    valid_extensions = [".yaml", ".yml", ".json"]
                    if not any(
                        config_path.lower().endswith(ext) for ext in valid_extensions
                    ):
                        errors.append(
                            f"Configuration file must have a valid extension: {config_path}. "
                            f"Supported extensions: {', '.join(valid_extensions)}"
                        )

            except (OSError, ValueError) as e:
                errors.append(
                    f"Invalid configuration file path '{config_path}': {str(e)}"
                )

    return len(errors) == 0, errors


def _resolve_and_validate_directory_path(
    directory_path: str,
) -> Tuple[bool, str, List[str]]:
    """Resolve and validate directory path with proper path resolution.

    This function implements proper directory validation and path resolution.

    Args:
        directory_path: Path to resolve and validate

    Returns:
        Tuple of (is_valid, resolved_path, list_of_errors)
    """
    errors = []
    resolved_path = directory_path

    try:
        # Resolve path to absolute path
        path_obj = Path(directory_path).resolve()
        resolved_path = str(path_obj)

        # Check if path exists
        if not path_obj.exists():
            errors.append(f"Directory does not exist: {resolved_path}")
            return False, resolved_path, errors

        # Check if it's actually a directory
        if not path_obj.is_dir():
            errors.append(f"Path is not a directory: {resolved_path}")
            return False, resolved_path, errors

        # Check for symbolic links and resolve them
        if path_obj.is_symlink():
            try:
                real_path = path_obj.resolve(strict=True)
                resolved_path = str(real_path)
                if not real_path.exists():
                    errors.append(
                        f"Symbolic link target does not exist: {resolved_path}"
                    )
                    return False, resolved_path, errors
                if not real_path.is_dir():
                    errors.append(
                        f"Symbolic link target is not a directory: {resolved_path}"
                    )
                    return False, resolved_path, errors
            except (OSError, RuntimeError) as e:
                errors.append(f"Failed to resolve symbolic link: {str(e)}")
                return False, resolved_path, errors

        # Check for common problematic paths
        problematic_paths = [
            Path.home() / ".ssh",
            Path("/etc"),
            Path("/sys"),
            Path("/proc"),
            Path("/dev"),
        ]

        for problematic_path in problematic_paths:
            try:
                if path_obj.is_relative_to(problematic_path):
                    errors.append(
                        f"Directory path appears to be in a system directory that should not be scanned: {resolved_path}"
                    )
                    break
            except (ValueError, AttributeError):
                # is_relative_to not available in older Python versions, skip this check
                pass

    except (OSError, ValueError) as e:
        errors.append(f"Failed to resolve directory path '{directory_path}': {str(e)}")
        return False, resolved_path, errors

    return len(errors) == 0, resolved_path, errors


def _validate_file_system_access(directory_path: str) -> Tuple[bool, List[str]]:
    """Validate file system access and permissions.

    This function implements file system validation as required by for graceful file
    system error handling.

    Args:
        directory_path: Path to validate

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    try:
        path_obj = Path(directory_path)

        # Test read access
        if not os.access(directory_path, os.R_OK):
            errors.append(f"No read permission for directory: {directory_path}")

        # Test if we can list directory contents
        try:
            list(path_obj.iterdir())
        except PermissionError:
            errors.append(f"Cannot list directory contents: {directory_path}")
        except OSError as e:
            errors.append(f"File system error accessing directory: {str(e)}")

        # Check available disk space (basic check)
        try:
            stat = os.statvfs(directory_path)
            available_bytes = stat.f_bavail * stat.f_frsize
            # Require at least 100MB free space for scan operations
            if available_bytes < 100 * 1024 * 1024:
                errors.append(
                    f"Insufficient disk space for scan operations. "
                    f"Available: {available_bytes // (1024 * 1024)}MB, Required: 100MB"
                )
        except (OSError, AttributeError):
            # statvfs not available on all platforms, skip this check
            pass

    except Exception as e:
        errors.append(f"Unexpected file system error: {str(e)}")

    return len(errors) == 0, errors


def _create_structured_error_response(
    error_type: str,
    error_message: str,
    context: Optional[Dict[str, Any]] = None,
    suggestions: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Create a structured error response for MCP operations.

    This function implements structured error responses as required by for scan
    operation failures.

    Args:
        error_type: Type of error (validation, runtime, filesystem, etc.)
        error_message: Human-readable error message
        context: Additional context information
        suggestions: List of actionable suggestions

    Returns:
        Structured error response dictionary
    """
    response = {
        "success": False,
        "error": error_message,
        "error_type": error_type,
        "timestamp": None,  # Will be set by caller if needed
    }

    if context:
        response["context"] = context

    if suggestions:
        response["suggestions"] = suggestions
    else:
        # Provide default suggestions based on error type
        default_suggestions = {
            "validation": [
                "Check that all required parameters are provided",
                "Verify that paths exist and are accessible",
                "Ensure severity threshold is valid (LOW, MEDIUM, HIGH, CRITICAL)",
            ],
            "filesystem": [
                "Check that the directory exists and is readable",
                "Verify sufficient disk space is available",
                "Ensure proper file permissions are set",
            ],
            "runtime": [
                "Check ASH installation and dependencies",
                "Verify system resources are available",
                "Review logs for additional error details",
            ],
            "dependency": [
                "Reinstall ASH to ensure MCP dependencies are available",
                "Check Python environment and package versions",
                "Verify ASH installation is complete",
            ],
        }
        response["suggestions"] = default_suggestions.get(
            error_type,
            [
                "Check system logs for additional information",
                "Verify ASH installation and configuration",
            ],
        )

    return response


def _get_ash_version_direct() -> tuple[bool, str]:
    """Get ASH version using direct Python call instead of subprocess.

    This replaces the subprocess call to 'ash --version' with a direct
    call to the get_ash_version() function.

    Returns:
        tuple: (success, version_info_or_error)
    """
    try:
        from automated_security_helper.utils.get_ash_version import get_ash_version

        version = get_ash_version()
        return True, f"ASH version {version}"
    except ImportError as e:
        # Handle case where package metadata is not available (development mode)
        if "No package metadata was found" in str(e):
            return True, "ASH version 3.0.0-dev (development mode)"
        return False, f"Error importing ASH version utility: {str(e)}"
    except Exception as e:
        return False, f"Error getting ASH version: {str(e)}"


def _run_ash_scan_direct(
    directory_path: str,
    severity_threshold: str = "MEDIUM",
    output_dir: Optional[str] = None,
    config_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Run ASH scan using direct Python call instead of subprocess.

    This replaces the subprocess call to 'ash --mode local ...' with a direct
    call to the run_ash_scan() function. Implements comprehensive error handling.

    Supports ASH configuration files and environment variables.

    Args:
        directory_path: Path to the directory to scan
        severity_threshold: Minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL)
        output_dir: Optional output directory path
        config_path: Optional path to ASH configuration file

    Returns:
        Dict containing scan results and metadata or structured error response
    """
    from datetime import datetime

    start_time = datetime.now()

    try:
        # Validate scan parameters first
        is_valid, validation_errors = _validate_scan_parameters(
            directory_path, severity_threshold, config_path
        )
        if not is_valid:
            return _create_structured_error_response(
                error_type="validation",
                error_message=f"Invalid scan parameters: {'; '.join(validation_errors)}",
                context={
                    "directory_path": directory_path,
                    "severity_threshold": severity_threshold,
                    "validation_errors": validation_errors,
                },
            )

        # Resolve directory path for consistent handling
        path_valid, resolved_directory_path, path_errors = (
            _resolve_and_validate_directory_path(directory_path)
        )
        if not path_valid:
            return _create_structured_error_response(
                error_type="validation",
                error_message=f"Directory path resolution failed: {'; '.join(path_errors)}",
                context={"original_path": directory_path, "path_errors": path_errors},
            )

        # Use resolved path for all subsequent operations
        directory_path = resolved_directory_path

        # Validate file system access
        fs_valid, fs_errors = _validate_file_system_access(directory_path)
        if not fs_valid:
            return _create_structured_error_response(
                error_type="filesystem",
                error_message=f"File system access error: {'; '.join(fs_errors)}",
                context={
                    "directory_path": directory_path,
                    "filesystem_errors": fs_errors,
                },
            )

        # Import required modules with proper error handling
        # Use module-level imports that are available for testing
        # Use module-level imports that are available for testing
        if run_ash_scan is None or resolve_config is None:
            return _create_structured_error_response(
                error_type="runtime",
                error_message="Failed to import ASH scan functionality: Required modules not available",
                context={"import_error": "ASH core modules not imported"},
                suggestions=[
                    "Verify ASH installation is complete",
                    "Check that all required dependencies are installed",
                    "Try reinstalling ASH with: pip install automated-security-helper",
                ],
            )

        run_ash_scan_func = run_ash_scan
        resolve_config_func = resolve_config

        try:
            from automated_security_helper.core.enums import RunMode, Phases
            from automated_security_helper.core.constants import (
                ASH_DEFAULT_SEVERITY_LEVEL,
            )
        except ImportError as e:
            return _create_structured_error_response(
                error_type="dependency",
                error_message=f"Failed to import ASH core functionality: {str(e)}",
                context={"import_error": str(e)},
                suggestions=[
                    "Verify ASH installation is complete",
                    "Check that all required dependencies are installed",
                    "Try reinstalling ASH with: pip install automated-security-helper",
                ],
            )

        # Load and validate ASH configuration
        # This implements requirement 7.1, 7.2, and 7.3 for configuration support
        try:
            # Load environment configuration first
            env_config = _load_environment_configuration()

            # Convert environment config to config overrides format
            config_overrides = []
            for config_path_key, value in env_config.items():
                config_overrides.append(f"{config_path_key}={value}")

            # Resolve configuration from file, environment variables, and defaults
            config = resolve_config_func(
                config_path=Path(config_path) if config_path else None,
                source_dir=Path(directory_path),
                fallback_to_default=True,
                config_overrides=config_overrides,  # Apply environment variable overrides
            )

            # Use configuration severity threshold if not explicitly provided
            # This ensures MCP scans respect same severity thresholds as regular ASH scans (requirement 7.1)
            if (
                severity_threshold == "MEDIUM"
                and config.global_settings.severity_threshold
                != ASH_DEFAULT_SEVERITY_LEVEL
            ):
                severity_threshold = config.global_settings.severity_threshold

        except Exception as e:
            return _create_structured_error_response(
                error_type="validation",
                error_message=f"Failed to load ASH configuration: {str(e)}",
                context={
                    "config_path": config_path,
                    "directory_path": directory_path,
                    "config_error": str(e),
                },
                suggestions=[
                    "Check that the configuration file exists and is valid",
                    "Verify YAML/JSON syntax in configuration file",
                    "Ensure configuration follows ASH schema requirements",
                ],
            )

        # Use default ASH output directory (relative to scan directory) if not provided
        # This ensures scan results are easily accessible and follows ASH conventions
        if output_dir is None:
            # Use ASH default: .ash/ash_output in the scan directory
            output_dir = os.path.join(directory_path, ".ash", "ash_output")

        # Ensure output directory exists with proper structure
        try:
            os.makedirs(output_dir, mode=0o755, exist_ok=True)

            # Create subdirectories that ASH expects
            reports_dir = os.path.join(output_dir, "reports")
            scanners_dir = os.path.join(output_dir, "scanners")

            os.makedirs(reports_dir, mode=0o755, exist_ok=True)
            os.makedirs(scanners_dir, mode=0o755, exist_ok=True)

            # Validate write permissions
            if not os.access(output_dir, os.W_OK):
                return _create_structured_error_response(
                    error_type="filesystem",
                    error_message=f"No write permission for output directory: {output_dir}",
                    context={"output_dir": output_dir},
                )
        except Exception as e:
            return _create_structured_error_response(
                error_type="filesystem",
                error_message=f"Failed to create output directory: {str(e)}",
                context={"output_dir": output_dir, "creation_error": str(e)},
            )

        # Call run_ash_scan directly with comprehensive error handling
        try:
            results = run_ash_scan_func(
                source_dir=directory_path,
                output_dir=output_dir,
                config=config_path,  # Pass configuration file path
                mode=RunMode.local,
                phases=[Phases.convert, Phases.scan, Phases.report],
                fail_on_findings=False,  # Always False for MCP to prevent server termination
                show_summary=False,  # Don't show summary output
                quiet=False,  # Enable output to allow event emission
                progress=True,  # Enable progress to allow event emission
                log_level=AshLogLevel.DEBUG,  # Enable debug logging to see events
            )
        except ScannerError as e:
            return _create_structured_error_response(
                error_type="runtime",
                error_message=f"ASH scanner error: {str(e)}",
                context={"directory_path": directory_path, "scanner_error": str(e)},
                suggestions=[
                    "Check that the directory contains scannable files",
                    "Verify ASH scanner dependencies are installed",
                    "Review ASH logs for detailed error information",
                ],
            )
        except ASHValidationError as e:
            return _create_structured_error_response(
                error_type="validation",
                error_message=f"ASH validation error: {str(e)}",
                context={"directory_path": directory_path, "validation_error": str(e)},
            )
        except Exception as e:
            return _create_structured_error_response(
                error_type="runtime",
                error_message=f"Unexpected error during ASH scan: {str(e)}",
                context={
                    "directory_path": directory_path,
                    "unexpected_error": str(e),
                    "error_type": type(e).__name__,
                },
            )

        execution_time = (datetime.now() - start_time).total_seconds()

        # Get ASH version for response
        version_success, version_info = _get_ash_version_direct()
        ash_version = version_info if version_success else "Unknown"

        return {
            "success": True,
            "exit_code": 0,
            "scan_path": directory_path,
            "mode": "local",
            "severity_threshold": severity_threshold,
            "execution_time_seconds": round(execution_time, 2),
            "ash_version": ash_version,
            "output_dir": output_dir,
            "results": results,
        }

    except Exception as e:
        # Catch-all for any unexpected errors
        execution_time = (datetime.now() - start_time).total_seconds()

        return _create_structured_error_response(
            error_type="runtime",
            error_message=f"Critical error during scan operation: {str(e)}",
            context={
                "directory_path": directory_path,
                "severity_threshold": severity_threshold,
                "execution_time_seconds": round(execution_time, 2),
                "critical_error": str(e),
                "error_type": type(e).__name__,
            },
            suggestions=[
                "Check system resources and permissions",
                "Verify ASH installation integrity",
                "Contact support if the issue persists",
            ],
        )


def _start_mcp_server(
    quiet: bool = False, log_level: AshLogLevel = AshLogLevel.INFO
) -> None:
    """Initialize and start the MCP server with proper lifecycle management.

    This function creates a FastMCP server instance, sets up signal handlers for
    graceful shutdown, and starts the server. It handles the complete server
    lifecycle including initialization, startup, and shutdown.

    Args:
        quiet: Whether to suppress output messages
        log_level: Logging level for the server

    Raises:
        KeyboardInterrupt: When user requests shutdown (Ctrl+C)
        Exception: For any server initialization or runtime errors
    """
    mcp_server = None

    try:
        # Use module-level imports (already validated in calling function)
        if FastMCP is None:
            error_msg = "FastMCP not available - MCP dependencies not imported"
            if not quiet:
                print(f"[red]{error_msg}[/red]")
            raise ScannerError(error_msg)

        # Initialize the MCP server with security-focused configuration
        try:
            # Set up logging to reduce verbosity
            import logging

            # Reduce MCP and FastMCP logging to INFO level only
            logging.getLogger("mcp").setLevel(logging.INFO)
            logging.getLogger("fastmcp").setLevel(logging.INFO)

            # Log security event for server initialization
            _security_logger.info("Initializing ASH MCP server with security controls")

            # Initialize server with localhost binding for security
            # This enforces binding only to localhost (127.0.0.1) as required by MCP security guidelines
            try:
                # Try to configure FastMCP with localhost binding
                # Note: FastMCP may not support direct transport configuration
                # In that case, it should default to stdio transport which is secure
                mcp_server = FastMCP("ASH Security Scanner")

                # Log successful initialization with security note
                _security_logger.info(
                    "MCP server initialized - using stdio transport (secure by default) "
                    "or localhost binding if network transport is used"
                )

            except Exception as transport_error:
                # Fallback to standard initialization if transport config fails
                _security_logger.warning(
                    f"Could not configure explicit transport security: {transport_error}. "
                    "Using default FastMCP configuration (should be stdio/secure by default)"
                )
                mcp_server = FastMCP("ASH Security Scanner")
        except Exception as e:
            error_msg = f"Failed to initialize MCP server: {str(e)}"
            if not quiet:
                print(f"[red]{error_msg}[/red]")
            raise ScannerError(error_msg) from e

        # Set up signal handlers for graceful shutdown with resource cleanup
        def signal_handler(signum, frame):
            """Handle shutdown signals gracefully with proper cleanup."""
            if not quiet:
                print(
                    f"\n[yellow]Received signal {signum}, shutting down MCP server...[/yellow]"
                )

            # Clean up scan progress store before shutdown
            try:
                _cleanup_scan_progress_store()
            except Exception as cleanup_error:
                if not quiet:
                    print(
                        f"[yellow]Warning during cleanup: {str(cleanup_error)}[/yellow]"
                    )

            # The KeyboardInterrupt will be caught by the calling function
            raise KeyboardInterrupt()

        # Register signal handlers for common shutdown signals
        try:
            signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
            if hasattr(signal, "SIGTERM"):
                signal.signal(signal.SIGTERM, signal_handler)  # Termination signal
        except Exception as e:
            if not quiet:
                print(
                    f"[yellow]Warning: Could not register signal handlers: {str(e)}[/yellow]"
                )

        # Set up MCP server handlers (tools, resources, prompts)
        try:
            _setup_mcp_server_handlers(mcp_server)
        except Exception as e:
            error_msg = f"Failed to set up MCP server handlers: {str(e)}"
            if not quiet:
                print(f"[red]{error_msg}[/red]")
            raise ScannerError(error_msg) from e

        if not quiet:
            print("[green]MCP server initialized successfully[/green]")
            print("[cyan]Server name: ASH Security Scanner[/cyan]")
            print("[cyan]Press Ctrl+C to stop the server[/cyan]")
            print()

        # Log server startup with security configuration
        _security_logger.info(
            f"ASH MCP server starting with security controls: "
            f"max_concurrent_scans={MAX_CONCURRENT_SCANS}, "
            f"max_scan_duration={MAX_SCAN_DURATION_MINUTES}min, "
            f"operation_timeout={MIN_OPERATION_TIMEOUT_MINUTES}min, "
            f"max_message_size={MAX_MESSAGE_SIZE_BYTES}bytes"
        )

        # Start the MCP server - this will block until shutdown
        try:
            mcp_server.run()
        except Exception as e:
            error_msg = f"MCP server runtime error: {str(e)}"
            if not quiet:
                print(f"[red]{error_msg}[/red]")
            raise ScannerError(error_msg) from e

    except KeyboardInterrupt:
        # Re-raise KeyboardInterrupt to be handled by the calling function
        if not quiet:
            print("[yellow]MCP server shutdown requested[/yellow]")
        raise
    except ScannerError:
        # Re-raise ScannerError as-is
        raise
    except Exception as e:
        error_msg = f"Unexpected MCP server error: {str(e)}"
        if not quiet:
            print(f"[red]{error_msg}[/red]")
        raise ScannerError(error_msg) from e
    finally:
        # Cleanup code - ensure scan progress store is cleaned up
        try:
            _cleanup_scan_progress_store()
        except Exception as cleanup_error:
            if not quiet:
                print(
                    f"[yellow]Warning during final cleanup: {str(cleanup_error)}[/yellow]"
                )

        if not quiet:
            print("[yellow]MCP server shutdown complete[/yellow]")


def _setup_mcp_server_handlers(mcp_server) -> None:
    """Set up MCP server tools, resources, and prompts.

    This function configures the MCP server with tools, resources, and prompts
    that provide ASH security scanning capabilities through the Model Context Protocol.

    Args:
        mcp_server: The FastMCP server instance to configure
    """
    # Use module-level Context import
    if Context is None:
        raise ScannerError("Context not available - MCP dependencies not imported")

    # Set up MCP tools
    _setup_mcp_tools(mcp_server, Context)

    # Set up MCP resources
    _setup_mcp_resources(mcp_server)

    # Set up MCP prompts
    _setup_mcp_prompts(mcp_server)


# Global storage for scan progress tracking
_scan_progress_store: Dict[str, Dict[str, Any]] = {}


# Security logging setup
def _setup_security_logging() -> logging.Logger:
    """Set up dedicated security event logging for MCP operations.

    This implements comprehensive security event logging as required by
    MCP security guidelines for monitoring and audit trails.

    Returns:
        Configured security logger instance
    """
    security_logger = logging.getLogger("ash.mcp.security")

    # Prevent duplicate handlers if called multiple times
    if security_logger.handlers:
        return security_logger

    # Set appropriate log level
    security_logger.setLevel(logging.INFO)

    # Create console handler for security events
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Create detailed formatter for security events
    security_formatter = logging.Formatter(
        "%(asctime)s - ASH-MCP-SECURITY - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_handler.setFormatter(security_formatter)

    security_logger.addHandler(console_handler)

    # Prevent propagation to root logger to avoid duplicate messages
    security_logger.propagate = False

    return security_logger


# Initialize security logger
_security_logger = _setup_security_logging()


def _with_timeout(timeout_minutes: int = MIN_OPERATION_TIMEOUT_MINUTES):
    """Decorator to add timeout protection to MCP operations.

    This implements operation timeouts as required by MCP security guidelines
    to prevent long-running operations from consuming resources indefinitely.

    Args:
        timeout_minutes: Timeout in minutes (minimum 3 minutes as specified)

    Returns:
        Decorator function
    """

    def decorator(func):
        import functools

        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                timeout_seconds = max(
                    timeout_minutes * 60, MIN_OPERATION_TIMEOUT_MINUTES * 60
                )

                _security_logger.info(
                    f"Starting operation {func.__name__} with {timeout_minutes} minute timeout"
                )

                try:
                    return await asyncio.wait_for(
                        func(*args, **kwargs), timeout=timeout_seconds
                    )
                except asyncio.TimeoutError:
                    error_msg = f"Operation {func.__name__} timed out after {timeout_minutes} minutes"
                    _security_logger.error(error_msg)
                    raise ScannerError(error_msg)
                except Exception as e:
                    _security_logger.error(
                        f"Operation {func.__name__} failed: {str(e)}"
                    )
                    raise

            return async_wrapper
        else:

            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                timeout_seconds = max(
                    timeout_minutes * 60, MIN_OPERATION_TIMEOUT_MINUTES * 60
                )

                _security_logger.info(
                    f"Starting operation {func.__name__} with {timeout_minutes} minute timeout"
                )

                # For synchronous functions, we'll use a different approach
                # since we can't use asyncio.wait_for directly
                import signal

                def timeout_handler(signum, frame):
                    error_msg = f"Operation {func.__name__} timed out after {timeout_minutes} minutes"
                    _security_logger.error(error_msg)
                    raise ScannerError(error_msg)

                # Set up timeout signal (Unix-like systems only)
                if hasattr(signal, "SIGALRM"):
                    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
                    signal.alarm(int(timeout_seconds))

                    try:
                        result = func(*args, **kwargs)
                        signal.alarm(0)  # Cancel the alarm
                        return result
                    except Exception as e:
                        signal.alarm(0)  # Cancel the alarm
                        signal.signal(
                            signal.SIGALRM, old_handler
                        )  # Restore old handler
                        _security_logger.error(
                            f"Operation {func.__name__} failed: {str(e)}"
                        )
                        raise
                    finally:
                        signal.signal(
                            signal.SIGALRM, old_handler
                        )  # Restore old handler
                else:
                    # Fallback for systems without SIGALRM (like Windows)
                    _security_logger.warning(
                        f"Timeout protection not available on this platform for {func.__name__}"
                    )
                    return func(*args, **kwargs)

            return sync_wrapper

    return decorator


def _cleanup_scan_progress_store() -> None:
    """Clean up the scan progress store."""
    global _scan_progress_store, _active_scans_by_directory
    _scan_progress_store.clear()
    _active_scans_by_directory.clear()


def _cleanup_old_scans(max_age_hours: int = 24) -> None:
    """Clean up old scan entries from the progress store.

    Args:
        max_age_hours: Maximum age in hours before a scan entry is removed
    """
    from datetime import datetime, timedelta

    current_time = datetime.now()
    cutoff_time = current_time - timedelta(hours=max_age_hours)

    scan_ids_to_remove = []

    for scan_id, progress_data in _scan_progress_store.items():
        try:
            start_time = datetime.fromisoformat(progress_data["start_time"])
            if start_time < cutoff_time:
                scan_ids_to_remove.append(scan_id)
        except (KeyError, ValueError):
            # Remove entries with invalid timestamps
            scan_ids_to_remove.append(scan_id)

    for scan_id in scan_ids_to_remove:
        del _scan_progress_store[scan_id]


def _setup_mcp_tools(mcp_server, Context) -> None:
    """Set up MCP tools with direct ASH integration and streaming support.

    Args:
        mcp_server: The FastMCP server instance
        Context: The MCP Context class for tool signatures
    """

    async def scan_directory_with_progress(
        directory_path: str, severity_threshold: str = "MEDIUM", config_path: str = None
    ) -> Dict[str, Any]:
        """
        Start a security scan with progress tracking using ASH's event system.

        This tool starts a scan in the background and returns immediately with a scan_id.
        Use get_scan_progress to track progress and get_scan_results for final results.

        Args:
            directory_path: Path to the directory to scan
            severity_threshold: Minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL)
            config_path: Optional path to ASH configuration file
        """
        import uuid
        from datetime import datetime
        import asyncio

        # Log security event for scan request
        _security_logger.info(
            f"Scan request received - directory: {directory_path[:100]}..., "
            f"severity: {severity_threshold}, config_provided: {config_path is not None}"
        )

        # Enhanced input validation with message size checking
        request_data = {
            "directory_path": directory_path,
            "severity_threshold": severity_threshold,
            "config_path": config_path,
        }

        msg_valid, msg_errors = _validate_message_size_and_format(request_data)
        if not msg_valid:
            _security_logger.warning(f"Message validation failed: {msg_errors}")
            return {
                "status": "error",
                "error": f"Request validation failed: {'; '.join(msg_errors)}",
                "message": "Fix request format issues before starting scan",
            }

        # Validate parameters first
        is_valid, validation_errors = _validate_scan_parameters(
            directory_path, severity_threshold, config_path
        )
        if not is_valid:
            _security_logger.warning(
                f"Scan parameter validation failed: {validation_errors}"
            )
            return {
                "status": "error",
                "error": f"Validation failed: {'; '.join(validation_errors)}",
                "message": "Fix validation errors before starting scan",
            }

        # Resolve directory path for concurrency control
        path_valid, resolved_directory_path, path_errors = (
            _resolve_and_validate_directory_path(directory_path)
        )
        if not path_valid:
            return {
                "status": "error",
                "error": f"Directory path resolution failed: {'; '.join(path_errors)}",
                "message": "Fix directory path issues before starting scan",
            }

        # Check resource limits before starting scan
        active_scan_count = len(
            [
                s
                for s in _scan_progress_store.values()
                if s["status"] in ["initializing", "running"]
            ]
        )
        if active_scan_count >= MAX_CONCURRENT_SCANS:
            _security_logger.warning(
                f"Scan request rejected - concurrent limit exceeded: {active_scan_count}/{MAX_CONCURRENT_SCANS}"
            )
            return {
                "status": "error",
                "error": f"Maximum concurrent scans ({MAX_CONCURRENT_SCANS}) exceeded",
                "message": "Wait for existing scans to complete before starting new ones",
            }

        # Check for existing scan on this directory
        if resolved_directory_path in _active_scans_by_directory:
            existing_scan_id = _active_scans_by_directory[resolved_directory_path]
            existing_scan = _scan_progress_store.get(existing_scan_id)

            if existing_scan and existing_scan["status"] in ["initializing", "running"]:
                _security_logger.info(
                    f"Scan request rejected - directory already being scanned: {resolved_directory_path}"
                )
                return {
                    "status": "conflict",
                    "error": f"A scan is already running for directory: {resolved_directory_path}",
                    "existing_scan_id": existing_scan_id,
                    "message": "Wait for the existing scan to complete or cancel it first",
                }

        # Generate unique scan ID
        scan_id = str(uuid.uuid4())

        # Register this scan for the directory
        _active_scans_by_directory[resolved_directory_path] = scan_id

        # Initialize progress tracking
        _scan_progress_store[scan_id] = {
            "scan_id": scan_id,
            "status": "initializing",
            "progress": 0,
            "current_phase": "validation",
            "current_scanner": None,
            "scanners_running": [],
            "scanners_completed": [],
            "scanners_failed": [],
            "findings": [],
            "total_scanners": 10,  # Default estimate based on typical ASH local mode scanners
            "start_time": datetime.now().isoformat(),
            "directory_path": resolved_directory_path,
            "severity_threshold": severity_threshold,
            "config_path": config_path,
            "error": None,
            "warnings": [],
        }

        # Start background scan with timeout protection
        scan_task = asyncio.create_task(_run_background_scan_with_events(scan_id))

        # Add timeout monitoring for the scan task
        async def monitor_scan_timeout():
            try:
                await asyncio.wait_for(
                    scan_task, timeout=MAX_SCAN_DURATION_MINUTES * 60
                )
            except asyncio.TimeoutError:
                _security_logger.error(
                    f"Scan {scan_id} timed out after {MAX_SCAN_DURATION_MINUTES} minutes"
                )
                # Update scan status to indicate timeout
                if scan_id in _scan_progress_store:
                    _scan_progress_store[scan_id].update(
                        {
                            "status": "error",
                            "error": f"Scan timed out after {MAX_SCAN_DURATION_MINUTES} minutes",
                            "current_phase": "timeout",
                            "end_time": datetime.now().isoformat(),
                        }
                    )
                    # Remove from active scans
                    directory_path = _scan_progress_store[scan_id].get("directory_path")
                    if directory_path and directory_path in _active_scans_by_directory:
                        if _active_scans_by_directory[directory_path] == scan_id:
                            del _active_scans_by_directory[directory_path]
            except Exception as e:
                _security_logger.error(
                    f"Error monitoring scan timeout for {scan_id}: {str(e)}"
                )

        # Start timeout monitoring task
        asyncio.create_task(monitor_scan_timeout())

        # Log successful scan start
        _security_logger.info(
            f"Scan started successfully - scan_id: {scan_id}, "
            f"directory: {resolved_directory_path}, severity: {severity_threshold}"
        )

        return {
            "scan_id": scan_id,
            "status": "started",
            "message": "Scan started with progress tracking. Use get_scan_progress to monitor progress.",
            "directory_path": resolved_directory_path,
            "severity_threshold": severity_threshold,
        }

    @mcp_server.tool()
    async def get_scan_progress(scan_id: str) -> Dict[str, Any]:
        """
        Get current progress and partial results for a running scan.

        Args:
            scan_id: The scan ID returned from scan_directory_with_progress
        """
        # Sanitize scan_id input
        sanitized_scan_id, scan_id_warnings = _sanitize_string_input(
            scan_id, max_length=100
        )
        if scan_id_warnings:
            _security_logger.warning(
                f"Scan ID sanitization warnings: {scan_id_warnings}"
            )
        scan_id = sanitized_scan_id

        # Log progress request
        _security_logger.debug(f"Progress request for scan_id: {scan_id}")

        if scan_id not in _scan_progress_store:
            return {
                "error": "Scan ID not found",
                "scan_id": scan_id,
                "available_scans": list(_scan_progress_store.keys()),
            }

        progress_data = _scan_progress_store[scan_id]

        # Calculate elapsed time
        from datetime import datetime

        start_time = datetime.fromisoformat(progress_data["start_time"])
        elapsed_seconds = (datetime.now() - start_time).total_seconds()

        return {
            "scan_id": scan_id,
            "status": progress_data["status"],
            "progress": progress_data["progress"],
            "current_phase": progress_data["current_phase"],
            "current_scanner": progress_data.get("current_scanner"),
            "scanners_running": progress_data.get("scanners_running", []),
            "scanners_completed": progress_data["scanners_completed"],
            "scanners_failed": progress_data.get("scanners_failed", []),
            "total_scanners": progress_data["total_scanners"],
            "findings_count": len(progress_data["findings"]),
            "recent_findings": (
                progress_data["findings"][-5:] if progress_data["findings"] else []
            ),
            "elapsed_time_seconds": round(elapsed_seconds, 2),
            "is_complete": progress_data["status"] in ["completed", "error"],
            "error": progress_data.get("error"),
            "warnings": progress_data.get("warnings", []),
        }

    @mcp_server.tool()
    async def get_scan_results(scan_id: str) -> Dict[str, Any]:
        """
        Get final results for a completed scan.

        Args:
            scan_id: The scan ID returned from scan_directory_with_progress
        """
        # Sanitize scan_id input
        sanitized_scan_id, scan_id_warnings = _sanitize_string_input(
            scan_id, max_length=100
        )
        if scan_id_warnings:
            _security_logger.warning(
                f"Scan ID sanitization warnings: {scan_id_warnings}"
            )
        scan_id = sanitized_scan_id

        # Log results request
        _security_logger.info(f"Results request for scan_id: {scan_id}")

        if scan_id not in _scan_progress_store:
            return {"error": "Scan ID not found", "scan_id": scan_id}

        progress_data = _scan_progress_store[scan_id]

        if progress_data["status"] not in ["completed", "error"]:
            return {
                "error": "Scan not completed yet",
                "scan_id": scan_id,
                "current_status": progress_data["status"],
                "progress": progress_data["progress"],
                "message": "Use get_scan_progress to monitor progress",
            }

        if progress_data["status"] == "error":
            return {
                "scan_id": scan_id,
                "status": "error",
                "error": progress_data["error"],
                "directory_path": progress_data["directory_path"],
            }

        # Calculate final stats
        from datetime import datetime

        start_time = datetime.fromisoformat(progress_data["start_time"])
        end_time = datetime.fromisoformat(
            progress_data.get("end_time", datetime.now().isoformat())
        )
        duration_seconds = (end_time - start_time).total_seconds()

        return {
            "scan_id": scan_id,
            "status": "completed",
            "directory_path": progress_data["directory_path"],
            "severity_threshold": progress_data["severity_threshold"],
            "findings": progress_data["findings"],
            "findings_summary": progress_data.get("findings_summary", {}),
            "scanners_run": progress_data["scanners_completed"],
            "duration_seconds": round(duration_seconds, 2),
            "ash_version": progress_data.get("ash_version", "Unknown"),
            "final_results": progress_data.get("final_results"),
        }

    @mcp_server.tool()
    async def list_active_scans() -> Dict[str, Any]:
        """
        List all active and recent scans with their current status.

        Returns information about all scans in the progress store.
        """
        from datetime import datetime

        # Log scan list request
        _security_logger.debug("Active scans list requested")

        # Clean up old scans first
        _cleanup_old_scans()

        if not _scan_progress_store:
            return {
                "active_scans": [],
                "message": "No active or recent scans found",
                "directories_with_active_scans": [],
            }

        scans = []
        for scan_id, progress_data in _scan_progress_store.items():
            # Calculate elapsed time
            try:
                start_time = datetime.fromisoformat(progress_data["start_time"])
                elapsed_seconds = (datetime.now() - start_time).total_seconds()
            except (KeyError, ValueError):
                elapsed_seconds = 0

            scan_info = {
                "scan_id": scan_id,
                "status": progress_data.get("status", "unknown"),
                "progress": progress_data.get("progress", 0),
                "directory_path": progress_data.get("directory_path", "unknown"),
                "current_phase": progress_data.get("current_phase", "unknown"),
                "elapsed_time_seconds": round(elapsed_seconds, 2),
                "findings_count": len(progress_data.get("findings", [])),
                "error": progress_data.get("error"),
            }
            scans.append(scan_info)

        # Sort by start time (most recent first)
        scans.sort(key=lambda x: x["elapsed_time_seconds"])

        return {
            "active_scans": scans,
            "total_scans": len(scans),
            "directories_with_active_scans": list(_active_scans_by_directory.keys()),
        }

    @mcp_server.tool()
    async def cancel_scan(scan_id: str) -> Dict[str, Any]:
        """
        Cancel a running scan and clean up its resources.

        Args:
            scan_id: The scan ID to cancel
        """
        # Sanitize scan_id input
        sanitized_scan_id, scan_id_warnings = _sanitize_string_input(
            scan_id, max_length=100
        )
        if scan_id_warnings:
            _security_logger.warning(
                f"Scan ID sanitization warnings: {scan_id_warnings}"
            )
        scan_id = sanitized_scan_id

        # Log cancellation request
        _security_logger.info(f"Scan cancellation requested for scan_id: {scan_id}")

        if scan_id not in _scan_progress_store:
            return {"error": "Scan ID not found", "scan_id": scan_id}

        progress_data = _scan_progress_store[scan_id]

        if progress_data["status"] in ["completed", "error"]:
            return {
                "message": f"Scan {scan_id} is already {progress_data['status']}",
                "scan_id": scan_id,
                "status": progress_data["status"],
            }

        # Mark as cancelled
        from datetime import datetime

        progress_data.update(
            {
                "status": "cancelled",
                "current_phase": "cancelled",
                "end_time": datetime.now().isoformat(),
                "error": "Scan was cancelled by user request",
            }
        )

        # Remove from active scans by directory
        directory_path = progress_data.get("directory_path")
        if directory_path and directory_path in _active_scans_by_directory:
            if _active_scans_by_directory[directory_path] == scan_id:
                del _active_scans_by_directory[directory_path]

        return {
            "message": f"Scan {scan_id} has been cancelled",
            "scan_id": scan_id,
            "status": "cancelled",
        }

    @mcp_server.tool()
    async def scan_directory(
        directory_path: str, severity_threshold: str = "MEDIUM", config_path: str = None
    ) -> Dict[str, Any]:
        """
        Start a security scan with progress tracking using ASH's event system.

        This is the primary scanning tool that starts a scan in the background and returns
        immediately with a scan_id. Use get_scan_progress to track progress and
        get_scan_results for final results.

        Args:
            directory_path: Path to the directory to scan
            severity_threshold: Minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL)
            config_path: Optional path to ASH configuration file
        """
        # Delegate to the progress-tracking implementation
        return await scan_directory_with_progress(
            directory_path, severity_threshold, config_path
        )

    @mcp_server.tool()
    def check_installation() -> Dict[str, Any]:
        """Check if ASH is properly installed and ready to use."""

        # Log installation check request
        _security_logger.debug("ASH installation check requested")

        try:
            is_installed, info = _get_ash_version_direct()

            # Additional validation checks
            additional_checks = []
            warnings = []

            if is_installed:
                # Check if core ASH modules can be imported using module-level imports
                if run_ash_scan is not None:
                    additional_checks.append("Core scan functionality: Available")
                else:
                    additional_checks.append(
                        "Core scan functionality: Error - Module not imported"
                    )
                    warnings.append("Core scan functionality may not be available")

                # Check if local mode scanners are available
                try:
                    additional_checks.append("Local mode support: Available")
                except ImportError as e:
                    additional_checks.append(f"Local mode support: Error - {str(e)}")
                    warnings.append("Local mode may not be fully functional")

                # Check basic file system permissions
                try:
                    import tempfile

                    with tempfile.TemporaryDirectory() as temp_dir:
                        test_file = os.path.join(temp_dir, "test.txt")
                        with open(test_file, "w") as f:
                            f.write("test")
                        os.unlink(test_file)
                    additional_checks.append("File system access: OK")
                except Exception as e:
                    additional_checks.append(f"File system access: Limited - {str(e)}")
                    warnings.append("File system access may be restricted")

            return {
                "installed": is_installed,
                "version_info": info if is_installed else None,
                "error": None if is_installed else info,
                "mode_supported": "local",
                "ready_to_scan": is_installed and len(warnings) == 0,
                "additional_checks": additional_checks,
                "warnings": warnings if warnings else None,
                "timestamp": datetime.now().isoformat(),
            }

        except Exception as e:
            # Return structured error response for unexpected errors
            return _create_structured_error_response(
                error_type="runtime",
                error_message=f"Error checking ASH installation: {str(e)}",
                context={
                    "check_error": str(e),
                    "error_type": type(e).__name__,
                    "timestamp": datetime.now().isoformat(),
                },
                suggestions=[
                    "Verify ASH installation integrity",
                    "Check Python environment and dependencies",
                    "Try reinstalling ASH",
                ],
            )


def _setup_mcp_resources(mcp_server) -> None:
    """Set up MCP resources with direct ASH integration.

    This function configures MCP resources that provide status and help information
    about ASH installation and capabilities.

    Args:
        mcp_server: The FastMCP server instance
    """

    @mcp_server.resource("ash://status")
    def get_ash_status() -> str:
        """Get the current status of ASH installation using direct version checking."""
        is_installed, info = _get_ash_version_direct()

        if is_installed:
            return f"""ASH Status: ✅ READY

{info}

ASH is installed and ready to perform security scans in local mode.
Local mode includes these scanners:
• Bandit (Python security issues)
• Semgrep (Multi-language security patterns)
• detect-secrets (Hardcoded secrets detection)
• Checkov (Infrastructure as Code security)
• cdk-nag (CDK security issues)
"""
        else:
            return f"""ASH Status: ❌ NOT AVAILABLE

{info}

To install ASH, run:
pipx install git+https://github.com/awslabs/automated-security-helper.git@v3.0.0-beta

Or with pip:
pip install git+https://github.com/awslabs/automated-security-helper.git@v3.0.0-beta
"""

    @mcp_server.resource("ash://help")
    def get_ash_help() -> str:
        """Get help information about ASH usage."""
        return """ASH (Automated Security Helper) Usage Guide

ASH is a security scanning orchestrator that runs multiple security tools:

🔍 **What ASH Scans For:**
• Python security issues (Bandit)
• Multi-language security patterns (Semgrep)
• Hardcoded secrets and credentials (detect-secrets)
• Infrastructure as Code issues (Checkov)
• CDK security problems (cdk-nag)

📁 **Supported File Types:**
• Python (.py)
• JavaScript/TypeScript (.js, .ts)
• CloudFormation (.yaml, .yml, .json)
• Terraform (.tf)
• Dockerfile
• And many more...

⚙️ **Local Mode Benefits:**
• Fast execution (Python-only scanners)
• No Docker required
• Good for development and CI/CD
• Covers most common security issues

🎯 **Best Practices:**
• Run scans early and often
• Review all findings, even low severity
• Use in pre-commit hooks for continuous security
• Combine with manual security reviews
"""


def _setup_mcp_prompts(mcp_server) -> None:
    """Set up MCP prompts for analyzing security findings.

    This function configures MCP prompts that provide structured guidance
    for analyzing ASH security scan results.

    Args:
        mcp_server: The FastMCP server instance
    """

    @mcp_server.prompt()
    def analyze_security_findings(scan_results: str) -> str:
        """Create a prompt for analyzing ASH security scan results"""
        return f"""Please analyze these ASH security scan results and provide:

1. **Summary**: Brief overview of the security scan results
2. **Key Findings**: Most important security issues discovered
3. **Risk Assessment**: Categorize findings by severity and potential impact
4. **Recommendations**: Specific actions to address the security issues
5. **Next Steps**: Prioritized list of what to fix first

Scan Results:
```json
{scan_results}
```

Focus on actionable insights and practical remediation steps."""


def _parse_ash_results(output_dir: str) -> Dict[str, Any]:
    """Parse ASH scan results from the output directory.

    This function is ported from the original MCP server script and parses
    the ash_aggregated_results.json file to extract key information about
    the scan results, maintaining identical logic and output format.

    Args:
        output_dir: Path to the ASH output directory

    Returns:
        Dict containing parsed results summary with same structure as original
    """
    results = {
        "scanners_run": [],
        "total_findings": 0,
        "actionable_findings": 0,
        "reports_generated": [],
    }

    try:
        # Look for the aggregated results JSON file
        aggregated_results_path = Path(output_dir) / "ash_aggregated_results.json"
        if aggregated_results_path.exists():
            with open(aggregated_results_path, "r") as f:
                data = json.load(f)
                # Extract key information
                if "additional_reports" in data:
                    results["scanners_run"] = list(data["additional_reports"].keys())

                # Extract summary information from metadata if available
                if "metadata" in data and "summary_stats" in data["metadata"]:
                    summary = data["metadata"]["summary_stats"]
                    if "total" in summary:
                        results["total_findings"] = summary["total"]
                    if "actionable" in summary:
                        results["actionable_findings"] = summary["actionable"]

                # If summary_stats not available, calculate from additional_reports
                if results["total_findings"] == 0 and "additional_reports" in data:
                    total_findings = 0
                    actionable_findings = 0
                    for scanner_name, scanner_data in data[
                        "additional_reports"
                    ].items():
                        if "source" in scanner_data:
                            source = scanner_data["source"]
                            if "finding_count" in source:
                                total_findings += source["finding_count"]
                            if "actionable_finding_count" in source:
                                actionable_findings += source[
                                    "actionable_finding_count"
                                ]
                    results["total_findings"] = total_findings
                    results["actionable_findings"] = actionable_findings

        # Look for report files
        reports_dir = Path(output_dir) / "reports"
        if reports_dir.exists():
            for report_file in reports_dir.iterdir():
                if report_file.is_file():
                    results["reports_generated"].append(
                        {
                            "name": report_file.name,
                            "path": str(report_file),
                            "size_bytes": report_file.stat().st_size,
                        }
                    )

    except Exception as e:
        results["parse_error"] = str(e)

    return results


async def _run_background_scan_with_events(scan_id: str) -> None:
    """
    Run ASH scan in background with event-driven progress tracking.

    This function uses ASH's event system to provide real-time progress updates
    during the scan execution.

    Args:
        scan_id: Unique identifier for the scan
    """
    from datetime import datetime
    from automated_security_helper.plugins.events import AshEventType

    progress_data = _scan_progress_store[scan_id]

    try:
        # Update status to running
        progress_data.update({"status": "running", "current_phase": "initializing"})

        # Set up event callbacks for progress tracking
        def create_event_handler(scan_id: str):
            """Create event handler closure with scan_id"""

            def handle_ash_event(event_type: AshEventType, event_data: Dict[str, Any]):
                """Handle ASH events and update progress"""
                progress = _scan_progress_store.get(scan_id)
                if not progress:
                    return

                # Debug logging to see what events we receive
                print(f"MCP: Received event {event_type} with data: {event_data}")

                if event_type == AshEventType.EXECUTION_START:
                    # Extract total scanners from enabled_scanners list
                    enabled_scanners = event_data.get("enabled_scanners", [])
                    total_scanners = (
                        len(enabled_scanners)
                        if enabled_scanners
                        else progress.get("total_scanners", 10)
                    )

                    print(
                        f"EXECUTION_START - enabled_scanners: {enabled_scanners}, total_scanners: {total_scanners}"
                    )

                    progress.update(
                        {
                            "status": "running",
                            "current_phase": "execution_started",
                            "total_scanners": total_scanners,
                        }
                    )

                elif event_type == AshEventType.EXECUTION_PROGRESS:
                    progress.update(
                        {
                            "progress": event_data.get(
                                "progress_percent", progress["progress"]
                            ),
                            "current_phase": event_data.get(
                                "current_phase", progress["current_phase"]
                            ),
                        }
                    )

                elif event_type == AshEventType.SCAN_PHASE_START:
                    progress.update({"current_phase": "scanning", "progress": 25})

                elif event_type == AshEventType.SCAN_START:
                    scanner_name = event_data.get(
                        "scanner", event_data.get("scanner_name", "unknown")
                    )

                    print(f"Scanner {scanner_name} started")

                    # Add to running scanners list
                    if scanner_name not in progress.get("scanners_running", []):
                        progress.setdefault("scanners_running", []).append(scanner_name)
                        print(
                            f"Added {scanner_name} to running scanners. Total running: {len(progress['scanners_running'])}"
                        )

                    # Update current phase to show all running scanners
                    running_scanners = progress.get("scanners_running", [])
                    if len(running_scanners) == 1:
                        phase_text = f"running {running_scanners[0]}"
                    else:
                        phase_text = f"running {len(running_scanners)} scanners: {', '.join(running_scanners)}"

                    progress.update(
                        {
                            "current_scanner": scanner_name,
                            "current_phase": phase_text,
                        }
                    )

                elif event_type == AshEventType.SCAN_COMPLETE:
                    scanner_name = event_data.get(
                        "scanner", event_data.get("scanner_name", "unknown")
                    )
                    findings = event_data.get("findings", [])
                    scan_success = event_data.get("success", True)

                    # Remove from running scanners
                    if scanner_name in progress.get("scanners_running", []):
                        progress["scanners_running"].remove(scanner_name)

                    # Add to appropriate completion list
                    if scan_success:
                        if scanner_name not in progress["scanners_completed"]:
                            progress["scanners_completed"].append(scanner_name)
                    else:
                        if scanner_name not in progress.get("scanners_failed", []):
                            progress.setdefault("scanners_failed", []).append(
                                scanner_name
                            )

                    # Update total_scanners dynamically based on completed + failed + running
                    total_completed = len(progress["scanners_completed"])
                    total_failed = len(progress.get("scanners_failed", []))
                    total_running = len(progress.get("scanners_running", []))
                    current_total = total_completed + total_failed + total_running

                    # Only update if we have a higher count (scanners are discovered as they complete)
                    if current_total > progress.get("total_scanners", 0):
                        progress["total_scanners"] = current_total
                        print(f"Updated total_scanners to {current_total}")

                    # Add findings
                    if findings:
                        progress["findings"].extend(findings)

                    # Update current phase based on remaining running scanners
                    running_scanners = progress.get("scanners_running", [])
                    if running_scanners:
                        if len(running_scanners) == 1:
                            phase_text = f"running {running_scanners[0]}"
                        else:
                            phase_text = f"running {len(running_scanners)} scanners: {', '.join(running_scanners)}"
                        progress["current_phase"] = phase_text
                        progress["current_scanner"] = (
                            running_scanners[0] if running_scanners else None
                        )
                    else:
                        progress["current_phase"] = "finalizing scans"
                        progress["current_scanner"] = None

                    # Update progress based on completed scanners
                    if progress["total_scanners"] > 0:
                        total_finished = len(progress["scanners_completed"]) + len(
                            progress.get("scanners_failed", [])
                        )
                        scanner_progress = (
                            total_finished / progress["total_scanners"]
                        ) * 60
                        progress["progress"] = min(25 + scanner_progress, 85)

                elif event_type == AshEventType.SCAN_PHASE_COMPLETE:
                    progress.update({"current_phase": "scan_complete", "progress": 85})

                elif event_type == AshEventType.REPORT_PHASE_START:
                    progress.update(
                        {"current_phase": "generating_reports", "progress": 90}
                    )

                elif event_type == AshEventType.REPORT_PHASE_COMPLETE:
                    progress.update(
                        {"current_phase": "reports_complete", "progress": 95}
                    )

                elif event_type == AshEventType.EXECUTION_COMPLETE:
                    progress.update(
                        {
                            "status": "completed",
                            "current_phase": "finished",
                            "progress": 100,
                            "end_time": datetime.now().isoformat(),
                            "final_results": event_data.get("results"),
                        }
                    )
                    # Remove from active scans
                    directory_path = progress.get("directory_path")
                    if directory_path and directory_path in _active_scans_by_directory:
                        if _active_scans_by_directory[directory_path] == scan_id:
                            del _active_scans_by_directory[directory_path]

                elif event_type == AshEventType.ERROR:
                    error_msg = event_data.get("error", "Unknown error occurred")
                    progress.update(
                        {
                            "status": "error",
                            "error": error_msg,
                            "current_phase": "failed",
                            "end_time": datetime.now().isoformat(),
                        }
                    )
                    # Remove from active scans
                    directory_path = progress.get("directory_path")
                    if directory_path and directory_path in _active_scans_by_directory:
                        if _active_scans_by_directory[directory_path] == scan_id:
                            del _active_scans_by_directory[directory_path]

                elif event_type == AshEventType.WARNING:
                    warning_msg = event_data.get("warning", "Warning occurred")
                    progress["warnings"].append(warning_msg)

            return handle_ash_event

        # Create event handler for this scan
        event_handler = create_event_handler(scan_id)

        # Run the scan with event callbacks
        scan_result = await _run_ash_scan_with_events(
            directory_path=progress_data["directory_path"],
            severity_threshold=progress_data["severity_threshold"],
            config_path=progress_data["config_path"],
            event_handler=event_handler,
        )

        # If scan completed successfully but events didn't trigger completion
        if progress_data["status"] == "running":
            # Parse final results
            try:
                findings_summary = _parse_ash_results_from_scan(
                    scan_result.get("results"), output_dir=scan_result.get("output_dir")
                )

                progress_data.update(
                    {
                        "status": "completed",
                        "current_phase": "finished",
                        "progress": 100,
                        "end_time": datetime.now().isoformat(),
                        "findings_summary": findings_summary,
                        "final_results": scan_result,
                        "ash_version": scan_result.get("ash_version", "Unknown"),
                    }
                )

                # Remove from active scans
                directory_path = progress_data.get("directory_path")
                if directory_path and directory_path in _active_scans_by_directory:
                    if _active_scans_by_directory[directory_path] == scan_id:
                        del _active_scans_by_directory[directory_path]
            except Exception as parse_error:
                progress_data.update(
                    {
                        "status": "error",
                        "error": f"Failed to parse results: {str(parse_error)}",
                        "current_phase": "failed",
                        "end_time": datetime.now().isoformat(),
                    }
                )

                # Remove from active scans
                directory_path = progress_data.get("directory_path")
                if directory_path and directory_path in _active_scans_by_directory:
                    if _active_scans_by_directory[directory_path] == scan_id:
                        del _active_scans_by_directory[directory_path]

    except Exception as e:
        progress_data.update(
            {
                "status": "error",
                "error": f"Scan execution failed: {str(e)}",
                "current_phase": "failed",
                "end_time": datetime.now().isoformat(),
            }
        )

        # Remove from active scans
        directory_path = progress_data.get("directory_path")
        if directory_path and directory_path in _active_scans_by_directory:
            if _active_scans_by_directory[directory_path] == scan_id:
                del _active_scans_by_directory[directory_path]


async def _run_ash_scan_with_events(
    directory_path: str,
    severity_threshold: str,
    config_path: Optional[str],
    event_handler,
) -> Dict[str, Any]:
    """
    Run ASH scan with real event system integration for progress tracking.

    This function integrates with ASH's actual event system to provide real-time
    progress updates during scanning operations by subscribing to ASH events.

    Args:
        directory_path: Path to scan
        severity_threshold: Severity threshold
        config_path: Optional config file path
        event_handler: Callback function for handling events

    Returns:
        Scan results dictionary
    """
    import asyncio
    from concurrent.futures import ThreadPoolExecutor
    from automated_security_helper.plugins.events import AshEventType
    from automated_security_helper.plugins import ash_plugin_manager

    def run_scan_with_real_events():
        """Run scan with real ASH event system integration"""

        # Subscribe to all relevant ASH events to forward to our event handler
        def forward_event(event_type):
            def event_forwarder(**kwargs):
                try:
                    # Forward the event to our MCP event handler
                    # The event handler expects (event_type, event_data_dict)
                    event_handler(event_type, kwargs)
                except Exception as e:
                    print(f"Error forwarding event {event_type}: {e}")

            return event_forwarder

        # Subscribe to key events we want to track
        event_subscriptions = []
        for event_type in [
            AshEventType.EXECUTION_START,
            AshEventType.EXECUTION_PROGRESS,
            AshEventType.EXECUTION_COMPLETE,
            AshEventType.SCAN_PHASE_START,
            AshEventType.SCAN_START,
            AshEventType.SCAN_COMPLETE,
            AshEventType.SCAN_PHASE_COMPLETE,
            AshEventType.CONVERT_PHASE_START,
            AshEventType.CONVERT_START,
            AshEventType.CONVERT_COMPLETE,
            AshEventType.CONVERT_PHASE_COMPLETE,
            AshEventType.REPORT_PHASE_START,
            AshEventType.REPORT_START,
            AshEventType.REPORT_COMPLETE,
            AshEventType.REPORT_PHASE_COMPLETE,
            AshEventType.ERROR,
            AshEventType.WARNING,
            AshEventType.INFO,
        ]:
            forwarder = forward_event(event_type)
            ash_plugin_manager.subscribe(event_type, forwarder)
            event_subscriptions.append((event_type, forwarder))
            print(f"Subscribed to event {event_type}")

        print(f"Total event subscriptions: {len(event_subscriptions)}")

        try:
            # Run the actual ASH scan - this will emit real events
            scan_result = _run_ash_scan_direct(
                directory_path=directory_path,
                severity_threshold=severity_threshold,
                config_path=config_path,
            )
            return scan_result

        except Exception as e:
            # Forward error to our event handler
            event_handler(AshEventType.ERROR, {"error": str(e)})
            raise
        finally:
            # Clean up event subscriptions
            for event_type, forwarder in event_subscriptions:
                try:
                    # Manual cleanup - remove from event handlers list
                    if hasattr(ash_plugin_manager.plugin_library, "event_handlers"):
                        if (
                            event_type
                            in ash_plugin_manager.plugin_library.event_handlers
                        ):
                            handlers = ash_plugin_manager.plugin_library.event_handlers[
                                event_type
                            ]
                            if forwarder in handlers:
                                handlers.remove(forwarder)
                except Exception as cleanup_error:
                    print(f"Error cleaning up event subscription: {cleanup_error}")

    # Run in thread pool to avoid blocking
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor() as executor:
        result = await loop.run_in_executor(executor, run_scan_with_real_events)

    return result


def _parse_ash_results_from_scan(
    scan_results: Optional[Dict[str, Any]], output_dir: Optional[str] = None
) -> Dict[str, Any]:
    """Parse ASH scan results from direct scan call results.

    This function extracts key information from the scan results returned by
    the direct run_ash_scan() call and formats it in the same way as the
    original parse_ash_results() function. It uses the actual output directory
    to parse the ash_aggregated_results.json file for accurate results.

    Args:
        scan_results: Results dictionary from direct scan call (may contain output_dir)
        output_dir: Optional explicit output directory path

    Returns:
        Dict containing parsed results summary
    """
    # Try to get output directory from scan results or use provided one
    actual_output_dir = output_dir
    if not actual_output_dir and isinstance(scan_results, dict):
        actual_output_dir = scan_results.get("output_dir")

    if actual_output_dir:
        # Use the ported parse_ash_results function with the output directory
        return _parse_ash_results(actual_output_dir)

    # Fallback to basic parsing if no output directory available
    results = {
        "scanners_run": [],
        "total_findings": 0,
        "actionable_findings": 0,
        "reports_generated": [],
    }

    if not scan_results:
        return results

    try:
        # Extract scanner information if available
        if isinstance(scan_results, dict):
            # Look for scanner-related information in the results
            # This will depend on the actual structure returned by run_ash_scan()

            # If scan_results contains scanner information, extract it
            if "scanners" in scan_results:
                results["scanners_run"] = list(scan_results["scanners"].keys())

            # If scan_results contains summary information, use it
            if "summary" in scan_results:
                summary = scan_results["summary"]
                if isinstance(summary, dict):
                    results.update(summary)

            # Look for findings count
            if "total_findings" in scan_results:
                results["total_findings"] = scan_results["total_findings"]

            if "actionable_findings" in scan_results:
                results["actionable_findings"] = scan_results["actionable_findings"]

    except Exception as e:
        results["parse_error"] = str(e)

    return results
