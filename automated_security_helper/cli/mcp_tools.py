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
    MCScanStatus,
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

    # Mark the scan as running
    registry.update_scan_status(scan_id, MCScanStatus.RUNNING)

    # Log the scan start
    _logger.info(
        f"Starting scan process for scan {scan_id} in directory {directory_path}"
    )

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
        registry.update_scan_status(scan_id, MCScanStatus.COMPLETED)
        _logger.info(f"Scan {scan_id} completed successfully")

    except Exception as e:
        error_message = f"Error executing scan: {str(e)}"
        registry.update_scan_status(scan_id, MCScanStatus.FAILED, error_message)
        _logger.error(f"Scan {scan_id} failed: {error_message}")


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

        # We already have the version from get_ash_version()
        ash_command_available = True
        ash_command_output = f"ASH version {version}"

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


_SEVERITY_RATIONALE: Dict[str, str] = {
    "CRITICAL": "CRITICAL severity — above any threshold",
    "HIGH": "HIGH severity — above MEDIUM threshold",
    "MEDIUM": "MEDIUM severity — above LOW threshold",
    "LOW": "LOW severity — below MEDIUM threshold",
    "INFO": "INFO severity — below default threshold",
}


def _load_flat_vulns_for_explain(results_path: Optional[str]) -> list:
    """Load FlatVulnerability list from an ash_aggregated_results.json directory."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    if results_path is None:
        output_dir = Path.cwd() / ".ash" / "ash_output"
    else:
        candidate = Path(results_path)
        output_dir = candidate if candidate.is_dir() else candidate.parent

    agg_file = output_dir / "ash_aggregated_results.json"
    if not agg_file.exists():
        raise FileNotFoundError(f"Results file not found: {agg_file}")
    model = AshAggregatedResults.from_json(agg_file.read_text())
    return model.to_flat_vulnerabilities()


def mcp_explain_finding(
    finding_id: str,
    results_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Return structured details for a single finding by ID.

    Purely a structured lookup — no LLM calls are made.

    Args:
        finding_id: The FlatVulnerability.id to look up.
        results_path: Optional path to the output directory (or file inside it)
                      containing ash_aggregated_results.json. Defaults to
                      <cwd>/.ash/ash_output.

    Returns:
        Dict with ``success`` and ``finding`` keys on success, or
        ``success: False`` with an ``error`` key when the ID is not found.
    """
    import json as _json

    try:
        flat_vulns = _load_flat_vulns_for_explain(results_path)
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to load scan results: {e}",
            "operation": "explain_finding",
        }

    match = next((v for v in flat_vulns if v.id == finding_id), None)
    if match is None:
        return {
            "success": False,
            "error": f"Finding '{finding_id}' not found in scan results",
            "operation": "explain_finding",
        }

    if match.references:
        try:
            references: list = _json.loads(match.references)
        except Exception:
            references = [match.references]
    else:
        references = []

    if match.raw_data:
        try:
            scanner_metadata: dict = _json.loads(match.raw_data)
        except Exception:
            scanner_metadata = {"raw": match.raw_data}
    else:
        scanner_metadata = {}

    severity_upper = (match.severity or "").upper()
    severity_rationale = _SEVERITY_RATIONALE.get(
        severity_upper, f"{severity_upper} severity"
    )

    return {
        "success": True,
        "operation": "explain_finding",
        "finding": {
            "title": match.title,
            "description": match.description,
            "severity": match.severity,
            "severity_rationale": severity_rationale,
            "cwe_id": match.cwe_id,
            "cve_id": match.cve_id,
            "references": references,
            "scanner": match.scanner,
            "scanner_metadata": scanner_metadata,
        },
    }


def mcp_diff_scan_results(before_path: str, after_path: str) -> Dict[str, Any]:
    """Compare two ash_aggregated_results.json files and return a structured diff.

    Args:
        before_path: Path to the baseline ash_aggregated_results.json file.
        after_path: Path to the comparison ash_aggregated_results.json file.

    Returns:
        Dict with keys:
          - new: List[dict] — findings present in after but not in before.
          - resolved: List[dict] — findings present in before but not in after.
          - severity_changed: List[dict] — findings in both with a different severity,
            each entry has {id, before_severity, after_severity}.
        On error, returns {"success": False, "error": <message>}.
    """
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    before_file = Path(before_path)
    after_file = Path(after_path)

    if not before_file.exists():
        return {
            "success": False,
            "error": f"before_path does not exist: {before_path}",
        }
    if not after_file.exists():
        return {
            "success": False,
            "error": f"after_path does not exist: {after_path}",
        }

    try:
        before_results = AshAggregatedResults.from_json(before_file.read_text())
        after_results = AshAggregatedResults.from_json(after_file.read_text())
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to parse result file: {e}",
        }

    before_vulns = before_results.to_flat_vulnerabilities()
    after_vulns = after_results.to_flat_vulnerabilities()

    before_by_id: Dict[str, Any] = {v.id: v for v in before_vulns}
    after_by_id: Dict[str, Any] = {v.id: v for v in after_vulns}

    before_ids = set(before_by_id)
    after_ids = set(after_by_id)

    new = [after_by_id[i].model_dump() for i in sorted(after_ids - before_ids)]
    resolved = [before_by_id[i].model_dump() for i in sorted(before_ids - after_ids)]

    severity_changed = []
    for vid in sorted(before_ids & after_ids):
        b_sev = (before_by_id[vid].severity or "").upper()
        a_sev = (after_by_id[vid].severity or "").upper()
        if b_sev != a_sev:
            severity_changed.append(
                {"id": vid, "before_severity": b_sev or None, "after_severity": a_sev or None}
            )

    return {"new": new, "resolved": resolved, "severity_changed": severity_changed}


def mcp_list_scanners() -> list:
    """Return per-scanner metadata for all registered ASH scanners.

    Each entry contains:
      name: scanner config name (e.g. "bandit")
      version: detected version string, or None if unavailable without an active context
      dependencies_satisfied: whether the scanner's dependencies are met
      offline_strategy: OfflineStrategy enum value string
      enabled: whether the scanner is enabled in the default config
    """
    from automated_security_helper.plugins import ash_plugin_manager
    from automated_security_helper.plugins.loader import load_internal_plugins, load_additional_plugin_modules
    from automated_security_helper.config.default_config import get_default_config

    load_internal_plugins()

    # Discover external plugin modules via importlib.metadata: any installed package
    # whose top-level name matches the ash plugin namespace pattern is imported so its
    # @ash_scanner_plugin decorators fire and register the scanner into ash_plugin_manager.
    import importlib as _importlib
    try:
        from importlib.metadata import packages_distributions
        _pkg_dist = packages_distributions()
    except Exception:
        _pkg_dist = {}

    _external_mods: list[str] = []
    for _top_level, _dists in _pkg_dist.items():
        if any(
            d.startswith("ash_") and d.endswith("_plugins")
            for d in _dists
        ):
            _external_mods.append(f"automated_security_helper.plugin_modules.{_top_level}")

    if _external_mods:
        load_additional_plugin_modules(_external_mods)
    else:
        # Fallback: import well-known external plugin modules directly so their decorators fire.
        # TODO: replace with entry-points once external packages declare 'ash.plugins' group.
        for _mod in (
            "automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner",
            "automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner",
            "automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner",
        ):
            try:
                _importlib.import_module(_mod)
            except ImportError:
                pass

    scanner_classes = ash_plugin_manager.plugin_modules("scanner")
    default_config = get_default_config()

    results = []
    for cls in scanner_classes:
        offline_strategy = getattr(cls, "offline_strategy", None)
        offline_strategy_value = offline_strategy.value if offline_strategy is not None else "unknown"

        scanner_name: Optional[str] = None
        scanner_enabled: bool = True

        # Derive the concrete config class from Pydantic model_fields.
        # The 'config' field annotation is Union[ConcreteConfig, ScannerPluginConfigBase, None].
        # The first arg of that Union is always the scanner-specific config.
        config_class = None
        config_field = getattr(cls, "model_fields", {}).get("config")
        if config_field is not None:
            annotation = getattr(config_field, "annotation", None)
            type_args = getattr(annotation, "__args__", None)
            if type_args:
                for arg in type_args:
                    if isinstance(arg, type) and arg.__name__.endswith("ScannerConfig") and arg.__name__ != "ScannerPluginConfigBase":
                        config_class = arg
                        break

        if config_class is not None:
            try:
                cfg_instance = config_class()
                raw_name = getattr(cfg_instance, "name", None)
                # Normalize kebab-case config names to snake_case
                scanner_name = raw_name.replace("-", "_") if raw_name else None
                scanner_enabled_default = getattr(cfg_instance, "enabled", True)

                if scanner_name:
                    found_cfg = default_config.get_plugin_config("scanner", scanner_name)
                    if found_cfg is not None:
                        scanner_enabled = (
                            found_cfg.get("enabled", scanner_enabled_default)
                            if isinstance(found_cfg, dict)
                            else getattr(found_cfg, "enabled", scanner_enabled_default)
                        )
                    else:
                        scanner_enabled = scanner_enabled_default
                else:
                    scanner_enabled = scanner_enabled_default
            except Exception:
                scanner_enabled = True

        if not scanner_name:
            import re as _re
            # Convert PascalCase class name to snake_case, strip trailing "Scanner"
            raw = cls.__name__
            raw = _re.sub(r"Scanner$", "", raw)
            scanner_name = _re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", raw).lower()

        results.append({
            "name": scanner_name,
            "version": None,
            "dependencies_satisfied": False,
            "offline_strategy": offline_strategy_value,
            "enabled": scanner_enabled,
        })

    return results


def mcp_get_config(
    config_path: Optional[str] = None,
    raw: bool = False,
    search_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Return the resolved ASH config (or raw file contents if raw=True).

    Args:
        config_path: Explicit path to config file. If None, auto-discovers.
        raw: If True, returns the user file contents without merging defaults.
        search_dir: Directory to search for config file when config_path is None.
                    Defaults to cwd.

    Returns:
        Dict representation of the resolved AshConfig, or raw YAML dict if raw=True.
    """
    import yaml as _yaml
    from automated_security_helper.config.resolve_config import (
        resolve_config,
        find_config_file,
    )
    from automated_security_helper.config.default_config import get_default_config

    if config_path is not None:
        path: Optional[Path] = Path(config_path)
        if not path.exists():
            return get_default_config().model_dump()
    else:
        search = Path(search_dir) if search_dir else None
        path = find_config_file(search_dir=search)

    if path is None:
        return get_default_config().model_dump()

    if raw:
        return _yaml.safe_load(path.read_text()) or {}

    # resolve_config short-circuits to default when source_dir is None,
    # so supply source_dir to force it to read the specified file.
    resolved = resolve_config(config_path=path, source_dir=path.parent)
    return resolved.model_dump()


def mcp_validate_config(
    config_content: Optional[str] = None,
    config_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Validate an ASH config supplied as a content string or file path.

    Args:
        config_content: YAML/JSON string to validate. Mutually exclusive with config_path.
        config_path: Path to the config file to validate.

    Returns:
        Dict with keys:
          - valid: bool
          - errors: List[{field: str, message: str, type: str}]
    """
    import re
    import tempfile

    from automated_security_helper.config.config_validator import ConfigValidator

    def _classify(raw: str) -> Dict[str, Any]:
        if "YAML parsing error" in raw or "yaml" in raw.lower():
            return {"field": "", "message": raw, "type": "yaml_parse_error"}
        if "JSON parsing error" in raw:
            return {"field": "", "message": raw, "type": "json_parse_error"}
        if "Missing required" in raw:
            m = re.search(r"'([^']+)'", raw)
            field = m.group(1) if m else ""
            return {"field": field, "message": raw, "type": "missing_required_field"}
        if "internal-only field" in raw or "internal field" in raw:
            m = re.search(r"field '([^']+)'", raw)
            field = m.group(1) if m else ""
            return {"field": field, "message": raw, "type": "internal_field"}
        if "Unknown" in raw or "unknown" in raw:
            m = re.search(r"'([^']+)'", raw)
            field = m.group(1) if m else ""
            return {"field": field, "message": raw, "type": "unknown_field"}
        if "Invalid" in raw or "invalid" in raw:
            m = re.search(r"'([^']+)'", raw)
            field = m.group(1) if m else ""
            return {"field": field, "message": raw, "type": "invalid_field"}
        if "Duplicate" in raw:
            m = re.search(r"'([^']+)'", raw)
            field = m.group(1) if m else ""
            return {"field": field, "message": raw, "type": "duplicate_field"}
        return {"field": "", "message": raw, "type": "validation_error"}

    if config_content is not None:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as tmp:
            tmp.write(config_content)
            tmp_path = Path(tmp.name)
        try:
            valid, raw_errors = ConfigValidator.validate_config_file(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)
    elif config_path is not None:
        path = Path(config_path)
        if not path.exists():
            return {
                "valid": False,
                "errors": [
                    {
                        "field": "config_path",
                        "message": f"Config file not found: {config_path}",
                        "type": "file_not_found",
                    }
                ],
            }
        valid, raw_errors = ConfigValidator.validate_config_file(path)
    else:
        return {
            "valid": False,
            "errors": [
                {
                    "field": "",
                    "message": "Either config_content or config_path must be provided.",
                    "type": "missing_input",
                }
            ],
        }

    return {
        "valid": valid,
        "errors": [_classify(e) for e in raw_errors],
    }


def mcp_suggest_suppression(
    finding_id: str,
    results_path: Optional[str] = None,
    expiration: Optional[str] = None,
    justification: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a paste-ready AshSuppression entry for a specific finding.

    Args:
        finding_id: Stable hash ID of the finding to suppress.
        results_path: Path to ash_aggregated_results.json. Defaults to
                      .ash/ash_output/ash_aggregated_results.json in cwd.
        expiration: Expiration date in YYYY-MM-DD format. Defaults to 90 days from today.
        justification: Human-readable reason for the suppression.

    Returns:
        Dict with keys:
          - success: bool
          - yaml: str — paste-ready YAML block
          - json: dict — same data as a dict
        On error: {"success": False, "error": <message>}
    """
    import yaml as _yaml
    from datetime import date, timedelta
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.models.core import AshSuppression

    if results_path is None:
        results_file = Path.cwd() / ".ash" / "ash_output" / "ash_aggregated_results.json"
    else:
        results_file = Path(results_path)

    if not results_file.exists():
        return {
            "success": False,
            "error": f"Results file not found: {results_file}",
        }

    try:
        results = AshAggregatedResults.from_json(results_file.read_text())
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to parse results file: {e}",
        }

    flat_vulns = results.to_flat_vulnerabilities()
    finding = next((v for v in flat_vulns if v.id == finding_id), None)

    if finding is None:
        return {
            "success": False,
            "error": f"Finding not found: {finding_id}",
        }

    expiration_date = expiration or (date.today() + timedelta(days=90)).strftime("%Y-%m-%d")
    reason = justification or "Suppressed via ASH MCP suggest_suppression tool — review before merging"

    suppression = AshSuppression(
        path=finding.file_path or "",
        rule_id=finding.rule_id,
        line_start=finding.line_start,
        line_end=finding.line_end,
        expiration=expiration_date,
        reason=reason,
    )

    suppression_dict = suppression.model_dump(exclude_none=True)
    suppression_yaml = _yaml.safe_dump(suppression_dict, default_flow_style=False, sort_keys=True)

    return {
        "success": True,
        "yaml": suppression_yaml,
        "json": suppression_dict,
    }


# ---------------------------------------------------------------------------
# Source delivery (Track 10.2): git-ref clone + chunked zip upload.
# ---------------------------------------------------------------------------


def mcp_set_source_git(
    url: str,
    ref: Optional[str] = None,
    *,
    ssh_key_id: Optional[str] = None,
    depth: int = 1,
    session_id: str,
) -> Dict[str, Any]:
    """Clone ``url`` at ``ref`` into the per-session workspace.

    Args:
        url: Remote URL to clone (https or ssh).
        ref: Optional branch/tag/commit. ``None`` uses the remote default.
        ssh_key_id: Opaque, server-side keyring identifier. Raw private keys
            are not accepted over the wire.
        depth: Shallow-clone depth. Defaults to 1.
        session_id: MCP session identifier scoping the workspace.

    Returns:
        ``{"success": True, "source_dir": str}`` on success;
        ``{"success": False, "error": str}`` on git failure.
    """
    from automated_security_helper.cli.mcp.source_delivery import set_source_git

    try:
        source_dir = set_source_git(
            url=url,
            ref=ref,
            ssh_key_id=ssh_key_id,
            depth=depth,
            session_id=session_id,
        )
    except (RuntimeError, ValueError) as e:
        return {"success": False, "error": str(e)}

    return {"success": True, "source_dir": str(source_dir)}


def mcp_set_source_zip_chunk(
    upload_id: str,
    sequence: int,
    data_b64: str,
    last: bool,
    *,
    session_id: str,
) -> Dict[str, Any]:
    """Append one base64-encoded chunk to an in-flight zipped-source upload.

    Args:
        upload_id: Caller-chosen identifier for this single upload.
        sequence: Zero-based ordinal; chunks must arrive in order.
        data_b64: Base64-encoded chunk payload (≤ 1 MiB decoded).
        last: ``True`` on the final chunk.
        session_id: MCP session identifier scoping the upload.

    Returns:
        ``{"success": True, "received": int, "next_sequence": int, "last": bool}``
        on success; ``{"success": False, "error": str}`` on validation
        failure (out-of-order, oversize, malformed b64).
    """
    from automated_security_helper.cli.mcp.source_delivery import set_source_zip_chunk

    try:
        result = set_source_zip_chunk(
            upload_id=upload_id,
            sequence=sequence,
            data_b64=data_b64,
            last=last,
            session_id=session_id,
        )
    except ValueError as e:
        return {"success": False, "error": str(e)}

    return {"success": True, **result}


def mcp_set_source_zip_finalize(
    upload_id: str,
    expected_sha256: str,
    *,
    session_id: str,
) -> Dict[str, Any]:
    """Finalize a chunked upload: verify checksum and extract.

    Args:
        upload_id: Identifier matching the prior chunk calls.
        expected_sha256: Hex sha256 the assembled zip must match.
        session_id: MCP session identifier.

    Returns:
        ``{"success": True, "source_dir": str}`` on success;
        ``{"success": False, "error": str}`` on checksum mismatch,
        oversize zip, oversize extraction, too-many-files, or any
        path-traversal/symlink-out-of-tree entry.
    """
    from automated_security_helper.cli.mcp.source_delivery import (
        set_source_zip_finalize,
    )

    try:
        source_dir = set_source_zip_finalize(
            upload_id=upload_id,
            expected_sha256=expected_sha256,
            session_id=session_id,
        )
    except (FileNotFoundError, ValueError) as e:
        return {"success": False, "error": str(e)}

    return {"success": True, "source_dir": str(source_dir)}


def mcp_clear_source(session_id: str) -> Dict[str, Any]:
    """Wipe the session workspace and forget any recorded ``source_dir``.

    Idempotent: missing workspaces succeed.

    Args:
        session_id: MCP session identifier.

    Returns:
        ``{"success": True}``.
    """
    from automated_security_helper.cli.mcp.source_delivery import clear_source

    clear_source(session_id=session_id)
    return {"success": True}
