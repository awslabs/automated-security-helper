#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
MCP server implementation for ASH security scanning.

This module provides an MCP server implementation that strictly follows
the MCP protocol for ASH security scanning.
"""

import asyncio
import json
import os
from typing import Dict, Any, Optional
from pathlib import Path

# Import MCP dependencies directly
from mcp.server.fastmcp import FastMCP, Context

from automated_security_helper.cli.mcp_tools import (
    mcp_scan_directory,
    mcp_get_scan_progress,
    mcp_get_scan_results,
    mcp_list_active_scans,
    mcp_cancel_scan,
    mcp_check_installation,
)

from automated_security_helper.core.resource_management.scan_registry import (
    get_scan_registry,
)
from automated_security_helper.utils.log import ASH_LOGGER

# Configure module logger
logger = ASH_LOGGER

# Create the FastMCP server
mcp = FastMCP(name="ASH Security Scanner")


@mcp.tool()
async def run_ash_scan(
    ctx: Context,
    source_dir: str = str(Path.cwd().absolute()),
    severity_threshold: str = "MEDIUM",
    config_path: Optional[str] = None,
    clean_output: bool = True,
) -> Dict[str, Any]:
    """
    Start a security scan and return immediately.

    This tool starts a scan and returns immediately with a scan ID.
    Progress updates will be reported through the MCP context.

    CRITICAL - Connection Management:
    ASH scans take 30-120+ seconds. To prevent MCP connection timeout:
    - Poll get_scan_progress(scan_id) every 5 seconds (keeps connection alive)
    - Check progress['is_complete'] or progress['status'] for completion
    - DO NOT sleep for long periods without polling

    Example usage:
        result = run_ash_scan(source_dir="/path/to/project")
        scan_id = result['scan_id']

        # Poll progress to keep connection alive
        while True:
            progress = get_scan_progress(scan_id=scan_id)
            if progress.get('is_complete'):
                break
            time.sleep(5)  # Poll every 5 seconds

        # Get filtered results after completion
        results = get_scan_results(
            output_dir=progress['output_directory'],
            filter_level="summary",
            actionable_only=True
        )

    Args:
        source_dir: Path to the directory to scan. This should be the absolute path!
        severity_threshold: Minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL)
        config_path: Optional path to ASH configuration file
        clean_output: Whether to clean up existing output files before starting the scan

    Returns:
        Dict with scan_id, status, and connection management guidance
    """
    try:
        # Ensure source_dir is an absolute path
        await ctx.info(f"run_ash_scan tool called in cwd: {Path.cwd()}")
        if not Path(source_dir).is_absolute():
            source_dir = str(Path.cwd() / source_dir)

        # Log the scan request
        await ctx.info(f"Starting scan for directory: {source_dir}")

        # Set up paths for monitoring
        directory_path_obj = Path(source_dir)
        output_dir = directory_path_obj.joinpath(".ash", "ash_output")
        aggregated_results_path = output_dir.joinpath("ash_aggregated_results.json")

        # Clean up any existing result files before starting the scan
        if clean_output and aggregated_results_path.exists():
            await ctx.info("Cleaning up existing results file...")
            try:
                # Remove the aggregated results file if it exists
                os.remove(aggregated_results_path)
                await ctx.debug(
                    f"Removed existing results file: {aggregated_results_path}"
                )
            except Exception as e:
                await ctx.warning(f"Failed to clean up results file: {str(e)}")

        # Start the scan
        result = await mcp_scan_directory(
            directory_path=source_dir,
            severity_threshold=severity_threshold,
            config_path=config_path,
        )

        # Check if scan started successfully
        if not result.get("success", False) or "scan_id" not in result:
            await ctx.error(
                f"Failed to start scan: {result.get('error', 'Unknown error')}"
            )
            return {
                "success": False,
                "error": f"Failed to start scan: {result.get('error', 'Unknown error')}",
                "error_type": "scan_start_failure",
            }

        scan_id = result["scan_id"]
        await ctx.info(f"Scan started with ID: {scan_id}")

        # Initial progress update
        try:
            await ctx.report_progress(
                progress=0.0,
                total=1.0,
                message="Scan started, initializing scanners...",
            )
        except Exception as e:
            # Log but don't fail if progress reporting fails
            logger.warning(f"Failed to send initial progress update: {str(e)}")

        # Start background task to monitor progress
        asyncio.create_task(_monitor_scan_progress(ctx, scan_id))

        # Return initial status with connection management guidance
        return {
            "success": True,
            "status": "running",
            "scan_id": scan_id,
            "progress": 0.0,
            "message": "Scan started, initializing scanners. Use get_scan_progress to track progress.",
            "directory_path": str(directory_path_obj),
            "important": {
                "connection_management": (
                    "CRITICAL: ASH scans take 30-120+ seconds. To prevent MCP connection timeout, "
                    "poll get_scan_progress(scan_id) every 5 seconds instead of sleeping. "
                    "Example: while True: progress = get_scan_progress(scan_id); "
                    "if progress['is_complete']: break; time.sleep(5)"
                ),
                "next_steps": [
                    "1. Poll get_scan_progress(scan_id) every 5 seconds to keep connection alive",
                    "2. Check progress['is_complete'] or progress['status'] for completion",
                    "3. After completion, use get_scan_results() with filtering for efficient data transfer",
                ],
            },
        }

    except Exception as e:
        logger.exception(f"Error in run_ash_scan: {str(e)}")
        await ctx.error(f"Error running scan: {str(e)}")
        return {
            "success": False,
            "error": f"Error running scan: {str(e)}",
            "error_type": type(e).__name__,
        }


async def _monitor_scan_progress(ctx: Context, scan_id: str) -> None:
    """
    Monitor scan progress and report updates.

    This function monitors the scan progress by checking for result files in the output directory
    and reports progress updates through the MCP context.

    Args:
        ctx: MCP context
        scan_id: The scan ID to monitor
    """
    try:
        # Get scan information
        registry_info = await mcp_get_scan_progress(scan_id=scan_id)
        if not registry_info.get("success", False):
            await ctx.error(
                f"Failed to get scan info: {registry_info.get('error', 'Unknown error')}"
            )
            return

        # Get output directory path
        directory_path = registry_info.get("directory_path", "")
        if not directory_path:
            await ctx.error("Missing directory path in scan registry")
            return

        directory_path_obj = Path(directory_path)
        output_dir = directory_path_obj / ".ash" / "ash_output"
        ash_aggregated_results = output_dir / "ash_aggregated_results.json"

        # Track completed scanners to avoid duplicate progress updates
        completed_scanners = set()
        total_scanners_estimate = 5  # Initial estimate, will be updated
        last_progress_time = asyncio.get_event_loop().time()
        heartbeat_interval = 15  # Send a heartbeat every 15 seconds
        max_wait_time = 1800  # 30 minutes maximum wait time
        start_time = asyncio.get_event_loop().time()
        completed = False

        # Initial progress update
        try:
            await ctx.report_progress(
                progress=0.0,
                total=1.0,
                message="Scan started, initializing scanners...",
            )
        except Exception as e:
            # Log but continue monitoring even if initial update fails
            logger.warning(
                f"Failed to send initial progress update in monitor: {str(e)}"
            )

        # Monitor scan progress until completion
        while not completed:
            current_time = asyncio.get_event_loop().time()

            # Check for timeout
            if current_time - start_time > max_wait_time:
                await ctx.warning(
                    f"Scan monitoring timed out after {max_wait_time} seconds"
                )
                return

            # Check if scan has completed
            if ash_aggregated_results.exists():
                completed = True

                # Report final progress
                try:
                    await ctx.report_progress(
                        progress=1.0,
                        total=1.0,
                        message="Scan completed, parsing results...",
                    )
                except Exception as e:
                    logger.debug(f"Failed to send completion progress: {str(e)}")

                # Get final results with the correct output directory path
                final_results = await mcp_get_scan_results(output_dir=str(output_dir))

                # Add summary information
                if final_results.get("success", False):
                    findings_count = final_results.get("findings_count", 0)
                    severity_counts = final_results.get("severity_counts", {})

                    if findings_count > 0:
                        summary = f"Scan completed with {findings_count} findings: "
                        summary += ", ".join(
                            f"{count} {severity.lower()}"
                            for severity, count in severity_counts.items()
                            if count > 0
                        )
                    else:
                        summary = "Scan completed with no findings."

                    try:
                        await ctx.info(summary)
                    except Exception as e:
                        # Connection may be closed, log but don't fail
                        logger.warning(f"Failed to send completion summary: {str(e)}")

                return

            # Check registry for scan status
            progress_info = await mcp_get_scan_progress(scan_id=scan_id)
            if progress_info.get("status") in ["failed", "cancelled"]:
                completed = True

                # Report final status
                try:
                    await ctx.report_progress(
                        progress=1.0,
                        total=1.0,
                        message=f"Scan {progress_info.get('status')}",
                    )
                except Exception as e:
                    logger.debug(f"Failed to send final status progress: {str(e)}")

                # Log completion
                try:
                    if progress_info.get("status") == "failed":
                        await ctx.error(
                            f"Scan failed: {progress_info.get('error_message', 'Unknown error')}"
                        )
                    elif progress_info.get("status") == "cancelled":
                        await ctx.info("Scan was cancelled.")
                except Exception as e:
                    logger.warning(f"Failed to send completion message: {str(e)}")

                return

            # Check for individual scanner results
            scanner_results = list(output_dir.glob("scanners/**/ASH.ScanResults.json"))

            # Update total scanners estimate if we find more
            if len(scanner_results) > 0:
                # Get unique scanner directories
                scanner_dirs = set(path.parent.parent.name for path in scanner_results)
                total_scanners_estimate = max(
                    total_scanners_estimate, len(scanner_dirs) * 2
                )  # Multiply by 2 for source and converted

            # Process new scanner results
            progress_updated = False
            for result_path in scanner_results:
                scanner_name = result_path.parent.parent.name
                target_type = result_path.parent.name
                scanner_key = f"{scanner_name}/{target_type}"

                if scanner_key not in completed_scanners:
                    completed_scanners.add(scanner_key)
                    progress_updated = True

                    # Read the scanner results to get severity counts
                    try:
                        with open(result_path, "r") as f:
                            scanner_data = json.load(f)

                        severity_counts = scanner_data.get("severity_counts", {})
                        finding_count = sum(severity_counts.values())

                        if finding_count > 0:
                            findings_summary = ", ".join(
                                f"{count} {severity.lower()}"
                                for severity, count in severity_counts.items()
                                if count > 0
                            )
                            message = f"{scanner_name} completed {target_type} scan: {findings_summary}"
                        else:
                            message = f"{scanner_name} completed {target_type} scan: No issues found"

                        # Calculate progress
                        progress = len(completed_scanners) / total_scanners_estimate
                        progress = min(
                            progress, 0.95
                        )  # Cap at 95% until fully complete

                        # Update progress
                        try:
                            await ctx.report_progress(
                                progress=progress,
                                total=1.0,
                                message=message,
                            )
                            # Update last progress time only if send succeeded
                            last_progress_time = current_time
                        except Exception as e:
                            # Connection may be closed, log but continue monitoring
                            logger.debug(f"Failed to send progress update: {str(e)}")

                        try:
                            await ctx.debug(
                                f"Scanner progress: {scanner_name}/{target_type} - {int(progress * 100)}%"
                            )
                        except Exception as e:
                            # Ignore debug message failures (connection may be closed)
                            logger.debug(f"Failed to send debug message: {str(e)}")
                    except asyncio.CancelledError:
                        raise  # Re-raise cancellation
                    except Exception as e:
                        logger.warning(
                            f"Error processing scanner results for {scanner_name}/{target_type}: {str(e)}"
                        )
                        try:
                            await ctx.warning(
                                f"Error processing scanner results for {scanner_name}/{target_type}: {str(e)}"
                            )
                        except Exception as e:
                            # Ignore errors sending warning (connection may be closed)
                            logger.debug(f"Failed to send warning message: {str(e)}")

            # Send heartbeat if no progress updates for a while
            if (
                not progress_updated
                and (current_time - last_progress_time) >= heartbeat_interval
            ):
                progress = len(completed_scanners) / max(total_scanners_estimate, 1)
                progress = min(progress, 0.95)  # Cap at 95% until fully complete

                try:
                    # Report heartbeat progress
                    await ctx.report_progress(
                        progress=progress,
                        total=1.0,
                        message=f"Scan in progress ({len(completed_scanners)}/{total_scanners_estimate} scanners completed)",
                    )

                    # Update last progress time
                    last_progress_time = current_time
                except Exception as e:
                    # Connection may be closed, log but continue monitoring
                    logger.debug(f"Failed to send heartbeat: {str(e)}")

            # Wait before checking again - use adaptive polling interval
            # For 2-5 minute scans, use longer intervals to reduce network traffic
            if len(completed_scanners) == 0:
                # No scanners completed yet (initialization phase), poll every 5 seconds
                await asyncio.sleep(5)
            elif len(completed_scanners) < 2:
                # Few scanners completed (early phase), poll every 8 seconds
                await asyncio.sleep(8)
            else:
                # Multiple scanners running (main phase), poll every 10 seconds
                await asyncio.sleep(10)

    except asyncio.CancelledError:
        # Task was cancelled, log and exit gracefully
        logger.info(f"Scan monitoring cancelled for scan_id: {scan_id}")
        try:
            await ctx.info("Scan monitoring stopped.")
        except Exception as e:
            # Ignore errors when trying to send final message (connection may be closed)
            logger.debug(f"Failed to send cancellation message: {str(e)}")
    except Exception as e:
        logger.exception(f"Error monitoring scan progress: {str(e)}")
        try:
            await ctx.error(f"Error monitoring scan progress: {str(e)}")
        except Exception:
            # Ignore errors when trying to send error message (connection may be closed)
            logger.error(f"Failed to send error message to client: {str(e)}")


@mcp.tool()
async def get_scan_progress(ctx: Context, scan_id: str) -> Dict[str, Any]:
    """
    Get current progress and partial results for a running scan.

    IMPORTANT: Call this tool every 5 seconds in a loop to:
    - Keep the MCP connection alive during long-running scans (30-120+ seconds)
    - Get real-time status updates
    - Detect completion or failures immediately

    Usage pattern:
        while True:
            progress = get_scan_progress(scan_id=scan_id)
            if progress.get('is_complete') or progress.get('status') in ['completed', 'failed', 'cancelled']:
                break
            time.sleep(5)  # Wait 5 seconds before next check

    Args:
        scan_id: The scan ID returned from run_ash_scan

    Returns:
        Dict with progress info including:
        - is_complete: Boolean indicating if scan is done
        - status: Current status (running, completed, failed, cancelled)
        - progress_percentage: Estimated completion percentage
        - message: Human-readable status message
    """
    try:
        await ctx.info(f"Getting progress for scan: {scan_id}")

        # Get basic progress info
        progress_info = await mcp_get_scan_progress(scan_id=scan_id)

        if not progress_info.get("success", False):
            return progress_info

        # Get registry information
        registry = get_scan_registry()
        entry = registry.get_scan(scan_id)

        if not entry:
            await ctx.error(f"Scan {scan_id} not found in registry")
            return {
                "success": False,
                "error": f"Scan {scan_id} not found in registry",
                "error_type": "scan_not_found",
            }

        # Get output directory
        output_dir = Path(entry.output_directory)

        # Find scanner result files
        scanner_results = {}
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "suppressed": 0,
        }

        # Look for scanner result files
        scanners_dir = output_dir / "scanners"
        if scanners_dir.exists():
            for scanner_dir in scanners_dir.iterdir():
                if not scanner_dir.is_dir():
                    continue

                scanner_name = scanner_dir.name
                scanner_results[scanner_name] = {}

                for target_dir in scanner_dir.iterdir():
                    if not target_dir.is_dir():
                        continue

                    target_type = target_dir.name
                    result_file = target_dir / "ASH.ScanResults.json"

                    if result_file.exists():
                        try:
                            # Read the scanner results file
                            with open(result_file, "r") as f:
                                result_data = json.load(f)

                            # Store the raw results
                            scanner_results[scanner_name][target_type] = result_data

                            # Update severity counts
                            if "severity_counts" in result_data:
                                for severity, count in result_data[
                                    "severity_counts"
                                ].items():
                                    if severity in severity_counts:
                                        severity_counts[severity] += count
                        except Exception as e:
                            await ctx.warning(
                                f"Error reading result file {result_file}: {str(e)}"
                            )

        # Add scanner results and severity counts to progress info
        progress_info["scanners"] = scanner_results
        progress_info["severity_counts"] = severity_counts

        return progress_info
    except Exception as e:
        logger.exception(f"Error in get_scan_progress: {str(e)}")
        await ctx.error(f"Error getting scan progress: {str(e)}")
        return {
            "success": False,
            "error": f"Error getting scan progress: {str(e)}",
            "error_type": type(e).__name__,
        }


@mcp.tool()
async def get_scan_results(
    ctx: Context,
    output_dir: str = ".ash/ash_output",
    filter_level: str = "full",
    scanners: str = None,
    severities: str = None,
    actionable_only: bool = False,
) -> Dict[str, Any]:
    """
    Get final results for a completed scan with optional filtering.

    Args:
        output_dir: Path to the scan output directory (absolute path recommended)
        filter_level: Filter level for response data. Options:
                - "full" (default): Return all results including raw_results, validation_checkpoints, etc.
                - "summary": Return only summary data (metadata, findings counts, scanner summaries)
                - "minimal": Return only basic scan status and completion info
        scanners: Comma-separated list of scanner names to include (e.g., "bandit,semgrep").
                  If not specified, includes all scanners.
        severities: Comma-separated list of severity levels to include (e.g., "critical,high,medium").
                    Options: critical, high, medium, low, info, suppressed
                    If not specified, includes all severities.
        actionable_only: If True, exclude suppressed findings from results. This filters out findings
                        that have been marked as false positives or accepted risks. Default is False.
    """
    try:
        # Ensure output_dir is an absolute path
        if not Path(output_dir).is_absolute():
            output_dir = str(Path.cwd() / output_dir)

        filter_info = f"filter_level={filter_level}"
        if scanners:
            filter_info += f", scanners={scanners}"
        if severities:
            filter_info += f", severities={severities}"
        if actionable_only:
            filter_info += ", actionable_only=True"

        await ctx.info(
            f"Getting results from ASH scan in directory: {output_dir} ({filter_info})"
        )

        # Get the raw results
        results = await mcp_get_scan_results(output_dir=output_dir)

        # Check if there was an actual error (not just missing success key)
        if "error" in results or not results.get("success"):
            return results

        # Apply actionable_only filter first (exclude suppressed findings)
        if actionable_only:
            results = _filter_actionable_only(results)

        # Apply scanner and severity filters if specified
        if scanners or severities:
            results = _apply_content_filters(results, scanners, severities)

        # Apply response size filter based on parameter
        if filter_level == "full":
            # Return full results for backward compatibility
            return results
        elif filter_level == "summary":
            # Return summary data only (similar to get_scan_summary but from this tool)
            return _filter_summary(results)
        elif filter_level == "minimal":
            # Return only basic status info
            return _filter_minimal(results)
        else:
            # Unknown filter - return full results with warning
            await ctx.warning(
                f"Unknown filter_level '{filter_level}', returning full results"
            )
            return results

    except Exception as e:
        logger.exception(f"Error in get_scan_results: {str(e)}")
        try:
            await ctx.error(f"Error getting scan results: {str(e)}")
        except Exception:
            # Ignore errors sending error message (connection may be closed)
            logger.error(f"Failed to send error message to client: {str(e)}")
        return {
            "success": False,
            "error": f"Error getting scan results: {str(e)}",
            "error_type": type(e).__name__,
        }


def _filter_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    """Filter results to return only summary information."""
    summary = {
        "success": True,
        "scan_id": results.get("scan_id"),
        "status": results.get("status"),
        "is_complete": results.get("is_complete"),
        "completion_time": results.get("completion_time"),
        "metadata": {},
        "findings_summary": {},
        "scanner_summary": {},
        "_filter": "summary",
    }

    # Extract metadata from raw_results
    raw_results = results.get("raw_results", {})
    metadata = raw_results.get("metadata", {})

    summary["metadata"] = {
        "generated_at": metadata.get("generated_at"),
        "ash_version": metadata.get("tool_version"),
        "scan_duration_seconds": metadata.get("summary_stats", {}).get("duration"),
    }

    # Extract findings summary by severity from summary_stats
    summary_stats = results.get("summary_stats", {})
    summary["findings_summary"] = {
        "by_severity": {
            "critical": summary_stats.get("critical", 0),
            "high": summary_stats.get("high", 0),
            "medium": summary_stats.get("medium", 0),
            "low": summary_stats.get("low", 0),
            "info": summary_stats.get("info", 0),
            "suppressed": summary_stats.get("suppressed", 0),
            "total": summary_stats.get("total", 0),
            "actionable": summary_stats.get("actionable", 0),
        },
        "scan_stats": {
            "passed": summary_stats.get("passed", 0),
            "failed": summary_stats.get("failed", 0),
            "missing": summary_stats.get("missing", 0),
            "skipped": summary_stats.get("skipped", 0),
        },
    }

    # Extract scanner summary from scanner_results
    scanner_results = raw_results.get("scanner_results", {})
    summary["scanner_summary"] = {
        "by_scanner": {},
        "total_scanners": len(scanner_results),
        "completed_scanners": 0,
    }

    for scanner_name, scanner_data in scanner_results.items():
        status = scanner_data.get("status", "UNKNOWN")
        severity_counts = scanner_data.get("severity_counts", {})

        scanner_info = {
            "status": status,
            "findings_count": scanner_data.get("finding_count", 0),
            "actionable_findings": scanner_data.get("actionable_finding_count", 0),
            "suppressed_findings": scanner_data.get("suppressed_finding_count", 0),
            "duration": scanner_data.get("duration", 0),
            "by_severity": {
                "critical": severity_counts.get("critical", 0),
                "high": severity_counts.get("high", 0),
                "medium": severity_counts.get("medium", 0),
                "low": severity_counts.get("low", 0),
                "info": severity_counts.get("info", 0),
                "suppressed": severity_counts.get("suppressed", 0),
            },
        }

        summary["scanner_summary"]["by_scanner"][scanner_name] = scanner_info

        # Count completed scanners
        if status in ["PASSED", "FAILED"]:
            summary["scanner_summary"]["completed_scanners"] += 1

    return summary


def _filter_minimal(results: Dict[str, Any]) -> Dict[str, Any]:
    """Filter results to return only minimal status information."""
    return {
        "success": True,
        "scan_id": results.get("scan_id"),
        "status": results.get("status"),
        "is_complete": results.get("is_complete"),
        "completion_time": results.get("completion_time"),
        "summary_stats": results.get("summary_stats", {}),
        "_filter": "minimal",
    }


def _filter_actionable_only(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Filter results to exclude suppressed findings.

    This removes findings that have been marked as false positives or accepted risks,
    returning only actionable findings that require attention.

    Args:
        results: The full scan results

    Returns:
        Filtered results with suppressed findings excluded
    """
    import copy

    # Create a deep copy to avoid modifying the original
    filtered_results = copy.deepcopy(results)

    # Filter SARIF results if present
    if "raw_results" in filtered_results and "sarif" in filtered_results["raw_results"]:
        sarif = filtered_results["raw_results"]["sarif"]
        if "runs" in sarif:
            for run in sarif["runs"]:
                if "results" in run and run["results"]:
                    # Filter out suppressed findings
                    run["results"] = [
                        result
                        for result in run["results"]
                        if not (
                            result.get("suppressions")
                            and len(result.get("suppressions", [])) > 0
                        )
                    ]

    # Update summary stats to reflect only actionable findings
    if "summary_stats" in filtered_results:
        summary_stats = filtered_results["summary_stats"]
        # Set suppressed count to 0 since we're excluding them
        summary_stats["suppressed"] = 0
        # Total should equal actionable when suppressed are excluded
        summary_stats["total"] = summary_stats.get("actionable", 0)

    # Update scanner-level suppressed counts
    if (
        "raw_results" in filtered_results
        and "scanner_results" in filtered_results["raw_results"]
    ):
        for scanner_name, scanner_data in filtered_results["raw_results"][
            "scanner_results"
        ].items():
            if "suppressed_finding_count" in scanner_data:
                scanner_data["suppressed_finding_count"] = 0
            if (
                "severity_counts" in scanner_data
                and "suppressed" in scanner_data["severity_counts"]
            ):
                scanner_data["severity_counts"]["suppressed"] = 0

    # Add filter metadata
    if "_content_filters" not in filtered_results:
        filtered_results["_content_filters"] = {}
    filtered_results["_content_filters"]["actionable_only"] = True

    return filtered_results


def _apply_content_filters(
    results: Dict[str, Any], scanners: str = None, severities: str = None
) -> Dict[str, Any]:
    """
    Filter results by scanner names and/or severity levels.

    Args:
        results: The full scan results
        scanners: Comma-separated list of scanner names (e.g., "bandit,semgrep")
        severities: Comma-separated list of severity levels (e.g., "critical,high")

    Returns:
        Filtered results with only matching scanners and severities
    """
    import copy

    # Parse filter lists
    scanner_list = (
        [s.strip().lower() for s in scanners.split(",")] if scanners else None
    )
    severity_list = (
        [s.strip().lower() for s in severities.split(",")] if severities else None
    )

    # Create a deep copy to avoid modifying the original
    filtered_results = copy.deepcopy(results)

    # Filter scanner_reports
    if "scanner_reports" in filtered_results and scanner_list:
        filtered_scanner_reports = {}
        for scanner_name, scanner_data in filtered_results["scanner_reports"].items():
            if scanner_name.lower() in scanner_list:
                filtered_scanner_reports[scanner_name] = scanner_data
        filtered_results["scanner_reports"] = filtered_scanner_reports

    # Filter raw_results.scanner_results
    if (
        "raw_results" in filtered_results
        and "scanner_results" in filtered_results["raw_results"]
    ):
        if scanner_list:
            filtered_scanner_results = {}
            for scanner_name, scanner_data in filtered_results["raw_results"][
                "scanner_results"
            ].items():
                if scanner_name.lower() in scanner_list:
                    # If severity filter is specified, filter severity counts
                    if severity_list and "severity_counts" in scanner_data:
                        filtered_severity_counts = {
                            k: v
                            for k, v in scanner_data["severity_counts"].items()
                            if k.lower() in severity_list
                        }
                        scanner_data = scanner_data.copy()
                        scanner_data["severity_counts"] = filtered_severity_counts
                    filtered_scanner_results[scanner_name] = scanner_data
            filtered_results["raw_results"]["scanner_results"] = (
                filtered_scanner_results
            )
        elif severity_list:
            # Only severity filter, apply to all scanners
            filtered_scanner_results = {}
            for scanner_name, scanner_data in filtered_results["raw_results"][
                "scanner_results"
            ].items():
                if "severity_counts" in scanner_data:
                    filtered_severity_counts = {
                        k: v
                        for k, v in scanner_data["severity_counts"].items()
                        if k.lower() in severity_list
                    }
                    scanner_data = scanner_data.copy()
                    scanner_data["severity_counts"] = filtered_severity_counts
                filtered_scanner_results[scanner_name] = scanner_data
            filtered_results["raw_results"]["scanner_results"] = (
                filtered_scanner_results
            )

    # Filter additional_reports
    if (
        "raw_results" in filtered_results
        and "additional_reports" in filtered_results["raw_results"]
    ):
        if scanner_list:
            filtered_additional_reports = {}
            for scanner_name, scanner_data in filtered_results["raw_results"][
                "additional_reports"
            ].items():
                if scanner_name.lower() in scanner_list:
                    filtered_additional_reports[scanner_name] = scanner_data
            filtered_results["raw_results"]["additional_reports"] = (
                filtered_additional_reports
            )

    # Update summary_stats to reflect filtered data
    if severity_list and "summary_stats" in filtered_results:
        filtered_summary_stats = {}
        for key, value in filtered_results["summary_stats"].items():
            if key.lower() in severity_list or key not in [
                "critical",
                "high",
                "medium",
                "low",
                "info",
                "suppressed",
            ]:
                filtered_summary_stats[key] = value
            elif key.lower() not in severity_list and key in [
                "critical",
                "high",
                "medium",
                "low",
                "info",
                "suppressed",
            ]:
                filtered_summary_stats[key] = 0
        filtered_results["summary_stats"] = filtered_summary_stats

    # Add filter metadata
    filter_metadata = {}
    if scanner_list:
        filter_metadata["scanners"] = scanner_list
    if severity_list:
        filter_metadata["severities"] = severity_list
    filtered_results["_content_filters"] = filter_metadata

    return filtered_results


@mcp.tool()
async def get_scan_summary(
    ctx: Context, output_dir: str = ".ash/ash_output"
) -> Dict[str, Any]:
    """
    Get a lightweight summary of scan results without detailed findings.

    This tool returns only high-level metadata and statistics, making it ideal for
    quick status checks without transferring large amounts of data.

    Returns:
    - Scan metadata (timestamps, duration, etc.)
    - Findings count by severity
    - Findings count by scanner/tool
    - Scanner execution status
    - No detailed finding information

    Args:
        output_dir: Path to the scan output directory (absolute path recommended)
    """
    import sys

    print("=" * 80, file=sys.stderr)
    print("DEBUG: get_scan_summary FUNCTION CALLED!", file=sys.stderr)
    print("=" * 80, file=sys.stderr)

    try:
        # Ensure output_dir is an absolute path
        if not Path(output_dir).is_absolute():
            output_dir = str(Path.cwd() / output_dir)

        await ctx.info(f"[SUMMARY TOOL] Getting scan summary from: {output_dir}")
        await ctx.info("[SUMMARY TOOL] *** EXECUTING get_scan_summary FUNCTION ***")

        # Get the raw results
        results = await mcp_get_scan_results(output_dir=output_dir)

        # Check if there was an actual error (not just missing success key)
        if "error" in results or not results.get("success"):
            return results

        # Extract only summary information - no detailed findings
        summary = {
            "success": True,
            "scan_id": results.get("scan_id"),
            "status": results.get("status"),
            "is_complete": results.get("is_complete"),
            "completion_time": results.get("completion_time"),
            "metadata": {},
            "findings_summary": {},
            "scanner_summary": {},
        }

        # Extract metadata from raw_results
        raw_results = results.get("raw_results", {})
        metadata = raw_results.get("metadata", {})

        summary["metadata"] = {
            "generated_at": metadata.get("generated_at"),
            "ash_version": metadata.get("tool_version"),
            "scan_duration_seconds": metadata.get("summary_stats", {}).get("duration"),
        }

        # Extract findings summary by severity from summary_stats
        summary_stats = results.get("summary_stats", {})
        summary["findings_summary"] = {
            "by_severity": {
                "critical": summary_stats.get("critical", 0),
                "high": summary_stats.get("high", 0),
                "medium": summary_stats.get("medium", 0),
                "low": summary_stats.get("low", 0),
                "info": summary_stats.get("info", 0),
                "suppressed": summary_stats.get("suppressed", 0),
                "total": summary_stats.get("total", 0),
                "actionable": summary_stats.get("actionable", 0),
            },
            "scan_stats": {
                "passed": summary_stats.get("passed", 0),
                "failed": summary_stats.get("failed", 0),
                "missing": summary_stats.get("missing", 0),
                "skipped": summary_stats.get("skipped", 0),
            },
        }

        # Extract scanner summary from scanner_results
        scanner_results = raw_results.get("scanner_results", {})
        summary["scanner_summary"] = {
            "by_scanner": {},
            "total_scanners": len(scanner_results),
            "completed_scanners": 0,
        }

        for scanner_name, scanner_data in scanner_results.items():
            status = scanner_data.get("status", "UNKNOWN")
            severity_counts = scanner_data.get("severity_counts", {})

            scanner_info = {
                "status": status,
                "findings_count": scanner_data.get("finding_count", 0),
                "actionable_findings": scanner_data.get("actionable_finding_count", 0),
                "suppressed_findings": scanner_data.get("suppressed_finding_count", 0),
                "duration": scanner_data.get("duration", 0),
                "by_severity": {
                    "critical": severity_counts.get("critical", 0),
                    "high": severity_counts.get("high", 0),
                    "medium": severity_counts.get("medium", 0),
                    "low": severity_counts.get("low", 0),
                    "info": severity_counts.get("info", 0),
                    "suppressed": severity_counts.get("suppressed", 0),
                },
            }

            summary["scanner_summary"]["by_scanner"][scanner_name] = scanner_info

            # Count completed scanners
            if status in ["PASSED", "FAILED"]:
                summary["scanner_summary"]["completed_scanners"] += 1

        # Add a marker to confirm this is from get_scan_summary
        summary["_source_function"] = "get_scan_summary"
        summary["_note"] = "Lightweight summary - filtered response"
        summary["_debug"] = "If you see this, the function executed correctly!"

        await ctx.info(
            f"[SUMMARY TOOL] Returning summary with {len(summary)} top-level keys"
        )

        return summary

    except Exception as e:
        logger.exception(f"Error in get_scan_summary: {str(e)}")
        try:
            await ctx.error(f"Error getting scan summary: {str(e)}")
        except Exception:
            logger.error(f"Failed to send error message to client: {str(e)}")
        return {
            "success": False,
            "error": f"Error getting scan summary: {str(e)}",
            "error_type": type(e).__name__,
        }


@mcp.tool()
async def get_scan_result_paths(
    ctx: Context, output_dir: str = ".ash/ash_output"
) -> Dict[str, Any]:
    """
    Get file paths for all scan result files by type.

    This tool returns the absolute paths to various result files (SARIF, JSON, HTML, etc.)
    allowing the client to decide which files to read and how to process them.

    Returns paths for:
    - SARIF report
    - Flat JSON report
    - HTML report
    - CSV report
    - Markdown summary
    - OCSF report
    - CycloneDX SBOM
    - JUnit XML report
    - GitLab SAST report

    Args:
        output_dir: Path to the scan output directory (absolute path recommended)
    """
    try:
        # Ensure output_dir is an absolute path
        if not Path(output_dir).is_absolute():
            output_dir = str(Path.cwd() / output_dir)

        output_path = Path(output_dir)
        reports_dir = output_path / "reports"

        await ctx.info(f"Getting scan result paths from: {output_dir}")

        # Check if output directory exists
        if not output_path.exists():
            return {
                "success": False,
                "error": f"Output directory does not exist: {output_dir}",
                "error_type": "DirectoryNotFound",
            }

        # Check if reports directory exists
        if not reports_dir.exists():
            return {
                "success": False,
                "error": f"Reports directory does not exist: {reports_dir}",
                "error_type": "DirectoryNotFound",
            }

        # Define expected report files
        report_files = {
            "sarif": reports_dir / "ash.sarif",
            "flat_json": reports_dir / "ash.flat.json",
            "html": reports_dir / "ash.html",
            "csv": reports_dir / "ash.csv",
            "markdown": reports_dir / "ash.summary.md",
            "text": reports_dir / "ash.summary.txt",
            "ocsf": reports_dir / "ash.ocsf.json",
            "cyclonedx": reports_dir / "ash.cdx.json",
            "junit_xml": reports_dir / "ash.junit.xml",
            "gitlab_sast": reports_dir / "ash.gl-sast-report.json",
        }

        # Build response with file paths and existence status
        result = {
            "success": True,
            "output_dir": str(output_path),
            "reports_dir": str(reports_dir),
            "files": {},
        }

        for report_type, file_path in report_files.items():
            result["files"][report_type] = {
                "path": str(file_path),
                "exists": file_path.exists(),
                "size_bytes": file_path.stat().st_size if file_path.exists() else 0,
            }

        # Add aggregated results file
        aggregated_file = output_path / "ash_aggregated_results.json"
        result["files"]["aggregated_results"] = {
            "path": str(aggregated_file),
            "exists": aggregated_file.exists(),
            "size_bytes": aggregated_file.stat().st_size
            if aggregated_file.exists()
            else 0,
        }

        # Add scanner-specific results
        scanners_dir = output_path / "scanners"
        if scanners_dir.exists():
            result["scanners_dir"] = str(scanners_dir)
            result["scanner_results"] = {}

            for scanner_dir in scanners_dir.iterdir():
                if scanner_dir.is_dir():
                    scanner_name = scanner_dir.name
                    result["scanner_results"][scanner_name] = {}

                    for target_dir in scanner_dir.iterdir():
                        if target_dir.is_dir():
                            target_name = target_dir.name
                            result_file = target_dir / "ASH.ScanResults.json"

                            result["scanner_results"][scanner_name][target_name] = {
                                "path": str(result_file),
                                "exists": result_file.exists(),
                                "size_bytes": result_file.stat().st_size
                                if result_file.exists()
                                else 0,
                            }

        return result

    except Exception as e:
        logger.exception(f"Error in get_scan_result_paths: {str(e)}")
        try:
            await ctx.error(f"Error getting scan result paths: {str(e)}")
        except Exception:
            logger.error(f"Failed to send error message to client: {str(e)}")
        return {
            "success": False,
            "error": f"Error getting scan result paths: {str(e)}",
            "error_type": type(e).__name__,
        }


@mcp.tool()
async def list_active_scans(ctx: Context) -> Dict[str, Any]:
    """
    List all active and recent scans with their current status.
    """
    try:
        await ctx.info("Listing active scans")
        return await mcp_list_active_scans()
    except Exception as e:
        logger.exception(f"Error in list_active_scans: {str(e)}")
        await ctx.error(f"Error listing active scans: {str(e)}")
        return {
            "success": False,
            "error": f"Error listing active scans: {str(e)}",
            "error_type": type(e).__name__,
        }


@mcp.tool()
async def cancel_scan(ctx: Context, scan_id: str) -> Dict[str, Any]:
    """
    Cancel a running scan and clean up its resources.

    Args:
        scan_id: The scan ID to cancel
    """
    try:
        await ctx.info(f"Cancelling scan: {scan_id}")
        return await mcp_cancel_scan(scan_id=scan_id)
    except Exception as e:
        logger.exception(f"Error in cancel_scan: {str(e)}")
        await ctx.error(f"Error cancelling scan: {str(e)}")
        return {
            "success": False,
            "error": f"Error cancelling scan: {str(e)}",
            "error_type": type(e).__name__,
        }


@mcp.tool()
async def check_installation(ctx: Context) -> Dict[str, Any]:
    """
    Check if ASH is properly installed and ready to use.
    """
    try:
        await ctx.info("Checking ASH installation")
        return await mcp_check_installation()
    except Exception as e:
        logger.exception(f"Error in check_installation: {str(e)}")
        await ctx.error(f"Error checking installation: {str(e)}")
        return {
            "success": False,
            "error": f"Error checking installation: {str(e)}",
            "error_type": type(e).__name__,
        }


@mcp.resource("ash://status")
def get_ash_status() -> str:
    """Get the current status of ASH installation."""
    try:
        from automated_security_helper.utils.get_ash_version import get_ash_version

        version = get_ash_version()
        return f"""ASH Status: ✅ READY

ASH version {version}

ASH is installed and ready to perform security scans in local mode.
Local mode includes these scanners:
• Bandit (Python security issues)
• Semgrep (Multi-language security patterns)
• detect-secrets (Hardcoded secrets detection)
• Checkov (Infrastructure as Code security)
• cdk-nag (CDK security issues)
"""
    except Exception as e:
        logger.exception(f"Error getting ASH status: {str(e)}")
        return f"""ASH Status: ❌ ERROR

Error: {str(e)}

Please check your ASH installation.
"""


@mcp.resource("ash://help")
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


@mcp.prompt(
    title="Run ASH Security Scan",
    description="This prompt invokes an ASH security scan of the source directory, defaulting to the current one",
)
def run_ash_security_scan(source_dir: str = str(Path.cwd().absolute())) -> str:
    """Create a prompt for analyzing ASH security scan results"""
    return f"""Please run an ASH security scan of the following directory: {source_dir}

The scan should be done using the `run_ash_scan` MCP tool from the `ash` MCP Server.

Once the scan has started, an ID will be returned. Using that scan ID, call the
`get_scan_progress` MCP tool with the scan ID to monitor until completion.

Once the scan is complete and the results are captured via either the
`get_scan_progress` or `get_scan_results` MCP tools, the results should be parsed and
provided in an actionable summary."""


@mcp.prompt(
    title="Analyze ASH Security Findings",
    description="This prompt advises the agent to review an existing ASH scan and provide and overview and opinionated guidance",
)
def analyze_security_findings(source_dir: str = str(Path.cwd().absolute())) -> str:
    """Create a prompt for analyzing ASH security scan results"""
    return f"""Please analyze these ASH security scan results in the source_dir:
{source_dir} and provide:

1. **Summary**: Brief overview of the security scan results
2. **Key Findings**: Most important security issues discovered
3. **Risk Assessment**: Categorize findings by severity and potential impact
4. **Recommendations**: Specific actions to address the security issues
5. **Next Steps**: Prioritized list of what to fix first

Scan Result Locations:

1. SARIF - Contains raw aggregated vulnerability findings in SARIF format: .ash/ash_output/reports/ash.sarif
2. Markdown Summary - Contains a summary of the results in Markdown format with up to 20 findings by default: .ash/ash_output/reports/ash.summary.md

Focus on actionable insights and practical remediation steps."""


def run_mcp_server():
    """Run the MCP server with improved error handling."""
    try:
        # Run the MCP server
        mcp.run()
    except KeyboardInterrupt:
        logger.info("MCP server stopped by user")
    except Exception as e:
        # Check if it's a connection-related error
        error_str = str(e)
        if "ClosedResourceError" in error_str or "TaskGroup" in error_str:
            logger.warning(
                "MCP server connection closed unexpectedly. "
                "This may happen if the client disconnects during a long-running operation."
            )
        else:
            logger.exception(f"Error running MCP server: {error_str}")
        # Don't re-raise - allow graceful shutdown


if __name__ == "__main__":
    run_mcp_server()
