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

from mcp.server.fastmcp import FastMCP, Context

from automated_security_helper.cli.mcp_tools import (
    mcp_scan_directory,
    mcp_get_scan_progress,
    mcp_get_scan_results,
    mcp_list_active_scans,
    mcp_cancel_scan,
    mcp_check_installation,
    mcp_get_config,
    mcp_diff_scan_results,
    mcp_validate_config,
    mcp_explain_finding,
)
from automated_security_helper.core.constants import ASH_EXIT_CODES

from automated_security_helper.core.resource_management.scan_registry import (
    get_scan_registry,
)
from automated_security_helper.core.resource_management.result_filters import (
    filter_summary,
    filter_minimal,
    filter_actionable_only,
    apply_content_filters,
)
from automated_security_helper.cli.mcp.progress_monitor import monitor_scan_progress
from automated_security_helper.utils.log import ASH_LOGGER

logger = ASH_LOGGER

# Backward-compatible private-name aliases (tests import these by name).
_filter_summary = filter_summary
_filter_minimal = filter_minimal
_filter_actionable_only = filter_actionable_only
_apply_content_filters = apply_content_filters
_monitor_scan_progress = monitor_scan_progress

mcp = FastMCP(name="ASH Security Scanner")


@mcp.tool()
async def run_ash_scan(
    ctx: Context,
    source_dir: Optional[str] = None,
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
        if source_dir is None:
            source_dir = str(Path.cwd().absolute())
        await ctx.info(f"run_ash_scan tool called in cwd: {Path.cwd()}")
        if not Path(source_dir).is_absolute():
            source_dir = str(Path.cwd() / source_dir)

        await ctx.info(f"Starting scan for directory: {source_dir}")

        directory_path_obj = Path(source_dir)
        output_dir = directory_path_obj.joinpath(".ash", "ash_output")
        aggregated_results_path = output_dir.joinpath("ash_aggregated_results.json")

        if clean_output and aggregated_results_path.exists():
            await ctx.info("Cleaning up existing results file...")
            try:
                os.remove(aggregated_results_path)
                await ctx.debug(
                    f"Removed existing results file: {aggregated_results_path}"
                )
            except Exception as e:
                await ctx.warning(f"Failed to clean up results file: {str(e)}")

        result = await mcp_scan_directory(
            directory_path=source_dir,
            severity_threshold=severity_threshold,
            config_path=config_path,
        )

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

        try:
            await ctx.report_progress(
                progress=0.0,
                total=1.0,
                message="Scan started, initializing scanners...",
            )
        except Exception as e:
            logger.warning(f"Failed to send initial progress update: {str(e)}")

        monitor_task = asyncio.create_task(monitor_scan_progress(ctx, scan_id))
        if not hasattr(run_ash_scan, "_monitor_tasks"):
            run_ash_scan._monitor_tasks = set()
        run_ash_scan._monitor_tasks.add(monitor_task)
        monitor_task.add_done_callback(lambda t: run_ash_scan._monitor_tasks.discard(t))

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

        progress_info = await mcp_get_scan_progress(scan_id=scan_id)

        if not progress_info.get("success", False):
            return progress_info

        registry = get_scan_registry()
        entry = registry.get_scan(scan_id)

        if not entry:
            await ctx.error(f"Scan {scan_id} not found in registry")
            return {
                "success": False,
                "error": f"Scan {scan_id} not found in registry",
                "error_type": "scan_not_found",
            }

        output_dir = Path(entry.output_directory)

        scanner_results = {}
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "suppressed": 0,
        }

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
                            with open(result_file, "r") as f:
                                result_data = json.load(f)

                            scanner_results[scanner_name][target_type] = result_data

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

        results = await mcp_get_scan_results(output_dir=output_dir)

        if "error" in results or not results.get("success"):
            return results

        if actionable_only:
            results = filter_actionable_only(results)

        if scanners or severities:
            results = apply_content_filters(results, scanners, severities)

        if filter_level == "full":
            return results
        elif filter_level == "summary":
            return filter_summary(results)
        elif filter_level == "minimal":
            return filter_minimal(results)
        else:
            await ctx.warning(
                f"Unknown filter_level '{filter_level}', returning full results"
            )
            return results

    except Exception as e:
        logger.exception(f"Error in get_scan_results: {str(e)}")
        try:
            await ctx.error(f"Error getting scan results: {str(e)}")
        except Exception:
            logger.error(f"Failed to send error message to client: {str(e)}")
        return {
            "success": False,
            "error": f"Error getting scan results: {str(e)}",
            "error_type": type(e).__name__,
        }


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
    return await get_scan_results(ctx, output_dir=output_dir, filter_level="summary")


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
        if not Path(output_dir).is_absolute():
            output_dir = str(Path.cwd() / output_dir)

        output_path = Path(output_dir)
        reports_dir = output_path / "reports"

        await ctx.info(f"Getting scan result paths from: {output_dir}")

        if not output_path.exists():
            return {
                "success": False,
                "error": f"Output directory does not exist: {output_dir}",
                "error_type": "DirectoryNotFound",
            }

        if not reports_dir.exists():
            return {
                "success": False,
                "error": f"Reports directory does not exist: {reports_dir}",
                "error_type": "DirectoryNotFound",
            }

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

        result: Dict[str, Any] = {
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

        aggregated_file = output_path / "ash_aggregated_results.json"
        result["files"]["aggregated_results"] = {
            "path": str(aggregated_file),
            "exists": aggregated_file.exists(),
            "size_bytes": aggregated_file.stat().st_size
            if aggregated_file.exists()
            else 0,
        }

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


@mcp.tool()
async def explain_finding(
    finding_id: str,
    results_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Return structured details for a single finding by ID.

    Performs a pure structured lookup against already-emitted SARIF results.
    No LLM calls are made.

    Args:
        finding_id: The FlatVulnerability ID to look up (e.g. "bandit-B601-deadbeef").
        results_path: Optional path to the output directory containing
                      ash_aggregated_results.json. Defaults to
                      <cwd>/.ash/ash_output.

    Returns:
        Dict with ``success`` and ``finding`` keys containing title, description,
        severity, severity_rationale, cwe_id, cve_id, references, scanner,
        and scanner_metadata.
    """
    try:
        return mcp_explain_finding(
            finding_id=finding_id,
            results_path=results_path,
        )
    except Exception as e:
        logger.exception(f"Error in explain_finding: {str(e)}")
        return {
            "success": False,
            "error": f"Error explaining finding: {str(e)}",
            "error_type": type(e).__name__,
        }


@mcp.tool()
async def get_config(
    config_path: Optional[str] = None,
    raw: bool = False,
) -> Dict[str, Any]:
    """Get the resolved ASH config (defaults + user overrides merged).

    Args:
        config_path: Optional explicit path to config file. If None, auto-discovers.
        raw: If True, returns the user file contents without merging defaults.
    """
    try:
        return mcp_get_config(config_path=config_path, raw=raw)
    except Exception as e:
        logger.exception(f"Error in get_config: {str(e)}")
        return {
            "success": False,
            "error": f"Error getting config: {str(e)}",
            "error_type": type(e).__name__,
        }


@mcp.tool()
async def diff_scan_results(
    before_path: str,
    after_path: str,
) -> Dict[str, Any]:
    """Compare two ash_aggregated_results.json files and return a structured diff.

    Args:
        before_path: Path to the baseline ash_aggregated_results.json file.
        after_path: Path to the comparison ash_aggregated_results.json file.

    Returns:
        Dict with keys new, resolved, and severity_changed.
    """
    try:
        return mcp_diff_scan_results(before_path=before_path, after_path=after_path)
    except Exception as e:
        logger.exception(f"Error in diff_scan_results: {str(e)}")
        return {
            "success": False,
            "error": f"Error diffing scan results: {str(e)}",
            "error_type": type(e).__name__,
        }


@mcp.tool()
def validate_config(
    config_content: Optional[str] = None,
    config_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Validate an ASH configuration file or content string.

    Args:
        config_content: YAML/JSON string to validate.
        config_path: Path to the config file to validate.

    Returns:
        Dict with valid (bool) and errors (list of {field, message, type}).
    """
    try:
        return mcp_validate_config(config_content=config_content, config_path=config_path)
    except Exception as e:
        logger.exception(f"Error in validate_config: {str(e)}")
        return {
            "valid": False,
            "errors": [
                {
                    "field": "",
                    "message": f"Unexpected error: {str(e)}",
                    "type": type(e).__name__,
                }
            ],
        }


def _read_ash_config_schema() -> str:
    """Read the AshConfig JSON schema from disk."""
    schema_path = Path(__file__).parent.parent / "schemas" / "AshConfig.json"
    return schema_path.read_text()


@mcp.resource("ash://schema/config")
def get_ash_config_schema() -> str:
    """Return the AshConfig JSON schema."""
    return _read_ash_config_schema()


def _build_ash_exit_codes() -> str:
    """Build JSON string of ASH exit codes from the canonical constant."""
    return json.dumps({str(k): v for k, v in ASH_EXIT_CODES.items()})


@mcp.resource("ash://exit-codes")
def get_ash_exit_codes() -> str:
    """Return the meaning of each ASH exit code as JSON."""
    return _build_ash_exit_codes()


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
def run_ash_security_scan(source_dir: Optional[str] = None) -> str:
    """Create a prompt for analyzing ASH security scan results"""
    if source_dir is None:
        source_dir = str(Path.cwd().absolute())
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
def analyze_security_findings(source_dir: Optional[str] = None) -> str:
    """Create a prompt for analyzing ASH security scan results"""
    if source_dir is None:
        source_dir = str(Path.cwd().absolute())
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
        mcp.run()
    except KeyboardInterrupt:
        logger.info("MCP server stopped by user")
    except Exception as e:
        error_str = str(e)
        if "ClosedResourceError" in error_str or "TaskGroup" in error_str:
            logger.warning(
                "MCP server connection closed unexpectedly. "
                "This may happen if the client disconnects during a long-running operation."
            )
        else:
            logger.exception(f"Error running MCP server: {error_str}")


if __name__ == "__main__":
    run_mcp_server()
