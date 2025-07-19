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
    Use get_scan_progress to track progress and get_scan_results for final results.

    Args:
        source_dir: Path to the directory to scan. This should be the absolute path!
        severity_threshold: Minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL)
        config_path: Optional path to ASH configuration file
        clean_output: Whether to clean up existing output files before starting the scan
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
        await ctx.report_progress(
            progress=0.0,
            total=1.0,
            message="Scan started, initializing scanners...",
        )

        # Start background task to monitor progress
        asyncio.create_task(_monitor_scan_progress(ctx, scan_id))

        # Return initial status
        return {
            "success": True,
            "status": "running",
            "scan_id": scan_id,
            "progress": 0.0,
            "message": "Scan started, initializing scanners. Use get_scan_progress to track progress.",
            "directory_path": str(directory_path_obj),
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
        heartbeat_interval = 10  # Send a heartbeat every 10 seconds
        max_wait_time = 1800  # 30 minutes maximum wait time
        start_time = asyncio.get_event_loop().time()
        completed = False

        # Initial progress update
        await ctx.report_progress(
            progress=0.0,
            total=1.0,
            message="Scan started, initializing scanners...",
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
                await ctx.report_progress(
                    progress=1.0,
                    total=1.0,
                    message="Scan completed, parsing results...",
                )

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

                    await ctx.info(summary)

                return

            # Check registry for scan status
            progress_info = await mcp_get_scan_progress(scan_id=scan_id)
            if progress_info.get("status") in ["failed", "cancelled"]:
                completed = True

                # Report final status
                await ctx.report_progress(
                    progress=1.0,
                    total=1.0,
                    message=f"Scan {progress_info.get('status')}",
                )

                # Log completion
                if progress_info.get("status") == "failed":
                    await ctx.error(
                        f"Scan failed: {progress_info.get('error_message', 'Unknown error')}"
                    )
                elif progress_info.get("status") == "cancelled":
                    await ctx.info("Scan was cancelled.")

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
                        await ctx.report_progress(
                            progress=progress,
                            total=1.0,
                            message=message,
                        )

                        # Update last progress time
                        last_progress_time = current_time

                        await ctx.debug(
                            f"Scanner progress: {scanner_name}/{target_type} - {int(progress * 100)}%"
                        )
                    except Exception as e:
                        await ctx.warning(
                            f"Error processing scanner results for {scanner_name}/{target_type}: {str(e)}"
                        )

            # Send heartbeat if no progress updates for a while
            if (
                not progress_updated
                and (current_time - last_progress_time) >= heartbeat_interval
            ):
                progress = len(completed_scanners) / max(total_scanners_estimate, 1)
                progress = min(progress, 0.95)  # Cap at 95% until fully complete

                # Report heartbeat progress
                await ctx.report_progress(
                    progress=progress,
                    total=1.0,
                    message=f"Scan in progress ({len(completed_scanners)}/{total_scanners_estimate} scanners completed)",
                )

                # Update last progress time
                last_progress_time = current_time

            # Wait before checking again
            await asyncio.sleep(1)

    except Exception as e:
        logger.exception(f"Error monitoring scan progress: {str(e)}")
        await ctx.error(f"Error monitoring scan progress: {str(e)}")


@mcp.tool()
async def get_scan_progress(ctx: Context, scan_id: str) -> Dict[str, Any]:
    """
    Get current progress and partial results for a running scan.

    Args:
        scan_id: The scan ID returned from scan_directory
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
    ctx: Context, output_dir: str = ".ash/ash_output"
) -> Dict[str, Any]:
    """
    Get final results for a completed scan.

    Args:
        output_dir: Path to the scan output directory (absolute path recommended)
    """
    try:
        # Ensure output_dir is an absolute path
        if not Path(output_dir).is_absolute():
            output_dir = str(Path.cwd() / output_dir)

        await ctx.info(f"Getting results from ASH scan in directory: {output_dir}")

        # Get the raw results
        results = await mcp_get_scan_results(output_dir=output_dir)

        if not results.get("success", False):
            return results

        # Process the raw results to remove specified keys
        if "raw_results" in results:
            raw_results = results["raw_results"]

            # Remove specified keys
            keys_to_remove = [
                "ash_config",
                "validation_checkpoints",
                "sarif",
                "cyclonedx",
            ]
            for key in keys_to_remove:
                if key in raw_results:
                    del raw_results[key]

            # Update the raw_results in the response
            results["raw_results"] = raw_results

        return results
    except Exception as e:
        logger.exception(f"Error in get_scan_results: {str(e)}")
        await ctx.error(f"Error getting scan results: {str(e)}")
        return {
            "success": False,
            "error": f"Error getting scan results: {str(e)}",
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
    """Run the MCP server."""
    try:
        # Run the MCP server
        mcp.run()
    except Exception as e:
        logger.exception(f"Error running MCP server: {str(e)}")
        raise


if __name__ == "__main__":
    run_mcp_server()
