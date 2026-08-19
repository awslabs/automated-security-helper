# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Background scan-progress monitor for the ASH MCP server.
"""

import asyncio
import json
from pathlib import Path

from mcp.server.fastmcp import Context

from automated_security_helper.cli.mcp_tools import (
    mcp_get_scan_progress,
    mcp_get_scan_results,
)
from automated_security_helper.utils.log import ASH_LOGGER

logger = ASH_LOGGER


async def monitor_scan_progress(ctx: Context, scan_id: str) -> None:
    """
    Monitor scan progress and report updates via the MCP context.

    Resilient to connection closures: if the client disconnects the monitor
    continues silently until the scan finishes or times out.

    Args:
        ctx: MCP context for reporting progress/log messages.
        scan_id: The scan ID returned by run_ash_scan.
    """
    connection_alive = True

    try:
        registry_info = await mcp_get_scan_progress(scan_id=scan_id)
        if not registry_info.get("success", False):
            await ctx.error(
                f"Failed to get scan info: {registry_info.get('error', 'Unknown error')}"
            )
            return

        directory_path = registry_info.get("directory_path", "")
        if not directory_path:
            await ctx.error("Missing directory path in scan registry")
            return

        directory_path_obj = Path(directory_path)
        output_dir = directory_path_obj / ".ash" / "ash_output"
        ash_aggregated_results = output_dir / "ash_aggregated_results.json"

        completed_scanners: set = set()
        total_scanners_estimate = 5
        last_progress_time = asyncio.get_event_loop().time()
        heartbeat_interval = 15
        max_wait_time = 1800
        start_time = asyncio.get_event_loop().time()
        completed = False

        try:
            await ctx.report_progress(
                progress=0.0,
                total=1.0,
                message="Scan started, initializing scanners...",
            )
        except Exception as e:
            logger.debug(f"Failed to send initial progress update in monitor: {str(e)}")
            connection_alive = False

        while not completed:
            current_time = asyncio.get_event_loop().time()

            if current_time - start_time > max_wait_time:
                await ctx.warning(
                    f"Scan monitoring timed out after {max_wait_time} seconds"
                )
                return

            if ash_aggregated_results.exists():
                completed = True

                try:
                    if connection_alive:
                        await ctx.report_progress(
                            progress=1.0,
                            total=1.0,
                            message="Scan completed, parsing results...",
                        )
                except Exception as e:
                    logger.debug(f"Failed to send completion progress: {str(e)}")
                    connection_alive = False

                final_results = await mcp_get_scan_results(output_dir=str(output_dir))

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
                        if connection_alive:
                            await ctx.info(summary)
                    except Exception as e:
                        logger.debug(f"Failed to send completion summary: {str(e)}")
                        connection_alive = False

                return

            progress_info = await mcp_get_scan_progress(scan_id=scan_id)
            if progress_info.get("status") in ["failed", "cancelled"]:
                completed = True

                try:
                    if connection_alive:
                        await ctx.report_progress(
                            progress=1.0,
                            total=1.0,
                            message=f"Scan {progress_info.get('status')}",
                        )
                except Exception as e:
                    logger.debug(f"Failed to send final status progress: {str(e)}")
                    connection_alive = False

                try:
                    if connection_alive:
                        if progress_info.get("status") == "failed":
                            await ctx.error(
                                f"Scan failed: {progress_info.get('error_message', 'Unknown error')}"
                            )
                        elif progress_info.get("status") == "cancelled":
                            await ctx.info("Scan was cancelled.")
                except Exception as e:
                    logger.debug(f"Failed to send completion message: {str(e)}")
                    connection_alive = False

                return

            scanner_results = list(output_dir.glob("scanners/**/ASH.ScanResults.json"))

            if len(scanner_results) > 0:
                scanner_dirs = set(path.parent.parent.name for path in scanner_results)
                total_scanners_estimate = max(
                    total_scanners_estimate, len(scanner_dirs) * 2
                )

            progress_updated = False
            for result_path in scanner_results:
                scanner_name = result_path.parent.parent.name
                target_type = result_path.parent.name
                scanner_key = f"{scanner_name}/{target_type}"

                if scanner_key not in completed_scanners:
                    completed_scanners.add(scanner_key)
                    progress_updated = True

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

                        progress = len(completed_scanners) / total_scanners_estimate
                        progress = min(progress, 0.95)

                        try:
                            if connection_alive:
                                await ctx.report_progress(
                                    progress=progress,
                                    total=1.0,
                                    message=message,
                                )
                                last_progress_time = current_time
                        except Exception as e:
                            logger.debug(f"Failed to send progress update: {str(e)}")
                            connection_alive = False

                        try:
                            if connection_alive:
                                await ctx.debug(
                                    f"Scanner progress: {scanner_name}/{target_type} - {int(progress * 100)}%"
                                )
                        except Exception as e:
                            logger.debug(f"Failed to send debug message: {str(e)}")
                            connection_alive = False
                    except asyncio.CancelledError:
                        raise
                    except Exception as e:
                        logger.warning(
                            f"Error processing scanner results for {scanner_name}/{target_type}: {str(e)}"
                        )
                        try:
                            if connection_alive:
                                await ctx.warning(
                                    f"Error processing scanner results for {scanner_name}/{target_type}: {str(e)}"
                                )
                        except Exception as e:
                            logger.debug(f"Failed to send warning message: {str(e)}")
                            connection_alive = False

            if (
                not progress_updated
                and connection_alive
                and (current_time - last_progress_time) >= heartbeat_interval
            ):
                progress = len(completed_scanners) / max(total_scanners_estimate, 1)
                progress = min(progress, 0.95)

                try:
                    await ctx.report_progress(
                        progress=progress,
                        total=1.0,
                        message=f"Scan in progress ({len(completed_scanners)}/{total_scanners_estimate} scanners completed)",
                    )
                    last_progress_time = current_time
                except Exception as e:
                    logger.debug(f"Failed to send heartbeat: {str(e)}")
                    connection_alive = False

            if len(completed_scanners) == 0:
                await asyncio.sleep(5)
            elif len(completed_scanners) < 2:
                await asyncio.sleep(8)
            else:
                await asyncio.sleep(10)

    except asyncio.CancelledError:
        logger.info(f"Scan monitoring cancelled for scan_id: {scan_id}")
        try:
            if connection_alive:
                await ctx.info("Scan monitoring stopped.")
        except Exception as e:
            logger.debug(f"Failed to send cancellation message: {str(e)}")
    except Exception as e:
        logger.exception(f"Error monitoring scan progress: {str(e)}")
        try:
            if connection_alive:
                await ctx.error(f"Error monitoring scan progress: {str(e)}")
        except Exception:
            logger.debug(f"Failed to send error message to client: {str(e)}")
