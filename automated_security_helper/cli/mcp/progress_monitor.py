# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Background scan-progress monitor for the ASH MCP server.
"""

import asyncio
import json
from pathlib import Path
from typing import Awaitable, Callable, Optional, Tuple

from mcp.server.fastmcp import Context

from automated_security_helper.cli.mcp_tools import (
    mcp_get_scan_progress,
    mcp_get_scan_results,
)
from automated_security_helper.utils.log import ASH_LOGGER

logger = ASH_LOGGER

_HEARTBEAT_INTERVAL_SECONDS = 15
_MAX_WAIT_SECONDS = 1800
_INITIAL_SCANNER_ESTIMATE = 5
_PROGRESS_CEILING = 0.95


async def _safe_send(
    connection_alive: bool,
    coro_factory: Callable[[], Awaitable[None]],
    debug_msg: str,
) -> bool:
    """Invoke a context-emitting coroutine while preserving connection-alive semantics.

    The original implementation repeated try/except blocks that swallowed any
    exception, logged it at debug level, and flipped ``connection_alive`` to
    False. This helper centralizes that pattern. Calls are skipped when the
    connection is already known to be dead.
    """
    if not connection_alive:
        return False
    try:
        await coro_factory()
        return True
    except Exception as exc:
        logger.debug(f"{debug_msg}: {str(exc)}")
        return False


async def _fetch_initial_scan_info(
    ctx: Context, scan_id: str
) -> Optional[Tuple[Path, Path, Path]]:
    """Resolve the scan's working directory or report the failure to the client.

    Returns ``(directory_path, output_dir, ash_aggregated_results)`` on success,
    or ``None`` when the registry lookup fails or the directory path is missing.
    """
    registry_info = await mcp_get_scan_progress(scan_id=scan_id)
    if not registry_info.get("success", False):
        await ctx.error(
            f"Failed to get scan info: {registry_info.get('error', 'Unknown error')}"
        )
        return None

    directory_path = registry_info.get("directory_path", "")
    if not directory_path:
        await ctx.error("Missing directory path in scan registry")
        return None

    directory_path_obj = Path(directory_path)
    output_dir = directory_path_obj / ".ash" / "ash_output"
    ash_aggregated_results = output_dir / "ash_aggregated_results.json"
    return directory_path_obj, output_dir, ash_aggregated_results


def _build_findings_summary(severity_counts: dict) -> str:
    """Render a comma-separated severity summary, matching the original format."""
    return ", ".join(
        f"{count} {severity.lower()}"
        for severity, count in severity_counts.items()
        if count > 0
    )


async def _handle_scan_completed(
    ctx: Context, output_dir: Path, connection_alive: bool
) -> bool:
    """Emit completion progress + summary once the aggregated results file exists.

    Returns the (possibly updated) ``connection_alive`` flag.
    """
    connection_alive = await _safe_send(
        connection_alive,
        lambda: ctx.report_progress(
            progress=1.0,
            total=1.0,
            message="Scan completed, parsing results...",
        ),
        "Failed to send completion progress",
    )

    final_results = await mcp_get_scan_results(output_dir=str(output_dir))
    if not final_results.get("success", False):
        return connection_alive

    findings_count = final_results.get("findings_count", 0)
    severity_counts = final_results.get("severity_counts", {})

    if findings_count > 0:
        summary = (
            f"Scan completed with {findings_count} findings: "
            + _build_findings_summary(severity_counts)
        )
    else:
        summary = "Scan completed with no findings."

    return await _safe_send(
        connection_alive,
        lambda: ctx.info(summary),
        "Failed to send completion summary",
    )


async def _handle_terminal_status(
    ctx: Context, progress_info: dict, connection_alive: bool
) -> bool:
    """Emit progress + final message for ``failed``/``cancelled`` statuses."""
    status = progress_info.get("status")
    connection_alive = await _safe_send(
        connection_alive,
        lambda: ctx.report_progress(
            progress=1.0,
            total=1.0,
            message=f"Scan {status}",
        ),
        "Failed to send final status progress",
    )

    if status == "failed":
        error_message = progress_info.get("error_message", "Unknown error")
        connection_alive = await _safe_send(
            connection_alive,
            lambda: ctx.error(f"Scan failed: {error_message}"),
            "Failed to send completion message",
        )
    elif status == "cancelled":
        connection_alive = await _safe_send(
            connection_alive,
            lambda: ctx.info("Scan was cancelled."),
            "Failed to send completion message",
        )
    return connection_alive


def _read_scanner_severity(result_path: Path) -> dict:
    """Load a scanner's ASH.ScanResults.json and return its severity_counts dict."""
    with open(result_path, "r") as f:
        scanner_data = json.load(f)
    return scanner_data.get("severity_counts", {})


def _format_scanner_message(
    scanner_name: str, target_type: str, severity_counts: dict
) -> str:
    """Build the human-readable progress message for a single completed scanner."""
    finding_count = sum(severity_counts.values())
    if finding_count > 0:
        findings_summary = _build_findings_summary(severity_counts)
        return f"{scanner_name} completed {target_type} scan: {findings_summary}"
    return f"{scanner_name} completed {target_type} scan: No issues found"


async def _emit_scanner_progress(
    ctx: Context,
    scanner_name: str,
    target_type: str,
    progress: float,
    message: str,
    connection_alive: bool,
) -> bool:
    """Send the scanner-completed progress + debug pair, tracking liveness."""
    connection_alive = await _safe_send(
        connection_alive,
        lambda: ctx.report_progress(
            progress=progress,
            total=1.0,
            message=message,
        ),
        "Failed to send progress update",
    )
    connection_alive = await _safe_send(
        connection_alive,
        lambda: ctx.debug(
            f"Scanner progress: {scanner_name}/{target_type} - {int(progress * 100)}%"
        ),
        "Failed to send debug message",
    )
    return connection_alive


async def _process_scanner_result(
    ctx: Context,
    result_path: Path,
    completed_scanners: set,
    total_scanners_estimate: int,
    connection_alive: bool,
) -> Tuple[bool, bool]:
    """Process a single scanner result file.

    Returns ``(connection_alive, progress_updated)``. ``progress_updated`` is
    True iff this call advanced the completed-scanners set (and therefore
    emitted progress). Errors during file parsing are logged and reported as a
    warning to the client without aborting the loop.
    """
    scanner_name = result_path.parent.parent.name
    target_type = result_path.parent.name
    scanner_key = f"{scanner_name}/{target_type}"

    if scanner_key in completed_scanners:
        return connection_alive, False

    completed_scanners.add(scanner_key)

    try:
        severity_counts = _read_scanner_severity(result_path)
        message = _format_scanner_message(scanner_name, target_type, severity_counts)
        progress = min(
            len(completed_scanners) / total_scanners_estimate, _PROGRESS_CEILING
        )
        connection_alive = await _emit_scanner_progress(
            ctx, scanner_name, target_type, progress, message, connection_alive
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.warning(
            f"Error processing scanner results for {scanner_name}/{target_type}: {str(exc)}"
        )
        connection_alive = await _safe_send(
            connection_alive,
            lambda: ctx.warning(
                f"Error processing scanner results for {scanner_name}/{target_type}: {str(exc)}"
            ),
            "Failed to send warning message",
        )

    return connection_alive, True


async def _emit_heartbeat(
    ctx: Context,
    completed_scanners: set,
    total_scanners_estimate: int,
    connection_alive: bool,
) -> bool:
    """Send a periodic heartbeat progress update."""
    progress = min(
        len(completed_scanners) / max(total_scanners_estimate, 1),
        _PROGRESS_CEILING,
    )
    return await _safe_send(
        connection_alive,
        lambda: ctx.report_progress(
            progress=progress,
            total=1.0,
            message=(
                f"Scan in progress ({len(completed_scanners)}/"
                f"{total_scanners_estimate} scanners completed)"
            ),
        ),
        "Failed to send heartbeat",
    )


def _sleep_interval_for(completed_count: int) -> int:
    """Backoff schedule: faster polling early, slower once scanners report in."""
    if completed_count == 0:
        return 5
    if completed_count < 2:
        return 8
    return 10


def _update_scanner_estimate(
    scanner_results: list, current_estimate: int
) -> int:
    """Infer scanner count from result paths; never shrink below current estimate."""
    if not scanner_results:
        return current_estimate
    scanner_dirs = {path.parent.parent.name for path in scanner_results}
    return max(current_estimate, len(scanner_dirs) * 2)


async def _send_initial_progress(ctx: Context) -> bool:
    """Send the 'scan started' update; returns False if the client is gone."""
    return await _safe_send(
        True,
        lambda: ctx.report_progress(
            progress=0.0,
            total=1.0,
            message="Scan started, initializing scanners...",
        ),
        "Failed to send initial progress update in monitor",
    )


async def _run_monitor_loop(
    ctx: Context,
    scan_id: str,
    output_dir: Path,
    ash_aggregated_results: Path,
    connection_alive: bool,
) -> None:
    """Poll-and-emit loop until the scan finishes, fails, cancels, or times out."""
    completed_scanners: set = set()
    total_scanners_estimate = _INITIAL_SCANNER_ESTIMATE
    start_time = asyncio.get_event_loop().time()
    last_progress_time = start_time

    while True:
        current_time = asyncio.get_event_loop().time()

        if current_time - start_time > _MAX_WAIT_SECONDS:
            await ctx.warning(
                f"Scan monitoring timed out after {_MAX_WAIT_SECONDS} seconds"
            )
            return

        if ash_aggregated_results.exists():
            await _handle_scan_completed(ctx, output_dir, connection_alive)
            return

        progress_info = await mcp_get_scan_progress(scan_id=scan_id)
        if progress_info.get("status") in ["failed", "cancelled"]:
            await _handle_terminal_status(ctx, progress_info, connection_alive)
            return

        scanner_results = list(output_dir.glob("scanners/**/ASH.ScanResults.json"))
        total_scanners_estimate = _update_scanner_estimate(
            scanner_results, total_scanners_estimate
        )

        progress_updated = False
        for result_path in scanner_results:
            connection_alive, was_new = await _process_scanner_result(
                ctx,
                result_path,
                completed_scanners,
                total_scanners_estimate,
                connection_alive,
            )
            if was_new:
                progress_updated = True
                last_progress_time = current_time

        if (
            not progress_updated
            and connection_alive
            and (current_time - last_progress_time) >= _HEARTBEAT_INTERVAL_SECONDS
        ):
            connection_alive = await _emit_heartbeat(
                ctx, completed_scanners, total_scanners_estimate, connection_alive
            )
            last_progress_time = current_time

        await asyncio.sleep(_sleep_interval_for(len(completed_scanners)))


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
        scan_info = await _fetch_initial_scan_info(ctx, scan_id)
        if scan_info is None:
            return
        _, output_dir, ash_aggregated_results = scan_info

        connection_alive = await _send_initial_progress(ctx)

        await _run_monitor_loop(
            ctx,
            scan_id,
            output_dir,
            ash_aggregated_results,
            connection_alive,
        )
    except asyncio.CancelledError:
        logger.info(f"Scan monitoring cancelled for scan_id: {scan_id}")
        await _safe_send(
            connection_alive,
            lambda: ctx.info("Scan monitoring stopped."),
            "Failed to send cancellation message",
        )
    except Exception as exc:
        logger.exception(f"Error monitoring scan progress: {str(exc)}")
        await _safe_send(
            connection_alive,
            lambda: ctx.error(f"Error monitoring scan progress: {str(exc)}"),
            "Failed to send error message to client",
        )
