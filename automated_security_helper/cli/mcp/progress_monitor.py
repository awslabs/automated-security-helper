# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Background scan-progress monitor for the ASH MCP server.
"""

import asyncio
import json
import os
import stat
from pathlib import Path
from typing import Awaitable, Callable, Dict, Optional, Tuple

from mcp.server.mcpserver import Context

from automated_security_helper.cli.mcp_tools import (
    mcp_get_scan_progress,
    mcp_get_scan_results,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.terminal_text import raw_controls_on_one_line

logger = ASH_LOGGER

_HEARTBEAT_INTERVAL_SECONDS = 15
_MAX_WAIT_SECONDS = 1800
_INITIAL_SCANNER_ESTIMATE = 5
_PROGRESS_CEILING = 0.95

#: How often the workspace monitor looks for a newly-finished project. Slower than
#: the single-scan loop's 5 seconds because the unit being watched is a whole
#: project scan rather than one scanner.
_WORKSPACE_POLL_INTERVAL_SECONDS = 5.0

#: What a finished project scan leaves in its output directory.
_AGGREGATED_RESULTS_FILENAME = "ash_aggregated_results.json"


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


def _in_session(session_id: Optional[str]) -> Dict[str, str]:
    """The keyword that reads the scan in the session that started it.

    The registry shows a scan only to its own session, so the monitor asks as
    that session. Omitted when there is none, which is the default session.
    """
    return {} if session_id is None else {"session_id": session_id}


async def _fetch_initial_scan_info(
    ctx: Context, scan_id: str, session_id: Optional[str] = None
) -> Optional[Tuple[Path, Path, Path]]:
    """Resolve the scan's working directory or report the failure to the client.

    Returns ``(directory_path, output_dir, ash_aggregated_results)`` on success,
    or ``None`` when the registry lookup fails or the directory path is missing.
    """
    registry_info = await mcp_get_scan_progress(
        scan_id=scan_id, **_in_session(session_id)
    )
    if not registry_info.get("success", False):
        # Through _safe_send like every other send of the monitor: a client that
        # is gone makes the send raise, and a bare send here landed that failure
        # in monitor_scan_progress's own handler, which sent a second error to
        # the same dead client and logged the dead send as a monitor failure.
        await _safe_send(
            True,
            lambda: ctx.error(
                raw_controls_on_one_line(
                    "Failed to get scan info: "
                    f"{registry_info.get('error', 'Unknown error')}"
                )
            ),
            "Failed to send scan-info error",
        )
        return None

    directory_path = registry_info.get("directory_path", "")
    if not directory_path:
        await _safe_send(
            True,
            lambda: ctx.error("Missing directory path in scan registry"),
            "Failed to send scan-info error",
        )
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


def _findings_in(final_results: dict) -> Tuple[int, dict]:
    """The finding count and per-severity counts of a ``mcp_get_scan_results`` reply.

    The reply carries the aggregated results' ``summary_stats``: its
    ``severity_counts`` mapping and its ``total``, the number of findings that
    are not suppressed. It has never carried a top-level ``findings_count`` or
    ``severity_counts``, which is what this monitor used to read, so every
    completed scan was announced as having no findings whatever it found.

    ``total`` is read when it is a number; otherwise the non-suppressed
    severities are summed, which is how the model derives it.
    """
    stats = final_results.get("summary_stats")
    if not isinstance(stats, dict):
        return 0, {}
    severity_counts = stats.get("severity_counts")
    if not isinstance(severity_counts, dict):
        severity_counts = {}
    total = stats.get("total")
    if isinstance(total, bool) or not isinstance(total, int):
        total = sum(
            count
            for severity, count in severity_counts.items()
            if isinstance(count, int)
            and not isinstance(count, bool)
            and str(severity).lower() != "suppressed"
        )
    return total, severity_counts


async def _handle_scan_completed(
    ctx: Context,
    output_dir: Path,
    connection_alive: bool,
    session_id: Optional[str] = None,
) -> bool:
    """Emit completion progress + summary once the aggregated results file exists.

    Returns the (possibly updated) ``connection_alive`` flag.

    The results are read as the scan's own session. A delivered tree's output
    sits inside that session's sandbox, which no operator grant names, so a
    read with no session is refused and the completion summary was never sent
    for a scan of a delivered tree.
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

    final_results = await mcp_get_scan_results(
        output_dir=str(output_dir), **_in_session(session_id)
    )
    if not final_results.get("success", False):
        return connection_alive

    findings_count, severity_counts = _findings_in(final_results)

    if findings_count > 0:
        summary = (
            f"Scan completed with {findings_count} findings: "
            + _build_findings_summary(severity_counts)
        )
    else:
        summary = "Scan completed with no findings."

    return await _safe_send(
        connection_alive,
        lambda: ctx.info(raw_controls_on_one_line(summary)),
        "Failed to send completion summary",
    )


async def _handle_terminal_status(
    ctx: Context, progress_info: dict, connection_alive: bool
) -> bool:
    """Emit progress + final message for ``failed``/``incomplete``/``cancelled``."""
    status = progress_info.get("status")
    connection_alive = await _safe_send(
        connection_alive,
        lambda: ctx.report_progress(
            progress=1.0,
            total=1.0,
            message=raw_controls_on_one_line(f"Scan {status}"),
        ),
        "Failed to send final status progress",
    )

    if status == "failed":
        error_message = progress_info.get("error_message", "Unknown error")
        connection_alive = await _safe_send(
            connection_alive,
            lambda: ctx.error(
                raw_controls_on_one_line(f"Scan failed: {error_message}")
            ),
            "Failed to send completion message",
        )
    elif status == "incomplete":
        names = ", ".join(
            row.get("scanner", "?")
            for row in progress_info.get("incomplete_scanners") or []
        )
        connection_alive = await _safe_send(
            connection_alive,
            lambda: ctx.warning(
                raw_controls_on_one_line(
                    "Scan finished with incomplete coverage; its results are partial"
                    + (f". Did not complete: {names}" if names else "")
                )
            ),
            "Failed to send completion message",
        )
    elif status == "cancelled":
        connection_alive = await _safe_send(
            connection_alive,
            lambda: ctx.info("Scan was cancelled."),
            "Failed to send completion message",
        )
    return connection_alive


#: The most of a scanner's ``ASH.ScanResults.json`` the monitor reads for its
#: severity counts. The file is a few KiB; a sandboxed scanner writes into this
#: directory, so the read is bounded rather than trusting the size.
_MAX_SCANNER_RESULTS_BYTES = 16 * 1024 * 1024


def _read_scanner_severity(result_path: Path) -> dict:
    """Load a scanner's ASH.ScanResults.json and return its severity_counts dict.

    encoding is explicit for the same reason as in ``cli/report.py``: ASH writes this
    file as UTF-8, and without an encoding text-mode open() uses the locale one,
    which on Windows is cp1252 and cannot decode a finding that quotes non-ASCII
    source.

    Opened without following a link at the name and without blocking, and read
    only when what was opened is a regular file, as the results readers in
    ``mcp_tools`` refuse a linked results file. The directory is one a sandboxed
    scanner writes; a plain ``open()`` there followed a link to any file the
    server can read, and blocked the event loop on a FIFO.
    """
    # The link check by name first: Windows has no O_NOFOLLOW, so the flag loop
    # below contributes nothing there and the open followed the link.
    if stat.S_ISLNK(os.lstat(result_path).st_mode):
        raise OSError(f"{result_path} is a link")
    flags = os.O_RDONLY
    for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC", "O_BINARY"):
        flags |= getattr(os, name, 0)
    fd = os.open(result_path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"{result_path} is not a regular file")
        with os.fdopen(fd, "rb") as f:
            fd = -1
            raw = f.read(_MAX_SCANNER_RESULTS_BYTES + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if len(raw) > _MAX_SCANNER_RESULTS_BYTES:
        raise OSError(
            f"{result_path} is larger than {_MAX_SCANNER_RESULTS_BYTES} bytes"
        )
    scanner_data = json.loads(raw.decode("utf-8"))
    if not isinstance(scanner_data, dict):
        return {}
    counts = scanner_data.get("severity_counts", {})
    return counts if isinstance(counts, dict) else {}


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
            message=raw_controls_on_one_line(message),
        ),
        "Failed to send progress update",
    )
    connection_alive = await _safe_send(
        connection_alive,
        lambda: ctx.debug(
            raw_controls_on_one_line(
                f"Scanner progress: {scanner_name}/{target_type} - "
                f"{int(progress * 100)}%"
            )
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
        # Format the message eagerly instead of closing over `exc`. Python deletes
        # the `except ... as` name when the handler exits, so a lambda that reads
        # `exc` raises NameError rather than reporting the original error if it is
        # ever called after the handler unwinds. It happens to work today only
        # because _safe_send invokes the callable before returning.
        warning_message = f"Error processing scanner results for {scanner_name}/{target_type}: {str(exc)}"
        logger.warning(warning_message)
        connection_alive = await _safe_send(
            connection_alive,
            lambda: ctx.warning(raw_controls_on_one_line(warning_message)),
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
            message=raw_controls_on_one_line(
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


def _update_scanner_estimate(scanner_results: list, current_estimate: int) -> int:
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
    connection_alive: bool,
    session_id: Optional[str] = None,
) -> None:
    """Poll-and-emit loop until the scan finishes, fails, cancels, or times out."""
    completed_scanners: set = set()
    total_scanners_estimate = _INITIAL_SCANNER_ESTIMATE
    start_time = asyncio.get_event_loop().time()
    last_progress_time = start_time

    while True:
        current_time = asyncio.get_event_loop().time()

        if current_time - start_time > _MAX_WAIT_SECONDS:
            # Honors connection_alive like the loop's other sends: nothing is
            # sent into a client the loop already knows is gone, and a send that
            # fails here is one failed send, not a monitor failure.
            await _safe_send(
                connection_alive,
                lambda: ctx.warning(
                    raw_controls_on_one_line(
                        f"Scan monitoring timed out after {_MAX_WAIT_SECONDS} seconds"
                    )
                ),
                "Failed to send timeout warning",
            )
            return

        # The registry's status decides when the scan is over, never the presence
        # of the aggregated results file. That file is there before the scan ends
        # when the previous scan's results were not set aside (clean_output off),
        # it is put back when a scan fails or is cancelled without results, and
        # the SCAN phase writes it before the REPORT phase has run; each of those
        # was announced as a completed scan with the file's findings.
        progress_info = await mcp_get_scan_progress(
            scan_id=scan_id, **_in_session(session_id)
        )
        status = progress_info.get("status")
        if status == "completed":
            await _handle_scan_completed(
                ctx, output_dir, connection_alive, session_id=session_id
            )
            return
        if status in ["failed", "incomplete", "cancelled"]:
            await _handle_terminal_status(ctx, progress_info, connection_alive)
            return

        # Blocking glob on the event loop. Deferred: see the note on the exists() call
        # above -- same polling loop, same reason.
        scanner_results = list(output_dir.glob("scanners/**/ASH.ScanResults.json"))  # noqa: ASYNC240
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


def _results_file_state(output_dir: Path) -> Optional[Tuple[int, int, int, int]]:
    """Identity and version of a project's aggregated results file, or None.

    Device, inode, modification time in nanoseconds and size: a file that was
    rewritten, replaced or newly written differs in at least one of them from
    the same name read earlier. Read with ``lstat`` so a link at the name is
    the link, not what it points at.
    """
    try:
        st = os.lstat(output_dir / _AGGREGATED_RESULTS_FILENAME)
    except OSError:
        return None
    return (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size)


ResultsFileState = Optional[Tuple[int, int, int, int]]


def results_files_before(
    project_outputs: Dict[str, Path],
) -> Dict[str, ResultsFileState]:
    """What each project's aggregated results file is now, keyed as ``project_outputs``.

    For :func:`monitor_workspace_progress`'s ``before``: taken by the caller
    before it touches the output directories, so the monitor compares against
    the file the previous scan left, not against an absence its own set-aside
    made.
    """
    return {key: _results_file_state(out) for key, out in project_outputs.items()}


async def monitor_workspace_progress(
    report_progress: Callable[..., Awaitable[None]],
    project_outputs: Dict[str, Path],
    *,
    poll_interval: float = _WORKSPACE_POLL_INTERVAL_SECONDS,
    before: Optional[Dict[str, ResultsFileState]] = None,
) -> None:
    """Report a workspace scan's progress as completed projects over total projects.

    Why the denominator is projects and not scanners
    -----------------------------------------------
    ``ctx.report_progress`` carries three fields -- progress, total, message -- and
    none of them is a project, so a workspace scan's shape has to be flattened into
    them. Counting projects is the only flattening that terminates.

    Summing per-project scanner fractions does not. ``_update_scanner_estimate``
    only ever raises its estimate (``max`` against the current value) as more
    scanner result files appear, and ``_PROGRESS_CEILING`` caps each project below
    1.0, so a project's own fraction never reaches one and its denominator keeps
    growing. Adding N of those together produces a number that drifts and never
    arrives, which is worse than a coarse count: a client watching it cannot tell
    a stalled scan from a slow one.

    So progress is the count of finished projects and total is the count of
    projects, which is what an MCP client renders as "3/7". The project key travels
    in the message, since there is no field for it.

    Args:
        report_progress: An awaitable taking ``progress``, ``total`` and
            ``message`` as keywords. ``Context.report_progress`` satisfies this;
            it is taken as a callable rather than a ``Context`` so the caller can
            run a workspace scan with no client attached.
        project_outputs: ``{project key: that project's output directory}``. The
            monitor watches for ``ash_aggregated_results.json`` appearing in each.
        poll_interval: Seconds between sweeps.
        before: What each project's aggregated results file was before the run
            touched its directory (:func:`results_files_before`); read here when
            not given. The workspace scan sets previous results aside before this
            monitor starts, so a snapshot taken here read every file as absent,
            and a failed project's restore of its previous file, which the run's
            settle makes while this monitor still polls, counted as its
            completion.

    Failure modes
    -------------
    * A project whose scan fails writes no aggregated-results file, so it never
      counts as complete and the monitor simply stops short. The verdict comes from
      the tool's return value, not from here; this is a liveness signal.
    * The caller cancels this task once execution returns, so the loop does not
      have to detect the end of the run.
    * A send that fails means the client is gone, and the monitor stops rather
      than looping for the rest of the scan emitting into a closed connection.
    """
    total = len(project_outputs)
    if total == 0:
        return

    completed: set = set()
    # What each project's aggregated results file was before the run touched
    # the directories, or when the monitor started when the caller took no
    # snapshot. A project is complete when that file is not what it was then: a
    # file the previous scan left (clean_output off) or that a failed project's
    # restore put back is the same file, and counted a project that never
    # finished, or had not started, as complete.
    if before is None:
        before = results_files_before(project_outputs)
    else:
        before = {key: before.get(key) for key in project_outputs}
    connection_alive = await _safe_send(
        True,
        lambda: report_progress(
            progress=0.0,
            total=float(total),
            message=raw_controls_on_one_line(
                f"Workspace scan started: 0/{total} projects complete"
            ),
        ),
        "Failed to send initial workspace progress update",
    )

    while connection_alive and len(completed) < total:
        for key, output_dir in project_outputs.items():
            if key in completed:
                continue
            state = _results_file_state(output_dir)
            if state is None or state == before[key]:
                continue
            completed.add(key)
            connection_alive = await _safe_send(
                connection_alive,
                # key and count bound now: the loop rebinds both, and a late
                # closure would report whichever project the sweep reached last.
                lambda k=key, done=len(completed): report_progress(
                    progress=float(done),
                    total=float(total),
                    message=raw_controls_on_one_line(
                        f"{k} complete ({done}/{total} projects)"
                    ),
                ),
                "Failed to send workspace progress update",
            )
            if not connection_alive:
                return
        if len(completed) >= total:
            return
        await asyncio.sleep(poll_interval)


async def monitor_scan_progress(
    ctx: Context, scan_id: str, session_id: Optional[str] = None
) -> None:
    """
    Monitor scan progress and report updates via the MCP context.

    Resilient to connection closures: if the client disconnects the monitor
    continues silently until the scan finishes or times out.

    Args:
        ctx: MCP context for reporting progress/log messages.
        scan_id: The scan ID returned by run_ash_scan.
        session_id: The session that started the scan, which is the only one
            the registry shows it to. None is the default session.
    """
    connection_alive = True
    try:
        scan_info = await _fetch_initial_scan_info(ctx, scan_id, session_id)
        if scan_info is None:
            return
        _, output_dir, _ = scan_info

        connection_alive = await _send_initial_progress(ctx)

        await _run_monitor_loop(
            ctx,
            scan_id,
            output_dir,
            connection_alive,
            session_id,
        )
    except asyncio.CancelledError:
        logger.info(f"Scan monitoring cancelled for scan_id: {scan_id}")
        await _safe_send(
            connection_alive,
            lambda: ctx.info("Scan monitoring stopped."),
            "Failed to send cancellation message",
        )
    except Exception as exc:
        # Eager format, same reason as the handler in _process_scanner_result
        # above: `exc` is unbound once this handler exits, so a lambda reading it
        # would raise NameError in place of the real error.
        error_message = f"Error monitoring scan progress: {str(exc)}"
        logger.exception(error_message)
        await _safe_send(
            connection_alive,
            lambda: ctx.error(raw_controls_on_one_line(error_message)),
            "Failed to send error message to client",
        )
