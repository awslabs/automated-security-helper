#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
MCP server implementation for ASH security scanning.

This module provides an MCP server implementation that strictly follows
the MCP protocol for ASH security scanning.
"""

import asyncio
import contextvars
import errno
import functools
import json
import logging
import os
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager, suppress
from typing import (
    Annotated,
    AsyncIterator,
    Callable,
    Dict,
    Any,
    Iterable,
    List,
    Literal,
    NamedTuple,
    Optional,
    Tuple,
)
from pathlib import Path

import anyio
from mcp.server.mcpserver import MCPServer, Context
from pydantic import Field

from automated_security_helper.cli.mcp_tools import (
    CONFIG_ENV_NOT_RESOLVED,
    REFUSED_CONFIG_EXIT_CODE,
    REFUSED_INTERNAL_EXIT_CODE,
    REFUSED_TARGET_EXIT_CODE,
    REFUSED_USAGE_EXIT_CODE,
    with_exit_code,
    mcp_scan_directory,
    mcp_get_scan_progress,
    mcp_get_scan_results,
    mcp_list_active_scans,
    mcp_cancel_scan,
    mcp_check_installation,
    mcp_get_config,
    mcp_list_scanners,
    mcp_diff_scan_results,
    mcp_validate_config,
    mcp_explain_finding,
    mcp_suggest_suppression,
    mcp_set_source_git,
    mcp_set_source_zip_chunk,
    mcp_set_source_zip_finalize,
    mcp_clear_source,
    mcp_list_profiles,
    mcp_select_profile,
    stop_running_scans,
    output_directory_refusal,
    source_directory_refusal,
    _results_file_outside_its_directory,
)
from automated_security_helper.core.committed_output import (
    COMMITTED_OUTPUT_REFUSED_EXIT_CODE,
    committed_entries_in_the_way,
    committed_output_files_error,
)
from automated_security_helper.core.constants import (
    ASH_EXIT_BAD_SELECTION,
    ASH_EXIT_BAD_SELECTION_MEANING,
    ASH_EXIT_CODES,
    ASH_EXIT_INTERRUPTED,
)
from automated_security_helper.core.exceptions import CommittedOutputFilesError
from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
)
from automated_security_helper.models.workspace import WorkspaceExitCode

from automated_security_helper.core.resource_management.scan_registry import (
    get_scan_registry,
)
from automated_security_helper.core.resource_management.scan_tracking import (
    UNKNOWN_SEVERITY,
    empty_severity_counts,
    resolves_to_directory_inside,
    summarize_scanner_statuses,
    restored_results_refusal,
)
from automated_security_helper.core.resource_management.result_filters import (
    ResultFilterInputError,
    filter_summary,
    filter_minimal,
    filter_actionable_only,
    apply_content_filters,
    add_findings_list,
)
from automated_security_helper.cli.mcp.profile_registry import (
    ProfileRegistryError,
    resolve_session_config_path,
)
from automated_security_helper.cli.mcp.sessions import (
    SESSION_WORKSPACE_BUSY,
    SessionWorkspaceBusyError,
)
from automated_security_helper.cli.mcp.progress_monitor import monitor_scan_progress
from automated_security_helper.cli.mcp.sandbox import (
    caller_is_remote,
    check_config_input,
)
from automated_security_helper.cli.mcp.scan_target import (
    OUTPUT_TREE_REFUSED_EXIT_CODE,
    resolve_scan_target,
    validate_output_tree,
    validate_scan_target,
)
from automated_security_helper.cli.mcp.session_identity import (
    resolve_caller_session_id,
    serving_local_client,
    session_identity_refusal,
)
from automated_security_helper.cli.mcp.source_delivery import (
    CLONE_MAX_WORKERS,
    DELIVERY_MAX_WORKERS,
    MAX_CLONE_DEPTH,
    delivered_session_count,
    get_session_source_dir,
)
from automated_security_helper.cli.mcp.workspace import (
    mcp_resolve_workspace,
    mcp_scan_workspace,
)
from automated_security_helper.utils.error_text import error_text, log_unexpected_error

# What a client reads and may display, an error or a message to its log, holds
# no control character: each is written as its escape, on one line.
from automated_security_helper.utils.terminal_text import raw_controls_on_one_line
from automated_security_helper.utils.log import (
    ASH_LOGGER,
    check_commands_of_stderr,
    check_commands_of_stdout,
    route_library_handlers_through_command_check,
)
from automated_security_helper.utils.subprocess_utils import kill_running_groups
from automated_security_helper.utils.threads import ash_thread

logger = ASH_LOGGER

#: Runs ``set_source_git``. A scan or any other ``asyncio.to_thread`` caller shares
#: the loop's default executor, so a clone that waits on a slow remote would take
#: a worker a scan needs; clones get their own, bounded. A clone holds a worker for
#: up to three git commands of 10 minutes each, so this pool is kept apart from
#: the one the quick deliveries use: sessions are cheap to open, and
#: ``CLONE_MAX_WORKERS`` cloning sessions fill it without delaying a chunk, a
#: clear or a finalize of any tenant.
_CLONE_EXECUTOR = ThreadPoolExecutor(
    max_workers=CLONE_MAX_WORKERS, thread_name_prefix="ash-mcp-clone"
)

#: Runs the other three source-delivery tools: appending a chunk, finalizing an
#: upload and clearing a session. They have their own pool so that no number of
#: clones queues them, at ``DELIVERY_MAX_WORKERS`` rather than the executor's
#: host-dependent default; see that constant.
_DELIVERY_EXECUTOR = ThreadPoolExecutor(
    max_workers=DELIVERY_MAX_WORKERS, thread_name_prefix="ash-mcp-delivery"
)


async def _run_on(
    executor: ThreadPoolExecutor, function: Callable[..., Any], kwargs: Dict[str, Any]
) -> Any:
    """Run ``function(**kwargs)`` on ``executor``, keeping the caller's context.

    Context variables are kept as ``asyncio.to_thread`` keeps them. Awaiting this
    and then cancelling does not stop the thread: the delivery finishes or times
    out server-side, and the session reads busy until then.

    The copy of the context is taken in the call, on the caller's thread, and
    is the callable the pool runs: the shape the thread-context check reads.
    """

    return await asyncio.get_running_loop().run_in_executor(
        executor, contextvars.copy_context().run, functools.partial(function, **kwargs)
    )


async def _run_clone(function: Callable[..., Any], /, **kwargs: Any) -> Any:
    """Run ``set_source_git``'s implementation on ``_CLONE_EXECUTOR``."""

    return await _run_on(_CLONE_EXECUTOR, function, kwargs)


async def _run_delivery(function: Callable[..., Any], /, **kwargs: Any) -> Any:
    """Run a chunk, finalize or clear implementation on ``_DELIVERY_EXECUTOR``."""

    return await _run_on(_DELIVERY_EXECUTOR, function, kwargs)


#: Whether the last shutdown of the two pools above (_wait_for_source_jobs) ended with a
#: clone or a delivery still running. run_mcp_server reads it on the way out.
_source_jobs_left_running = False


def _join_source_pools(executors: Tuple[ThreadPoolExecutor, ...]) -> None:
    """Return once every worker of ``executors`` has finished its job and exited."""

    for executor in executors:
        executor.shutdown(wait=True)


def _begin_stopping_source_jobs() -> threading.Thread:
    """Drop the queued clones and deliveries now; return the thread joining the rest.

    A pool that is not shut down is joined by the interpreter's own exit, which
    runs every job still queued and waits for each one that runs: a clone the
    client no longer waits for, for as long as git takes (three commands of up to
    ten minutes), or an extraction still writing into the workspace the server is
    about to remove. A job already running cannot be stopped from here, so it is
    waited for, for a bounded time, by _wait_for_source_jobs on the thread this
    returns. Nothing new is accepted afterwards: a call that comes in then fails
    on submitting.
    """

    executors = (_CLONE_EXECUTOR, _DELIVERY_EXECUTOR)
    for executor in executors:
        executor.shutdown(wait=False, cancel_futures=True)
    joiner = ash_thread(
        _join_source_pools,
        args=(executors,),
        name="ash-mcp-source-jobs-join",
        daemon=True,
    )
    joiner.start()
    return joiner


async def _wait_for_source_jobs(joiner: threading.Thread, deadline: float) -> bool:
    """Wait until ``deadline`` (``time.monotonic()``) for the jobs ``joiner`` joins.

    Returns whether any is still running, which is also kept in
    ``_source_jobs_left_running``. The join runs on a worker thread, so that the
    event loop stays free: the stdio serving's signal watcher runs on it.
    """

    global _source_jobs_left_running
    await asyncio.to_thread(joiner.join, max(0.0, deadline - time.monotonic()))
    _source_jobs_left_running = joiner.is_alive()
    return _source_jobs_left_running


# Backward-compatible private-name aliases (tests import these by name).
_filter_summary = filter_summary
_filter_minimal = filter_minimal
_filter_actionable_only = filter_actionable_only
_apply_content_filters = apply_content_filters
_add_findings_list = add_findings_list
_monitor_scan_progress = monitor_scan_progress

#: How long a stdio server whose client has left waits for its scans to stop.
#: Inside the window the client gives: the MCP SDK's stdio client closes the
#: server's stdin, sends SIGTERM to its process group two seconds later and
#: SIGKILL two seconds after that. A scanner's tool runs in a process group of its
#: own, which neither signal reaches, so the server has to have stopped it by
#: then. The scans are stopped promptly (PROMPT_STOP_GRACE_SECONDS after
#: SIGTERM), which with the quarter-second cancel poll fits in this.
STDIO_SCAN_STOP_TIMEOUT_SECONDS = 1.5

#: The signals that stop a stdio server, and the status it then exits with.
#: SIGTERM is a request to stop and ends the session as the client leaving does,
#: and so is SIGHUP, from a closed terminal or a supervisor, where the platform
#: has it; unhandled, it ended the process at once, leaving every scanner's tool
#: running in its own session and the previous results set aside. SIGINT is the
#: user's Ctrl-C (ASH_EXIT_INTERRUPTED, as on every transport).
_STOP_SIGNALS: Dict[int, int] = {signal.SIGTERM: 0, signal.SIGINT: ASH_EXIT_INTERRUPTED}
_SIGHUP = getattr(signal, "SIGHUP", None)
if _SIGHUP is not None:
    _STOP_SIGNALS[_SIGHUP] = 0


#: The stop signals a process may start with ignored, and then keeps ignored.
_KEPT_IGNORED = {signal.SIGINT} | ({_SIGHUP} if _SIGHUP is not None else set())


def _watched_stop_signals() -> Dict[int, int]:
    """_STOP_SIGNALS, without SIGINT or SIGHUP when the process started with it ignored.

    A shell starts a background job with SIGINT ignored, so that Ctrl-C reaches
    only the job in the foreground. Python and asyncio leave an ignored SIGINT
    ignored, and so does the server, on every transport: uvicorn, which serves
    the HTTP ones, is kept from replacing it (cli/mcp._uvicorn_server_class).
    nohup starts a command with SIGHUP ignored, so that it outlives the terminal
    it was started from, and the server leaves that ignored too, also on HTTP
    (cli/mcp._ask_server_to_stop_on_sighup). Nothing in
    `ash mcp` changes either before the server reads them here, so one that is
    ignored was ignored when the process started.
    """
    return {
        signum: status
        for signum, status in _STOP_SIGNALS.items()
        if signum not in _KEPT_IGNORED or signal.getsignal(signum) != signal.SIG_IGN
    }


#: True while run_mcp_server serves stdio. The lifespan stops scans only then: the
#: in-process test client and the HTTP transports enter the same lifespan, and
#: neither ends the process's scans when it closes.
_serving_stdio = False


@asynccontextmanager
async def _lifespan(_server: MCPServer) -> AsyncIterator[Dict[str, Any]]:
    """Stop the scans when a stdio client leaves, before stdout goes back to it.

    A stdio server's lifetime is its client's: the client started the process and
    is the only thing that can talk to it, so once it has closed the connection a
    running scan has no one to report to and nothing left to poll or collect it.
    Each is cancelled as cancel_scan would cancel it, which stops its scanner's
    tool with every process it started and puts the previous results in its
    output directory back, and the server waits for that before it exits. Promptly,
    within STDIO_SCAN_STOP_TIMEOUT_SECONDS, because the client kills the server
    shortly after it closes the connection. SIGTERM, SIGHUP and Ctrl-C end the
    session the same way (_stop_on_signal).

    It happens here, inside the transport, because the SDK points fd 1 at stderr
    only while it serves and back at the client's pipe once it returns: a scan
    still running then would write into the JSON-RPC channel. For the same
    reason sys.stdout is flushed here, while the bytes a scan printed during the
    session still go to stderr; a pipe makes it block-buffered, and its buffer
    would otherwise be flushed onto the wire at exit. Shielded, so a cancelled serving
    task still waits for the scans to stop: that is what Ctrl-C does where the
    server cannot watch for signals (_watches_signals).

    The source-delivery pools are stopped in the same window
    (_begin_stopping_source_jobs): the queued clones and deliveries are dropped
    at once, and the ones running get what is left of
    STDIO_SCAN_STOP_TIMEOUT_SECONDS after the scans, so that they are not still
    writing when run_mcp_server removes the stdio session workspace.
    """
    try:
        yield {}
    finally:
        if _serving_stdio:
            with anyio.CancelScope(shield=True):
                deadline = time.monotonic() + STDIO_SCAN_STOP_TIMEOUT_SECONDS
                joiner = _begin_stopping_source_jobs()
                await stop_running_scans(
                    "the stdio client closed the connection",
                    timeout=STDIO_SCAN_STOP_TIMEOUT_SECONDS,
                    promptly=True,
                )
                await _wait_for_source_jobs(joiner, deadline)
            # The process ends next, by the client's SIGTERM if not sooner; a tool
            # still running then would outlive it (_stop_on_signal).
            kill_running_groups()
            _flush_stdout()


mcp = MCPServer(name="ASH Security Scanner", lifespan=_lifespan)
# MCPServer() has just put the SDK's own handler on the root logger, when it had
# none, and the SDK logs a client's tool name through it.
route_library_handlers_through_command_check()


class _OmittedSourceResolution(NamedTuple):
    """Outcome of resolving ``run_ash_scan`` with no ``source_dir``.

    Exactly one field is set: ``source_dir`` when a target was resolved, or
    ``error`` when the call must be refused.
    """

    source_dir: Optional[str] = None
    error: Optional[Dict[str, Any]] = None


def _holds_an_entry(directory: Path) -> bool:
    """Whether ``directory`` is a directory with at least one entry in it.

    A delivered tree that is on disk but empty is the same false-negative shape
    as one that is gone: the scan runs and reports clean. A directory whose
    listing fails is read as holding nothing, so the caller refuses it as it
    refuses one that cannot be read.
    """
    try:
        if not directory.is_dir():
            return False
        return any(True for _ in directory.iterdir())
    except OSError:
        return False


def _entries_of(directory: Path) -> List[Path]:
    """The entries of ``directory``, sorted; none when it cannot be listed.

    The results readers walk a scan's output while the scan thread may be
    moving or rewriting that tree, and a results reader that walks the output
    of a scan another call is setting up meets the same. A directory that is
    gone, or is a file, by the time it is listed holds no results to add, and
    the poll goes on with what it has, instead of failing as a whole on one
    vanished directory.
    """
    try:
        return sorted(directory.iterdir())
    except OSError:
        return []


def _resolve_omitted_source_dir(session_id: str) -> _OmittedSourceResolution:
    """Decide what ``run_ash_scan()`` with no arguments should scan.

    WHY THIS REFUSES RATHER THAN GUESSING
    -------------------------------------
    The obvious implementation falls back to the process working directory when
    the session has no delivered tree, and that fallback is the dangerous kind:
    on a network transport the working directory is the *server's*, holds none of
    the caller's code, and scanning it completes normally and reports no
    findings. A caller cannot tell that from a clean repository. A security
    scanner that examined nothing and reads as clean is worse than one that
    fails, so the ambiguous cases are refused with a message naming the cause.

    The fallback survives only where it is unambiguous. A transport that carries
    no session header is a single local client -- stdio, where ``ash mcp`` runs
    in the tree the developer means and the working directory has always been the
    documented default. That case keeps working.

    THE CASE THIS EXISTS FOR
    ------------------------
    On Bedrock AgentCore the platform mints session ids, and whether the id the
    server receives is stable across requests in one session is not established
    (see cli/mcp/session_identity.py). If it rotates, an upload lands under one
    session directory and the scan looks under another. That shows up here as
    "this session has nothing, but some other session does", which is reported as
    exactly that rather than papered over -- the count of other delivering
    sessions is the tell, and it names the likely cause in the error.

    The registry record is checked against the filesystem rather than trusted.
    The two can disagree -- a delivery interrupted mid-swap, or anything outside
    the server removing the directory -- and a record pointing at a directory
    that is gone, or at one that is empty, is the same false-negative shape as
    the fallback above: the scan runs and reports clean.

    Args:
        session_id: The session this call resolved to.

    Returns:
        An :class:`_OmittedSourceResolution` carrying either a target path or a
        structured refusal.
    """

    from automated_security_helper.cli.mcp.profile_registry import (
        DEFAULT_SESSION_ID,
    )

    delivered = get_session_source_dir(session_id)
    if delivered is not None and _holds_an_entry(delivered):
        return _OmittedSourceResolution(source_dir=str(delivered))

    if delivered is not None:
        # Registered, but the directory is gone, cannot be read, or holds
        # nothing. Returning the path anyway would report "directory not found"
        # for a tree the server said it had, and an empty-but-present tree would
        # be worse still -- it scans and reports clean. Naming the state is what
        # makes it actionable, since re-delivering is the fix and the caller
        # cannot guess that from a missing-path error. A target the server
        # cannot scan, as a missing source_dir is.
        return _OmittedSourceResolution(
            error=with_exit_code(
                {
                    "success": False,
                    "error": raw_controls_on_one_line(
                        f"The source tree delivered under this session id is no "
                        f"longer on disk at {delivered}, or holds no file. Deliver "
                        f"it again with set_source_git or "
                        f"set_source_zip_chunk/set_source_zip_finalize. Refusing to "
                        f"scan: the recorded directory cannot be read, and scanning "
                        f"the server's working directory instead would report on a "
                        f"tree that is not yours."
                    ),
                    "error_type": "delivered_source_missing",
                    "session_id": session_id,
                },
                REFUSED_TARGET_EXIT_CODE,
            )
        )

    if session_id == DEFAULT_SESSION_ID:
        # stdio's single local client, where the working directory is the
        # documented default and is the tree the caller means. A network caller
        # never resolves to this id; see session_identity.resolve_caller_session_id.
        #
        # Checked BEFORE the cross-session diagnostic below, and the order is
        # load-bearing. The other-sessions signal is only meaningful for a caller
        # that HAS a session id; a caller with none cannot be the victim of an id
        # that rotated, so letting another session's delivery refuse this call
        # would break the documented stdio default for an unrelated reason.
        return _OmittedSourceResolution(source_dir=str(Path.cwd().absolute()))

    other_sessions = delivered_session_count()
    if other_sessions:
        # Somebody delivered source; this session is not who. Do not scan
        # anything -- naming another session's tree would be a cross-tenant read,
        # and the working directory is not what the caller meant either.
        # The request named no source_dir and has nothing to fall back on.
        return _OmittedSourceResolution(
            error=with_exit_code(
                {
                    "success": False,
                    "error": raw_controls_on_one_line(
                        "No source has been delivered under this session id, but "
                        f"{other_sessions} other session(s) currently hold delivered "
                        "source. This session id is most likely not stable across "
                        "calls, so the upload and this scan resolved to different "
                        "workspaces. Pass the source_dir that set_source_git or "
                        "set_source_zip_finalize returned, rather than omitting it. "
                        "Refusing to scan: falling back to the server's working "
                        "directory would report a clean result for a tree that is "
                        "not yours."
                    ),
                    "error_type": "session_source_mismatch",
                    "session_id": session_id,
                },
                REFUSED_USAGE_EXIT_CODE,
            )
        )

    return _OmittedSourceResolution(
        error=with_exit_code(
            {
                "success": False,
                "error": raw_controls_on_one_line(
                    "No source has been delivered under this session id, so there is "
                    "nothing to scan. Deliver a tree first with set_source_git or "
                    "set_source_zip_chunk/set_source_zip_finalize, or pass source_dir "
                    "explicitly. Refusing to scan: falling back to the server's "
                    "working directory holds none of your code, and would complete "
                    "with no findings and no error."
                ),
                "error_type": "no_source_delivered",
                "session_id": session_id,
            },
            REFUSED_USAGE_EXIT_CODE,
        )
    )


#: The context's log methods. ``_tell_client`` refuses any other name before it
#: touches the context, so a mistyped level is a loud coding mistake instead of
#: a message that silently never arrives.
_CLIENT_LOG_LEVELS = frozenset(("debug", "info", "warning", "error"))


async def _tell_client(
    ctx: Context,
    level: Literal["debug", "info", "warning", "error"],
    message: str,
) -> None:
    """Send ``message`` to the client at ``level``, without a failed send raising.

    ``level`` is the name of the context's log method: ``debug``, ``info``,
    ``warning`` or ``error``. Every log a tool sends goes through here.

    The log is a courtesy: the result a tool returns is what the client acts on.
    A client whose transport has closed makes every send raise, whatever its
    level, and that must not replace the tool's own result with an exception. It
    must not turn a success into a failure either: a scan that has started stays
    reported with its scan_id, so the client can follow and cancel it.

    A mistyped ``level`` is not a failed send, it is a coding mistake, so it is
    checked and the method looked up before the guard: swallowed with the failed
    sends, the message would never reach the client and nothing would name the
    mistake.
    """
    if level not in _CLIENT_LOG_LEVELS:
        raise ValueError(
            f"Unknown client log level {level!r}; expected one of "
            f"{sorted(_CLIENT_LOG_LEVELS)}"
        )
    send = getattr(ctx, level)
    try:
        await send(message)
    except Exception:
        # A closed transport is the expected condition here: one line at warning
        # names the lost send, and the traceback stays at debug, matching the
        # monitor's _safe_send instead of an ERROR traceback per send. The line
        # names the send by its level and size, never by its text: every message
        # a tool hands here is already shown text (its controls escaped for the
        # client), and a log line that repeats it shows it a second time, so a
        # name holding an escape reads as the text of one. The tool's own result
        # carries what the client needed; the log is the courtesy that was lost.
        # Nothing of the message reaches the log, not even its size: the
        # shown-twice check reads any value derived from it in a log call as
        # the text shown again, and the failure path must not raise over a
        # message that is not a str either.
        logger.warning(
            f"Failed to send {level} message to client; "
            "the tool's result carries what it said"
        )
        logger.debug(f"The {level} send that failed, with why:", exc_info=True)


async def _tell_client_error(ctx: Context, message: str) -> None:
    """Send ``message`` to the client as an error log, without ever raising."""
    await _tell_client(ctx, "error", message)


async def _profile_needs_a_session(
    ctx: Context, session_id: str, profile: Optional[str], operation: str
) -> Optional[Dict[str, Any]]:
    """The refusal a workspace tool returns when an unidentified caller names a profile.

    The workspace tools need no session of their own, but a ``profile`` named
    on the call is materialized into the caller's session workspace, and a
    caller the server could not identify has none. Left to the workspace
    module, that call fails on the missing workspace, which it reports as an
    invalid config (exit 3): a config refusal for a request that named a valid
    profile, with nothing in the answer naming the cause. The cause is the
    request's missing session, so it is refused here the way every session
    tool refuses it, with the same error_type (session_identity_required) and
    the same usage code. None when no profile was named, or the caller has a
    session.
    """
    if profile is None:
        return None
    refusal = session_identity_refusal(session_id, operation, ctx=ctx)
    if refusal is None:
        return None
    await _tell_client_error(ctx, raw_controls_on_one_line(refusal["error"]))
    return with_exit_code(refusal, REFUSED_USAGE_EXIT_CODE)


@mcp.tool()
async def run_ash_scan(
    ctx: Context,
    source_dir: Optional[str] = None,
    severity_threshold: Optional[str] = None,
    config_path: Optional[str] = None,
    clean_output: bool = True,
) -> Dict[str, Any]:
    """
    Start a security scan and return immediately.

    This tool starts a scan and returns immediately with a scan ID.
    Progress updates will be reported through the MCP context.

    Poll get_scan_progress(scan_id) every 5 seconds for progress updates.
    The scan continues server-side independently of the client connection.
    Stop polling when progress['is_complete'] is true, then read
    progress['status'].

    is_complete becomes true when the scan ends, in any of 'completed',
    'incomplete', 'failed' or 'cancelled'. results_available is true for
    'completed' and 'incomplete', the two whose results get_scan_results can
    read. 'incomplete' means the run finished and its results are readable, but
    one or more selected scanners did not complete: treat it as terminal with
    partial coverage and read incomplete_scanners for which and why.

    Example usage:
        result = run_ash_scan(source_dir="/path/to/project")
        scan_id = result['scan_id']

        # Poll until is_complete is true, then read the status
        while True:
            progress = get_scan_progress(scan_id=scan_id)
            if progress.get('is_complete'):
                break
            time.sleep(5)  # Poll every 5 seconds

        # Completed and incomplete scans have readable results; for failed or
        # cancelled scans, read the status and error before retrying.
        if progress.get('results_available'):
            results = get_scan_results(
                output_dir=progress['output_directory'],
                filter_level="summary",
                actionable_only=True
            )

    Args:
        source_dir: Path to the directory to scan. This should be the absolute path!
            Omit it to scan a source tree this session delivered with
            set_source_git or set_source_zip_finalize.
        severity_threshold: The least severe finding that still counts as actionable:
            ALL, LOW, MEDIUM, HIGH or CRITICAL, in any case. It can make the
            config's global_settings.severity_threshold stricter for this scan,
            never looser: the scan runs at the stricter of the two, which decides
            which findings are actionable and whether a scanner reports FAILED.
            Omit it to use the config's own threshold (MEDIUM unless the config
            sets one).
        config_path: Optional path to ASH configuration file
        clean_output: Hide the previous scan's results when this call starts the scan.
            Either way they are put back if this scan fails or is cancelled, and
            replaced once it finishes; with false they stay visible until the scan's
            own set-up moves them a moment later. A call refused because the
            directory already has a scan touches nothing in it.

    Refused (error_type source_delivery_busy) while clear_source, set_source_git
    or set_source_zip_finalize is changing this session's delivered source;
    call it again once that call has returned.

    Needs a session, because get_scan_progress and cancel_scan do: refused
    (error_type session_identity_required) on a stateless server run without
    --trust-upstream-session-id. run_ash_workspace_scan returns its results in
    its response and needs none.

    On a network transport a session runs at most the operator's
    max_concurrent_scans_per_session scans at once (default 2); one more is
    refused (error_type session_scan_limit) until one has finished.

    Returns:
        Dict with scan_id, status, and connection management guidance. A refused
        scan returns `success` false, `error_type`, and the `exit_code` the CLI
        exits with for the same refusal, with its `exit_code_meaning`: 3 for a
        config that is refused or unusable, a link at `.ash` or
        `.ash/ash_output` in source_dir (as run_ash_workspace_scan reports one
        in its output tree), or a file git tracks in `.ash/ash_output` where the
        scan writes, or cannot say whether it does (`error_type`
        committed_output_files); 5 for the request itself (an unusable session
        header, no session at all (`session_identity_required`), an unusable
        severity_threshold, a source_dir that is missing or not a directory, or
        no source_dir with nothing delivered); 4 for a target the
        server will not scan (outside the permitted roots, or a delivered tree
        no longer on disk); 1 for anything else, another scan of the same
        directory included.
    """
    try:
        try:
            session_id = resolve_caller_session_id(ctx)
        except ValueError as e:
            await _tell_client_error(ctx, raw_controls_on_one_line(error_text(e)))
            return _scan_session_error(e)

        # A scan is followed with get_scan_progress and stopped with cancel_scan,
        # and both need a session. A caller the server could not identify would
        # start a scan it can neither follow nor stop, so it starts none.
        refusal = session_identity_refusal(session_id, "run_ash_scan", ctx=ctx)
        if refusal is not None:
            await _tell_client_error(ctx, raw_controls_on_one_line(refusal["error"]))
            # A call that carries no session is the request's own fault, as an
            # unusable session header is, so it reports the same usage code.
            return with_exit_code(refusal, REFUSED_USAGE_EXIT_CODE)

        # An empty or blank source_dir names no directory: it is the omitted
        # form, which resolves to the delivered tree or refuses, never the
        # server's working directory (Path("") is the working directory).
        if source_dir is None or not source_dir.strip():
            resolved = _resolve_omitted_source_dir(session_id)
            if resolved.error is not None:
                await _tell_client_error(
                    ctx, raw_controls_on_one_line(resolved.error["error"])
                )
                return resolved.error
            source_dir = resolved.source_dir
        # The working directory is the server's filesystem layout, which this
        # module withholds from a network caller (_resolve_omitted_source_dir):
        # only the local client, whose directory it is, is told it.
        await _tell_client(
            ctx,
            "info",
            "run_ash_scan tool called"
            if caller_is_remote(session_id)
            else raw_controls_on_one_line(
                f"run_ash_scan tool called in cwd: {Path.cwd()}"
            ),
        )
        if not Path(source_dir).is_absolute():
            source_dir = str(Path.cwd() / source_dir)

        # A profile this session bound with select_profile supplies the config
        # when the caller names none. The caller's own config_path wins, because
        # naming one on the call is the more specific statement and silently
        # replacing it would make the explicit argument a lie.
        #
        # Nothing is invented for an unbound session: config_path stays None and
        # ASH's own discovery finds an in-tree .ash.yaml as it always has.
        config_check = None
        if config_path is None:
            try:
                config_path = resolve_session_config_path(session_id)
            except ProfileRegistryError as exc:
                # The bound profile's file is gone and cannot be written again
                # (the profile is no longer registered, or the session's
                # workspace cannot be written). A config refusal, exit 3, as a
                # named config that cannot be used is; not the catch-all's
                # internal error, which would log it as an ASH bug.
                await _tell_client_error(ctx, raw_controls_on_one_line(str(exc)))
                return with_exit_code(
                    {
                        "success": False,
                        "error": raw_controls_on_one_line(str(exc)),
                        "error_type": "bound_profile_unavailable",
                        "error_category": ErrorCategory.FILE_NOT_FOUND.value,
                    },
                    REFUSED_CONFIG_EXIT_CODE,
                )
            except SessionWorkspaceBusyError as exc:
                # The bound profile's file is gone and another request holds
                # the session's workspace (its removal by the TTL sweep, a
                # clear, the end of the session), so it is not written again
                # under that removal: the hold's own refusal, as select_profile
                # answers it, and the scan is asked for again once it ends.
                await _tell_client_error(ctx, raw_controls_on_one_line(str(exc)))
                return {
                    "success": False,
                    "error": raw_controls_on_one_line(str(exc)),
                    "error_type": SESSION_WORKSPACE_BUSY,
                }
            if config_path is not None:
                await _tell_client(
                    ctx,
                    "info",
                    raw_controls_on_one_line(
                        f"Using the config bound to this session by select_profile: "
                        f"{config_path}"
                    ),
                )
        else:
            # Caller-named, so it is caller-supplied input and gets the same
            # boundary the workspace tools' config inputs get. Without this the
            # scan tool would be the one unconfined config read left. Every base
            # its `extends` chain names is checked the same way, against the scan
            # target the chain will be resolved for. mcp_scan_directory is handed
            # the result, so the file is read once.
            config_check = check_config_input(
                config_path, session_id=session_id, source_dir=source_dir
            )
            config_error = config_check.refusal
            if config_error:
                await _tell_client_error(
                    ctx, raw_controls_on_one_line(str(config_error))
                )
                return with_exit_code(
                    {
                        "success": False,
                        "error": raw_controls_on_one_line(str(config_error)),
                        "error_type": "config_input_not_permitted",
                        "error_category": config_error.context["error_category"],
                    },
                    REFUSED_CONFIG_EXIT_CODE,
                )

        # Check the root policy before acting on the target in any way. The scan
        # writes inside the caller-named directory, and clean_output moves the
        # previous results there, so neither may happen for a target the policy
        # refuses. mcp_scan_directory checks this again for callers that reach it
        # directly.
        #
        # The session id is passed so that this session's own workspace counts as
        # a permitted root. Without it a delivered tree is refused by the very
        # allowlist the operator set to bound the scan surface, since no operator
        # lists a directory the server invented per connection.
        target = resolve_scan_target(source_dir, session_id=session_id)
        if target.error is not None:
            await _tell_client_error(ctx, raw_controls_on_one_line(str(target.error)))
            return with_exit_code(
                {
                    "success": False,
                    "error": raw_controls_on_one_line(str(target.error)),
                    "error_type": "scan_target_not_permitted",
                    # Mirrors the category create_error_response sets on the
                    # mcp_tools side, so one key identifies a refusal from any
                    # entry point rather than two depending on which tool was
                    # called.
                    "error_category": target.error.context["error_category"],
                },
                REFUSED_TARGET_EXIT_CODE,
            )
        resolved_target = target.require()

        # A permitted target that cannot be scanned (missing, not a directory, or
        # one that cannot be entered) is refused before anything looks beneath it,
        # with the exit code the CLI uses for it.
        source_refusal = source_directory_refusal(source_dir, "run_ash_scan")
        if source_refusal is not None:
            await _tell_client_error(
                ctx, raw_controls_on_one_line(source_refusal["error"])
            )
            return source_refusal

        # The policy canonicalized the target and nothing beneath it. The scan and
        # clean_output write inside <target>/.ash, which would follow a symlinked
        # .ash out of the permitted roots, so the tree is checked before anything
        # reads or writes through it. The exit code is the one
        # run_ash_workspace_scan reports for the same link.
        output_error = validate_output_tree(resolved_target, ".ash", "ash_output")
        if output_error is not None:
            await _tell_client_error(ctx, raw_controls_on_one_line(str(output_error)))
            return with_exit_code(
                {
                    "success": False,
                    "error": raw_controls_on_one_line(str(output_error)),
                    "error_type": "output_dir_not_permitted",
                    "error_category": output_error.context["error_category"],
                },
                OUTPUT_TREE_REFUSED_EXIT_CODE,
            )

        directory_path_obj = Path(source_dir)
        output_dir = resolved_target.joinpath(".ash", "ash_output")

        # A file where the output directory goes is refused as scan_directory
        # refuses it, before the committed-files check below reads beneath it.
        output_refusal = output_directory_refusal(output_dir, "run_ash_scan")
        if output_refusal is not None:
            await _tell_client_error(
                ctx, raw_controls_on_one_line(output_refusal["error"])
            )
            return output_refusal

        # Before the scan starts, and so before clean_output sets the previous
        # results aside: a file git tracks where the scan deletes or writes its own
        # is refused here as the CLI refuses it (core/committed_output.py), and so
        # is any file there when git cannot say what is committed, which the check
        # raises. mcp_scan_directory refuses it too, for a caller that reaches it
        # directly.
        committed_refusal: Optional[CommittedOutputFilesError] = None
        try:
            committed = committed_entries_in_the_way(output_dir)
        except CommittedOutputFilesError as unverified:
            committed_refusal = unverified
        else:
            if committed:
                committed_refusal = committed_output_files_error(output_dir, committed)
        if committed_refusal is not None:
            await _tell_client_error(
                ctx, raw_controls_on_one_line(str(committed_refusal))
            )
            # The code the CLI exits with for the same tree.
            return with_exit_code(
                {
                    "success": False,
                    "error": raw_controls_on_one_line(str(committed_refusal)),
                    "error_type": "committed_output_files",
                    "error_category": ErrorCategory.INVALID_PATH.value,
                },
                COMMITTED_OUTPUT_REFUSED_EXIT_CODE,
            )

        await _tell_client(
            ctx,
            "info",
            raw_controls_on_one_line(f"Starting scan for directory: {source_dir}"),
        )

        # session_id is what engages the per-session scan lock in
        # mcp_scan_directory. Two scans in one session write the same
        # <workspace>/<session>/source tree and the same .ash output inside it, so
        # they have to serialize; scans in different sessions still run in
        # parallel because they contend on different locks.
        #
        # Nothing is deleted or set aside here: mcp_scan_directory (with
        # clean_output) or the scan's own set-up sets the previous results
        # aside, both only once the registry has given the scan the directory,
        # so a call refused because another scan is running there leaves that
        # scan's output alone.
        result = await mcp_scan_directory(
            directory_path=source_dir,
            severity_threshold=severity_threshold,
            config_path=config_path,
            session_id=session_id,
            config_check=config_check,
            clean_output=clean_output,
        )

        for warning in result.get("warnings") or []:
            await _tell_client(ctx, "warning", raw_controls_on_one_line(str(warning)))

        if result.get("error_type") == CONFIG_ENV_NOT_RESOLVED:
            # A refusal of the config, reported as itself like the
            # config_input_not_permitted refusal above, not as a failure to
            # start. Passed on as mcp_scan_directory gave it, so the caller
            # sees the same error_type, category and exit code.
            await _tell_client_error(
                ctx, raw_controls_on_one_line(str(result["error"]))
            )
            return result
        if not result.get("success", False):
            # Refused before the output directory was touched: nothing to undo.
            # Passed on as mcp_scan_directory gave it, so a caller of either tool
            # sees the same error_type, category and exit code for one refusal.
            await _tell_client_error(
                ctx,
                raw_controls_on_one_line(
                    f"Failed to start scan: {result.get('error', 'Unknown error')}"
                ),
            )
            if "exit_code" not in result:
                # Every refusal this tool returns carries the code the CLI exits
                # with (the docstring's contract). The ones mcp_scan_directory
                # shapes without one, a session whose delivered source is being
                # changed and a session at its scan limit, are the "anything
                # else" case there, with another scan of the same directory.
                with_exit_code(result, REFUSED_INTERNAL_EXIT_CODE)
            return result
        if "scan_id" not in result:
            await _tell_client_error(
                ctx, "Failed to start scan: no scan id was returned"
            )
            return with_exit_code(
                {
                    "success": False,
                    "error": "Failed to start scan: no scan id was returned",
                    "error_type": "scan_start_failure",
                },
                REFUSED_INTERNAL_EXIT_CODE,
            )

        scan_id = result["scan_id"]
        await _tell_client(
            ctx, "info", raw_controls_on_one_line(f"Scan started with ID: {scan_id}")
        )

        try:
            await ctx.report_progress(
                progress=0.0,
                total=1.0,
                message="Scan started, initializing scanners...",
            )
        except Exception as e:
            logger.warning(f"Failed to send initial progress update: {error_text(e)}")

        monitor_task = asyncio.create_task(
            monitor_scan_progress(ctx, scan_id, session_id=session_id)
        )
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
            "session_id": session_id,
            "important": {
                "connection_management": (
                    "Poll get_scan_progress(scan_id) every 5 seconds for updates. "
                    "The scan continues server-side independently of the client connection. "
                    "Stop when is_complete is true, then read the status: "
                    "completed, incomplete, failed or cancelled."
                ),
                "next_steps": [
                    "1. Store scan_id and poll get_scan_progress(scan_id) every 5 seconds",
                    "2. Stop polling when is_complete is true, then read the status: completed, incomplete, failed, or cancelled",
                    "3. Fetch results for completed or incomplete scans and review coverage; for failed or cancelled scans, read the status and error before retrying",
                ],
            },
        }

    except Exception as e:
        log_unexpected_error(logger, e, "Error in run_ash_scan")
        await _tell_client_error(
            ctx, raw_controls_on_one_line(f"Error running scan: {error_text(e)}")
        )
        return with_exit_code(
            {
                "success": False,
                "error": raw_controls_on_one_line(
                    f"Error running scan: {error_text(e)}"
                ),
                "error_type": type(e).__name__,
            },
            REFUSED_INTERNAL_EXIT_CODE,
        )


@mcp.tool()
async def resolve_ash_workspace(
    ctx: Context,
    workspace_file: str,
    workspace_config: Optional[str] = None,
    allow_missing_projects: bool = False,
    config_overrides: Optional[list] = None,
    profile: Optional[str] = None,
) -> Dict[str, Any]:
    """Resolve a VS Code workspace file into a scan plan without scanning anything.

    The MCP equivalent of `ash --workspace <file> --dry-run`. Reads the workspace
    definition and every project's own ASH config, then reports which directories
    became projects, what key each was given, which scanners its config enables,
    which severity threshold it will be judged against, and which projects were
    dropped and why. Nothing is scanned and no output tree is written, so this is
    the cheap way to check a workspace before committing to N repository scans.

    Call this first when a workspace is unfamiliar, then run_ash_workspace_scan on
    the same arguments: the scan resolves the same plan from the same inputs.

    Args:
        workspace_file: Absolute path to the .code-workspace file.
        workspace_config: Optional path to a workspace policy file. Must exist if
            given; ASH will not fall back to searching for one.
        allow_missing_projects: Mark project directories that are absent or
            unreadable as skipped instead of refusing the workspace.
        config_overrides: Optional list of `key=value` config overrides, applied to
            each project's config so the reported threshold is the enforced one.
        profile: Name of a registered config profile to resolve under for this one
            call, instead of whatever select_profile bound to this session. Call
            list_profiles to see what the operator registered. The fields the
            profile sets are final for every project, and a project's own config
            fills the rest.

    Returns:
        Dict with `plan` (the rendered plan, for a human to read), `projects` (the
        same decisions structured), `session_config_path` (the config a scan of
        this plan would run under, or null), and `exit_code` -- 0 on success, 4 for
        a workspace definition, policy or confinement problem, 3 for a project
        whose own config is invalid, an unknown profile, or a workspace
        definition, policy file or project config outside the directories the
        session may read config from (`error_type` config_input_not_permitted,
        whether the caller named it or ASH found it), 5 for an unusable
        session header, and 1 for anything else. A refusal carries the code's
        `exit_code_meaning` too.
    """
    try:
        session_id = resolve_caller_session_id(ctx)
    except ValueError as e:
        await _tell_client_error(ctx, raw_controls_on_one_line(error_text(e)))
        return _scan_session_error(e)

    profile_refusal = await _profile_needs_a_session(
        ctx, session_id, profile, "resolve_ash_workspace"
    )
    if profile_refusal is not None:
        return profile_refusal

    try:
        await _tell_client(
            ctx,
            "info",
            raw_controls_on_one_line(f"Resolving ASH workspace: {workspace_file}"),
        )
        response = await mcp_resolve_workspace(
            workspace_file=workspace_file,
            workspace_config=workspace_config,
            allow_missing_projects=allow_missing_projects,
            config_overrides=list(config_overrides) if config_overrides else None,
            session_id=session_id,
            profile=profile,
        )
        if not response.get("success", False):
            await _tell_client_error(
                ctx,
                raw_controls_on_one_line(str(response.get("error", "Unknown error"))),
            )
        return response
    except Exception as e:
        log_unexpected_error(logger, e, "Error in resolve_ash_workspace")
        await _tell_client_error(
            ctx, raw_controls_on_one_line(f"Error resolving workspace: {error_text(e)}")
        )
        return with_exit_code(
            {
                "success": False,
                "error": raw_controls_on_one_line(
                    f"Error resolving workspace: {error_text(e)}"
                ),
                "error_type": type(e).__name__,
            },
            int(WorkspaceExitCode.INTERNAL_ERROR),
        )


@mcp.tool()
async def run_ash_workspace_scan(
    ctx: Context,
    workspace_file: str,
    workspace_config: Optional[str] = None,
    allow_missing_projects: bool = False,
    config_overrides: Optional[list] = None,
    output_dir: Optional[str] = None,
    scanners: Optional[list] = None,
    excluded_scanners: Optional[list] = None,
    offline: bool = False,
    clean_output: bool = True,
    profile: Optional[str] = None,
) -> Dict[str, Any]:
    """Scan every project in a VS Code workspace and return the per-project verdict.

    The MCP equivalent of `ash --workspace <file>`. Each project is scanned with
    its own ASH config and its own severity threshold, a workspace policy file can
    impose a ceiling over all of them, and the results are aggregated into one
    workspace payload.

    Unlike run_ash_scan this call does not return early: it waits for the whole
    workspace and returns the verdict. Progress is reported as completed projects
    over total projects, with the project key in the message, so a client watching
    progress notifications can see which project is finishing.

    Every project gets its own entry in the scan registry, so the `scan_ids` map in
    the response can be used with get_scan_progress and get_scan_results per
    project. A project skipped at resolution gets no entry and no id. cancel_scan
    with one project's id stops that project, and the others carry on. A caller
    with no session the server issued still gets its results in this response,
    but get_scan_progress and cancel_scan need a session, so they refuse that
    caller's `scan_ids`.

    Server limits: the scan counts as one scan against the server's
    max_concurrent_scans however many projects it has, and is refused the way
    run_ash_scan is when no slot is free. The server's scan_timeout_seconds covers
    the whole workspace scan: past it every project is stopped and marked failed,
    and the call returns `success` false with `error_category`
    `operation_timeout` and the `scan_ids`.

    Confinement: `ASH_MCP_ALLOWED_ROOTS` governs the project directories, plus this
    session's own workspace so a tree delivered with set_source_git or
    set_source_zip_finalize is scannable. One project outside the permitted roots
    refuses the whole workspace rather than scanning the rest -- a green result
    covering fewer projects than you asked for is the outcome that refusal exists to
    prevent. The .code-workspace file and the workspace policy file are config
    inputs, governed by `ASH_MCP_ALLOWED_CONFIG_ROOTS` on a network transport.

    When this session has delivered a tree, the scan holds it until the scan's
    work is done, even if this call is cancelled first: clear_source,
    set_source_git and set_source_zip_finalize are refused meanwhile (error_type
    source_delivery_busy), and this call is refused the same way while one of
    them is changing the tree.

    Not available in container mode; workspace mode runs locally.

    Args:
        workspace_file: Absolute path to the .code-workspace file.
        workspace_config: Optional path to a workspace policy file.
        allow_missing_projects: Skip absent or unreadable project directories
            rather than refusing the workspace.
        config_overrides: Optional list of `key=value` config overrides.
        output_dir: Where to write the workspace output tree. Defaults to
            `<workspace root>/.ash/ash_output`. Refused when it, a directory or
            file ASH writes in it, or a project's `projects/<key>` is a symlink.
        scanners: Restrict every project to these scanner names.
        excluded_scanners: Exclude these scanners from every project. Takes
            precedence over `scanners`.
        offline: Run without network access.
        clean_output: Hide each project's previous results once the scan has its
            directory. Either way they are put back for a project whose scan does
            not finish. A scan refused because a project already has a scan
            touches nothing in any project's output.
        profile: Name of a registered config profile to scan under for this one
            call, instead of whatever select_profile bound to this session. An
            unknown name refuses the whole scan; running N repository scans under
            the default config because a profile name was misspelled, and
            reporting success, is the outcome a whole-workspace refusal exists
            to prevent, as one project outside the permitted roots refuses the
            whole workspace. The fields the profile sets are final for every
            project, and a project's own config fills the rest. Needs a session:
            refused (error_type session_identity_required) for a caller with no
            session the server issued, because the profile is materialized into
            the caller's session workspace.

    Returns:
        Dict with `scan_ids` (project key to registry scan id), `projects` (each
        project's status, finding counts and threshold verdict), `results_path`,
        `session_config_path` (the config the scan ran under, or null), and
        `exit_code`. `success` reports whether the scan ran; the verdict is
        `exit_code`.

        On success, `exit_code` is the workspace's verdict: 3 when a project's
        own config is invalid; else 2 when a project has actionable findings, at
        or above its effective severity threshold; else 1 when a project failed,
        or completed with a scanner that did not run to the end; 4 when no
        project was attempted and none was skipped as unchanged; 0 when none of
        these holds.

        On failure (`success` false), `exit_code` is 4 for a workspace
        definition, policy or confinement refusal, 3 for an invalid config (an
        unknown profile, a refused override, or a project's own), a workspace
        definition, policy file or project config outside the directories the
        session may read config from (`error_type` config_input_not_permitted,
        whether the caller named it or ASH found it, as run_ash_scan reports
        one), or a link in the output tree, as run_ash_scan reports
        one, 5 for a
        `scanners` selection no project can run (an unknown name, or every one
        excluded) or an unusable session header, and 1 for anything else, the
        server's timeout included.
    """
    try:
        session_id = resolve_caller_session_id(ctx)
    except ValueError as e:
        await _tell_client_error(ctx, raw_controls_on_one_line(error_text(e)))
        return _scan_session_error(e)

    profile_refusal = await _profile_needs_a_session(
        ctx, session_id, profile, "run_ash_workspace_scan"
    )
    if profile_refusal is not None:
        return profile_refusal

    try:
        await _tell_client(
            ctx,
            "info",
            raw_controls_on_one_line(f"Starting ASH workspace scan: {workspace_file}"),
        )
        # No filesystem work happens here. The confinement check needs the
        # resolved project directories, so it lives inside mcp_scan_workspace,
        # which runs it immediately after resolution and before its first mkdir or
        # clean_output deletion -- the same ordering run_ash_scan enforces above by
        # checking the policy before touching the target.
        response = await mcp_scan_workspace(
            workspace_file=workspace_file,
            workspace_config=workspace_config,
            allow_missing_projects=allow_missing_projects,
            config_overrides=list(config_overrides) if config_overrides else None,
            output_dir=output_dir,
            scanners=list(scanners) if scanners else None,
            excluded_scanners=list(excluded_scanners) if excluded_scanners else None,
            offline=offline,
            clean_output=clean_output,
            progress_reporter=ctx.report_progress,
            session_id=session_id,
            profile=profile,
        )
        if not response.get("success", False):
            await _tell_client_error(
                ctx,
                raw_controls_on_one_line(str(response.get("error", "Unknown error"))),
            )
            return response

        await _tell_client(
            ctx,
            "info",
            raw_controls_on_one_line(
                f"Workspace scan finished with exit code {response.get('exit_code')} "
                f"across {len(response.get('scan_ids', {}))} project(s)"
            ),
        )
        return response
    except Exception as e:
        log_unexpected_error(logger, e, "Error in run_ash_workspace_scan")
        await _tell_client_error(
            ctx,
            raw_controls_on_one_line(f"Error running workspace scan: {error_text(e)}"),
        )
        return with_exit_code(
            {
                "success": False,
                "error": raw_controls_on_one_line(
                    f"Error running workspace scan: {error_text(e)}"
                ),
                "error_type": type(e).__name__,
            },
            int(WorkspaceExitCode.INTERNAL_ERROR),
        )


@mcp.tool()
async def get_scan_progress(ctx: Context, scan_id: str) -> Dict[str, Any]:
    """
    Get current progress and partial results for a running scan.

    Poll this tool every 5 seconds for status updates and to see the ending
    as soon as the scan reaches it. The scan continues server-side
    independently of the client connection: polling keeps nothing alive.
    Poll from the session that started the scan, which is the only one that
    can read it (below).

    Usage pattern:
        while True:
            progress = get_scan_progress(scan_id=scan_id)
            if progress.get('is_complete'):
                break
            time.sleep(5)  # Wait 5 seconds before next check

    Only a scan this session started is visible: another session's scan id
    answers exactly like an id that was never issued.

    Args:
        scan_id: The scan ID returned from run_ash_scan

    Returns:
        Dict with progress info including:
        - success: False when the poll itself failed, in which case `error`
          describes why and no other key below is populated.
        - is_complete: True once the scan has ended, whatever the ending:
          `completed`, `incomplete`, `failed` or `cancelled`. Poll until it is
          true; `status` says which ending it was. It is not a statement that
          every scanner ran; `coverage_complete` is.
        - results_available: True for `completed` and `incomplete`, the scans
          whose results get_scan_results can read; False while running and for
          `failed` or `cancelled`.
        - output_holds_previous_results: True when the scan ended without
          results and ASH put the previous scan's results back in
          `output_directory`. The scanner fields below are then empty, because
          those files are not this scan's.
        - status: Current status (pending, running, completed, incomplete,
          failed, cancelled). `incomplete` is terminal: the run finished and
          produced results, but coverage has a gap -- a selected scanner was
          MISSING or ERROR or lost targets, no scanner reached a verdict, a
          converter did not run or could not convert some of its inputs, a
          rule could not be evaluated, or a content
          database was past its declared age bound. Its
          findings are real and partial. `failed` means the run crashed or
          produced no readable results.
        - error_message: Why a `failed` scan failed. For a run ASH refused or
          gave up, "ASH exited with code N: " and the text the CLI shows for
          it, on one line, with terminal controls written as escapes.
        - exit_code / exit_code_meaning: For a `failed` scan that ASH ended with
          an exit or an error, the code the CLI exits with and its meaning: 3 for a config
          that does not validate or files git tracks where the scan writes, 1
          for an error during the scan. None otherwise: while the scan runs, for
          one that finished (an MCP scan runs without the findings gate, so it
          has no CLI verdict), one that was cancelled, and one the server
          stopped at its timeout.
        - severity_threshold: The threshold the scan's findings were judged by,
          the stricter of run_ash_scan's severity_threshold and the config's.
          None until the scan finishes with results (`completed` or
          `incomplete`), and for a scan that failed or was cancelled.
        - requested_severity_threshold: The severity_threshold run_ash_scan was
          called with, upper-cased, or None. A request looser than the config's
          threshold is not applied, so this is not the threshold the scan ran at.
        - coverage_complete: True when nothing below names a gap, False when
          something does, None while running and for failed or cancelled scans.
          Reported whatever the completeness gate says, so a scan run with
          `fail_on_incomplete_scanners: false` is `completed` with
          `coverage_complete: false` when scanners did not run.
        - incomplete_scanners: Each selected scanner that did not complete, as
          `scanner`, `status` (MISSING, ERROR, FAILED for a current scan's
          partial loss whose surviving findings fail the severity gate, FAILED
          for findings that outrank a tree that went unevaluated, with
          `detail` reading `FAILED (MISSING on some files)`, or a status an
          older results file kept despite lost targets), `reason`
          and `detail`. `reason` is
          `partial_coverage` whenever the recorded counts show a partial audit
          (some targets evaluated, some not), whatever the status says;
          otherwise `missing_dependencies`, `error`, or `unrecognized_status`
          from the status token. A FAILED row reads `partial_coverage` with
          or without counts.
        - no_scanner_ran: Scanners were expected and none reached a verdict.
        - incomplete_converters: Converters that should have run and did not,
          and converters that ran and could not convert some of their inputs,
          each with `converter`, `reason` and `failed_input_kinds` (the
          distinct kinds, "input" or "tool", of the records behind the reason;
          empty for a converter that did not run). An input error accepted by
          a suppression with rule_id "ash-unconverted-input" is not listed.
        - unevaluated_rules: Rules that raised instead of reaching a verdict.
        - stale_content_databases: Content databases past their declared age
          bound under `content_db_staleness: fail`, one record each with `name`,
          `scanner`, `built`, `age`, `max_age` and `refresh`. Reported with the
          completeness gate on or off; a scanner listed here only for its
          database is not also in incomplete_scanners.
        - finished_scanners / total_scanners: How many scanners have ended,
          whatever their status, out of how many are known so far; the first
          reaches the second when every scanner has ended. Use these for a
          progress display.
        - completed_scanners: How many scanners ran and reported PASSED. A
          scanner that found something, errored or never ran is not counted.
        - scanner_status_counts: The scanners by state: `passed` (PASSED),
          `failed` (FAILED or ERROR), `skipped` (MISSING or SKIPPED), `running`
          and `pending`.
        - scanner_statuses: Per-scanner status for every scanner ASH considered,
          including ones that never ran. Empty until the scan finishes.
        - skipped_scanners: The subset that did not run, each with a `reason` of
          `missing_dependencies`, `excluded_by_configuration` or `skipped`. Use
          this to tell "scanned, found nothing" from "never ran"; a zero finding
          count alone cannot distinguish the two.
    """
    try:
        session_id = resolve_caller_session_id(ctx)
    except ValueError as e:
        await _tell_client_error(ctx, raw_controls_on_one_line(error_text(e)))
        return _session_error(e)

    # Needs a session: its result belongs to one, and this call may carry none.
    refusal = session_identity_refusal(session_id, "get_scan_progress", ctx=ctx)
    if refusal is not None:
        await _tell_client_error(ctx, raw_controls_on_one_line(refusal["error"]))
        return refusal

    try:
        await _tell_client(
            ctx,
            "info",
            raw_controls_on_one_line(f"Getting progress for scan: {scan_id}"),
        )

        # Scoped to this session: another session's scan id answers exactly like
        # one that was never issued.
        progress_info = await mcp_get_scan_progress(
            scan_id=scan_id, session_id=session_id
        )

        # Discriminates rather than tests presence. `not
        # progress_info.get("success")` was true on both branches, because the
        # producer set the key only on failure: this was an unconditional return
        # and everything below it -- the scanners walk, the severity totals and
        # summarize_scanner_statuses -- was dead on a real poll. Both arms are
        # needed: a producer can report a problem by setting success False, or by
        # including error without setting success at all.
        if "error" in progress_info or progress_info.get("success") is False:
            return progress_info

        registry = get_scan_registry()
        entry = registry.get_scan(scan_id, session_id=session_id)

        if not entry:
            await _tell_client_error(
                ctx, raw_controls_on_one_line(f"Scan {scan_id} not found in registry")
            )
            return {
                "success": False,
                "error": raw_controls_on_one_line(
                    f"Scan {scan_id} not found in registry"
                ),
                "error_type": "scan_not_found",
            }

        output_dir = Path(entry.output_directory)

        # The producer's view is the one to keep. Its `scanners` map names every
        # scanner the scan knows of, a scanner that wrote no results file
        # included, and its `severity_counts` carries the catch-all bucket for a
        # finding whose severity is off the ladder (scan_tracking). The walk
        # below adds each results file's own content under its scanner and
        # target; it replaces neither map, and the totals are summed from the
        # files only when the producer gave none.
        producer_scanners = progress_info.get("scanners")
        scanner_results: Dict[str, Any] = (
            {name: dict(targets) for name, targets in producer_scanners.items()}
            if isinstance(producer_scanners, dict)
            else {}
        )
        producer_counts = progress_info.get("severity_counts")
        counts_from_files = not isinstance(producer_counts, dict)
        severity_counts: Dict[str, int] = (
            empty_severity_counts() if counts_from_files else producer_counts
        )

        # The files in output_dir are the previous scan's when this one ended
        # without results and they were put back; check_scan_progress read nothing
        # from them, and neither does this. They are the previous scan's as well
        # while this one is still pending: a scan queued behind another of its
        # session, or started with clean_output false and not yet through its
        # own set-up, has written nothing there, and what is there is not its.
        previous_only = (
            bool(progress_info.get("output_holds_previous_results"))
            or progress_info.get("status") == "pending"
        )

        # The scanners directory, each scanner's and each target's are read only
        # when they resolve to a directory inside the output directory, as every
        # other results reader does: through a link, a results file would be read
        # from another tree and returned as this scan's. Each is listed through
        # _entries_of: the scan thread may move or rewrite the tree between the
        # check and the listing, and one vanished directory does not fail the poll.
        scanners_dir = output_dir / "scanners"
        if not previous_only and resolves_to_directory_inside(scanners_dir, output_dir):
            for scanner_dir in _entries_of(scanners_dir):
                if not resolves_to_directory_inside(scanner_dir, output_dir):
                    continue

                scanner_name = scanner_dir.name
                scanner_results.setdefault(scanner_name, {})

                for target_dir in _entries_of(scanner_dir):
                    if not resolves_to_directory_inside(target_dir, output_dir):
                        continue

                    target_type = target_dir.name
                    result_file = target_dir / "ASH.ScanResults.json"

                    if result_file.exists():
                        try:
                            # encoding explicit: see cli/report.py. ASH writes this
                            # file as UTF-8; the locale default is cp1252 on Windows.
                            # Blocking open + json.load on the event loop, which stalls this MCP server for
                            # every other in-flight request while a scan result is read. A correct fix moves
                            # both calls into asyncio.to_thread together (reading in a thread and parsing on
                            # the loop just relocates the stall), so it is a real change to this function
                            # rather than a lint edit. Deferred deliberately.
                            with open(result_file, "r", encoding="utf-8") as f:  # noqa: ASYNC230
                                result_data = json.load(f)

                            scanner_results[scanner_name][target_type] = result_data

                            if counts_from_files and isinstance(
                                result_data.get("severity_counts"), dict
                            ):
                                for severity, count in result_data[
                                    "severity_counts"
                                ].items():
                                    # A count under a key off the ladder is a
                                    # finding too: it goes to the catch-all
                                    # bucket, never nowhere.
                                    bucket = (
                                        severity
                                        if severity in severity_counts
                                        else UNKNOWN_SEVERITY
                                    )
                                    severity_counts[bucket] += count
                        except Exception as e:
                            await _tell_client(
                                ctx,
                                "warning",
                                raw_controls_on_one_line(
                                    f"Error reading result file {result_file}: "
                                    f"{error_text(e)}"
                                ),
                            )

        progress_info["scanners"] = scanner_results
        progress_info["severity_counts"] = severity_counts

        # `scanners` above is built by globbing result files, so a scanner that
        # never ran leaves nothing behind and silently disappears from it. That
        # made a scanner skipped for missing dependencies indistinguishable from
        # one that ran clean. These two keys come from scanner_results in the
        # aggregated output, which records the real status for every scanner ASH
        # considered. Empty while the scan is still running. The reason a
        # scanner did not run can quote an exception, so it is redacted with
        # the values this run read from its environment, as the registry's own
        # poll does with the same call.
        status_summary = (
            {"scanner_statuses": {}, "skipped_scanners": []}
            if previous_only
            else summarize_scanner_statuses(
                output_dir, environment_values=entry.environment_values
            )
        )
        progress_info["scanner_statuses"] = status_summary["scanner_statuses"]
        progress_info["skipped_scanners"] = status_summary["skipped_scanners"]

        return progress_info
    except Exception as e:
        log_unexpected_error(logger, e, "Error in get_scan_progress")
        await _tell_client_error(
            ctx,
            raw_controls_on_one_line(f"Error getting scan progress: {error_text(e)}"),
        )
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"Error getting scan progress: {error_text(e)}"
            ),
            "error_type": type(e).__name__,
        }


@mcp.tool()
async def get_scan_results(
    ctx: Context,
    output_dir: str = ".ash/ash_output",
    filter_level: str = "full",
    # Optional in the schema as well as in the default: a client that sends an
    # explicit null for "no filter" is validated, not refused.
    scanners: Optional[str] = None,
    severities: Optional[str] = None,
    actionable_only: bool = False,
) -> Dict[str, Any]:
    """
    Get final results for a completed scan with optional filtering.

    Works the same for an `incomplete` scan, whose partial findings are returned
    in full. The response's `status` is `completed` or `incomplete`, decided by
    the rule the scan's exit code uses, with `coverage_complete`,
    `incomplete_scanners`, `no_scanner_ran`, `incomplete_converters`,
    `unevaluated_rules` and `stale_content_databases` naming any gap, as in
    get_scan_progress.

    When the last scan in `output_dir` ended without results and ASH put the
    previous scan's results back, the response is the not-complete error
    (`error_category` `scan_incomplete`) with
    `context.output_holds_previous_results` true, as it is from
    get_scan_summary, get_scan_result_paths, explain_finding, diff_scan_results
    and suggest_suppression for that directory.

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
        actionable_only: If True, keep only the findings that make the scan exit 2.
                        Those are the actionable ones: not suppressed, and at or above the
                        severity threshold the scan was judged by (a scanner's own
                        threshold where its config sets one). Findings below it, which the
                        scan reports but does not fail on, are left out, as are findings
                        marked as false positives or accepted risks. Adds `findings`, a
                        flat list of the actionable findings (rule_id, severity, message,
                        scanner, file_path, line_start, line_end), with `findings_count`.
                        The list honors `scanners` and `severities`; use filter_level
                        "full" to receive it. Default is False.
    """
    try:
        session_id = resolve_caller_session_id(ctx)
    except ValueError as e:
        await _tell_client_error(ctx, raw_controls_on_one_line(error_text(e)))
        return _session_error(e)

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

        await _tell_client(
            ctx,
            "info",
            raw_controls_on_one_line(
                f"Getting results from ASH scan in directory: {output_dir} "
                f"({filter_info})"
            ),
        )

        # The session is passed so a results directory inside this session's own
        # sandbox is readable. A delivered tree's output lands at
        # <sandbox>/source/.ash/ash_output, which no operator grant names, so
        # without the id a client could scan a tree it delivered and then be
        # refused its own results. It also keeps a sibling session from reading
        # them, which the shared-workspace deny rule enforces either way.
        #
        # The findings list actionable_only adds is built from the scan's SARIF,
        # which the producer leaves out unless asked. Without it the list was
        # built from nothing, and was empty on every real scan. Not asked for a
        # level that drops the list (summary, minimal): the whole SARIF was read
        # and held for a response that never carried it. An unknown level returns
        # the full results below, list included, so it reads it.
        results = await mcp_get_scan_results(
            output_dir=output_dir,
            session_id=session_id,
            include_sarif=actionable_only
            and filter_level not in ("summary", "minimal"),
        )

        # `not results.get("success")` was true on both branches, because the
        # producer set the key only on failure. Every filter below sat behind
        # that early return, so filter_level, scanners, severities and
        # actionable_only were all inert on a real scan while the unit tests --
        # which stub the producer with a dict that does carry the key -- passed.
        if "error" in results or results.get("success") is False:
            return results

        if actionable_only:
            results = filter_actionable_only(results)

        if scanners or severities:
            results = apply_content_filters(results, scanners, severities)

        # When actionable_only is requested, extract a flat findings list for easy
        # consumption. The SARIF it was built from is dropped afterwards: it holds
        # the same findings at many times the size. So are the thresholds read with
        # it to judge the findings.
        if actionable_only:
            results = _add_findings_list(results)
            results.get("raw_results", {}).pop("sarif", None)
            results.get("raw_results", {}).pop("severity_thresholds", None)

        # Apply response size filter based on parameter. The summary and minimal
        # filters carry the coverage keys of the document themselves, as the
        # docstring promises, so nothing is copied onto their result here.
        if filter_level == "full":
            return results
        elif filter_level == "summary":
            return filter_summary(results)
        elif filter_level == "minimal":
            return filter_minimal(results)
        else:
            await _tell_client(
                ctx,
                "warning",
                raw_controls_on_one_line(
                    f"Unknown filter_level '{filter_level}', returning full results"
                ),
            )
            return results

    except ResultFilterInputError as e:
        # The client's own input: an unknown scanner or severity name in the
        # filters. It used to reach the handler below and leave as a server
        # fault, logged as unexpected and with no category a client could
        # branch on. The response names its category (the filter class
        # carries it) and the server log does not record it as its own error.
        message = raw_controls_on_one_line(
            f"Error getting scan results: {error_text(e)}"
        )
        try:
            await _tell_client_error(ctx, message)
        except Exception:
            logger.error(f"Failed to send error message to client: {error_text(e)}")
        return {
            "success": False,
            "error": message,
            "error_type": type(e).__name__,
            "error_category": e.error_category,
        }

    except Exception as e:
        log_unexpected_error(logger, e, "Error in get_scan_results")
        try:
            await _tell_client_error(
                ctx,
                raw_controls_on_one_line(
                    f"Error getting scan results: {error_text(e)}"
                ),
            )
        except Exception:
            logger.error(f"Failed to send error message to client: {error_text(e)}")
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"Error getting scan results: {error_text(e)}"
            ),
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
    - Scan metadata (timestamps, duration, etc.), including
      `ignore_file_exclusions`: whether the scanned repository's .gitignore and
      .ignore files were honored and how many files they excluded from the scan set
    - Findings count by severity
    - Findings count by scanner/tool
    - Scanner execution status
    - No detailed finding information

    Args:
        output_dir: Path to the scan output directory (absolute path recommended)
    """
    summary = await get_scan_results(ctx, output_dir=output_dir, filter_level="summary")
    # Tag the response with the entry point that produced it. get_scan_results
    # serves several filter levels, so callers use this to tell a summary obtained
    # via get_scan_summary from one obtained by calling get_scan_results directly.
    # Preserved from the pre-refactor implementation; asserted by
    # tests/unit/cli/test_mcp_server.py::TestGetScanSummary.
    #
    # Conditioned on the absence of a failure signal rather than on the presence
    # of `success`, matching the guards in the two tools above. Requiring the key
    # to be present and truthy meant the tag was never attached on a real scan:
    # get_scan_results returned early before filter_summary -- the only thing on
    # this path that sets the key -- ever ran.
    if (
        isinstance(summary, dict)
        and "error" not in summary
        and summary.get("success") is not False
    ):
        summary["_source_function"] = "get_scan_summary"
    return summary


def _directory_not_read(directory: Path, output_path: Path) -> Optional[str]:
    """Why ``get_scan_result_paths`` does not read a directory under ``output_path``.

    A directory is read when it resolves to a directory inside the output
    directory. Anything else at the path, a link elsewhere and a link to
    nothing alike, is not read, so the reply says nothing about where a link
    leads. None when the directory is read, or when there is nothing at the
    path, which the caller reports as it always has.
    """
    if not os.path.lexists(directory) or resolves_to_directory_inside(
        directory, output_path
    ):
        return None
    name = directory.relative_to(output_path).as_posix()
    return (
        f"The results directory '{name}' in '{output_path}' does not resolve to "
        "a directory in that output directory, so it was not read."
    )


#: The errors a stat raises for a path with nothing at it, the ones
#: ``Path.exists`` reads as False: no entry, a file on the way, a bad
#: descriptor, a link loop. Any other error on a stat is reported as before.
_NOT_THERE_ERRNOS = frozenset({errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP})


def _result_path_entry(
    file_path: Path, output_path: Path, not_read: Optional[str] = None
) -> Dict[str, Any]:
    """``get_scan_result_paths``'s entry for one results file.

    A file that does not resolve to a file in its own directory and in the
    output directory, or one in a directory that was not read (``not_read``,
    the reason), is listed as not there, with no size and the reason, without
    following the link. Any other file is listed as it is: whether it exists,
    and its size.
    """
    if not_read is None:
        refusal = _results_file_outside_its_directory(
            file_path, "get_scan_result_paths", output_path
        )
        if refusal is not None:
            not_read = str(refusal["error"])
    if not_read is not None:
        return {
            "path": str(file_path),
            "exists": False,
            "size_bytes": None,
            "error": raw_controls_on_one_line(not_read),
        }
    # One stat, read for both fields: a file that goes away between an existence
    # check and its stat, as when a new scan sets the previous results aside,
    # is listed as not there instead of failing the whole call.
    try:
        size = file_path.stat().st_size
    except OSError as error:
        if error.errno not in _NOT_THERE_ERRNOS:
            raise
        return {"path": str(file_path), "exists": False, "size_bytes": 0}
    return {"path": str(file_path), "exists": True, "size_bytes": size}


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
        session_id = resolve_caller_session_id(ctx)
    except ValueError as e:
        await _tell_client_error(ctx, raw_controls_on_one_line(error_text(e)))
        return _session_error(e)

    try:
        if not Path(output_dir).is_absolute():
            output_dir = str(Path.cwd() / output_dir)

        output_path = Path(output_dir)
        reports_dir = output_path / "reports"

        # Same roots as the scan tools: this returns paths from a caller-named
        # directory, and an output directory for a permitted scan lives beneath
        # the permitted target. Checked before the existence branch below so a
        # refusal is not reported as a missing directory.
        target_error = validate_scan_target(output_path, session_id=session_id)
        if target_error:
            await _tell_client_error(ctx, raw_controls_on_one_line(str(target_error)))
            return {
                "success": False,
                "error": raw_controls_on_one_line(str(target_error)),
                "error_type": "scan_target_not_permitted",
                # Mirrors the category create_error_response sets on the
                # mcp_tools side, so one key identifies a refusal from any entry
                # point rather than two depending on which tool was called.
                "error_category": target_error.context["error_category"],
            }

        await _tell_client(
            ctx,
            "info",
            raw_controls_on_one_line(f"Getting scan result paths from: {output_dir}"),
        )

        # The files there are the scan before the last one's when the last one
        # ended without results; handing out their paths would present them as
        # its results.
        restored = restored_results_refusal(output_path, "get_scan_result_paths")
        if restored is not None:
            await _tell_client_error(ctx, raw_controls_on_one_line(restored["error"]))
            return restored

        # Blocking stat on the event loop. Deferred with the other MCP-server sites.
        if not output_path.exists():  # noqa: ASYNC240
            return {
                "success": False,
                "error": raw_controls_on_one_line(
                    f"Output directory does not exist: {output_dir}"
                ),
                "error_type": "DirectoryNotFound",
            }

        # A file's existence and size are read through any link to it, so each
        # entry, and each directory the entries are in, is checked to stay in
        # the output directory first.
        reports_not_read = _directory_not_read(reports_dir, output_path)
        if reports_not_read is None and not reports_dir.exists():
            return {
                "success": False,
                "error": raw_controls_on_one_line(
                    f"Reports directory does not exist: {reports_dir}"
                ),
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
            result["files"][report_type] = _result_path_entry(
                file_path, output_path, reports_not_read
            )

        aggregated_file = output_path / "ash_aggregated_results.json"
        result["files"]["aggregated_results"] = _result_path_entry(
            aggregated_file, output_path
        )

        # A scanners directory, or a scanner's, that is not read is not listed,
        # as when nothing is there: its entries could only come from the link.
        scanners_dir = output_path / "scanners"
        if (
            _directory_not_read(scanners_dir, output_path) is None
            and scanners_dir.exists()
        ):
            result["scanners_dir"] = str(scanners_dir)
            result["scanner_results"] = {}

            # Listed through _entries_of: a directory a new scan moves away
            # between the check above and its listing is listed as empty.
            for scanner_dir in _entries_of(scanners_dir):
                if (
                    _directory_not_read(scanner_dir, output_path) is None
                    and scanner_dir.is_dir()
                ):
                    scanner_name = scanner_dir.name
                    result["scanner_results"][scanner_name] = {}

                    for target_dir in _entries_of(scanner_dir):
                        # A target directory that is a link is listed by its
                        # name here; its results file is checked like any other.
                        if target_dir.is_symlink() or target_dir.is_dir():
                            target_name = target_dir.name
                            result_file = target_dir / "ASH.ScanResults.json"

                            result["scanner_results"][scanner_name][target_name] = (
                                _result_path_entry(
                                    result_file,
                                    output_path,
                                    _directory_not_read(target_dir, output_path),
                                )
                            )

        return result

    except Exception as e:
        log_unexpected_error(logger, e, "Error in get_scan_result_paths")
        try:
            await _tell_client_error(
                ctx,
                raw_controls_on_one_line(
                    f"Error getting scan result paths: {error_text(e)}"
                ),
            )
        except Exception:
            logger.error(f"Failed to send error message to client: {error_text(e)}")
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"Error getting scan result paths: {error_text(e)}"
            ),
            "error_type": type(e).__name__,
        }


@mcp.tool()
async def list_active_scans(ctx: Context) -> Dict[str, Any]:
    """
    List this session's active and recent scans with their current status.

    Only scans this session started are listed; another session's scans are not
    visible, and the statistics count only this session's.
    """
    try:
        session_id = resolve_caller_session_id(ctx)
    except ValueError as e:
        await _tell_client_error(ctx, raw_controls_on_one_line(error_text(e)))
        return _session_error(e)

    # Needs a session: its result belongs to one, and this call may carry none.
    refusal = session_identity_refusal(session_id, "list_active_scans", ctx=ctx)
    if refusal is not None:
        await _tell_client_error(ctx, raw_controls_on_one_line(refusal["error"]))
        return refusal

    try:
        await _tell_client(ctx, "info", "Listing active scans")
        return await mcp_list_active_scans(session_id=session_id)
    except Exception as e:
        log_unexpected_error(logger, e, "Error in list_active_scans")
        await _tell_client_error(
            ctx,
            raw_controls_on_one_line(f"Error listing active scans: {error_text(e)}"),
        )
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"Error listing active scans: {error_text(e)}"
            ),
            "error_type": type(e).__name__,
        }


@mcp.tool()
async def cancel_scan(ctx: Context, scan_id: str) -> Dict[str, Any]:
    """
    Cancel a running scan and stop it.

    The scanner tool running at the time is stopped with every process it started
    (SIGTERM, then SIGKILL after 10 seconds). The scan stops at its next check:
    no further scanner, phase or reporter starts, and no further results are
    written. Work already under way that is not waiting on a child process, such
    as a scanner reading its tool's output, finishes first and may still write.
    The previous scan's results are then put back in place of every result the
    cancelled scan wrote; its logs, ash.log and ash.log.jsonl, stay. Without
    previous results, what it wrote before it stopped stays, except that its
    reports are removed when it stops during the report phase, with every other
    file a reporter wrote beside them; the unused-suppressions reporter's
    markdown file goes with them.

    The scan's status becomes `cancelled` at once; until the scan has stopped, a
    new scan of the same directory is refused as still stopping. A scan that has
    already finished cannot be cancelled; the response then has `success` false
    and the scan's status. For one project of a workspace scan, that project stops
    and the workspace's other projects carry on.

    Only a scan this session started can be cancelled; another session's scan id
    gets the same not-found response as an id that was never issued, and that
    scan keeps running.

    Args:
        scan_id: The scan ID to cancel
    """
    try:
        session_id = resolve_caller_session_id(ctx)
    except ValueError as e:
        await _tell_client_error(ctx, raw_controls_on_one_line(error_text(e)))
        return _session_error(e)

    # Needs a session: its result belongs to one, and this call may carry none.
    refusal = session_identity_refusal(session_id, "cancel_scan", ctx=ctx)
    if refusal is not None:
        await _tell_client_error(ctx, raw_controls_on_one_line(refusal["error"]))
        return refusal

    try:
        await _tell_client(
            ctx, "info", raw_controls_on_one_line(f"Cancelling scan: {scan_id}")
        )
        return await mcp_cancel_scan(scan_id=scan_id, session_id=session_id)
    except Exception as e:
        log_unexpected_error(logger, e, "Error in cancel_scan")
        await _tell_client_error(
            ctx, raw_controls_on_one_line(f"Error cancelling scan: {error_text(e)}")
        )
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"Error cancelling scan: {error_text(e)}"
            ),
            "error_type": type(e).__name__,
        }


@mcp.tool()
async def check_installation(ctx: Context) -> Dict[str, Any]:
    """Report whether ASH can scan, from each built-in scanner's dependency check.

    Returns installed (ASH is installed and at least one enabled scanner can
    run), ready (every enabled scanner can run), version, scanners (name,
    enabled, dependencies_satisfied, version), missing_dependencies and
    undetermined_dependencies (enabled scanners whose tool is missing, or whose
    check could not run), and ash_command_available (an `ash` executable on
    PATH, which the server does not need). Each check may run its scanner's
    tool, so this takes seconds. It installs and downloads nothing. A scanner
    whose tool is not installed yet, and that a scan installs with uv when it
    starts the scanner (not offline, uv present: bandit, checkov, semgrep on a
    fresh install), is listed in installs_on_first_scan rather than
    missing_dependencies, and does not make ready false. ash_command_output names
    the executable's path only for the client that launched the server; a
    remote session is told only whether there is one.
    """
    # Decided by the transport, like every other tool here. The session id is all
    # sandbox.caller_is_remote has to go on, and the request headers answer
    # DEFAULT_SESSION_ID (the local client's) for a network call that sends no
    # Mcp-Session-Id, which would hand that call the server's ash path. The tool
    # needs no session of its own, so an unidentified caller is answered as the
    # remote one it is, not refused.
    try:
        session_id = resolve_caller_session_id(ctx)
    except ValueError as e:
        await _tell_client_error(ctx, raw_controls_on_one_line(error_text(e)))
        return _session_error(e)

    try:
        await _tell_client(ctx, "info", "Checking ASH installation")
        return await mcp_check_installation(session_id=session_id)
    except Exception as e:
        log_unexpected_error(logger, e, "Error in check_installation")
        await _tell_client_error(
            ctx,
            raw_controls_on_one_line(f"Error checking installation: {error_text(e)}"),
        )
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"Error checking installation: {error_text(e)}"
            ),
            "error_type": type(e).__name__,
        }


@mcp.tool()
async def explain_finding(
    ctx: Context,
    finding_id: str,
    results_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Return structured details for a single finding by ID.

    Performs a pure structured lookup against already-emitted SARIF results.
    No LLM calls are made.

    Args:
        finding_id: The FlatVulnerability ID to look up (e.g. "bandit-B601-880359fd90e1").
        results_path: Optional path to the output directory containing
                      ash_aggregated_results.json. Defaults to
                      <cwd>/.ash/ash_output.

    Returns:
        Dict with ``success`` and ``finding`` keys containing title, description,
        severity, severity_rationale, cwe_id, cve_id, references, scanner,
        and scanner_metadata.
    """
    try:
        session_id = resolve_caller_session_id(ctx)
    except ValueError as e:
        return _session_error(e)

    try:
        return mcp_explain_finding(
            finding_id=finding_id,
            results_path=results_path,
            session_id=session_id,
        )
    except Exception as e:
        log_unexpected_error(logger, e, "Error in explain_finding")
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"Error explaining finding: {error_text(e)}"
            ),
            "error_type": type(e).__name__,
        }


@mcp.tool()
async def get_config(
    ctx: Context,
    config_path: Optional[str] = None,
    raw: bool = False,
    search_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Get the resolved ASH config (defaults + user overrides merged).

    The answer is the configuration a scan of the same inputs would run
    under, so its `ash_plugin_modules` list is judged as that scan judges it:
    an entry every such scan refuses answers `success` false with
    `error_type` plugin_module_refused and exit code 3, rather than showing a
    configuration no scan runs under. Only the config's own entries are
    judged -- the server-side `ASH_PLUGIN_MODULES` variable is a CLI scan
    option that no scan started through this server reads. `raw` requests
    are never judged: they ask for a document, not a run.

    Args:
        config_path: Optional explicit path to config file. If None, auto-discovers.
        raw: If True, returns the file's contents as written, without merging
             defaults or reading the environment. A value the config's loader
             would read from the environment (an `!ENV` value, or an unquoted
             `${VAR:default}`) comes back as `!ENV ` and the reference, never as
             its value; a quoted string that only looks like a reference comes
             back as written.
        search_dir: The directory the caller's scan will target
             (scan_directory's directory_path). With config_path None it is
             where the config is discovered; with a named config_path it is
             the target the file is judged for, so the answer refuses exactly
             what a scan of that target refuses -- an entry such a scan drops
             with a warning never refuses the answer. Without it, a named
             file is judged for this session's delivered source, or else the
             server's working directory.

    Returns:
        The config. On failure, `success` false with `exit_code` and its
        `exit_code_meaning`: 3 for a config outside the directories the session
        may read config from (`error_type` config_input_not_permitted), one
        that cannot be loaded, or one whose plugin-module list a scan refuses
        (`error_type` plugin_module_refused), 4 for a `search_dir` outside
        the directories this session may scan (`error_type`
        scan_target_not_permitted, the scan tool's own refusal of the same
        target), 5 for an unusable session header or a `search_dir` no scan
        could target (`error_type` source_dir_not_usable, as a scan of it
        answers), and 1 for anything else.
    """
    try:
        session_id = resolve_caller_session_id(ctx)
    except ValueError as e:
        return _scan_session_error(e)

    try:
        return mcp_get_config(
            config_path=config_path,
            raw=raw,
            search_dir=search_dir,
            session_id=session_id,
        )
    except Exception as e:
        log_unexpected_error(logger, e, "Error in get_config")
        return with_exit_code(
            {
                "success": False,
                "error": raw_controls_on_one_line(
                    f"Error getting config: {error_text(e)}"
                ),
                "error_type": type(e).__name__,
            },
            REFUSED_INTERNAL_EXIT_CODE,
        )


@mcp.tool()
async def list_scanners() -> list:
    """List all registered ASH scanners with their metadata.

    Returns one entry per scanner with:
      name: scanner config name (e.g. "bandit", "checkov")
      version: detected version string, or null when the scanner reports none.
        The format is whatever each scanner reports and is not consistent between
        them -- bandit reports "bandit 1.9.4" where checkov reports "3.3.11".
      dependencies_satisfied: true, false, or null when it could not be
        determined, which happens when a scanner cannot be constructed or its own
        dependency check raises. Treat null as "unknown", not as "not met": a
        scanner reporting null may well run.
      offline_strategy: one of "bundled", "cache_flags", "skip_offline", "unknown"
      enabled: whether the scanner is enabled in the default ASH config
      installs_on_first_scan: true when the scanner's tool is not installed and a
        scan installs it with uv when it starts the scanner; its
        dependencies_satisfied is then false

    Nothing is installed or downloaded to answer: a tool that is not already
    present is reported as such.

    dependencies_satisfied describes this deployment's environment at the moment of
    the call. It is not a prediction about a scan: a scanner reporting true can
    still fail on a given target, and a scan may skip a scanner for reasons of
    configuration rather than dependencies.

    The list covers the built-in scanners and the community scanners ASH ships
    (ferret-scan, snyk-code, trivy-repo). Listing a community scanner does not add
    it to any scan: a scan runs the built-in scanners plus those of the plugin
    modules its own ash_plugin_modules names, so a community scanner runs only in a
    scan whose config or --ash-plugin-modules names its module.
    """
    try:
        # Off the event loop, as check_installation runs the same inventory: the
        # probes run each scanner's dependency check in turn and then wait on
        # the process-wide inventory lock, seconds during which every other
        # session's calls would otherwise stall.
        return await asyncio.to_thread(mcp_list_scanners)
    except Exception as e:
        log_unexpected_error(logger, e, "Error in list_scanners")
        return [
            {
                "success": False,
                "error": raw_controls_on_one_line(
                    f"Error listing scanners: {error_text(e)}"
                ),
                "error_type": type(e).__name__,
            }
        ]


@mcp.tool()
async def diff_scan_results(
    ctx: Context,
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
        session_id = resolve_caller_session_id(ctx)
    except ValueError as e:
        return _session_error(e)

    try:
        return mcp_diff_scan_results(
            before_path=before_path, after_path=after_path, session_id=session_id
        )
    except Exception as e:
        log_unexpected_error(logger, e, "Error in diff_scan_results")
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"Error diffing scan results: {error_text(e)}"
            ),
            "error_type": type(e).__name__,
        }


@mcp.tool()
def validate_config(
    ctx: Context,
    config_content: Optional[str] = None,
    config_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Validate an ASH configuration file or content string.

    Args:
        config_content: YAML/JSON string to validate.
        config_path: Path to the config file to validate.

    Returns:
        Dict with valid (true when a scan accepts the config), errors (what makes
        a scan refuse it) and warnings (what a scan accepts but is probably a
        mistake, such as an unknown key or a missing project_name). Both are lists
        of {field, message, type}.
    """
    try:
        session_id = resolve_caller_session_id(ctx)
    except ValueError as e:
        return {
            "valid": False,
            "errors": [
                {
                    "field": "",
                    "message": raw_controls_on_one_line(error_text(e)),
                    "type": "invalid_session_id",
                }
            ],
            "warnings": [],
        }

    try:
        return mcp_validate_config(
            config_content=config_content,
            config_path=config_path,
            session_id=session_id,
        )
    except Exception as e:
        log_unexpected_error(logger, e, "Error in validate_config")
        return {
            "valid": False,
            "errors": [
                {
                    "field": "",
                    "message": raw_controls_on_one_line(
                        f"Unexpected error: {error_text(e)}"
                    ),
                    "type": type(e).__name__,
                }
            ],
            "warnings": [],
        }


def _read_ash_config_schema() -> str:
    """Read the AshConfig JSON schema from disk."""
    schema_path = Path(__file__).parent.parent / "schemas" / "AshConfig.json"
    return schema_path.read_text()


@mcp.resource("ash://schema/config")
def get_ash_config_schema() -> str:
    """Return the AshConfig JSON schema."""
    return _read_ash_config_schema()


def _read_ash_suppression_schema() -> str:
    """Return the AshSuppression JSON schema as a string."""
    from automated_security_helper.models.core import AshSuppression
    import json as _json

    return _json.dumps(AshSuppression.model_json_schema(), indent=2)


@mcp.resource("ash://schema/suppression")
def get_ash_suppression_schema() -> str:
    """Return the AshSuppression JSON schema."""
    return _read_ash_suppression_schema()


@mcp.tool()
async def suggest_suppression(
    ctx: Context,
    finding_id: str,
    results_path: Optional[str] = None,
    expiration: Optional[str] = None,
    justification: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a paste-ready AshSuppression entry for a specific finding.

    Args:
        finding_id: Stable hash ID of the finding (from get_scan_results or explain_finding).
        results_path: Path to ash_aggregated_results.json. Defaults to
                      .ash/ash_output/ash_aggregated_results.json in cwd.
        expiration: Expiration date in YYYY-MM-DD format. Defaults to 90 days from today.
        justification: Human-readable reason for the suppression.
    """
    try:
        session_id = resolve_caller_session_id(ctx)
    except ValueError as e:
        return _session_error(e)

    try:
        return mcp_suggest_suppression(
            finding_id=finding_id,
            results_path=results_path,
            expiration=expiration,
            justification=justification,
            session_id=session_id,
        )
    except Exception as e:
        log_unexpected_error(logger, e, "Error in suggest_suppression")
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"Error suggesting suppression: {error_text(e)}"
            ),
            "error_type": type(e).__name__,
        }


# ---------------------------------------------------------------------------
# Source delivery.
#
# A client on a network transport shares no filesystem with the server, so the
# tree to scan has to arrive over the protocol. These four tools are the
# delivery surface; the implementation and its limits live in
# cli/mcp/source_delivery.py, and the wrappers below it in cli/mcp_tools.py.
#
# Each one takes its session from the transport rather than from an argument.
# Letting a client name its own session id would let it name another client's
# workspace, and on AgentCore the platform supplies the id anyway -- see
# cli/mcp/session_identity.py.
#
# The delivered tree becomes the default target of run_ash_scan for that
# session, so the usual sequence is deliver -> run_ash_scan() with no arguments
# -> get_scan_progress.
# ---------------------------------------------------------------------------


def _session_error(e: ValueError) -> Dict[str, Any]:
    """Shape a rejected session header like the tools' other failures."""
    return {
        "success": False,
        "error": raw_controls_on_one_line(error_text(e)),
        "error_type": "invalid_session_id",
    }


def _scan_session_error(e: ValueError) -> Dict[str, Any]:
    """The scan tools' refusal of an unusable session header: a usage error.

    The scan tools report an exit code for every refusal, as the CLI exits with
    one, and a header the server cannot use is the request's own fault.
    """
    return with_exit_code(_session_error(e), REFUSED_USAGE_EXIT_CODE)


def _with_session(result: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    """Echo the resolved session id back to the caller.

    Two reasons. It tells a client which workspace a call actually landed in,
    which is otherwise invisible when the id comes from a header the client did
    not set. And it makes an open question answerable from outside the container:
    on Bedrock AgentCore the platform mints session ids and it is not established
    whether the id the server *receives* is stable across requests in one session
    (see cli/mcp/session_identity.py). Calling any of these tools twice and
    comparing this field settles it without a code change or a log dive.

    Echoing costs nothing in disclosure: the value is the caller's own id, which
    it or the platform acting for it supplied. mcp_select_profile already returns
    session_id for the same reason.
    """
    return {**result, "session_id": session_id}


@mcp.tool()
async def set_source_git(
    ctx: Context,
    url: str,
    ref: Optional[str] = None,
    ssh_key_id: Optional[str] = None,
    # The limits are shown in the input schema and not enforced by it. The argument
    # model validates before the tool runs, so a limit it enforced would turn a depth
    # outside the range into a framework error with no error_type, where the tool
    # answers invalid_clone_depth. The delivery checks the range.
    depth: Annotated[
        int, Field(json_schema_extra={"minimum": 1, "maximum": MAX_CLONE_DEPTH})
    ] = 1,
) -> Dict[str, Any]:
    """Clone a repository into this session's workspace and make it the scan target.

    After this returns, call run_ash_scan() with no source_dir to scan the clone.

    The server clones only from hosts its operator listed, over https or ssh,
    and never with the server's own credentials: no ssh agent, keys, credential
    helpers, proxies or git configuration of the server account reach git. A
    local path or file:// URL is refused.

    Args:
        url: Remote URL to clone: https://, ssh:// or user@host:path. Refused if
             it begins with '-' or uses the ext:: transport, both of which make
             git run a command, if it holds a control character or a lone
             surrogate, and unless its host is on the operator's list.
             An ssh:// url with %, ?, #, [ or ] before the path is refused too.
        ref: Optional branch, tag, or commit. Defaults to the remote's default
             branch. Refused if it begins with '-' or holds a control character
             (NUL included) or a lone surrogate.
        ssh_key_id: Must be omitted. The server registers no ssh keys, so any id
                    is refused. Raw private keys are never accepted over the wire.
        depth: Shallow-clone depth, a whole number from 1 to 1000. Defaults to 1.
            The limit is on how much history is fetched. A depth below 1 or
            above 1000 is refused before anything is created, with error_type
            invalid_clone_depth.

    Refused while a scan of this session runs (error_type source_delivery_busy),
    because the clone replaces the tree the scan is reading.

    A re-delivery needs room for both trees at once: the new clone is made
    beside the delivered source, which is deleted only after it. When the disk
    is short, call clear_source first to free the delivered one. A clone, fetch
    or checkout that fails for want of space returns git's own message, with
    that advice added when the session has a delivered source to free.

    Each git command (the clone, and for a ref the fetch and the checkout) has
    10 minutes. One that runs longer is stopped, nothing is kept, and the call
    fails with error_type clone_timed_out. A clone that passes the archive size
    or entry limits is refused with error_type clone_too_large, which means the
    limits only: shrink the request (a smaller repository or a lower depth). A
    clone whose tree cannot be read, while git runs or once it has exited, is
    refused with error_type clone_tree_unreadable, which is a server-side
    fault, not a size to reduce. If this call is cancelled, the clone finishes
    or times out on the server and the session reads busy until then.

    Returns:
        Dict with success and source_dir, or success=False with error and
        error_type: clone_url_not_permitted, clone_ref_not_permitted (a ref
        beginning with '-' or holding a control character or a lone surrogate),
        invalid_clone_depth (below 1 or above 1000), invalid_session_id,
        local_clone_source_refused (a local path or file:// URL, which would
        read the server's own filesystem), clone_host_not_permitted (the host
        is not on the operator's list), ssh_key_not_registered (an ssh_key_id
        was named), source_delivery_busy, clone_timed_out, git_clone_failed or
        git_checkout_failed (git's own message is in error; git_clone_failed
        also covers a git that is not on PATH or cannot be started), or
        session_workspace_unavailable (the session's workspace could not take
        the clone: a directory could not be created, the previously delivered
        source could not be moved aside for it, or the clone could not be moved
        into place; each move is tried a few times before it fails).

        The clone is made beside the delivered source and replaces it only once
        it has worked, so a delivery that fails for any of these reasons leaves
        the previously delivered source in place, and run_ash_scan() with no
        source_dir scans it. A partial clone that cannot be fully deleted stays
        beside the source, logged, for the next delivery to delete, and the
        error returned is still git's own. The one exception is a clone that
        could not be moved into place after the previous source had been moved
        aside and could not be put back: the recorded source then names a path
        that is gone, and run_ash_scan() with no source_dir answers
        delivered_source_missing until a source is delivered again; that next
        delivery puts the previous source back first.

        A session_workspace_unavailable that names a refused rename can be
        retried with the same call: the refusal is usually a program holding a
        handle inside a tree (a virus scanner, a file indexer), and it passes.
    """
    try:
        session_id = resolve_caller_session_id(ctx)
    except ValueError as e:
        await _tell_client_error(ctx, raw_controls_on_one_line(error_text(e)))
        return _session_error(e)

    # Needs a session: its result belongs to one, and this call may carry none.
    refusal = session_identity_refusal(session_id, "set_source_git", ctx=ctx)
    if refusal is not None:
        await _tell_client_error(ctx, raw_controls_on_one_line(refusal["error"]))
        return refusal

    try:
        # Off the event loop: a clone takes as long as the remote makes it, and
        # every other session's calls share the loop.
        result = await _run_clone(
            mcp_set_source_git,
            url=url,
            ref=ref,
            ssh_key_id=ssh_key_id,
            depth=depth,
            session_id=session_id,
        )
    except Exception as e:
        log_unexpected_error(logger, e, "Error in set_source_git")
        return {
            "success": False,
            "error": raw_controls_on_one_line(f"Error cloning source: {error_text(e)}"),
            "error_type": type(e).__name__,
        }

    if result.get("success"):
        await _tell_client(
            ctx,
            "info",
            raw_controls_on_one_line(f"Source cloned for session {session_id}"),
        )
    else:
        await _tell_client_error(
            ctx, raw_controls_on_one_line(str(result.get("error", "clone failed")))
        )
    return _with_session(result, session_id)


@mcp.tool()
async def set_source_zip_chunk(
    ctx: Context,
    upload_id: str,
    sequence: int,
    data_b64: str,
    last: bool,
) -> Dict[str, Any]:
    """Upload one base64 chunk of a zipped source tree.

    Chunks must arrive in order, each at most 1 MiB once decoded. Send the final
    chunk with last=True, then call set_source_zip_finalize to verify and extract.

    Args:
        upload_id: Identifier you choose, scoping this one upload.
        sequence: Zero-based ordinal of this chunk.
        data_b64: Base64-encoded chunk payload.
        last: True on the final chunk.

    Returns:
        Dict with success, received, next_sequence and last; or success=False
        and error on an out-of-order, oversize, or malformed chunk, with
        error_type session_workspace_unavailable when the session's workspace
        directory could not be created, and with error_type
        session_workspace_busy while the server removes this session's
        workspace for being unused longer than its time to live (send the
        upload again from its first chunk).
    """
    try:
        session_id = resolve_caller_session_id(ctx)
    except ValueError as e:
        await _tell_client_error(ctx, raw_controls_on_one_line(error_text(e)))
        return _session_error(e)

    # Needs a session: its result belongs to one, and this call may carry none.
    refusal = session_identity_refusal(session_id, "set_source_zip_chunk", ctx=ctx)
    if refusal is not None:
        await _tell_client_error(ctx, raw_controls_on_one_line(refusal["error"]))
        return refusal

    try:
        return _with_session(
            await _run_delivery(
                mcp_set_source_zip_chunk,
                upload_id=upload_id,
                sequence=sequence,
                data_b64=data_b64,
                last=last,
                session_id=session_id,
            ),
            session_id,
        )
    except Exception as e:
        log_unexpected_error(logger, e, "Error in set_source_zip_chunk")
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"Error accepting source chunk: {error_text(e)}"
            ),
            "error_type": type(e).__name__,
        }


@mcp.tool()
async def set_source_zip_finalize(
    ctx: Context,
    upload_id: str,
    expected_sha256: str,
) -> Dict[str, Any]:
    """Verify an uploaded zip and extract it as this session's scan target.

    The assembled zip must hash to expected_sha256. Entries with absolute paths,
    '..' components, or symlinks are refused before anything is extracted, and
    the archive is capped at 100 MiB on the wire, 500 MiB extracted, and 50000
    entries. After this returns, call run_ash_scan() with no source_dir. Refused
    while a scan of this session runs (error_type source_delivery_busy); chunks
    of other uploads may be sent meanwhile. If this call is cancelled, the extraction
    finishes or fails server-side and the session reads busy until then.

    Args:
        upload_id: The identifier used for the preceding chunk calls.
        expected_sha256: Hex sha256 of the complete zip.

    Returns:
        Dict with success and source_dir, or success=False and error, with
        error_type session_workspace_unavailable when the session's workspace
        could not take the tree: a directory could not be created, the previous
        tree could not be renamed aside (nothing is deleted where it stands), or
        the extracted one could not be moved into place. The previous tree stays
        delivered and the uploaded zip is kept, so the same call can be sent
        again; when the previous tree could not be put back either,
        run_ash_scan() with no source_dir answers delivered_source_missing. A
        failure on disk while the archive is read or extracted (no space, no
        permission, a file that vanished) returns the class name of the
        exception as error_type; only an upload that never received its last
        chunk returns error with no error_type.
    """
    try:
        session_id = resolve_caller_session_id(ctx)
    except ValueError as e:
        await _tell_client_error(ctx, raw_controls_on_one_line(error_text(e)))
        return _session_error(e)

    # Needs a session: its result belongs to one, and this call may carry none.
    refusal = session_identity_refusal(session_id, "set_source_zip_finalize", ctx=ctx)
    if refusal is not None:
        await _tell_client_error(ctx, raw_controls_on_one_line(refusal["error"]))
        return refusal

    try:
        result = await _run_delivery(
            mcp_set_source_zip_finalize,
            upload_id=upload_id,
            expected_sha256=expected_sha256,
            session_id=session_id,
        )
    except Exception as e:
        log_unexpected_error(logger, e, "Error in set_source_zip_finalize")
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"Error finalizing source upload: {error_text(e)}"
            ),
            "error_type": type(e).__name__,
        }

    if result.get("success"):
        await _tell_client(
            ctx,
            "info",
            raw_controls_on_one_line(f"Source extracted for session {session_id}"),
        )
    else:
        await _tell_client_error(
            ctx, raw_controls_on_one_line(str(result.get("error", "finalize failed")))
        )
    return _with_session(result, session_id)


@mcp.tool()
async def clear_source(ctx: Context) -> Dict[str, Any]:
    """Delete this session's delivered source tree and workspace.

    Idempotent: a session that delivered nothing still succeeds. Call this to
    reclaim space or before delivering a different tree. Refused while a scan of
    this session runs or a chunk is being written (error_type
    source_delivery_busy); call it again once that has finished. If this call is
    cancelled, the clear finishes server-side and the session reads busy until
    then.

    Returns:
        Dict with success.
    """
    try:
        session_id = resolve_caller_session_id(ctx)
    except ValueError as e:
        await _tell_client_error(ctx, raw_controls_on_one_line(error_text(e)))
        return _session_error(e)

    # Needs a session: its result belongs to one, and this call may carry none.
    refusal = session_identity_refusal(session_id, "clear_source", ctx=ctx)
    if refusal is not None:
        await _tell_client_error(ctx, raw_controls_on_one_line(refusal["error"]))
        return refusal

    try:
        result = await _run_delivery(mcp_clear_source, session_id=session_id)
    except Exception as e:
        log_unexpected_error(logger, e, "Error in clear_source")
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"Error clearing source: {error_text(e)}"
            ),
            "error_type": type(e).__name__,
        }

    if result.get("success"):
        await _tell_client(
            ctx,
            "info",
            raw_controls_on_one_line(f"Source cleared for session {session_id}"),
        )
    else:
        await _tell_client_error(
            ctx,
            raw_controls_on_one_line(str(result.get("error", "clear_source failed"))),
        )
    return _with_session(result, session_id)


@mcp.tool()
async def list_profiles() -> Dict[str, Any]:
    """List the config profiles the operator registered at server startup.

    A profile is a named ASH config file. Profiles come only from the operator:
    each `--profile NAME=path/to/ash.yaml` passed to `ash mcp` (repeatable, on any
    transport) registers the file at that path under NAME, and the server loads
    and validates every one when it starts, refusing to start (exit 3) if one does
    not load. A client cannot add one, and an edit to a profile's file takes
    effect only when the server restarts. Only the name and a SHA-256 of the
    file's absolute path are returned, not the path or the contents: the hash
    changes when the operator points NAME at a different file.

    Returns:
        Dict with profiles (a list of name/path_sha256 pairs, sorted by name) and
        count. An empty list means the operator registered none, not that the
        call failed.
    """
    try:
        return mcp_list_profiles()
    except Exception as e:
        log_unexpected_error(logger, e, "Error in list_profiles")
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"Error listing profiles: {error_text(e)}"
            ),
            "error_type": type(e).__name__,
        }


@mcp.tool()
async def select_profile(
    ctx: Context,
    profile_name: str,
    patch_ops: Optional[list] = None,
    override_yaml: Optional[str] = None,
) -> Dict[str, Any]:
    """Bind one of the operator's registered config profiles to this session.

    Every later call in this session that does not name a config of its own runs
    under the bound one: run_ash_scan, resolve_ash_workspace and
    run_ash_workspace_scan all pick it up. The profiles are the ones the operator
    registered when starting the server, with `ash mcp --profile NAME=path/to/ash.yaml`
    (repeatable); call list_profiles to see their names.

    Three modes, distinguished by which optional argument you pass:

    * Neither: bind the profile as the operator wrote it.
    * patch_ops: apply a JSON-Patch document to it first. Each op is checked
      against the server's runtime-override allowlist, and one rejected op fails
      the whole call without changing the session's config.
    * override_yaml: replace it wholesale with your own YAML, still validated.
      The difference from the profile is checked against the same allowlist as
      patch_ops, so a field the YAML leaves out reverts to its default and is
      refused like any other change the allowlist does not permit.

    patch_ops and override_yaml are mutually exclusive.

    Binding replaces any previous binding for this session. Sessions do not share
    a binding, and a config bound by one session is not readable by another.

    Args:
        profile_name: Name the operator registered the profile under.
        patch_ops: JSON-Patch operations to apply to the profile's config.
        override_yaml: Complete ASH config YAML replacing the profile's.

    Returns:
        Dict with success, mode ('static', 'inherit_and_patch' or 'override'),
        profile_name, session_id, and config_path -- the file inside this
        session's workspace that later scans will be handed. On failure,
        success=False and error, for an unknown profile, a denied patch op or
        override, or YAML that does not validate; with error_type
        session_workspace_busy while another request holds this session's
        workspace: the server removing a session unused longer than its time
        to live, clear_source, or the end of the session (select the profile
        again once the hold has ended). A set_source_git or
        set_source_zip_finalize in progress does not refuse it.
    """
    try:
        session_id = resolve_caller_session_id(ctx)
    except ValueError as e:
        await _tell_client_error(ctx, raw_controls_on_one_line(error_text(e)))
        return _session_error(e)

    # Needs a session: its result belongs to one, and this call may carry none.
    refusal = session_identity_refusal(session_id, "select_profile", ctx=ctx)
    if refusal is not None:
        await _tell_client_error(ctx, raw_controls_on_one_line(refusal["error"]))
        return refusal

    try:
        result = mcp_select_profile(
            profile_name,
            patch_ops=patch_ops,
            override_yaml=override_yaml,
            session_id=session_id,
        )
    except Exception as e:
        log_unexpected_error(logger, e, "Error in select_profile")
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"Error selecting profile: {error_text(e)}"
            ),
            "error_type": type(e).__name__,
        }

    if result.get("success"):
        await _tell_client(
            ctx,
            "info",
            raw_controls_on_one_line(
                f"Profile {profile_name!r} bound to session {session_id} "
                f"({result.get('mode')})"
            ),
        )
    else:
        await _tell_client_error(
            ctx,
            raw_controls_on_one_line(str(result.get("error", "select_profile failed"))),
        )
    return _with_session(result, session_id)


def _build_ash_exit_codes() -> str:
    """Build JSON string of ASH exit codes from the canonical constant.

    Each code with a scan's meaning (ASH_EXIT_CODES), and under ``commands`` the
    codes one command gives a meaning of its own: ``ash dependencies install``'s
    bad selection, at ASH_EXIT_BAD_SELECTION.
    """
    codes: Dict[str, Any] = {str(k): v for k, v in ASH_EXIT_CODES.items()}
    codes["commands"] = {
        "ash dependencies install": {
            str(ASH_EXIT_BAD_SELECTION): ASH_EXIT_BAD_SELECTION_MEANING
        }
    }
    return json.dumps(codes)


@mcp.resource("ash://exit-codes")
def get_ash_exit_codes() -> str:
    """Return the meaning of each ASH exit code as JSON."""
    return _build_ash_exit_codes()


def _builtin_scanner_lines() -> str:
    """One bullet per built-in scanner, read from the scanners ASH registers.

    Both resources below named five scanners in static text while the default
    configuration enables ten, so a client reading them was told about half of
    what a scan runs. The names come from ``ash_builtin.ASH_SCANNERS``, the
    classes a scan loads, and whether each is enabled from the operator's default
    configuration. Nothing is probed: whether each tool is installed takes
    seconds per scanner to find out, which is what ``list_scanners`` is for.

    ``ASH_SCANNERS`` is read directly rather than through
    ``load_internal_plugins``, which also subscribes the package's event handlers
    on every call.
    """
    from automated_security_helper.config.default_config import (
        default_config_for_tree,
    )
    from automated_security_helper.core.scanner_inventory import (
        _declared_config_class,
        _scanner_name_from_class,
    )
    from automated_security_helper.plugin_modules.ash_builtin import ASH_SCANNERS

    # As a scan rooted at the server's working directory loads it: an
    # ASH_CONFIG file inside this checkout stays loadable whatever it writes
    # for an operator-only option, so the resource answers instead of failing
    # over a value a scan reads past.
    default_config = default_config_for_tree()
    lines = []
    for scanner_class in ASH_SCANNERS:
        config_class = _declared_config_class(scanner_class)
        name = (
            getattr(config_class(), "name", None) if config_class is not None else None
        ) or _scanner_name_from_class(scanner_class)
        plugin_config = default_config.get_plugin_config(
            plugin_type="scanner", plugin_name=name
        )
        enabled = (plugin_config or {}).get("enabled", True)
        lines.append(f"• {name}" if enabled else f"• {name} (disabled in the config)")
    return "\n".join(sorted(lines))


@mcp.resource("ash://status")
def get_ash_status() -> str:
    """Get the current status of ASH installation."""
    try:
        from automated_security_helper.utils.get_ash_version import get_ash_version

        version = get_ash_version()
        scanners = _builtin_scanner_lines()
        return f"""ASH Status: ✅ READY

ASH version {version}

ASH is installed and scans run in local mode. Whether each scanner's tool is
installed is not checked here.
Built-in scanners:
{scanners}

A scanner runs only when its tool is installed. Call the list_scanners tool for
each scanner's version and whether its dependencies are met.
"""
    except Exception as e:
        log_unexpected_error(logger, e, "Error getting ASH status")
        # Client-visible, so written as every other error text the module hands
        # a client: controls as escapes, on one line.
        return f"""ASH Status: ❌ ERROR

Error: {raw_controls_on_one_line(error_text(e))}

Please check your ASH installation.
"""


@mcp.resource("ash://help")
def get_ash_help() -> str:
    """Get help information about ASH usage."""
    try:
        scanners = _builtin_scanner_lines()
    except Exception as e:
        log_unexpected_error(logger, e, "Error listing scanners for ash://help")
        scanners = "• (could not be listed; call the list_scanners tool)"
    return (
        """ASH (Automated Security Helper) Usage Guide

ASH is a security scanning orchestrator that runs multiple security tools.

🔍 **Built-in scanners:**
"""
        + scanners
        + """

📁 **Supported File Types:**
• Python (.py)
• JavaScript/TypeScript (.js, .ts)
• CloudFormation (.yaml, .yml, .json)
• Terraform (.tf)
• Dockerfile
• And many more...

⚙️ **Local Mode Benefits:**
• No Docker required
• Good for development and CI/CD
• A scanner runs only when its tool is installed; list_scanners says which are

🎯 **Best Practices:**
• Run scans early and often
• Review all findings, even low severity
• Use in pre-commit hooks for continuous security
• Combine with manual security reviews
"""
    )


#: What the two prompts name when the caller names no source_dir. A prompt has
#: no request context, so it cannot tell a local client from a network one, and
#: the server's working directory is the right target only for the first: on a
#: network session it is the server's own tree, which run_ash_scan refuses to
#: fall back to (_resolve_omitted_source_dir). Naming it here steered a remote
#: agent to pass it explicitly. The prompt names the session's directory instead
#: and has the agent omit source_dir, which run_ash_scan resolves the same way
#: for both: the delivered tree, or the working directory for the local client.
_SESSION_SOURCE_DIR_WORDS = (
    "this session's source directory (the tree delivered with set_source_git or "
    "set_source_zip_finalize, or the server's working directory for the local "
    "client that started it over stdio)"
)


@mcp.prompt(
    title="Run ASH Security Scan",
    description="This prompt invokes an ASH security scan of the source directory, defaulting to the current one",
)
def run_ash_security_scan(source_dir: Optional[str] = None) -> str:
    """Create a prompt for analyzing ASH security scan results"""
    if source_dir is None:
        target = _SESSION_SOURCE_DIR_WORDS
        how = (
            "The scan should be done using the `run_ash_scan` MCP tool from the "
            "`ash` MCP Server, called with no source_dir: the tool resolves that "
            "directory itself and refuses to guess when nothing was delivered."
        )
    else:
        target = f"the following directory: {source_dir}"
        how = (
            "The scan should be done using the `run_ash_scan` MCP tool from the "
            "`ash` MCP Server."
        )
    return f"""Please run an ASH security scan of {target}

{how}

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
    where = (
        _SESSION_SOURCE_DIR_WORDS
        if source_dir is None
        else f"the source_dir:\n{source_dir}"
    )
    return f"""Please analyze these ASH security scan results in {where} and provide:

1. **Summary**: Brief overview of the security scan results
2. **Key Findings**: Most important security issues discovered
3. **Risk Assessment**: Categorize findings by severity and potential impact
4. **Recommendations**: Specific actions to address the security issues
5. **Next Steps**: Prioritized list of what to fix first

Scan Result Locations:

1. SARIF - Contains raw aggregated vulnerability findings in SARIF format: .ash/ash_output/reports/ash.sarif
2. Markdown Summary - Contains a summary of the results in Markdown format with up to 20 findings by default: .ash/ash_output/reports/ash.summary.md

Focus on actionable insights and practical remediation steps."""


#: Decision point: whether ``ash mcp`` honors ASH_ALLOW_IN_TREE_TOOLS. It does not:
#: an MCP client chooses what is scanned, including trees it delivers, so its scans
#: never run a tool from inside a scanned tree, whatever the server's environment
#: says. Scanners for MCP use are installed outside the repository. See
#: utils/subprocess_utils.honor_in_tree_opt_in.
MCP_HONORS_IN_TREE_OPT_IN = False


def _flush_stdout() -> None:
    try:
        sys.stdout.flush()
    except (OSError, ValueError, RuntimeError):
        # RuntimeError: a termination signal handled while the buffered writer was
        # already flushing, which Python refuses as "reentrant call". The late
        # handlers are installed before _keep_stdout_off_the_wire flushes, so
        # exit_at_once can run inside that flush; it is about to end the process,
        # and what the interrupted flush held is not wanted.
        pass


def _stdout_is_fd_1() -> bool:
    """Whether sys.stdout writes to fd 1: the case in which the SDK claims fd 1."""
    try:
        return sys.stdout.buffer.fileno() == 1
    except (AttributeError, OSError, ValueError):
        return False


def _keep_stdout_off_the_wire() -> None:
    """Point fd 1 at stderr for the rest of the process.

    The SDK has just put fd 1 back on the client's pipe. Nothing in an `ash mcp`
    process writes there legitimately once the transport is done, and a scan that
    did not stop in time, or a child process it started, still could.
    """
    try:
        diversion = os.dup(2)
    except OSError:
        diversion = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(diversion, 1)
    finally:
        os.close(diversion)
    _flush_stdout()


async def _stop_on_signal(signals: Optional[Iterable[int]] = None) -> None:
    """On SIGTERM, SIGHUP or Ctrl-C, stop the scans as a disconnect does, then exit.

    ``signals`` defaults to _watched_stop_signals().

    The MCP SDK's stdio client sends SIGTERM to a server that has not exited two
    seconds after its stdin closed, and a supervisor may send it at any time.
    Unhandled, SIGTERM ended the process at once, in the middle of stopping its
    scans: their previous results stayed set aside, and their scanners' tools,
    which run in process groups of their own, kept running. So did SIGHUP, from
    a closed terminal or a supervisor.

    The scans are stopped here, on this task, rather than by cancelling the
    serving and letting the lifespan do it: the transport reads stdin on a
    worker thread that a cancel cannot interrupt, so with stdin still open the
    serving would never finish unwinding. Ctrl-C is such a cancel: asyncio turns
    SIGINT into a cancel of the serving, and a server whose client keeps stdin
    open would still be running 20 seconds later. Once the scans have stopped, or
    STDIO_SCAN_STOP_TIMEOUT_SECONDS has passed, the process exits without
    unwinding the transport, with the signal's status in _STOP_SIGNALS: 0 for
    SIGTERM and SIGHUP, ASH_EXIT_INTERRUPTED for SIGINT. Running alongside a
    stop the lifespan has begun is harmless: both wait on the same scans.
    """
    if signals is None:
        signals = _watched_stop_signals()
    with anyio.open_signal_receiver(*signals) as received:
        async for signum in received:
            name = signal.Signals(signum).name
            logger.warning(f"{name} received: stopping the scans and the server")
            with anyio.CancelScope(shield=True):
                await stop_running_scans(
                    f"the server received {name}",
                    timeout=STDIO_SCAN_STOP_TIMEOUT_SECONDS,
                    promptly=True,
                )
            exit_at_once(_STOP_SIGNALS[signum])


#: The stdio server's presence entry while run_mcp_server serves, for exit_at_once:
#: os._exit skips the finally that would leave it, and with it the removal of
#: the default workspace when this is the last stdio server.
_stdio_presence: Optional[Any] = None


def _leave_stdio_presence() -> None:
    """Drop this server's presence entry, and the default workspace if it is the last.

    What run_mcp_server's finally does on a return; called by exit_at_once,
    which never returns there. Idempotent, so the finally after a recorded exit
    (tests replace os._exit) finds nothing left to do. A failure to leave does
    not keep the process from exiting: the entry's lock is released with the
    process either way, and the next stdio server drops the dead entry when it
    registers.
    """
    presence = _stdio_presence
    if presence is None:
        return
    try:
        presence.__exit__(None, None, None)
    except Exception as e:
        logger.warning(f"Could not remove the stdio session workspace: {e}")


def exit_at_once(status: int) -> None:
    """End the process with ``status``, without waiting for any scan's thread.

    For a server whose stop is done: what put back a stopped scan's previous
    results has run by then, on that scan's thread. A scan still stopping when
    the wait ran out has its tool running in a session of its own, which
    os._exit does not end, so what is left of the tools' groups is killed first.
    os._exit skips the interpreter's own cleanup, so stdout and the log
    handlers are flushed here, and the stdio server's presence entry is left
    (_leave_stdio_presence), which removes the default workspace when this was
    the last stdio server, as a return through run_mcp_server does.
    """
    kill_running_groups()
    _leave_stdio_presence()
    _flush_stdout()
    logging.shutdown()
    os._exit(status)


def _exit_on_late_signal(signum: int, frame: Any) -> None:
    """A stop signal after the transport returned: end the tools' groups, exit.

    The lifespan has stopped the scans by then (promptly, for at most
    STDIO_SCAN_STOP_TIMEOUT_SECONDS), and the asyncio watcher is gone with the
    event loop's serving. But the interpreter still waits for a scan thread that
    did not stop, one busy outside a scanner's tool, and the client sends SIGTERM
    two seconds after it closed stdin. With no handler, that SIGTERM would end the
    server with -15, not the 0 a SIGTERM gets while it serves, and a Ctrl-C would
    raise KeyboardInterrupt into that wait while the server went on waiting for
    the thread and exited 0. So each, and SIGHUP, exits with the status it gets
    while the server serves (_STOP_SIGNALS). The scan's previous results stay
    set aside; the next MCP scan in that directory takes them back.
    """
    name = signal.Signals(signum).name
    logger.warning(f"{name} received while waiting for a scan to stop: exiting")
    exit_at_once(_STOP_SIGNALS[signum])


def _watches_signals() -> bool:
    """Whether this thread can watch for _STOP_SIGNALS: the main thread, not Windows.

    Python lets only the main thread set signal handlers; started on another one,
    the watcher raised "set_wakeup_fd only works in main thread" into a server
    that had closed cleanly.
    """
    return os.name != "nt" and threading.current_thread() is threading.main_thread()


async def _serve_stdio() -> None:
    claims_fd_1 = _stdout_is_fd_1()
    watches_signals = _watches_signals()
    stop_signals = _watched_stop_signals() if watches_signals else {}
    # A task of its own rather than a task group around the serving: a group
    # would wrap whatever the serving raises in an exception group, and
    # run_mcp_server tells a client that left from a failure by the exception.
    watcher = (
        asyncio.get_running_loop().create_task(_stop_on_signal(stop_signals))
        if watches_signals
        else None
    )
    try:
        await mcp.run_stdio_async()
    finally:
        if watcher is not None:
            watcher.cancel()
            with suppress(asyncio.CancelledError):
                await watcher
        # Closing the watcher left the signals it watched at their defaults, and
        # the interpreter may still wait for a scan thread.
        for signum in stop_signals:
            signal.signal(signum, _exit_on_late_signal)
        if claims_fd_1:
            _keep_stdout_off_the_wire()


async def stop_scans_at_server_exit(reason: str) -> bool:
    """Stop the scans promptly, then kill what is left of their tools' groups.

    For a server about to exit that has no client to report to: the HTTP
    transports call it when their app's lifespan ends (cli/mcp), as the stdio
    lifespan does when its client leaves. Returns whether a scan (stop_running_scans)
    or a source clone or delivery (_begin_stopping_source_jobs) was still
    running when the wait ended.
    """
    with anyio.CancelScope(shield=True):
        deadline = time.monotonic() + STDIO_SCAN_STOP_TIMEOUT_SECONDS
        joiner = _begin_stopping_source_jobs()
        still_running = await stop_running_scans(
            reason, timeout=STDIO_SCAN_STOP_TIMEOUT_SECONDS, promptly=True
        )
        jobs_running = await _wait_for_source_jobs(joiner, deadline)
    kill_running_groups()
    return bool(still_running) or jobs_running


#: What the transport raises when the client has gone: its end of a pipe closed
#: while the server was reading or writing.
_CLIENT_GONE = (
    BrokenPipeError,
    ConnectionResetError,
    anyio.BrokenResourceError,
    anyio.ClosedResourceError,
    anyio.EndOfStream,
)


def _grouped(error: BaseException) -> Optional[tuple]:
    """The exceptions ``error`` groups, if it is an exception group.

    By its ``exceptions`` tuple rather than by class: the built-in group types
    exist from Python 3.11, and on 3.10 anyio raises the exceptiongroup
    backport's.
    """
    inner = getattr(error, "exceptions", None)
    return inner if isinstance(inner, tuple) else None


def _only_the_client_left(error: BaseException) -> bool:
    """Whether ``error``, and every exception it groups, is the client going away."""
    inner = _grouped(error)
    if inner is not None:
        return all(_only_the_client_left(e) for e in inner)
    return isinstance(error, _CLIENT_GONE)


def _interrupted(error: BaseException) -> bool:
    """Whether ``error`` is a Ctrl-C, alone or grouped with the client going away.

    A group counts only if it holds a KeyboardInterrupt: one of nothing but the
    client going away is a disconnect, which exits 0.
    """
    inner = _grouped(error)
    if inner is not None:
        return any(_interrupted(e) for e in inner) and all(
            _interrupted(e) or _only_the_client_left(e) for e in inner
        )
    return isinstance(error, KeyboardInterrupt)


def run_mcp_server():
    """Serve MCP over stdio until the client closes the connection.

    Returns when the client closes the connection, also when it does so while the
    server is writing to it: `ash mcp` exits 0 for both. Any other failure is
    raised, and `ash mcp` exits 1 with the error on stderr. An exception group
    counts as a dropped connection only when every exception it groups is the
    client going away, whatever its message says ("TaskGroup" is in every anyio
    task group failure's).

    Scans still running when the client leaves are stopped first (_lifespan).
    On Linux and macOS, SIGTERM, SIGHUP and Ctrl-C stop them the same way,
    whether or not stdin is still open, and then end the process without
    returning here (_stop_on_signal): with status 0 on SIGTERM and SIGHUP and
    130 on Ctrl-C, also once the transport has returned (_exit_on_late_signal).
    A SIGINT or a SIGHUP the process was started with ignored stays ignored
    (_watched_stop_signals). On Windows the server cannot watch for signals
    (_watches_signals), and Ctrl-C takes asyncio's path instead: it cancels the
    serving, the lifespan stops the scans, whose tools never see the Ctrl-C
    (subprocess_utils starts them with CREATE_NEW_PROCESS_GROUP), and
    KeyboardInterrupt is raised from here, so `ash mcp` exits 130, but only once
    the client has closed stdin: the SDK reads it on a non-daemon worker thread
    that a cancel cannot interrupt. The previous handlers of the stop signals are
    put back on the way out, except while a source clone or delivery is still
    running (_wait_for_source_jobs): the interpreter's own exit waits for that
    thread after this returns, and a SIGTERM then, with the previous handler's
    default action, would end the server with -15 and leave the tools' groups
    running, so _exit_on_late_signal stays installed until the process ends.

    The HTTP transports are served by uvicorn instead (cli/mcp). There, Ctrl-C
    stops the server gracefully, the app's lifespan stops the scans, and
    `ash mcp` exits 130 as well. A SIGINT or a SIGHUP the process was started
    with ignored stays ignored there too (cli/mcp._uvicorn_server_class and
    cli/mcp._ask_server_to_stop_on_sighup), so on every transport.
    """
    global _serving_stdio, _source_jobs_left_running, _stdio_presence
    _source_jobs_left_running = False
    # The sinks that are not handlers write to sys.stderr as given: lastResort
    # for a library logger with no handler, warnings, and the thread and sys
    # excepthooks. Python's writes to sys.stderr, bytes to its buffer included,
    # go through the check, once, and so do text writes to sys.stdout: while the
    # server serves, fd 1 points at stderr and a stray print lands there; the
    # SDK's frames go through its own copy of fd 1 or sys.stdout.buffer, which
    # the stdout wrap hands on unchecked. Made here, as the server starts, so
    # that a program that imports this module for its tools keeps its own
    # streams.
    check_commands_of_stderr()
    check_commands_of_stdout()
    # stdio serves one client for the life of the process, so its session ends
    # when the server does. The default workspace is shared by every stdio
    # server of the same user, so it is removed only when the last of them
    # exits; see ``sessions.StdioServerPresence``. Its one client is the local
    # client, the only caller that gets stdio's local trust
    # (``serving_local_client``). MCP scans never run a tool from inside a
    # scanned tree, whatever the server's environment says.
    from automated_security_helper.cli.mcp.sessions import StdioServerPresence
    from automated_security_helper.utils.subprocess_utils import honor_in_tree_opt_in

    honor_in_tree_opt_in(MCP_HONORS_IN_TREE_OPT_IN)
    _serving_stdio = True
    previous_handlers = (
        {signum: signal.getsignal(signum) for signum in _STOP_SIGNALS}
        if _watches_signals()
        else {}
    )
    stdio_presence = StdioServerPresence()
    try:
        # Inside the try, so that a server which cannot lock its presence entry
        # (PresenceLockError) still clears the stdio flag and puts the signal
        # handlers back as the error propagates: it does not start.
        stdio_presence.__enter__()
        # Known to exit_at_once from here: SIGTERM, SIGHUP and Ctrl-C end the
        # process without reaching the finally below, and leave the entry through it.
        _stdio_presence = stdio_presence
        with serving_local_client():
            anyio.run(_serve_stdio)
    except KeyboardInterrupt:
        logger.info("MCP server stopped by user")
        raise
    except BaseException as e:
        if _interrupted(e):
            # A Ctrl-C grouped with the client going away is still a Ctrl-C.
            logger.info("MCP server stopped by user")
            raise KeyboardInterrupt from e
        elif _only_the_client_left(e):
            logger.warning(
                "The MCP client closed the connection while the server was "
                "reading from or writing to it"
            )
        else:
            raise
    finally:
        _serving_stdio = False
        _stdio_presence = None
        try:
            stdio_presence.__exit__(None, None, None)
        except Exception as e:
            # Shutdown must not fail on cleanup.
            logger.warning(f"Could not remove the stdio session workspace: {e}")
        for signum, handler in previous_handlers.items():
            if handler is None:
                continue
            if (
                _source_jobs_left_running
                and signal.getsignal(signum) is _exit_on_late_signal
            ):
                # The interpreter waits for the job's thread after this returns.
                continue
            signal.signal(signum, handler)


def _run_as_the_mcp_command(**kwargs: Any) -> Any:
    """``ash mcp`` with this process's arguments, for ``python -m``.

    The entry point's ``run_module_app`` calls the app it is given the way click's
    ``main`` is called, with ``standalone_mode=False``, so a usage error and a
    command's exit code come back to it instead of ending the process there. The
    three command modules hand it a Typer app, which takes that keyword; this
    module runs the root app's ``mcp`` command instead, so whatever the entry
    point passes is forwarded to the root app behind the command name and this
    process's arguments. A callable that took no keyword failed every
    ``python -m automated_security_helper.cli.mcp_server`` start with a TypeError
    once the entry point began passing one. The imports are inside: cli.main
    imports this module.
    """
    import sys

    from automated_security_helper.cli.main import app

    return app(["mcp", *sys.argv[1:]], **kwargs)


if __name__ == "__main__":
    # `python -m automated_security_helper.cli.mcp_server` starts the way `ash mcp`
    # does, with the same arguments, so it makes the same startup checks
    # (ASH_CONFIG, ASH_MCP_TRANSPORT, the options) and the same process setup
    # before it serves. Run through the entry point's failure path, as the other
    # command modules are, so an exception that escapes is shown, not obeyed
    # (tests/unit/cli/test_typer_output_is_shown_not_obeyed.py).
    from automated_security_helper.cli.entrypoint import run_module_app

    run_module_app(_run_as_the_mcp_command)
