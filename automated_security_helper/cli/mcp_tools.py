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
import contextlib
import contextvars
import errno
import os
import stat
import threading
import time
import uuid
import zipfile
from datetime import datetime
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    List,
    NamedTuple,
    Optional,
    Tuple,
    Union,
    cast,
)

from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.core.resource_management.scan_registry import (
    get_scan_registry,
    MCScanStatus,
)
from automated_security_helper.core.resource_management.scan_tracking import (
    get_scan_results_with_error_handling,
    resolves_to_directory_inside,
    restored_results_refusal,
)
from automated_security_helper.core.resource_management.scan_management import (
    list_active_scans,
    cancel_scan,
    check_scan_progress,
)
from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
    create_error_response,
    source_directory_error,
    validate_output_directory_path,
)
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.cli.mcp.session_identity import (
    UNIDENTIFIED_SESSION_ID,
)
from automated_security_helper.utils.directory_refusals import output_dir_unmakeable
from automated_security_helper.utils.numeric_text import MIN_REDACTED_LENGTH
from automated_security_helper.utils.error_text import (
    carry_environment_values,
    config_environment_values,
    error_text,
    log_unexpected_error,
    os_error_without_named_file,
    text_without_values,
    timeout_limit_phrase,
)

# A tool's error, which a client reads and may display, holds no control
# character: each is written as its escape, on one line.
from automated_security_helper.utils.terminal_text import raw_controls_on_one_line
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.output_dir_links import (
    WHY as OUTPUT_LINK_WHY,
    OutputDirLinkRefused,
)
from automated_security_helper.utils.log import (
    ASH_LOGGER,
    begin_run_log_scope,
    current_run_log_scope,
    disown_run_log_scope,
    end_run_log_scope,
    hold_run_log_scope,
    open_run_log_scope,
    release_run_log_scope,
)

if TYPE_CHECKING:
    # Typing only: the runtime import stays local to the tools that need it.
    from automated_security_helper.cli.mcp.sandbox import ConfigInputCheck
    from automated_security_helper.config.ash_config import (
        AshConfig,
        MCPResourceManagementConfig,
    )
    from automated_security_helper.config.config_sources import OpenedConfig
    from automated_security_helper.config.config_validator import ConfigCheck
    from automated_security_helper.config.operator_only_options import (
        RepositorySettings,
    )

# Configure module logger (without affecting global logging)
# The MCP logging patch will ensure this logger is properly isolated
_logger = ASH_LOGGER

#: The remedy for a scan this server started: it writes to .ash/ash_output in the
#: scanned directory, which the client cannot redirect.
MCP_SCAN_OUTPUT_REMEDY = (
    f"{OUTPUT_LINK_WHY} This server writes a scan's output to .ash/ash_output in the "
    "scanned directory: replace the link there with a directory."
)

#: The runner task of every scan this process started that has not ended, with
#: its scan id. asyncio holds only a weak reference to a task, so a runner that
#: nothing else referenced could be collected mid-scan; and the stdio server
#: stops these when its client leaves (stop_running_scans).
_scan_tasks: Dict["asyncio.Task[None]", str] = {}


def _start_scan_task(
    scan_id: str,
    runner: Any,
    *,
    if_never_run: Optional[Callable[[], None]] = None,
) -> None:
    """Start ``runner``, a scan's coroutine, as the scan's task.

    ``if_never_run`` is what to do when the task ends without the runner having
    run a line. A task cancelled before the loop first ran it (the server
    stopping right after the start) runs no line of the coroutine, its
    ``finally`` included, so what that ``finally`` would have released -- the
    session claim, the count against the per-session limit, the PENDING entry
    -- is released by this callback instead.

    Whether the runner ran is this function's own reading: the runner is started
    through a wrapper that marks the start as its first step, before the first
    line of the runner, so the mark cannot be left out. Handed in as a marker
    the caller also had to pass to the runner, a caller that passed it here
    alone would have had the callback release, a second time, everything a
    runner that did run released itself.
    """
    ran = False

    async def _mark_then_run() -> None:
        nonlocal ran
        ran = True
        await runner

    task = asyncio.create_task(_mark_then_run())
    _scan_tasks[task] = scan_id
    task.add_done_callback(lambda done: _scan_tasks.pop(done, None))

    def _release_if_the_runner_never_ran(done: "asyncio.Task[None]") -> None:
        if ran:
            return
        # The runner was never awaited: closed here, so nothing warns of an
        # un-awaited coroutine when it is collected.
        close = getattr(runner, "close", None)
        if close is not None:
            close()
        if if_never_run is not None:
            if_never_run()

    task.add_done_callback(_release_if_the_runner_never_ran)
    # The scan's log scope, which the task inherits from this context, is held
    # until the task is done, however it ends: a runner cancelled before the
    # loop first ran it never reaches its own cleanup, and an open scope the
    # server opened keeps every line of no run's out of every run's handlers.
    # The runner and its scan thread hold it as well, so it closes after the
    # last of them (utils/log.py, release_run_log_scope).
    log_scope = current_run_log_scope()
    if log_scope is not None:
        hold_run_log_scope(log_scope)
        task.add_done_callback(lambda done: release_run_log_scope(log_scope))


async def stop_running_scans(
    reason: str, timeout: float, promptly: bool = False
) -> bool:
    """Cancel every scan this process is running and wait for each to stop.

    Each is cancelled the way cancel_scan cancels one, so it stops at its next
    check, its scanner's tool is stopped with every process it started, and the
    previous results in its output directory are put back. With ``promptly`` the
    tool gets PROMPT_STOP_GRACE_SECONDS after SIGTERM instead of the usual ten
    seconds, for a process that is about to be killed. Waits at most ``timeout``
    seconds in all; a scan still running then is named in the log and left to the
    process exit.

    Workspace scans too (cli/mcp/workspace.stop_workspace_scans): every project of
    each is cancelled, and the wait is for the scan's thread to have stopped and
    settled.

    Returns whether a scan was still running when the wait ended: its thread,
    busy where no cancel check reaches it, is one the event loop's executor will
    wait for when the loop closes.
    """
    from automated_security_helper.cli.mcp.workspace import stop_workspace_scans

    # This loop's: a task of a loop that is gone can never finish, and waiting
    # on it would only run out the timeout.
    loop = asyncio.get_running_loop()
    running = {
        task: scan_id
        for task, scan_id in _scan_tasks.items()
        if task.get_loop() is loop and not task.done()
    }
    registry = get_scan_registry()
    for scan_id in running.values():
        _logger.warning(f"Stopping scan {scan_id}: {reason}")
        entry = registry.get_scan(scan_id)
        if promptly and entry is not None:
            entry.cancel_event.stop_promptly = True
        registry.cancel_scan(scan_id)
    workspaces = stop_workspace_scans(reason, promptly)
    if not running and not workspaces:
        return False
    _, still_running = await asyncio.wait([*running, *workspaces], timeout=timeout)
    for pending in still_running:
        if pending in running:
            _logger.error(
                f"Scan {running[pending]} did not stop within {timeout:g}s of its "
                "cancel"
            )
        else:
            _logger.error(
                f"A workspace scan did not stop within {timeout:g}s of its cancel"
            )
    return bool(still_running)


#: ``error_type`` of every refusal of a config input outside the permitted roots,
#: whichever tool refused it. The same value ``run_ash_scan`` returns.
CONFIG_INPUT_NOT_PERMITTED = "config_input_not_permitted"
#: ``error_type`` for a client-delivered config that sets a field the session's
#: runtime-override policy denies; see ``config/client_config_policy.py``.
CONFIG_FIELD_DENIED = "config_field_denied"
#: ``error_type`` for a client-delivered config whose policy cannot be established.
CONFIG_POLICY_UNREADABLE = "config_policy_unreadable"
#: ``error_type`` for a scan refused because the check of the config sources in
#: its target could not finish (an unreadable entry, a link loop). The config is
#: not known to be outside the permitted roots, so this is not
#: ``CONFIG_INPUT_NOT_PERMITTED``.
CONFIG_CHECK_FAILED = "config_check_failed"

#: ``error_type`` of the refusal of a config file an MCP client delivered that
#: reads from the environment, which such a file may not
#: (``ASHConfigEnvNotResolvedError``).
CONFIG_ENV_NOT_RESOLVED = "config_env_not_resolved"

#: ``error_type`` of the refusal of a profile in which a value read from the
#: environment is part of a longer string, which a session's copy would hold as
#: the value (``EnvironmentValueInPath``). The message names the key path and the
#: variable, never the value.
ENV_VALUE_IN_LONGER_STRING = "environment_value_in_longer_string"

#: ``error_type`` of the refusal of a config whose ``ash_plugin_modules`` a
#: scan refuses (a module outside the plugin namespace, or one no installed
#: package provides). Its own type: the file loaded and parsed, so the
#: load-failure frame sent a client to re-format a healthy file.
PLUGIN_MODULE_REFUSED = "plugin_module_refused"

#: The exit code a scan tool's refusal reports, by what it refused, so a client
#: can branch on it as a script branches on the CLI's status: a config the scan
#: cannot use (3, as the CLI exits for one), the request itself (5, the CLI's
#: usage-error code: a session header, a severity, a source_dir that is missing
#: or not a directory), a target the server will not scan (4, outside the
#: permitted roots), and anything else (1).
REFUSED_CONFIG_EXIT_CODE = 3
REFUSED_USAGE_EXIT_CODE = ASH_EXIT_USAGE_ERROR
REFUSED_TARGET_EXIT_CODE = 4
REFUSED_INTERNAL_EXIT_CODE = 1

#: ``error_type`` of a scan refused for its source directory: one that does not
#: exist, is not a directory, or cannot be entered. The same value
#: ``run_ash_scan`` returns.
SOURCE_DIR_NOT_USABLE = "source_dir_not_usable"


def _search_dir_outside_the_scan_roots(
    search: Path, session_id: Optional[str]
) -> Optional[Dict[str, Any]]:
    """The refusal of the scan tool's root policy for ``search``, or None.

    ``resolve_scan_target`` reads no existence and opens nothing under the
    directory, so the refusal says nothing about whether a directory outside
    the roots exists, and it can be made before any file is opened.
    """
    from automated_security_helper.cli.mcp.scan_target import resolve_scan_target

    target = resolve_scan_target(str(search), session_id=session_id)
    if target.error is None:
        return None
    return with_exit_code(
        {
            "success": False,
            "operation": "get_config",
            "error": raw_controls_on_one_line(str(target.error)),
            "error_type": "scan_target_not_permitted",
            # Mirrors the category create_error_response sets, as the
            # run_ash_scan wrapper does, so one key identifies a path
            # refusal from any entry point.
            "error_category": target.error.context["error_category"],
        },
        REFUSED_TARGET_EXIT_CODE,
    )


def _search_dir_a_scan_refuses(
    search: Path, session_id: Optional[str]
) -> Optional[Dict[str, Any]]:
    """The refusal a scan of ``search`` makes of its target, or None.

    ``search_dir`` names the directory the caller's scan will target, so it
    crosses the scan tool's own gates in the scan tool's order: the root
    policy first (:func:`_search_dir_outside_the_scan_roots`), then the
    source-directory check. One helper for both of ``mcp_get_config``'s
    branches, so the named-file and discovery answers cannot drift on what a
    scan of the same target refuses.
    """
    refused = _search_dir_outside_the_scan_roots(search, session_id)
    if refused is not None:
        return refused
    return source_directory_refusal(search, "get_config")


def source_directory_refusal(
    directory_path: Union[str, Path], operation: str
) -> Optional[Dict[str, Any]]:
    """The refusal of a scan of ``directory_path`` as its source, or None.

    In the CLI's words for ``--source-dir`` (``source_directory_error``), with
    the path as the caller gave it, ``error_type`` SOURCE_DIR_NOT_USABLE and
    ``exit_code`` 5, the code the CLI exits with for it.
    """
    error = source_directory_error(directory_path)
    if error is None:
        return None
    refusal = create_error_response(
        error=error,
        operation=operation,
        suggestions=[
            "Check that the path names the directory to scan",
            "Check that the directory can be read by the user the server runs as",
        ],
    )
    refusal["error_type"] = SOURCE_DIR_NOT_USABLE
    return with_exit_code(refusal, REFUSED_USAGE_EXIT_CODE)


#: ``error_type`` of a scan refused because a file is where its output directory
#: goes. The same value ``run_ash_scan`` returns.
OUTPUT_DIR_NOT_USABLE = "output_dir_not_usable"

#: ``error_type`` of a suggest_suppression refused because no suppression path names
#: the finding's file alone: its path holds a backslash, a separator in a pattern
#: (path_matching.literal_path_pattern).
PATH_NOT_EXPRESSIBLE = "path_not_expressible"

#: ``error_type`` of a suggest_suppression refused because the finding names no
#: file or no rule: a suppression built from it would match nothing (an empty
#: path), or every rule in the file (no rule id), never that finding alone.
SUPPRESSION_NOT_SPECIFIC = "suppression_not_specific"

#: ``error_type`` of a suggest_suppression refused for an ``expiration`` that is
#: not a YYYY-MM-DD date (``models.core.EXPIRATION_RULE``).
INVALID_EXPIRATION = "invalid_expiration"


def output_directory_refusal(
    directory_path: Union[str, Path], operation: str
) -> Optional[Dict[str, Any]]:
    """The refusal of a scan whose output directory is a file, or None.

    In the CLI's words for an ``--output-dir`` that is a file
    (``validate_output_directory_path``), with ``error_type``
    OUTPUT_DIR_NOT_USABLE and ``exit_code`` 5, the code the CLI exits with for
    it. A missing output directory is not refused: the scan creates it.
    """
    error = validate_output_directory_path(directory_path)
    if error is None:
        return None
    refusal = create_error_response(
        error=error,
        operation=operation,
        suggestions=["Remove or rename the file where the scan writes its output"],
    )
    refusal["error_type"] = OUTPUT_DIR_NOT_USABLE
    return with_exit_code(refusal, REFUSED_USAGE_EXIT_CODE)


def _exit_message(ended: SystemExit) -> str:
    """Why a scan ASH ended with a non-zero exit failed, as plain text.

    The code, then, for a run ASH refused or gave up (ScanRefusedExit), the text
    the CLI showed for it. Not shown: :func:`_scan_failed` shows it once, in the
    error_message and in the log line it is put in.
    """
    from automated_security_helper.interactions.run_ash_scan import ScanRefusedExit

    message = f"ASH exited with code {ended.code}"
    if isinstance(ended, ScanRefusedExit) and ended.message:
        message = f"{message}: {ended.message}"
    return message


def _scan_failed(
    registry: Any,
    scan_id: str,
    reason: str,
    exit_code: Optional[int] = None,
    environment_values: Tuple[str, ...] = (),
) -> None:
    """Close a scan as failed with *reason*, and log it.

    *reason* is plain text, and is shown on one line once where it is used: in
    the error_message a client reads, and in the whole log line, since a log sink
    shows the text it is given and a line built around shown text would show it
    twice. The text quotes paths, names, config values and exception messages
    from the repository and the operator, and a client may print it to a
    terminal or a CI log. ``environment_values`` are what the scan's config
    read from the environment: the scan runs with that config in use, so a
    reason that quotes one of its values is shown redacted on both sinks.
    """
    from automated_security_helper.utils.terminal_text import shown_on_one_line

    reason = text_without_values(reason, environment_values)
    registry.finish_scan(
        scan_id,
        MCScanStatus.FAILED,
        shown_on_one_line(reason),
        exit_code=exit_code,
    )
    _logger.error(shown_on_one_line(f"Scan {scan_id} failed: {reason}"))


def with_exit_code(response: Dict[str, Any], code: int) -> Dict[str, Any]:
    """``response``, a refusal, with ``exit_code`` and its ``exit_code_meaning``."""
    from automated_security_helper.core.constants import ASH_EXIT_CODES

    response["exit_code"] = code
    response["exit_code_meaning"] = ASH_EXIT_CODES[code]
    return response


def _resource_limits() -> "MCPResourceManagementConfig":
    """The operator's MCP resource limits: ASH_CONFIG's section, else the defaults.

    ``mcp-resource-management`` declares server limits, so it is read from the
    operator's default config and never from the config a scan resolves, which can
    be the scanned repository's own or one a client delivered: a limit that the
    party it limits can raise is not one. Two of its fields are enforced,
    ``max_concurrent_scans`` and ``scan_timeout_seconds``; the model says which.
    Read per scan, so a changed ASH_CONFIG file applies to the next one.

    Loaded as a scan rooted at the server's working directory loads it
    (default_config_for_tree): what an ASH_CONFIG file inside this checkout
    writes for an operator-only option is left out, so a value a scan reads
    past does not make the limits unreadable. The limits themselves are not
    operator-only options, so the file's own section is read as written.
    """
    from automated_security_helper.config.default_config import (
        default_config_for_tree,
    )

    return default_config_for_tree().mcp_resource_management


def _operator_environment_values(limits: Any) -> Tuple[str, ...]:
    """The values the operator's ASH_CONFIG chain read from the environment,
    off the section _resource_limits returns.

    A configuration gives every section it holds its environment values
    (redacted_model.carry_environment_values), so the limits section carries
    the whole chain's. They join the scan's own config's values in the
    redaction set: every scan starts from the operator's file too, and it can
    read the environment the same way. Read tolerantly, so a test double with
    no record adds none and a reading that raises removes none of the scan's
    own values.
    """
    from automated_security_helper.utils.redacted_model import environment_strings

    getter = getattr(limits, "redaction_values", None)
    if not callable(getter):
        # A stand-in with no record carries no values; said at DEBUG, since
        # test doubles land here by design.
        _logger.debug(
            "the operator chain's environment values are not readable from "
            "the limits section; the scan's own values still redact"
        )
        return ()
    try:
        return environment_strings(getter())
    except Exception as exc:  # noqa: BLE001 -- the scan's own values still redact
        # Only the type: the values this failed to read are the ones no log
        # line may hold.
        _logger.warning(
            "the operator chain's environment values could not be read for "
            f"redaction ({type(exc).__name__}); the scan's own values still "
            "redact"
        )
        return ()


def _profile_environment_values(
    profile: Optional[Path],
    source_dir: Optional[str] = None,
    permit_base: Optional[Callable[[Path], bool]] = None,
) -> Tuple[str, ...]:
    """The environment values the session-bound profile's chain read.

    For a scan of a client-delivered config: the scan resolves the profile as
    its trusted base, so a failure's text can quote what that chain read from
    the environment, and the pre-check -- which resolves only the delivered
    file's own chain -- never saw those values. Resolved the way the scan
    itself loads the trusted base (``load_config_file_for_run`` with the
    scan's source directory and the session's base gate), so a chain is in
    this set exactly when the scan runs with it. Read tolerantly: the scan's
    own values still redact when this read fails, and the failure is logged
    by type only, since the values it failed to read are the ones no log
    line may hold.
    """
    if profile is None:
        return ()
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )

    try:
        _document, config = load_config_file_for_run(
            profile, source_dir=source_dir, permit_base=permit_base
        )
        return tuple(config._environment_values)
    except Exception as exc:  # noqa: BLE001 -- the scan's own values still redact
        _logger.warning(
            "the session profile's environment values could not be read for "
            f"redaction ({type(exc).__name__}); the scan's own values still "
            "redact"
        )
        return ()


class ProfileSnapshotUnavailable(RuntimeError):
    """The per-scan copy of the session's profile could not be written.

    Fails the scan closed: without the copy the scan would load the live
    profile again after any wait for the session lock, and the live file is
    the one whose mid-wait rebinds the redaction set never saw. The message
    carries the failure's type only, because the file that could not be
    copied is the one whose values no recorded reason may hold.
    """


def _foreign_scan_copy_max_age_seconds() -> float:
    """How long a copy whose writer is not provably in this process's own pid view
    is kept before the sweep removes it.

    A scan is bounded by its timeouts, far inside this, so a copy older than it is
    no live scan's. It is the bound the sweep of interrupted container runs puts on
    its own records, one number for both sweeps, so the two cannot drift apart. The
    runtime import stays local, as the others from that package in this module do.
    """
    from automated_security_helper.interactions.container_leftovers import (
        RECORD_MAX_AGE_SECONDS,
    )

    return RECORD_MAX_AGE_SECONDS


#: How far ahead of this clock a copy's modification time may sit before the
#: sweep stops believing it: a writer on another host whose clock runs a little
#: fast is normal on a shared filesystem, a date days ahead is not a write time.
_CLOCK_SKEW_ALLOWANCE_SECONDS = 24 * 3600

#: "This host's token", the default of ``_scan_snapshot_path``'s ``writer_host``,
#: told apart from an explicit None (a writer with no identity).
_THIS_HOST = object()


def _this_host_token() -> Optional[str]:
    """The identity token of the place this process runs in, or None.

    The sweep of the interrupted container runs' records decides what is its own
    by the same key (``container_leftovers.host_key``: the boot and the pid
    namespace on Linux, the boot session on macOS), so a pid is read in the pid
    view that gave it. None where that cannot be read, and a copy written without
    a token matches no host.
    """
    import hashlib

    from automated_security_helper.interactions.container_leftovers import host_key

    key = host_key()
    if key is None:
        return None
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _scan_snapshot_path(
    profile: Path,
    scan_id: str,
    writer_pid: Optional[int] = None,
    writer_host: Any = _THIS_HOST,
) -> Path:
    """Where one scan's copy of the profile lives: beside it, named for the scan.

    Deterministic for a given host identity, so the runner records it before
    the file exists and its cleanup covers the whole window the copy is
    written in; the runner computes it once per scan and hands it to the
    writer (``_snapshot_profile_for_scan``) rather than building it twice.
    Built from the
    prefix messages map back to the copied file's own name
    (config_sources.SCAN_COPY_PREFIX and original_of_scan_copy): the scan id
    is a UUID, never holding a dot, so the mapping is unambiguous.

    The name also records the writing process's pid (this process's, unless
    a test names another) and the identity of the place it ran in
    (``_this_host_token``, unless a test names another, or None for a writer that
    could not read its own): servers on the default session share one config
    directory, and the sweep must not remove a copy a sibling server's live
    scan holds (_sweep_stale_scan_snapshots). The directory can be on a shared
    filesystem, where a pid means nothing in another host's view, so the pid is
    only ever asked about for a copy whose identity is the sweeper's own.
    """
    from automated_security_helper.config.config_sources import (
        SCAN_COPY_HOST_MARK,
        SCAN_COPY_PID_MARK,
        SCAN_COPY_PREFIX,
    )

    pid = os.getpid() if writer_pid is None else writer_pid
    host = _this_host_token() if writer_host is _THIS_HOST else writer_host
    host_part = "" if host is None else f"{SCAN_COPY_HOST_MARK}{host}"
    return profile.with_name(
        f"{SCAN_COPY_PREFIX}{scan_id}{SCAN_COPY_PID_MARK}{pid}{host_part}.{profile.name}"
    )


def _process_may_be_running(pid: int) -> bool:
    """False only when *pid* is provably not a running process.

    A permission error means the process exists; any other failure to ask,
    and every platform where signal 0 is not a harmless probe (Windows, where
    os.kill terminates), reads as "may be running", since the sweep deletes
    only what it can prove abandoned. A reused pid reads as running too: the
    copy then stays until a later bind finds that pid free, which costs a
    leftover file and never a live scan's copy.
    """
    if os.name == "nt":
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OverflowError:
        return False
    except OSError:
        return True
    return True


def _snapshot_profile_for_scan(
    profile: Path, scan_id: str, *, snapshot_path: Path
) -> Path:
    """A server-written copy of the session's profile for one scan.

    The runner reads the profile's environment values before the scan, and the
    scan loads the profile again later, after any wait for the session lock.
    select_profile rewrites the session's file in between, so without a
    snapshot a rebound profile could run with values the redaction set never
    saw. The copy is written beside the profile, so a chain the profile
    extends resolves exactly as the profile's own, and named for the scan,
    a name select_profile never writes. A copy that cannot be written refuses
    the scan (ProfileSnapshotUnavailable, a type-only sentence) rather than
    letting it read the live file, and whatever was partly written is removed
    with the refusal.

    The name is taken exclusively at mode 0600 and the copy is then given the
    profile's own permission bits: a name already present -- a planted link
    included -- refuses the scan rather than truncating or following it, and
    the copy, which holds the profile's content, is never readable more
    widely than the profile. A name this call did not create is not removed
    with the refusal.

    *snapshot_path* is the copy's name, computed once by the caller
    (``_scan_snapshot_path``) and required: the scan runner passes the path it
    recorded, so the file written and the path the scan loads and the runner
    discards are one name even if the host identity the name embeds reads
    differently on a second call. A path in another directory than the
    profile, or a name ``parse_scan_copy_name`` does not admit -- a file the
    sweep of leftover copies could never judge -- is refused with
    ProfileSnapshotUnavailable, the exception every other refusal here raises,
    before anything is written. So is a name that parses to another scan's id
    or does not end in ``.`` plus the profile's own name: the copy belongs to
    this scan and this profile. The runner records the planned path before it
    calls this function and resets that record on ProfileSnapshotUnavailable,
    so the refusals share one reset path; a name this call did not create is
    never removed.
    """
    from automated_security_helper.config.config_sources import (
        discard_scan_copy,
        parse_scan_copy_name,
        register_scan_copy,
    )

    if snapshot_path.parent != profile.parent:
        raise ProfileSnapshotUnavailable(
            "the session profile could not be copied for this scan (the "
            "planned path names another directory than the profile's); the "
            "scan was refused rather than run on the live profile"
        )
    parsed = parse_scan_copy_name(snapshot_path.name)
    if parsed is None:
        raise ProfileSnapshotUnavailable(
            "the session profile could not be copied for this scan (the "
            "planned name is not a scan copy's name, so the sweep of leftover "
            "copies could never place the file); the scan was refused rather "
            "than run on the live profile"
        )
    if parsed[0] != scan_id or not snapshot_path.name.endswith(f".{profile.name}"):
        raise ProfileSnapshotUnavailable(
            "the session profile could not be copied for this scan (the "
            "planned name does not belong to this scan and this profile); the "
            "scan was refused rather than run on the live profile"
        )
    snapshot = snapshot_path
    created = False
    try:
        content = profile.read_bytes()
        profile_mode = stat.S_IMODE(profile.stat().st_mode) & 0o777
        fd = os.open(
            str(snapshot),
            # O_BINARY where the platform defines it (Windows), so the copy
            # is the profile's bytes, not a newline-translated rendering.
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0),
            0o600,
        )
        created = True
        # Registered the moment the file exists: messages map the copy's
        # name back to the profile only while a scan holds the copy, and the
        # sweep knows the copy for this process's own by the same record.
        register_scan_copy(snapshot)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            if hasattr(os, "fchmod"):
                # By descriptor, so the bits land on the file this call
                # created whatever the name holds by then.
                os.fchmod(handle.fileno(), profile_mode)
            else:
                # Windows before Python 3.13 has no fchmod, and an
                # AttributeError here is not an OSError, so it would escape
                # the refusal below as a raw traceback. The name was taken
                # exclusively above, so applying the bits by name reaches
                # the file this call created.
                os.chmod(snapshot, profile_mode)
    except OSError as exc:
        # A failed write can leave a partial file (no space mid-copy); it
        # must not sit beside the session's config, and nothing later would
        # remove it. Only what this call created: a name that already
        # existed (FileExistsError, before `created`) is someone else's and
        # stays as it was.
        if created:
            # Discarded only once the file is gone: a delete that fails (a
            # handle still open on Windows) leaves the copy on disk, and the
            # registration is what lets the next bind's sweep recognize and
            # retry it.
            try:
                snapshot.unlink(missing_ok=True)
            except OSError:
                pass
            else:
                discard_scan_copy(snapshot)
        raise ProfileSnapshotUnavailable(
            "the session profile could not be copied for this scan "
            f"({type(exc).__name__}); the scan was refused rather than run "
            "on the live profile"
        ) from exc
    return snapshot


def _names_the_same_file(named: str, session_file: str) -> bool:
    """Whether the client's path *named* is the file at *session_file*.

    By file identity (``os.path.samefile``), so a ``..`` form, a relative path
    and a link to the file all name it, and by resolved path when either side
    cannot be statted, so a file that is not there yet is still told apart
    from another. Never raises. Reads the filesystem: call it from a worker
    thread, never from the event loop.
    """
    if Path(named) == Path(session_file):
        return True
    try:
        return os.path.samefile(named, session_file)
    except (OSError, ValueError):
        pass
    try:
        return Path(named).resolve() == Path(session_file).resolve()
    except (OSError, RuntimeError, ValueError):
        return False


def _session_file_named_by(
    config_path: str, *session_files: Optional[str]
) -> Optional[Path]:
    """The session's own spelling of the first of *session_files* that
    *config_path* names, or None.

    The scan's copy is taken from the path the session registry holds, not from
    the text the client typed: a link the client named could be pointed
    elsewhere between this decision and the copy, and the registry's path is the
    one file the session writes. Read the filesystem: worker thread only.
    """
    for session_file in session_files:
        if session_file is not None and _names_the_same_file(config_path, session_file):
            return Path(session_file)
    return None


def config_load_category(error: BaseException) -> ErrorCategory:
    """The ``error_category`` of a config that could not be loaded.

    ``file_not_found`` when the file does not exist (a missing path, a link to
    nothing, an ``ASH_CONFIG`` naming a missing file, which
    ``ASHConfigFileNotFoundError`` is for), ``permission_denied`` for a file
    that could not be read (a PermissionError in the chain), ``invalid_path``
    for any other OSError (a read that failed before any parse: the advice is
    about the path, not the format), and ``invalid_format`` for anything
    else. Read through the error's causes, so a refusal raised from one (the
    workspace resolver's, which names the project) has its cause's category.
    One rule for both scan tools (cli/mcp/workspace._error_response), so a
    client reads one category for one refusal from either.

    A read refused because the file changed after it was checked is
    ``invalid_path`` too, whether the refusal is the error or its cause or a
    rewording that dropped the cause and kept the mark
    (``config_sources.config_file_changed``): the advice is about the file, not
    about its format.
    """
    from automated_security_helper.config.config_sources import config_file_changed
    from automated_security_helper.core.exceptions import ASHConfigFileNotFoundError
    from automated_security_helper.utils.error_text import caused_by

    if config_file_changed(error):
        return ErrorCategory.INVALID_PATH
    if caused_by(error, (ASHConfigFileNotFoundError, FileNotFoundError)):
        return ErrorCategory.FILE_NOT_FOUND
    if caused_by(error, PermissionError):
        return ErrorCategory.PERMISSION_DENIED
    if caused_by(error, OSError):
        return ErrorCategory.INVALID_PATH
    return ErrorCategory.INVALID_FORMAT


#: The plugin-module refusal's closing on this surface (the shared builder is
#: config/plugin_module_trust.plugin_module_refusal_message; the closing varies by surface).
#: It names what an MCP client can change -- the config file, or the config
#: content sent -- and never a CLI-only option (--config-overrides,
#: --ash-plugin-modules), which a client cannot pass.
_MCP_PLUGIN_MODULE_CLOSINGS = {
    "namespace_closing": (
        "Nothing was imported. Rename the package or name the "
        "packages inside it, or remove the entry from the config "
        "file or the config content sent"
    ),
    "import_closing": (
        "Nothing was imported. Install what the module needs, "
        "or remove the entry from the config file or the config "
        "content sent"
    ),
}

#: The same refusal's closing on the no-file answer, whose entries are the
#: operator configuration's: it says the entry is in the file ASH_CONFIG
#: names on the server -- naming the variable, never its value or the file's
#: path -- and offers no remedy the client cannot apply (the client named no
#: file and sent no content).
_MCP_NO_FILE_PLUGIN_MODULE_CLOSINGS = {
    "namespace_closing": (
        "Nothing was imported. The entry is in the file ASH_CONFIG "
        "names on the server, which only the server's operator can "
        "change: rename the package or name the packages inside it, "
        "or remove the entry there"
    ),
    "import_closing": (
        "Nothing was imported. The entry is in the file ASH_CONFIG "
        "names on the server, which only the server's operator can "
        "change: install what the module needs, or remove the entry "
        "there"
    ),
}


#: Why a config that changed after it was checked is not read, in the words of
#: the read's own refusal (``config_sources.read_config_bytes``) so a client
#: reads one reason whichever layer reported it.
_CONFIG_FILE_CHANGED_REASON = "the file changed after it was checked, so it is not read"


def _config_load_failure(
    error: Exception, path: Optional[Path], operation: str = "get_config"
) -> Dict[str, Any]:
    """The response of ``operation`` for a config that could not be loaded.

    In the category config_load_category gives it. ``path`` is None when the
    file refused is not the one asked for: the file ASH_CONFIG names, which the
    error itself names.

    Exit code 3, as the CLI exits for a config it cannot use. A parser's
    refusal is given as unparsed_config_reason gives it, never in the parser's
    own words, which can quote the file.
    """
    from pydantic import ValidationError

    from automated_security_helper.config.config_sources import (
        config_file_changed,
        describe_config_path,
        is_config_parse_error,
        parse_error_kind,
    )
    from automated_security_helper.config.config_validator import (
        describe_validation_error,
    )

    context: Dict[str, Any] = {"error_category": config_load_category(error).value}
    reason: Any = error
    if config_file_changed(error):
        # Said as one reason whatever carried it: the error, its cause, or the
        # mark of a rewording that dropped the cause (a base the environment
        # chose, whose own text names neither the file nor the change).
        reason = _CONFIG_FILE_CHANGED_REASON
    elif is_config_parse_error(error):
        # The frame names the file where it has one, so the reason does not
        # name it again (unparsed_config_reason's words, without the path).
        reason = f"it could not be parsed {parse_error_kind(error)}"
    elif isinstance(error, ValidationError):
        # A raw pydantic ValidationError's str quotes every input
        # (input_value=...). Described as the CLI describes one: one line per
        # field, no input (describe_validation_error).
        reason = describe_validation_error(error)
    elif isinstance(error, OSError) and path is not None and error.filename:
        # The operating system's refusal names the file the frame names, as
        # given or resolved, so its copy is left out and the message names
        # the file once (os_error_without_named_file).
        filename = Path(os.fsdecode(error.filename))
        if filename in (Path(path), Path(os.path.realpath(path))):
            reason = os_error_without_named_file(error, filename)
    if path is not None:
        context["config_path"] = str(path)
        # One spelling for the check and the frame (describe_config_path): on
        # Windows str(path) writes backslashes while the check reads the POSIX
        # form, so the frame named the file in a form the check never matched.
        described = describe_config_path(path)
        if str(reason).startswith(described):
            # The reader's refusal names the file itself (the TOML reader's
            # do), so the frame names it once by leaving its own name out.
            message = f"Configuration file cannot be loaded: {reason}"
        else:
            message = f"Configuration file {described} cannot be loaded: {reason}"
    else:
        message = f"The configuration cannot be loaded: {reason}"
    return with_exit_code(
        create_error_response(MCPResourceError(message, context=context), operation),
        REFUSED_CONFIG_EXIT_CODE,
    )


def _bound_profile_unavailable(error: Exception, operation: str) -> Dict[str, Any]:
    """The response of ``operation`` when the session's bound profile cannot be used.

    The profile ``select_profile`` bound is no longer registered, or its file is
    gone and cannot be written to the session's workspace again. That is the
    session's state, not the file the call asked about, so it is answered as
    ``run_ash_scan`` answers it (``bound_profile_unavailable``) and never as
    that file's load failure.

    The two causes are told apart by the error's ``workspace_unwritable``
    (``BoundProfileUnavailableError``), as ``run_ash_scan`` tells them: False
    when the profile is no longer registered, which is a config refusal, exit
    code 3; True when the session's workspace cannot be written (the writer's
    error, an OSError or the sandbox's RuntimeError, is the chained cause),
    which is the server's failure and not the caller's config: exit code 1, the
    category of the cause, and a warning in the server log for the operator,
    who is the one that can act on a workspace permission. Answered as a config
    refusal, an unwritable workspace read as the caller's own fault and left
    nothing in the log. An error that is not a ``BoundProfileUnavailableError``
    is the first kind.
    """
    if not getattr(error, "workspace_unwritable", False):
        return with_exit_code(
            {
                "success": False,
                "error": raw_controls_on_one_line(str(error)),
                "error_type": "bound_profile_unavailable",
                "error_category": ErrorCategory.FILE_NOT_FOUND.value,
                "operation": operation,
            },
            REFUSED_CONFIG_EXIT_CODE,
        )
    _logger.warning(
        "The session's bound profile could not be written to its workspace, so "
        f"{operation} was refused: {raw_controls_on_one_line(str(error))}"
    )
    return with_exit_code(
        {
            "success": False,
            "error": raw_controls_on_one_line(str(error)),
            "error_type": "bound_profile_unavailable",
            "error_category": (
                ErrorCategory.PERMISSION_DENIED.value
                if isinstance(error.__cause__, PermissionError)
                else ErrorCategory.UNEXPECTED_ERROR.value
            ),
            "operation": operation,
        },
        REFUSED_INTERNAL_EXIT_CODE,
    )


class _ConfigPreCheck(NamedTuple):
    """What one resolution of the scan's config gives the start path.

    ``env_refusal`` is the refusal for a file of a chain an MCP client
    delivered that reads from the environment
    (config_sources.refuse_environment_in_a_delivered_file); ``load_refusal``
    names the file the scan cannot read or parse with the refusal the scan
    makes for it; both None for a file the scan can use, or when there is no
    config. ``environment_values`` are what the file's chain read from the
    environment (``ResolvedConfigDocument.environment_values``), kept for
    ``error_text``'s ``values`` at the start-failure arms."""

    env_refusal: Optional[Exception]
    load_refusal: Optional[Tuple[Path, Exception]]
    environment_values: Tuple[str, ...]


def _config_pre_check(
    config_path: Optional[Path], source_dir: Path, session_id: Optional[str]
) -> _ConfigPreCheck:
    """One resolution of the config a scan of ``source_dir`` would load
    (``config_path``, or the one it discovers there when that is None), read
    before the scan is registered.

    The scan tool refuses the file as get_config does, and as the scan itself
    would (resolve_config's words), rather than starting a scan that ends in
    that refusal: an environment-reading delivered file in the words get_config
    uses, an unreadable or unparsable file with its reason. A file that parses
    is left to the scan, which validates it, and discovery's own refusals are
    the scan's to report. One resolution answers both checks and keeps the
    chain's environment values, where two separate helpers each resolved the
    chain again for one answer.

    The chain is read with the settings the scan's own load uses
    (resolve_config builds ``scan_repository_settings(scanned_trees(source_dir),
    every_file=untrusted)`` for the selected chain): what the repository's
    files, and the files of any other checkout, write for the operator-only
    options left out, and the chain's
    ownership known to the patch pointer fold. Read without them, a chain the
    scan loads could resolve differently only here -- an operator file's
    pointer a repository twin makes ambiguous, say -- and that refusal is
    swallowed below, so the scan would run while the redaction set silently
    lacked the chain's environment values.
    """
    import yaml

    from automated_security_helper.cli.mcp.sandbox import (
        client_named_config_is_untrusted,
        config_base_gate,
    )
    from automated_security_helper.config.config_sources import (
        default_confinement_root,
        describe_config_path,
        is_config_parse_error,
        resolve_config_document,
        unparsed_config_reason,
    )
    from automated_security_helper.config.operator_only_options import (
        scan_repository_settings,
    )
    from automated_security_helper.config.resolve_config import find_config_file
    from automated_security_helper.config.sandbox_grants import scanned_trees
    from automated_security_helper.core.exceptions import (
        ASHConfigEnvNotResolvedError,
        ASHConfigSourceError,
        ASHConfigValidationError,
    )

    client_named = config_path is not None
    if config_path is None:
        try:
            config_path = find_config_file(source_dir)
        except (ASHConfigValidationError, OSError):
            # Discovery's own refusals are the scan's to report.
            return _ConfigPreCheck(None, None, ())
        if config_path is None:
            return _ConfigPreCheck(None, None, ())
    path: Path = config_path
    # The scan's own settings for this chain (see the docstring): a named file
    # the client chose resolves with every chain file confined, any other with
    # the files of the scanned tree and of any other checkout confined and the
    # operator's writes owned. The predicate is the scan's own
    # (_run_scan's untrusted_config, through client_named_config_is_untrusted):
    # a named path is the client's unless the operator set it aside, in a
    # config root or as this session's profile file. Judging only whether a
    # client delivered the file read a named file elsewhere with the
    # operator's settings while the scan read it confined, and a refusal of
    # that read was swallowed below as the scan's.
    try:
        # Inside the try: the predicate reads the filesystem (a resolve, a
        # samefile), so a link loop at the named path, or its directory gone
        # since the request was made, raises an OSError here. Outside the try
        # it left this function as an exception, through the thread the start
        # path runs it in, and the start answered an internal error with a
        # traceback instead of the read refusal below, which is what the same
        # path gets when the file itself cannot be read.
        settings = scan_repository_settings(
            scanned_trees(source_dir),
            every_file=client_named
            and client_named_config_is_untrusted(path, session_id=session_id),
        )
        resolved = resolve_config_document(
            path,
            confine_to=default_confinement_root(path, source_dir),
            permit_base=config_base_gate(session_id),
            confine=settings.confine,
            repository_file=settings.is_repository_file,
        )
    except ASHConfigEnvNotResolvedError as exc:
        return _ConfigPreCheck(exc, None, ())
    except ASHConfigValidationError:
        # Read with the scan's own settings above, a refusal here is one the
        # scan's load raises too, so it is the scan's to report: no scan runs
        # with this chain's values, and no redaction value is lost by
        # answering empty.
        return _ConfigPreCheck(None, None, ())
    except (OSError, UnicodeDecodeError, yaml.YAMLError, ValueError) as exc:
        # json.JSONDecodeError and UnicodeDecodeError are ValueErrors. Made
        # here and not raised, so the parser's error is not its context.
        if is_config_parse_error(exc):
            # The parser's own words can quote the file (unparsed_config_reason).
            return _ConfigPreCheck(
                None,
                (path, ASHConfigSourceError(unparsed_config_reason(path, exc))),
                (),
            )
        verb = "read" if isinstance(exc, OSError) else "parse"
        return _ConfigPreCheck(
            None,
            (
                path,
                ASHConfigSourceError(
                    f"could not {verb} {describe_config_path(path)}: {error_text(exc)}"
                ),
            ),
            (),
        )
    return _ConfigPreCheck(None, None, tuple(resolved.environment_values))


def _config_env_refusal(error: Exception, operation: str) -> Dict[str, Any]:
    """The response for a config file an MCP client delivered that reads from
    the environment. The error names the file, and the line or key where it has
    one, never a value: the refusal is made before the file is read with the
    environment. Exit code 3, as for any config the scan cannot use."""
    return with_exit_code(
        {
            "success": False,
            "operation": operation,
            "error": raw_controls_on_one_line(error_text(error)),
            "error_type": CONFIG_ENV_NOT_RESOLVED,
            "error_category": ErrorCategory.INVALID_FORMAT.value,
        },
        REFUSED_CONFIG_EXIT_CODE,
    )


def _plugin_module_refusal(
    message: str, path: Optional[Path], operation: str = "get_config"
) -> Dict[str, Any]:
    """The response of ``operation`` for a config whose ``ash_plugin_modules``
    a scan refuses.

    Its own ``error_type`` and ``error_category`` (PLUGIN_MODULE_REFUSED), so
    a client can branch on either: the file loaded and parsed, and the
    load-failure frame ("Configuration file ... cannot be loaded", under the
    invalid_format category with file-format suggestions) sent a client to
    re-format a healthy file. The message is the refusal itself, in this
    surface's closing words (``config/plugin_module_trust.plugin_module_refusal_message``);
    ``path`` is the file asked about, carried in the structured context, and
    None on the no-file answer, whose entries are the ASH_CONFIG chain's.
    ``suggestions`` names only what an MCP client can change, as the closings
    do, so the response keeps the shape of ``create_error_response``'s; the
    list is the category's own default
    (error_handling.PLUGIN_MODULE_REFUSED_SUGGESTIONS), one wording for both
    surfaces. Exit code 3, as the CLI exits for a configuration a scan
    refuses.
    """
    from automated_security_helper.core.resource_management.error_handling import (
        PLUGIN_MODULE_REFUSED_SUGGESTIONS,
    )

    context: Dict[str, Any] = {
        "error_category": ErrorCategory.PLUGIN_MODULE_REFUSED.value,
    }
    if path is not None:
        context["config_path"] = str(path)
    return with_exit_code(
        {
            "success": False,
            "operation": operation,
            "error": raw_controls_on_one_line(message),
            "error_type": PLUGIN_MODULE_REFUSED,
            "error_category": ErrorCategory.PLUGIN_MODULE_REFUSED.value,
            "context": context,
            "suggestions": list(PLUGIN_MODULE_REFUSED_SUGGESTIONS),
        },
        REFUSED_CONFIG_EXIT_CODE,
    )


class ConfigCheckFailedError(MCPResourceError):
    """The check of a scan target's config sources could not finish."""


def _config_refusal(error: MCPResourceError, operation: str) -> Dict[str, Any]:
    """The response for a config input outside the permitted roots.

    A check that could not finish is ``CONFIG_CHECK_FAILED`` instead: it did not
    find the config outside the roots, so the fix for that refusal does not apply.

    No ``context`` key, unlike ``create_error_response``: it would carry the
    resolved path, and the caller's own spelling in ``error`` already identifies
    what was refused. ``error`` is described, not quoted, should it come from a
    pydantic ValidationError. Exit code 3, the code every tool gives this
    refusal.
    """
    return with_exit_code(
        {
            "success": False,
            "operation": operation,
            "error": raw_controls_on_one_line(error_text(error)),
            "error_type": CONFIG_INPUT_NOT_PERMITTED,
            "error_category": error.context["error_category"],
        },
        REFUSED_CONFIG_EXIT_CODE,
    )


#: The context keys the refusal's readers take from the mapping AFTER it is
#: redacted: the MCPResourceError arms read ``suggestions``, and
#: create_error_response and _config_refusal read ``error_category`` (the
#: builder also writes ``error``, ``error_type`` and ``error_message``
#: envelope entries from context-shaped producers). A redaction value can
#: match inside a key -- "r_ca" holds "_", so it is replaced anywhere,
#: "error_category" included -- and a rewritten key disconnects the reader
#: from the mapping: the producer's suggestions fall to the generic list, and
#: _config_refusal's lookup raises. So a top-level key on this list is never
#: rewritten; its VALUE is still redacted. A producer's own keys, and every
#: nested key, are redacted like values.
_STRUCTURAL_CONTEXT_KEYS = frozenset(
    {"error", "error_category", "error_type", "error_message", "suggestions"}
)


#: What a context entry the walker cannot show is shown as: a container the
#: walk is already inside. Value-free, so it needs no redaction.
_CYCLE_NOTE = "(cyclic reference)"


def _context_without_values(
    value: Any,
    values: Tuple[str, ...],
    *,
    _structural: frozenset = _STRUCTURAL_CONTEXT_KEYS,
    _walking: Optional[set] = None,
) -> Any:
    """*value* with every string in it, in nested dicts, lists and tuples too,
    redacted with *values* (utils/error_text.py's text_without_values).

    For an error context the response shows to the client: error_text redacts
    the error's own message with the values it carries, but the context's
    strings and the suggestions taken from it go into the response as they
    were raised, so they are redacted here with the same values. Dict KEYS are
    redacted like items, since a key is shown exactly like a value -- except
    the top-level structural keys the readers take back from the redacted
    mapping (_STRUCTURAL_CONTEXT_KEYS), which must stay findable; their values
    are still redacted, and ``_structural`` empties for every nested level. A
    list or a tuple is rebuilt as a PLAIN list or tuple: ``type(value)`` with
    one iterable assumed every sequence type's constructor, and a producer's
    namedtuple -- as a value or as a dict key -- raised TypeError out of the
    error handler instead. The response shows the entries, not the type, and
    a plain tuple stays hashable where the namedtuple was a key. Two keys
    hiding to the same text are both kept, the later entries under
    deterministic "#2", "#3", ... suffixes. A container the walk is already
    inside (a context holding itself) is shown as the cycle note instead of
    recursing forever; ``_walking`` tracks the walk's own stack, so a subtree
    referenced twice is still redacted in both places. An int or float leaf
    whose str() equals a read value of redactable length is shown redacted (a
    numeric token identifies the value the same way a string does); None,
    bools and other numbers pass through. A leaf that is not a string and not
    a plain scalar is shown as its redacted str() -- a Path or an exception
    object renders as text in the response, so it leaks the same way a string
    does.
    """
    if isinstance(value, str):
        return text_without_values(value, values)
    walking = set() if _walking is None else _walking
    if isinstance(value, dict):
        if id(value) in walking:
            return _CYCLE_NOTE
        walking.add(id(value))
        try:
            redacted: Dict[Any, Any] = {}
            for key, item in value.items():
                shown_key = (
                    key
                    if isinstance(key, str) and key in _structural
                    else _context_without_values(
                        key, values, _structural=frozenset(), _walking=walking
                    )
                )
                if shown_key in redacted:
                    # Two keys hiding to the same text (two secrets both shown
                    # as the redaction marker) collided in the rebuilt
                    # mapping, and the dict silently kept only the later
                    # entry. Both are kept, the later under a deterministic
                    # "#2" (then "#3", ...) suffix in the producer's order.
                    suffix = 2
                    while f"{shown_key}#{suffix}" in redacted:
                        suffix += 1
                    shown_key = f"{shown_key}#{suffix}"
                redacted[shown_key] = _context_without_values(
                    item, values, _structural=frozenset(), _walking=walking
                )
            return redacted
        finally:
            # The guard tracks the walk's own stack, never everything seen: a
            # subtree referenced twice is redacted twice, and only a container
            # holding itself reads as the cycle note.
            walking.discard(id(value))
    if isinstance(value, list):
        if id(value) in walking:
            return _CYCLE_NOTE
        walking.add(id(value))
        try:
            return [
                _context_without_values(
                    item, values, _structural=frozenset(), _walking=walking
                )
                for item in value
            ]
        finally:
            walking.discard(id(value))
    if isinstance(value, tuple):
        if id(value) in walking:
            return _CYCLE_NOTE
        walking.add(id(value))
        try:
            return tuple(
                _context_without_values(
                    item, values, _structural=frozenset(), _walking=walking
                )
                for item in value
            )
        finally:
            walking.discard(id(value))
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        # A numeric leaf that PRINTS a read value identifies it the same way
        # a string does: a port or a numeric token the config read from the
        # environment comes back as the number the client renders. One whose
        # str() equals a read value of redactable length is shown redacted; a
        # value under the floor stays, as redact_values leaves a short
        # unquoted form in text, and a bool is a flag, not a read value.
        printed = str(value)
        if any(printed == read and len(read) >= MIN_REDACTED_LENGTH for read in values):
            return text_without_values(printed, values)
        return value
    try:
        return text_without_values(str(value), values)
    except Exception:  # noqa: BLE001 -- the walker runs inside the error
        # handler, so a leaf whose rendering raises (an object's __str__)
        # must not replace the refusal with a crash; shown value-free.
        return "(not shown)"


def _scan_owner(session_id: Optional[str]) -> str:
    """The session whose scans a registry tool acts on.

    A caller that names no session is the default session -- stdio's single
    client, or an in-process caller -- and sees the scans registered the same
    way, never every session's.
    """
    return session_id or _default_session_id()


def _discovered_config_refusal(
    target: Path, session_id: Optional[str]
) -> Optional[MCPResourceError]:
    """The refusal for a config source in ``target`` outside this session's grant, or None.

    ``target`` is a directory this session may scan, but a config source in it
    -- ``pyproject.toml``, a dedicated config name, a linked ``.ash/`` -- may be a
    symbolic link to a file anywhere on the server. Each one that exists is
    checked by the path it resolves to, opening none of them, so the answer is
    the same whether that file is missing, unreadable or readable. The scan's own
    discovery checks them the same way (``run_ash_scan``'s config_base_gate).

    The file discovery selects is then checked as ``get_config`` checks a file
    it finds (``validate_config_input``), before anything reads it, and the
    refusal names it as found. The scan's own resolution refuses it the same
    way (``config_sources.check_discovered_source``).

    A check of the candidates that fails for any other reason is a refusal too.
    """
    from automated_security_helper.cli.mcp.sandbox import (
        config_base_gate,
        config_chain_refusal,
        validate_config_input,
    )
    from automated_security_helper.config.config_sources import (
        check_discovery_candidates,
        discover_config_source,
    )
    from automated_security_helper.core.exceptions import (
        ASHConfigInputNotPermittedError,
    )

    permit = config_base_gate(session_id)
    try:
        check_discovery_candidates(target, permit)
    except ASHConfigInputNotPermittedError as exc:
        return config_chain_refusal(target, exc)
    except Exception as exc:  # noqa: BLE001 -- a check that cannot finish refuses
        # Not left to the scan: this check decides whether a source in the
        # target may be read at all, so one that cannot finish stops the scan
        # here, as a refusal the caller can read.
        _logger.warning(f"Config sources not checked before the scan: {exc}")
        return ConfigCheckFailedError(
            f"The configuration found in {target.as_posix()} could not be checked "
            f"against the permitted roots: {type(exc).__name__}",
            context={
                "directory_path": str(target),
                "error_category": ErrorCategory.INVALID_PATH.value,
            },
        )
    try:
        # Under the gate again: a source can change after the check above.
        selected = discover_config_source(target, permit=permit).selected
    except Exception as exc:  # noqa: BLE001 -- reported by the scan's own read
        _logger.debug(f"Config not discovered before the scan ({exc})")
        return None
    if selected is None:
        return None
    return validate_config_input(selected.path, session_id=session_id)


def _discovered_config_path(
    target: Path, *, permit: Callable[[Path], bool]
) -> Tuple[Optional[Path], Optional[MCPResourceError]]:
    """The config file a scan of ``target`` would discover, under ``permit``.

    ``permit`` is the session's ``config_base_gate``. Returns ``(path, None)``,
    ``(None, None)`` when there is none, or ``(None, error)`` when discovery
    refuses the source it would select: a pyproject.toml that declares
    ``[tool.ash]`` but cannot be read or parsed, as the scan's own discovery
    refuses it. Discovery names the file in that message and gives the parser's
    position, not the file's text. Any other failure is left to the scan;
    ``_discovered_config_refusal`` has already refused a source outside the grant.
    """
    from automated_security_helper.config.config_sources import (
        discover_config_source,
    )
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    try:
        selected = discover_config_source(target, permit=permit).selected
    except ASHConfigValidationError as exc:
        return None, MCPResourceError(
            f"The configuration found in {target.as_posix()} cannot be loaded: {exc}",
            context={
                "directory_path": str(target),
                "error_category": ErrorCategory.INVALID_FORMAT.value,
            },
        )
    except Exception as exc:  # noqa: BLE001 -- reported by the scan's own read
        _logger.debug(f"Config not discovered before the scan ({exc})")
        return None, None
    return (selected.path if selected is not None else None), None


def _load_error_response(
    checked: Any,
    config_path: Optional[str],
    target: Path,
    session_id: Optional[str],
) -> Dict[str, Any]:
    """The refusal of a config, named or discovered, that does not load or validate.

    Refused here rather than by the scan, which would start and then fail on its
    first read of the config. ``checked.load_error`` names the file, in the
    text that repeats no client's or repository's value
    (``sandbox.check_config_input``). A file a client delivered that also sets a
    field it may not is refused for that first, as the scan would refuse it while
    resolving: the denial names what to remove. So is one this session's policy
    cannot be read for. A denial check that cannot finish on a file that does not
    validate leaves the load error to report. Exit code 3 either way, as the
    CLI exits for a config the scan cannot use.
    """
    if checked.document is not None:
        denial = _client_config_denial(
            config_path,
            target,
            session_id,
            "scan_directory",
            document=checked.document,
        )
        if denial is not None and denial.get("error_type") in (
            CONFIG_FIELD_DENIED,
            CONFIG_POLICY_UNREADABLE,
        ):
            return denial
    return with_exit_code(
        create_error_response(
            error=checked.load_error,
            operation="scan_directory",
            suggestions=[
                "Fix the error the message names; a syntax error names its line",
                "Run 'ash config lint' on the file to check it",
            ],
        ),
        REFUSED_CONFIG_EXIT_CODE,
    )


def _session_client_rules(
    session_id: Optional[str], repository: Optional["RepositorySettings"] = None
) -> Any:
    """The ClientConfigRules a config this session's client delivers is checked against.

    From the registered profile the session bound, never from its materialized
    config; see ``profile_registry.session_client_rules``. Raises when the bound
    profile is gone, so a scan is refused rather than checked against another
    policy. ``repository`` is the settings the caller's own load of the
    ASH_CONFIG chain uses, so the server's default config is read as that load
    reads it.
    """
    from automated_security_helper.cli.mcp.profile_registry import (
        session_client_rules,
    )

    return session_client_rules(session_id, repository=repository)


def _denied_response(exc: Exception, operation: str) -> Dict[str, Any]:
    """The response for a client-delivered config that was refused.

    Exit code 3, as for any config the scan cannot use: a field the session's
    policy denies, or a policy that cannot be read for the file, refuses the
    config as the CLI's exit does, and ``run_ash_scan`` and ``get_config`` pass
    the response on promising that code.
    """
    from automated_security_helper.core.exceptions import (
        ASHConfigPolicyUnreadableError,
    )

    return with_exit_code(
        {
            "success": False,
            "operation": operation,
            "error": raw_controls_on_one_line(str(exc)),
            "error_type": (
                CONFIG_POLICY_UNREADABLE
                if isinstance(exc, ASHConfigPolicyUnreadableError)
                else CONFIG_FIELD_DENIED
            ),
        },
        REFUSED_CONFIG_EXIT_CODE,
    )


def _client_config_denial(
    config_path: Optional[str],
    source_dir: Path,
    session_id: Optional[str],
    operation: str,
    document: Optional[Any] = None,
) -> Optional[Dict[str, Any]]:
    """Refuse up front a client-delivered config the scan would refuse while resolving.

    The scan resolves the config in the background, so the same check runs here
    first and the client is told which field to remove at once. The chain is read
    the way the scan reads it: the named file, or the file discovered in
    ``source_dir``. ``document`` is that chain when the caller has read it already
    (``sandbox.ConfigInputCheck.document`` for ``config_path``), so it is not read
    again. Any other chain problem is left to the scan, which reports it as it
    always has. The scan's own check is the one that decides; this one only
    reports early.
    """
    from automated_security_helper.cli.mcp.sandbox import (
        caller_is_remote,
        client_named_config_is_untrusted,
        config_base_gate,
    )
    from automated_security_helper.config.client_config_policy import (
        apply_client_config_rules,
    )
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.config_sources import (
        default_confinement_root,
        discover_config_source,
        env_refused_for,
        resolve_config_document,
    )
    from automated_security_helper.core.exceptions import (
        ASHConfigFieldDeniedError,
        ASHConfigPolicyUnreadableError,
    )

    try:
        rules = _session_client_rules(session_id)
    except Exception as exc:  # noqa: BLE001 -- rules that cannot be read refuse
        # The scan reads the same rules and refuses on the same failure
        # (``_run_scan_async``); refused here too, as a response the caller can
        # read rather than an exception out of the tool.
        # Described (error_text): a validation error's own text quotes the
        # refused input, and the response goes to a remote client.
        _logger.warning(
            f"Session config rules not read before the scan: {error_text(exc)}"
        )
        # Exit code 3, as _denied_response gives the same error_type: the
        # config is refused because its policy cannot be read.
        return with_exit_code(
            {
                "success": False,
                "operation": operation,
                "error": raw_controls_on_one_line(
                    "The config could not be checked against this session's "
                    f"runtime-override policy: {error_text(exc)}"
                ),
                "error_type": CONFIG_POLICY_UNREADABLE,
            },
            REFUSED_CONFIG_EXIT_CODE,
        )
    permit_base = config_base_gate(session_id)
    # A named path the client chose is the client's wherever it is, as the scan
    # reads it (resolve_config's untrusted_config).
    named_by_client = config_path is not None and client_named_config_is_untrusted(
        config_path, session_id=session_id
    )
    try:
        if document is None:
            if config_path is not None:
                path = Path(config_path)
                confine = default_confinement_root(path, source_dir)
            else:
                # Under the session's gate, as the scan discovers it.
                selected = discover_config_source(
                    source_dir, permit=permit_base
                ).selected
                if selected is None:
                    return None
                path, confine = selected.path, source_dir
            document = resolve_config_document(
                path,
                confine_to=confine,
                permit_base=permit_base,
                refuse_env=env_refused_for(caller_is_remote(session_id), session_id),
            )
    except Exception as exc:  # noqa: BLE001 -- reported by the scan's own read
        _logger.debug(f"Config chain not read before the scan: {exc}")
        return None
    try:
        apply_client_config_rules(
            AshConfig(),
            document.documents,
            rules=rules,
            trusted_config_path=None,
            source_dir=source_dir,
            permit_base=permit_base,
            all_delivered=named_by_client,
            names=document.names,
        )
    except (ASHConfigFieldDeniedError, ASHConfigPolicyUnreadableError) as exc:
        return _denied_response(exc, operation)
    except Exception as exc:  # noqa: BLE001 -- a check that cannot finish refuses
        # Not left to the scan: the check is what decides whether the client's
        # file may be used, so one that cannot finish stops the scan here, as a
        # refusal the caller can read rather than an exception out of the tool.
        # Described (error_text), as create_error_response described it: the
        # raw text of a validation error quotes the refused input, and both the
        # log line and the response leave the server.
        _logger.warning(
            f"Config policy check failed before the scan: {error_text(exc)}"
        )
        response = create_error_response(error=exc, operation=operation)
        response["error"] = raw_controls_on_one_line(
            "The config could not be checked against this session's "
            f"runtime-override policy: {error_text(exc)}"
        )
        # A documented type, not the exception's class name: a client branches
        # on error_type (mcp_server.run_ash_scan answers scan_start_failure for
        # a start that gives no scan id). Exit code 1, as for a start that fails
        # on the server's side: the config was not found wanting, the check of
        # it broke.
        response["error_type"] = "scan_start_failure"
        return with_exit_code(response, REFUSED_INTERNAL_EXIT_CODE)
    return None


async def mcp_scan_directory(
    directory_path: str,
    severity_threshold: Optional[str] = None,
    config_path: Optional[str] = None,
    session_id: Optional[str] = None,
    clean_output: bool = False,
    *,
    config_check: Optional["ConfigInputCheck"] = None,
) -> Dict[str, Any]:
    """
    Start a security scan with file-based progress tracking.

    This tool starts a scan in the background and returns immediately with a scan_id.
    Use get_scan_progress to track progress and get_scan_results for final results.

    The scan progress is tracked by monitoring the existence of result files in the
    output directory, providing a more reliable approach than event-based tracking.

    Args:
        directory_path: Path to the directory to scan
        severity_threshold: A threshold (ALL, LOW, MEDIUM, HIGH, CRITICAL, any
            case) the scan must be at least as strict as. The scan runs at the
            stricter of it and the config's global_settings.severity_threshold,
            so it can tighten the config's threshold and never loosen it. None
            keeps the config's.
        config_path: Optional path to ASH configuration file
        session_id: Optional MCP session id. When set, the scan acquires the
            per-session lock (Track 10.5 #63) so two concurrent scans on the
            same session serialize instead of racing on the shared output
            dir. Distinct sessions never contend. A caller the server could not
            identify is refused before anything is checked or written: its scan
            would be one it can neither poll nor cancel.
        clean_output: Set the previous results in the output directory aside
            before this returns, so a client polling at once does not read them
            as this scan's; the scan's own set-up does it a moment later
            otherwise. Done only once the registry has given this scan the
            directory: before that, the directory may be another scan's, still
            running or still stopping, and what is there is its output.
        config_check: What ``sandbox.check_config_input`` found for
            ``config_path``, this session and this target, when the caller has
            already run it (``run_ash_scan`` does, before it acts on the
            target). The file is then not read again here.

    Returns:
        Dictionary with scan ID and status information
    """
    from automated_security_helper.cli.mcp.session_identity import (
        session_identity_refusal,
    )

    # No session id is an in-process caller, not a network caller the server
    # could not identify (UNIDENTIFIED_SESSION_ID), so there is nothing to refuse.
    # An id another tool resolved and passed down: no request is in reach here,
    # so the refusal claims no cause and gives the mode-less advice.
    refusal = (
        session_identity_refusal(session_id, "scan_directory", ctx=None)
        if session_id is not None
        else None
    )
    if refusal is not None:
        # The request's own fault, as run_ash_scan codes the same refusal.
        return with_exit_code(refusal, REFUSED_USAGE_EXIT_CODE)

    from automated_security_helper.cli.mcp.scan_target import (
        ASH_MCP_ALLOWED_ROOTS_ENV,
        OUTPUT_TREE_REFUSED_EXIT_CODE,
        resolve_scan_target,
        validate_output_tree,
    )
    from automated_security_helper.core.committed_output import (
        COMMITTED_OUTPUT_REFUSED_EXIT_CODE,
        UnverifiedOutputFilesError,
        committed_entries_in_the_way,
        committed_output_files_error,
    )
    from automated_security_helper.core.exceptions import ASHConfigValidationError
    from automated_security_helper.core.resource_management.error_handling import (
        VALID_SEVERITY_THRESHOLDS,
        validate_severity_threshold,
        validate_config_path,
    )

    # Upper case once, here, so the value registered, echoed and handed to the
    # scan is the one ASH's configuration accepts ("low" validated, and then the
    # scan's override failed on it).
    if severity_threshold is not None:
        severity_threshold = severity_threshold.upper()

    # Check the root policy before anything else looks at the target. This runs
    # ahead of the existence check so that a refused target is reported as
    # refused rather than as a missing directory, and ahead of the output
    # directory creation below so that a refused target is not written into.
    target = resolve_scan_target(directory_path, session_id=session_id)
    if target.error is not None:
        return with_exit_code(
            create_error_response(
                error=target.error,
                operation="scan_directory",
                suggestions=[
                    (
                        f"Add the directory to {ASH_MCP_ALLOWED_ROOTS_ENV} if the MCP "
                        "server should be able to scan it"
                    ),
                    "Verify that the path is correct",
                ],
            ),
            REFUSED_TARGET_EXIT_CODE,
        )
    resolved_target = target.require()

    # A permitted target that cannot be scanned is the request's fault: refused
    # here, before anything looks beneath it (the output-tree check below would
    # raise for a directory that cannot be entered).
    source_refusal = source_directory_refusal(directory_path, "scan_directory")
    if source_refusal is not None:
        return source_refusal

    # The policy canonicalized the target and nothing beneath it. The output tree
    # is created below with parents=True, which follows a symlinked ".ash" out of
    # the permitted roots, so each component it is about to create is checked
    # first. The exit code is the one a workspace scan reports for the same link.
    output_error = validate_output_tree(resolved_target, ".ash", "ash_output")
    if output_error is not None:
        response = create_error_response(
            error=output_error,
            operation="scan_directory",
            suggestions=[
                (
                    "Remove or replace the symlinked .ash directory in the scan "
                    "target so the scan output stays inside it"
                ),
                (
                    f"Add the directory the link points at to "
                    f"{ASH_MCP_ALLOWED_ROOTS_ENV} and scan it directly if that is "
                    f"what was intended"
                ),
            ],
        )
        return with_exit_code(response, OUTPUT_TREE_REFUSED_EXIT_CODE)

    # A file where the output directory goes is refused here, as the CLI refuses
    # an --output-dir that is a file: no scan can write into it. register_scan
    # refuses it too, but as a registry error, exit 1.
    output_dir = resolved_target / ".ash" / "ash_output"
    output_refusal = output_directory_refusal(output_dir, "scan_directory")
    if output_refusal is not None:
        return output_refusal

    # A file git tracks where the scan deletes or writes its own stops it here,
    # before a scan is registered and started and before clean_output sets the
    # previous results aside, which moves them, with the message the CLI prints;
    # the started scan would refuse it too, after that move, with only its exit
    # code to show for it (core/committed_output.py). So does any file there when
    # git cannot say what is committed, which the check raises.
    refused: Optional[Dict[str, Any]] = None
    try:
        committed = committed_entries_in_the_way(output_dir)
    except UnverifiedOutputFilesError as unverified:
        refused = create_error_response(
            error=MCPResourceError(
                str(unverified),
                context={
                    "directory_path": directory_path,
                    "error_category": ErrorCategory.INVALID_PATH.value,
                    "unverified_files": [
                        path.as_posix() for path in unverified.entries
                    ],
                },
            ),
            operation="scan_directory",
            suggestions=[
                "Let git read the repository the scan target is in",
                "Remove the previous results from .ash/ash_output",
            ],
        )
    else:
        if committed:
            committed_refusal = committed_output_files_error(output_dir, committed)
            refused = create_error_response(
                error=MCPResourceError(
                    str(committed_refusal),
                    context={
                        "directory_path": directory_path,
                        "error_category": ErrorCategory.INVALID_PATH.value,
                        "committed_files": [path.as_posix() for path in committed],
                    },
                ),
                operation="scan_directory",
                suggestions=[
                    "Move the committed files out of .ash/ash_output",
                    "Scan with the CLI and write its output elsewhere with --output-dir",
                ],
            )
    if refused is not None:
        # The code the CLI exits with for the same tree.
        return with_exit_code(refused, COMMITTED_OUTPUT_REFUSED_EXIT_CODE)

    # Validate severity threshold. None is not a threshold but the absence of one:
    # the scan keeps whatever its config says.
    severity_error = (
        validate_severity_threshold(severity_threshold)
        if severity_threshold is not None
        else None
    )
    if severity_error:
        return with_exit_code(
            create_error_response(
                error=severity_error,
                operation="scan_directory",
                suggestions=[
                    "Valid severity thresholds are: "
                    + ", ".join(VALID_SEVERITY_THRESHOLDS),
                    # The value was upper-cased above, so its case is not the
                    # problem.
                    (
                        "Check the spelling of the severity threshold; any case "
                        "is accepted"
                    ),
                ],
            ),
            REFUSED_USAGE_EXIT_CODE,
        )

    # Validate config path if provided. Confinement first, covering every base the
    # config extends, so a refused path is reported as refused and not as missing.
    # `is not None`: an empty path is a config input too, and is refused here
    # rather than starting a scan that fails on it.
    # The chain the check below read, which the denial check reads from.
    chain_document: Optional[Any] = None
    if config_path is not None:
        from automated_security_helper.cli.mcp.sandbox import check_config_input

        if not config_path.strip():
            # A parameter that names nothing is the request's own fault, as an
            # unusable severity is: the CLI's usage-error code.
            return with_exit_code(
                create_error_response(
                    error=MCPResourceError(
                        "The configuration file path is empty. Name a config file, "
                        "or omit config_path to use the configuration found in the "
                        "directory.",
                        context={
                            "error_category": ErrorCategory.INVALID_PARAMETER.value,
                        },
                    ),
                    operation="scan_directory",
                ),
                REFUSED_USAGE_EXIT_CODE,
            )

        # One read of the file and its chain answers both checks below: a base
        # outside the grant (a refusal) and a config that does not load.
        checked = (
            config_check
            if config_check is not None
            else check_config_input(
                config_path, session_id=session_id, source_dir=resolved_target
            )
        )
        if checked.refusal is not None:
            return _config_refusal(checked.refusal, "scan_directory")

        config_error = validate_config_path(config_path)
        if config_error:
            return with_exit_code(
                create_error_response(
                    error=config_error,
                    operation="scan_directory",
                    suggestions=[
                        "Check that the configuration file exists and is accessible",
                        "Verify that the path is correct",
                        (
                            "Ensure the file has a valid extension (.yaml, .yml, "
                            ".json, or .toml)"
                        ),
                    ],
                ),
                REFUSED_CONFIG_EXIT_CODE,
            )
    else:
        # The config the scan discovers in the target is checked as a named one
        # is, before anything reads it: it can be a link out of the roots.
        from automated_security_helper.cli.mcp.sandbox import (
            validate_discovered_config,
        )

        discovered_error = await asyncio.to_thread(
            validate_discovered_config, resolved_target, session_id
        )
        if discovered_error is not None:
            return _config_refusal(discovered_error, "scan_directory")

    # One pre-check resolution for both branches: the named file when the
    # client gave one, else whatever the target's discovery finds.
    pre_check = await asyncio.to_thread(
        _config_pre_check,
        Path(config_path) if config_path else None,
        resolved_target,
        session_id,
    )
    if pre_check.env_refusal is not None:
        return _config_env_refusal(pre_check.env_refusal, "scan_directory")
    if pre_check.load_refusal is not None:
        unloadable_path, load_refusal = pre_check.load_refusal
        return _config_load_failure(load_refusal, unloadable_path, "scan_directory")

    # The values the pre-check's one resolution read from the environment.
    # Nothing in the registration block below reads the resolved config, so no
    # error raised there carries one of these today; they are kept as defense
    # in depth, so a start failure's text is still shown redacted if a later
    # change ever puts a config-read value in its path.
    environment_values = pre_check.environment_values

    # The operator's limits come from the configuration a scan starts from (the
    # file ASH_CONFIG names). One that is refused, or that the server cannot
    # read (OSError), refuses the request as a config, exit 3, as the CLI's
    # scan refuses it and as get_config answers a named file it cannot read,
    # before anything is registered: inside the try below the refusal read as
    # "Unexpected error starting scan" with exit 1, and raised after
    # register_scan it would leave the scan registered.
    try:
        limits = _resource_limits()
    except (ASHConfigValidationError, OSError) as e:
        return _config_load_failure(e, None, operation="scan_directory")
    # The operator's ASH_CONFIG chain can read the environment the same way,
    # and every scan starts from it: its values join the redaction set.
    environment_values = tuple(
        dict.fromkeys((*environment_values, *_operator_environment_values(limits)))
    )

    if config_path is not None:
        # A delivered config that uses !ENV is refused before the scan starts and
        # in the words the scan would use, rather than by a scan that ends with
        # exit code 3; the same read found it.
        if checked.env_error is not None:
            return _config_env_refusal(checked.env_error, "scan_directory")
        chain_document = checked.document
        if checked.load_error:
            return _load_error_response(
                checked, config_path, resolved_target, session_id
            )
    else:
        link_out = _discovered_config_refusal(resolved_target, session_id)
        if link_out is not None:
            return _config_refusal(link_out, "scan_directory")
        # The file the scan will discover, checked as a named one is, in one
        # read: a delivered one that uses !ENV, and one that does not load or
        # validate, are refused before the scan starts, naming the file.
        from automated_security_helper.cli.mcp.sandbox import config_base_gate

        discovered, not_discovered = _discovered_config_path(
            resolved_target, permit=config_base_gate(session_id)
        )
        if not_discovered is not None:
            # A config the scan cannot use, as a named file that does not parse
            # is: the same code (3) whichever way the file reached the scan.
            return with_exit_code(
                create_error_response(
                    error=not_discovered,
                    operation="scan_directory",
                    suggestions=[
                        (
                            "Fix the error the message names; a syntax error names "
                            "its line"
                        ),
                        "Run 'ash config lint' on the file to check it",
                    ],
                ),
                REFUSED_CONFIG_EXIT_CODE,
            )
        if discovered is not None:
            from automated_security_helper.cli.mcp.sandbox import check_config_input

            checked = check_config_input(
                discovered, session_id=session_id, source_dir=resolved_target
            )
            if checked.refusal is not None:
                return _config_refusal(checked.refusal, "scan_directory")
            if checked.env_error is not None:
                return _config_env_refusal(checked.env_error, "scan_directory")
            chain_document = checked.document
            if checked.load_error:
                return _load_error_response(checked, None, resolved_target, session_id)

    denial = _client_config_denial(
        config_path,
        resolved_target,
        session_id,
        "scan_directory",
        document=chain_document,
    )
    if denial is not None:
        return denial

    # Claimed before the scan id is returned, because the scan takes the
    # session's lock only later, on a worker thread: from here on a change to
    # the delivered tree is refused and the session's removal waits for the
    # scan. Refused while such a change is in progress. See
    # MCPSession.try_claim_scan. The claim is on the in-memory session: a scan
    # creates nothing under the workspace root, so it starts even when that root
    # can't be created.
    claimed_session = None
    if session_id is not None and session_id != UNIDENTIFIED_SESSION_ID:
        from automated_security_helper.cli.mcp.sessions import (
            get_default_registry as _get_session_registry,
        )
        from automated_security_helper.cli.mcp.source_delivery import (
            SOURCE_DELIVERY_BUSY,
        )

        claimed_session = _get_session_registry().session_for(session_id)
        if not claimed_session.try_claim_scan():
            # Neither the config, the request nor the target: the code for
            # anything else, as the registry's refusal of a busy directory.
            return with_exit_code(
                {
                    "success": False,
                    "operation": "scan_directory",
                    "error_type": SOURCE_DELIVERY_BUSY,
                    "error": (
                        "the delivered source of this session is being changed; "
                        "start the scan after the change finishes"
                    ),
                },
                REFUSED_INTERNAL_EXIT_CODE,
            )
    # Counted against the operator's per-session limit from here until the scan
    # returns; the task uncounts it. A limited caller with no session counts on
    # the count all such callers share. See sessions.per_session_scan_limit.
    from automated_security_helper.cli.mcp.sessions import (
        per_session_scan_limit,
        session_scan_limit_refusal,
        sessionless_scan_count,
    )

    counted: Optional[Any] = None
    limit = per_session_scan_limit(session_id)
    if claimed_session is not None:
        if limit is None:
            # No limit applies, and with none try_start_scan always counts. The
            # scan is counted anyway, so a limit set later sees it running.
            claimed_session.try_start_scan(None)
        elif not claimed_session.try_start_scan(limit):
            # The claim goes back as the task's finally gives it back: with the
            # end of a session that arrived while it was held completed, not
            # left for the TTL sweep, off the event loop and without raising,
            # so the refusal below is answered whatever the removal did. The
            # limit is the server's, not the request's, the config's or the
            # target's: the code for anything else, as the registry's
            # concurrency refusal reports.
            await _release_what_the_scan_held_off_the_loop(
                None,
                claimed_session,
                session_id,
                scan_id=None,
                environment_values=environment_values,
            )
            # try_start_scan turns a scan away only when a limit is reached.
            return with_exit_code(
                session_scan_limit_refusal("scan_directory", limit),
                REFUSED_INTERNAL_EXIT_CODE,
            )
        counted = claimed_session
    elif limit is not None:
        shared = sessionless_scan_count()
        if not shared.try_start_scan(limit):
            return with_exit_code(
                session_scan_limit_refusal("scan_directory", limit, shared=True),
                REFUSED_INTERNAL_EXIT_CODE,
            )
        counted = shared
    try:
        # Create a unique scan ID
        scan_id = str(uuid.uuid4())

        # The output directory. Built from the resolved target rather than from
        # the caller's text, so the directory created is the one
        # validate_output_tree just checked.
        directory_path_obj = Path(directory_path)
        output_dir = resolved_target / ".ash" / "ash_output"

        # Assigned before the first statement of this try that can raise, so
        # the outer finally can always read it.
        task_started = False
        # The scan's log scope opens before its registration, so the registry's
        # "Registered scan" line is the run's own and lands in no other scan's
        # ash.log. Opened, never joined: two scans started from one context
        # (one task awaiting the tool twice) must not share. The runner's task
        # joins it (create_task copies this context), and it closes once the
        # task, the runner and the scan's thread are all done with it. Until
        # the task exists the scope is this call's: every way out before then,
        # a refusal or an error, closes it in the finally below, and once the
        # task exists the finally puts this context back.
        log_scope, log_scope_token = open_run_log_scope()
        # Set once the registry holds the scan, and once its previous results
        # may have been set aside: until the task starts, nothing else will
        # close the one or put the other back (the except arm below).
        registered = False
        previous_results_moved = False
        try:
            # Register the scan in the registry, within the operator's
            # concurrency limit; see _resource_limits. Off the event loop, as
            # the other registry work of this tool is: the registration waits
            # for an output-tree removal still in progress for the same
            # directory (ScanRegistry.register_scan), and that wait, run on the
            # loop's thread, froze every other request for as long as the
            # delete took.
            registry = get_scan_registry()
            registration = asyncio.ensure_future(
                asyncio.to_thread(
                    registry.register_scan,
                    directory_path=str(directory_path_obj),
                    output_directory=str(output_dir),
                    # Not known yet: the scan runs at the stricter of the
                    # request and its config's threshold, and the runner
                    # records the one it used (_judged_threshold). The request
                    # is kept beside it.
                    severity_threshold=None,
                    requested_severity_threshold=severity_threshold,
                    config_path=config_path,
                    scan_id=scan_id,
                    # 0 or None is no limit.
                    max_active=limits.max_concurrent_scans or None,
                    session_id=_scan_owner(session_id),
                    # The registry redacts every error message it applies with
                    # these, so a failure arm that closes the entry with a bare
                    # exception's text is backstopped at the sink.
                    environment_values=environment_values,
                )
            )
            try:
                # Shielded: a cancel here cannot interrupt the worker thread, which
                # goes on to register the scan, so the registration is left to
                # finish and is closed below instead of being abandoned half
                # done.
                scan_id = await asyncio.shield(registration)
            except asyncio.CancelledError:
                # `registered` is still False, so the arm below gives nothing
                # back, and the entry the thread writes would stay PENDING,
                # holding its directory and a max_concurrent_scans slot for the
                # server's life. It is closed as a scan that did not start the
                # moment the thread returns (at once when it already has). The
                # session's claim and count are given back by the finally of
                # this function, as for every other way out before the task.
                registration.add_done_callback(
                    lambda done: _close_a_registration_nobody_awaited(
                        done, registry, scan_id, output_dir, environment_values
                    )
                )
                raise
            registered = True
            # The runner's claim on the entry, recorded here rather than by the
            # runner's first step: between the set-aside below and that step a
            # progress poll read a PENDING entry with no runner, which the
            # registry closes from the results file (check_scan_progress), and
            # the file was just set aside, so the scan was closed FAILED before
            # it ran. Every way out of this tool that leaves no runner to settle
            # the entry marks the runner done (the mkdir arm below and
            # _give_back_a_scan_that_did_not_start), so the claim does not keep
            # the directory held (occupies_its_directory).
            claimed_entry = registry.get_scan(scan_id)
            if claimed_entry is not None:
                claimed_entry.has_runner = True

            # Created only now that the registry has given this scan the
            # directory, so a refused scan leaves nothing in the scanned
            # repository. A scan whose output cannot be created gives its claim
            # back, and is refused as output_directory_refusal refuses one it
            # can tell beforehand: under a .ash that cannot be written, it is
            # known only now.
            try:
                output_dir.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                # The operating system's words are recorded and shown, so this
                # arm redacts with the config's environment values as the
                # other failure arms do (text_without_values: the text is not
                # an exception's own).
                unmakeable = text_without_values(
                    output_dir_unmakeable(output_dir, e.strerror or type(e).__name__),
                    environment_values,
                )
                registry.finish_scan(
                    scan_id, MCScanStatus.FAILED, error_message=unmakeable
                )
                # No runner will settle this entry: the claim made at
                # registration is released, or the closed entry would hold
                # its directory for the server's life.
                if claimed_entry is not None:
                    claimed_entry.runner_done.set()
                unmakeable_response = create_error_response(
                    error=MCPResourceError(
                        unmakeable,
                        context={
                            "directory_path": str(output_dir),
                            "error_category": ErrorCategory.INVALID_PARAMETER.value,
                        },
                    ),
                    operation="scan_directory",
                    suggestions=["Make the scan's output directory one it can create"],
                )
                unmakeable_response["error_type"] = OUTPUT_DIR_NOT_USABLE
                return with_exit_code(unmakeable_response, REFUSED_USAGE_EXIT_CODE)

            # The directory is this scan's from here, and its runner puts the
            # previous results back on every ending that has no results of its
            # own (core/previous_results.py). Not fatal: the scan's own set-up
            # sets them aside again.
            warnings: List[str] = []
            if clean_output:
                from automated_security_helper.core.previous_results import (
                    PreviousResults,
                )

                previous_results_moved = True
                try:
                    PreviousResults(output_dir).set_aside()
                except OSError as e:
                    # The system's words go into the started reply's warnings
                    # and the log, so they redact like the failure arms.
                    warnings.append(
                        "Could not set the previous results aside: "
                        f"{error_text(e, environment_values)}"
                    )
                    _logger.warning(f"Scan {scan_id}: {warnings[-1]}")

            # Start the scan process asynchronously. A task cancelled before
            # the loop first ran it runs no line of the runner, its finally
            # included, so the task's done callback gives back what the runner
            # would have (_start_scan_task reads whether the runner ran): the
            # registered entry, closed as a scan that did not start, with the
            # previous results set aside above put back; the count and the
            # claim; and the end of a session that arrived while the claim was
            # held.

            def _give_back_what_the_runner_never_took() -> None:
                _give_back_a_scan_that_did_not_start(
                    registry,
                    scan_id,
                    output_dir,
                    asyncio.CancelledError(
                        "the scan's task was cancelled before it ran"
                    ),
                    previous_results_moved=previous_results_moved,
                    environment_values=environment_values,
                )
                try:
                    _release_what_the_scan_held(counted, claimed_session, session_id)
                except Exception as release_error:  # noqa: BLE001 -- a done callback
                    # Never out of a done callback, which asyncio would only
                    # log; the claim and the count are released before the
                    # session's end is completed, which is what can raise.
                    _logger.error(
                        f"Scan {scan_id}: could not complete the end of its session "
                        f"after its task was cancelled before it ran: "
                        f"{error_text(release_error, environment_values)}"
                    )

            _start_scan_task(
                scan_id,
                _run_scan_async(
                    scan_id=scan_id,
                    directory_path=str(directory_path_obj),
                    output_dir=str(output_dir),
                    severity_threshold=severity_threshold,
                    config_path=config_path,
                    session_id=session_id,
                    scan_claim=claimed_session,
                    scan_counted=counted,
                    scan_timeout_seconds=limits.scan_timeout_seconds or None,
                    environment_values=environment_values,
                ),
                if_never_run=_give_back_what_the_runner_never_took,
            )
            task_started = True

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
                "warnings": warnings,
            }
        except BaseException as start_error:
            # Registered, and no task to close the entry: left pending it would
            # occupy its directory, refusing every later scan of it, and count
            # against max_concurrent_scans for the rest of the process. Closed as
            # failed with the reason, as the mkdir arm above closes one, and the
            # previous results set aside for it are put back, as its runner
            # would have. The error still reaches the arms below.
            if registered and not task_started:
                _give_back_a_scan_that_did_not_start(
                    registry,
                    scan_id,
                    output_dir,
                    start_error,
                    previous_results_moved=previous_results_moved,
                    environment_values=environment_values,
                )
            raise
        finally:
            if task_started:
                # The runner's task holds the scope now; this context goes
                # back to its own, so another scan started from it gets a
                # scope of its own.
                disown_run_log_scope(log_scope_token)
            else:
                end_run_log_scope(log_scope, log_scope_token)

    except MCPResourceError as e:
        # Handle specific MCPResourceError with enhanced context. The error's own
        # suggestions win when it has them: a refusal at the concurrency limit or
        # for a directory already being scanned says what to do about it, which
        # the generic list below does not. No refusal raised here quotes a value
        # the scan's config read from the environment today, but the response
        # shows the error's text, so the values ride on the error and every
        # printer redacts with them, as the sibling arms redact theirs. The
        # response also shows the error's context and the suggestions taken
        # from it, which no printer touches, so those are redacted here with
        # the same values before the response is built.
        carry_environment_values(e, environment_values)
        try:
            e.context = _context_without_values(e.context, environment_values)
        except Exception:  # noqa: BLE001 -- this arm IS the error handler
            # Whatever the walker could not take (a shape it cannot walk, a
            # recursion past the interpreter's limit), the refusal is still
            # answered structured. The context is dropped rather than shown:
            # unredacted it could hold exactly what the redaction hides.
            e.context = {
                "context": "(not shown: the error's context could not be redacted)"
            }
        return with_exit_code(
            create_error_response(
                error=e,
                operation="scan_directory",
                suggestions=e.context.get("suggestions")
                or [
                    "Check that the directory exists and is accessible",
                    "Verify that the severity threshold is valid",
                    "Ensure the configuration file is valid if provided",
                ],
            ),
            REFUSED_INTERNAL_EXIT_CODE,
        )
    except Exception as e:
        # Handle unexpected errors. Nothing in the registration block reads
        # the resolved config, so no error caught here quotes a config-read
        # environment value today; the pre-check's values are passed as
        # defense in depth, so the text stays redacted if that ever changes.
        log_unexpected_error(
            _logger, e, "Unexpected error starting scan", values=environment_values
        )
        return with_exit_code(
            create_error_response(
                error=MCPResourceError(
                    f"Unexpected error starting scan: {error_text(e, environment_values)}",
                    context={
                        "directory_path": directory_path,
                        "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                        "error_type": type(e).__name__,
                        "error_message": error_text(e, environment_values),
                    },
                ),
                operation="scan_directory",
            ),
            REFUSED_INTERNAL_EXIT_CODE,
        )
    finally:
        # The task releases the claim and the count once it has started; a scan
        # that never started releases them here, and completes the end of a
        # session that arrived while the claim was held, as the task would:
        # off the event loop, and without raising, so what this tool was
        # returning (a refusal, the exit-coded error reply) still reaches the
        # client when the removal fails.
        if not task_started:
            await _release_what_the_scan_held_off_the_loop(
                counted,
                claimed_session,
                session_id,
                scan_id=scan_id,
                environment_values=environment_values,
            )


async def _release_what_the_scan_held_off_the_loop(
    scan_counted: Optional[Any],
    scan_claim: Optional[Any],
    session_id: Optional[str],
    *,
    scan_id: Optional[str],
    environment_values: Tuple[str, ...],
) -> None:
    """Give back what a scan took of its session, off the event loop, never raising.

    :func:`_release_what_the_scan_held` for the start paths of an async tool.
    The removal of an ended session's workspace deletes a tree, so it runs on a
    worker thread, as :func:`_run_scan_async`'s finally runs it, and shielded:
    a tool call cancelled while it refuses a scan still completes the end it
    deferred. The claim and the count are given back first, on this thread, so
    a removal that fails leaves neither held; the failure is logged, redacted
    with the config's environment values like every failure arm, and not
    raised: at the per-session limit a raise would replace the structured
    refusal, and in ``mcp_scan_directory``'s outer finally it would replace
    whatever the tool was returning, so the client would get an exception for
    a scan that was refused.
    """
    _give_back_the_scans_claim(scan_counted, scan_claim)
    if not _holds_a_session(session_id):
        return
    import anyio

    from automated_security_helper.cli.mcp.sessions import finish_ended_session

    try:
        with anyio.CancelScope(shield=True):
            await anyio.to_thread.run_sync(finish_ended_session, session_id)
    except Exception as release_error:  # noqa: BLE001 -- the tool's own reply wins
        _logger.error(
            f"Scan {scan_id or '(not started)'}: could not complete the end of "
            "its session after the scan was not started: "
            f"{error_text(release_error, environment_values)}"
        )


def _release_what_the_scan_held(
    scan_counted: Optional[Any], scan_claim: Optional[Any], session_id: Optional[str]
) -> None:
    """Give back what a scan took of its session when it was started.

    ``scan_counted`` is what counted the scan against the per-session limit
    (its ``MCPSession``, or the shared ``sessions.ScanCount`` of a caller with
    no session), uncounted here; ``scan_claim`` the ``MCPSession`` whose scan
    claim ``mcp_scan_directory`` took, released here. Then a session that ended
    while the scan held or claimed it has its workspace removed
    (``sessions.finish_ended_session``): ``end_session`` is refused while a
    claim is held and leaves the removal pending for whoever releases the
    claim, so every path that releases one completes it, the runner's finally
    and the start paths that give the claim back without a scan alike.

    The removal runs here, on the calling thread, and raises what it raises:
    this is the form for a done callback, which cannot await and guards the
    call itself (``_give_back_what_the_runner_never_took``). An async start path
    uses :func:`_release_what_the_scan_held_off_the_loop`.
    """
    _give_back_the_scans_claim(scan_counted, scan_claim)
    if _holds_a_session(session_id):
        from automated_security_helper.cli.mcp.sessions import finish_ended_session

        finish_ended_session(session_id)


def _give_back_the_scans_claim(
    scan_counted: Optional[Any], scan_claim: Optional[Any]
) -> None:
    """Uncount a scan and release its claim; see :func:`_release_what_the_scan_held`."""
    if scan_counted is not None:
        scan_counted.scan_returned()
    if scan_claim is not None:
        scan_claim.release_scan()


def _holds_a_session(session_id: Optional[str]) -> bool:
    """Whether a scan with this id took a session claim: a caller the server
    could identify (not None, not the unidentified sentinel)."""
    return session_id is not None and session_id != UNIDENTIFIED_SESSION_ID


def _give_back_a_scan_that_did_not_start(
    registry: Any,
    scan_id: str,
    output_dir: Path,
    start_error: BaseException,
    *,
    previous_results_moved: bool,
    environment_values: Tuple[str, ...] = (),
) -> None:
    """Close a registered scan whose runner's task never started.

    The entry is closed as failed with the reason, so it no longer occupies its
    directory or a max_concurrent_scans slot, and previous results set aside for
    the scan are put back, recorded on the entry as its runner records them.
    Never raises: it runs on the way out of an error the caller reports.

    ``environment_values`` are what the scan's config read from the environment
    (``_config_pre_check``). The reason lands in the entry's error_message,
    which get_scan_progress hands to the client, so its text is redacted with
    them, as every other showing of the start error is.
    """
    reason = (
        f"The scan could not be started: {error_text(start_error, environment_values)}"
    )
    try:
        registry.finish_scan(scan_id, MCScanStatus.FAILED, error_message=reason)
    except Exception as finish_error:  # noqa: BLE001
        _logger.error(
            f"Scan {scan_id}: could not close the scan that did not start: "
            f"{error_text(finish_error, environment_values)}"
        )
    # The tool claimed the runner's ownership of the entry at registration
    # (mcp_scan_directory); no runner will mark it done, so this does, or the
    # closed entry would hold its directory for the server's life
    # (occupies_its_directory).
    try:
        entry = registry.get_scan(scan_id)
        if entry is not None:
            entry.runner_done.set()
    except Exception as claim_error:  # noqa: BLE001
        _logger.error(
            f"Scan {scan_id}: could not release the runner's claim of the scan "
            f"that did not start: {error_text(claim_error, environment_values)}"
        )
    if not previous_results_moved:
        return
    from automated_security_helper.core.previous_results import (
        PreviousResults,
        holds_restored_results,
    )

    try:
        PreviousResults(output_dir).restore()
        entry = registry.get_scan(scan_id)
        if entry is not None:
            entry.output_holds_previous_results = holds_restored_results(output_dir)
    except Exception as restore_error:  # noqa: BLE001
        _logger.error(
            f"Scan {scan_id}: could not put the previous results back in "
            f"{output_dir}: {error_text(restore_error, environment_values)}"
        )


def _close_a_registration_nobody_awaited(
    registration: "asyncio.Future[str]",
    registry: Any,
    scan_id: str,
    output_dir: Path,
    environment_values: Tuple[str, ...] = (),
) -> None:
    """Close the entry of a registration whose start was cancelled while it ran.

    ``mcp_scan_directory`` awaits ``registry.register_scan`` in a worker thread,
    and a cancel cannot interrupt that thread: it goes on to write the PENDING entry
    after the caller has gone. This done callback of the registration's future
    closes that entry as a scan that did not start, through
    ``_give_back_a_scan_that_did_not_start``, so it no longer occupies its
    directory or a max_concurrent_scans slot. A registration that was refused or
    cancelled wrote no entry, and its error is read here so it is not reported
    as never retrieved. Never raises: asyncio would only log it.
    """
    if registration.cancelled() or registration.exception() is not None:
        return
    _give_back_a_scan_that_did_not_start(
        registry,
        scan_id,
        output_dir,
        asyncio.CancelledError("the scan's start was cancelled while it registered"),
        previous_results_moved=False,
        environment_values=environment_values,
    )


def _judged_threshold(results: Any) -> Optional[str]:
    """The global severity threshold a finished scan's findings were judged by.

    Read from the config the scan resolved, which is what decided it: the client's
    threshold when it named one, else the config file's. None when the results
    carry no config, which a test double or an older results shape can do.
    """
    config = getattr(results, "ash_config", None)
    settings = getattr(config, "global_settings", None)
    threshold = getattr(settings, "severity_threshold", None)
    return threshold if isinstance(threshold, str) else None


def _gap_named_by_the_exit(ended: BaseException) -> Dict[str, Any]:
    """The coverage gap an exit for incomplete coverage names, from its plain rows.

    For a scan that exited with ``ScanIncompleteExit`` when its close could not be
    worked out in full (``to_payload()`` or the judged threshold raised). The
    registry refuses to close a scan as incomplete with no gap attached, so the
    close needs one, and the exit's scanner rows are what its exit code was decided
    on. The shape is the payload's, minus the reason tokens. Never raises: a row
    that cannot be read is left out.
    """
    incompleteness = getattr(ended, "incompleteness", None)
    rows: List[Dict[str, Any]] = []
    try:
        raw_status = dict(getattr(incompleteness, "observed", ()) or ())
        for name, detail in getattr(incompleteness, "scanners", ()) or ():
            rows.append(
                {"scanner": name, "status": raw_status.get(name, ""), "detail": detail}
            )
    except Exception:  # noqa: BLE001
        pass
    return {
        "incomplete_scanners": rows,
        "no_scanner_ran": bool(getattr(incompleteness, "no_scanner_ran", False)),
    }


def _scan_timeout_reason(scan_timeout_seconds: Any, environment_values: Any) -> str:
    """The FAILED reason for a scan that exceeded the server's time limit.

    The limit prints through the shared timeout formatter
    (error_text.timeout_limit_phrase), so a limit that ever comes from the
    environment names the option instead of riding the reason as a bare
    number -- and names THIS option, scan_timeout_seconds, not the scanner's
    scan_timeout, which the bare token's fallback would.
    """
    phrase = timeout_limit_phrase(
        scan_timeout_seconds, environment_values, option_name="scan_timeout_seconds"
    )
    return f"Scan exceeded the server's {phrase} and was cancelled"


async def _run_scan_async(
    scan_id: str,
    directory_path: str,
    output_dir: str,
    severity_threshold: Optional[str],
    config_path: Optional[str] = None,
    session_id: Optional[str] = None,
    scan_claim: Optional[Any] = None,
    scan_counted: Optional[Any] = None,
    scan_timeout_seconds: Optional[float] = None,
    environment_values: Tuple[str, ...] = (),
) -> None:
    """Run an ASH scan asynchronously, then release what it held of its session.

    Arguments as :func:`_run_scan`, plus ``scan_claim``: the ``MCPSession``
    whose scan claim :func:`mcp_scan_directory` took, released when the scan
    returns, before a session that ended meanwhile is removed; and
    ``scan_counted``: what counted this scan against the per-session limit (its
    ``MCPSession``, or for a caller with no session the shared
    ``sessions.ScanCount``), uncounted at the same time
    (:func:`_release_what_the_scan_held`). A task cancelled before this
    coroutine ran a line, whose finally below never runs, is told apart from
    one that ran and released these itself by :func:`_start_scan_task`, which
    marks the start before the runner's first line.
    """
    try:
        await _run_scan(
            scan_id=scan_id,
            directory_path=directory_path,
            output_dir=output_dir,
            severity_threshold=severity_threshold,
            config_path=config_path,
            session_id=session_id,
            scan_timeout_seconds=scan_timeout_seconds,
            environment_values=environment_values,
        )
    finally:
        _give_back_the_scans_claim(scan_counted, scan_claim)
        if _holds_a_session(session_id):
            # A session that ended while this scan held or claimed it has its
            # workspace removed now that the scan no longer reads it. The
            # removal deletes a tree, so it runs off the event loop every
            # session's tool calls share, and shielded: this finally runs for
            # a cancelled task too, and the removal has to complete anyway
            # (http_sessions ends its own sessions the same way).
            import anyio

            from automated_security_helper.cli.mcp.sessions import (
                finish_ended_session,
            )

            with anyio.CancelScope(shield=True):
                await anyio.to_thread.run_sync(finish_ended_session, session_id)


async def _run_scan(
    scan_id: str,
    directory_path: str,
    output_dir: str,
    severity_threshold: Optional[str],
    config_path: Optional[str] = None,
    session_id: Optional[str] = None,
    scan_timeout_seconds: Optional[float] = None,
    environment_values: Tuple[str, ...] = (),
) -> None:
    """
    Run an ASH scan asynchronously.

    This function runs the scan using direct Python calls to the ASH functionality
    and updates the scan registry with the scan status.

    When ``session_id`` is provided, the scan acquires the per-session
    lock from :class:`MCPSessionRegistry` for the duration of the
    underlying ``run_ash_scan`` call. Two concurrent scans on the same
    session serialize on this lock; distinct sessions never contend.

    Args:
        scan_id: ID of the scan
        directory_path: Path to the directory to scan
        output_dir: Path to the output directory
        severity_threshold: Threshold applied over the config's
            global_settings.severity_threshold, or None to keep the config's
        config_path: Optional path to ASH configuration file
        session_id: Optional MCP session id whose per-session lock guards
            the scan. None means no session — equivalent to legacy behavior.
        scan_timeout_seconds: The operator's limit on how long the scan may run,
            counted from when it starts running. A scan still running then is
            closed as failed and stopped the way cancel_scan stops one. None
            for no limit.
        environment_values: What the scan's config read from the environment
            (the caller's pre-check resolution; this runner widens them with
            the session profile's chain -- the trusted base of a delivered
            config, or the profile standing as the scan's own config -- read
            under the scan's own gates from the snapshot the scan loads). The
            scan runs with that
            config in use, so a failure here is the live producer of a text
            that can quote one of its values: every reason this runner records
            or logs is redacted with them. An error that carries the values
            itself (carry_environment_values) was already shown redacted;
            these cover the ones that do not.

    The previous scan's results in output_dir are dropped when this scan has its
    own and put back on every other ending (core/previous_results.py). The scan
    runs with keep_previous_results, so the orchestrator sets them aside and puts
    them back when its phases fail; dropping them is left to this runner, which
    decides last whether the scan has results.
    """
    from automated_security_helper.core.cancellation import (
        ScanCancelled,
        cancel_scope,
        raise_if_cancelled,
    )
    from automated_security_helper.core.enums import AshLogLevel, RunMode
    from automated_security_helper.core.resource_management.scan_tracking import (
        assess_coverage,
        coverage_has_gap,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.interactions.run_ash_scan import (
        ScanIncompleteExit,
        run_ash_scan,
    )

    from automated_security_helper.cli.mcp.profile_registry import (
        resolve_session_config_path,
        resolve_session_trusted_config_path,
    )
    from automated_security_helper.cli.mcp.sandbox import (
        caller_is_remote,
        config_base_gate,
        client_named_config_is_untrusted,
    )

    from automated_security_helper.core.previous_results import (
        PreviousResults,
        SettleHandoff,
        holds_restored_results,
    )

    registry = get_scan_registry()
    entry = registry.get_scan(scan_id)
    if not entry:
        _logger.error(f"Scan {scan_id} not found in registry")
        return

    previous_results = PreviousResults(Path(output_dir))
    handoff = SettleHandoff()
    # Set once the scan has been settled as one with results of its own: the
    # previous results are gone and the scan's are on disk. Read by the timeout,
    # which must not then close the entry as failed (_stop_at_timeout), and by
    # the runner's own failure arms (_close_after_the_runner_failed).
    settled_with_results = threading.Event()
    # Orders the scan thread's settle decision against the runner's failure
    # arms. The thread decides, under this lock, whether the scan has results of
    # its own and sets the mark before it drops the previous results; an arm
    # checks the mark and closes the entry under the same lock. One that runs
    # first closes the entry and sets the cancel event, which the decision then
    # reads; one that runs after finds the mark set. Held only for the decision
    # and for an arm's check-then-close, never across the disk work that follows
    # the decision.
    settle_decision = threading.Lock()
    # What a scan that kept its results is closed with: its status, coverage
    # payload and severity threshold, worked out once on the scan's thread and
    # recorded under settle_decision beside the mark. Every close of such a scan
    # reads it -- the runner's own, and the one through the mark when the runner
    # fails first -- so the entry is the same whichever runs. The mark alone could
    # not tell an incomplete ending from a complete one.
    settled_close: Optional[
        Tuple[MCScanStatus, Optional[Dict[str, Any]], Optional[str]]
    ] = None
    # Whether the caller is a remote one, decided before any closure below can
    # run. The close helpers read it, and the refusal arms that run before the
    # config work close an entry through them, so it cannot be assigned further
    # down: a free variable read before its assignment raises.
    remote_client = caller_is_remote(session_id)

    def _work_out_the_close(
        ended: Optional[BaseException], results: Any
    ) -> Tuple[MCScanStatus, Optional[Dict[str, Any]], Optional[str]]:
        """The status, coverage and threshold a scan that kept its results records.

        ``ended`` is the exit for incomplete coverage, or None for a return or an
        exit 0; ``results`` is what a return handed back (a results model, or
        anything else a test double returns). The coverage of an incomplete scan
        is the facts assessed from its results when they name a gap, and the
        exit's own reasons otherwise; the coverage of a completed one is the
        assessed facts, whatever the gate says. It reads the exit's payload and the
        judged threshold without a guard of their own, so it can raise: call
        ``_close_for``, which cannot.
        """
        if isinstance(ended, ScanIncompleteExit):
            # The gap reported is the facts whatever the gate says, as for a
            # completed scan. The exception's own reasons are the fallback: they
            # are what the exit code was decided on, so they are never empty.
            coverage: Optional[Dict[str, Any]] = ended.incompleteness.to_payload()
            try:
                _, facts = assess_coverage(ended.results)
                if coverage_has_gap(facts):
                    coverage = facts
            except Exception as assess_error:  # noqa: BLE001
                _logger.warning(
                    f"Scan {scan_id}: could not assess coverage, reporting the exit "
                    f"code's reasons instead: {error_text(assess_error, environment_values)}"
                )
            return MCScanStatus.INCOMPLETE, coverage, _judged_threshold(ended.results)
        coverage = None
        if isinstance(results, AshAggregatedResults):
            try:
                _, coverage = assess_coverage(results)
            except Exception as assess_error:  # noqa: BLE001
                # The scan succeeded. Failing to describe its coverage must not
                # turn it into a failed one; check_scan_progress assesses the
                # results file instead when no coverage was recorded.
                _logger.warning(
                    f"Scan {scan_id}: could not assess coverage: "
                    f"{error_text(assess_error, environment_values)}"
                )
        return MCScanStatus.COMPLETED, coverage, _judged_threshold(results)

    def _close_for(
        ended: Optional[BaseException], results: Any
    ) -> Tuple[MCScanStatus, Optional[Dict[str, Any]], Optional[str]]:
        """``_work_out_the_close``, which never raises: every caller is covered.

        Failing to describe the coverage must not change how the scan ended. The
        runner calls this from its return arm and from its incomplete-coverage arm
        for a scan whose thread recorded no close (its cancel event was set), where
        an error would leave the task, which nothing awaits, with the entry still
        running, or close a scan that ended normally as failed. The scan has results,
        so on an error it is closed as what it ended as, with no threshold:
        ``COMPLETED`` with no coverage, or, for the exit for incomplete coverage,
        ``INCOMPLETE`` with the gap its own scanner rows name, because the registry
        refuses to close a scan as incomplete with no gap attached.
        """
        try:
            status, coverage, threshold = _work_out_the_close(ended, results)
        except Exception as close_error:  # noqa: BLE001
            fallback: Tuple[MCScanStatus, Optional[Dict[str, Any]], Optional[str]]
            if isinstance(ended, ScanIncompleteExit):
                fallback = (
                    MCScanStatus.INCOMPLETE,
                    _gap_named_by_the_exit(ended),
                    None,
                )
            else:
                fallback = (MCScanStatus.COMPLETED, None, None)
            _logger.warning(
                f"Scan {scan_id}: could not work out the coverage and severity "
                f"threshold of a scan that has its own results; it is closed as "
                f"{fallback[0].value} without the full set: "
                f"{error_text(close_error, environment_values)}"
            )
            status, coverage, threshold = fallback
        # Inside the never-raises contract, as the work above is: a row that
        # cannot be redacted must not turn the close into an exception, which
        # would leave the entry running. It is stored without its reasons
        # instead, since a reason is what names the process id.
        try:
            shown = _coverage_as_the_caller_may_see_it(coverage, remote_client)
        except Exception as redact_error:  # noqa: BLE001
            _logger.warning(
                f"Scan {scan_id}: could not redact the coverage's reasons for "
                "this caller, so they are not stored: "
                f"{error_text(redact_error, environment_values)}"
            )
            shown = _coverage_without_reasons(coverage)
        return status, shown, threshold

    def _coverage_without_reasons(
        coverage: Optional[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """``coverage`` with every could_not_stop row cut down to its scanner.

        Never raises, whatever the rows are: a row that is not a mapping names
        no scanner and is stored as ``unknown``, so the gap is still counted.
        """
        if not isinstance(coverage, dict):
            return None
        rows = coverage.get("could_not_stop")
        if not isinstance(rows, (list, tuple)):
            return coverage
        return {
            **coverage,
            "could_not_stop": [
                {
                    "scanner": str(row.get("scanner", "unknown"))
                    if isinstance(row, dict)
                    else "unknown"
                }
                for row in rows
            ],
        }

    def _coverage_as_the_caller_may_see_it(
        coverage: Optional[Dict[str, Any]],
        remote_client: bool,
    ) -> Optional[Dict[str, Any]]:
        """The coverage to store, its could_not_stop reasons shown as this caller may see them.

        A reason names the process id of the tool ASH could not end
        (``could_not_stop_default``). The cancel warning withholds that id from a
        network transport and the workspace tool withholds it from a remote
        caller (``_project_coverage``); the stored coverage is what a later
        progress call returns, so it is stored the same way, decided by the
        request-scoped predicate the response uses (``remote_client``, from
        ``caller_is_remote``), never by the process-wide transport. Every close
        of this scan passes through here, so the stored and the returned rows
        agree. A progress call by a different caller than the one that scanned
        reads this caller's choice; redacting at the read would cover that and
        is not done here.
        """
        if not coverage or not remote_client:
            return coverage
        rows = coverage.get("could_not_stop")
        if not rows:
            return coverage
        from automated_security_helper.utils.subprocess_utils import (
            without_process_ids,
        )

        return {
            **coverage,
            "could_not_stop": [
                {**row, "reason": without_process_ids(str(row.get("reason", "")))}
                for row in rows
            ],
        }

    def _settle_previous_results(
        ended: Optional[BaseException], results: Any = None
    ) -> None:
        """Drop the previous results if the scan has its own, else put them back.

        A scan has its own when run_ash_scan returned or exited 0, or exited
        with ScanIncompleteExit, which is raised only with results in hand, and
        its cancel event is not set. One that ended that way with the event set
        was cancelled or timed out after run_ash_scan's last check, and the
        client was told so, so it is settled as a scan without results.
        Otherwise the entry records whether the directory now holds the previous
        scan's results (the orchestrator may have put them back already), so its
        progress does not report them as this scan's.

        Never raises: this runs on the paths that record how the scan ended, and
        an exception here would leave the entry RUNNING.
        """
        # The decision and the mark are one step under settle_decision, so a
        # runner failure arm either closes the entry (and sets the cancel event)
        # before the decision, which then reads the event, or finds the mark set
        # after it (_close_after_the_runner_failed).
        nonlocal settled_close
        ended_with_results = (
            ended is None
            or isinstance(ended, ScanIncompleteExit)
            or (isinstance(ended, SystemExit) and ended.code in (None, 0))
        )
        # Worked out before the lock: it reads the results model, not the
        # entry, and the lock is held only for the decision.
        # _close_for never raises (Exception), so nothing here is left half done
        # when the exit's payload or the judged threshold cannot be read.
        close: Optional[
            Tuple[MCScanStatus, Optional[Dict[str, Any]], Optional[str]]
        ] = None
        if ended_with_results:
            close = _close_for(ended, results)
        with settle_decision:
            has_results = ended_with_results and not entry.cancel_event.is_set()
            if has_results:
                settled_close = close
                settled_with_results.set()
        try:
            if has_results:
                previous_results.discard()
            else:
                previous_results.restore()
                entry.output_holds_previous_results = holds_restored_results(
                    Path(output_dir)
                )
        except Exception as settle_error:
            # Redacted like every other reason this runner logs (the
            # environment_values docstring above): the system's words can
            # quote a path or value the failing move touched.
            _logger.error(
                f"Scan {scan_id}: could not settle the previous results in "
                f"{output_dir}: {error_text(settle_error, environment_values)}"
            )

    def _close_after_the_runner_failed(
        reason: str, *, exit_code: Optional[int] = None, stop_the_scan: bool = False
    ) -> None:
        """Close the entry for a runner that failed, unless the scan finished.

        The check of the mark and the close are one step under
        ``settle_decision``, the lock the thread's decision is made under. A
        thread that settled the scan as one with results has its results on disk
        and is dropping the previous scan's, so a failure that reaches the runner
        after that point -- the loop cancelling the task while the drop runs, or
        the close of a finished scan raising -- does not make it a scan without a
        result: the entry is closed with what the thread worked out for it
        (``settled_close``): the status, coverage and severity threshold the
        runner's own close would have recorded. When that close raises too (the
        runner's own close failed on the same values), the entry is closed with the
        status alone and the line says what was left out. Any other failure closes it
        FAILED with ``reason``, and with ``stop_the_scan`` sets the cancel
        event under the same lock, so the thread's decision reads the entry
        closed and the event set, or has been made first and the entry is
        closed after it.
        """
        from automated_security_helper.utils.terminal_text import shown_on_one_line

        with settle_decision:
            if settled_with_results.is_set():
                # Set under this lock with the mark, so it is there whenever the
                # mark is.
                status, coverage, threshold = settled_close or (
                    MCScanStatus.COMPLETED,
                    None,
                    None,
                )
                dropped: Optional[Exception] = None
                try:
                    recorded = registry.finish_scan(
                        scan_id,
                        status,
                        coverage=coverage,
                        severity_threshold=threshold,
                    )
                except Exception as close_error:  # noqa: BLE001
                    # The runner's own close of this scan carried the same coverage
                    # and threshold, and its failure is what brought the runner here.
                    # A failure that comes from them comes again, and an exception
                    # out of this arm leaves the entry running, which this arm
                    # exists to prevent. The status alone is what the entry must end
                    # with, so it is recorded without the two values.
                    dropped = close_error
                    recorded = registry.finish_scan(scan_id, status)
                # Only an entry this call closed: one already closed (cancelled
                # by the client, say) keeps its status, and the line would
                # report a record that was not made.
                if recorded:
                    without = (
                        ""
                        if dropped is None
                        else (
                            " without its coverage and severity threshold, which "
                            "could not be recorded: "
                            f"{error_text(dropped, environment_values)}"
                        )
                    )
                    _logger.warning(
                        shown_on_one_line(
                            text_without_values(
                                f"Scan {scan_id} had its own results when the "
                                f"runner failed; recorded as {status.value}"
                                f"{without}: {reason}",
                                environment_values,
                            )
                        )
                    )
                return
            _scan_failed(
                registry,
                scan_id,
                reason,
                exit_code=exit_code,
                environment_values=environment_values,
            )
            if stop_the_scan:
                entry.cancel_event.set()

    def _refuse_before_running(exc: BaseException) -> None:
        """Close the entry for a scan refused before its thread ran.

        The runner's own try begins at the RUNNING mark below, so a refusal in
        the set-up before it records the entry FAILED itself (left PENDING, it
        would read as running) and settles the previous results as a scan
        without results does: what clean_output set aside in
        mcp_scan_directory is put back, and whether the directory holds them is
        recorded on the entry. The thread never started, so this runner marks
        its own end.

        The reason is written as every other reason this runner records or logs
        is (error_text with the scan's environment values): a refusal raised
        here can quote a path or a value the session's configuration read, and
        written raw it reached the entry's error_message, which
        get_scan_progress hands to the client, and the log.
        """
        reason = error_text(exc, environment_values)
        registry.finish_scan(scan_id, MCScanStatus.FAILED, reason)
        _logger.error(f"Scan {scan_id} refused: {reason}")
        _settle_previous_results(exc)
        entry.runner_done.set()

    # Every config read inside the scan checks each `extends` base against this
    # session's grant. mcp_scan_directory checked the chain before starting; this
    # is what holds if a base changes between that check and the scan.
    base_gate = config_base_gate(session_id)

    # A config the client delivered into a session sandbox (an upload or a clone)
    # is the client's, not the operator's, wherever the scan target is. It is
    # resolved restrict-only for sandbox settings, with the profile this session
    # bound, if any, as the trusted base the grants come from: the registered
    # profile, not the session's copy of it after the client's patch, which is
    # itself a config the client supplied.
    # A config path the client named is the client's unless the operator set it
    # aside (client_named_config_is_untrusted), even when it is a file in another
    # repository the server may scan. The predicate reads the filesystem (a
    # resolve, a samefile), so a link loop or a directory gone since the start
    # raises here, before the RUNNING mark: refused like the profile steps
    # below, never raised out of this coroutine with the entry left PENDING.
    try:
        untrusted_config = config_path is not None and client_named_config_is_untrusted(
            config_path, session_id=session_id
        )
    except Exception as exc:  # noqa: BLE001 -- an entry left PENDING reads as running
        _refuse_before_running(exc)
        return
    # The session's bound profile is written again here when its file is gone;
    # a profile that cannot be written again (unregistered, or an unwritable
    # workspace), or one whose workspace another request holds (its removal by
    # the sweep, a clear, the end of the session: the write hold's refusal),
    # refuses the scan. Caught here, not left to propagate: the runner's own
    # try begins further down, and an exception out of this coroutine would
    # leave the entry PENDING, which reads as running. Every exception, not the
    # registry's and the workspace hold's alone: the lookup stats the recorded
    # files first, and a stat refused on the workspace's parent raises an OSError
    # of its own, which left the entry PENDING with its runner claimed and never
    # marked done, so the directory was held for the server's life.
    try:
        trusted_config_path = (
            resolve_session_trusted_config_path(session_id)
            if untrusted_config
            else None
        )
    except Exception as exc:  # noqa: BLE001 -- an entry left PENDING reads as running
        _refuse_before_running(exc)
        return
    # For a remote caller (remote_client, above), every config file the operator
    # did not set aside resolves no !ENV, the target's own .ash.yaml included;
    # see "Environment variables" in config/config_sources.py.
    # Every file of the chain a client delivered, the named upload or the
    # target's own .ash.yaml, is checked against this session's policy.
    try:
        client_config_policy = _session_client_rules(session_id)
    except Exception as exc:  # noqa: BLE001 -- an entry left PENDING reads as running
        _refuse_before_running(exc)
        return
    # The session's own profile as the scan's config: what the server passes
    # when the client names none. It is the same live file select_profile
    # rewrites, so it needs the same per-scan snapshot the trusted base of a
    # delivered config gets; without one, a rebind while this scan waits at
    # the session lock would run it on values the redaction set never saw.
    # The client types the config path, so whether it names the profile is
    # decided by file identity (_session_file_named_by: a ../ form, a relative
    # path and a link to the file all name it), and that reads the filesystem,
    # so it is decided on the worker thread of the snapshot step below and
    # never here on the event loop. Only whether the config could be the
    # profile is known here.
    try:
        session_profile = resolve_session_config_path(session_id)
    except Exception as exc:  # noqa: BLE001 -- an entry left PENDING reads as running
        # As above: a bound profile that cannot be read as registered, whose
        # workspace another request holds, or whose recorded file cannot be
        # stat'ed, refuses the scan, recorded on the entry rather than raised
        # out of the runner.
        _refuse_before_running(exc)
        return
    config_may_be_the_profile = (
        config_path is not None and not untrusted_config and session_profile is not None
    )
    # The scan copies the file it loads in the role the copy takes. As the
    # trusted base of a client's config that is the registered profile
    # (trusted_config_path), never the session's config path: for a patched
    # binding that is the client's patched copy, and a trusted base made from it
    # would be the client's settings compared with themselves. As the scan's own
    # config it is the session's profile.
    profile_to_snapshot: Optional[Path] = None
    if trusted_config_path is not None:
        profile_to_snapshot = Path(trusted_config_path)
    elif session_profile is not None and config_may_be_the_profile:
        profile_to_snapshot = Path(session_profile)
    scan_profile_snapshot: Optional[Path] = None

    def _discard_the_scans_profile_snapshot() -> None:
        # Idempotent (missing_ok): the scan thread's finally and this
        # runner's can both call it.
        from automated_security_helper.config.config_sources import (
            discard_scan_copy,
        )

        if scan_profile_snapshot is not None:
            # Discarded only once the file is gone, as in the sweep: a failed
            # delete leaves the copy on disk, still registered, for the next
            # bind to retry.
            try:
                scan_profile_snapshot.unlink(missing_ok=True)
            except OSError as exc:
                _logger.debug(
                    "the scan's profile snapshot could not be removed "
                    f"({type(exc).__name__})"
                )
            else:
                discard_scan_copy(scan_profile_snapshot)

    # Resolve the per-session lock if a session_id was supplied. The lock is
    # acquired inside the executor wrapper below — we MUST NOT hold it on the
    # event-loop thread, since the underlying ``run_ash_scan`` blocks for the
    # full scan duration.
    #
    # Resolved before the entry is marked RUNNING, so that nothing which can
    # raise sits between marking it and the try below that closes it.
    # check_scan_progress lets a RUNNING entry's runner decide its status, so an
    # entry left RUNNING would read as running forever.
    session_lock = None
    # A caller the server could not identify has no session to serialize on.
    if session_id is not None and session_id != UNIDENTIFIED_SESSION_ID:
        from automated_security_helper.cli.mcp.sessions import (
            get_default_registry as _get_session_registry,
        )

        try:
            session_lock = _get_session_registry().session_for(session_id).lock
        except Exception as exc:  # noqa: BLE001 -- an entry left PENDING reads as running
            _refuse_before_running(exc)
            return

    # The client's threshold reaches the scan as a restriction: the orchestrator
    # runs it at the stricter of this and the threshold the config resolved to,
    # so a client can tighten a repository's or operator's threshold and never
    # loosen it. None when the client named none.

    # The timeout closes the entry as failed first, so the status says why, and
    # then sets the cancel event, which stops the scan; the runner's ScanCancelled
    # arm below then finds the entry closed and leaves it. finish_scan returns
    # False for an entry already closed, so a scan that finished or was cancelled
    # just before the timer fired is left as it ended. A scan whose thread has
    # already kept its results is left too: its thread marks it, under
    # settle_decision, before it drops the previous results, and the entry is
    # open until the runner closes it, so the timer can fall due anywhere in
    # between. Closing it FAILED as timed out then would report a failure for a
    # scan whose results are on disk and whose previous ones are going away.
    #
    # The check of the mark, the close and the set of the cancel event are one
    # step under settle_decision, the lock the thread's decision is made under:
    # the thread reads the entry closed and the event set, or it has decided
    # first and the timer finds the mark. It never reads the event clear on an
    # entry the timer has already closed.
    def _stop_at_timeout() -> None:
        reason = _scan_timeout_reason(scan_timeout_seconds, environment_values)
        with settle_decision:
            if settled_with_results.is_set():
                return
            closed = registry.finish_scan(scan_id, MCScanStatus.FAILED, reason)
            if closed:
                entry.cancel_event.set()
        if closed:
            _logger.error(f"Scan {scan_id} failed: {reason}")

    # Armed when the scan starts running on its thread, after any wait for the
    # session lock: a scan queued behind another of its session has not used any
    # of its time. The thread asks the loop to arm it; the runner's finally
    # cancels it.
    loop = asyncio.get_running_loop()
    timeout_handles: list = []

    def _arm_timeout(seconds: float) -> None:
        timeout_handles.append(loop.call_later(seconds, _stop_at_timeout))

    def _start_the_clock() -> None:
        if scan_timeout_seconds:
            loop.call_soon_threadsafe(_arm_timeout, scan_timeout_seconds)

    # Mark the scan as running. From here this runner owns the directory until
    # its scan thread has stopped and settled it, which can be after the entry
    # is closed (occupies_its_directory); the try below sets runner_done on
    # every way out.
    entry.has_runner = True
    registry.update_scan_status(scan_id, MCScanStatus.RUNNING)

    # The run's log scope, joined in the try below. Until then nothing holds
    # it here: a runner that fails before it joins leaves the scope to the
    # task that holds it (_start_scan_task).
    log_scope: Optional[str] = None
    log_scope_token: Optional[contextvars.Token] = None
    # One release per hold, decided once: this runner's own share of the scope
    # and the scan thread's. The thread lets its share go when it ends, or this
    # task does if the thread never starts, and whichever path runs first turns
    # the flag off, so no path releases a share twice. An unmatched release is
    # ignored in log.py too, but these handles keep it from being sent at all.
    runner_share = {"held": False}
    thread_share = {"held": False}

    def _release_the_runners_share() -> None:
        if runner_share["held"]:
            runner_share["held"] = False
            release_run_log_scope(log_scope)

    def _release_the_threads_share() -> None:
        if thread_share["held"]:
            thread_share["held"] = False
            release_run_log_scope(log_scope)

    def _scan() -> Any:
        # progress=False: the Rich live display is for a terminal, and this scan
        # has none. It redraws from its own thread and swaps sys.stdout while it
        # runs, which on the stdio transport is the JSON-RPC channel; progress
        # reaches a client through get_scan_progress instead.
        return run_ash_scan(
            source_dir=directory_path,
            output_dir=output_dir,
            config=config_path,
            severity_threshold_restriction=severity_threshold,
            mode=RunMode.local,
            log_level=AshLogLevel.INFO,
            fail_on_findings=False,
            show_summary=False,
            progress=False,
            config_base_gate=base_gate,
            untrusted_config=untrusted_config,
            trusted_config_path=trusted_config_path,
            client_config_policy=client_config_policy,
            remote_client=remote_client,
            keep_previous_results=True,
        )

    # The exception that ended the scan on its thread, for the record step.
    ending: Dict[str, Optional[BaseException]] = {"exception": None}

    def _record_the_tools_the_stop_could_not_end() -> None:
        """Put the tools the stop could not end on the entry before the directory is let go.

        A stop (cancel_scan, the scan timeout, a cancelled runner task) ends the
        scan on its thread with a ScanCancelled, and the subprocess layer records
        on the entry's cancel event, the root of the scan's cancel chain, every
        tool it could not end (CancelEvent.note_could_not_stop). They are read
        here, on the thread, after run_ash_scan ended and before runner_done is
        set: the arm that catches the ScanCancelled runs on the runner's task,
        which a cancelled task no longer has, and once runner_done is set the
        registry may let the directory go (occupies_its_directory). The
        registry attaches them only to an entry the server stopped; a scan that
        ended on its own has no records. On a network transport the client's
        warning names the tools only, and the process ids go to this log. Never
        raises: it runs in the thread's finally, ahead of runner_done, and the
        caller sets runner_done whatever happens here.
        """
        try:
            # The event's records, then any the ScanCancelled that ended the
            # scan carries and the event does not: a raise site may build the
            # exception with its own pairs (scanner_executor's union of a
            # pool's cancels, a stand-in in a test) without noting them on the
            # event, and those pairs are the stop's outcome all the same.
            records = tuple(entry.cancel_event.could_not_stop_records())
            for record in getattr(ending["exception"], "could_not_stop", ()):
                if record not in records:
                    records = records + (record,)
            if not records:
                return
            # Named by the caller the scan was started for, as a workspace scan
            # names them (caller_is_remote), not by the transport alone: the
            # transport misses a remote caller on a transport the operator did
            # not mark as networked, and that caller would be handed the
            # server's process ids by get_scan_progress.
            if registry.record_cancel_outcome(
                scan_id, records, name_process_ids=not remote_client
            ):
                named = ", ".join(f"{tool} (pid {pid})" for tool, pid in records)
                _logger.warning(
                    f"Scan {scan_id} was stopped, but {len(records)} scanner "
                    f"tool(s) could not be stopped and may still be running: {named}"
                )
        except Exception as recording_error:  # noqa: BLE001 -- the thread's finally must go on
            _logger.warning(
                f"Scan {scan_id}: the tools the stop could not end were not "
                f"recorded: {type(recording_error).__name__}"
            )

    def _scan_under_session_lock() -> Any:
        """Acquire the session lock (if any) and run the scan synchronously.

        Wrapped in a function so the lock is acquired on the executor
        worker thread, not the asyncio event-loop thread. Returns what
        ``run_ash_scan`` returned, which on exit 0 is the results model.

        The scan also holds its session's ``ScanPresence`` while it runs, so the
        TTL sweep of another server sharing the workspace root skips the
        session.

        The scan runs inside its registry entry's cancel scope, so cancel_scan
        stops it (core/cancellation.py). The check after the lock is for a scan
        cancelled while it waited for another scan in the same session.

        The previous results are settled here, on the thread that wrote the new
        ones, and not in the runner's arms below: when the runner's task is
        cancelled, this thread is still running the scan until the cancel event
        stops it, and a restore from the event loop would race its writes. The
        orchestrator puts them back when its phases fail; this drops them for a
        scan that has results, and puts them back on every other ending. If the
        task gave up before this thread started, the task settled them, and the
        scan does not run.
        """
        from automated_security_helper.cli.mcp.sessions import ScanPresence

        if not handoff.thread_starts():
            return None
        try:
            if session_lock is not None:
                with session_lock, ScanPresence(session_id):
                    with cancel_scope(entry.cancel_event):
                        raise_if_cancelled()
                        _start_the_clock()
                        results = _scan()
            else:
                with cancel_scope(entry.cancel_event):
                    _start_the_clock()
                    results = _scan()
        except BaseException as ended:
            # Kept for the record step in the finally: a ScanCancelled may
            # carry pairs the cancel event never saw.
            ending["exception"] = ended
            _settle_previous_results(ended)
            raise
        else:
            _settle_previous_results(None, results)
            return results
        finally:
            # Before runner_done: from then on the registry may let the
            # directory go, and a tool still running would write into it. In
            # its own try: a record step that raised would otherwise skip
            # runner_done, and the entry would hold its directory for the
            # server's life (occupies_its_directory), refusing every rescan.
            try:
                _record_the_tools_the_stop_could_not_end()
            finally:
                entry.runner_done.set()
            # After run_ash_scan ended on this thread, so the scan can no
            # longer load it.
            _discard_the_scans_profile_snapshot()
            # After the thread's last line: a task cancelled while this
            # thread ran has let go already, and the scope closes now.
            _release_the_threads_share()
            # The session lock is released (the `with` above has exited). A
            # session that ended while this thread held it had its end
            # refused by the lock and left pending (sessions.end_session).
            # The runner's task asks for it too, in its finally, but a task
            # cancelled while this thread ran asked while the lock was still
            # held, and nothing else asks again before the TTL sweep: so the
            # thread asks once more, now that the lock is free. Harmless
            # when the task has not released its claim yet: end_session is
            # refused by the claim and the task's own call completes it.
            if session_lock is not None:
                from automated_security_helper.cli.mcp.sessions import (
                    finish_ended_session,
                )

                try:
                    finish_ended_session(session_id)
                except Exception as end_error:  # noqa: BLE001 -- the scan is over
                    # Never out of the thread: the scan ended as it ended, and
                    # an exception here would reach the runner's failure arm
                    # for a scan that has its results.
                    _logger.error(
                        f"Scan {scan_id}: could not complete the end of its "
                        f"session: {error_text(end_error, environment_values)}"
                    )

    try:
        # The run's log scope: joined from mcp_scan_directory, which opened it
        # before registering the scan, so the registration line, this runner's
        # lines, the scan's own (the executor runs it under a copy of this
        # context) and the timeout's (armed under that copy) are one run's.
        # They go only to this scan's ash.log, which takes no other run's
        # lines. Without the scope, every scan's handlers sat on the one
        # process-wide "ash" logger: a finished scan's ash.log took the next
        # scan's lines, and a scan that set up while another ran took the
        # running scan's. A caller that opened none gets one here for the same
        # isolation. Inside the try: from the RUNNING mark above, everything
        # that can raise is in it, so the entry is never left RUNNING.
        log_scope, log_scope_token = begin_run_log_scope()
        # This runner holds the scope, and so does the thread the scan runs
        # on: cancelling this task does not stop that thread, whose last lines
        # (stopping the scanner, settling the previous results) are the scan's.
        # The scope closes when the last of them lets go.
        hold_run_log_scope(log_scope)
        runner_share["held"] = True
        hold_run_log_scope(log_scope)
        thread_share["held"] = True

        if profile_to_snapshot is not None:
            # The scan takes its own server-written snapshot of the session's
            # profile -- the trusted base of a delivered config, or the
            # profile standing as the scan's own config: the values below are
            # read from the snapshot and the scan loads the snapshot, so the
            # file the redaction set saw is the file the scan runs under.
            # Without it, a select_profile rebind between this read and the
            # scan's own load (which happens after any wait for the session
            # lock) would run the scan with values the set never saw. Inside
            # the try: a runner cancelled at the await below must still
            # settle its entry (the arms below do), and its finally is then
            # what discards the copy, which nothing else removes.
            trusted_profile = profile_to_snapshot

            def _snapshot_and_read_its_values() -> Tuple[str, ...]:
                # The profile is an operator file and can read the
                # environment the way any operator file does, while a
                # delivered chain's own values are always empty (an
                # environment-reading delivered file is refused before the
                # scan starts). Its values join the redaction set here, at
                # the one place the profile is selected: the config the scan
                # itself resolves is not reachable in the failure arms below,
                # because the scan resolves it internally and a failure
                # leaves no results or config object to read. Resolved under
                # the scan's own gates, and run in a thread as
                # _config_pre_check is: file reads must not stall the event
                # loop every session's tool calls run on.
                nonlocal scan_profile_snapshot
                # Whether the scan's own config is the session's profile is a
                # file-identity read, so it is made here too. A delivered
                # config copies the profile as its trusted base whatever the
                # config names.
                if trusted_config_path is None and (
                    config_path is None
                    or _session_file_named_by(config_path, session_profile) is None
                ):
                    # The config names no file of the session's, and there is
                    # no trusted base to copy: the scan loads what it was
                    # handed, as it does with no session at all.
                    return ()
                # Recorded before the file exists -- the path is
                # deterministic -- so a runner cancelled while the copy is
                # written already holds it, and its finally discards it. A
                # refusal resets it: the helper removed anything it wrote,
                # and a name it did not create is not the runner's to
                # remove.
                # Computed once and handed on: the name embeds the host
                # identity, so a second computation could name another file
                # than the one recorded here and discarded below.
                planned_snapshot = _scan_snapshot_path(trusted_profile, scan_id)
                scan_profile_snapshot = planned_snapshot
                try:
                    snapshot = _snapshot_profile_for_scan(
                        trusted_profile, scan_id, snapshot_path=planned_snapshot
                    )
                except ProfileSnapshotUnavailable:
                    scan_profile_snapshot = None
                    raise
                if entry.runner_done.is_set():
                    # The runner ended while the copy was written: its
                    # finally may have run before the file existed, so this
                    # thread discards, and no scan follows that could want
                    # the values. The arms set runner_done before the
                    # finally runs, so one side always sees the other's
                    # work: a finally that ran first missed only a file
                    # created after it, and this check then sees
                    # runner_done; a check that saw it unset ran before the
                    # finally, which then holds the recorded path.
                    _discard_the_scans_profile_snapshot()
                    return ()
                return _profile_environment_values(snapshot, directory_path, base_gate)

            profile_values = await asyncio.to_thread(_snapshot_and_read_its_values)
            if scan_profile_snapshot is not None:
                if trusted_config_path is not None:
                    trusted_config_path = str(scan_profile_snapshot)
                else:
                    # The copy is the scan's config itself: the scan loads it
                    # where it would have loaded the live profile.
                    config_path = str(scan_profile_snapshot)
            environment_values = tuple(
                dict.fromkeys((*environment_values, *profile_values))
            )

        # Log the scan start
        _logger.info(
            f"Starting scan process for scan {scan_id} in directory {directory_path}"
        )

        loop = asyncio.get_event_loop()
        # Under a copy of this context, so the scan thread is in this run's log
        # scope, as its scanners' workers are in the scan's
        # (core/cancellation.py's note on copy_context).
        results = await loop.run_in_executor(
            None, contextvars.copy_context().run, _scan_under_session_lock
        )

        # Exit 0. The coverage facts are still recorded: with the completeness
        # gate turned off, a scan whose scanners did not run exits 0, and its
        # client is still told which ones in incomplete_scanners and
        # coverage_complete. A return that is not a results model is a test
        # double or a future return shape, and asserts no coverage.
        # What the thread worked out when it decided (settled_close), or, when it
        # did not keep the results, the same worked out here.
        status, coverage, threshold = (
            settled_close if settled_close is not None else _close_for(None, results)
        )
        registry.finish_scan(
            scan_id, status, coverage=coverage, severity_threshold=threshold
        )
        _logger.info(f"Scan {scan_id} completed successfully")

    except ScanCancelled as cancelled:
        # cancel_scan set the entry's cancel event and the scan stopped at its next
        # check: before a phase or a scanner, or while waiting on a scanner's child
        # process, which was stopped. Nothing after that point ran, so no reports and
        # no results file. The entry is already CANCELLED; finish_scan leaves a
        # closed entry alone, which keeps that status. Not re-raised: the scan
        # ended the way the client asked, and this task has nothing left to do.
        registry.finish_scan(scan_id, MCScanStatus.CANCELLED)
        # A tool the stop could not end is still running, and may write into the
        # output directory after the cancel. The exception carries which ones
        # (core/cancellation.py), and the thread that ran the scan put them on
        # the entry before it let the directory go
        # (_record_the_tools_the_stop_could_not_end); a cancelled task never
        # reaches this arm, so the thread is where the record is made. Only the
        # registry can tell the client, through the entry's warnings, because
        # the closed entry takes no other change.
        if cancelled.could_not_stop:
            _logger.warning(
                f"Scan {scan_id} was cancelled, but {len(cancelled.could_not_stop)} "
                "scanner tool(s) could not be stopped and may still be running"
            )
        _logger.info(f"Scan {scan_id} stopped after it was cancelled")

    except ScanIncompleteExit as e:
        # Exit 1 because coverage has a gap, and NOT because something broke: the
        # run finished and its results are on disk. Ahead of the SystemExit arm,
        # which it would otherwise land in as "ASH exited with code 1" -- the
        # same status a crash gets. The signal is the exception's type, raised
        # only where _compute_exit_code returned 1 with results in hand. Neither
        # the exit code nor the results file can carry it: a crash after the SCAN
        # phase also exits 1 and leaves a parseable file behind.
        #
        # The gap reported is the facts whatever the gate says, as for a
        # completed scan. The exception's own reasons are the fallback: they are
        # what the exit code was decided on, so they are never empty, and an
        # exception raised from this handler would escape the task and leave the
        # entry RUNNING. Worked out by _close_for, on the scan's thread when it
        # decided (settled_close), or here when it did not keep the results.
        status, coverage, threshold = (
            settled_close if settled_close is not None else _close_for(e, e.results)
        )
        registry.finish_scan(
            scan_id, status, coverage=coverage, severity_threshold=threshold
        )
        _logger.warning(f"Scan {scan_id} finished with incomplete coverage: {coverage}")

    except SystemExit as e:
        # run_ash_scan ends with sys.exit on a non-zero verdict and on every error
        # path it handles itself. SystemExit is not an Exception, so without this
        # arm it escaped the task and the entry stayed RUNNING for good: listed as
        # active, blocking the next scan of the same directory, never carrying the
        # failure, and -- since a RUNNING entry's runner decides its status --
        # reading as running forever. fail_on_findings=False does not make the
        # non-zero branch unreachable: the results-is-None arm of
        # _compute_exit_code runs before fail_on_findings is resolved,
        # deliberately, so an incomplete scan still exits non-zero.
        #
        # Recorded and not re-raised, unlike the BaseException arm below. This
        # coroutine is launched with a bare asyncio.create_task, and asyncio
        # re-raises a BaseException out of Task.__step into the event loop:
        # letting a SystemExit through stops the MCP server and takes every other
        # session's in-flight scan with it, while the client sees only a dropped
        # connection.
        #
        # A run ASH refused or gave up exits with ScanRefusedExit, which carries
        # what the CLI showed for it, so the client is told why as well as the
        # code; the bare exit gave only "ASH exited with code N".
        if e.code in (None, 0):
            registry.finish_scan(scan_id, MCScanStatus.COMPLETED)
            _logger.info(f"Scan {scan_id} completed successfully")
        else:
            error_message = _exit_message(e)
            # An output directory refused before the scan started says why, since
            # the client cannot read the console it was printed to, and with a
            # remedy an MCP client can act on: it has no --output-dir to pass.
            # OutputDirRefusedExit's own reason gives the command line's remedy, so
            # only the link it found is used.
            found = getattr(e, "found", None)
            reason = getattr(e, "reason", None)
            if found:
                error_message = (
                    f"{error_message}: "
                    f"{OutputDirLinkRefused(found, MCP_SCAN_OUTPUT_REMEDY)}"
                )
            elif isinstance(reason, str) and reason:
                # A refusal that carries its reason (ReportPathRefusedExit: a link
                # at a report path, or a report file name outside the reports
                # directory) says why, for the same reason.
                error_message = f"{error_message}: {reason}"
            _scan_failed(
                registry,
                scan_id,
                error_message,
                exit_code=e.code if isinstance(e.code, int) else 1,
                environment_values=environment_values,
            )

    except ProfileSnapshotUnavailable as e:
        # Fail closed: the scan never started, and the live profile is never
        # read in the copy's place -- it is the one file whose mid-wait
        # rebinds the redaction set never saw. The reason is the exception's
        # own type-only sentence, so no path, errno text, or value from the
        # file it failed to copy can ride it.
        _scan_failed(
            registry,
            scan_id,
            str(e),
            exit_code=REFUSED_INTERNAL_EXIT_CODE,
            environment_values=environment_values,
        )
        if handoff.task_abandons():
            _settle_previous_results(e)
            entry.runner_done.set()

    except Exception as e:
        # An error out of the scan's thread, or from the executor itself before
        # the thread ran: the CLI exits 1 for an error during a scan. An error
        # raised after the thread returned with results (the close of the
        # finished scan above) finds the mark set and closes the entry COMPLETED.
        _close_after_the_runner_failed(
            f"Error executing scan: {error_text(e, environment_values)}",
            exit_code=REFUSED_INTERNAL_EXIT_CODE,
        )
        if handoff.task_abandons():
            _settle_previous_results(e)
            entry.runner_done.set()

    except BaseException as e:
        # asyncio.CancelledError (server shutdown, a cancelled task) and
        # KeyboardInterrupt. The scan did not produce a verdict, so the entry is
        # closed as failed, and the exception is re-raised so cancellation still
        # propagates. Cancelling this task does not stop the executor thread, so
        # the entry's cancel event is set as well: the scan stops at its next
        # check, stops its scanner's child process, and puts the previous results
        # back on its own thread. A thread that never started cannot, so this
        # task does. The close and the event are one step under the lock the
        # thread decides under (settle_decision), so the thread's decision reads
        # the entry closed and the event set, or has been made first and the
        # entry is closed after it. A thread that decided first and marked the
        # scan as one with results (a cancellation landing while the previous
        # results are dropped) leaves a scan that has a result: the entry is
        # closed COMPLETED and the event is not set.
        _close_after_the_runner_failed(
            f"Scan task ended without a result: {type(e).__name__}",
            stop_the_scan=True,
        )
        if handoff.task_abandons():
            _settle_previous_results(e)
            entry.runner_done.set()
        raise

    finally:
        for handle in timeout_handles:
            handle.cancel()
        # After the arms above, so "completed successfully" and the failure
        # lines are this task's last lines in the scan's ash.log. A scope this
        # runner opened goes out of this context; the scope itself closes when
        # its last holder lets go.
        if log_scope_token is not None:
            disown_run_log_scope(log_scope_token)
        if handoff.task_abandons():
            # The thread never started, so it never lets go: this task
            # does for it.
            _release_the_threads_share()
        _release_the_runners_share()
        # Only once the thread is done (or never started, which sets
        # runner_done on the abandon paths above): a thread still running
        # may yet load the snapshot.
        if entry.runner_done.is_set():
            _discard_the_scans_profile_snapshot()


async def mcp_get_scan_progress(
    scan_id: str, session_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get current progress and partial results for a running scan using file-based tracking.

    This tool checks for the existence of result files to determine scan progress,
    providing a more reliable approach than event-based tracking.

    Args:
        scan_id: The scan ID returned from scan_directory
        session_id: The calling session. Another session's scan id answers
            exactly like one that was never issued. None is the default
            session, which is stdio's and an in-process caller's.

    Returns:
        Dictionary with scan progress information
    """
    from automated_security_helper.cli.mcp.sandbox import caller_is_remote
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

        # The poll reads the scan's results files, each of which must be where
        # it is named.
        entry = get_scan_registry().get_scan(
            scan_id, session_id=_scan_owner(session_id)
        )
        if entry is not None:
            output_directory = Path(entry.output_directory)
            for results_file in _result_files_in(output_directory):
                linked = _results_file_outside_its_directory(
                    results_file, "get_scan_progress", output_directory
                )
                if linked is not None:
                    return linked

        # Check scan progress using the scan management function. The entry
        # records the tools a cancel could not end with their process ids; the
        # read keeps them out of what a remote caller is told, by the same
        # request-scoped predicate the scan's own response uses.
        progress_info = await check_scan_progress(
            scan_id,
            session_id=_scan_owner(session_id),
            name_process_ids=not caller_is_remote(session_id),
        )

        # Add timestamp and operation to the response for consistency
        progress_info["timestamp"] = datetime.now().isoformat()
        progress_info["operation"] = "get_scan_progress"

        return _error_message_shown(progress_info)

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
        log_unexpected_error(_logger, e, "Unexpected error getting scan progress")
        return create_error_response(
            error=MCPResourceError(
                f"Unexpected error getting scan progress: {error_text(e)}",
                context={
                    "scan_id": scan_id,
                    "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                    "error_type": type(e).__name__,
                    "error_message": error_text(e),
                },
            ),
            operation="get_scan_progress",
        )


async def mcp_get_scan_results(
    output_dir: str, session_id: Optional[str] = None, include_sarif: bool = False
) -> Dict[str, Any]:
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
        include_sarif: Also return the scan's SARIF under
            ``raw_results["sarif"]``; see ``scan_tracking.get_scan_results``.

    Returns:
        Dictionary with scan results information
    """
    from automated_security_helper.cli.mcp.scan_target import (
        ASH_MCP_ALLOWED_ROOTS_ENV,
        validate_scan_target,
    )
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

        # Results are read from a caller-named directory, so the same roots that
        # bound what may be scanned bound what may be read back. A legitimate
        # output directory sits at <source_dir>/.ash/ash_output, beneath the scan
        # target, so a root that permits the scan permits its results too.
        #
        # The session id matters here for the same reason it does on the scan: a
        # delivered tree's output lands inside this session's sandbox, which no
        # operator grant names, so without it a client is refused the results of a
        # scan it was permitted to run.
        target_error = validate_scan_target(resolved_output_dir, session_id=session_id)
        if target_error:
            return create_error_response(
                error=target_error,
                operation="get_scan_results",
                suggestions=[
                    (
                        f"Add the directory to {ASH_MCP_ALLOWED_ROOTS_ENV} if the "
                        "MCP server should be able to read results from it"
                    ),
                    "Verify that the path is correct",
                ],
            )

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

        linked = _results_file_outside_its_directory(
            resolved_output_dir / "ash_aggregated_results.json", "get_scan_results"
        )
        if linked is not None:
            return linked

        # Get scan results with error handling
        results = get_scan_results_with_error_handling(
            resolved_output_dir, include_sarif=include_sarif
        )

        # Add timestamp and operation to the response for consistency
        if isinstance(results, dict):
            if "timestamp" not in results:
                results["timestamp"] = datetime.now().isoformat()
            results["operation"] = "get_scan_results"

        return results

    except Exception as e:
        # Handle unexpected errors
        log_unexpected_error(_logger, e, "Unexpected error getting scan results")
        return create_error_response(
            error=MCPResourceError(
                f"Unexpected error getting scan results: {error_text(e)}",
                context={
                    # "scan_id": scan_id,
                    "cwd": str(Path.cwd()),
                    "output_dir": output_dir,
                    "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                    "error_type": type(e).__name__,
                    "error_message": error_text(e),
                },
            ),
            operation="get_scan_results",
        )


def _error_message_shown(reply: Dict[str, Any]) -> Dict[str, Any]:
    """*reply*, a scan's progress or registry entry, with its "error_message"
    shown for the client that reads it: on one line, each control as its escape.

    The registry keeps the message as raised, so the ASH log that quotes it shows
    it once; the reply is a copy, and the registry's own dict is left as it is.
    """
    message = reply.get("error_message")
    if not isinstance(message, str):
        return reply
    return {**reply, "error_message": raw_controls_on_one_line(message)}


async def mcp_list_active_scans(session_id: Optional[str] = None) -> Dict[str, Any]:
    """
    List the calling session's active and recent scans with their current status.

    This tool uses the scan registry to list all active and recent scans,
    providing more reliable information than event-based tracking.

    Args:
        session_id: The calling session. Only its own scans are listed, and the
            statistics count only those, so nothing in the response shows that
            another session exists. None is the default session.

    Returns:
        Dictionary with information about the session's scans in the registry
    """
    owner = _scan_owner(session_id)
    try:
        # Get active scans from the scan management function
        active_scans = await list_active_scans(session_id=owner)

        # Get all scans (including completed ones)
        registry = get_scan_registry()
        all_scans = registry.list_scans(session_id=owner)

        # Get scan statistics
        stats = {
            "total_scans": registry.get_scan_count(session_id=owner),
            "active_scans": registry.get_active_scan_count(session_id=owner),
            "status_counts": registry.get_scan_status_counts(session_id=owner),
        }

        # Return standardized successful response
        return {
            "success": True,
            "active_scans": [_error_message_shown(scan) for scan in active_scans],
            "all_scans": [_error_message_shown(scan) for scan in all_scans],
            "stats": stats,
            "timestamp": datetime.now().isoformat(),
            "operation": "list_active_scans",
        }

    except Exception as e:
        # Handle unexpected errors
        log_unexpected_error(_logger, e, "Unexpected error listing active scans")
        return create_error_response(
            error=MCPResourceError(
                f"Unexpected error listing active scans: {error_text(e)}",
                context={
                    "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                    "error_type": type(e).__name__,
                    "error_message": error_text(e),
                },
            ),
            operation="list_active_scans",
        )


async def mcp_cancel_scan(
    scan_id: str, session_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Cancel a running scan and clean up its resources using file-based tracking.

    This tool uses the scan registry to cancel a scan and clean up its resources,
    providing a more reliable approach than event-based tracking.

    Args:
        scan_id: The scan ID to cancel
        session_id: The calling session. Another session's scan id answers
            exactly like one that was never issued, and nothing is cancelled.

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
        result = await cancel_scan(scan_id, session_id=_scan_owner(session_id))

        # Add timestamp and operation to the response for consistency
        if isinstance(result, dict):
            if "timestamp" not in result:
                result["timestamp"] = datetime.now().isoformat()
            if "operation" not in result:
                result["operation"] = "cancel_scan"

        return result

    except Exception as e:
        # Handle unexpected errors
        log_unexpected_error(_logger, e, "Unexpected error cancelling scan")
        return create_error_response(
            error=MCPResourceError(
                f"Unexpected error cancelling scan: {error_text(e)}",
                context={
                    "scan_id": scan_id,
                    "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                    "error_type": type(e).__name__,
                    "error_message": error_text(e),
                },
            ),
            operation="cancel_scan",
        )


def _builtin_scanner_classes() -> list:
    """The scanners ASH ships in ash_builtin: the set a default scan runs.

    Not ``_loaded_scanner_classes``, which list_scanners uses: that also imports
    the community plugin packages and every installed ``ash_*_plugins``
    distribution, and an installation check has no reason to run their code.
    """
    from automated_security_helper.plugin_modules.ash_builtin import ASH_SCANNERS

    return list(ASH_SCANNERS)


async def mcp_check_installation(session_id: Optional[str] = None) -> Dict[str, Any]:
    """Report whether ASH can scan, from the scanners' own dependency checks.

    Each built-in scanner is asked whether its dependencies are satisfied, by the
    same check list_scanners
    reports and a scan runs before it starts a scanner, in check-only mode
    (``list_scanner_inventory``): nothing is installed or downloaded.

    Returns:
        Dictionary with:
          installed: ASH is installed and at least one enabled built-in scanner
            can run, or will once the first scan installs its tool. False means
            a scan would run nothing.
          ready: every enabled built-in scanner can run, or the first scan
            installs its tool, so a default scan is complete. False names the
            gaps in missing_dependencies and undetermined_dependencies.
          version: ASH's version.
          scanners: each built-in scanner's name, enabled, dependencies_satisfied
            (True, False, or None when it could not be determined) and version.
          missing_dependencies: enabled scanners whose dependencies are missing
            and that a scan cannot install.
          installs_on_first_scan: enabled scanners whose tool is not installed
            yet, which the first scan installs with uv (needs network access).
          undetermined_dependencies: enabled scanners whose check could not run.
          ash_command_available: whether an ``ash`` executable is on PATH. The
            server scans in-process and does not need one.
          ash_command_output: that executable's path, or why there is none. The
            path only for the client that launched the server (stdio); a remote
            caller (``sandbox.caller_is_remote``) is told only whether there is
            one, because the path is the server's filesystem layout.

    Args:
        session_id: The session this call acts for, which decides whether the
            caller is remote.
    """
    import shutil

    from automated_security_helper.cli.mcp.sandbox import caller_is_remote

    try:
        version = get_ash_version()
        # Installs nothing: the inventory runs the checks in check-only mode.
        inventory = await asyncio.to_thread(
            list_scanner_inventory, _builtin_scanner_classes, concurrent=True
        )
        scanners = [
            {
                "name": entry["name"],
                "enabled": entry["enabled"],
                "dependencies_satisfied": entry["dependencies_satisfied"],
                "installs_on_first_scan": entry["installs_on_first_scan"],
                "version": entry["version"],
            }
            for entry in inventory
        ]
        enabled = [s for s in scanners if s["enabled"]]
        first_scan = sorted(s["name"] for s in enabled if s["installs_on_first_scan"])
        missing = sorted(
            s["name"]
            for s in enabled
            if s["dependencies_satisfied"] is False and not s["installs_on_first_scan"]
        )
        undetermined = sorted(
            s["name"] for s in enabled if s["dependencies_satisfied"] is None
        )
        runnable = [
            s
            for s in enabled
            if s["dependencies_satisfied"] is True or s["installs_on_first_scan"]
        ]
        ash_command = shutil.which("ash")
        if ash_command is None:
            ash_command_output = "no ash executable on PATH"
        elif caller_is_remote(session_id):
            ash_command_output = "an ash executable is on the server's PATH"
        else:
            ash_command_output = ash_command

        return {
            "success": True,
            "installed": version not in (None, "unknown") and bool(runnable),
            "ready": bool(enabled) and not missing and not undetermined,
            "version": version,
            "scanners": scanners,
            "missing_dependencies": missing,
            "installs_on_first_scan": first_scan,
            "undetermined_dependencies": undetermined,
            "ash_command_available": ash_command is not None,
            "ash_command_output": ash_command_output,
            "timestamp": datetime.now().isoformat(),
        }

    except Exception as e:
        # Handle unexpected errors
        log_unexpected_error(_logger, e, "Unexpected error checking installation")
        return create_error_response(
            error=MCPResourceError(
                f"Unexpected error checking installation: {error_text(e)}",
                context={
                    "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                    "error_type": type(e).__name__,
                    "error_message": error_text(e),
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


def _load_flat_vulns_for_explain(
    results_path: Optional[str], *, results_dir: Optional[Path] = None
) -> list:
    """Load FlatVulnerability list from an ash_aggregated_results.json directory.

    ``results_dir`` is the output directory the caller already derived from
    ``results_path`` and checked (``mcp_explain_finding``: against the roots, the
    restored marker and a link out of the directory); given, it is read as is,
    so the directory read is the one checked, and ``is_dir`` is never asked a
    second time for an answer that can differ from the first. Without it the
    directory is derived here: ``results_path`` itself when it is a directory,
    else its parent, and the working directory's ``.ash/ash_output`` for None.
    """
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    if results_dir is not None:
        output_dir = results_dir
    elif results_path is None:
        output_dir = Path.cwd() / ".ash" / "ash_output"
    else:
        candidate = Path(results_path)
        output_dir = candidate if candidate.is_dir() else candidate.parent

    agg_file = output_dir / "ash_aggregated_results.json"
    if not agg_file.exists():
        raise FileNotFoundError(f"Results file not found: {agg_file}")
    # ASH writes its results files as UTF-8; the locale default is cp1252 on
    # Windows, which cannot decode every byte they hold.
    model = AshAggregatedResults.from_json(agg_file.read_text(encoding="utf-8"))
    return model.to_flat_vulnerabilities()


def mcp_explain_finding(
    finding_id: str,
    results_path: Optional[str] = None,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Return structured details for a single finding by ID.

    Purely a structured lookup — no LLM calls are made.

    Args:
        finding_id: The FlatVulnerability.id to look up.
        results_path: Optional path to the output directory (or file inside it)
                      containing ash_aggregated_results.json. Defaults to
                      <cwd>/.ash/ash_output.
        session_id: The MCP session this call acts for.

    Returns:
        Dict with ``success`` and ``finding`` keys on success, or
        ``success: False`` with an ``error`` key when the ID is not found.
    """
    import json as _json

    from automated_security_helper.cli.mcp.scan_target import (
        ASH_MCP_ALLOWED_ROOTS_ENV,
        validate_scan_target,
    )

    # Same roots as the other results readers: this reads
    # ash_aggregated_results.json out of a caller-named output directory. The
    # directory is derived from results_path once, here, and handed to
    # _load_flat_vulns_for_explain, so the directory checked below (roots,
    # restored marker, a link out of it) is the directory read: a second
    # derivation there asked is_dir again, and a path whose answer changed in
    # between (a directory removed or made) read one the checks never saw.
    if results_path is None:
        _results_dir = Path.cwd() / ".ash" / "ash_output"
    else:
        _candidate = Path(results_path)
        _results_dir = _candidate if _candidate.is_dir() else _candidate.parent
    target_error = validate_scan_target(_results_dir, session_id=session_id)
    if target_error:
        return create_error_response(
            error=target_error,
            operation="explain_finding",
            suggestions=[
                (
                    f"Add the directory to {ASH_MCP_ALLOWED_ROOTS_ENV} if the "
                    "MCP server should be able to read results from it"
                ),
                "Verify that the path is correct",
            ],
        )
    restored = restored_results_refusal(_results_dir, "explain_finding")
    if restored is not None:
        return restored
    linked = _results_file_outside_its_directory(
        _results_dir / "ash_aggregated_results.json", "explain_finding"
    )
    if linked is not None:
        return linked

    try:
        flat_vulns = _load_flat_vulns_for_explain(
            results_path, results_dir=_results_dir
        )
    except Exception as e:
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"Failed to load scan results: {error_text(e)}"
            ),
            "operation": "explain_finding",
        }

    match = next((v for v in flat_vulns if v.id == finding_id), None)
    if match is None:
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"Finding '{finding_id}' not found in scan results"
            ),
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


def _results_file_outside_its_directory(
    results_file: Path, operation: str, output_dir: Optional[Path] = None
) -> Optional[Dict[str, Any]]:
    """Refuse a results file that leads out of the directory it is named in.

    The results readers check the directory, or the path they are given, against
    the session's roots, and the file there would then be read wherever it led: a
    link to another tree's results would be answered as this directory's. A
    results file is read only when it resolves to a file inside its own directory.
    When ``output_dir`` is given (for a file below it, such as a scanner's
    results), the path must also lead to somewhere inside that directory, whether
    or not anything is there: a linked directory on the way to the file cannot
    lead out either, and a path through one is refused whether the file it leads
    to exists or not. A link elsewhere and a link to a file that is not there are
    refused alike, so the answer says nothing about where the link leads, and the
    message names the file as the caller gave it. None when there is nothing at
    the path and the path stays in its directory, which each reader reports as it
    always has, or when the file is where it says.

    The one check for every reader: get_scan_results, explain_finding,
    suggest_suppression, diff_scan_results, get_scan_progress and
    get_scan_result_paths.
    """
    directory = results_file.parent if output_dir is None else output_dir
    try:
        # Not strict: a link to nothing still resolves to where it points.
        stays_in = results_file.resolve().is_relative_to(directory.resolve())
    except (OSError, RuntimeError):
        stays_in = False
    if stays_in and not os.path.lexists(results_file):
        return None
    try:
        resolved = results_file.resolve(strict=True)
        inside = (
            stays_in
            and resolved.is_file()
            and resolved.is_relative_to(results_file.parent.resolve(strict=True))
            and resolved.is_relative_to(directory.resolve(strict=True))
        )
    except (OSError, RuntimeError):
        inside = False
    if inside:
        return None
    try:
        name = results_file.relative_to(directory).as_posix()
    except ValueError:
        name = results_file.name
    return create_error_response(
        error=MCPResourceError(
            f"The results file '{name}' in '{directory}' does not "
            "resolve to a file in that directory, so it was not read.",
            context={
                "results_file": str(results_file),
                "error_category": ErrorCategory.INVALID_PATH.value,
            },
        ),
        operation=operation,
        suggestions=[
            "Read the results from the output directory the scan wrote them to",
            "Replace the link with the results file itself",
        ],
    )


def _result_files_in(output_dir: Path) -> List[Path]:
    """Every results file a progress poll of ``output_dir`` reads, as named there.

    The aggregated results, and each scanner's ``ASH.ScanResults.json`` under
    ``scanners/<scanner>/<target>/``, found by the entry itself, so a link to a
    file that is not there is listed too. The scanners directory, a scanner's and
    a target's are followed only when they resolve to a directory inside
    ``output_dir``, as the poll itself follows them
    (``scan_tracking.resolves_to_directory_inside``).
    """
    files = [output_dir / "ash_aggregated_results.json"]
    scanners_dir = output_dir / "scanners"
    if resolves_to_directory_inside(scanners_dir, output_dir):
        for scanner_dir in _entries_of(scanners_dir):
            if not resolves_to_directory_inside(scanner_dir, output_dir):
                continue
            for target_dir in _entries_of(scanner_dir):
                if resolves_to_directory_inside(target_dir, output_dir):
                    files.append(target_dir / "ASH.ScanResults.json")
    return files


def _entries_of(directory: Path) -> List[Path]:
    """``directory``'s entries, sorted; none when it cannot be listed.

    A poll lists the directories of a scan that is running, or whose
    clean_output is setting the previous results aside: one checked a moment
    ago can be renamed aside or removed before it is listed, and the
    ``FileNotFoundError`` (or ``NotADirectoryError``) that raised then turned
    the poll into an unexpected-error reply. A directory that is gone holds no
    results file to check, so it lists as empty, and the poll goes on.
    """
    try:
        return sorted(directory.iterdir())
    except OSError:
        return []


def _refuse_results_file(
    path: Path, operation: str, session_id: Optional[str]
) -> Optional[Dict[str, Any]]:
    """Check a caller-named results file against the scan roots, as a results dir is.

    Before the existence check, so a refused path is reported as refused rather
    than as missing. A permitted file in a directory whose last scan had the
    previous results put back is refused as not complete
    (scan_tracking.restored_results_refusal).

    The directory the file is named in is what is checked against the roots, and
    the file then against that directory (_results_file_outside_its_directory),
    which together hold it inside the roots. Checking the file's own path
    followed it when it was a link, and the roots' refusal of it carried the
    path the link resolves to.
    """
    from automated_security_helper.cli.mcp.scan_target import (
        ASH_MCP_ALLOWED_ROOTS_ENV,
        validate_scan_target,
    )

    target_error = validate_scan_target(path.parent, session_id=session_id)
    if target_error is None:
        # A results file beside the marker is the scan before the last one's.
        return restored_results_refusal(
            path.parent, operation
        ) or _results_file_outside_its_directory(path, operation)
    return create_error_response(
        error=target_error,
        operation=operation,
        suggestions=[
            (
                f"Add the directory to {ASH_MCP_ALLOWED_ROOTS_ENV} if the MCP "
                "server should be able to read results from it"
            ),
            "Verify that the path is correct",
        ],
    )


def mcp_diff_scan_results(
    before_path: str, after_path: str, session_id: Optional[str] = None
) -> Dict[str, Any]:
    """Compare two ash_aggregated_results.json files and return a structured diff.

    Args:
        before_path: Path to the baseline ash_aggregated_results.json file.
        after_path: Path to the comparison ash_aggregated_results.json file.
        session_id: The MCP session this call acts for.

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

    for candidate in (before_file, after_file):
        refusal = _refuse_results_file(candidate, "diff_scan_results", session_id)
        if refusal is not None:
            return refusal

    if not before_file.exists():
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"before_path does not exist: {before_path}"
            ),
        }
    if not after_file.exists():
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"after_path does not exist: {after_path}"
            ),
        }

    try:
        # ASH writes its results files as UTF-8; the locale default is cp1252 on
        # Windows, which cannot decode every byte they hold.
        before_results = AshAggregatedResults.from_json(
            before_file.read_text(encoding="utf-8")
        )
        after_results = AshAggregatedResults.from_json(
            after_file.read_text(encoding="utf-8")
        )
    except Exception as e:
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"Failed to parse result file: {error_text(e)}"
            ),
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
                {
                    "id": vid,
                    "before_severity": b_sev or None,
                    "after_severity": a_sev or None,
                }
            )

    return {"new": new, "resolved": resolved, "severity_changed": severity_changed}


# ---------------------------------------------------------------------------
# Scanner inventory (issues #606, #626).
#
# The probe logic that describes each scanner -- its detected version, whether
# its dependencies are satisfied, its offline strategy, and whether it is enabled
# -- now lives in ``automated_security_helper.core.scanner_inventory`` so the MCP
# ``list_scanners`` tool and the ``ash plugin list`` CLI command call one path and
# cannot drift (the drift risk #626 calls out). These names are re-exported here
# because existing tests import them from this module and monkeypatch
# ``mcp_tools._loaded_scanner_classes`` by name; keeping them as module attributes
# preserves both.
# ---------------------------------------------------------------------------
from automated_security_helper.core.scanner_inventory import (  # noqa: E402
    _ABSENT_VERSION_MARKERS,
    _VENDORED_SCANNER_PLUGIN_PACKAGES,
    _declared_config_class,
    _discover_external_scanner_plugin_packages,
    _loaded_scanner_classes,
    _normalized_version,
    _scanner_name_from_class,
    describe_scanner as _describe_scanner,
    list_scanner_inventory,
)

# Re-exported so existing imports/patches keep resolving; silence "imported but
# unused" for the ones this module does not itself reference.
__all_scanner_inventory_reexports__ = (
    _ABSENT_VERSION_MARKERS,
    _VENDORED_SCANNER_PLUGIN_PACKAGES,
    _declared_config_class,
    _discover_external_scanner_plugin_packages,
    _normalized_version,
    _scanner_name_from_class,
    _describe_scanner,
)


def mcp_list_scanners() -> list:
    """Return per-scanner metadata for all registered ASH scanners.

    Thin wrapper over
    :func:`automated_security_helper.core.scanner_inventory.list_scanner_inventory`.
    It passes this module's own ``_loaded_scanner_classes`` so that tests which
    ``monkeypatch.setattr("...mcp_tools._loaded_scanner_classes", ...)`` continue
    to intercept the scanner set the inventory describes.

    Each entry contains:
      name: scanner config name, snake_cased (e.g. "bandit", "cdk_nag")
      version: detected version string, or None when the scanner reports none
      dependencies_satisfied: True, False, or None when it could not be determined
      offline_strategy: OfflineStrategy enum value string
      enabled: whether the scanner is enabled in the default config
    """
    return list_scanner_inventory(scanner_classes_provider=_loaded_scanner_classes)


#: What raw get_config puts before a value ASH's loader takes from the
#: environment, so a client can tell it from a string that only looks like one.
ENV_VALUE_PREFIX = "!ENV "


class _HeldConfigFiles(contextlib.ExitStack):
    """The config files one ``get_config`` call holds open, closed when it ends.

    The grant check opens the file it judges
    (``config_sources.open_config_for_judgment``) and the call keeps that
    descriptor until it has answered: the read is held to its (device, inode), and
    the descriptor keeps the inode in use, so a file made later cannot be given
    the same number. ``files`` finds a held file by that identity.
    """

    def __init__(self) -> None:
        super().__init__()
        self.files: Dict[Tuple[int, int], "OpenedConfig"] = {}

    def keep(self, opened: "OpenedConfig") -> None:
        self.files[opened.identity] = opened
        self.callback(opened.close)


def _check_and_identify_config(
    config_path: Any,
    session_id: Optional[str],
    held: Optional[_HeldConfigFiles] = None,
) -> Tuple[Optional[MCPResourceError], Optional[Tuple[int, int]]]:
    """The grant check of ``config_path`` (``sandbox.validate_config_input``) and
    the identity ``(device, inode)`` the read that follows is held to.

    The file is opened first and the check judges the path the descriptor leads
    to, which is the path of the file the read will use, and not the path the
    name resolves to a moment later: a name that changes between a resolution and
    the identity read would have the check judge one file and the read open
    another. The identity is the descriptor's. With ``held`` the descriptor stays
    open until the call that owns it ends, so the read can take the bytes from it
    (``read_opened_config_bytes``) and the inode stays in use.

    The identity is compared with three others to be returned: the file the name
    led to before the open, the file the check approved (it reports the identity
    of the path it judged), and the file the name leads to after. They are one file
    when nothing changed. A name that led to a file, then to another while the
    check ran, then back, disagrees with itself in one of them. A name that
    cannot be opened as a regular file (absent, a directory, a FIFO) is judged
    as it always was, by the identity of the name before and after the check.

    When they disagree the identity is None and the caller refuses a read of a
    file then: the name led somewhere else around the check, so nothing can be
    held to. A name that led nowhere gives ``ABSENT_FILE`` (``identity_to_hold``)
    in all three, and the read is held to it like to any identity, so a file made
    at the name since is refused as one that was not there when the check
    approved it. A check that records no identity (only a stand-in for the real
    check does not) is judged by the identity before and after it.
    """
    from automated_security_helper.cli.mcp.sandbox import validate_config_input
    from automated_security_helper.config.config_sources import (
        ABSENT_FILE,
        identity_to_hold,
        open_config_for_judgment,
    )

    name = Path(config_path)
    before = identity_to_hold(name)
    opened = open_config_for_judgment(name)
    kept = False
    try:
        judged_path: Dict[str, Any] = {}
        if opened is not None:
            if opened.real is None or opened.identity != before:
                # The path the descriptor leads to cannot be told, or the name
                # led elsewhere between the first look and the open.
                return None, None
            judged_path["resolved"] = opened.real
        approved: List[Optional[Tuple[int, int]]] = []
        refusal = validate_config_input(
            config_path, session_id=session_id, identity_out=approved, **judged_path
        )
        if refusal is not None:
            return refusal, None
        after = identity_to_hold(name)
        judged = approved[0] if approved else before
        if judged is None:
            # The approved path led nowhere.
            judged = ABSENT_FILE
        if before != judged or before != after:
            return None, None
        if opened is not None and held is not None:
            held.keep(opened)
            kept = True
        return None, before
    finally:
        if opened is not None and not kept:
            opened.close()


def _config_as_written(
    path: Path,
    expect: Optional[Tuple[int, int]] = None,
    content: Optional[bytes] = None,
) -> Any:
    """A config file's content, parsed without reading the environment.

    ``expect`` is the file's ``identity_to_hold`` as the caller took it when it
    checked the path: the file is read only if it is still that file, and one
    swapped in after the check is refused (OSError, ESTALE).

    ``content`` is the file's bytes when the caller already took them from the
    descriptor of the file it checked (``config_sources.read_opened_config_bytes``):
    nothing is then opened by name for the read. Either way the bytes are read
    once, and a refusal is made of them.

    Each value a load would take from the environment is returned as
    ``ENV_VALUE_PREFIX`` followed by the reference as the file writes it: an
    ``!ENV`` scalar; a plain YAML scalar shaped like ``${VAR:default}``, which
    the loader tags ``!ENV`` implicitly; and a TOML string starting with ``${``.
    A quoted YAML string shaped like a reference is a literal to the loader
    (implicit tags apply only to plain scalars) and comes back as written. Without
    the prefix the two came back the same, and a client could not tell
    ``!ENV ${VAR:d}`` from the literal ``"${VAR:d}"``.

    Otherwise this is what the loader returns: a ``pyproject.toml`` yields its
    ``[tool.ash]`` table, with the loader's errors for a file that is not valid
    TOML or has no such table.
    """
    import json as _json

    import yaml as _yaml

    from automated_security_helper.config.ash_config import ENV_REFERENCE_PATTERN
    from automated_security_helper.config import config_sources

    def contents() -> bytes:
        # The bytes the caller took from the descriptor of the file it checked,
        # when it did; otherwise the file the name leads to, read only if it is
        # still the one that was checked.
        if content is not None:
            return content
        return config_sources.read_config_bytes(path, expect=expect)

    # The format comes from the suffix in either case, as the loader takes it.
    if config_sources.is_json_file(path):
        # utf-8-sig, as the loader reads a JSON config: a leading byte order
        # mark is dropped, as it is for YAML and TOML (Windows PowerShell 5
        # writes one), so a file the resolved read loads is not refused here.
        return _json.loads(contents().decode("utf-8-sig"))
    if config_sources.is_toml_file(path):
        # One read. The bytes this branch holds (the descriptor's, or one read
        # of the name held to its identity) are the whole of what it judges:
        # every refusal below is made of that text, in the loader's own words,
        # so a file rewritten in place after the read cannot turn a refusal
        # into an answer. The loader resolves every ${VAR} it reads, and the
        # answer here never holds a value read from the environment.
        return _mark_toml_references(
            config_sources.toml_config_table(
                path, config_sources.toml_text_of(path, contents())
            )
        )

    from automated_security_helper.utils.yaml_aliases import NoRecursiveAliasLoader

    # A recursive alias is refused while the document is composed
    # (utils/yaml_aliases.py): built, the document contains itself, the
    # caller's handler sees no error, and the MCP transport cannot serialize
    # the answer, a transport failure in place of this tool's own refusal.
    class _AsWrittenLoader(NoRecursiveAliasLoader):
        pass

    # The loader's two rules (ash_config.load_yaml_config): a plain scalar shaped
    # like a reference is tagged !ENV, and every !ENV scalar is read from the
    # environment. Here the tagged value is marked instead of read.
    _AsWrittenLoader.add_implicit_resolver("!ENV", ENV_REFERENCE_PATTERN, None)

    def _marked_reference(loader: _yaml.SafeLoader, node: _yaml.Node) -> str:
        # Any node written with !ENV reaches here. construct_scalar takes a
        # scalar, or a mapping with a "=" key, and refuses anything else with the
        # loader's ConstructorError, as the loader's own constructor does; the
        # cast names what it takes and checks nothing.
        return ENV_VALUE_PREFIX + loader.construct_scalar(
            cast(Union[_yaml.ScalarNode, _yaml.MappingNode], node)
        )

    _AsWrittenLoader.add_constructor("!ENV", _marked_reference)
    text = contents().decode("utf-8")
    # A stream named for the file, as every other parse of read text is
    # (config_sources.named_text_stream): a YAML error then names the file and
    # the position, and not "<unicode string>" followed by a copy of the
    # offending line.
    loader = _AsWrittenLoader(config_sources.named_text_stream(text, path))
    try:
        document = loader.get_single_data()
    finally:
        loader.dispose()
    # The answer is the parsed document, and the transport writes out each
    # place a shared node is reachable from. The chain's budgets apply here
    # too (config_sources.refuse_past_expansion_bound): every place against
    # the place bound and every string's length against the text budget,
    # charged without a rebuild. The refusal opens with the file's name, so
    # _config_load_failure's frame leaves its own copy out and the message
    # names the file once.
    config_sources.refuse_past_expansion_bound(
        document, config_sources.describe_config_path(path)
    )
    return document


def _document_kind(document: Any) -> str:
    """How a refusal names a parsed document that is not a mapping, by kind."""
    if isinstance(document, list):
        return "a list"
    if isinstance(document, bool):
        return "a boolean"
    if isinstance(document, (int, float)):
        return "a number"
    if isinstance(document, str):
        return "a string"
    return f"a {type(document).__name__}"


def _mark_toml_references(value: Any) -> Any:
    """The TOML document with each string the loader resolves marked as such.

    By the loader's own rule (config_sources._resolve_toml_env): a string that
    starts with a ``${VAR:default}`` reference.
    """
    from automated_security_helper.config.ash_config import ENV_REFERENCE_PATTERN

    if isinstance(value, dict):
        return {k: _mark_toml_references(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_mark_toml_references(v) for v in value]
    if isinstance(value, str) and ENV_REFERENCE_PATTERN.match(value):
        return ENV_VALUE_PREFIX + value
    return value


def mcp_get_config(
    config_path: Optional[str] = None,
    raw: bool = False,
    search_dir: Optional[str] = None,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Return the resolved ASH config (or raw file contents if raw=True).

    Args:
        config_path: Explicit path to config file. If None, auto-discovers.
        raw: If True, returns the file's contents as written, without merging
            defaults and without reading the environment: a value the loader
            would read from the environment is returned as ``!ENV `` and the
            reference (see _config_as_written).
        search_dir: The directory the caller's scan will target. When
            config_path is None, where discovery searches (defaults to the
            working directory). With a named config_path, the target the
            whole answer is judged for -- the file's plugin modules, the
            ``sandbox`` section shown, and which chain files count as the
            scanned repository's own -- so the answer refuses exactly what
            a scan of that target refuses; without it, the session's
            delivered source stands in, or the working directory for the
            local client, whose own tree it is. A network session that
            delivered nothing names no target a scan of it could take, so
            a file of the client's (named outside every granted config
            root) is judged for no scanned tree (the file confined by its
            own root, no checkout's operator-only options read), which
            leaves out more than a scan would, never less; a file the
            operator granted keeps the working-directory judgment, under
            which its ``ash_plugin_modules`` entries are kept and judged,
            so a module every scan refuses refuses this answer too instead
            of being dropped by the no-tree confinement.
            A given search_dir crosses the scan tool's own root gate, so a
            directory this session may not scan is refused as a scan of it
            is (``scan_target_not_permitted``, exit 4), before anything
            reads it.
        session_id: The MCP session this call acts for. The named or discovered
            file, and every base it extends, must be readable as a config input
            for it; see ``cli/mcp/sandbox.validate_config_input``.

    Returns:
        Dict representation of the resolved AshConfig, or raw YAML dict if raw=True.
        Its ``sandbox`` section is the one a scan of the answered target --
        ``search_dir`` when given, else this session's default target -- would
        apply, so a file the client delivered shows no grants of its own. The reporter options only the operator may set
        (``config/operator_only_options.py``) that a file in a checkout sets are
        shown as a scan of that checkout applies them, ignored:
        ``<operator only; ignored from this file: VALUE>``. A refused path
        returns ``success`` False with ``error_type``
        ``config_input_not_permitted``, and a file a client delivered that
        reads from the environment the same with ``config_env_not_resolved``.
        A resolved config whose ``ash_plugin_modules`` a scan of the answered
        target refuses (a module outside the plugin namespace, or one no
        installed package provides) is refused as ``ash config get`` refuses
        it, ``success`` False with exit code 3, ``error_type``
        ``plugin_module_refused`` and this surface's closing, rather than
        shown as a configuration such a scan would use. The list judged is
        the one that scan imports: entries its trust confinement drops never
        refuse, ``ASH_PLUGIN_MODULES`` -- the CLI scan option's variable,
        which no MCP scan reads -- is never judged here, and ``raw`` mode
        never judges at all: it asks for a document, not a run.
        A named file that does not exist, and a named or discovered file that
        cannot be loaded, return ``success`` False with ``error_category``
        ``file_not_found`` or ``invalid_format``; the default config is
        returned only when no file is named or found.
    """

    # The files the grant check opens stay open until the answer is made.
    with _HeldConfigFiles() as held:
        return _answer_get_config(config_path, raw, search_dir, session_id, held)


def _answer_get_config(
    config_path: Optional[str],
    raw: bool,
    search_dir: Optional[str],
    session_id: Optional[str],
    held: _HeldConfigFiles,
) -> Dict[str, Any]:
    """The answer of ``mcp_get_config``, with the config files its grant check
    opened held in ``held`` until the caller leaves."""

    import yaml

    # The same judgment `ash config get` makes of the ash_plugin_modules list
    # a scan would import, through the same builder, so the two surfaces
    # cannot drift apart on the shared half; the closing is this surface's
    # own (_MCP_PLUGIN_MODULE_CLOSINGS).
    from automated_security_helper.config.plugin_module_trust import (
        plugin_module_refusal_message,
        refuse_plugin_modules_a_scan_refuses,
    )
    from automated_security_helper.cli.mcp.profile_registry import (
        DEFAULT_SESSION_ID,
        resolve_session_trusted_config_path,
    )
    from automated_security_helper.cli.mcp.sandbox import (
        caller_is_remote,
        config_base_gate,
        config_chain_refusal,
        client_named_config_is_untrusted,
        config_is_client_supplied,
        validate_config_input,
        validate_discovered_config,
    )
    from automated_security_helper.cli.mcp.source_delivery import (
        get_session_source_dir,
    )
    from automated_security_helper.config.resolve_config import (
        resolve_config,
        find_config_file,
    )
    from automated_security_helper.config.config_sources import (
        ConfigFileChangedError,
        default_confinement_root,
    )
    from automated_security_helper.config.environment_record import (
        environment_marker,
        record_environment_references,
    )
    from automated_security_helper.config.operator_only_options import (
        RepositorySettings,
        mark_operator_only_options,
        repository_settings_for_root,
    )
    from automated_security_helper.config.sandbox_grants import (
        files_inside,
        in_a_checkout,
        working_directory,
    )
    from automated_security_helper.config.default_config import (
        get_default_config,
    )
    from automated_security_helper.core.exceptions import (
        ASHConfigFieldDeniedError,
        ASHConfigEnvNotResolvedError,
        ASHConfigInputNotPermittedError,
        ASHConfigPolicyUnreadableError,
        ASHConfigSourceError,
        ASHConfigValidationError,
    )
    from automated_security_helper.plugins.loader import PluginModuleError

    # A value a config file read from the environment is the server's, so it is
    # shown as `<from ${VAR}>`, never as the value, at its own place
    # (AshConfig._displayed_environment_references, the reads the merged
    # document still shows; a read an overlay wrote a literal over marks
    # nothing, since that place's value is the overlay's own), whatever its
    # length; text elsewhere that equals it is the file's own and is shown. A
    # list entry is the one at the index the file wrote the reference at: in a
    # session config, the index the profile's patch moved it to. Any other entry
    # of that list, one a client added say, is shown as written whatever it holds.
    def shown_config(config: Any, data: Any) -> Any:
        return record_environment_references(
            data,
            tuple(getattr(config, "_displayed_environment_references", ()) or ()),
            mark=environment_marker,
            exact_indices=True,
        )

    # The file the path leads to before it is checked: the read below must open
    # that same file, so one swapped in after the check is refused. A path that
    # leads nowhere then is held to the identity no file has
    # (identity_to_hold), so a link made at the name after the check is refused
    # too, and not read as a file nothing judged. None only while no file is
    # named or found, when nothing is read.
    checked = None
    if config_path is not None:
        # With a named file, search_dir is the directory the caller's scan
        # will target: the judgment below follows it, so the answer refuses
        # what a scan of THAT target refuses -- through the scan tool's own
        # gates, root policy first, so a directory no scan may target (one
        # under the config roots included) is refused, and the refusal never
        # leaks whether a directory outside the roots exists. The root policy
        # answers before the named file is opened: the grant check below
        # opens it, and a refused directory is refused before anything under
        # it is opened, the named file inside it included.
        search = Path(search_dir) if search_dir else None
        if search is not None:
            refused = _search_dir_outside_the_scan_roots(search, session_id)
            if refused is not None:
                return refused
        # The file the check approves: the read below must open that same file,
        # so one swapped in after the check, or in during it and out again, is
        # refused rather than read.
        # Before the existence check: the default config for an absent path and
        # the file for a present one would otherwise answer whether it exists.
        refusal, checked = _check_and_identify_config(config_path, session_id, held)
        if refusal is not None:
            return _config_refusal(refusal, "get_config")
        path: Optional[Path] = Path(config_path)
        if not path.exists():
            # Refused as `ash config get` refuses a named file that is not there,
            # a link to nothing included: answering with the default config read
            # as that file's settings. Only after the check above, so the answer
            # says nothing about a path outside the roots.
            return _config_load_failure(
                FileNotFoundError("the file does not exist"), path
            )
        # The source-directory check of the same target, after the root
        # policy above and the file's own checks.
        if search is not None:
            refused = source_directory_refusal(search, "get_config")
            if refused is not None:
                return refused
    else:
        # The directory discovery searches: the caller's, or the working
        # directory; None when that no longer exists (deleted while the
        # server runs). A given search_dir that no scan could target is
        # refused below (source_dir_not_usable, exit 5), as a scan of it is.
        # Only the working-directory default keeps the softer answer: a
        # working directory that no longer exists holds no file, so there is
        # nothing to search, and the answer is then the configuration a scan
        # would start from.
        search = Path(search_dir) if search_dir else working_directory()
        path = None
        refusal = None
        if search is not None:
            if search_dir:
                # A given search_dir names the target discovery searches, so
                # it crosses the scan tool's own gates (root policy first, so
                # a directory no scan may target is refused and the refusal
                # says nothing about a directory outside the roots, then the
                # source-directory check).
                refused = _search_dir_a_scan_refuses(search, session_id)
                if refused is not None:
                    return refused
            else:
                # The working-directory default keeps its own handling: for a
                # remote caller the directory is checked first, so a refusal
                # names it rather than a file found in it, which would say
                # the file exists. A local caller keeps discovery from any
                # directory, the filesystem root included. The file is
                # checked either way: it may be a link out.
                refusal = (
                    validate_config_input(search, session_id=session_id)
                    if caller_is_remote(session_id)
                    else None
                )
            if refusal is None:
                # Before discovery, which reads a pyproject.toml to learn
                # whether it configures ASH: that file, and the one discovery
                # selects, can be a link out of the roots.
                refusal = validate_discovered_config(search, session_id)
            if refusal is None:
                try:
                    path = find_config_file(search_dir=search)
                except ASHConfigSourceError as exc:
                    # Discovery's own read failure: a pyproject.toml that
                    # declares [tool.ash] but cannot be read. Refused as a
                    # config the tool cannot load, exit 3, with the file in the
                    # context, the same shape as a discovered file that does
                    # not parse. The pyproject is the one file discovery reads
                    # before selecting, so it is the one that failed. Never
                    # raised out of the tool.
                    return _config_load_failure(exc, search / "pyproject.toml")
                except (
                    ASHConfigValidationError,
                    yaml.YAMLError,
                    OSError,
                    ValueError,
                ) as exc:
                    # The kinds the resolve step below catches. The measured
                    # input that reaches this one: a .ash directory the server
                    # may not search, whose Path.is_file re-raises the stat
                    # PermissionError on Python 3.10 to 3.13 (3.14 answers
                    # False and discovery skips the names). An unreadable
                    # candidate file is answered by the path-bearing branch
                    # above instead, and a directory is skipped. Which file
                    # failed is in the error's own text where the OS supplied
                    # it, so no path is guessed.
                    return _config_load_failure(exc, None)
                if path is not None:
                    # The file discovery selected, as the check approves it,
                    # for the read below.
                    refusal, checked = _check_and_identify_config(
                        path, session_id, held
                    )
        if refusal is not None:
            return _config_refusal(refusal, "get_config")

    if path is not None and checked is None:
        # A file is about to be read and the check recorded none at the name: it
        # approved a path that led nowhere (or, for a discovered file, one that
        # had vanished), and a file is there now. It was made after the check,
        # so nothing judged it, and an identity of None would hold the read to
        # nothing. Refused as a changed file, which it is.
        return _config_load_failure(
            ConfigFileChangedError(
                errno.ESTALE,
                "changed after it was checked, so it is not read",
                os.fspath(path),
            ),
            path,
        )

    # A scan starts from get_default_config(), the file ASH_CONFIG names or the
    # defaults, and refuses the run when that file is refused. This tool answers
    # with what a scan would use, so it loads the file as that scan loads it: an
    # operator-only option a chain file inside the searched tree writes is left
    # out (the scan ignores it), shown ignored, and refused the same way
    # otherwise, naming that file.
    if path is None:
        # `search` is the searched directory, or None when the working
        # directory is deleted: the load then confines fail-closed, every
        # checkout file's operator-only options left out
        # (repository_settings_for_root).
        settings = repository_settings_for_root(search)
        # One read of each chain file for the whole answer: the confined
        # resolution below consults these caches (resolve_config's reads and
        # texts), so a chain file that changes on disk between the two steps
        # cannot put one read's marking record beside another read's judged
        # list in one answer.
        chain_reads: Dict[Path, Any] = {}
        chain_texts: Dict[Path, str] = {}
        try:
            base = get_default_config(
                settings.confine,
                repository_file=settings.is_repository_file,
                reads=chain_reads,
                texts=chain_texts,
            )
        except (ASHConfigValidationError, OSError) as exc:
            # OSError: a file ASH_CONFIG names that the server cannot read is
            # a config it cannot load, exit 3, not the generic handler's 1.
            return _config_load_failure(exc, None)
        # The references the marking below shows written-as-reference values
        # with are this FIRST read's: they keep each reference at a place the
        # confinement left out of the answer, which is exactly where a marker
        # has a value to show. The scan-confined read below rewrites its own
        # references when an in-tree chain file's places are dropped, so they
        # no longer carry those places. mark_operator_only_options reads them
        # only to match the record's written values -- the first read's --
        # and never touches ash_plugin_modules, whose display is the
        # answered document's own.
        marking_references = tuple(getattr(base, "_environment_references", ()) or ())
        if not raw:
            # The answer IS the scan's own resolution: resolve_config's
            # no-file branch reads the ASH_CONFIG chain exactly as a scan of
            # `search` reads it -- an in-tree chain file's sandbox grants are
            # dropped with a warning, and its unimportable plugin-module
            # entries likewise -- so every section of the answer, sandbox
            # included, is the one such a scan applies. Splicing single
            # sections out of this read into the read above showed the
            # unconfined read's values everywhere the splice did not reach.
            # The marking below uses the first read's references (see
            # marking_references above), not this resolution's. The
            # operator-only record stays `settings`, which
            # read the same documents (the shared caches above) under the
            # same confine identity (scan_repository_settings, which
            # repository_settings_for_root applies). no_discovery:
            # this tool discovered already, under the session's gates, and
            # found nothing, so this read answers from the chain and the
            # defaults alone -- a config file created in `search` since that
            # check is not selected here, where no gate would see it. Inside
            # `if not raw:` with the judgment: raw asks for a document (with
            # no file, the default configuration as the chain wrote it), not
            # a run, so it keeps the read above and cannot fail through this
            # arm. fallback_to_default stays True on purpose: the default
            # configuration IS this read's answer, and the fallback covers
            # only "no file selected", never an error. A chain the FIRST
            # read cannot load never reaches this call: get_default_config
            # above refuses it (the unparsable-chain cell pins that); a
            # failure of THIS read raises into the arm below, which the
            # confined-second-read cell pins.
            try:
                base = resolve_config(
                    config_path=None,
                    source_dir=search,
                    scanned_root=search,
                    no_scanned_tree=search is None,
                    no_discovery=True,
                    reads=chain_reads,
                    texts=chain_texts,
                )
            except (
                ASHConfigValidationError,
                yaml.YAMLError,
                ValueError,
                OSError,
            ) as exc:
                # The same kinds the first read refuses: the chain is the same
                # files, read once more under the scan's confinement.
                return _config_load_failure(exc, None)
            # The configuration a scan starts from is judged as that scan
            # judges it: an entry such a scan refuses answers success False in
            # this surface's closing words, rather than showing a
            # configuration no scan of this target runs under.
            # ASH_PLUGIN_MODULES is passed empty on purpose: it is the CLI
            # scan option's variable, which no MCP scan reads, so judging it
            # would refuse answers for configs every MCP scan runs under --
            # and put the server's own variable content in a client's refusal.
            # raw mode never judges, on either answer path: it asks for a
            # document (the file as written, or with no file the default
            # configuration), not a run, so the same raw request cannot
            # succeed or fail by whether a file exists.
            try:
                refuse_plugin_modules_a_scan_refuses(base, ())
            except PluginModuleError as exc:
                return _plugin_module_refusal(
                    plugin_module_refusal_message(
                        exc, **_MCP_NO_FILE_PLUGIN_MODULE_CLOSINGS
                    ),
                    None,
                )
        return shown_config(
            base,
            mark_operator_only_options(
                base.model_dump(),
                settings,
                marking_references,
            ),
        )

    if raw:
        # Before the open: a FIFO's open waits for a writer, and a directory or a
        # device is not a config.
        from automated_security_helper.config.config_sources import (
            read_config_bytes,
            read_opened_config_bytes,
            refuse_unless_a_file,
        )

        try:
            refuse_unless_a_file(Path(path))
        except ASHConfigValidationError as exc:
            return _config_load_failure(exc, Path(path))
        # As written: no value is read from the environment, for an operator's
        # file or a client's. yaml.safe_load refused every file that used !ENV
        # (no constructor for the tag), and the TOML branch went through the
        # loader, which resolves each "${...}" string. A file that does not parse
        # is refused as a resolved read refuses it, not left to the tool's
        # generic handler. (json.JSONDecodeError and UnicodeDecodeError are both
        # ValueErrors.)
        # Raw mode asks for a document, not a run: it judges nothing and refuses
        # no file for reading the environment, whoever named it, because it
        # resolves no reference. Each value the loader would read from the
        # environment comes back as the reference the file writes, marked
        # (ENV_VALUE_PREFIX), so the answer holds the client's own text and
        # nothing of the server's. Whether a file may resolve its references is
        # the resolved read's question (env_refused_for), answered there.
        try:
            # Read from the descriptor of the file the check judged, which the
            # call holds open; a name the check could not open is opened once,
            # and only if it is the file that was checked. One read: the bytes
            # below are what the answer is made of.
            opened = held.files.get(checked) if checked is not None else None
            content = (
                read_opened_config_bytes(opened, Path(path))
                if opened is not None
                else read_config_bytes(Path(path), expect=checked)
            )
            document = _config_as_written(path, expect=checked, content=content)
        except (
            ASHConfigValidationError,
            yaml.YAMLError,
            ValueError,
            OSError,
        ) as exc:
            return _config_load_failure(exc, Path(path))
        if document is None:
            # An empty file: the configuration it writes is empty.
            return {}
        if not isinstance(document, dict):
            # The tool answers a mapping of settings (its documented return,
            # and what the wire carries): a file whose top level is a list or a
            # scalar is a config the loader cannot use, refused as every other
            # unusable config is (exit 3), not returned as the file's content.
            # Described by kind, not quoted: the value is the file's own.
            from automated_security_helper.config.config_sources import (
                describe_config_path,
            )

            return _config_load_failure(
                ASHConfigSourceError(
                    f"{describe_config_path(Path(path))} holds "
                    f"{_document_kind(document)} at its top level, not a mapping "
                    "of settings"
                ),
                Path(path),
            )
        return document

    # resolve_config short-circuits to default when source_dir is None, so
    # supply one to force it to read the specified file. It is also where
    # `extends` bases must stay, so it is the searched directory when the file
    # was discovered, and otherwise the file's own project directory (the
    # parent of .ash/ for a file in .ash/), never .ash/ itself.
    #
    # The sandbox section is shown as a scan would apply it. A discovered file is
    # resolved for the directory searched, which is what a scan of it would find.
    # A named file is resolved for the directory the caller's scan will target
    # when search_dir names one; with none, for the target run_ash_scan() takes
    # when none is named: this session's delivered source, or the working
    # directory for the local client, or no tree at all for a network session
    # that delivered nothing (run_ash_scan refuses the working directory for
    # it). Never for the file's own directory: no scan targets the
    # directory of a bound profile or a config root, so treating the file as
    # inside its own scanned tree would hide grants a scan applies. A file the
    # client delivered is restrict-only wherever it is, with the bound profile
    # as the trusted base, as the scan runner resolves it.
    # The tree the answer is confined for; None means no tree is scanned (the
    # working directory deleted while the server runs): resolve_config then
    # judges the file by its own confinement root, which leaves out more,
    # never less, and the ASH_CONFIG pre-check below confines fail-closed.
    #
    # Whether the client named the file is read once, when the target needs it
    # (a remote session that delivered nothing) and again below for the trusted
    # base it is resolved against; the second use takes this reading, so the
    # target and the base cannot be decided by two reads of a file that changed
    # between them.
    named_untrusted: Optional[bool] = None
    scanned_root: Optional[Path]
    if config_path is None:
        # Discovery above found `path` inside `search`, so `search` names a
        # directory that existed; were it None, no file could have been found
        # in it, and the file's own confinement root is the right fallback,
        # as for a named file with no delivered source.
        source_dir = search if search is not None else default_confinement_root(path)
        scanned_root = search
    else:
        # The caller's named target widens the chain root exactly as it
        # widens the scan's: a scan of `search` resolves this file with the
        # target as its source directory, so a config inside the target may
        # extend a base anywhere in it. For a file outside the target, and
        # with no target named, the root stays the file's own
        # (default_confinement_root ignores a source_dir the file is not
        # inside, and takes None).
        source_dir = default_confinement_root(path, search)
        if search is not None:
            # The caller named the directory its scan will target
            # (mcp_scan_directory's directory_path): the file is judged as a
            # scan of that target judges it -- an entry a scan of the target
            # drops never refuses here -- wherever the server's own working
            # directory or this session's delivered source sits.
            scanned_root = search
        else:
            # None is the stdio session; an empty string is a session of its
            # own (profile_registry's reading), so it never borrows the stdio
            # session's delivered tree as the target this answer is judged for.
            delivered = get_session_source_dir(
                DEFAULT_SESSION_ID if session_id is None else session_id
            )
            delivered_here = delivered is not None and delivered.is_dir()
            if caller_is_remote(session_id) and not delivered_here:
                named_untrusted = client_named_config_is_untrusted(
                    path, session_id=session_id
                )
            if delivered_here:
                scanned_root = delivered
            elif named_untrusted:
                # A network session that delivered nothing has no tree a scan
                # of it may target: run_ash_scan refuses to fall back to the
                # server's working directory for it (_resolve_omitted_source_dir),
                # so a file of the CLIENT's (named outside every granted config
                # root) is not judged for that directory either. It is judged
                # for no scanned tree, the fail-closed path a deleted working
                # directory already takes: the file is confined by its own
                # root and the operator-only options of no checkout are read,
                # which leaves out more, never less. A file the OPERATOR granted
                # (inside ASH_MCP_ALLOWED_CONFIG_ROOTS) is not confined that way:
                # under the no-tree load a trusted file in any checkout joins
                # the confinement and its unimportable plugin modules are
                # DROPPED, so the answer would show a configuration every scan
                # of it refuses; it keeps the working-directory judgment, under
                # which the file sits outside the tree, its entries are kept
                # and judged, and the refusal below answers.
                scanned_root = None
            else:
                # The local client's working directory is its own tree, the
                # target run_ash_scan takes for it when none is named; a
                # network session's granted file keeps the same judgment, as
                # the arm above says.
                scanned_root = working_directory()

    # resolve_config starts from the ASH_CONFIG base and raises when it is
    # refused. Checked first, so the refusal is not reported as the file asked
    # for -- and loaded as a scan of scanned_root loads it, with the tree's
    # operator-only options left out (fail-closed when no tree is scanned), so
    # a value such a scan reads past does not refuse the file asked for either.
    try:
        # Not a _ConfigPreCheck: the RepositorySettings a scan of
        # scanned_root reads the ASH_CONFIG chain with. With no scanned_root
        # the load below reads source_dir as its root (resolve_config rebinds
        # it), so the pre-check takes source_dir's trees too: built from none,
        # it would read a file inside that directory as the operator's and
        # refuse a value the load leaves out.
        chain_root = scanned_root if scanned_root is not None else source_dir
        chain_settings = repository_settings_for_root(chain_root)
        get_default_config(
            chain_settings.confine,
            repository_file=chain_settings.is_repository_file,
        )
    except (ASHConfigValidationError, OSError) as exc:
        # OSError as above: refused as a config, never the file asked for.
        return _config_load_failure(exc, None)
    if config_path is None:
        untrusted_config = config_is_client_supplied(path)
    elif named_untrusted is not None:
        untrusted_config = named_untrusted
    else:
        untrusted_config = client_named_config_is_untrusted(path, session_id=session_id)
    # The trusted base a client-supplied config is resolved against: the
    # session's bound profile, written again from the binding when its file is
    # gone. Resolved before the load, so a binding that cannot be written again
    # (its profile unregistered, its workspace unwritable) is answered as the
    # session's refusal, the way run_ash_scan answers it, and never as the named
    # file's load failure: that blamed the client's config for the server's own
    # state. A BoundProfileUnavailableError is a ValueError too, so inside the
    # load's try it was caught as one.
    trusted_config_path: Optional[str] = None
    if untrusted_config:
        from automated_security_helper.cli.mcp.profile_registry import (
            ProfileRegistryError,
        )
        from automated_security_helper.cli.mcp.sessions import (
            SessionWorkspaceBusyError,
        )

        try:
            trusted_config_path = resolve_session_trusted_config_path(session_id)
        except ProfileRegistryError as exc:
            return _bound_profile_unavailable(exc, "get_config")
        except SessionWorkspaceBusyError as exc:
            # The file is gone and another request holds the session's
            # workspace (its removal), so it is not written again under that
            # removal: the hold's own refusal, as select_profile answers it,
            # with the exit code every refusal of this tool carries.
            return with_exit_code(
                {
                    "success": False,
                    "error": raw_controls_on_one_line(str(exc)),
                    "error_type": exc.error_type,
                    "operation": "get_config",
                },
                REFUSED_INTERNAL_EXIT_CODE,
            )
    # The selected config's chain, handed out by the load itself (chain_out),
    # so this tool never reverse-engineers how the load's file lists were put
    # together: a subtraction over files_read dropped the first copy of a
    # base both chains extend, whichever chain it belonged to, and kept the
    # operator's files.
    chain: list[Path] = []
    # The RepositorySettings that read the chain: what each checkout file
    # wrote for the operator-only options, recorded at the one read the
    # marking below answers from.
    chain_repository: list[RepositorySettings] = []
    try:
        # Not falling back to the defaults, as `ash config get` does not: on a
        # file that does not parse resolve_config logs it and returns the default
        # configuration, which this answered as the file's own settings.
        resolved = resolve_config(
            config_path=path,
            source_dir=source_dir,
            fallback_to_default=False,
            permit_base=config_base_gate(session_id),
            scanned_root=scanned_root,
            untrusted_config=untrusted_config,
            trusted_config_path=trusted_config_path,
            # The rules' trusted default config is the ASH_CONFIG file, read with
            # the settings the pre-check above used (a fresh instance: one
            # instance records one read), so a value the load leaves out never
            # makes the rules unreadable.
            client_config_policy=_session_client_rules(
                session_id, repository_settings_for_root(chain_root)
            ),
            remote_client=caller_is_remote(session_id),
            # No tree is scanned (the working directory deleted while the
            # server runs): the real load's ASH_CONFIG and trusted-base
            # reads then fail closed, as the pre-check above did, so a
            # value they leave out never refuses the file asked for.
            no_scanned_tree=scanned_root is None,
            chain_out=chain,
            repository_out=chain_repository,
            # The file the check approved: one swapped in since is refused and
            # not shown, as the raw read refuses it.
            expect=checked,
        )
    except ASHConfigInputNotPermittedError as exc:
        return _config_refusal(config_chain_refusal(path, exc), "get_config")
    except (ASHConfigFieldDeniedError, ASHConfigPolicyUnreadableError) as exc:
        return _denied_response(exc, "get_config")
    except ASHConfigEnvNotResolvedError as exc:
        return _config_env_refusal(exc, "get_config")
    except (ASHConfigValidationError, yaml.YAMLError, ValueError, OSError) as exc:
        # The errors `ash config get` exits 3 for (cli/config.py).
        return _config_load_failure(exc, path)
    if resolved is None:
        # No file resolved and no default taken (fallback_to_default=False): a
        # discovered config whose path is a dangling link. Answered as not
        # found, never raised out of the tool.
        return _config_load_failure(FileNotFoundError(str(path)), path)
    try:
        # The ash_plugin_modules list a scan would import -- the resolved
        # entries after trust confinement (a client-delivered or in-tree
        # file's dropped entries never refuse) -- is judged as that scan
        # judges it. An agent client shown a config a scan of the answered
        # target refuses would be misled by a success answer, so the tool
        # refuses instead,
        # in this surface's closing words, exit 3. ASH_PLUGIN_MODULES is
        # passed empty on purpose: it is the CLI scan option's variable,
        # which no MCP scan reads, so judging it would refuse answers for
        # configs every MCP scan runs under -- and put the server's own
        # variable content in a client's refusal.
        refuse_plugin_modules_a_scan_refuses(resolved, ())
    except PluginModuleError as exc:
        return _plugin_module_refusal(
            plugin_module_refusal_message(exc, **_MCP_PLUGIN_MODULE_CLOSINGS),
            path,
        )
    shown = resolved.model_dump()
    # The reporter options only the operator may set are shown as a scan of the
    # file's own repository applies them: ignored. A file outside every checkout
    # is an operator's, and a scan that names it applies them. The selected
    # chain is the load's own list (chain_out), so a base BOTH chains extend
    # stays the selected chain's own file for the checkout guard below, and a
    # chain file changed on disk since the load is still judged as read.
    # The record is the resolution's own (repository_out): the chain is not
    # resolved again, so a chain file that changed on disk since the read
    # cannot raise past the structured refusals above or put a second read's
    # values in the answer.
    [written] = chain_repository
    # Marked when no chain file is inside the scanned trees -- judged against
    # the trees the resolution confined with (RepositorySettings.trees), with
    # the same fail-closed walk, so an undecided name counts as the trees' here
    # as it did there -- and one is in a checkout. The resolution's list of
    # repository files is not that test: it also holds a chain file in another
    # checkout, which the confinement left out as the repository's and which
    # is exactly the file whose options are marked here, so a guard keyed on it
    # skipped the marker and answered without the option.
    if not files_inside([path, *chain], written.trees, [path, *chain]) and any(
        # The fail-closed answer: a file whose walk never decided it is in a
        # checkout, as the resolution's own membership read it.
        in_a_checkout(file)
        for file in [path, *chain]
    ):
        # Marked only where a checkout file of the chain writes one: the dump
        # holds a scanner's typed options whether or not any file named them,
        # and a file of the chain outside every checkout is an operator's,
        # whose values a scan keeps (set_elsewhere skips those places). No
        # chain file is inside the scanned trees here (the guard above), so
        # the resolution confined each checkout file of the chain exactly as
        # the dropped re-read did.
        # The resolution's references: an option the chain read from the
        # environment is marked by the reference it was written as, never by
        # its value. The confinement rewrite (_take_confined_references) drops
        # the references at the places it settled, a chain file in another
        # checkout included, so a marker for an environment-read option may
        # find no reference and would fall back to the value the server's
        # environment gave. Such a marker is not written: the option stays as
        # the load left it, absent or at the configuration's own value.
        shown = _without_environment_read_markers(
            shown,
            mark_operator_only_options(
                shown,
                written,
                tuple(getattr(resolved, "_environment_references", ()) or ()),
            ),
            config_environment_values(resolved),
        )
    return shown_config(resolved, shown)


_OPERATOR_ONLY_MARKER_HEAD = "<operator only; ignored from this file: "


def _without_environment_read_markers(
    before: Dict[str, Any],
    marked: Dict[str, Any],
    environment_values: Tuple[str, ...],
) -> Dict[str, Any]:
    """*marked*, with each operator-only marker that would print a value the
    configuration read from the environment put back to what *before* held.

    ``mark_operator_only_options`` shows an environment-read value as the
    reference the file wrote only when a reference still sits at the place;
    otherwise it shows the value itself, as JSON. The references at a settled
    place are the ones the confinement rewrite drops, so for a chain file in
    another checkout the fallback is reached, and the value is one the server's
    environment gave. A marker whose text is that fallback for any of
    *environment_values* (the configuration's own record of what its chain read,
    every read included) is withdrawn: the option is left as *before* has it,
    absent where the load left it out, or at the value the configuration holds
    there. A literal that happens to equal an environment value is withheld
    too, which errs toward showing less. *marked* is changed in place and
    returned.
    """
    import json as _json

    from automated_security_helper.utils.terminal_text import shown_on_one_line

    fallbacks = {
        f"{_OPERATOR_ONLY_MARKER_HEAD}{shown_on_one_line(_json.dumps(value))}>"
        for value in environment_values
        if isinstance(value, str)
    }
    if not fallbacks:
        return marked
    for kind in ("reporters", "scanners"):
        sections = marked.get(kind)
        if not isinstance(sections, dict):
            continue
        before_sections = before.get(kind)
        before_sections = before_sections if isinstance(before_sections, dict) else {}
        for key, section in sections.items():
            options = section.get("options") if isinstance(section, dict) else None
            if not isinstance(options, dict):
                continue
            before_section = before_sections.get(key)
            before_options = (
                before_section.get("options")
                if isinstance(before_section, dict)
                else None
            )
            before_options = before_options if isinstance(before_options, dict) else {}
            for option, text in list(options.items()):
                if not isinstance(text, str) or text not in fallbacks:
                    continue
                if before_options.get(option) == text:
                    continue
                if option in before_options:
                    options[option] = before_options[option]
                else:
                    options.pop(option)
    return marked


def _config_problem(field: str, message: str, kind: str) -> Dict[str, Any]:
    """One of validate_config's errors or warnings, as a client reads it.

    The message quotes the config's keys and values, a parser's message and the
    file's path, and the field is a key taken from the message, so either can
    hold an ESC, a newline or a right-to-left override from the file. Both are
    shown on one line here, at the reply; the validator keeps them as raised.
    """
    return {
        "field": raw_controls_on_one_line(field),
        "message": raw_controls_on_one_line(message),
        "type": kind,
    }


def _classify_validation_message(raw: str) -> Dict[str, Any]:
    """One of the validator's messages as validate_config's error or warning.

    Typed by the validator's own prefixes first, and shown on one line
    (:func:`_config_problem`). The one classifier for every message a reply
    carries, the policy check's own included, so no line of a reply skips the
    sanitizer or takes another type than the validator would give it.
    """
    import re

    from automated_security_helper.config.config_validator import ConfigValidator

    # By the validator's own prefixes first. A message about a base names
    # the base's file, so a YAML check that matched any message containing
    # "yaml" would type every extends error naming base.yaml as a YAML parse
    # error of the file being validated.
    if raw.startswith(ConfigValidator.NOT_PERMITTED_ERROR_PREFIX):
        return _config_problem("", raw, CONFIG_INPUT_NOT_PERMITTED)
    if raw.startswith(ConfigValidator.ENV_NOT_RESOLVED_ERROR_PREFIX):
        return _config_problem("", raw, CONFIG_ENV_NOT_RESOLVED)
    # Also before the generic branches: the message quotes module names.
    # The validator's module check (ConfigValidator._plugin_module_refusal)
    # gives the loader's refusal as it is, which opens with the field's name
    # ("ash_plugin_modules names ..."), not with this prefix.
    if raw.startswith(
        (ConfigValidator.PLUGIN_MODULES_ERROR_PREFIX, "ash_plugin_modules ")
    ):
        return _config_problem("ash_plugin_modules", raw, "invalid_field")
    if raw.startswith(ConfigValidator.EXTENDS_ERROR_PREFIX):
        return _config_problem("", raw, "extends_error")
    # The category words, from the one place the validator spells them.
    # The validator's full prefix ends ": ", but a ConfigCheck message
    # built elsewhere can carry the words alone ("YAML parsing error near
    # line 4"), so the match drops the trailing ": " and types by the
    # words; a message that merely names them further in keeps its type.
    parse_words = {
        kind: prefix.rstrip(": ")
        for kind, prefix in ConfigValidator.PARSE_ERROR_PREFIXES.items()
    }
    if raw.startswith(parse_words["YAML"]):
        return _config_problem("", raw, "yaml_parse_error")
    if raw.startswith(parse_words["JSON"]):
        return _config_problem("", raw, "json_parse_error")
    if raw == ConfigValidator.MISSING_PROJECT_NAME_MESSAGE:
        # A warning: project_name has a default. Typed missing_required_field,
        # so a client that looks for that type finds it.
        return _config_problem("project_name", raw, "missing_required_field")
    # The TOML reader's parse refusals carry their own category prefix
    # (ASHConfigUnparsedError in the validator). Its other refusals, a
    # pyproject.toml with no [tool.ash] table and a tool.ash that is not a
    # table, keep "TOML error: " and fall through.
    if raw.startswith(parse_words["TOML"]):
        return _config_problem("", raw, "toml_parse_error")
    if "Missing required" in raw:
        m = re.search(r"'([^']+)'", raw)
        field = m.group(1) if m else ""
        return _config_problem(field, raw, "missing_required_field")
    if "internal-only field" in raw or "internal field" in raw:
        m = re.search(r"field '([^']+)'", raw)
        field = m.group(1) if m else ""
        return _config_problem(field, raw, "internal_field")
    if "Unknown" in raw or "unknown" in raw:
        m = re.search(r"'([^']+)'", raw)
        field = m.group(1) if m else ""
        return _config_problem(field, raw, "unknown_field")
    if "Invalid" in raw or "invalid" in raw:
        m = re.search(r"'([^']+)'", raw)
        field = m.group(1) if m else ""
        return _config_problem(field, raw, "invalid_field")
    if "Duplicate" in raw:
        m = re.search(r"'([^']+)'", raw)
        field = m.group(1) if m else ""
        return _config_problem(field, raw, "duplicate_field")
    return _config_problem("", raw, "validation_error")


def mcp_validate_config(
    config_content: Optional[str] = None,
    config_path: Optional[str] = None,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Validate an ASH config supplied as a content string or file path.

    The client's config is also checked against the session's runtime-override
    policy, as a scan of it would be: ``config_content`` from a remote caller,
    and a ``config_path`` a client delivered or outside the directories
    ``ASH_MCP_ALLOWED_CONFIG_ROOTS`` names, unless it is a profile file the server
    wrote in the calling session's ``config/`` directory
    (``sandbox.client_named_config_is_untrusted``). Each field it denies is a
    ``denied_by_runtime_policy`` error. A ``${VAR}`` or ``${VAR:default}``
    reference at the start of a plain value, or an ``!ENV`` tag, is a
    ``config_env_not_resolved`` error in the files
    ``config_sources.env_refused_for`` gives for the caller: for a remote caller
    the client's config as above, content included; otherwise only a file a
    client delivered.

    Args:
        config_content: YAML/JSON string to validate. Mutually exclusive with config_path.
        config_path: Path to the config file to validate.
        session_id: The MCP session this call acts for. ``config_path`` and every
            base either input extends must be readable as a config input for it.

    Returns:
        Dict with keys:
          - valid: bool, True when a scan accepts the config
          - errors: List[{field: str, message: str, type: str}], what makes a
            scan refuse it; empty when valid
          - warnings: the same shape, for what a scan accepts but is probably a
            mistake (an unknown or internal-only key, a missing project_name, a
            directory path without ``**``)

        ``errors`` holds errors only, so a valid config has none there, whatever
        its warnings.
    """
    import tempfile

    from automated_security_helper.cli.mcp.sandbox import (
        caller_is_remote,
        client_named_config_is_untrusted,
        config_base_gate,
        validate_config_input,
    )
    from automated_security_helper.config.config_sources import (
        env_refused_for,
        identity_to_hold,
        text_reads_the_environment,
    )
    from automated_security_helper.config.config_validator import ConfigValidator

    permit_base = config_base_gate(session_id)
    remote_client = caller_is_remote(session_id)

    if config_content is not None and config_path is not None:
        # The two inputs are exclusive (the docstring): given both, validating
        # the content and answering as if for the file reported one input's
        # result under the other's name. Refused as the missing-input case is,
        # before anything is read.
        return {
            "valid": False,
            "errors": [
                {
                    "field": "",
                    "message": (
                        "Give either config_content or config_path, not both: the "
                        "answer would be about one of them only."
                    ),
                    "type": "conflicting_input",
                }
            ],
            "warnings": [],
        }

    if config_content is not None:
        if caller_is_remote(session_id) and text_reads_the_environment(
            Path("config.yaml"), config_content
        ):
            # A config a remote client wrote reads nothing from the
            # environment, as a file it delivered does not
            # (config_sources.refuse_environment_in_a_delivered_file); the
            # temporary file below is outside the session's sandbox.
            return {
                "valid": False,
                "errors": [
                    _config_problem(
                        "",
                        "The config content reads a value from the environment (an "
                        "!ENV tag or a ${VAR} reference), which a config a remote "
                        "client sends may not. Write the value itself, or leave "
                        "the setting to the server's config.",
                        CONFIG_ENV_NOT_RESOLVED,
                    )
                ],
                "warnings": [],
            }
        # A private, otherwise empty directory rather than the shared temp dir:
        # the file's directory is where an `extends` in the content may look
        # for bases, and nothing a client did not send should be found there.
        # Content a remote client sent may not use !ENV, wherever the file is
        # written. On stdio the caller launched this server, and the same text
        # as a local file of its own would resolve.
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir) / "config.yaml"
            tmp_path.write_text(config_content, encoding="utf-8")
            # Client content is untrusted, as a scan under it treats it: a
            # not-installed ash_plugin_modules entry is dropped, not refused.
            check = ConfigValidator.check_config_file(
                tmp_path, permit_base=permit_base, untrusted_config=True
            )
    elif config_path is not None:
        # The file the path leads to before it is checked: the check below
        # reads only that file, so one swapped in after the grant check is
        # refused as unreadable and not validated. A path that leads nowhere
        # now is held to the identity no file has (identity_to_hold), so a
        # link made at the name after the grant check is refused as well.
        checked = identity_to_hold(Path(config_path))
        # Before the existence check, so a refused path is reported as refused
        # and not as missing.
        refusal = validate_config_input(config_path, session_id=session_id)
        if refusal is not None:
            return {
                "valid": False,
                "errors": [
                    _config_problem(
                        "config_path", str(refusal), CONFIG_INPUT_NOT_PERMITTED
                    )
                ],
                "warnings": [],
            }
        path = Path(config_path)
        if not path.exists():
            return {
                "valid": False,
                "errors": [
                    _config_problem(
                        "config_path",
                        f"Config file not found: {config_path}",
                        "file_not_found",
                    )
                ],
                "warnings": [],
            }
        check = ConfigValidator.check_config_file(
            path,
            permit_base=permit_base,
            # A path the client named is judged as the scan judges it
            # (resolve_config's untrusted_config, through the same predicate):
            # the client's unless the operator set it aside, in a config root or
            # as this session's own profile file. Judging only whether a client
            # delivered the file passed a repository config elsewhere as the
            # operator's, which the scan then refused, and the reverse.
            untrusted_config=client_named_config_is_untrusted(
                path, session_id=session_id
            ),
            expect=checked,
            # The environment is the server's. A remote caller's config reads
            # nothing from it unless it is one of the operator's files
            # (env_refused_for), and the validator resolves every reference it
            # finds, so it reads each file of the chain under that rule: the
            # one read that resolves is the one the rule governs, a refusal
            # comes before anything is read with the environment, and the
            # answer does not turn on which variables the server has set.
            refuse_env=env_refused_for(remote_client, session_id),
        )
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
            "warnings": [],
        }

    errors = [_classify_validation_message(e) for e in check.errors]
    # What the policy refuses in the documents the validator held, beside the
    # validator's errors: a message the validator gave is not given twice.
    given = {(error["type"], error["message"]) for error in errors}
    denied = [
        problem
        for problem in _validated_document_denials(
            config_content, config_path, session_id, check
        )
        if (problem["type"], problem["message"]) not in given
    ]
    return {
        "valid": check.scan_accepts and not denied,
        "errors": errors + denied,
        "warnings": [_classify_validation_message(w) for w in check.warnings],
    }


def _unchecked_against_policy(error: BaseException) -> Dict[str, Any]:
    """The validation error for a config the session's runtime-override policy
    could not finish judging.

    Shown as every other line of validate_config's reply is
    (:func:`_config_problem`, one line). A refusal the validator's own prefixes
    type (an input outside the roots, a read of the environment) keeps that
    type, as the validator would give it; any other failure is a
    ``validation_error``.
    """
    from automated_security_helper.config.config_validator import ConfigValidator
    from automated_security_helper.core.exceptions import (
        ASHConfigEnvNotResolvedError,
        ASHConfigSourceError,
    )

    if isinstance(error, ASHConfigEnvNotResolvedError):
        # A file the policy refuses to read the environment for, more widely than
        # the validator does for a remote caller: the refusal the validator
        # reports for a delivered file, in its words and its type.
        return _classify_validation_message(
            f"{ConfigValidator.ENV_NOT_RESOLVED_ERROR_PREFIX}{error}"
        )
    if isinstance(error, ASHConfigSourceError):
        # Typed by the validator's prefixes; the text is the config's own and
        # can hold its control characters, which the line shown here does not.
        return _classify_validation_message(str(error))
    return _config_problem(
        "",
        "The config could not be checked against this session's "
        f"runtime-override policy: {error}",
        "validation_error",
    )


def _validated_document_denials(
    config_content: Optional[str],
    config_path: Optional[str],
    session_id: Optional[str],
    check: "ConfigCheck",
) -> list:
    """The fields a client's config sets that this session's policy denies, as errors.

    Judged on the documents the validator held (``check.documents``, ``names``
    and ``texts``), never on a second read of the files: a file rewritten in
    place, replaced, or removed after the validator read it changes nothing
    here, so the verdict is not one file's validation beside another file's
    policy. A named file is checked with every base its ``extends`` chain
    reached; each file of the chain a client delivered is checked. Content is the
    caller's own text, so it is checked only for a remote caller: on stdio the
    caller launched this server, and the same text as a local file is not a
    client's.

    A remote caller's client files read nothing from the environment
    (``config_sources.env_refused_for``). The validator reads the chain under
    that rule and refuses such a file in its read, so a check that holds
    documents holds none that read it. The held texts are decided against the
    same rule once more (``config_sources.environment_read_refusals``), which
    finds nothing while the validator and this check are given one rule; a file
    it did find would be reported and not judged, since a denial must not quote
    a value the environment gave, and the denials of the chain's other files
    reported beside it.

    ``check`` is what the validator made of the same config. A check that
    resolved no chain (``check.documents`` empty) holds nothing to judge: the
    validator refused the config and said why, so this adds nothing. A check
    that accepted the config holds the chain, so one that holds none leaves the
    policy unjudged and the config is not valid. Every refusal of this check is
    returned: a caller reports them beside the validator's errors.
    """
    from automated_security_helper.cli.mcp.sandbox import (
        caller_is_remote,
        client_named_config_is_untrusted,
    )
    from automated_security_helper.config.client_config_policy import (
        client_file_denials,
    )
    from automated_security_helper.config.config_sources import (
        env_refused_for,
        environment_read_refusals,
    )
    from automated_security_helper.config.operator_only_options import (
        repository_settings_for_root,
    )
    from automated_security_helper.config.sandbox_grants import working_directory

    # The rules' trusted default config is the file ASH_CONFIG names, read with
    # the settings the validator's own load of it uses (it roots them at the
    # working directory: check_config_file is given no source directory), so a
    # value that load leaves out never makes the rules unreadable. With the
    # working directory deleted the root is None and the read confines
    # fail-closed. The settings walk the directory's git checkouts, and a walk
    # that fails is a check that cannot finish, which refuses (as get_config
    # does for the same walk) rather than raising out of the tool.
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    try:
        rules = _session_client_rules(
            session_id, repository_settings_for_root(working_directory())
        )
    except (ASHConfigValidationError, OSError) as exc:
        return [_unchecked_against_policy(exc)]
    checked = (
        caller_is_remote(session_id)
        if config_content is not None
        else config_path is not None
        and client_named_config_is_untrusted(config_path, session_id=session_id)
    )
    if rules.unreadable is not None and checked:
        return [_config_problem("", rules.unreadable, CONFIG_POLICY_UNREADABLE)]
    if config_content is not None and not checked:
        return []
    if config_content is None and config_path is None:
        return []
    if not check.documents:
        if check.scan_accepts:
            return [
                _unchecked_against_policy(
                    RuntimeError("the validator held no document of the config")
                )
            ]
        return []
    if config_content is not None:
        # The content is one document: the validator's root. A base it names
        # outside its private directory is not a file the client sent, and was
        # never part of this check.
        root = check.chain[-1] if check.chain else None
        if root not in check.documents:
            return [
                _unchecked_against_policy(
                    RuntimeError("the validator held no document of the content")
                )
            ]
        documents: Dict[Path, Any] = {root: check.documents[root]}
        names = None
        problems: List[Dict[str, Any]] = []
    else:
        names = check.document_names
        # A file that read the environment under a rule that keeps it from doing
        # so is refused and not judged: the validator parsed it with the
        # environment's values, which a denial must not quote.
        refused = environment_read_refusals(
            {
                path: check.texts[path]
                for path in check.documents
                if path in check.texts
            },
            names,
            env_refused_for(caller_is_remote(session_id), session_id),
            shown=check.shown_path,
        )
        problems = [_unchecked_against_policy(error) for error in refused.values()]
        documents = {
            path: document
            for path, document in check.documents.items()
            if path not in refused
        }
    found: List[Tuple[str, str]]
    try:
        if config_content is not None:
            # The same check a scan of a delivered file gets, the restrict-only
            # settings and the moved scanner exclusions included.
            found = [
                (denial.key, denial.reason)
                for _file, denials in client_file_denials(
                    documents, rules, all_delivered=True, moved_exclusions=True
                )
                for denial in denials
            ]
        else:
            # A named path the client chose counts as delivered, every file of
            # its chain with it, as resolve_config(untrusted_config=True) does.
            found = [
                (denial.key, f"{denial.reason}, in {file.name}")
                for file, denials in client_file_denials(
                    documents,
                    rules,
                    all_delivered=checked,
                    names=names,
                    moved_exclusions=True,
                )
                for denial in denials
            ]
    except Exception as exc:  # noqa: BLE001 -- a check that cannot finish refuses
        return problems + [_unchecked_against_policy(exc)]
    shown = _plugin_modules_shown(check)
    # A denial quotes the config's own text -- a module name the policy refuses
    # can hold a value the chain read from the environment, glued in by "_".
    # _with_modules_shown covers a name the environment supplied whole; every
    # other value passes the same redaction as the validator's own errors.
    return problems + [
        _config_problem(
            key,
            check.redact(
                "{} may not be set by a config an MCP client delivers: {}".format(
                    key, _with_modules_shown(reason, shown)
                )
            ),
            "denied_by_runtime_policy",
        )
        for key, reason in found
    ]


def _plugin_modules_shown(check: "ConfigCheck") -> Dict[str, str]:
    """How a denial names each ``ash_plugin_modules`` module of ``check``'s config:
    one the config read from the environment as ``<value>``, the others as written
    (``plugin_module_trust.shown_module_names``)."""
    from automated_security_helper.config.plugin_module_trust import (
        shown_module_names,
    )

    resolved, shown = check.resolved_data, check.shown_resolved
    if not isinstance(resolved, dict) or not isinstance(shown, dict):
        return {}
    return shown_module_names(
        resolved.get("ash_plugin_modules"), shown.get("ash_plugin_modules")
    )


def _with_modules_shown(reason: str, shown: Dict[str, str]) -> str:
    """``reason`` with each quoted module name of ``shown`` written as it is shown,
    so a denial never quotes a module name the environment supplied."""
    for name, as_shown in shown.items():
        if as_shown != name:
            reason = reason.replace(repr(name), repr(as_shown))
    return reason


def _block_yaml_one_line_per_key(data: Dict[str, Any]) -> str:
    """``data`` as safe_dump writes it, with each key and its value on one line.

    A string holding a line break, or any character outside printable ASCII, is
    written double-quoted, where that character is its escape. In the plain or
    single-quoted style safe_dump would otherwise choose, a line break in a
    finding's path started a line of its own. And no value is folded at a width:
    a long path with spaces was continued on the next line.
    """
    import sys

    import yaml

    class _Dumper(yaml.SafeDumper):
        pass

    def _represent_str(dumper: yaml.SafeDumper, value: str) -> yaml.ScalarNode:
        from automated_security_helper.config.ash_config import ENV_REFERENCE_PATTERN

        printable = all(" " <= c <= "~" for c in value)
        if printable and ENV_REFERENCE_PATTERN.match(value):
            # Paste-ready text is written for the config loader, which reads a
            # plain ``${VAR...}`` start as an environment reference. Quoted, the
            # pasted value loads back as the literal text this block displayed
            # (the config writer's convention for a reference lookalike).
            return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="'")
        return dumper.represent_scalar(
            "tag:yaml.org,2002:str", value, style=None if printable else '"'
        )

    _Dumper.add_representer(str, _represent_str)
    return yaml.dump(
        data,
        Dumper=_Dumper,
        default_flow_style=False,
        sort_keys=True,
        width=sys.maxsize,
    )


def mcp_suggest_suppression(
    finding_id: str,
    results_path: Optional[str] = None,
    expiration: Optional[str] = None,
    justification: Optional[str] = None,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a paste-ready AshSuppression entry for a specific finding.

    Args:
        finding_id: Stable hash ID of the finding to suppress.
        results_path: Path to ash_aggregated_results.json. Defaults to
                      .ash/ash_output/ash_aggregated_results.json in cwd.
        expiration: Expiration date in YYYY-MM-DD format. Defaults to 90 days from today.
        justification: Human-readable reason for the suppression.
        session_id: The MCP session this call acts for. The results file must be
            inside its scan roots, as for the other results readers.

    Returns:
        Dict with keys:
          - success: bool
          - yaml: str — paste-ready YAML block
          - json: dict — same data as a dict
        On error: {"success": False, "error": <message>}. A finding whose file
        path holds a backslash has ``error_type`` PATH_NOT_EXPRESSIBLE: no
        suppression path names that file alone. A finding that reports no file
        path, or no rule id, has ``error_type`` SUPPRESSION_NOT_SPECIFIC: a
        suppression with an empty path matches nothing, and one with no rule
        covers every rule in the file (or the lines), never that finding
        alone, so none is suggested. An ``expiration`` that is not a YYYY-MM-DD
        date has ``error_type`` INVALID_EXPIRATION, with the rule the config
        model applies to the field.
    """
    from datetime import date, timedelta

    from pydantic import ValidationError

    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.models.core import (
        AshSuppression,
        expiration_date_problem,
    )
    from automated_security_helper.utils.path_matching import (
        PathNotExpressible,
        literal_path_pattern,
    )

    # The client's date, checked before the results are read: the model refuses
    # the same shape (validate_expiration_date), and a refusal out of it was a
    # ValidationError raised from the tool, logged as an unexpected error and
    # answered with a class name. An empty string is no date either; only None
    # takes the default.
    if expiration is not None:
        problem = expiration_date_problem(expiration)
        if problem is not None:
            return {
                "success": False,
                "error_type": INVALID_EXPIRATION,
                "error": raw_controls_on_one_line(
                    f"No suppression suggested: the expiration is not a date the "
                    f"config accepts. {problem}."
                ),
            }

    if results_path is None:
        results_file = (
            Path.cwd() / ".ash" / "ash_output" / "ash_aggregated_results.json"
        )
    else:
        results_file = Path(results_path)

    refusal = _refuse_results_file(results_file, "suggest_suppression", session_id)
    if refusal is not None:
        return refusal

    if not results_file.exists():
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"Results file not found: {results_file}"
            ),
        }

    try:
        # ASH writes its results files as UTF-8; the locale default is cp1252 on
        # Windows, which cannot decode every byte they hold.
        results = AshAggregatedResults.from_json(
            results_file.read_text(encoding="utf-8")
        )
    except Exception as e:
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"Failed to parse results file: {error_text(e)}"
            ),
        }

    flat_vulns = results.to_flat_vulnerabilities()
    finding = next((v for v in flat_vulns if v.id == finding_id), None)

    if finding is None:
        return {
            "success": False,
            "error": raw_controls_on_one_line(f"Finding not found: {finding_id}"),
        }

    expiration_date = (
        expiration
        if expiration is not None
        else (date.today() + timedelta(days=90)).strftime("%Y-%m-%d")
    )
    reason = (
        justification
        or "Suppressed via ASH MCP suggest_suppression tool — review before merging"
    )

    # A suppression names the finding by its file and its rule. A finding with
    # no file path would give one with an empty path, which matches nothing and
    # was answered as a success; one with no rule id would give a suppression
    # with no rule, which the matcher reads as every rule in that file (or in
    # those lines), far more than the finding asked about. Neither names the
    # finding alone, so neither is suggested.
    if not finding.file_path:
        return {
            "success": False,
            "error_type": SUPPRESSION_NOT_SPECIFIC,
            "error": raw_controls_on_one_line(
                f"No suppression suggested for finding {finding_id}: it reports "
                "no file path, so a suppression built from it would match "
                "nothing."
            ),
        }
    if not finding.rule_id:
        return {
            "success": False,
            "error_type": SUPPRESSION_NOT_SPECIFIC,
            "error": raw_controls_on_one_line(
                f"No suppression suggested for finding {finding_id}: it reports "
                "no rule id, so a suppression built from it would cover every "
                "rule in its file, not this finding alone. Write one by hand "
                "with the rule, the path and the lines meant."
            ),
        }

    # The suppression's path is a pattern: written so that it matches the
    # finding's file and no other, where "[", "*" or "?" in the file's name read
    # as glob syntax. A backslash, a separator there, has no spelling at all.
    try:
        path_pattern = literal_path_pattern(finding.file_path)
    except PathNotExpressible as e:
        return {
            "success": False,
            "error_type": PATH_NOT_EXPRESSIBLE,
            "error": raw_controls_on_one_line(
                f"No suppression suggested for finding {finding_id}: {e}."
            ),
        }

    # A suppression with line_start and no line_end is open-ended (the matcher
    # reads it as "from this line to the end of the file"), so a finding that
    # reports one line gets a suppression that covers that one line.
    line_end = finding.line_end if finding.line_end is not None else finding.line_start
    try:
        suppression = AshSuppression(
            path=path_pattern,
            rule_id=finding.rule_id,
            line_start=finding.line_start,
            line_end=line_end,
            expiration=expiration_date,
            reason=reason,
        )
    except ValidationError as e:
        # The fields come from the finding and the client (the date is checked
        # above; a line number or a reason the model refuses is still possible):
        # answered as the tool's own refusal, described without the input, not
        # raised out of the tool as an unexpected error.
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"No suppression suggested for finding {finding_id}: {error_text(e)}"
            ),
        }

    suppression_dict = suppression.model_dump(exclude_none=True)
    suppression_yaml = _block_yaml_one_line_per_key(suppression_dict)

    return {
        "success": True,
        "yaml": suppression_yaml,
        "json": suppression_dict,
    }


def mcp_list_profiles() -> Dict[str, Any]:
    """List registered MCP config profiles by name + path SHA256.

    The path itself is intentionally not exposed — operators may register
    profiles with sensitive filesystem paths, and the SHA is sufficient for
    a client to detect "is this the same profile as before".
    """
    from automated_security_helper.cli.mcp.profile_registry import (
        get_profile_registry,
    )

    registry = get_profile_registry()
    profiles = sorted(
        (
            {"name": name, "path_sha256": entry.path_sha256}
            for name, entry in registry.items()
        ),
        key=lambda e: e["name"],
    )
    return {"profiles": profiles, "count": len(profiles)}


def mcp_select_profile(
    profile_name: str,
    *,
    patch_ops: Optional[list] = None,
    override_yaml: Optional[str] = None,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Bind a registered profile to the calling session.

    Three modes:
        * **static** — `patch_ops` and `override_yaml` are both None; the
          profile's resolved config is bound as-is.
        * **inherit-and-patch** — `patch_ops` is provided; the profile's
          config is patched through `apply_runtime_patch` (which enforces the
          MCP allowlist).
        * **override** — `override_yaml` is provided; the profile is
          replaced wholesale by the YAML, validated through `AshConfig`, and
          held to the same allowlist as `patch_ops`: the difference between
          the profile and the YAML is checked as the JSON-Patch that produces
          it (`apply_runtime_override`), so both modes are held to one set of
          rules.

    `patch_ops` and `override_yaml` are mutually exclusive.

    Every mode materializes the resolved config into the session's own sandbox
    and records the path, which is what makes the binding observable: a later
    scan that names no config is handed this path. Before that, the resolved
    config was stored in a field nothing read, so this call returned
    ``success: True`` and changed nothing a client could detect.

    Where it is written decides whose it is. The registered profile always goes
    to the session's ``config/`` directory, which counts as the operator's. A
    profile a client changed (a non-empty ``patch_ops``, or any ``override_yaml``)
    goes to ``client-config/``, which counts as the client's: the allowlist lets
    the client set those keys, and does not make its values the operator's. That
    copy is what ``config_path`` names, and every consumer resolves it with the
    client's rules against the registered profile in ``config/`` as the trusted
    base (``resolve_session_trusted_config_path``).

    Refused with ``error_type`` ``session_workspace_busy`` while another
    request holds the session's workspace (``sessions.writing_session_state``):
    the server removing a session unused longer than its time to live,
    ``clear_source``, or the end of the session; select the profile again once
    the hold ends. A ``set_source_git`` or ``set_source_zip_finalize`` in
    progress does not refuse it.
    """
    from automated_security_helper.cli.mcp.profile_registry import binding_writes
    from automated_security_helper.cli.mcp.sessions import (
        SESSION_WORKSPACE_BUSY,
        SessionWorkspaceBusyError,
        writing_session_state,
    )

    try:
        # The write hold keeps the sweep off the workspace; the binding lock
        # keeps another writer of this session's binding files (a rewrite of a
        # gone file, profile_registry._rematerialize_binding) from landing an
        # older profile's files after this one's. Taken inside the hold, as the
        # rewrite takes it.
        with writing_session_state(session_id), binding_writes(session_id):
            return _select_profile(
                profile_name,
                patch_ops=patch_ops,
                override_yaml=override_yaml,
                session_id=session_id,
            )
    except SessionWorkspaceBusyError as e:
        return {
            "success": False,
            "error": raw_controls_on_one_line(str(e)),
            "error_type": SESSION_WORKSPACE_BUSY,
        }


def _select_profile(
    profile_name: str,
    *,
    patch_ops: Optional[list],
    override_yaml: Optional[str],
    session_id: Optional[str],
) -> Dict[str, Any]:
    """:func:`mcp_select_profile`, once the session is held against the sweep."""
    from automated_security_helper.cli.mcp.profile_registry import (
        bind_session_config,
        client_values_present,
        get_profile_registry,
    )
    from automated_security_helper.config.runtime_patch import (
        RuntimePatchDeniedError,
        apply_runtime_override,
        apply_runtime_patch,
    )
    from automated_security_helper.config.ash_config import (
        AshConfig,
        RuntimeOverridesConfig,
        load_config_yaml,
    )
    import yaml as _yaml
    from pydantic import ValidationError as _ValidationError

    def _runtime_overrides_policy(profile_cfg: AshConfig) -> RuntimeOverridesConfig:
        # One reading of the profile's allowlist for both mutating modes, so
        # override_yaml cannot be checked against a different policy than
        # patch_ops, and the same reading the delivered-file check uses
        # (client_config_policy.policy_of), stale shipped defaults included.
        from automated_security_helper.config.client_config_policy import policy_of

        return policy_of(profile_cfg)

    if patch_ops is not None and override_yaml is not None:
        return {
            "success": False,
            "error": "patch_ops and override_yaml are mutually exclusive",
        }

    # Whether a client changed the profile, read once for both branches below: it
    # decides whether the client's copy is written, and a stored binding answers it
    # the same way (SessionState.client_changed).
    changed = client_values_present(patch_ops, override_yaml)

    registry = get_profile_registry()
    if profile_name not in registry:
        if not registry:
            return {
                "success": False,
                "error": raw_controls_on_one_line(
                    f"unknown profile {profile_name!r} (none registered)"
                ),
            }
        known = sorted(registry)
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"unknown profile {profile_name!r}; known: {', '.join(known)}"
            ),
        }

    entry = registry[profile_name]
    base_cfg: AshConfig = entry.config

    if override_yaml is not None:
        from automated_security_helper.config.config_sources import (
            refuse_past_expansion_bound,
        )
        from automated_security_helper.core.exceptions import ASHConfigSourceError

        try:
            # The client's own text, parsed with the config loader: safe tags
            # only and no aliases at all, so a recursive alias is refused while
            # the document is composed, as a parse error below.
            raw = load_config_yaml(override_yaml)
            # The same budgets the config chain applies to a file's anchors,
            # worded under this branch's error-prefix convention.
            refuse_past_expansion_bound(
                raw, "the document", "override_yaml validation error: "
            )
        except ASHConfigSourceError as exc:
            return {
                "success": False,
                "error": raw_controls_on_one_line(str(exc)),
            }
        except _yaml.YAMLError as exc:
            from automated_security_helper.config.config_sources import (
                parse_error_kind,
            )

            # The problem and its places, in the words the config loaders use
            # (parse_error_kind): where the parser stopped and, when it
            # differs, where the construct it was reading started. The
            # parser's whole message also repeats the line it stopped at,
            # values and all. The problem names what it found by kind, or by
            # a character, an alias or a tag.
            problem = getattr(exc, "problem", None)
            return {
                "success": False,
                "error": raw_controls_on_one_line(
                    "override_yaml parse error"
                    + (f": {problem}" if isinstance(problem, str) else "")
                    + f" {parse_error_kind(exc)}"
                ),
            }
        # The shape first, before anything iterates the document: the gate
        # below iterated whatever the client's text loaded to, so a list of
        # lists answered iteration's own TypeError as a generic tool error,
        # a number "'int' object is not iterable", and plain text was read
        # as its characters, "unknown top-level field(s)" naming each one
        # (measured through the tool). The kind only, never the value.
        if raw is not None and not isinstance(raw, dict):
            return {
                "success": False,
                "error": raw_controls_on_one_line(
                    "override_yaml validation error: the document must be a "
                    f"mapping, got {type(raw).__name__}"
                ),
            }
        # The keys' types, before the gate below reads them: YAML reads a
        # plain `on`, `1` or `2024-01-01` key as a boolean, a number or a
        # date, and the gate's set difference and join over such keys raised
        # the raw TypeError the shape check above exists to prevent. The
        # kinds only, never a key, which is the client's text.
        wrong_kinds = sorted(
            {type(key).__name__ for key in (raw or {}) if not isinstance(key, str)}
        )
        if wrong_kinds:
            return {
                "success": False,
                "error": raw_controls_on_one_line(
                    "override_yaml validation error: the top-level keys must "
                    f"be strings, got {', '.join(wrong_kinds)}"
                ),
            }
        # Strict-extra gate: AshConfig.model_config has extra='ignore' for
        # back-compat with end-user configs, but profiles are operator-
        # controlled deployment artifacts and should fail on typos.
        allowed = set(AshConfig.model_fields.keys())
        for finfo in AshConfig.model_fields.values():
            if finfo.alias:
                allowed.add(finfo.alias)
        unknown = sorted(set(raw or {}) - allowed)
        if unknown:
            return {
                "success": False,
                "error": raw_controls_on_one_line(
                    f"override_yaml validation error: unknown top-level "
                    f"field(s): {', '.join(unknown)}"
                ),
            }
        try:
            override_cfg = AshConfig.model_validate(raw or {}, strict=True)
        except _ValidationError as exc:
            # error_text: each entry of errors() holds the refused input, and
            # the response goes to the client.
            return {
                "success": False,
                "error": raw_controls_on_one_line(
                    f"override_yaml validation error: {error_text(exc)}"
                ),
            }
        try:
            new_cfg = apply_runtime_override(
                base_cfg,
                override_cfg,
                allowlist=_runtime_overrides_policy(base_cfg),
            )
        except RuntimePatchDeniedError as exc:
            return {
                "success": False,
                "error": raw_controls_on_one_line(f"override denied: {exc}"),
            }
        materialized = _materialize_or_error(
            session_id, base_cfg, new_cfg if changed else None
        )
        if isinstance(materialized, dict):
            return materialized
        config_path, trusted_config_path = materialized
        bind_session_config(
            session_id,
            config=new_cfg,
            profile_name=profile_name,
            override_yaml=override_yaml,
            config_path=config_path,
            trusted_config_path=trusted_config_path,
        )
        return {
            "success": True,
            "mode": "override",
            "profile_name": profile_name,
            "session_id": session_id or _default_session_id(),
            "config_path": config_path,
        }

    if patch_ops is not None:
        try:
            patched = apply_runtime_patch(
                base_cfg, patch_ops, allowlist=_runtime_overrides_policy(base_cfg)
            )
        except RuntimePatchDeniedError as exc:
            return {
                "success": False,
                "error": raw_controls_on_one_line(f"patch denied: {exc}"),
            }
        # An empty patch changes nothing, so there is no client value to keep apart.
        materialized = _materialize_or_error(
            session_id, base_cfg, patched if changed else None
        )
        if isinstance(materialized, dict):
            return materialized
        config_path, trusted_config_path = materialized
        bind_session_config(
            session_id,
            config=patched,
            profile_name=profile_name,
            patch_ops=patch_ops,
            config_path=config_path,
            trusted_config_path=trusted_config_path,
        )
        return {
            "success": True,
            "mode": "inherit_and_patch",
            "profile_name": profile_name,
            "session_id": session_id or _default_session_id(),
            "config_path": config_path,
        }

    materialized = _materialize_or_error(session_id, base_cfg, None)
    if isinstance(materialized, dict):
        return materialized
    config_path, trusted_config_path = materialized
    bind_session_config(
        session_id,
        config=base_cfg,
        profile_name=profile_name,
        config_path=config_path,
        trusted_config_path=trusted_config_path,
    )
    return {
        "success": True,
        "mode": "static",
        "profile_name": profile_name,
        "session_id": session_id or _default_session_id(),
        "config_path": config_path,
    }


def _materialize_or_error(
    session_id: Optional[str],
    registered: "AshConfig",
    patched: Optional["AshConfig"],
) -> Union[Tuple[str, str], Dict[str, Any]]:
    """Write the binding out, or return this tool's failure shape.

    ``profile_registry.materialize_session_binding`` writes ``registered`` to
    the session's ``config/`` and ``patched``, the client's version, to its
    ``client-config/``. Returns ``(config_path, trusted_config_path)`` on success
    and an error dict on failure, which the caller distinguishes with
    ``isinstance(..., dict)``. The alternative -- letting the
    exception escape -- would surface as an unhandled error from a tool whose
    other failure modes all return ``success: False``, so a client would need two
    ways to detect the same class of problem.

    Binding is NOT attempted when this fails. A bound config whose file does not
    exist is worse than no binding: every later scan would be handed a path to a
    missing file and fail with a config error naming a path the client never
    supplied.
    """
    from automated_security_helper.cli.mcp.profile_registry import (
        materialize_session_binding,
    )
    from automated_security_helper.config.environment_record import (
        EnvironmentValueInPath,
    )
    from automated_security_helper.core.resource_management.error_handling import (
        ErrorCategory,
    )

    try:
        materialized = materialize_session_binding(session_id, registered, patched)
    except EnvironmentValueInPath as exc:
        # Refused before any file is written (AshConfig.save builds the dump
        # first), and the message holds no value.
        return with_exit_code(
            {
                "success": False,
                "error": raw_controls_on_one_line(str(exc)),
                "error_type": ENV_VALUE_IN_LONGER_STRING,
                "error_category": ErrorCategory.INVALID_FORMAT.value,
            },
            REFUSED_CONFIG_EXIT_CODE,
        )
    except (OSError, RuntimeError) as exc:
        _logger.error(f"Could not materialize the session config: {exc}")
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                f"Profile resolved, but its config could not be written to this "
                f"session's workspace, so a scan could not be given it: {exc}"
            ),
            "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
        }
    # The moment the session's config is written is when leftover scan copies
    # beside it are swept; the sweep never fails the bind (its docstring). A
    # patched binding has two files in two directories, and a scan copies the
    # registered one as its trusted base, so both directories are swept.
    _sweep_stale_scan_snapshots(Path(materialized[0]))
    if materialized[1] != materialized[0]:
        _sweep_stale_scan_snapshots(Path(materialized[1]))
    return materialized


#: Names of copies already reported as dated in the future, so a copy that stays
#: for days is reported once. Bounded: past the cap the report is dropped, never
#: the sweep.
_FUTURE_DATED_REPORTED: set[str] = set()
_FUTURE_DATED_REPORT_CAP = 256

#: Set once the sweep has said that this host's identity cannot be read.
_UNREADABLE_IDENTITY_REPORTED = False


def _scan_copy_age(path: Path) -> float:
    """Seconds since *path* was last written; 0 where that cannot be read, so a
    file the sweep cannot date is kept.

    A modification time more than ``_CLOCK_SKEW_ALLOWANCE_SECONDS`` ahead of this
    clock is not a write time (a writer's clock far ahead, or a time set by
    hand), and would hold the copy until this clock passes it. The copy is then
    dated by its change time, which the writer cannot set, and the sweep says so
    once for that name.
    """
    try:
        status = path.lstat()
    except OSError:
        return 0.0
    now = time.time()
    if status.st_mtime - now <= _CLOCK_SKEW_ALLOWANCE_SECONDS:
        return max(0.0, now - status.st_mtime)
    if (
        path.name not in _FUTURE_DATED_REPORTED
        and len(_FUTURE_DATED_REPORTED) < _FUTURE_DATED_REPORT_CAP
    ):
        _FUTURE_DATED_REPORTED.add(path.name)
        _logger.warning(
            f"The scan copy {path.name} is dated more than a day ahead of this "
            "clock; its age is taken from its change time."
        )
    return max(0.0, now - status.st_ctime)


def _sweep_stale_scan_snapshots(profile: Path) -> None:
    """Remove scan copies beside *profile* that no current scan holds.

    A scan's runner discards its profile copy in its finally, but a process
    killed outright between the write and that finally leaves the copy --
    the profile's full content -- in the session's config directory, and
    nothing else removes it. The names are deterministic
    (_scan_snapshot_path), so a leftover is recognizable here, when the
    session's config is written: a copy whose scan id is still registered
    and whose scan is not over stays, since a scan started under an earlier
    binding may still read it -- "over" meaning ended AND its runner thread
    done, because the timeout closes the entry while the thread still runs.
    The registry is per process but the directory is not (servers on the
    default session share it), so a copy this registry does not know is
    judged by where its writer ran. One written on this host stays while the
    process whose pid its name records is still running and that process is
    not this one: a copy this process wrote is judged by the registry alone,
    so one it no longer holds goes even while its writer, this process, still
    runs. One written on
    another host, or with no host token, stays until it is older than
    _foreign_scan_copy_max_age_seconds(), since a pid read in a pid view that
    did not give it proves nothing, even when its writer is gone. Where this
    host cannot read its own identity the sweep says so once, and judges by age
    every copy but one this process's writer created (the copies it registered
    and has not discarded, tested first whatever identity the name or the sweep
    reads), which is swept like any copy it does not hold. A
    copy's age is its modification time, or its change time when the
    modification time sits more than a day ahead of this clock
    (_scan_copy_age). This process's identity is read once per sweep.
    A copy that cannot be removed does not fail the bind -- the next bind
    retries. A name under the prefix that does not parse as
    a copy's -- the id segment must be a UUID in the scan writer's own
    spelling (config_sources.parse_scan_copy_name) -- is some other file and
    stays as it was, and so is a symbolic link, whatever its name, since the
    writer takes its names exclusively and never creates one: the sweep never
    unlinks a file it cannot prove a scan wrote.
    """
    from automated_security_helper.config.config_sources import (
        SCAN_COPY_PREFIX,
        discard_scan_copy,
        is_registered_scan_copy,
        parse_scan_copy_name,
        scan_copy_writer_host,
        scan_copy_writer_pid,
    )

    registry = get_scan_registry()
    try:
        candidates = list(profile.parent.glob(f"{SCAN_COPY_PREFIX}*"))
    except OSError:
        return
    here = _this_host_token()
    global _UNREADABLE_IDENTITY_REPORTED
    if here is None and not _UNREADABLE_IDENTITY_REPORTED:
        _UNREADABLE_IDENTITY_REPORTED = True
        _logger.warning(
            "This host's identity cannot be read, so scan copies left beside "
            "the session profile by other processes are removed by age only "
            "not by whether their writer still runs."
        )
    for candidate in candidates:
        if candidate.is_symlink():
            # The writer takes its names exclusively (O_CREAT | O_EXCL),
            # which never creates a link, so a link is not a file a scan
            # wrote, whatever its name says.
            continue
        parsed = parse_scan_copy_name(candidate.name)
        if parsed is None:
            continue
        scan_id = parsed[0]
        entry = registry.get_scan(scan_id)
        # The status alone is not the test: the timeout and the BaseException
        # arm close the entry FAILED while the scan thread is still running,
        # and that thread may yet load its copy (the runner's finally waits
        # on runner_done for the same reason). occupies_its_directory is
        # "active, or closed with its runner not yet done".
        if entry is not None and entry.occupies_its_directory():
            continue
        # The registry is this process's own. Servers on the default session
        # share this directory (session_sandbox grants a per-session one only
        # for a real session id), so an id this registry does not know can be
        # a sibling server's live scan. On this host it stays while its writer
        # runs; a copy this process wrote is judged by the registry alone. On
        # another host, or on a shared filesystem, a pid is read in a pid view
        # that did not give it, so it proves nothing: the copy stays until it
        # is old. A copy with no identity (an older writer's, or a writer that
        # could not read its own) matches no host and takes the same path.
        if entry is None:
            written_on = scan_copy_writer_host(candidate.name)
            writer = scan_copy_writer_pid(candidate.name)
            # A copy this process's writer created (registered at O_EXCL
            # creation and not yet discarded) is its own, and
            # goes at once like any copy this process wrote and does not hold,
            # whatever identity the sweep or the name reads: this host's
            # identity can read differently between two calls, so a copy
            # written with a token can be swept without one, and the reverse.
            # The pid in the name is never the evidence: servers started from
            # one image share small pids and a session directory, so another
            # server's live copy can carry this process's pid and no token. A
            # copy that is not in the record takes the age path, which
            # includes a copy an earlier process of this server left under a
            # reused pid.
            if is_registered_scan_copy(candidate):
                pass
            elif here is None or written_on != here:
                if _scan_copy_age(candidate) < _foreign_scan_copy_max_age_seconds():
                    continue
            elif (
                writer is not None
                and writer != os.getpid()
                and _process_may_be_running(writer)
            ):
                continue
        try:
            candidate.unlink(missing_ok=True)
        except OSError:
            continue
        discard_scan_copy(candidate)


def _default_session_id() -> str:
    """Return the profile_registry DEFAULT_SESSION_ID without circular import."""
    from automated_security_helper.cli.mcp.profile_registry import (
        DEFAULT_SESSION_ID,
    )

    return DEFAULT_SESSION_ID


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

    The client names the URL and the server runs git, so what git can reach is
    the server's to decide. Refused before anything is created or cloned: an
    option-like or command-executing URL, a local path or ``file://`` URL
    (never cloned, whatever the scan roots allow), a scheme other than https
    or ssh, a host the operator did not list in ``ASH_MCP_GIT_ALLOWED_HOSTS``
    (empty by default, so every remote is refused until the operator names
    one), and any ``ssh_key_id``, because no keys are registered. git then runs
    without the server's credentials or configuration; see
    ``source_delivery._git_environment``. HTTP redirects are not followed;
    give the URL the host redirects to (for example with the ``.git`` suffix).

    A re-delivery needs room for both trees at once: the new clone is made beside
    the delivered source, which is deleted only after it. When the disk is short,
    call ``clear_source`` first to free the delivered one. A clone, fetch or checkout
    that fails for want of space returns git's own message, with that advice added
    when the session has a delivered source to free.

    Args:
        url: Remote URL to clone: ``https://``, ``ssh://`` or ``user@host:path``.
        ref: Optional branch/tag/commit. ``None`` uses the remote default.
        ssh_key_id: Must be None; no ssh keys are registered on the server.
            Raw private keys are not accepted over the wire.
        depth: Shallow-clone depth, a whole number of commits from 1 to 1000
            (``source_delivery.MAX_CLONE_DEPTH``). Defaults to 1.
        session_id: MCP session identifier scoping the workspace.

    Returns:
        ``{"success": True, "source_dir": str}`` on success. Otherwise
        ``{"success": False, "error": str, "error_type": str}``, where
        ``error_type`` is one of:

        - ``clone_url_not_permitted``: ``url`` begins with ``-`` or uses the
          ``ext::`` transport, both of which make git run a command, holds a
          control character or a lone surrogate, or its host cannot be read;
        - ``clone_ref_not_permitted``: ``ref`` begins with ``-``, or holds a
          control character (NUL included) or a lone surrogate;
        - ``invalid_clone_depth``: ``depth`` is below 1 or above 1000 (the limit is
          on how much history is fetched);
        - ``local_clone_source_refused``: ``url`` is a local path or ``file://``
          URL, which would read the server's own filesystem (with
          ``error_category``);
        - ``clone_host_not_permitted``: the operator did not list the host in
          ``ASH_MCP_GIT_ALLOWED_HOSTS``;
        - ``ssh_key_not_registered``: an ``ssh_key_id`` was named;
        - ``source_delivery_busy``: a scan of the session runs, as
          ``set_source_zip_finalize`` reports the same refusal;
        - ``clone_timed_out``: git ran past its time limit and was stopped;
        - ``invalid_session_id``: the session id is not one a workspace can be
          made for;
        - ``git_clone_failed`` or ``git_checkout_failed``: git ran and failed,
          with git's own message in ``error``, or git could not be run at all
          (not on PATH, or not with the url or the ref given);
        - ``session_workspace_unavailable``: the session's workspace could not
          take the clone: a directory of it could not be created (no space, no
          permission, a file in its place), the previously delivered source could
          not be moved aside for it, or the clone could not be moved into place
          (after a few attempts). ``error`` has the path and the OS error.

        Every refusal is decided before anything is created or cloned. The clone
        is made in a staging directory beside ``source`` and replaces the
        previously delivered source only once it has worked, so a delivery that
        fails for any of these reasons leaves that source, and the record that
        names it, in place; a partial clone that cannot be fully deleted stays in
        the staging directory, logged, for the next delivery to delete, and the
        error returned is still git's own. The one
        exception is a clone that could not be moved into place after the previous
        source had been moved aside and could not be put back: the session's
        recorded source then names a path that is gone, and ``run_ash_scan`` with
        no ``source_dir`` answers ``delivered_source_missing`` until the source is
        delivered again; that next delivery puts the previous source back first.

        A ``session_workspace_unavailable`` that names a refused rename can be
        retried with the same call: the refusal is usually a program holding a
        handle inside a tree (a virus scanner, a file indexer), and it passes.
    """
    from automated_security_helper.cli.mcp.source_delivery import (
        ASH_MCP_GIT_ALLOWED_HOSTS_ENV,
        CLONE_REF_NOT_PERMITTED,
        CLONE_TIMED_OUT,
        CLONE_URL_NOT_PERMITTED,
        GIT_CLONE_FAILED,
        INVALID_CLONE_DEPTH,
        SESSION_WORKSPACE_UNAVAILABLE,
        SOURCE_DELIVERY_BUSY,
        CloneRefusedError,
        GitCommandError,
        GitTimeoutError,
        InvalidSessionIdError,
        SessionWorkspaceError,
        SourceDeliveryBusyError,
        _refuse_ssh_key_id,
        _reject_option_like,
        _validate_clone_url,
        _validated_clone_depth,
        clone_endpoint_allowed,
        git_allowed_hosts,
        local_clone_path,
        remote_clone_endpoint,
        set_source_git,
    )

    def refused(error: Exception, error_type: str) -> Dict[str, Any]:
        # Described, not quoted: a ValueError or RuntimeError from set_source_git,
        # or an OSError it wraps, could be or come from a pydantic ValidationError.
        return {
            "success": False,
            "error": raw_controls_on_one_line(error_text(error)),
            "error_type": error_type,
        }

    # The URL's own rules first, so an option-like or command-executing URL gets
    # that refusal rather than being read as a filesystem path.
    try:
        _validate_clone_url(url)
    except ValueError as e:
        return refused(e, CLONE_URL_NOT_PERMITTED)
    if ref:
        try:
            _reject_option_like(ref, "ref")
        except ValueError as e:
            return refused(e, CLONE_REF_NOT_PERMITTED)
    try:
        _validated_clone_depth(depth)
    except ValueError as e:
        return refused(e, INVALID_CLONE_DEPTH)

    if local_clone_path(url) is not None:
        return {
            "success": False,
            "error": (
                "set_source_git clones from a remote https or ssh url only; a "
                "local path or file:// url would read the server's own "
                "filesystem. Name a directory the operator granted as "
                "run_ash_scan's source_dir instead."
            ),
            "error_type": "local_clone_source_refused",
            "error_category": ErrorCategory.INVALID_PATH.value,
        }

    try:
        scheme, host, port = remote_clone_endpoint(url)
    except ValueError as e:
        return {
            "success": False,
            "error": raw_controls_on_one_line(str(e)),
            "error_type": "clone_url_not_permitted",
        }
    if not clone_endpoint_allowed(scheme, host, port):
        if host in git_allowed_hosts():
            where = (
                f"Refusing to clone over {scheme} on port {port} from {host!r}: "
                f"{ASH_MCP_GIT_ALLOWED_HOSTS_ENV} lists the host, but not for "
                f"that scheme and port. An entry is [scheme://]host[:port], and a "
                f"bare host stands for the default port (https 443, ssh 22). "
            )
        else:
            where = (
                f"Refusing to clone from {host!r}: it is not in "
                f"{ASH_MCP_GIT_ALLOWED_HOSTS_ENV}, the hosts the operator lets "
                f"this server clone from. The list is empty unless the operator "
                f"sets it. "
            )
        return {
            "success": False,
            "error": raw_controls_on_one_line(
                where + "Ask the operator to add the host, or deliver the tree "
                "with set_source_zip_chunk and set_source_zip_finalize."
            ),
            "error_type": "clone_host_not_permitted",
        }

    try:
        _refuse_ssh_key_id(ssh_key_id)
    except ValueError as e:
        return {
            "success": False,
            "error": raw_controls_on_one_line(str(e)),
            "error_type": "ssh_key_not_registered",
        }

    try:
        source_dir = set_source_git(
            url=url,
            ref=ref,
            ssh_key_id=ssh_key_id,
            depth=depth,
            session_id=session_id,
        )
    except SourceDeliveryBusyError as e:
        # A RuntimeError too, so it is caught first: a client retries this one
        # after the scan ends, and branches on error_type to know that.
        return {
            "success": False,
            "error": raw_controls_on_one_line(str(e)),
            "error_type": SOURCE_DELIVERY_BUSY,
        }
    except GitTimeoutError as e:
        return {
            "success": False,
            "error": raw_controls_on_one_line(str(e)),
            "error_type": CLONE_TIMED_OUT,
        }
    except CloneRefusedError as e:
        # Every other clone refusal names its own error_type (a clone over the size
        # limit, a tree that cannot be read), so it is returned as that type and
        # not as a failed clone.
        return {
            "success": False,
            "error": raw_controls_on_one_line(str(e)),
            "error_type": e.error_type,
        }
    except SessionWorkspaceError as e:
        return refused(e, SESSION_WORKSPACE_UNAVAILABLE)
    except GitCommandError as e:
        return refused(e, e.error_type)
    except RuntimeError as e:
        # How set_source_git reported a git failure before GitCommandError, and
        # still the type it documents; a substitute raising it gets the same
        # answer a failed clone does.
        return refused(e, GIT_CLONE_FAILED)
    except InvalidSessionIdError as e:
        # The session id set_source_git makes the workspace for, refused before
        # the session is taken.
        return refused(e, "invalid_session_id")
    # No arm for any other ValueError. url, ref, depth and the session id passed
    # their checks, and a step git cannot be started for is a GitCommandError with
    # that step's type, caught above, so a ValueError reaching here comes from a
    # bug. It is not a failed clone: it goes to the tool's own handler, which logs
    # it as unexpected and answers with its class name.

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
        failure (out-of-order, oversize, malformed b64), and with
        ``error_type`` ``session_workspace_busy`` while the server removes the
        session's workspace for being unused longer than its time to live
        (send the upload again from its first chunk), or ``error_type``
        ``session_workspace_unavailable`` when the session's workspace
        directory could not be created.
    """
    from automated_security_helper.cli.mcp.sessions import (
        SESSION_WORKSPACE_BUSY,
        SessionWorkspaceBusyError,
    )
    from automated_security_helper.cli.mcp.source_delivery import (
        SESSION_WORKSPACE_UNAVAILABLE,
        SessionWorkspaceError,
        set_source_zip_chunk,
    )

    try:
        result = set_source_zip_chunk(
            upload_id=upload_id,
            sequence=sequence,
            data_b64=data_b64,
            last=last,
            session_id=session_id,
        )
    except SessionWorkspaceBusyError as e:
        return {
            "success": False,
            "error": raw_controls_on_one_line(str(e)),
            "error_type": SESSION_WORKSPACE_BUSY,
        }
    except SessionWorkspaceError as e:
        return {
            "success": False,
            "error": raw_controls_on_one_line(error_text(e)),
            "error_type": SESSION_WORKSPACE_UNAVAILABLE,
        }
    except ValueError as e:
        return {"success": False, "error": raw_controls_on_one_line(error_text(e))}

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
        oversize zip, oversize extraction, too-many-files, any
        path-traversal/symlink-out-of-tree entry, or assembled bytes that are
        not a zip archive (``zipfile.BadZipFile``: the checksum matched, so the
        client sent what it meant to and packaged it wrong), and with ``error_type``
        ``session_workspace_unavailable`` when the session's workspace could not
        take the tree: a directory of it could not be created, the previous tree
        could not be renamed aside (nothing is deleted where it stands), the
        extracted one could not be moved into place, whatever the OS error. An
        upload that never received its last chunk returns ``error`` with no
        ``error_type``. A failure on disk while the archive is read or extracted
        (no space, no permission, a file that vanished) is not one of these: the
        server answers it with the exception's class name as ``error_type``. The
        previous tree stays delivered and the uploaded zip is kept, so the same
        call can be sent again. When the previous tree could not be put back
        either, the session's recorded source names a path that is gone, and
        ``run_ash_scan`` with no ``source_dir`` answers ``delivered_source_missing``.
    """
    from automated_security_helper.cli.mcp.source_delivery import (
        SESSION_WORKSPACE_UNAVAILABLE,
        SOURCE_DELIVERY_BUSY,
        SessionWorkspaceError,
        SourceDeliveryBusyError,
        UploadNotFoundError,
        set_source_zip_finalize,
    )

    try:
        source_dir = set_source_zip_finalize(
            upload_id=upload_id,
            expected_sha256=expected_sha256,
            session_id=session_id,
        )
    except SourceDeliveryBusyError as e:
        return {
            "success": False,
            "error": raw_controls_on_one_line(str(e)),
            "error_type": SOURCE_DELIVERY_BUSY,
        }
    except SessionWorkspaceError as e:
        return {
            "success": False,
            "error": raw_controls_on_one_line(error_text(e)),
            "error_type": SESSION_WORKSPACE_UNAVAILABLE,
        }
    except (UploadNotFoundError, ValueError, zipfile.BadZipFile) as e:
        # BadZipFile is the client's packaging error the delivery documents
        # (set_source_zip_finalize), answered as the refusals are, not left to
        # the generic handler as an unexpected error with a class name.
        return {"success": False, "error": raw_controls_on_one_line(error_text(e))}
    # No arm for any other OSError. The delivery maps the failures of the session's
    # workspace itself (a directory that cannot be created, a swap that cannot
    # complete) to SessionWorkspaceError, caught above. One raised while reading the
    # archive or extracting a member is the archive's, not the workspace's, and goes
    # to the tool's own handler, which logs it and answers with its class name. That
    # includes a FileNotFoundError from a file that vanished during the extraction:
    # only an upload that never arrived (UploadNotFoundError) is answered above as
    # the client's mistake.

    return {"success": True, "source_dir": str(source_dir)}


def mcp_clear_source(session_id: str) -> Dict[str, Any]:
    """Wipe the session workspace and forget any recorded ``source_dir``.

    Idempotent: missing workspaces succeed. Refused while a scan of the session
    runs, because the scan is reading the tree.

    Args:
        session_id: MCP session identifier.

    Returns:
        ``{"success": True}``, or ``{"success": False, "error": str,
        "error_type": "source_delivery_busy"}`` while a scan of the session runs.
    """
    from automated_security_helper.cli.mcp.source_delivery import (
        SOURCE_DELIVERY_BUSY,
        SourceDeliveryBusyError,
        clear_source,
    )

    try:
        clear_source(session_id=session_id)
    except SourceDeliveryBusyError as e:
        return {
            "success": False,
            "error": raw_controls_on_one_line(str(e)),
            "error_type": SOURCE_DELIVERY_BUSY,
        }
    return {"success": True}
