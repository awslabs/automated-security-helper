#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Scan registry and management components for ASH MCP server.

This module provides classes and functions for managing scan metadata and tracking
active scans. It implements a thread-safe registry to track active scans and
provides functions for listing, cancelling, and cleaning up scans.
"""

import itertools
import os
import signal
import uuid
from datetime import datetime
from enum import Enum
from pathlib import Path
from threading import Event, Lock
from time import monotonic

from automated_security_helper.core.cancellation import CancelEvent
from automated_security_helper.core.constants import ASH_EXIT_CODES
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_tracking import (
    MCScannerStatus,
    ScanProgress,
    assess_coverage,
    coverage_has_gap,
    create_scan_progress_from_files,
    load_aggregated_results_model,
    summarize_scanner_statuses,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.redacted_model import value_tuple


def _canonical_directory(directory_path: str) -> Path:
    """Reduce a caller-supplied directory string to one comparable form.

    Every directory-keyed decision in this module used to compare the raw string
    it was handed. That made ``/proj`` and ``/proj/`` two different directories,
    as it did ``/proj/../proj`` and ``/proj``, so ``register_scan`` admitted a
    second active scan on a tree that already had one and both then wrote into
    ``<proj>/.ash/ash_output``: the same source examined twice, its findings
    attributed twice, its suppressions applied twice, and two writers racing on
    one output tree.

    ``Path.resolve()`` and not a trailing-separator strip or a prefix test. A
    prefix test collapses ``proj`` and ``proj-backup``, which are two
    directories; resolve() also follows symlinks and collapses ``..``, which a
    string rule cannot.

    Returns the path unresolved rather than raising. Callers here have already
    run ``validate_directory_path``, which requires the directory to exist, so
    this is a guard against a platform refusing to resolve a path that exists
    rather than an expected branch -- and falling back to the raw form restores
    the old comparison for that one entry instead of failing the call.

    ``RuntimeError`` is what ``Path.resolve`` raises for a symlink loop on
    Python 3.10 to 3.12 (``OSError`` with ELOOP from 3.13), and ``ValueError``
    what it raises for a NUL byte in the string. Caught too: this used to run
    over every entry at each registration, so one historical entry whose
    directory had since become a loop made every later ``register_scan`` raise.
    """
    try:
        return Path(directory_path).resolve()
    except (OSError, RuntimeError, ValueError):
        return Path(directory_path)


class MCScanStatus(Enum):
    """Status of a scan.

    ``INCOMPLETE`` is terminal, like ``COMPLETED``: the run finished and its results
    are readable, but coverage has a gap. One or more selected scanners did not
    complete (MISSING or ERROR, or lost some of their targets), no scanner reached a
    verdict, a converter did not run, a rule could not be evaluated, or a content
    database was past its declared age bound. These are
    the conditions ``_compute_exit_code`` exits 1 for when results exist. It is kept
    apart from ``FAILED`` because exit 1 also means a crash, and a client that is
    shown ``failed`` for both cannot tell "read these partial results" from "there
    is nothing to read".
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    INCOMPLETE = "incomplete"
    FAILED = "failed"
    CANCELLED = "cancelled"


#: Terminal statuses whose run finished and left results to read: the
#: ``results_available`` of a progress response, unless the results file has
#: since become unreadable (``check_scan_progress`` then reports False with the
#: reason in ``error_message``, the status unchanged). ``coverage_complete`` is
#: the separate answer to "did it cover everything".
FINISHED_WITH_RESULTS = frozenset({MCScanStatus.COMPLETED, MCScanStatus.INCOMPLETE})

#: Every status a scan ends in. ``is_complete`` in a progress response is true for
#: these: it answers "has the scan ended", which is what the server tells clients
#: to poll on. ``results_available`` answers "are there results", true for
#: FINISHED_WITH_RESULTS only.
ENDED = frozenset(
    {
        MCScanStatus.COMPLETED,
        MCScanStatus.INCOMPLETE,
        MCScanStatus.FAILED,
        MCScanStatus.CANCELLED,
    }
)


#: The session a scan belongs to when its registrar named none: stdio's single
#: client and in-process callers. The same value as
#: ``cli.mcp.profile_registry.DEFAULT_SESSION_ID``, spelled here rather than
#: imported because this module sits below the MCP CLI package.
DEFAULT_SCAN_SESSION = "__default__"


def _owner(session_id: Optional[str]) -> str:
    """The session a registry entry is recorded under, or looked up for."""
    return session_id or DEFAULT_SCAN_SESSION


def _empty_coverage() -> Dict[str, Any]:
    """The coverage payload of a scan with no gap to report.

    The same key set as ``ScanIncompleteness.to_payload()``, ``could_not_stop``
    included: without it a progress response's keys depended on whether the
    runner had recorded coverage, so a client reading the key of a running or
    failed scan got KeyError where a finished one answered.
    """
    return {
        "incomplete_scanners": [],
        "no_scanner_ran": False,
        "incomplete_converters": [],
        "unevaluated_rules": [],
        "stale_content_databases": [],
        "could_not_stop": [],
    }


#: The order scans were registered in, process-wide. Two registrations inside
#: one clock tick tie on ``start_time``, and a wall clock that steps back
#: reverses them, so which of two scans of one output tree is the EARLIER one
#: is read from this counter and never from the clock
#: (``ScanRegistry._record_supersession``). Whether the later one supersedes
#: the earlier is a separate question, answered when the later scan claims the
#: tree: see ``ScanRegistryEntry.later_scan_ids``.
_REGISTRATION_SEQUENCE = itertools.count(1)


class ScanRegistryEntry:
    """Entry in the scan registry."""

    def __init__(
        self,
        scan_id: str,
        directory_path: str,
        output_directory: str,
        severity_threshold: Optional[str] = "MEDIUM",
        config_path: Optional[str] = None,
        session_id: Optional[str] = None,
        slot: Optional[str] = None,
        requested_severity_threshold: Optional[str] = None,
        environment_values: Tuple[str, ...] = (),
    ):
        """
        Initialize a scan registry entry.

        Args:
            scan_id: Unique identifier for the scan
            directory_path: Path to the directory being scanned
            output_directory: Path to the output directory for scan results
            severity_threshold: The threshold the scan's findings are judged by,
                when that is known up front (a workspace project's own). None
                otherwise; the runner records the value the scan used when it
                finishes with results.
            requested_severity_threshold: The threshold the client asked for,
                if any. Kept apart from ``severity_threshold``: the scan runs at
                the stricter of it and its config's, so the request is not the
                threshold that applies, and reporting it as such said CRITICAL
                for a scan judged at MEDIUM.
            config_path: Optional path to ASH configuration file
            session_id: The MCP session that started the scan. Only that session
                sees the entry through a session-scoped lookup. Not part of
                ``to_dict``: the owner is never reported, not even to itself.
            slot: The max_concurrent_scans slot the scan holds, when it shares one
                with other entries: the projects of one workspace scan. None for
                a scan that holds a slot of its own.
            environment_values: The values the run's configuration read from the
                environment. The registry redacts every error message it applies
                with them, so a failure arm that closes the entry with a bare
                exception's text is backstopped at the one sink the arms share.
                They exist to be hidden: ``to_dict`` is an explicit allowlist
                and never includes them.
        """
        self.scan_id = scan_id
        self.session_id = _owner(session_id)
        self.slot = slot
        self.environment_values = tuple(environment_values)
        self.directory_path = directory_path
        # The directory as one comparable form, fixed at registration. Every
        # directory-keyed decision compares this, not a re-resolution of the raw
        # string: resolved again at each lookup, a symlink retargeted after the
        # scan started made the entry occupy whatever the link pointed at now,
        # admitting a second scan of the directory it was scanning and blocking
        # an unrelated one.
        self.canonical_directory = _canonical_directory(directory_path)
        self.output_directory = output_directory
        # The output tree as one comparable form too, fixed at registration like
        # canonical_directory. Two uses: two scans of different source
        # directories that name the same output directory would write one
        # tree, so register_scan refuses the second; and whether a later scan
        # took this scan's results over is a question about the OUTPUT tree,
        # not the source directory, so a later scan of the same source that
        # writes elsewhere leaves this scan's files untouched.
        self.canonical_output_directory = _canonical_directory(output_directory)
        self.start_time = datetime.now()
        # Position in the registration order; see _REGISTRATION_SEQUENCE.
        self.registration_seq = next(_REGISTRATION_SEQUENCE)
        # The ids of the later scans of this output tree that have CLAIMED it:
        # recorded by ScanRegistry._record_supersession when such a scan is
        # marked running, or is closed after it ran, never at registration. A
        # scan registered and then cancelled or failed before anything ran (a
        # workspace batch rolled back marks its entries CANCELLED) touched no
        # file, so it is not here; recorded at registration, it hid this scan's
        # results behind a scan that never wrote. Kept on this entry so the fact
        # survives the later scan's removal from the registry: worked out from
        # registry membership alone, cleaning the later scan up made this
        # scan read the later scan's files as its own again.
        self.later_scan_ids: List[str] = []
        # Whether this scan has been recorded on the earlier scans of its output
        # tree (_record_supersession). Recorded once, at the first claim.
        self.claimed_output_tree = False
        self.end_time: Optional[datetime] = None
        self.status = MCScanStatus.PENDING
        self.severity_threshold = severity_threshold
        self.requested_severity_threshold = requested_severity_threshold
        self.config_path = config_path
        self.process_id: Optional[int] = None
        self.error_message: Optional[str] = None
        # The code the CLI exits with for how the scan ended, when the runner
        # knows it: a scan ASH refused or gave up records the code it exited
        # with. None otherwise; an MCP scan runs without the findings gate, so a
        # scan that finished has no CLI verdict to record.
        self.exit_code: Optional[int] = None
        self.warnings: List[str] = []
        # What the runner recorded about coverage when it closed the entry: the
        # ScanIncompleteness.to_payload() shape. None until a runner records one.
        self.coverage: Optional[Dict[str, Any]] = None
        # Set when the scan is cancelled. The runner runs the scan inside
        # core.cancellation.cancel_scope(cancel_event), so setting it stops the
        # scan at its next check, its running scanner's child process included.
        # An in-process scan has no process to signal, so this is the only way a
        # cancel reaches it.
        self.cancel_event = CancelEvent()
        # Set by the runner when the scan ended and the previous scan's results
        # were put back in its output directory (core/previous_results.py). The
        # files there are then not this scan's, and its progress does not read
        # them as its own.
        self.output_holds_previous_results = False
        # Whether an in-process runner (mcp_tools._run_scan_async, or the
        # workspace thread of cli/mcp/workspace.py for a workspace project)
        # drives this scan, and whether it has finished: its scan thread has
        # stopped and has settled the output directory. A cancel or the timeout closes the entry
        # at once, while that thread may run for seconds more, stopping its
        # scanner's child process and putting the previous results back; a new
        # scan of the directory in that window would have its output removed by
        # that restore. See occupies_its_directory.
        self.has_runner = False
        self.runner_done = Event()
        # The scanner tools a stop could not end, as (tool, pid) pairs, put here
        # by record_cancel_outcome from the records the scan's cancel event
        # collected. A tool still running can write into the output directory
        # after the stop, so the entry keeps its directory while one of them
        # runs (occupies_its_directory). Empty for a scan nothing stopped.
        self.could_not_stop: Tuple[Tuple[str, int], ...] = ()
        # The start time of each pid in could_not_stop as the system recorded
        # it when the pair was recorded (_process_start_time), or None where
        # the system does not tell. A pid the system has since given to another
        # process carries another start time, so the probe reads it as gone
        # instead of holding the directory until the stranger ends; a zombie
        # keeps its start time and stays until its runner reaps it.
        self.tool_start_times: Dict[int, Optional[str]] = {}
        # Set while remove_output_of_scan deletes this scan's output tree off
        # the registry lock, and set-and-cleared when the delete has ended,
        # whatever its outcome. register_scan waits on it for a scan of the
        # same output tree; remove_output_of_scan refuses a second removal of
        # the tree while it is set. None otherwise.
        self.output_removal: Optional[Event] = None
        # Set when check_scan_progress closed this entry from a results file
        # while it was PENDING with no runner. That file can be a previous
        # scan's, so the runner's later RUNNING claim is admitted for such an
        # entry (and clears what the file put there); for an entry a cancel or
        # a runner closed, the claim is refused.
        self.closed_from_file = False

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the entry to a dictionary for serialization.

        Returns:
            Dictionary representation of the entry
        """
        return {
            "scan_id": self.scan_id,
            "directory_path": self.directory_path,
            "output_directory": self.output_directory,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "status": self.status.value,
            "severity_threshold": self.severity_threshold,
            "requested_severity_threshold": self.requested_severity_threshold,
            "config_path": self.config_path,
            "process_id": self.process_id,
            "error_message": self.error_message,
            "warnings": self.warnings,
            "coverage": self.coverage,
        }

    def mark_running(self, process_id: Optional[int] = None) -> None:
        """
        Mark the scan as running.

        Args:
            process_id: Optional process ID of the scan process

        A running scan has not ended: whatever an earlier close recorded (the
        end time, an error message, coverage, an exit code) is cleared, so an
        entry reopened from a file-derived close does not carry that file's
        coverage and error text into the new run's result.
        """
        self.status = MCScanStatus.RUNNING
        self.process_id = process_id
        self.end_time = None
        self.error_message = None
        self.coverage = None
        self.exit_code = None
        self.closed_from_file = False

    def mark_completed(self) -> None:
        """Mark the scan as completed."""
        self.status = MCScanStatus.COMPLETED
        self.end_time = datetime.now()

    def mark_incomplete(self) -> None:
        """Mark the scan as finished with partial coverage."""
        self.status = MCScanStatus.INCOMPLETE
        self.end_time = datetime.now()

    def mark_failed(self, error_message: str) -> None:
        """
        Mark the scan as failed.

        Args:
            error_message: Error message explaining the failure
        """
        self.status = MCScanStatus.FAILED
        self.end_time = datetime.now()
        self.error_message = error_message

    def mark_cancelled(self) -> None:
        """Mark the scan as cancelled, and tell its runner to stop it."""
        self.status = MCScanStatus.CANCELLED
        self.end_time = datetime.now()
        self.cancel_event.set()

    def add_warning(self, warning: str) -> None:
        """
        Add a warning message to the scan.

        Args:
            warning: Warning message to add
        """
        self.warnings.append(warning)

    def is_active(self) -> bool:
        """
        Check if the scan is active.

        Returns:
            True if the scan is pending or running, False otherwise
        """
        return self.status in [MCScanStatus.PENDING, MCScanStatus.RUNNING]

    def occupies_its_directory(self) -> bool:
        """Whether the scan may still run, or write, in its directory.

        True while it is active, after it was closed for as long as its runner
        has not finished, and after that for as long as a scanner tool its stop
        could not end (``could_not_stop``) is still running: such a tool writes
        into the output directory on its own clock, and the runner's finish says
        nothing about it. register_scan refuses another scan of the directory,
        and counts the scan against max_concurrent_scans, while this holds.
        """
        if self.is_active() or (self.has_runner and not self.runner_done.is_set()):
            return True
        return self.a_surviving_tool_is_running()

    def a_surviving_tool_is_running(self) -> bool:
        """Whether a scanner tool the cancel could not end still runs, by its pid.

        The pid is read with the start time recorded for it, so a pid the
        system has reused for another process does not count as the tool.
        """
        return any(
            not _pid_was_reused(pid, self.tool_start_times.get(pid))
            and _tool_may_be_running(pid)
            for _tool, pid in self.could_not_stop
        )

    def tool_display_names(self) -> List[str]:
        """The scanner tools the cancel could not end, by basename, in order, once each.

        A tool is recorded as argv0 as spawned, which can be a full path on the
        server; what leaves the registry in a refusal or a coverage payload is
        the basename (:func:`_shown_tool_name`), as the entry's own warning
        names it on a network transport (``record_cancel_outcome``): a remote
        client has no use for the server's path and should not learn it.
        """
        return list(
            dict.fromkeys(_shown_tool_name(tool) for tool, _pid in self.could_not_stop)
        )

    def stopped_by_the_server(self) -> bool:
        """Whether a cancel, the scan timeout, or a cancelled runner task ended this scan.

        CANCELLED is a client's cancel. FAILED with the cancel event set is the
        timeout or a cancelled runner task: each closes the entry FAILED first,
        with its own reason, and sets the event under the same lock. A FAILED
        scan whose event is clear ended on its own error, and nothing stopped
        it, so a stop's outcome does not belong to it.
        """
        if self.status == MCScanStatus.CANCELLED:
            return True
        return self.status == MCScanStatus.FAILED and self.cancel_event.is_set()


def _without_process_ids(text: str) -> str:
    """*text* with every ``(pid N)`` parenthetical dropped (utils/subprocess_utils).

    Imported at the call, not at the module: the helper is the one spelling of
    the pid parenthetical the executor writes and the only redactor of it, and
    only a remote read (``check_scan_progress(..., name_process_ids=False)``)
    needs it, so a tree without it still imports this module and serves every
    local read.
    """
    from automated_security_helper.utils.subprocess_utils import without_process_ids

    return without_process_ids(text)


def _coverage_without_process_ids(payload: Dict[str, Any]) -> Dict[str, Any]:
    """A copy of a coverage payload whose ``could_not_stop`` reasons name no pid.

    The payload is the entry's stored coverage (or the empty one), so it is not
    changed in place: the rows are copied with their ``reason`` redacted and
    every other key is the same object.
    """
    rows = payload.get("could_not_stop")
    if not isinstance(rows, list):
        return payload
    shown = []
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("reason"), str):
            shown.append({**row, "reason": _without_process_ids(row["reason"])})
        else:
            shown.append(row)
    return {**payload, "could_not_stop": shown}


def _claims_output_tree(
    status: MCScanStatus, *, was_pending: bool, had_runner: bool
) -> bool:
    """Whether moving to ``status`` means the scan has written, or is writing, its tree.

    Marked RUNNING, a scan is about to write its output tree; closed COMPLETED
    or INCOMPLETE, it ran. Closed FAILED or CANCELLED, it ran only when it had
    left PENDING or a runner had claimed it (``had_runner``): a scan registered
    and then cancelled or failed before anything ran, as a workspace batch
    rolled back is, touched no file. The earlier scans of the tree are recorded
    as superseded on a claim and never on a registration
    (``ScanRegistry._record_supersession``).
    """
    if status in (
        MCScanStatus.RUNNING,
        MCScanStatus.COMPLETED,
        MCScanStatus.INCOMPLETE,
    ):
        return True
    if status in (MCScanStatus.FAILED, MCScanStatus.CANCELLED):
        return not was_pending or had_runner
    return False


def _process_start_time(pid: int) -> Optional[str]:
    """The start time the system records for *pid*, or None where it does not say.

    Read from ``/proc/<pid>/stat`` (its field 22, ``starttime``, in clock ticks
    since boot), which is the Linux fact that tells a process from the one the
    system later gave its pid to. None on a system without ``/proc`` (Windows,
    macOS), for a pid with no such entry, or on any read error: the caller then
    has no start time to compare and falls back to the liveness probe alone, so
    the check is Linux-only and says so here.
    """
    if pid <= 0 or os.name == "nt":
        return None
    try:
        with open(f"/proc/{pid}/stat", "rb") as handle:
            stat_line = handle.read()
    except OSError:
        return None
    # The command name sits in parentheses and may hold spaces; the fields
    # after it are split from the text after the last ")".
    _head, _sep, tail = stat_line.rpartition(b")")
    fields = tail.split()
    # state is fields[0] (overall field 3); starttime is overall field 22.
    if len(fields) < 20:
        return None
    return fields[19].decode("ascii", "replace")


def _pid_was_reused(pid: int, started: Optional[str]) -> bool:
    """Whether *pid* now names a process other than the one recorded with *started*.

    ``started`` is the start time ``_process_start_time`` read when the tool was
    recorded. True only when both that and the start time read now are known
    and differ: the system has given the pid to another process since, so the
    recorded tool is gone whatever the liveness probe says of the pid. With no
    recorded time, or none readable now (a system without ``/proc``, a pid with
    no entry), nothing is known and the probe alone decides, as before. A
    zombie keeps its entry and its start time, so it is not read as reused.
    """
    if started is None:
        return False
    now = _process_start_time(pid)
    return now is not None and now != started


def _tool_may_be_running(pid: int) -> bool:
    """Whether a scanner tool's process, named by pid, may still be running.

    False only when the pid provably names no process. On POSIX ``kill(pid, 0)``
    delivers nothing and only asks: no such process is False; a process of
    another user (the signal refused) is running; a pid out of range names no
    process. On Windows signal 0 would terminate the process, so it is opened
    for a query and its exit code read instead (``_windows_process_is_running``).
    A pid the system has since given to another process reads as running here;
    the entry tells the two apart by the start time it recorded
    (``_pid_was_reused``), and where no start time is known the directory stays
    held until that process ends too: a wait, never a scan's output lost.
    """
    if pid <= 0:
        return False
    if os.name == "nt":
        return _windows_process_is_running(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (OverflowError, ValueError):
        return False
    except OSError:
        return True
    return True


def _windows_process_is_running(pid: int) -> bool:
    """The Windows probe behind ``_tool_may_be_running``.

    A handle whose exit code reads STILL_ACTIVE is a running process; an open
    refused for access is a running process of another user; any other refusal
    is no process. A probe that cannot ask at all (no kernel32, a call that
    raises) answers False with a debug line, so a directory is never held for
    good by a probe that cannot answer.
    """
    import ctypes

    process_query_limited_information = 0x1000
    still_active = 259
    error_access_denied = 5
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
        if not handle:
            return ctypes.get_last_error() == error_access_denied
        try:
            code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return True
            return code.value == still_active
        finally:
            kernel32.CloseHandle(handle)
    except (AttributeError, OSError, ValueError) as probe_error:
        ASH_LOGGER.debug(
            f"Could not ask whether process {pid} is running: "
            f"{type(probe_error).__name__}"
        )
        return False


def _shown_tool_name(tool: Any) -> str:
    """The name a client is shown for a recorded tool: its basename, or the
    recorded name when it has none.

    A tool is recorded as argv0 as spawned (utils/subprocess_utils
    ``_shown_tool``), which can be a full path on the server
    (``/opt/.../venv/bin/semgrep``). The registry does not know the transport,
    and a remote client has no use for a server path, so every text the
    registry builds from the record uses this form. A trailing separator
    (``/opt/bin/``) would give an empty basename, so separators at the end are
    dropped first."""
    name = str(tool)
    separators = "/\\" if os.name == "nt" else "/"
    return os.path.basename(name.rstrip(separators)) or name


def _without_environment_values(
    text: Optional[str], environment_values: Any
) -> Optional[str]:
    """``text`` with the entry's environment values redacted, when there are
    any; ``text`` as it is otherwise. The one redaction every message the
    registry applies or reports goes through, idempotent over text already
    redacted (a needle that was replaced is not there to match again)."""
    if not text or not environment_values:
        return text
    # Imported here: utils.error_text defers its config imports, and the
    # registry is imported while the config package loads.
    from automated_security_helper.utils.error_text import text_without_values

    return text_without_values(text, environment_values)


def _shares_an_output_tree(one: Path, other: Path) -> bool:
    """Whether two canonical output directories are one tree: the same
    directory, or one inside the other. By path component, never by string
    prefix (``out`` and ``out-backup`` share nothing)."""
    return one == other or one in other.parents or other in one.parents


def _slot_of(entry: "ScanRegistryEntry") -> Tuple[str, str]:
    """The max_concurrent_scans slot an entry holds: its shared slot, or its own."""
    if entry.slot is not None:
        return ("shared", entry.slot)
    return ("own", entry.scan_id)


#: How long ``register_scan`` waits, in all, for a removal of the requested
#: output tree to end before it refuses the scan. The wait runs on the caller's
#: thread, which for the MCP tools is the event-loop thread, so it is short: a
#: tree that takes longer to delete is a refusal the client retries, not a
#: server that answers nothing meanwhile. Before this bound the wait had none.
OUTPUT_REMOVAL_WAIT_SECONDS = 5.0


class _OutputRemovalInProgress(Exception):
    """register_scan's locked attempt met an output tree being removed.

    Carries the removal's Event; the caller waits on it off the lock, within
    ``OUTPUT_REMOVAL_WAIT_SECONDS`` in all, and tries again. Never leaves
    ScanRegistry.
    """

    def __init__(self, removal: Event) -> None:
        super().__init__("an output tree removal is in progress")
        self.removal = removal


class ScanRegistry:
    """Thread-safe registry for tracking active scans."""

    def __init__(self) -> None:
        """Initialize the scan registry."""
        self._registry: Dict[str, ScanRegistryEntry] = {}
        self._registry_lock = Lock()
        self._logger = ASH_LOGGER

    def _later_scans_holding(self, entry: ScanRegistryEntry) -> List[str]:
        """The later scans whose files ``entry``'s output tree holds, oldest first.

        The one reading of ``later_scan_ids`` every reader uses (the caller holds
        the lock). ``later_scan_ids`` holds the later scans that CLAIMED the
        tree (:meth:`_record_supersession`: marked running, or closed after
        they ran; a scan registered and never run is not there), so a recorded
        later scan counts unless it put the previous results back
        (``output_holds_previous_results``); one the registry no longer holds
        counts, because ``_forget_later_scan`` dropped the ids of the removed
        scans that had put the previous results back, so a remaining id of a
        removed scan is a scan whose files are what the tree holds. Before this
        ``check_scan_progress`` and ``remove_output_of_scan`` each read the list
        on their own (one counted a removed later scan, the other did not), and
        the two readers disagreed: an earlier scan read as superseded while
        cleaning it deleted the later scan's files.
        """
        holding: List[str] = []
        for later in entry.later_scan_ids:
            other = self._registry.get(later)
            if other is None:
                holding.append(later)
            elif not other.output_holds_previous_results:
                holding.append(later)
        return holding

    def _forget_later_scan(self, removed: ScanRegistryEntry) -> None:
        """Drop ``removed`` from the earlier entries' ``later_scan_ids`` when its
        files are not what the tree holds: it put the previous results back. A
        removed scan whose own files are in the tree stays recorded (the caller
        holds the lock); a scan that never claimed the tree was never recorded."""
        if not removed.output_holds_previous_results:
            return
        for other in self._registry.values():
            if removed.scan_id in other.later_scan_ids:
                other.later_scan_ids = [
                    later for later in other.later_scan_ids if later != removed.scan_id
                ]

    def _another_scan_occupies(self, entry: ScanRegistryEntry) -> bool:
        """Whether another entry occupies ``entry``'s source directory or output
        tree (the caller holds the lock)."""
        for other in self._registry.values():
            if other.scan_id == entry.scan_id:
                continue
            if (
                other.canonical_directory == entry.canonical_directory
                or other.canonical_output_directory == entry.canonical_output_directory
            ) and other.occupies_its_directory():
                return True
        return False

    def register_scan(
        self,
        directory_path: str,
        output_directory: str,
        severity_threshold: Optional[str] = "MEDIUM",
        config_path: Optional[str] = None,
        scan_id: Optional[str] = None,
        max_active: Optional[int] = None,
        session_id: Optional[str] = None,
        slot: Optional[str] = None,
        requested_severity_threshold: Optional[str] = None,
        environment_values: Iterable[str] = (),
        removal_wait_seconds: Optional[float] = None,
    ) -> str:
        """Register a new scan in the registry; see :meth:`_register_scan_once`.

        A scan whose output tree is being removed by ``remove_output_of_scan``
        (which deletes off the registry lock) waits for that removal to end
        and is then registered, or refused, on the registry as it is then. The
        wait is on the removal's own event, so the registry lock is free for
        every other caller meanwhile; the delete used to run under the lock,
        which held a synchronous caller on the event-loop thread (get_scan,
        list_scans, cancel_scan, this method) for as long as the tree took to
        remove.

        The wait is bounded: ``removal_wait_seconds`` in all (None for
        :data:`OUTPUT_REMOVAL_WAIT_SECONDS`), across every removal of the tree
        met meanwhile, and a scan still waiting at the bound is refused with an
        ``MCPResourceError`` in the ``operation_timeout`` category, naming the
        output directory and asking the client to try again. The wait itself
        runs on the caller's thread, so a caller on an event loop is held for at
        most the bound; ``0`` waits for nothing and refuses at once, for a caller
        that would rather retry on its own schedule. Before the bound a slow
        delete held the caller, and the loop it ran on, for as long as it took.
        """
        if removal_wait_seconds is None:
            removal_wait_seconds = OUTPUT_REMOVAL_WAIT_SECONDS
        deadline = monotonic() + removal_wait_seconds
        while True:
            try:
                return self._register_scan_once(
                    directory_path,
                    output_directory,
                    severity_threshold=severity_threshold,
                    config_path=config_path,
                    scan_id=scan_id,
                    max_active=max_active,
                    session_id=session_id,
                    slot=slot,
                    requested_severity_threshold=requested_severity_threshold,
                    environment_values=environment_values,
                )
            except _OutputRemovalInProgress as in_progress:
                # wait() returns the flag: True once the removal ended (try
                # again, against the registry as it is now), False at the
                # bound. A deadline already passed waits for nothing.
                remaining = max(0.0, deadline - monotonic())
                if in_progress.removal.wait(timeout=remaining):
                    continue
                # Imported here as _register_scan_once imports it: the module
                # loads error_handling lazily.
                from automated_security_helper.core.resource_management.error_handling import (
                    ErrorCategory,
                )

                raise MCPResourceError(
                    f"Output directory {output_directory} is being removed by a "
                    "cleanup of an earlier scan's results, and the removal did "
                    f"not end within {removal_wait_seconds:g} seconds. Try again "
                    "once it has.",
                    context={
                        "directory_path": directory_path,
                        "output_directory": output_directory,
                        "waited_seconds": removal_wait_seconds,
                        "error_category": ErrorCategory.OPERATION_TIMEOUT.value,
                        "suggestions": [
                            "Retry the scan in a few seconds",
                            "Check the earlier scan's cleanup if the refusal repeats",
                        ],
                    },
                )

    def _register_scan_once(
        self,
        directory_path: str,
        output_directory: str,
        severity_threshold: Optional[str] = "MEDIUM",
        config_path: Optional[str] = None,
        scan_id: Optional[str] = None,
        max_active: Optional[int] = None,
        session_id: Optional[str] = None,
        slot: Optional[str] = None,
        requested_severity_threshold: Optional[str] = None,
        environment_values: Iterable[str] = (),
    ) -> str:
        """
        Register a new scan in the registry (one attempt; ``register_scan``
        retries it after an output tree removal in progress ends).

        Args:
            directory_path: Path to the directory being scanned
            output_directory: Path to the output directory for scan results. It
                need not exist yet, and must not be anything but a directory if
                it does: a caller creates it once the scan is registered, so a
                refused scan leaves nothing on disk, and gives the scan back if
                that fails.
            severity_threshold: The threshold the scan's findings are judged by,
                when it is known before the scan runs; None when it comes from a
                config the scan resolves (``finish_scan`` records it then).
            requested_severity_threshold: What the client asked for, when that
                is not the threshold that applies; see ScanRegistryEntry.
            config_path: Optional path to ASH configuration file
            scan_id: Optional scan ID to use (generated if not provided)
            max_active: Refuse the scan when this many already occupy their
                directories (pending, running, or cancelled and still stopping;
                see ScanRegistryEntry.occupies_its_directory): the operator's
                ``max_concurrent_scans``. Counted and registered under one lock,
                so two requests at once cannot both take the last slot. None for
                no limit; the caller passes None for a configured 0.
            session_id: The MCP session starting the scan; None records it under
                :data:`DEFAULT_SCAN_SESSION`.
            slot: Names the max_concurrent_scans slot this scan shares with
                others: a workspace scan registers each of its projects under one
                slot, so the whole workspace counts as one scan. A scan joining a
                slot already held needs no free one; the first scan of a slot is
                refused like any other when none is free. Counted per slot, a
                workspace with more projects than the limit could never start.
                None for a scan that holds a slot of its own.
            environment_values: The values the run's configuration read from the
                environment (the scan's own config's and the operator chain's).
                Attached to the entry so the registry redacts every error
                message it applies with them -- the failure arms share this one
                sink, so an arm closing the entry with a bare exception's text
                no longer decides whether a value leaks. Never part of the
                entry's dictionary. A lone string counts as one value
                (``value_tuple``), not as its characters.

        Returns:
            Scan ID for the registered scan

        Raises:
            MCPResourceError: If the scan cannot be registered
        """
        from automated_security_helper.core.resource_management.error_handling import (
            source_directory_error,
            validate_output_directory_path,
            validate_severity_threshold,
            validate_config_path,
            ErrorCategory,
        )

        # Validate input parameters before acquiring lock
        dir_error = source_directory_error(directory_path)
        if dir_error:
            raise dir_error

        # May not exist yet: the caller creates it once this has given it the
        # scan, so a refused scan leaves nothing on disk.
        output_dir_error = validate_output_directory_path(output_directory)
        if output_dir_error:
            raise output_dir_error

        # None: the caller named no threshold and the scan keeps its config's.
        for threshold in (severity_threshold, requested_severity_threshold):
            if threshold is not None:
                severity_error = validate_severity_threshold(threshold)
                if severity_error:
                    raise severity_error

        if config_path:
            config_error = validate_config_path(config_path)
            if config_error:
                raise config_error

        with self._registry_lock:
            # Generate a scan ID if not provided
            if scan_id is None:
                scan_id = str(uuid.uuid4())
            elif not isinstance(scan_id, str) or not scan_id:
                raise MCPResourceError(
                    f"Invalid scan ID: {scan_id}. Must be a non-empty string.",
                    context={
                        "scan_id": scan_id,
                        "error_category": ErrorCategory.INVALID_PARAMETER.value,
                    },
                )

            # Check if scan ID already exists
            if scan_id in self._registry:
                raise MCPResourceError(
                    f"Scan ID {scan_id} already exists in registry",
                    context={
                        "scan_id": scan_id,
                        "error_category": ErrorCategory.INVALID_PARAMETER.value,
                        "suggestions": [
                            "Use a different scan ID",
                            "Check if you're trying to register the same scan twice",
                            "Use the existing scan ID to check progress or results",
                        ],
                    },
                )

            # The limit is server-wide, so the count is of every session's scans,
            # and the refusal names the limit only: the count would tell any
            # session how many scans the others are running. Refused here, before
            # the entry exists, a scan never holds a slot it would have to give
            # back.
            if max_active is not None:
                held = {
                    _slot_of(e)
                    for e in self._registry.values()
                    if e.occupies_its_directory()
                }
                joining = slot is not None and ("shared", slot) in held
                if not joining and len(held) >= max_active:
                    raise MCPResourceError(
                        f"The MCP server is at its max_concurrent_scans limit of "
                        f"{max_active}",
                        context={
                            "directory_path": directory_path,
                            "max_concurrent_scans": max_active,
                            "error_category": ErrorCategory.RESOURCE_EXHAUSTED.value,
                            "suggestions": [
                                "Wait for a running scan to finish, then retry",
                                "Cancel a scan that is no longer needed",
                                "The operator sets max_concurrent_scans in ASH_CONFIG",
                            ],
                        },
                    )

            # Check if there's already an active scan for this directory.
            #
            # Compared canonically, because two spellings of one directory are
            # one directory and the caller's string is untrusted -- a workspace
            # scan derives N of these from a file an operator wrote, and
            # str(Path) never ends in a separator, so a trailing one only ever
            # arrives from outside.
            #
            # occupies_its_directory() stays in the condition. The rule is about
            # concurrent scans, not about a directory ever having been scanned:
            # without it, the first scan of a directory would permanently block
            # every later one. It is more than is_active(): a cancelled scan still
            # stopping counts, because its restore of the previous results would
            # remove what a new scan had written.
            #
            # The refusal names the running scan's id, and how a stopping scan
            # ended, only to the session that owns it. Another session is told
            # the directory is busy, which it needs to know, and nothing that
            # would let it address that scan or learn its outcome: not even
            # that the scan is stopping rather than running, which says that
            # someone closed it.
            requested = _canonical_directory(directory_path)
            requested_output = _canonical_directory(output_directory)
            for entry in self._registry.values():
                if entry.output_removal is not None and _shares_an_output_tree(
                    entry.canonical_output_directory, requested_output
                ):
                    # The tree, or one that contains it or lies inside it, is
                    # being deleted off the lock (remove_output_of_scan).
                    # register_scan waits for that to
                    # end, within its bound, and tries again, so the new scan is
                    # not registered into a tree being removed from under it. Decided under
                    # the lock, so a removal that starts after this attempt
                    # found none sees this entry as an occupant instead.
                    raise _OutputRemovalInProgress(entry.output_removal)
                if not entry.occupies_its_directory():
                    continue
                same_directory = entry.canonical_directory == requested
                same_output = entry.canonical_output_directory == requested_output
                if not same_directory and not same_output:
                    continue
                owned = entry.session_id == _owner(session_id)
                named: Dict[str, Any] = {"directory_path": directory_path}
                if owned:
                    named["scan_id"] = entry.scan_id
                if not same_directory:
                    # Another source directory's scan writes into this output
                    # directory: two scans on one output tree, each removing
                    # and rewriting the other's files.
                    raise MCPResourceError(
                        f"Output directory {output_directory} is in use by a scan "
                        "of another directory",
                        context={
                            **named,
                            "output_directory": output_directory,
                            "error_category": ErrorCategory.RESOURCE_EXHAUSTED.value,
                            "suggestions": [
                                "Wait for the existing scan to complete",
                                "Use a different output directory for the new scan",
                            ],
                        },
                    )
                if owned and not entry.is_active():
                    if entry.has_runner and entry.runner_done.is_set():
                        # The runner is done; what holds the directory is a
                        # scanner tool the stop could not end, still running
                        # (occupies_its_directory). Named by tool basename, as
                        # the entry's own warning names it for a remote client:
                        # this refusal reaches the owning session, which on a
                        # network transport is remote, and the registry does
                        # not know the transport, so it never shows the
                        # server path a tool was spawned as, and never a pid
                        # (the server's log has both).
                        tools = ", ".join(entry.tool_display_names())
                        raise MCPResourceError(
                            f"Directory {directory_path} has a stopped scan "
                            f"({entry.status.value}) whose scanner tool(s) could "
                            f"not be stopped and may still be running: {tools}",
                            context={
                                **named,
                                "error_category": ErrorCategory.RESOURCE_EXHAUSTED.value,
                                "suggestions": [
                                    (
                                        "End the tool's process (the scan's entry "
                                        "names it in its warnings), then retry"
                                    ),
                                    "Wait for the tool to exit, then retry",
                                ],
                            },
                        )
                    raise MCPResourceError(
                        f"Directory {directory_path} has a scan that is still "
                        f"stopping ({entry.status.value})",
                        context={
                            **named,
                            "error_category": ErrorCategory.RESOURCE_EXHAUSTED.value,
                            "suggestions": [
                                (
                                    "Retry in a few seconds: the scan stops its "
                                    "scanner and puts the previous results back "
                                    "before the directory is free"
                                ),
                            ],
                        },
                    )
                raise MCPResourceError(
                    f"Directory {directory_path} already has an active scan",
                    context={
                        **named,
                        "error_category": ErrorCategory.RESOURCE_EXHAUSTED.value,
                        "suggestions": [
                            "Wait for the existing scan to complete",
                            "Cancel the existing scan if it's no longer needed",
                            "Use a different directory for the new scan",
                        ],
                    },
                )

            # Create and register the scan entry
            try:
                entry = ScanRegistryEntry(
                    scan_id=scan_id,
                    directory_path=directory_path,
                    output_directory=output_directory,
                    severity_threshold=severity_threshold,
                    config_path=config_path,
                    session_id=session_id,
                    slot=slot,
                    requested_severity_threshold=requested_severity_threshold,
                    environment_values=value_tuple(environment_values),
                )
                # The earlier scans of this output tree are NOT recorded as
                # superseded here. A scan that is registered and never runs (a
                # workspace batch rolled back marks its entries CANCELLED without
                # a run) touches no file, and recorded at registration it hid the
                # earlier scan's results behind a scan that never wrote, and
                # refused their removal. _record_supersession records this scan
                # on them when it claims the tree (_apply_status).
                self._registry[scan_id] = entry
                self._logger.info(
                    f"Registered scan {scan_id} for directory {directory_path}"
                )

                return scan_id
            except Exception as e:
                # Handle unexpected errors during entry creation
                self._logger.error(
                    f"Error creating scan registry entry: {str(e)}", exc_info=True
                )
                raise MCPResourceError(
                    f"Failed to register scan: {str(e)}",
                    context={
                        "directory_path": directory_path,
                        "output_directory": output_directory,
                        "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                    },
                )

    def get_scan(
        self, scan_id: str, session_id: Optional[str] = None
    ) -> Optional[ScanRegistryEntry]:
        """
        Get a scan entry by ID.

        Args:
            scan_id: ID of the scan to retrieve
            session_id: When given, only that session's scan is returned; another
                session's id answers exactly like an id that was never issued.
                None is the unscoped lookup the scan runners use.

        Returns:
            Scan registry entry or None if not found
        """
        with self._registry_lock:
            return self._visible(scan_id, session_id)

    def _visible(
        self, scan_id: str, session_id: Optional[str]
    ) -> Optional[ScanRegistryEntry]:
        """The entry for ``scan_id`` as ``session_id`` may see it. Caller holds the lock."""
        entry = self._registry.get(scan_id)
        if entry is None or session_id is None:
            return entry
        return entry if entry.session_id == _owner(session_id) else None

    def _entries_for(self, session_id: Optional[str]) -> List[ScanRegistryEntry]:
        """Every entry ``session_id`` may see; all of them for None. Caller holds the lock."""
        if session_id is None:
            return list(self._registry.values())
        owner = _owner(session_id)
        return [e for e in self._registry.values() if e.session_id == owner]

    def get_scan_by_directory(
        self, directory_path: str, session_id: Optional[str] = None
    ) -> Optional[ScanRegistryEntry]:
        """
        Get the scan that occupies a directory.

        Args:
            directory_path: Path to the directory
            session_id: When given, only that session's scan is returned;
                another session's answers None, as every session-scoped lookup
                answers for a scan it does not own. None is the unscoped lookup.

        Returns:
            The registry entry occupying the directory, or None if there is none

        Canonicalised on both sides, matching :meth:`register_scan`. The two have
        to agree: a caller told "directory /proj/ already has an active scan" and
        given that scan's id has to be able to reach the same entry by the same
        string, and before this they could not. They agree on what occupies a
        directory too (:meth:`ScanRegistryEntry.occupies_its_directory`): a
        cancelled scan whose runner is still stopping is what register_scan
        refuses the directory for, and this used to answer None for it, so a
        directory reported free was refused.
        """
        requested = _canonical_directory(directory_path)
        with self._registry_lock:
            for entry in self._entries_for(session_id):
                if (
                    entry.canonical_directory == requested
                    and entry.occupies_its_directory()
                ):
                    return entry
            return None

    def scan_writing_output(self, output_directory: str) -> Optional[str]:
        """The id of a scan that still occupies ``output_directory`` as its output, or None.

        The same question :meth:`register_scan` asks before it admits a scan whose
        output directory another scan writes, asked under the same lock and with
        the same canonical form (:func:`_canonical_directory`), so a caller that
        checks several output directories before registering any of them
        (the workspace scan, one per project) gets the registry's own idea of
        occupancy (:meth:`ScanRegistryEntry.occupies_its_directory`): a closed
        entry occupies its directory while its runner has not finished, and a
        cancelled or failed entry that never had a runner, or whose runner is
        done, occupies nothing. A status list read off ``list_scans`` got both
        halves wrong: it refused the rollback entries a workspace registration
        marks CANCELLED without ever running, and admitted a timed-out scan whose
        entries are FAILED while its thread still writes.
        """
        requested = _canonical_directory(output_directory)
        with self._registry_lock:
            for entry in self._registry.values():
                if (
                    entry.canonical_output_directory == requested
                    and entry.occupies_its_directory()
                ):
                    return entry.scan_id
            return None

    def scan_writing_within(self, output_directory: str) -> Optional[str]:
        """The id of a scan that still occupies an output tree that shares
        ``output_directory``: the same directory, one inside it, or one that
        contains it. None when there is none.

        :meth:`scan_writing_output` answers for one directory exactly, which is
        the question for a project's own output folder. A workspace scan also
        writes its unified results, reports and spool into its output ROOT, and
        two workspace scans with different projects and one root shared nothing
        at the project level, so both were admitted and each run's cleanup
        removed the other's; a single scan whose output tree is the root, or
        contains it, was admitted the same way. Occupancy is the registry's own
        (:meth:`ScanRegistryEntry.occupies_its_directory`), under the lock, in
        canonical form; the tree relation is by path component
        (``Path.parents``), so ``out`` and ``out-backup`` are two trees.
        """
        requested = _canonical_directory(output_directory)
        with self._registry_lock:
            for entry in self._registry.values():
                if entry.occupies_its_directory() and _shares_an_output_tree(
                    entry.canonical_output_directory, requested
                ):
                    return entry.scan_id
            return None

    def remove_output_of_scan(
        self, entry: ScanRegistryEntry, remover: Callable[[], bool]
    ) -> Tuple[Optional[str], bool]:
        """Run ``remover``, which deletes ``entry``'s output directory, unless
        the directory is another scan's too.

        Returns ``(reason, removed)``: the reason the remover was not run and
        False, or None and what the remover returned.

        Scans of one source directory write the same output tree under it by
        default, and the question is about that tree, so the comparison is on
        ``canonical_output_directory``: a scan of the same source that was given
        another output directory shares nothing with this one. Two output
        directories share a tree when they are the same directory or one lies
        inside the other (``_shares_an_output_tree``), so a project scan whose
        output sits under this scan's output directory is another scan's tree
        too. The tree is another scan's while that scan occupies it
        (:meth:`ScanRegistryEntry.occupies_its_directory`), and it holds a LATER
        scan's results once one has claimed it (``later_scan_ids``: marked
        running, or closed after it ran), whatever that scan's state since,
        and whether or not that scan is still in the registry
        (``_later_scans_holding``, the one reading ``check_scan_progress`` uses
        for ``output_superseded``): ``cleanup_old_scans`` reaches here for an
        old scan while a newer, completed scan's results sit in the shared tree,
        and removing them left that scan reporting results_available over an
        empty directory. A later scan that was registered and never ran holds
        nothing here, so it does not refuse the removal; nor does one that ended
        without writing and had the previous results put back.

        The check runs under the registry lock and the delete runs OFF it: the
        entry is marked as having its output removal in progress
        (``ScanRegistryEntry.output_removal``) under the lock, the lock is
        released, the remover runs, and the mark is cleared under the lock
        again, whatever the remover did. A ``register_scan`` of the same output
        tree meanwhile waits on the mark's event (for at most
        ``OUTPUT_REMOVAL_WAIT_SECONDS``, then it is refused) and then proceeds
        against the registry as it is after the delete, so it is not registered
        into a tree being removed from under it; a second removal of the tree
        meanwhile is refused. The delete used to run with the lock held, which held every
        synchronous registry caller, on the event-loop thread included
        (get_scan, list_scans, cancel_scan, register_scan), for as long as the
        tree took to remove. The remover still runs on the caller's thread;
        callers run this off the event loop (``asyncio.to_thread``).

        Two refusals are about ``entry`` itself, decided under the same lock. An
        entry the registry no longer holds (a concurrent cleanup removed it
        between the caller's read and this call) is refused: the mark would sit
        on an object no ``register_scan`` can see, so a new scan of the tree
        would be admitted while it is being deleted. An entry that still
        occupies its directory (:meth:`ScanRegistryEntry.occupies_its_directory`:
        active, its runner not finished, or a scanner tool the cancel could not
        end still running) is refused too: the tree is still being written,
        and ``cleanup_scan`` keeps such an entry for the same reason.
        """
        with self._registry_lock:
            if self._registry.get(entry.scan_id) is not entry:
                return (
                    "this scan is no longer in the registry",
                    False,
                )
            if entry.occupies_its_directory():
                return (
                    (
                        "this scan is still running or stopping, or a scanner tool "
                        "the cancel could not end is still running"
                    ),
                    False,
                )
            if entry.output_removal is not None:
                return (
                    "this scan's output directory is already being removed",
                    False,
                )
            for other in self._registry.values():
                if other.scan_id == entry.scan_id:
                    continue
                # A tree, not a name: a project scan of a workspace writes under
                # the output directory of a single scan of the workspace root, so
                # an equality test let the removal of the outer tree delete a
                # running project's live output.
                if not _shares_an_output_tree(
                    other.canonical_output_directory, entry.canonical_output_directory
                ):
                    continue
                if other.output_removal is not None:
                    return (
                        (
                            "another scan's removal of this output directory is "
                            "in progress"
                        ),
                        False,
                    )
                if other.occupies_its_directory():
                    return (
                        (
                            "another scan is running or stopping and shares this "
                            "output directory"
                        ),
                        False,
                    )
            if self._later_scans_holding(entry):
                return (
                    "a later scan holds its results in this output directory",
                    False,
                )
            removal = entry.output_removal = Event()
        try:
            return None, remover()
        finally:
            with self._registry_lock:
                entry.output_removal = None
            removal.set()

    def update_scan_status(
        self, scan_id: str, status: MCScanStatus, error_message: Optional[str] = None
    ) -> bool:
        """
        Update the status of a scan.

        Args:
            scan_id: ID of the scan to update
            status: New status for the scan
            error_message: Optional error message for failed scans

        Returns:
            True if the scan was updated, False if not found, or if ``status``
            is RUNNING and the entry has ended.

        ``PENDING`` is refused with ValueError: it is the state an entry is
        registered in and nothing moves one back to it, so the call used to
        return True and log an update while changing nothing.

        ``RUNNING`` over an ended entry is refused, so the runner's claim of its
        entry cannot reopen a scan that a cancel closed before the runner's first
        step, or that a runner closed. The one entry it may reopen is one that
        :meth:`check_scan_progress` closed from a results file while the entry
        was PENDING with no runner (``closed_from_file``): that file can be the
        previous scan's, and the runner that then claims the entry owns its
        lifecycle; ``mark_running`` clears what the file put there.

        Not even that one once the tree has moved on: an entry closed from a
        file no longer occupies its directory, so ``register_scan`` admits a
        second scan of it, and reopening the first then put two RUNNING scans on
        one output tree. The reopen is refused (False, logged) while another
        entry occupies the directory or the output tree, or a later scan has
        taken the tree (``_later_scans_holding``); the runner's claim fails and
        it reports the scan as not started.
        """
        if status == MCScanStatus.INCOMPLETE:
            # finish_scan is the only way in, because it carries the coverage gap.
            raise ValueError(
                f"Scan {scan_id} cannot be marked incomplete without its coverage "
                "gap; close it with finish_scan(..., coverage=...)"
            )
        if status == MCScanStatus.PENDING:
            raise ValueError(
                f"Scan {scan_id} cannot be moved back to pending: it is the state a "
                "scan is registered in"
            )
        with self._registry_lock:
            entry = self._registry.get(scan_id)
            if entry is None:
                return False
            if status == MCScanStatus.RUNNING and entry.status in ENDED:
                if not entry.closed_from_file:
                    self._logger.info(
                        f"Scan {scan_id} stays {entry.status.value}: a scan that "
                        "has ended is not reopened as running"
                    )
                    return False
                if self._another_scan_occupies(entry) or self._later_scans_holding(
                    entry
                ):
                    self._logger.info(
                        f"Scan {scan_id} stays {entry.status.value}: it was closed "
                        "from a results file and another scan has since taken its "
                        "directory, so it is not reopened as running"
                    )
                    return False
            self._apply_status(scan_id, entry, status, error_message)
            return True

    def _apply_status(
        self,
        scan_id: str,
        entry: ScanRegistryEntry,
        status: MCScanStatus,
        error_message: Optional[str],
    ) -> None:
        """Move ``entry`` to ``status``. The caller holds ``_registry_lock``.

        The error message is redacted with the entry's registered environment
        values before it is recorded. The arms that close a scan each redact
        the text they build, and one that closes with a bare exception's text
        forgets to -- so the one sink they all reach does it too. Idempotent
        over already-redacted text: a needle that was replaced is not there to
        match again.
        """
        error_message = _without_environment_values(
            error_message, entry.environment_values
        )
        was_pending = entry.status == MCScanStatus.PENDING
        had_runner = entry.has_runner
        if status == MCScanStatus.RUNNING:
            entry.mark_running()
        elif status == MCScanStatus.COMPLETED:
            entry.mark_completed()
        elif status == MCScanStatus.INCOMPLETE:
            entry.mark_incomplete()
        elif status == MCScanStatus.FAILED:
            entry.mark_failed(error_message or "Unknown error")
        elif status == MCScanStatus.CANCELLED:
            entry.mark_cancelled()
        if _claims_output_tree(status, was_pending=was_pending, had_runner=had_runner):
            self._record_supersession(entry)

        self._logger.info(f"Updated scan {scan_id} status to {status.value}")

    def _record_supersession(self, entry: ScanRegistryEntry) -> None:
        """Record ``entry`` as a later scan on every earlier scan of its output tree.

        The caller holds ``_registry_lock``. Called when the scan claims the
        tree (:func:`_claims_output_tree`), once per entry: a scan that is
        marked running and then closed is recorded at the first of the two.
        "Earlier" is the registration order (``registration_seq``), never the
        clock, and only an entry whose output tree is this one is touched: a
        later scan of the same source that writes elsewhere leaves the others'
        files untouched, so it supersedes none of them.
        """
        if entry.claimed_output_tree:
            return
        entry.claimed_output_tree = True
        for other in self._registry.values():
            if other.scan_id == entry.scan_id:
                continue
            if other.canonical_output_directory != entry.canonical_output_directory:
                continue
            if other.registration_seq > entry.registration_seq:
                continue
            if entry.scan_id not in other.later_scan_ids:
                other.later_scan_ids.append(entry.scan_id)

    def finish_scan(
        self,
        scan_id: str,
        status: MCScanStatus,
        error_message: Optional[str] = None,
        coverage: Optional[Dict[str, Any]] = None,
        severity_threshold: Optional[str] = None,
        exit_code: Optional[int] = None,
    ) -> bool:
        """Close a scan as its runner, unless something already closed it.

        ``coverage`` is what the runner knows about the scan's coverage, in the
        ``ScanIncompleteness.to_payload()`` shape. ``INCOMPLETE`` without it is
        refused with ``ValueError``: the status exists to point a client at the
        gap, so a status with no gap attached would tell them to look and give
        them nothing to look at.

        ``exit_code`` is the code ASH exited with, for a scan it ended with an
        exit; progress reports it with its meaning.

        ``severity_threshold`` is the threshold the scan's findings were judged
        by, read from the config it resolved. It replaces the registered value,
        which is None for a scan that named no threshold, so progress reports
        the threshold that applied rather than one the client did not choose.

        For the code that ran the scan, when the run returns. ``update_scan_status``
        overwrites whatever is there, so a runner finishing after ``cancel_scan``
        turned a cancelled scan back into a completed one -- the cancel cannot stop
        an in-process scan, only record that it was asked to. Checked and applied
        under the registry lock, so a cancel landing between the two is not lost.

        Returns:
            True if the entry was closed, False if it was not found or had already
            left the active states.
        """
        if status == MCScanStatus.INCOMPLETE and not coverage_has_gap(coverage):
            # A non-empty payload whose every gap list is empty names no gap
            # either: closed with it, the scan read "incomplete" beside
            # coverage_complete true.
            raise ValueError(
                f"Scan {scan_id} cannot be closed as incomplete without the coverage "
                "gap that makes it so"
            )
        with self._registry_lock:
            entry = self._registry.get(scan_id)
            if entry is None or not entry.is_active():
                return False
            if coverage is not None:
                entry.coverage = coverage
            if severity_threshold is not None:
                entry.severity_threshold = severity_threshold
            if exit_code is not None:
                entry.exit_code = exit_code
            self._apply_status(scan_id, entry, status, error_message)
            return True

    def record_cancel_outcome(
        self,
        scan_id: str,
        could_not_stop: Iterable[Tuple[str, int]],
        *,
        name_process_ids: bool = True,
    ) -> bool:
        """Attach to a scan the server stopped the scanner tools its stop could not end.

        A stop closes the entry at once: ``cancel_scan`` as CANCELLED, the scan
        timeout and a cancelled runner task as FAILED with the cancel event set.
        The thread that runs the scan learns only afterwards, from the records
        its cancel event collected (``CancelEvent.could_not_stop_records``),
        which tools kept running past the stop, and ``finish_scan`` leaves a
        closed entry alone by design, so that outcome had nowhere to go and a
        stop whose tool was still running read back as a clean one. This is the
        one way to add it: the ``(tool, pid)`` pairs are kept on the entry
        (``could_not_stop``, which keeps the directory held while one of them
        runs), and a warning names each tool, so a client polling the entry is
        told the output directory may still be written to.

        Admitted for an entry the server stopped (``stopped_by_the_server``):
        CANCELLED, or FAILED with its cancel event set. A RUNNING entry, a scan
        that finished, and a FAILED scan nothing stopped take no outcome: the
        records would describe a stop that did not happen. A pair already on
        the entry is not recorded twice, so the thread that ran the scan and a
        runner's arm may both call this with the same records.

        ``name_process_ids`` False keeps the process ids out of the warning: on
        a network transport the client is remote, and a server-side pid is
        nothing it can act on and nothing it should learn. The same warning
        names each tool by its basename: a tool is recorded as argv0 as spawned
        (utils/subprocess_utils ``_shown_tool``), which can be a full path on
        the server, and a remote client has no use for that path either. The
        caller logs the ids on the server side instead; the entry keeps the
        pairs as recorded either way.

        Returns:
            True if a warning was attached, False if there was nothing new to
            attach, the entry is missing, or the server did not stop it.
        """
        records = tuple(dict.fromkeys(could_not_stop))
        if not records:
            return False
        with self._registry_lock:
            entry = self._registry.get(scan_id)
            if entry is None or not entry.stopped_by_the_server():
                return False
            new = tuple(r for r in records if r not in entry.could_not_stop)
            if not new:
                return False
            entry.could_not_stop = entry.could_not_stop + new
            # The start time of each new pid, read now, so a later probe can
            # tell the tool from a process the system gives its pid to after
            # it ends (a_surviving_tool_is_running).
            for _tool, pid in new:
                entry.tool_start_times.setdefault(pid, _process_start_time(pid))
            if name_process_ids:
                named = ", ".join(f"{tool} (pid {pid})" for tool, pid in new)
                how = "end the listed process(es) before reading or reusing it."
            else:
                named = ", ".join(_shown_tool_name(tool) for tool, _pid in new)
                how = (
                    "the server's log names the process(es); end them before "
                    "reading or reusing it."
                )
            entry.add_warning(
                f"{len(new)} scanner tool(s) could not be stopped and may still "
                f"be running: {named}. A tool still running can write into the "
                f"output directory after the stop; {how}"
            )
            return True

    def list_scans(
        self,
        active_only: bool = False,
        directory_path: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        List scans in the registry.

        Args:
            active_only: If True, only list active scans
            directory_path: Optional directory path to filter by
            session_id: When given, only that session's scans are listed

        Returns:
            List of scan entries as dictionaries

        The ``directory_path`` filter is canonicalised on both sides, for the
        reason :meth:`get_scan_by_directory` gives: one directory has to answer to
        one query however the caller spelled it.
        """
        requested = _canonical_directory(directory_path) if directory_path else None
        with self._registry_lock:
            result = []
            for entry in self._entries_for(session_id):
                if active_only and not entry.is_active():
                    continue
                if requested is not None and entry.canonical_directory != requested:
                    continue
                result.append(entry.to_dict())
            return result

    def cancel_scan(self, scan_id: str, session_id: Optional[str] = None) -> bool:
        """
        Cancel a scan.

        Args:
            scan_id: ID of the scan to cancel
            session_id: When given, only that session's scan can be cancelled;
                another session's id is treated as not found.

        Returns:
            True if the scan was cancelled, False if not found or already completed

        Raises:
            MCPResourceError: If the scan cannot be cancelled
        """
        with self._registry_lock:
            entry = self._visible(scan_id, session_id)
            if entry is None:
                return False

            if not entry.is_active():
                # Scan is already completed, failed, or cancelled
                return False

            # An in-process scan has no process ID. mark_cancelled below sets its
            # cancel event, which stops it; a scan with a process of its own is
            # also signalled. A signal the system refuses is recorded on the
            # entry as a warning and does not stop the cancel: raising here left
            # the entry active with its cancel event never set, so a scan whose
            # recorded pid could not be signalled could not be cancelled at all.
            # The pid is signalled as recorded; whether it still belongs to the
            # scan is not checked, which no portable call answers.
            if entry.process_id:
                try:
                    os.kill(entry.process_id, signal.SIGTERM)
                    self._logger.info(
                        f"Sent SIGTERM to process {entry.process_id} for scan {scan_id}"
                    )
                except ProcessLookupError:
                    self._logger.warning(
                        f"Process {entry.process_id} for scan {scan_id} not found"
                    )
                except PermissionError:
                    self._logger.error(
                        f"Permission denied when trying to terminate process {entry.process_id}"
                    )
                    entry.add_warning(
                        f"Permission denied when trying to terminate process "
                        f"{entry.process_id}; the scan was cancelled through its "
                        "cancel event only"
                    )
                except OSError as e:
                    self._logger.error(
                        f"Error terminating process {entry.process_id}: {str(e)}"
                    )
                    entry.add_warning(
                        f"Error terminating process {entry.process_id}: {str(e)}; "
                        "the scan was cancelled through its cancel event only"
                    )

            # Mark the scan as cancelled, which also sets its cancel event. A
            # scan cancelled while running may have written its output tree, so
            # it is recorded on the earlier scans of the tree as a claim; one
            # cancelled before anything ran is not (_claims_output_tree).
            was_pending = entry.status == MCScanStatus.PENDING
            had_runner = entry.has_runner
            entry.mark_cancelled()
            if _claims_output_tree(
                MCScanStatus.CANCELLED, was_pending=was_pending, had_runner=had_runner
            ):
                self._record_supersession(entry)
            self._logger.info(
                f"Cancelled scan {scan_id}; it stops at its next cancellation check"
            )
            return True

    def cleanup_scan(self, scan_id: str, session_id: Optional[str] = None) -> bool:
        """
        Remove a scan from the registry.

        Args:
            scan_id: ID of the scan to remove
            session_id: When given, only that session's scan is removed; another
                session's id is treated as not found.

        Returns:
            True if the scan was removed, False if not found, if its runner
            has not finished, if a scanner tool its stop could not end is still
            running, or if its output tree is being removed.

        An entry whose runner is still stopping is kept, and so is one whose
        stop left a scanner tool running (``could_not_stop``). The entry is what
        makes ``register_scan`` refuse a second scan of the directory and count
        the scan against ``max_concurrent_scans`` while the directory may still
        be written to (``occupies_its_directory``); deleted now, a new scan of
        the directory would be admitted into the window in which that runner, or
        that tool, still writes. Remove it again once they are done.
        """
        with self._registry_lock:
            entry = self._visible(scan_id, session_id)
            if entry is None:
                return False
            if entry.has_runner and not entry.runner_done.is_set():
                self._logger.warning(
                    f"Scan {scan_id} is kept in the registry: its runner has not "
                    "finished settling the output directory"
                )
                return False
            if entry.a_surviving_tool_is_running():
                self._logger.warning(
                    f"Scan {scan_id} is kept in the registry: a scanner tool its "
                    "stop could not end is still running"
                )
                return False
            if entry.output_removal is not None:
                # The entry carries the mark register_scan waits on while its
                # output tree is being deleted off the lock
                # (remove_output_of_scan). Dropped here, the mark went with it:
                # a second cleanup of the same scan during the first's delete
                # (its refused removal is a warning to the caller, which then
                # unregisters) removed the entry, and a registration of the
                # same output tree arriving after that found no mark, did not
                # wait, and was registered into a tree being removed from
                # under it. The entry stays until the remover has returned.
                self._logger.warning(
                    f"Scan {scan_id} is kept in the registry: its output directory "
                    "is being removed"
                )
                return False
            del self._registry[scan_id]
            self._forget_later_scan(entry)
            self._logger.info(f"Removed scan {scan_id} from registry")
            return True

    def cleanup_completed_scans(self, max_age_hours: int = 24) -> int:
        """
        Clean up old completed scans from the registry.

        Args:
            max_age_hours: Maximum age in hours for completed scans

        Returns:
            Number of scans cleaned up
        """
        with self._registry_lock:
            now = datetime.now()
            cutoff_time = now.timestamp() - (max_age_hours * 3600)
            scans_to_remove = []

            for scan_id, entry in self._registry.items():
                # A closed entry whose runner is still stopping stays, as in
                # cleanup_scan: it still holds its directory. So does one whose
                # output tree is being removed off the lock: its mark is what a
                # registration of the tree waits on, and a COMPLETED entry
                # under removal does not occupy its directory, so the age
                # sweep reached it.
                if entry.output_removal is not None:
                    continue
                if not entry.occupies_its_directory():
                    # Check if the scan is old enough to be removed
                    end_time = entry.end_time or entry.start_time
                    if end_time.timestamp() < cutoff_time:
                        scans_to_remove.append(scan_id)

            # Remove the old scans
            for scan_id in scans_to_remove:
                removed = self._registry.pop(scan_id)
                self._forget_later_scan(removed)

            if scans_to_remove:
                self._logger.info(
                    f"Cleaned up {len(scans_to_remove)} old scans from registry"
                )

            return len(scans_to_remove)

    def get_active_scan_count(self, session_id: Optional[str] = None) -> int:
        """
        Get the number of active scans.

        Args:
            session_id: When given, count only that session's scans

        Returns:
            Number of active scans
        """
        with self._registry_lock:
            return sum(
                1 for entry in self._entries_for(session_id) if entry.is_active()
            )

    def get_scan_count(self, session_id: Optional[str] = None) -> int:
        """
        Get the total number of scans in the registry.

        Args:
            session_id: When given, count only that session's scans

        Returns:
            Total number of scans
        """
        with self._registry_lock:
            return len(self._entries_for(session_id))

    def get_scan_status_counts(
        self, session_id: Optional[str] = None
    ) -> Dict[str, int]:
        """
        Get counts of scans by status.

        Args:
            session_id: When given, count only that session's scans

        Returns:
            Dictionary mapping status values to counts
        """
        with self._registry_lock:
            counts = {status.value: 0 for status in MCScanStatus}
            for entry in self._entries_for(session_id):
                counts[entry.status.value] += 1
            return counts

    def get_scan_statistics(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """The total, active and per-status counts, read in one lock acquisition.

        Args:
            session_id: When given, count only that session's scans

        Returns:
            ``total_scans``, ``active_scans`` and ``status_counts``, which agree
            with each other: read as three separate calls, a registration or a
            close between two of them made the total disagree with the sum of
            the status counts.
        """
        with self._registry_lock:
            entries = self._entries_for(session_id)
            counts = {status.value: 0 for status in MCScanStatus}
            for entry in entries:
                counts[entry.status.value] += 1
            return {
                "total_scans": len(entries),
                "active_scans": sum(1 for entry in entries if entry.is_active()),
                "status_counts": counts,
            }

    def check_scan_progress(
        self,
        scan_id: str,
        session_id: Optional[str] = None,
        *,
        name_process_ids: bool = True,
    ) -> Dict[str, Any]:
        """
        Check the progress of a scan.

        ``name_process_ids`` False keeps server process ids out of the response:
        the entry's warnings (``record_cancel_outcome`` names each tool the
        cancel could not end with its pid on a local transport) and the stored
        coverage's ``could_not_stop`` reasons (the executor records each with
        the pid of the tool it could not end) are read through
        ``utils.subprocess_utils.without_process_ids``. The texts were written
        for the transport of the moment they were recorded; a later read by a
        remote client, or by a client the "every caller remote" override makes
        remote, was handed them as recorded. The entry's own records are not
        changed, so a local read after a remote one still names the pids.

        Args:
            scan_id: ID of the scan to check
            session_id: When given, another session's scan is reported exactly
                as an unknown id is

        Returns:
            Dictionary with scan progress information

        Raises:
            MCPResourceError: If the scan is not found or output directory is invalid
        """
        from automated_security_helper.core.resource_management.error_handling import (
            validate_scan_id,
            validate_directory_path,
            ErrorCategory,
        )

        # Validate scan ID before acquiring lock
        error = validate_scan_id(scan_id)
        if error:
            raise error

        with self._registry_lock:
            entry = self._visible(scan_id, session_id)
            if entry is None:
                raise MCPResourceError(
                    f"Scan {scan_id} not found in registry",
                    context={
                        "scan_id": scan_id,
                        "error_category": ErrorCategory.SCAN_NOT_FOUND.value,
                        "suggestions": [
                            "Check that the scan ID is correct",
                            "Verify that the scan exists in the registry",
                            "The scan may have been cleaned up if it was completed a long time ago",
                        ],
                    },
                )

            # Convert output directory to Path
            output_dir = Path(entry.output_directory)

            # An output directory that is not there (never created, or removed
            # since) is not an error of the poll: the entry's status is still
            # the answer, with nothing read from files. Raising here made the
            # failed status and reason of a scan whose directory was gone
            # unreadable by polling. Only "not there" is read that way: a
            # directory the process may not read, or one the system could not
            # examine, is still there with results this poll cannot see, and
            # that is the caller's error to act on, not a missing tree.
            output_error = validate_directory_path(output_dir)
            output_missing = output_error is not None and output_error.context.get(
                "error_category"
            ) in (
                ErrorCategory.FILE_NOT_FOUND.value,
                ErrorCategory.INVALID_PATH.value,
            )
            if output_error is not None and not output_missing:
                output_error.context.setdefault("scan_id", scan_id)
                raise output_error

            try:
                # Create scan progress object from files, then reconcile it with
                # the registry entry, whose status is the response's status.
                #
                # Who decides depends on whether anything owns the scan's
                # lifecycle. A RUNNING entry has a runner that will close it, so the
                # runner decides and the file is only partial results: the SCAN
                # phase writes a parseable results file before the REPORT phase has
                # run, and a previous scan's file can still be on disk. A FAILED or
                # CANCELLED entry was closed by its runner, and a parseable file
                # means results exist, not that the scan succeeded. Only a PENDING
                # entry, which no runner has claimed, takes its status from the
                # file. Marking the entry completed because the file merely existed
                # is how a file that did not parse came back as a completed scan
                # with no scanners.
                #
                # After a scan that ended without results and had the previous
                # scan's results put back, the directory holds those: complete,
                # parseable, and not this scan's. Nothing is read from it then.
                #
                # The same holds once a LATER scan of the same directory has
                # claimed the tree (marked running, or closed after it ran):
                # every scan of a directory writes the one output tree under
                # it, so after this scan ended the files there are the later
                # scan's, whatever its state since. Read as this scan's, they
                # reported another scan's scanners and findings (another session's
                # too) under this id, and could re-close this entry on them.
                #
                # Except a later scan that ended without writing and had the
                # previous results put back: what the directory holds then is
                # what was there before it, this scan's own results, and they
                # are not hidden. The later scans are the ones
                # _record_supersession recorded on this entry (later_scan_ids),
                # keyed by the OUTPUT tree, so a later scan that wrote elsewhere
                # does not count, nor one that was registered and never ran (a
                # workspace batch rolled back), and one that has since been
                # removed from the registry still does: its files are what the
                # tree holds (_later_scans_holding, the reading
                # remove_output_of_scan uses too).
                previous_only = entry.output_holds_previous_results
                superseded_by = self._later_scans_holding(entry)
                superseded = entry.status in ENDED and bool(superseded_by)
                # A PENDING entry a runner has claimed (has_runner) has had
                # nothing of its own written yet: the runner marks RUNNING
                # before the orchestrator sets the previous results aside, so
                # whatever the tree holds at this moment is the previous
                # scan's. Read as this scan's, those files reported the
                # previous scan's scanners, counts and scanner statuses under
                # the new id while the status said pending. A PENDING entry no
                # runner owns keeps the file read: that file is what closes it
                # (closed_from_file, the arms below).
                claimed_pending = (
                    entry.status == MCScanStatus.PENDING and entry.has_runner
                )
                foreign_output = (
                    previous_only or superseded or output_missing or claimed_pending
                )
                scan_progress = (
                    ScanProgress(scan_id=scan_id)
                    if foreign_output
                    else create_scan_progress_from_files(scan_id, output_dir)
                )
                results_path = output_dir / "ash_aggregated_results.json"

                # A PENDING entry a runner has claimed (has_runner) is the
                # runner's to close, as a RUNNING one is: the file on disk is
                # the previous scan's until the runner writes, and is not read
                # (claimed_pending above). Only a PENDING entry with no runner
                # takes its status from the file.
                owned_by_a_runner = entry.status == MCScanStatus.RUNNING or (
                    entry.status == MCScanStatus.PENDING and entry.has_runner
                )

                if owned_by_a_runner:
                    scan_progress.mark_in_progress()
                elif (
                    scan_progress.results_pending
                    and entry.status in FINISHED_WITH_RESULTS
                ):
                    # A JSON object with neither scanner_results nor sarif is not a
                    # results document. Before anything has closed the entry that
                    # is "not finished"; once it was closed with results, the final
                    # document never arrived. The same rule as the unreadable
                    # file below: the runner's status stands, the poll reports
                    # the file, and results_available below says there is
                    # nothing to read. This used to re-close a COMPLETED entry
                    # as FAILED while the unreadable file kept it, so the two
                    # unusable-file shapes answered differently; and it sat
                    # below the terminal-status arm, which kept an INCOMPLETE
                    # entry's keyless file as "results available, 0 findings".
                    scan_progress.mark_failed(
                        f"Aggregated results file {results_path} has neither "
                        "scanner_results nor sarif, and the scan has ended, so it "
                        "never wrote its final results"
                    )
                elif entry.status in (
                    MCScanStatus.FAILED,
                    MCScanStatus.CANCELLED,
                    MCScanStatus.INCOMPLETE,
                ):
                    # The runner's terminal status and reason stand. Whatever
                    # scanners the file holds stay readable as partial results.
                    pass
                elif scan_progress.status == "completed":
                    if entry.status != MCScanStatus.COMPLETED:
                        # A PENDING entry, which no runner owns, so the file
                        # decides -- and it decides incomplete versus completed by
                        # the rule the runner's exit code uses, not by the file
                        # merely parsing. Recorded as closed from the file, so a
                        # runner that claims the entry after all may reopen it.
                        model = load_aggregated_results_model(output_dir)
                        if model is None:
                            entry.mark_completed()
                        else:
                            gate_fires, entry.coverage = assess_coverage(model)
                            if gate_fires:
                                entry.mark_incomplete()
                            else:
                                entry.mark_completed()
                        entry.closed_from_file = True
                elif scan_progress.status == "failed":
                    # The results file exists and cannot be read as results.
                    # Only an entry no runner owns (PENDING) takes its status
                    # from the file. A runner closed a COMPLETED entry on a
                    # scan that did finish; a file that later reads as
                    # unusable is reported on the response, with its reason,
                    # and does not turn a read-only poll into a permanent
                    # FAILED with a moved end_time. Closed through
                    # _apply_status, the one sink that redacts the message
                    # with the entry's environment values; mark_failed called
                    # directly skipped that.
                    if entry.status == MCScanStatus.PENDING:
                        self._apply_status(
                            scan_id,
                            entry,
                            MCScanStatus.FAILED,
                            scan_progress.error_message
                            or f"Aggregated results file {results_path} could not be read",
                        )
                        entry.closed_from_file = True
                elif scan_progress.results_pending:
                    # A keyless results document under a PENDING entry no runner
                    # owns: not finished yet, nothing to decide (the finished
                    # case is the arm above the terminal statuses).
                    pass
                elif entry.status == MCScanStatus.COMPLETED:
                    # No results file, and whoever ran the scan closed the entry as
                    # completed. The entry owns the lifecycle here: a workspace
                    # closes a project's entry this way when the run returned and
                    # nothing says the project did not.
                    scan_progress.mark_completed()

                # A scanner still RUNNING in a scan that has ended did not
                # finish. A cancel or a crash mid-write leaves a per-scanner
                # file that is not yet a JSON object, which the file view
                # reports as running until a later poll reads a document, and
                # for an ended scan no later poll will. Left as it was, the
                # response said is_complete True beside
                # scanner_status_counts.running 1 on every poll.
                if entry.status in ENDED:
                    for targets in scan_progress.scanners.values():
                        for scanner_progress in targets.values():
                            if scanner_progress.status is MCScannerStatus.RUNNING:
                                scanner_progress.mark_failed()

                # A finished scan whose results file cannot be read as results
                # (the two branches above that keep the entry's status). The
                # status is the runner's and stands; what the response says
                # about the RESULTS has to follow the file: there are none to
                # read, so results_available is False and coverage_complete
                # None, with error_message naming the file. Reported as
                # status completed / results_available True / total_findings 0
                # / coverage_complete True, this read as a clean scan that
                # found nothing, with the reason in a field a client checking
                # the counts never looks at.
                results_unreadable = (
                    entry.status in FINISHED_WITH_RESULTS
                    and scan_progress.status == "failed"
                )
                # A finished scan with no results of its own to read for the
                # other reasons nothing was read above (foreign_output): its
                # output directory is gone (never created, or removed since), a
                # later scan has taken the one output tree over
                # (output_superseded), or the tree holds the previous scan's
                # results put back (output_holds_previous_results). Each left
                # the response at status completed / results_available True /
                # total_findings 0 / error_message None, the same clean-scan
                # reading the unreadable-file case had, and a client checking
                # results_available found nothing wrong. The directory that is
                # gone is named in error_message when the entry carries no
                # reason of its own; a superseded scan is named by superseded_by;
                # a put-back is named by output_holds_previous_results.
                results_absent = (
                    entry.status in FINISHED_WITH_RESULTS and foreign_output
                )
                results_unavailable = results_unreadable or results_absent
                output_missing_message = (
                    f"Output directory {output_dir} does not exist"
                    if output_missing and entry.status in ENDED
                    else None
                )

                # Convert scan progress to dictionary
                progress_dict = scan_progress.to_dict()

                # Coverage of a finished scan. The runner records it when it closes
                # the entry; an entry closed without one (a workspace project the
                # payload did not mention, a caller using update_scan_status) is
                # assessed from the results file. None while the scan runs, and for
                # a failed or cancelled one, because whether that covered everything
                # is not a question with an answer. The gap lists the runner
                # recorded are kept below (they describe the run), but
                # coverage_complete is None when the results cannot be read:
                # coverage of results that are not there is not an answer either.
                coverage = entry.coverage
                if (
                    coverage is None
                    and entry.status in FINISHED_WITH_RESULTS
                    and not foreign_output
                    and not results_unreadable
                ):
                    # Guarded: this runs on every poll of such an entry, and a
                    # results set the assessment cannot read would otherwise
                    # fail every progress call for the scan from here on. The
                    # progress is still reported, with coverage unknown.
                    try:
                        model = load_aggregated_results_model(output_dir)
                        if model is not None:
                            _, coverage = assess_coverage(model)
                    except Exception as e:
                        self._logger.warning(
                            f"Coverage of scan {scan_id} could not be assessed "
                            f"from its results: {type(e).__name__}: {e}"
                        )
                        coverage = None
                coverage_complete: Optional[bool] = None
                if (
                    entry.status in FINISHED_WITH_RESULTS
                    and coverage is not None
                    and not results_unavailable
                ):
                    coverage_complete = not coverage_has_gap(coverage)

                # Which scanners did not run, and why. The `scanners` map below
                # now carries a per-scanner status, but only as one of
                # MCScannerStatus' five values: it cannot separate a tool that is
                # not installed from one the configuration excluded, and both
                # arrive there as "skipped". This list carries that reason, which
                # is the difference between "install it" and "you turned it off".
                #
                # Computed here even though cli/mcp_server.py recomputes it from
                # the same file, because that is not the only consumer:
                # mcp_tools.mcp_get_scan_progress and
                # scan_management.check_scan_progress both hand this payload
                # straight back to their callers.
                status_summary = (
                    {"scanner_statuses": {}, "skipped_scanners": []}
                    if foreign_output
                    else summarize_scanner_statuses(
                        output_dir, environment_values=entry.environment_values
                    )
                )

                # The gap lists: the runner's coverage when it recorded one,
                # else the empty payload. When neither names a tool the stop
                # could not end, the entry's own record (record_cancel_outcome)
                # fills could_not_stop, in the payload's row shape and by tool
                # basename, never pid: a CANCELLED scan whose tool survived
                # read could_not_stop [] here while register_scan refused its
                # directory for that same tool, and only the free-text warning
                # said why.
                coverage_payload = (
                    coverage if coverage is not None else _empty_coverage()
                )
                if entry.could_not_stop and not coverage_payload.get("could_not_stop"):
                    # Imported here as the other utils imports of this module
                    # are; the wording has one home (subprocess_utils).
                    from automated_security_helper.utils.subprocess_utils import (
                        could_not_stop_sentence,
                    )

                    coverage_payload = {
                        **coverage_payload,
                        "could_not_stop": [
                            {
                                "scanner": name,
                                "reason": could_not_stop_sentence(name),
                            }
                            for name in dict.fromkeys(
                                _shown_tool_name(tool)
                                for tool, _pid in entry.could_not_stop
                            )
                        ],
                    }
                warnings = list(entry.warnings)
                if not name_process_ids:
                    # Read-side redaction: the stored texts keep their pids
                    # (a local read still names them); this response does not.
                    warnings = [_without_process_ids(text) for text in warnings]
                    coverage_payload = _coverage_without_process_ids(coverage_payload)

                # Combine registry entry information with progress info
                result = {
                    # Set explicitly on the path where the call worked. Only
                    # create_error_response had ever set this key, always to
                    # False, so a consumer testing `not
                    # progress_info.get("success")` got the same answer on both
                    # branches and its guard returned unconditionally.
                    "success": True,
                    "scan_id": scan_id,
                    "directory_path": entry.directory_path,
                    "output_directory": str(output_dir),
                    "start_time": entry.start_time.isoformat(),
                    "end_time": entry.end_time.isoformat() if entry.end_time else None,
                    "status": entry.status.value,
                    "severity_threshold": entry.severity_threshold,
                    "requested_severity_threshold": (
                        entry.requested_severity_threshold
                    ),
                    "config_path": entry.config_path,
                    "warnings": warnings,
                    # The entry's reason when it has one; else, for an ended
                    # scan, what the file read found, so a finished scan whose
                    # results file is now unreadable says so without the entry
                    # being re-closed; else, for an ended scan whose output
                    # directory is gone, that it is. A running scan's file is
                    # partial by nature and carries no such message. The file's
                    # text is redacted with the entry's environment values as
                    # every message the registry applies is (_apply_status):
                    # it names the results path and what the parse met, and
                    # this arm used to be the one path that skipped that.
                    "error_message": entry.error_message
                    or (
                        _without_environment_values(
                            scan_progress.error_message, entry.environment_values
                        )
                        if entry.status in ENDED
                        else None
                    )
                    or output_missing_message,
                    # The CLI's code for a scan ASH ended with an exit, so a client
                    # can branch on why it failed as a script branches on the
                    # CLI's status. None for any other ending.
                    "exit_code": entry.exit_code,
                    "exit_code_meaning": (
                        None
                        if entry.exit_code is None
                        else ASH_EXIT_CODES.get(entry.exit_code, "unknown exit code")
                    ),
                    # "The scan has ended", from the entry alone. The server tells
                    # clients to poll until this is true, so it has to be true for
                    # every ending, a cancelled scan and one that failed before
                    # writing results included, and it never depends on a results
                    # file, which can be a previous scan's. Which ending it was is
                    # `status`; whether there are results is `results_available`;
                    # whether they cover everything is `coverage_complete`.
                    "is_complete": entry.status in ENDED,
                    # False for a finished scan whose results file is now
                    # unusable (results_unreadable above), or whose results are
                    # not in its output tree at all (results_absent above: the
                    # tree is gone, a later scan holds it, or it holds the
                    # previous scan's results put back): the status says the
                    # scan finished, this says its results cannot be read.
                    "results_available": entry.status in FINISHED_WITH_RESULTS
                    and not results_unavailable,
                    "output_holds_previous_results": previous_only,
                    # True once a later scan of the same directory has taken the
                    # one output tree over: nothing below is read from the files,
                    # so without this a superseded scan read exactly like a scan
                    # that completed and found nothing.
                    "output_superseded": superseded,
                    # The later scans whose files the output tree holds, oldest
                    # first; empty when output_superseded is False. A client that
                    # wants this scan's results has none to read, and this names
                    # the scan whose results it would be reading instead.
                    "superseded_by": superseded_by if superseded else [],
                    "coverage_complete": coverage_complete,
                    **coverage_payload,
                    "completed_scanners": scan_progress.completed_scanners,
                    "finished_scanners": scan_progress.finished_scanners,
                    "total_scanners": scan_progress.total_scanners,
                    "scanner_status_counts": scan_progress.scanner_status_counts,
                    "total_findings": scan_progress.total_findings,
                    "severity_counts": scan_progress.severity_counts,
                    "scanners": progress_dict.get("scanners", {}),
                    "skipped_scanners": status_summary["skipped_scanners"],
                }

                return result

            except Exception as e:
                # Handle unexpected errors during progress checking
                if isinstance(e, MCPResourceError):
                    # If it's already an MCPResourceError, just add scan context if needed
                    if "scan_id" not in e.context:
                        e.context["scan_id"] = scan_id
                    raise e
                else:
                    # Wrap other exceptions in MCPResourceError
                    self._logger.error(
                        f"Error checking scan progress: {str(e)}", exc_info=True
                    )
                    raise MCPResourceError(
                        f"Failed to check scan progress: {str(e)}",
                        context={
                            "scan_id": scan_id,
                            "directory_path": entry.directory_path,
                            "output_directory": str(output_dir),
                            "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                            "error_type": type(e).__name__,
                            "error_message": str(e),
                        },
                    )


# Create a global instance of the scan registry
_scan_registry = ScanRegistry()


def get_scan_registry() -> ScanRegistry:
    """
    Get the global scan registry instance.

    Returns:
        Global scan registry instance
    """
    return _scan_registry
