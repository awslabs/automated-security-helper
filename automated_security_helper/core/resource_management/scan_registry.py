#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Scan registry and management components for ASH MCP server.

This module provides classes and functions for managing scan metadata and tracking
active scans. It implements a thread-safe registry to track active scans and
provides functions for listing, cancelling, and cleaning up scans.
"""

import os
import signal
import uuid
from datetime import datetime
from enum import Enum
from pathlib import Path
from threading import Event, Lock

from automated_security_helper.core.cancellation import CancelEvent
from automated_security_helper.core.constants import ASH_EXIT_CODES
from typing import Any, Dict, Iterable, List, Optional, Tuple

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_tracking import (
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

    Returns the path unresolved on an OSError rather than raising. Callers here
    have already run ``validate_directory_path``, which requires the directory to
    exist, so this is a guard against a platform refusing to resolve a path that
    exists rather than an expected branch -- and falling back to the raw form
    restores the old comparison for that one entry instead of failing the call.
    """
    try:
        return Path(directory_path).resolve()
    except OSError:
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
#: ``results_available`` of a progress response. ``coverage_complete`` is the
#: separate answer to "did it cover everything".
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
    """The coverage payload of a scan with no gap to report."""
    return {
        "incomplete_scanners": [],
        "no_scanner_ran": False,
        "incomplete_converters": [],
        "unevaluated_rules": [],
        "stale_content_databases": [],
    }


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
        self.output_directory = output_directory
        self.start_time = datetime.now()
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
        """
        self.status = MCScanStatus.RUNNING
        self.process_id = process_id

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

        True while it is active, and after it was closed for as long as its
        runner has not finished. register_scan refuses another scan of the
        directory, and counts the scan against max_concurrent_scans, while this
        holds.
        """
        return self.is_active() or (self.has_runner and not self.runner_done.is_set())


def _slot_of(entry: "ScanRegistryEntry") -> Tuple[str, str]:
    """The max_concurrent_scans slot an entry holds: its shared slot, or its own."""
    if entry.slot is not None:
        return ("shared", entry.slot)
    return ("own", entry.scan_id)


class ScanRegistry:
    """Thread-safe registry for tracking active scans."""

    def __init__(self) -> None:
        """Initialize the scan registry."""
        self._registry: Dict[str, ScanRegistryEntry] = {}
        self._registry_lock = Lock()
        self._logger = ASH_LOGGER

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
    ) -> str:
        """
        Register a new scan in the registry.

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
            # would let it address that scan or learn its outcome.
            requested = _canonical_directory(directory_path)
            for entry in self._registry.values():
                if (
                    _canonical_directory(entry.directory_path) == requested
                    and entry.occupies_its_directory()
                ):
                    owned = entry.session_id == _owner(session_id)
                    named: Dict[str, Any] = {"directory_path": directory_path}
                    if owned:
                        named["scan_id"] = entry.scan_id
                    if not entry.is_active():
                        ending = f" ({entry.status.value})" if owned else ""
                        raise MCPResourceError(
                            f"Directory {directory_path} has a scan that is still "
                            f"stopping{ending}",
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

    def get_scan_by_directory(self, directory_path: str) -> Optional[ScanRegistryEntry]:
        """
        Get the active scan for a directory.

        Args:
            directory_path: Path to the directory

        Returns:
            Active scan registry entry or None if not found

        Canonicalised on both sides, matching :meth:`register_scan`. The two have
        to agree: a caller told "directory /proj/ already has an active scan" and
        given that scan's id has to be able to reach the same entry by the same
        string, and before this they could not.
        """
        requested = _canonical_directory(directory_path)
        with self._registry_lock:
            for entry in self._registry.values():
                if (
                    _canonical_directory(entry.directory_path) == requested
                    and entry.is_active()
                ):
                    return entry
            return None

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
            True if the scan was updated, False if not found
        """
        if status == MCScanStatus.INCOMPLETE:
            # finish_scan is the only way in, because it carries the coverage gap.
            raise ValueError(
                f"Scan {scan_id} cannot be marked incomplete without its coverage "
                "gap; close it with finish_scan(..., coverage=...)"
            )
        with self._registry_lock:
            entry = self._registry.get(scan_id)
            if entry is None:
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
        if error_message and entry.environment_values:
            # Imported here: utils.error_text defers its config imports, and
            # the registry is imported while the config package loads.
            from automated_security_helper.utils.error_text import (
                text_without_values,
            )

            error_message = text_without_values(error_message, entry.environment_values)
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

        self._logger.info(f"Updated scan {scan_id} status to {status.value}")

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
        if status == MCScanStatus.INCOMPLETE and not coverage:
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
                if (
                    requested is not None
                    and _canonical_directory(entry.directory_path) != requested
                ):
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
            # also signalled.
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
                    raise MCPResourceError(
                        f"Permission denied when trying to terminate process {entry.process_id}",
                        context={"scan_id": scan_id, "process_id": entry.process_id},
                    )
                except OSError as e:
                    self._logger.error(
                        f"Error terminating process {entry.process_id}: {str(e)}"
                    )
                    raise MCPResourceError(
                        f"Error terminating process {entry.process_id}: {str(e)}",
                        context={"scan_id": scan_id, "process_id": entry.process_id},
                    )

            # Mark the scan as cancelled, which also sets its cancel event
            entry.mark_cancelled()
            self._logger.info(
                f"Cancelled scan {scan_id}; it stops at its next cancellation check"
            )
            return True

    def cleanup_scan(self, scan_id: str) -> bool:
        """
        Remove a scan from the registry.

        Args:
            scan_id: ID of the scan to remove

        Returns:
            True if the scan was removed, False if not found
        """
        with self._registry_lock:
            if scan_id in self._registry:
                del self._registry[scan_id]
                self._logger.info(f"Removed scan {scan_id} from registry")
                return True
            return False

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
                if not entry.is_active():
                    # Check if the scan is old enough to be removed
                    end_time = entry.end_time or entry.start_time
                    if end_time.timestamp() < cutoff_time:
                        scans_to_remove.append(scan_id)

            # Remove the old scans
            for scan_id in scans_to_remove:
                del self._registry[scan_id]

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

    def check_scan_progress(
        self, scan_id: str, session_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Check the progress of a scan.

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

            # Validate output directory using our enhanced validation
            error = validate_directory_path(output_dir)
            if error:
                # Add scan context to the error
                error.context["scan_id"] = scan_id
                raise error

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
                previous_only = entry.output_holds_previous_results
                scan_progress = (
                    ScanProgress(scan_id=scan_id)
                    if previous_only
                    else create_scan_progress_from_files(scan_id, output_dir)
                )
                results_path = output_dir / "ash_aggregated_results.json"

                if entry.status == MCScanStatus.RUNNING:
                    scan_progress.mark_in_progress()
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
                        # merely parsing.
                        model = load_aggregated_results_model(output_dir)
                        if model is None:
                            entry.mark_completed()
                        else:
                            gate_fires, entry.coverage = assess_coverage(model)
                            if gate_fires:
                                entry.mark_incomplete()
                            else:
                                entry.mark_completed()
                elif scan_progress.status == "failed":
                    # The results file exists and cannot be read as results.
                    entry.mark_failed(
                        scan_progress.error_message
                        or f"Aggregated results file {results_path} could not be read"
                    )
                elif scan_progress.results_pending:
                    # A JSON object with neither scanner_results nor sarif is not a
                    # results document. Before anything has closed the entry that
                    # is "not finished"; once it was closed as completed, the final
                    # document never arrived.
                    if entry.status == MCScanStatus.COMPLETED:
                        scan_progress.mark_failed()
                        scan_progress.error_message = (
                            f"Aggregated results file {results_path} has neither "
                            "scanner_results nor sarif, and the scan has ended, so it "
                            "never wrote its final results"
                        )
                        entry.mark_failed(scan_progress.error_message)
                elif entry.status == MCScanStatus.COMPLETED:
                    # No results file, and whoever ran the scan closed the entry as
                    # completed. The entry owns the lifecycle here: a workspace
                    # closes a project's entry this way when the run returned and
                    # nothing says the project did not.
                    scan_progress.mark_completed()

                # Convert scan progress to dictionary
                progress_dict = scan_progress.to_dict()

                # Coverage of a finished scan. The runner records it when it closes
                # the entry; an entry closed without one (a workspace project the
                # payload did not mention, a caller using update_scan_status) is
                # assessed from the results file. None while the scan runs, and for
                # a failed or cancelled one, because whether that covered everything
                # is not a question with an answer.
                coverage = entry.coverage
                if (
                    coverage is None
                    and entry.status in FINISHED_WITH_RESULTS
                    and not previous_only
                ):
                    model = load_aggregated_results_model(output_dir)
                    if model is not None:
                        _, coverage = assess_coverage(model)
                coverage_complete: Optional[bool] = None
                if entry.status in FINISHED_WITH_RESULTS and coverage is not None:
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
                    if previous_only
                    else summarize_scanner_statuses(output_dir)
                )

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
                    "warnings": entry.warnings,
                    "error_message": entry.error_message,
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
                    "results_available": entry.status in FINISHED_WITH_RESULTS,
                    "output_holds_previous_results": previous_only,
                    "coverage_complete": coverage_complete,
                    **(coverage if coverage is not None else _empty_coverage()),
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
