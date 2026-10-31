#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
File-based scan tracking utilities for ASH MCP server.

This module provides utility functions to check for the existence of result files
and parse scan result files to extract progress information. It implements a more
reliable approach to track scan progress and completion than event-based tracking.
"""

import json
import os
import stat
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set

from automated_security_helper.core.resource_management.error_handling import (
    _NotARegularFile,
    _read_regular_file_text,
)
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    warning_of_dropped_keys,
)
from automated_security_helper.utils.error_text import (
    error_text,
    log_unexpected_error,
    text_without_values,
    validation_errors_in,
)
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.scanner_tool_types import result_scanner_name
from automated_security_helper.utils.severity_ladder import result_severity
from automated_security_helper.utils.terminal_text import raw_controls_on_one_line

# Configure module logger
_logger = ASH_LOGGER

# The severity buckets this module's progress views count into, plus the bucket
# that catches everything else.
#
# UNKNOWN_SEVERITY exists because a finding must never be counted in
# total_findings and nowhere in severity_counts. It used to be: the summary held
# only the six named buckets and every producer guarded with
# `if severity in <buckets>`, so a finding whose severity was missing, or was a
# value outside the ladder -- a SARIF `level` of "error" or "warning", say --
# was dropped from the breakdown while still counting toward the total. For a
# security scanner that is the wrong direction to fail in: the finding is real,
# and it disappeared from the only view that says how bad things are.
#
# Every one of the three sites that builds one of these dicts derives it from
# here, because the bug was originally fixed in one of them and left in the
# other two.
#
# This is deliberately NOT the same thing as ASH's severity ladder. The
# canonical per-scanner counts in the aggregated results file are typed by
# ScannerTargetStatusInfo and have a fixed field set; this constant governs only
# the MCP progress and summary views assembled in this module.
SEVERITY_BUCKETS = ("critical", "high", "medium", "low", "info", "suppressed")
UNKNOWN_SEVERITY = "unknown"


def empty_severity_counts() -> Dict[str, int]:
    """A zeroed severity breakdown, including the catch-all bucket."""
    counts = dict.fromkeys(SEVERITY_BUCKETS, 0)
    counts[UNKNOWN_SEVERITY] = 0
    return counts


class MCScannerStatus(Enum):
    """Status of an individual scanner."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


#: ``core.enums.ScannerStatus`` value -> the ``MCScannerStatus`` it means here.
#: Keyed on the string rather than on the enum member, matching
#: :func:`summarize_scanner_statuses`, which reads the same field out of the same
#: document and also compares strings -- the value arrives from JSON, so it is a
#: string by the time either function sees it.
_SCANNER_STATUS_MAP = {
    "PASSED": MCScannerStatus.COMPLETED,
    "FAILED": MCScannerStatus.FAILED,
    "ERROR": MCScannerStatus.FAILED,
    "MISSING": MCScannerStatus.SKIPPED,
    "SKIPPED": MCScannerStatus.SKIPPED,
}


def scanner_status_from_results(status: Any) -> MCScannerStatus:
    """Map a ``scanner_results`` status onto the progress view's status.

    ``create_scan_progress_from_files`` used to pass the literal
    ``MCScannerStatus.COMPLETED`` for every entry in ``scanner_results`` and
    never read the status the document recorded, so an aggregated file reporting
    bandit PASSED, semgrep MISSING and grype ERROR came back as
    ``completed_scanners`` 3 of 3 with all three statuses ``'completed'``. A
    scanner that never ran read as one that ran and found nothing, which for a
    security tool inverts the answer. That document is the fixture in
    ``tests/unit/core/resource_management/test_mcp_success_contract.py``'s
    ``test_completed_scanners_counts_only_the_ones_that_ran_clean``, which now
    asserts 1 of 3.

    An unrecognized value maps to FAILED rather than to COMPLETED or SKIPPED.
    ``ScannerStatus`` is a closed set of five members, all of them mapped above,
    so anything else means the document disagrees with the code that wrote it.
    FAILED is the loudest of the available outcomes and the only one that both
    keeps the scanner out of ``completed_scanners`` and surfaces as a problem
    rather than as a routine skip.
    """
    if isinstance(status, str):
        return _SCANNER_STATUS_MAP.get(status.upper(), MCScannerStatus.FAILED)
    return MCScannerStatus.FAILED


def _recorded_status_word(status: Any) -> Optional[str]:
    """The status word a ``scanner_results`` entry recorded, upper-cased, or None.

    The results model reads the word without regard to case; a value that is
    not a string (null, a number) is no word. Callers that count the scanners
    that ran to an end compare this with the recorded words PASSED and FAILED
    (``get_scan_results``' rule), not with the registry view's status mapping,
    which folds ERROR into FAILED for its status column.
    """
    return status.upper() if isinstance(status, str) else None


#: The scanner states that are an ending: ``finished_scanners`` counts these.
_FINISHED_SCANNER_STATUSES = frozenset(
    {MCScannerStatus.COMPLETED, MCScannerStatus.FAILED, MCScannerStatus.SKIPPED}
)

#: ``scanner_status_counts`` key per state. COMPLETED means the scanner PASSED,
#: and is named for that so the breakdown cannot be read as "finished".
_SCANNER_STATUS_COUNT_NAMES = {
    MCScannerStatus.COMPLETED: "passed",
    MCScannerStatus.FAILED: "failed",
    MCScannerStatus.SKIPPED: "skipped",
    MCScannerStatus.RUNNING: "running",
    MCScannerStatus.PENDING: "pending",
}


class ScannerProgress:
    """
    Progress information for an individual scanner.

    This class tracks the progress of a single scanner, including its status,
    target types (source or converted), duration, and finding counts.
    """

    def __init__(
        self,
        scanner_name: str,
        target_type: str,
        status: MCScannerStatus = MCScannerStatus.PENDING,
        duration: Optional[float] = None,
        finding_count: int = 0,
        severity_counts: Optional[Dict[str, int]] = None,
    ):
        """
        Initialize a scanner progress tracker.

        Args:
            scanner_name: Name of the scanner
            target_type: Type of target being scanned ("source" or "converted")
            status: Current status of the scanner
            duration: Duration of the scan in seconds (if completed)
            finding_count: Number of findings detected
            severity_counts: Dictionary mapping severity levels to counts
        """
        self.scanner_name = scanner_name
        self.target_type = target_type
        self.status = status
        self.duration = duration
        self.finding_count = finding_count
        # Copy the dict (if provided) so caller's dict isn't aliased; otherwise
        # build a fresh default so instances don't share the same dict.
        self.severity_counts = (
            dict(severity_counts)
            if severity_counts
            else {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "suppressed": 0,
            }
        )
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

    def mark_running(self) -> None:
        """Mark the scanner as running and record the start time."""
        self.status = MCScannerStatus.RUNNING
        self.start_time = datetime.now()

    def mark_completed(self) -> None:
        """Mark the scanner as completed and calculate duration."""
        self.status = MCScannerStatus.COMPLETED
        self.end_time = datetime.now()
        if self.start_time:
            duration = (self.end_time - self.start_time).total_seconds()
            # Ensure duration is at least a small positive value for cross-platform compatibility
            self.duration = max(duration, 0.001)

    def mark_failed(self) -> None:
        """Mark the scanner as failed and calculate duration."""
        self.status = MCScannerStatus.FAILED
        self.end_time = datetime.now()
        if self.start_time:
            duration = (self.end_time - self.start_time).total_seconds()
            # Ensure duration is at least a small positive value for cross-platform compatibility
            self.duration = max(duration, 0.001)

    def mark_skipped(self) -> None:
        """Mark the scanner as skipped."""
        self.status = MCScannerStatus.SKIPPED

    def update_findings(self, findings: List[Dict[str, Any]]) -> None:
        """
        Update finding counts based on a list of findings.

        The count is the non-suppressed findings, SummaryStats' ``total``: a
        finding whose severity is ``suppressed`` is in the ``suppressed``
        bucket beside the count and not in it, as the recorded counts of the
        per-target and aggregated documents are read.

        Args:
            findings: List of finding dictionaries
        """
        self.severity_counts = extract_findings_summary(findings)
        self.finding_count = sum(
            value
            for bucket, value in self.severity_counts.items()
            if bucket != "suppressed"
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the scanner progress to a dictionary.

        Returns:
            Dictionary representation of the scanner progress
        """
        return {
            "scanner_name": self.scanner_name,
            "target_type": self.target_type,
            "status": self.status.value,
            "duration": self.duration,
            "finding_count": self.finding_count,
            "severity_counts": self.severity_counts,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
        }


#: The order in which one scanner's targets decide the scanner's own status. A
#: scanner with a target still unfinished has not finished, whatever its other
#: targets did. Of the finished ones a failure outranks a pass, and a pass outranks
#: a skip: a scanner that ran on one target and had nothing to do on another ran.
_SCANNER_STATUS_PRECEDENCE = (
    MCScannerStatus.RUNNING,
    MCScannerStatus.PENDING,
    MCScannerStatus.FAILED,
    MCScannerStatus.COMPLETED,
    MCScannerStatus.SKIPPED,
)


def _status_of_scanner(targets: Dict[str, ScannerProgress]) -> MCScannerStatus:
    """One scanner's status over its targets (source and converted)."""
    statuses = {progress.status for progress in targets.values()}
    for status in _SCANNER_STATUS_PRECEDENCE:
        if status in statuses:
            return status
    return MCScannerStatus.SKIPPED


class ScanProgress:
    """
    Aggregate progress information for a complete scan.

    This class aggregates progress information from multiple scanners and
    provides an overall view of the scan progress.
    """

    def __init__(
        self,
        scan_id: str,
        status: str = "in_progress",
        start_time: Optional[datetime] = None,
    ):
        """
        Initialize a scan progress tracker.

        Args:
            scan_id: ID of the scan
            status: Current status of the scan
            start_time: Start time of the scan
        """
        self.scan_id = scan_id
        self.status = status
        self.scanners: Dict[str, Dict[str, ScannerProgress]] = {}
        self.start_time = start_time or datetime.now()
        self.end_time: Optional[datetime] = None
        self.duration: Optional[float] = None
        self.total_findings: int = 0
        self.severity_counts: Dict[str, int] = empty_severity_counts()
        # Why the failure happened, for the caller that has to act on it. A
        # failed status with no reason is what let a truncated results file be
        # reported to an operator as a finished scan with nothing to report.
        self.error_message: Optional[str] = None
        # The aggregated file exists but is not the final document yet; see
        # create_scan_progress_from_files. The caller decides what that means,
        # because only the registry knows whether the scan is still running.
        self.results_pending: bool = False

    def add_scanner_progress(self, scanner_progress: ScannerProgress) -> None:
        """
        Add or update progress information for a scanner.

        Args:
            scanner_progress: Scanner progress information
        """
        scanner_name = scanner_progress.scanner_name
        target_type = scanner_progress.target_type

        # Initialize scanner dictionary if it doesn't exist
        if scanner_name not in self.scanners:
            self.scanners[scanner_name] = {}

        # Add or update scanner progress
        self.scanners[scanner_name][target_type] = scanner_progress

        # Update total findings and severity counts
        self.update_totals()

    def update_totals(self) -> None:
        """Update total findings and severity counts from all scanners.

        A per-scanner count under a key this aggregate does not name is folded
        into UNKNOWN_SEVERITY rather than discarded. Scanner counts can arrive
        verbatim from the aggregated results file, so this layer cannot assume
        the producer used only the named buckets.
        """
        self.total_findings = 0
        self.severity_counts = empty_severity_counts()

        for scanner_dict in self.scanners.values():
            for scanner_progress in scanner_dict.values():
                self.total_findings += scanner_progress.finding_count
                for severity, count in scanner_progress.severity_counts.items():
                    bucket = severity if severity in self.severity_counts else None
                    if bucket is None:
                        bucket = UNKNOWN_SEVERITY
                    self.severity_counts[bucket] += count

    def mark_completed(self) -> None:
        """Mark the scan as completed and calculate duration."""
        self.status = "completed"
        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()
        # Ensure duration is at least a small positive value for cross-platform compatibility
        self.duration = max(duration, 0.001)

    def mark_failed(self, error_message: Optional[str] = None) -> None:
        """Mark the scan as failed and calculate duration.

        Args:
            error_message: Why the scan failed. Optional so existing callers
                that have nothing to add keep working, but supply it wherever
                one is available: this is the only channel by which a parse
                failure reaches the operator polling for progress.
        """
        self.status = "failed"
        self.end_time = datetime.now()
        if error_message is not None:
            self.error_message = error_message
        duration = (self.end_time - self.start_time).total_seconds()
        # Ensure duration is at least a small positive value for cross-platform compatibility
        self.duration = max(duration, 0.001)

    def mark_in_progress(self) -> None:
        """Mark the scan as not finished, keeping whatever scanners were read.

        For a scan whose runner has not closed it: a results file on disk is
        partial results at most, whatever it says about itself.
        """
        self.status = "in_progress"
        self.end_time = None
        self.duration = None

    @property
    def completed_scanners(self) -> int:
        """
        Get the number of completed scanners: those that ran and PASSED.

        A scanner that failed, errored or never ran is not counted here; see
        :attr:`finished_scanners` for every scanner that has ended.

        Every count here is of scanners, not of (scanner, target) pairs: one that
        ran on the source and on its converted files is one scanner, as it is in
        the aggregated results file, so the counts do not change when that file
        replaces the per-target ones. A scanner's status over its targets is
        :func:`_status_of_scanner`.

        Returns:
            Number of completed scanners
        """
        return sum(
            1
            for targets in self.scanners.values()
            if _status_of_scanner(targets) == MCScannerStatus.COMPLETED
        )

    @property
    def finished_scanners(self) -> int:
        """The number of scanners that have ended, whatever their status.

        PASSED, FAILED or errored, MISSING or SKIPPED all count. This is the
        progress count: ``completed_scanners`` counts PASSED only, so a finished
        scan with one finding or one missing tool never reaches 100% by it. How
        each scanner ended is :attr:`scanner_status_counts`.
        """
        return sum(
            1
            for targets in self.scanners.values()
            if _status_of_scanner(targets) in _FINISHED_SCANNER_STATUSES
        )

    @property
    def scanner_status_counts(self) -> Dict[str, int]:
        """How many scanners are in each state.

        ``passed`` is PASSED, ``failed`` FAILED or ERROR, ``skipped`` MISSING or
        SKIPPED; ``running`` and ``pending`` have not finished. The keys are
        always all present.
        """
        counts = dict.fromkeys(_SCANNER_STATUS_COUNT_NAMES.values(), 0)
        for targets in self.scanners.values():
            counts[_SCANNER_STATUS_COUNT_NAMES[_status_of_scanner(targets)]] += 1
        return counts

    @property
    def total_scanners(self) -> int:
        """
        Get the total number of scanners.

        Returns:
            Total number of scanners: one per scanner name, however many targets
            it has results for
        """
        return len(self.scanners)

    @property
    def is_complete(self) -> bool:
        """
        Check if the scan is complete.

        Returns:
            True if the scan is complete, False otherwise
        """
        return self.status in ["completed", "failed"]

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the scan progress to a dictionary.

        Returns:
            Dictionary representation of the scan progress
        """
        scanner_progress_dict = {}
        for scanner_name, target_dict in self.scanners.items():
            scanner_progress_dict[scanner_name] = {
                target_type: progress.to_dict()
                for target_type, progress in target_dict.items()
            }

        return {
            "scan_id": self.scan_id,
            "status": self.status,
            "is_complete": self.is_complete,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": self.duration,
            "completed_scanners": self.completed_scanners,
            "finished_scanners": self.finished_scanners,
            "total_scanners": self.total_scanners,
            "scanner_status_counts": self.scanner_status_counts,
            "total_findings": self.total_findings,
            "severity_counts": self.severity_counts,
            "scanners": scanner_progress_dict,
            "error_message": self.error_message,
        }


#: The most a per-scanner ``ASH.ScanResults.json`` is read as. The file ASH
#: writes is a few hundred bytes of metadata; a progress poll under the registry
#: lock never reads more than this from one, so a file that grows without bound
#: cannot hold the poll or its memory.
_SCANNER_RESULT_FILE_MAX_BYTES = 16 * 1024 * 1024


def is_regular_result_file(
    path: Path, max_bytes: Optional[int] = _SCANNER_RESULT_FILE_MAX_BYTES
) -> bool:
    """Whether ``path`` is a regular file, read without following a link.

    The result files under a scan's output directory are read by the progress
    poll while it holds the registry lock. ``read_text`` on a FIFO at that name
    blocks until something writes to it, and on a link it reads whatever the
    link points at as this scan's. Both are refused here, as are sockets and
    devices: only a regular file is read, of at most ``max_bytes`` when a bound
    is given (the per-scanner files are small; the aggregated results file
    carries the whole SARIF and is read with no bound).
    """
    try:
        info = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISREG(info.st_mode):
        return False
    return max_bytes is None or info.st_size <= max_bytes


#: How a result file is opened for reading: by descriptor, never following a
#: link at its name (O_NOFOLLOW, where the platform has it), never blocking on a
#: FIFO left there (O_NONBLOCK), closed on exec.
_RESULT_READ_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_BINARY", 0)
)


def _read_result_file_bytes(path: Path, max_bytes: Optional[int]) -> Optional[bytes]:
    """The bytes of the regular file at ``path``, or None.

    None when the name cannot be opened, when what was opened is not a regular
    file, or when the file is larger than ``max_bytes`` (a bound of None reads
    the whole file). The check and the read are one descriptor: the name is
    opened without following a link and without blocking, the descriptor is
    ``fstat``-ed, and at most ``max_bytes + 1`` bytes are read from that same
    descriptor. :func:`is_regular_result_file` looks at the name; a scanner
    that swaps a link or a FIFO in between its look and a read by name had the
    link followed or the reader held, and a file that grew after the look was
    read in full. Through this, nothing past the bound is read and what is read
    is what was checked.
    """
    try:
        fd = os.open(path, _RESULT_READ_FLAGS)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None
        if max_bytes is not None and info.st_size > max_bytes:
            return None
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            if max_bytes is None:
                return handle.read()
            data = handle.read(max_bytes + 1)
            return data if len(data) <= max_bytes else None
    except OSError:
        return None
    finally:
        if fd != -1:
            os.close(fd)


def _read_scanner_result_document(result_file: Path) -> Optional[Dict[str, Any]]:
    """The JSON object a scanner wrote into its ``ASH.ScanResults.json``, or None.

    Read through :func:`_read_result_file_bytes` with the per-scanner bound, so
    the regular-file check, the bound and the read are one descriptor.
    """
    raw = _read_result_file_bytes(result_file, _SCANNER_RESULT_FILE_MAX_BYTES)
    if raw is None:
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def _findings_of_document(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The ``findings`` array of a scanner's result document, or an empty list.

    The per-target file ASH writes carries none (its counts are the record;
    see :func:`_counts_of_document`); a document with a findings array is read
    as the array says.
    """
    findings = data.get("findings")
    return findings if isinstance(findings, list) else []


def _status_of_document(data: Dict[str, Any]) -> Optional[str]:
    """The ``status`` a scanner wrote into its result document, or None."""
    status = data.get("status")
    return status if isinstance(status, str) and status else None


#: Keys of a ``severity_counts`` object that total the buckets beside them and
#: are not buckets themselves.
_SEVERITY_SUMMARY_KEYS = frozenset({"total", "actionable"})


def _counts_of_document(
    data: Dict[str, Any],
) -> Tuple[Optional[int], Optional[Dict[str, int]]]:
    """The ``finding_count`` and ``severity_counts`` a scanner recorded, or Nones.

    The per-target file ASH writes carries no findings array; its counts are
    the only record of what the scanner found until the aggregated results file
    exists. A progress view that counted only a findings array reported every
    finished scanner as 0 findings with all-zero severity counts while a scan
    ran.

    The summary fields a severity-count object can carry beside its buckets
    (``total`` and ``actionable``, the totals ``ScannerSeverityCount`` exposes)
    are not buckets: read as one, each added its value under ``unknown``, a
    finding that does not exist.
    """
    count = data.get("finding_count")
    counts = data.get("severity_counts")
    return (
        count
        if isinstance(count, int) and not isinstance(count, bool) and count >= 0
        else None,
        {
            str(key).lower(): value
            for key, value in counts.items()
            if isinstance(value, int)
            and not isinstance(value, bool)
            and value >= 0
            and str(key).lower() not in _SEVERITY_SUMMARY_KEYS
        }
        if isinstance(counts, dict)
        else None,
    )


def _progress_counts_of_document(
    document: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], int, Dict[str, int]]:
    """The findings, count and buckets a progress view reports for one document.

    The one rule both file-based views follow (``get_scanner_progress`` and
    ``create_scan_progress_from_files`` each had a copy, and the copies
    differed). The buckets are the ones the scanner recorded
    (``severity_counts``, folded into the named buckets with anything else
    under ``unknown``), else the ones the findings array gives. The count is the
    recorded ``finding_count`` when the document carries one. Without one it is
    the non-suppressed sum of the recorded buckets, the count the aggregated
    path gives the same scanner (``_add_aggregated_scanner_progress``), and
    failing both the length of the findings array
    (``test_malformed_counts_are_read_defensively``).

    The one adjustment: a recorded count beside recorded buckets has the
    ``suppressed`` bucket taken out of it. The per-target file ASH writes counts
    suppressed findings in ``finding_count`` (the executor sets it to
    ``severity_counts.total + severity_counts.suppressed``), while the
    aggregated file's per-scanner ``finding_count`` is ``ScannerMetrics.total``,
    which leaves them out, so a scan's ``total_findings`` dropped by its
    suppressed count the moment the aggregated file appeared. Reported this way
    the count is SummaryStats' ``total``: the non-suppressed findings, with
    ``suppressed`` a bucket beside it, mid-scan and after.

    A recorded count beside NO usable buckets (no ``severity_counts``, or one
    that is not an object) is graded by the findings array, and whatever that
    array does not account for lands in ``unknown``: the module's rule is that
    a finding is never in the total and in no bucket, and the aggregated path
    puts such a count under ``unknown`` too, so the breakdown does not change
    when the aggregated file appears. The same holds for a recorded count
    beside buckets that do not add up to it: the difference lands in
    ``unknown``, where it used to stay in the total and in no bucket.
    """
    findings = _findings_of_document(document)
    recorded_count, recorded_counts = _counts_of_document(document)
    if not recorded_counts:
        # An object that names no usable bucket ({} or only unusable values)
        # records nothing: the findings array speaks, as it does when the
        # document has no severity_counts at all.
        recorded_counts = None
    if recorded_counts is not None:
        counts = empty_severity_counts()
        for severity, value in recorded_counts.items():
            counts[severity if severity in counts else UNKNOWN_SEVERITY] += value
    else:
        counts = extract_findings_summary(findings)
    if recorded_count is None:
        if recorded_counts is not None:
            count = sum(
                value for bucket, value in counts.items() if bucket != "suppressed"
            )
        else:
            count = len(findings)
    elif recorded_counts is not None:
        count = max(recorded_count - counts["suppressed"], 0)
        ungraded = count - (sum(counts.values()) - counts["suppressed"])
        if ungraded > 0:
            counts[UNKNOWN_SEVERITY] += ungraded
    else:
        count = recorded_count
        ungraded = recorded_count - sum(counts.values())
        if ungraded > 0:
            counts[UNKNOWN_SEVERITY] += ungraded
    return findings, count, counts


def check_scan_completion(
    output_dir: Path | None = None,
) -> bool:
    """
    Check if a scan has completed by looking for the aggregated results file.

    Args:
        output_dir: Path to the scan output directory

    Returns:
        True if the scan has completed, False otherwise
    """
    if output_dir is None:
        output_dir = Path.cwd().joinpath(".ash", "ash_output")
    aggregated_results_path = output_dir / "ash_aggregated_results.json"
    return aggregated_results_path.exists()


def resolves_to_directory_inside(directory: Path, output_dir: Path) -> bool:
    """Whether ``directory`` resolves to a directory inside ``output_dir``.

    A results directory under a scan's output directory is read only when this
    holds. Through a link, a scanner's directory would list, and its results
    file would be read from, another tree, as this scan's. A link elsewhere and
    a link to nothing are both False, so what is read says nothing about where
    a link leads.
    """
    try:
        resolved = directory.resolve(strict=True)
        return resolved.is_dir() and resolved.is_relative_to(
            output_dir.resolve(strict=True)
        )
    except (OSError, RuntimeError):
        return False


def _list_directory(directory: Path) -> List[Path]:
    """The entries of ``directory``, or none when it cannot be listed.

    The poll that reads the results directories runs while a scan starts, ends or
    cleans up, and each of those sets aside, restores or removes ``scanners/`` or a
    directory under it. One that went between the check that it is a directory and
    the listing, or that cannot be read, is a directory with no results yet, not a
    reason to fail the whole poll.
    """
    try:
        return list(directory.iterdir())
    except OSError:
        return []


def find_scanner_result_files(
    output_dir: Path | None = None,
) -> Dict[str, Dict[str, Path]]:
    """
    Find individual scanner result files to determine partial progress.

    The scanners directory, each scanner's and each target's are followed only
    when they resolve to a directory inside ``output_dir``
    (``resolves_to_directory_inside``). A directory that cannot be listed is
    skipped (``_list_directory``).

    Args:
        output_dir: Path to the scan output directory

    Returns:
        Dictionary mapping scanner names to target types and result file paths
    """
    if output_dir is None:
        output_dir = Path.cwd().joinpath(".ash", "ash_output")
    scanner_results: Dict[str, Dict[str, Path]] = {}

    # Look for scanner result files in the pattern:
    # .ash/ash_output/scanners/{scanner_name}/{target_type}/ASH.ScanResults.json
    scanners_dir = output_dir / "scanners"

    if not resolves_to_directory_inside(scanners_dir, output_dir):
        return scanner_results

    # Each level is checked on its own before it is listed and again for every
    # entry in it, so a directory swapped for a link between a check and its
    # listing lists another tree's names, and none of them passes the check of the
    # level below.
    for scanner_dir in _list_directory(scanners_dir):
        if not resolves_to_directory_inside(scanner_dir, output_dir):
            continue

        scanner_name = scanner_dir.name
        targets: Dict[str, Path] = {}

        for target_dir in _list_directory(scanner_dir):
            if not resolves_to_directory_inside(target_dir, output_dir):
                continue

            target_type = target_dir.name
            result_file = target_dir / "ASH.ScanResults.json"

            # The file itself gets the same care as the directories above it:
            # only a regular file, not a link (which would read another tree's
            # file as this scan's) nor a FIFO (which would block the poll), and
            # not one past the per-scanner bound. A file that is there and is
            # left out is said once, so a scanner does not vanish from every
            # view in silence (this runs on every poll, so once per file).
            if is_regular_result_file(result_file):
                targets[target_type] = result_file
            elif os.path.lexists(result_file):
                _report_irregular_result_file(result_file)

        # A scanner is listed once it has written a result for at least one
        # target. Listed as soon as its directory existed, it read as a
        # completed scanner before it had written anything.
        if targets:
            scanner_results[scanner_name] = targets

    return scanner_results


#: Result files already reported as left out of the progress view (a link, a
#: FIFO, a file past the bound), so each is said once per process, not once per
#: poll.
_REPORTED_IRREGULAR_RESULT_FILES: Set[str] = set()


def _report_irregular_result_file(result_file: Path) -> None:
    """Say once that a result file that is there is left out of every view."""
    key = str(result_file)
    if key in _REPORTED_IRREGULAR_RESULT_FILES:
        return
    _REPORTED_IRREGULAR_RESULT_FILES.add(key)
    _logger.warning(
        f"Result file {result_file} is not a regular file, or is larger than "
        f"{_SCANNER_RESULT_FILE_MAX_BYTES} bytes; it is left out of the progress "
        "view, so its scanner is reported from its other targets or not at all"
    )


def get_completed_scanners(
    output_dir: Path | None = None,
) -> Set[str]:
    """
    Get the set of scanners that have completed at least one target.

    A target is completed when its result file is a readable JSON object: a
    file that is not one yet (empty, truncated, mid-write) is a scanner that
    has not finished writing, which ``create_scan_progress_from_files`` reports
    as running. Read from the file's presence alone, such a scanner was
    completed here and running there.

    Args:
        output_dir: Path to the scan output directory

    Returns:
        Set of scanner names that have completed at least one target
    """
    if output_dir is None:
        output_dir = Path.cwd().joinpath(".ash", "ash_output")
    return {
        scanner_name
        for scanner_name, info in get_scanner_progress(output_dir).items()
        if info["targets_completed"]
    }


def get_scanner_progress(
    output_dir: Path | None = None,
) -> Dict[str, Dict[str, Any]]:
    """
    Get progress information for each scanner.

    ``targets_completed`` and ``targets_count`` name the targets whose result
    file is a readable JSON object. A scanner whose only result file is not one
    yet is listed with none, as ``create_scan_progress_from_files`` lists it as
    running; counted from the file's presence, the same file read as a
    completed target here and a running scanner there.

    Args:
        output_dir: Path to the scan output directory

    Returns:
        Dictionary mapping scanner names to progress information
    """
    if output_dir is None:
        output_dir = Path.cwd().joinpath(".ash", "ash_output")
    scanner_progress: Dict[str, Dict[str, Any]] = {}
    scanner_results = find_scanner_result_files(output_dir)

    for scanner_name, target_results in scanner_results.items():
        scanner_progress[scanner_name] = {
            "targets_completed": [],
            "targets_count": 0,
            "findings": [],
            # What the scanner recorded, for the per-target file ASH writes,
            # which has finding_count and severity_counts and no findings
            # array; counted from the array alone, every finished scanner read
            # as 0 findings while the scan ran.
            "finding_count": 0,
            "severity_counts": empty_severity_counts(),
        }

        # One read per file, through the regular-file guard, and the findings,
        # count and buckets derived from that one document by the one rule
        # (_progress_counts_of_document), the same create_scan_progress_from_files
        # applies.
        for target_type, result_file in target_results.items():
            try:
                document = _read_scanner_result_document(result_file)
                if document is None:
                    continue
                findings, count, counts = _progress_counts_of_document(document)
                scanner_progress[scanner_name]["targets_completed"].append(target_type)
                scanner_progress[scanner_name]["targets_count"] += 1
                scanner_progress[scanner_name]["findings"].extend(findings)
                scanner_progress[scanner_name]["finding_count"] += count
                totals = scanner_progress[scanner_name]["severity_counts"]
                for severity, value in counts.items():
                    totals[severity] += value
            except Exception as e:
                _logger.warning(
                    f"Failed to parse result file for scanner {scanner_name}, target {target_type}: {str(e)}"
                )

    return scanner_progress


def parse_scanner_result_file(
    result_file: Path | None = None,
) -> List[Dict[str, Any]]:
    """
    Parse a scanner result file to extract findings.

    Args:
        result_file: Path to the scanner result file

    Returns:
        List of findings from the scanner result file
    """
    if result_file is None:
        result_file = Path.cwd().joinpath(
            ".ash", "ash_output", "ash_aggregated_results.json"
        )

    # The same guarded read as the progress views (_read_result_file_bytes):
    # by a checked descriptor, never through a link or a FIFO at the name. No
    # bound: the default path is the aggregated results file, which carries the
    # whole SARIF. This was the one exported per-scanner reader that went
    # through a read by name.
    raw = _read_result_file_bytes(Path(result_file), max_bytes=None)
    if raw is None:
        _logger.warning(
            f"Error reading result file {result_file}: it is absent, cannot be "
            "opened, or is not a regular file"
        )
        return []
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError) as e:
        _logger.warning(f"Error reading result file {result_file}: {str(e)}")
        return []
    if not isinstance(data, dict):
        _logger.warning(
            f"Unexpected result file structure in {result_file}. "
            f"Expected either 'findings' array or 'scanner_name' metadata. "
            f"Found a {type(data).__name__}, not an object"
        )
        return []

    # Extract findings from the result file
    # The structure can be either:
    # Format 1 (expected by original code):
    # {
    #   "findings": [
    #     {
    #       "id": "...",
    #       "severity": "...",
    #       ...
    #     },
    #     ...
    #   ]
    # }
    # Format 2 (actual ASH output):
    # {
    #   "scanner_name": "detect-secrets",
    #   "target": "/path/to/project",
    #   "target_type": "source",
    #   "exit_code": 0,
    #   "finding_count": 1,
    #   "severity_counts": {...},
    #   "status": "PASSED" or "FAILED"
    # }

    if data and "findings" in data and isinstance(data["findings"], list):
        # Format 1: Direct findings array
        return data["findings"]
    elif data and "scanner_name" in data:
        # Format 2: ASH scanner result metadata (no findings in this file)
        # The actual findings are in the aggregated results file
        _logger.debug(
            f"Scanner result file {result_file} contains metadata only (no findings array). "
            f"Scanner: {data.get('scanner_name')}, Status: {data.get('status')}, "
            f"Finding count: {data.get('finding_count', 0)}"
        )
        return []
    else:
        _logger.warning(
            f"Unexpected result file structure in {result_file}. "
            f"Expected either 'findings' array or 'scanner_name' metadata. "
            f"Available keys: {list(data.keys()) if data else 'None'}"
        )
        return []


def summarize_scanner_statuses(
    output_dir: Path, environment_values: Any = ()
) -> Dict[str, Any]:
    """Read the authoritative per-scanner statuses for a scan.

    A scanner skipped for missing dependencies used to be indistinguishable from
    one that ran and found nothing, which for a security tool is the whole
    answer. The information was never lost in the core -- scan_phase records
    ``ScannerStatusInfo(status=ScannerStatus.MISSING, ...)`` in
    ``scanner_results`` -- but the MCP progress view rebuilt its own map by
    globbing ``scanners/*/*/ASH.ScanResults.json``. A scanner that never ran
    writes no such file, so it fell out of the map entirely and the remaining
    entries looked like the complete set.

    This reads ``scanner_results`` instead of re-deriving it from whatever
    happens to be on disk.

    Returns a dict with two keys, both always present:

    ``scanner_statuses``
        Every scanner ASH considered, including those that never ran.
    ``skipped_scanners``
        Only those that did not run, each with a machine-readable ``reason`` so a
        caller can tell a missing tool from a deliberate exclusion.

    Returns empty collections rather than raising. ``get_scan_progress`` polls
    this while a scan is still running, when the aggregated file does not exist
    yet, so absence is the ordinary case and not an error. A file that is not
    UTF-8 is the same: the text is not decoded, so it is not a results document.

    A ``MISSING`` scanner whose dependencies were satisfied did not run for a
    reason other than a missing tool (its filtering raised, or it could not be
    built). Its ``reason`` is the generic ``skipped``, so the reason the row
    recorded (``missing_reason``, or ``skipped_reason``) is carried as ``detail``
    on every skipped entry that has one. The reason can hold the text of an
    exception, so it is shown as the registry shows an error message: the
    values in ``environment_values`` (the ones the run's configuration read from
    the environment) are redacted from it, and control characters are written as
    escapes. Neither was done, and the reason reached a client as the writer
    recorded it.
    """
    empty: Dict[str, Any] = {"scanner_statuses": {}, "skipped_scanners": []}

    results_path = Path(output_dir) / "ash_aggregated_results.json"
    # The same guard the per-scanner files get: a FIFO or a link at this name
    # is not read (this runs under the registry lock).
    if not is_regular_result_file(results_path, max_bytes=None):
        return empty
    try:
        # The look above is by name; the read is by descriptor, opened without
        # following a link or waiting on a FIFO and checked to be a regular
        # file's, so a link or FIFO swapped in between the two is refused where
        # a reopen by name followed it or blocked under the registry lock. The
        # file is replaced atomically while a scan writes it, and on Windows a
        # read that lands in the replace fails with a PermissionError that
        # passes a moment later: retried, where one read here reported a scan that
        # had skipped scanners as having skipped none.
        raw = _read_regular_file_text(results_path)
    except (OSError, ValueError, _NotARegularFile):
        # ValueError: UnicodeDecodeError, a file that is not UTF-8.
        return empty

    try:
        data = json.loads(raw)
    except (ValueError, TypeError, RecursionError):
        # A poll can land midway through the file being written.
        return empty

    if not isinstance(data, dict):
        return empty

    scanner_results = data.get("scanner_results")
    if not isinstance(scanner_results, dict):
        return empty

    statuses: Dict[str, Any] = {}
    skipped: List[Dict[str, Any]] = []

    for scanner_name, info in scanner_results.items():
        if not isinstance(info, dict):
            continue

        status = info.get("status")
        excluded = _recorded_flag(info.get("excluded"), False)
        dependencies_satisfied = _recorded_flag(
            info.get("dependencies_satisfied"), True
        )

        # The status is read as scanner_status_from_results reads it from the
        # same document, case-insensitively, and reported in the form the
        # enum writes, so one payload does not say "missing" here and
        # "MISSING" in skipped_scanners for the same scanner. A status that is
        # not a string is reported as recorded.
        recorded_status = status.upper() if isinstance(status, str) else None
        statuses[scanner_name] = {
            "status": recorded_status if recorded_status is not None else status,
            "excluded": excluded,
            "dependencies_satisfied": dependencies_satisfied,
        }

        # FAILED and ERROR are deliberately not included. Those scanners ran;
        # reporting them as skipped would send a user looking for a missing tool.
        if recorded_status not in ("MISSING", "SKIPPED"):
            continue

        if not dependencies_satisfied:
            reason = "missing_dependencies"
        elif excluded:
            reason = "excluded_by_configuration"
        else:
            reason = "skipped"

        entry: Dict[str, Any] = {
            "scanner": scanner_name,
            "status": recorded_status,
            "reason": reason,
        }
        detail = info.get("missing_reason") or info.get("skipped_reason")
        if isinstance(detail, str) and detail:
            if environment_values:
                detail = text_without_values(detail, environment_values)
            entry["detail"] = raw_controls_on_one_line(detail)
        skipped.append(entry)

    return {"scanner_statuses": statuses, "skipped_scanners": skipped}


def _recorded_flag(value: Any, default: bool) -> bool:
    """A boolean the results document recorded, read as the results model reads it.

    A real boolean is itself. The strings and integers the model accepts for one
    (``"false"``, ``"0"``, ``0``) are read as it reads them, where ``bool()`` made
    every non-empty string true. Anything else, an absent key included, is
    ``default``, the model's own default for the field.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in ("true", "1", "yes", "on", "t", "y"):
            return True
        if text in ("false", "0", "no", "off", "f", "n"):
            return False
    return default


def parse_aggregated_results(
    output_dir: Path | None = None,
) -> Dict[str, Any] | None:
    """
    Parse the aggregated results file to extract scan results.

    Args:
        output_dir: Path to the scan output directory

    Returns:
        Dictionary containing the parsed aggregated results

    Raises:
        MCPResourceError: If the aggregated results file is not found or cannot be parsed
    """
    if output_dir is None:
        output_dir = Path.cwd().joinpath(".ash", "ash_output")
    from automated_security_helper.core.resource_management.error_handling import (
        safe_read_json_file,
        ErrorCategory,
    )

    aggregated_results_path = output_dir / "ash_aggregated_results.json"

    # A FIFO or a link at the results name is refused here, before the read,
    # with this function's own error (naming output_dir in its context);
    # safe_read_json_file refuses the same shapes with its own text, and the
    # registry's readers hold its lock while they read, so an early answer
    # keeps a poll short. The lock is not what makes a read consistent: it
    # serializes the registry's own readers, not the scan that replaces the
    # file, so two reads of the file by one caller can be two documents. A
    # caller that needs one view parses once and derives everything from that
    # dict (get_scan_progress_info does; the registry's progress poll still
    # reads the file more than once under its lock).
    if os.path.lexists(aggregated_results_path) and not is_regular_result_file(
        aggregated_results_path, max_bytes=None
    ):
        raise MCPResourceError(
            f"Aggregated results path is not a regular file: {aggregated_results_path}",
            context={
                "output_dir": str(output_dir),
                "error_category": ErrorCategory.INVALID_PATH.value,
            },
        )

    # Use safe_read_json_file for robust error handling
    data, error = safe_read_json_file(aggregated_results_path, required=True)

    if error:
        # Enhance the error with additional context
        if error.context.get("error_category") == ErrorCategory.FILE_NOT_FOUND.value:
            raise MCPResourceError(
                f"Aggregated results file not found: {aggregated_results_path}",
                context={
                    "output_dir": str(output_dir),
                    "error_category": ErrorCategory.FILE_NOT_FOUND.value,
                    "suggestions": [
                        "Check if the scan has completed",
                        "Verify the output directory path is correct",
                        "Ensure the scan process has write permissions to the output directory",
                    ],
                },
            )
        else:
            # For other errors, propagate with enhanced context
            error.context["output_dir"] = str(output_dir)
            raise error

    return data


def coverage_has_gap(coverage: Optional[Dict[str, Any]]) -> bool:
    """Whether a coverage payload (``ScanIncompleteness.to_payload()``) names a gap."""
    if not coverage:
        return False
    return bool(
        coverage.get("incomplete_scanners")
        or coverage.get("no_scanner_ran")
        or coverage.get("incomplete_converters")
        or coverage.get("unevaluated_rules")
        or coverage.get("stale_content_databases")
        or coverage.get("could_not_stop")
    )


def assess_coverage(results: AshAggregatedResults) -> Tuple[bool, Dict[str, Any]]:
    """``(gate_fires, coverage)`` for a scan whose results are in hand.

    ``gate_fires`` is whether ``_compute_exit_code`` would exit 1 on these results
    for coverage, and it is what separates ``incomplete`` from ``completed``. It
    resolves the gate the way an MCP scan does: no command-line flag, because the
    MCP runner passes none, so the config the scan ran under (``results.ash_config``)
    decides, and the gate is on when that is absent.

    ``coverage`` is the facts whatever the gate says, which matches what the
    workspace layer's ``incomplete_scanners`` does. An operator who turned the
    gate off has accepted the gap. They have not asked to be told there was none,
    so a ``completed`` scan still names the scanners that did not run and reports
    ``coverage_complete: false``.

    Both come from ``scan_incompleteness``, the object ``_compute_exit_code``
    reaches its verdict from. Nothing here re-derives a coverage rule.
    """
    from types import SimpleNamespace

    from automated_security_helper.interactions.run_ash_scan import (
        _resolve_fail_on_incomplete_scanners,
        scan_incompleteness,
    )

    gate = _resolve_fail_on_incomplete_scanners(
        results, SimpleNamespace(fail_on_incomplete_scanners=None), None
    )
    gated = scan_incompleteness(results, gate=gate)
    facts = scan_incompleteness(results, gate=True)
    return bool(gated), facts.to_payload()


def load_aggregated_results_model(
    output_dir: Path,
) -> Optional[AshAggregatedResults]:
    """The aggregated results file as a model, or None if it cannot be one.

    None covers a missing file, a file that does not parse, and a document that
    fails ``validate_result_structure``. A caller that needs to tell those apart
    goes through ``get_scan_results``. This one answers only "are there results
    to assess".
    """
    try:
        raw = parse_aggregated_results(output_dir)
    except MCPResourceError:
        return None
    return _results_model_of(raw, output_dir)


def _results_model_of(
    raw: Any, output_dir: Path | None
) -> Optional[AshAggregatedResults]:
    """The results model of an already-parsed document, or None.

    The second half of :func:`load_aggregated_results_model`, for a caller that
    has parsed the file itself and must not parse it again: a second read of
    the file is a second document when the scan replaces the file in between,
    so counts from one read beside coverage from the next described no scan
    that ever existed. ``output_dir`` names the file in the log line only.
    """
    if not isinstance(raw, dict):
        return None
    is_valid, _ = validate_result_structure(raw)
    if not is_valid:
        return None
    try:
        return AshAggregatedResults(**raw)
    except Exception as e:  # noqa: BLE001 -- "not assessable" is the answer
        _logger.debug(
            f"Aggregated results in {output_dir} did not load: {error_text(e)}",
            extra=NO_MARKUP,
        )
        return None


class _UnusableResultsError(ValueError):
    """The aggregated results document is the wrong shape somewhere specific."""


def _add_aggregated_scanner_progress(
    scan_progress: ScanProgress, results: Dict[str, Any]
) -> None:
    """Add one ScannerProgress per entry in an aggregated results document.

    ``results`` has already passed ``validate_result_structure``. That checks the
    containers, not the entries in them, so an entry that is not an object is
    rejected here with its scanner named.
    """
    from automated_security_helper.utils.sarif_utils import is_result_suppressed

    findings = []

    # The findings of the SARIF, each with the scanner that reported it. A
    # result with a suppression in effect is graded ``suppressed``, as the
    # completed view grades it (_completed_findings_summary): it is in that
    # bucket and not in its severity or in the count.
    for run, result in _sarif_run_results(results.get("sarif")):
        findings.append(
            {
                "id": result.get("ruleId", "unknown"),
                "severity": (
                    "suppressed"
                    if is_result_suppressed(result)
                    else result_severity(result)
                ),
                # The scanner the result names, as every other reader of the
                # aggregated SARIF attributes it (sarif_utils). The run's tool is
                # the fallback only: ASH writes one run for all its scanners, so
                # the driver name there is ASH's, and matched against a scanner
                # name it found nothing.
                "scanner": result_scanner_name(result) or _run_driver_name(run),
            }
        )

    scanner_results = results.get("scanner_results") or {}
    for scanner_name, scanner_info in scanner_results.items():
        if not isinstance(scanner_info, dict):
            raise _UnusableResultsError(
                f"scanner_results[{scanner_name!r}] must be an object, found "
                f"{type(scanner_info).__name__}"
            )

    # Create scanner progress objects for each completed scanner
    for scanner_name, scanner_info in scanner_results.items():
        # Filter findings for this scanner
        scanner_findings = [f for f in findings if f.get("scanner") == scanner_name]

        # What the document recorded for the scanner, read as the per-target
        # path reads a document (_counts_of_document): a count the results
        # model accepts as null is no recorded count, and neither is anything
        # that is not a non-negative integer; a bucket whose value is not one
        # is dropped, and the bucket names are lowercased. Stored as recorded,
        # a bucket holding a string reached update_totals, whose TypeError
        # failed the whole document.
        recorded_count, recorded_counts = _counts_of_document(scanner_info)
        if not recorded_counts:
            # An object that names no usable bucket ({} or only unusable
            # values) records nothing, as it does for the per-target file
            # (_progress_counts_of_document): the SARIF results, or the
            # recorded count under unknown, speak instead of all-zero buckets.
            recorded_counts = None

        # Create scanner progress for source target, carrying the status the
        # document recorded rather than assuming success. The results model reads a
        # status that is absent as PASSED, and so does this.
        mapped_status = scanner_status_from_results(
            scanner_info.get("status", "PASSED")
        )
        source_progress = ScannerProgress(
            scanner_name=scanner_name,
            target_type="source",
            status=mapped_status,
            # A scanner that did not run has no duration: the results model
            # dumps its default 0.0, which is not a measurement.
            duration=(
                None
                if mapped_status is MCScannerStatus.SKIPPED
                else _recorded_duration(scanner_info)
            ),
            finding_count=recorded_count or 0,
        )

        # The breakdown the scanner recorded, folded into the named buckets
        # with anything else under unknown; failing that, the one its SARIF
        # results give. A recorded count with neither goes under the catch-all
        # bucket, so it is not in the total and in no bucket, and the count of
        # results that matched no scanner (none, when the SARIF names no scanner)
        # does not replace it. A null count beside recorded buckets is the
        # non-suppressed sum, SummaryStats' total, the count the per-target
        # path reports for the same scanner; summed over every bucket it
        # counted the suppressed findings the recorded count leaves out.
        if recorded_counts is not None:
            counts = empty_severity_counts()
            for severity, value in recorded_counts.items():
                counts[severity if severity in counts else UNKNOWN_SEVERITY] += value
            source_progress.severity_counts = counts
            if recorded_count is None:
                source_progress.finding_count = sum(
                    value for bucket, value in counts.items() if bucket != "suppressed"
                )
        elif scanner_findings:
            source_progress.update_findings(scanner_findings)
            # A recorded count the results do not account for stays the count
            # (the per-target path keeps it too) with the rest under unknown;
            # a count below the results is the results' to raise.
            unmatched = (recorded_count or 0) - source_progress.finding_count
            if unmatched > 0:
                source_progress.finding_count += unmatched
                source_progress.severity_counts[UNKNOWN_SEVERITY] += unmatched
        elif recorded_count:
            source_progress.severity_counts = empty_severity_counts()
            source_progress.severity_counts[UNKNOWN_SEVERITY] = recorded_count

        # The status is the constructor's and no end_time is set: the document
        # records how long a scanner took (the duration above), not when it ended,
        # and the time of this poll is not that. mark_completed and mark_failed
        # wrote it as the end_time, and left the duration unset.
        scan_progress.add_scanner_progress(source_progress)


def _run_driver_name(run: Dict[str, Any]) -> str:
    """The name of the tool a SARIF run records, or ``unknown``."""
    tool = run.get("tool")
    driver = tool.get("driver") if isinstance(tool, dict) else None
    name = driver.get("name") if isinstance(driver, dict) else None
    return name if isinstance(name, str) and name else "unknown"


def _sarif_run_results(sarif: Any) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """Every ``(run, result)`` pair of a SARIF document, however sparse it is.

    The progress views read the SARIF of a document that has been through
    ``validate_result_structure``, which checks that ``runs`` is a list and not
    what is in it. A run whose ``results`` is null, which the SARIF model allows
    (``schemas/sarif_schema_model.py``), has no results, as one with no ``results``
    key has none; a run or a result that is not an object is no run or result. None
    of them fails the view.
    """
    pairs: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    if not isinstance(sarif, dict):
        return pairs
    runs = sarif.get("runs")
    for run in runs if isinstance(runs, list) else []:
        if not isinstance(run, dict):
            continue
        run_results = run.get("results")
        for result in run_results if isinstance(run_results, list) else []:
            if isinstance(result, dict):
                pairs.append((run, result))
    return pairs


def _recorded_duration(scanner_info: Dict[str, Any]) -> Optional[float]:
    """The ``duration`` a ``scanner_results`` entry recorded, or None."""
    duration = scanner_info.get("duration")
    if isinstance(duration, bool) or not isinstance(duration, (int, float)):
        return None
    return float(duration)


def create_scan_progress_from_files(
    scan_id: str, output_dir: Path | None = None
) -> ScanProgress:
    """
    Create a ScanProgress object by analyzing scan result files.

    Once ``ash_aggregated_results.json`` exists, the progress is built from it.
    What this returns describes the *file*. It is not the scan's status: the SCAN
    phase writes a complete-looking results document before the REPORT phase runs,
    so a readable file does not mean the scan has finished. ``check_scan_progress``
    reconciles this with the registry entry, which knows whether a runner still
    owns the scan. There are three outcomes:

    * The file is a results document: ``completed``, with one entry per scanner.
    * The file cannot be read as results -- it does not parse, is not a JSON object
      (``safe_read_json_file`` refuses a list or a scalar with its INVALID_FORMAT
      message, "Expected a JSON object in file ..., found list"), or has
      ``scanner_results``/``sarif`` of the wrong shape: ``failed``, with
      ``error_message`` naming the file and what is wrong with it. Since the file is
      replaced atomically (utils/atomic_write.py) a reader never sees a write in
      progress, so this is a file that is corrupt, truncated on disk, or not ASH's.
      It used to fall through to a completed scan with no scanners.
    * The file is a JSON object with neither ``scanner_results`` nor ``sarif``:
      ``results_pending`` is set and the status is left ``in_progress``. The SCAN
      phase used to write exactly that, because ``save_model`` dumped with
      ``exclude_unset`` and the scan fills ``scanner_results`` in place; it now
      dumps the full model, so an ASH-written file always carries both. Whether such
      a file means "not finished yet" or "finished without results" depends on
      whether the scan has been closed, which only the registry knows, so the
      caller decides.

    Args:
        scan_id: ID of the scan
        output_dir: Path to the scan output directory

    Returns:
        ScanProgress object with information from scan result files
    """
    if output_dir is None:
        output_dir = Path.cwd().joinpath(".ash", "ash_output")
    # Check if scan has completed
    is_complete = check_scan_completion(output_dir)

    # Create scan progress object
    scan_progress = ScanProgress(scan_id=scan_id)

    if is_complete:
        aggregated_results_path = output_dir / "ash_aggregated_results.json"

        def unusable(reason: str) -> ScanProgress:
            # Discard anything partially built, so a failed read never carries
            # scanners that look like results.
            scan_progress.scanners = {}
            scan_progress.update_totals()
            scan_progress.mark_failed()
            scan_progress.error_message = (
                f"Aggregated results file {aggregated_results_path} is not a usable "
                f"results document: {reason}"
            )
            _logger.error(scan_progress.error_message)
            return scan_progress

        try:
            results = parse_aggregated_results(output_dir)
        except MCPResourceError as e:
            # safe_read_json_file's message already names the file and the parse
            # error, e.g. "Invalid JSON format in file <path>: Expecting value: ...".
            # It is carried on the object because without it the caller cannot
            # tell a corrupt file from a scan that genuinely produced no scanners.
            _logger.error(f"Error parsing aggregated results: {str(e)}")
            scan_progress.mark_failed(str(e))
            return scan_progress

        # parse_aggregated_results returns a dict or raises: safe_read_json_file
        # refuses a non-object document, so the list-valued case is the except
        # arm above, with its message. (A type check here could never run.)
        if results.get("sarif") is None and results.get("scanner_results") is None:
            scan_progress.results_pending = True
            return scan_progress

        is_valid, validation_error = validate_result_structure(results)
        if not is_valid:
            return unusable(str(validation_error))

        try:
            _add_aggregated_scanner_progress(scan_progress, results)
        except _UnusableResultsError as e:
            return unusable(str(e))
        except (AttributeError, TypeError, ValueError) as e:
            return unusable(f"{type(e).__name__}: {e}")

        scan_progress.mark_completed()
        return scan_progress
    else:
        # Find individual scanner result files
        scanner_results = find_scanner_result_files(output_dir)

        # Create scanner progress objects for each scanner with results
        for scanner_name, target_results in scanner_results.items():
            for target_type, result_file in target_results.items():
                try:
                    # One read per file, through the regular-file guard (this
                    # runs under the registry lock); the findings, counts and
                    # status below all come from that one document.
                    #
                    # A file that is not yet a JSON object (empty, truncated,
                    # mid-write) is a scanner that has not finished writing,
                    # not one that PASSED with 0 findings. It is reported as
                    # running until a later poll reads a document.
                    document = _read_scanner_result_document(result_file)
                    if document is None:
                        unfinished = ScannerProgress(
                            scanner_name=scanner_name, target_type=target_type
                        )
                        unfinished.mark_running()
                        scan_progress.add_scanner_progress(unfinished)
                        continue

                    # The scanner has finished: it wrote its results. How it
                    # finished is in the file's own status, which every scanner
                    # writes; one without it is counted as passed.
                    #
                    # What it found is in the file's own counts, which is the
                    # record ASH writes (finding_count and severity_counts, no
                    # findings array) until the aggregated file exists. The
                    # counts win when the document carries them and a findings
                    # array fills in only when it does not, with the suppressed
                    # findings left out of the count as the aggregated file
                    # leaves them out: the one rule both progress paths follow
                    # (_progress_counts_of_document), so a scanner reports one
                    # total mid-scan and after aggregation. Counted from the
                    # array alone, every finished scanner read as 0 findings
                    # while the scan ran.
                    findings, count, counts = _progress_counts_of_document(document)
                    scanner_progress = ScannerProgress(
                        scanner_name=scanner_name,
                        target_type=target_type,
                        status=MCScannerStatus.COMPLETED,
                        finding_count=count,
                        severity_counts=counts,
                    )
                    scanner_progress.mark_completed()
                    recorded = _status_of_document(document)
                    if recorded is not None:
                        scanner_progress.status = scanner_status_from_results(recorded)

                    # Add to scan progress
                    scan_progress.add_scanner_progress(scanner_progress)

                except Exception as e:
                    _logger.warning(
                        f"Error parsing result file for scanner {scanner_name}, target {target_type}: {str(e)}"
                    )

        return scan_progress


def get_scan_progress_info(
    output_dir: Path | None = None,
) -> Dict[str, Any]:
    """
    Get comprehensive scan progress information.

    What this returns describes the files in ``output_dir``, as
    :func:`create_scan_progress_from_files` does, and no registry entry decides it.

    * ``completed``: the aggregated results file is a results document. That is
      not the scan having ended: the SCAN phase writes the document before the
      REPORT phase runs, so a caller that needs to know the scan is over asks the
      registry (``check_scan_progress``).
    * ``in_progress`` with ``results_pending`` true: the file is a JSON object with
      neither ``scanner_results`` nor ``sarif``, which is not a results document
      yet.
    * ``in_progress`` otherwise: the per-scanner files. ``findings_count`` is
      then what the scanners recorded (their non-suppressed count, the rule
      :func:`_progress_counts_of_document` states), which is more than
      ``len(findings)`` for the files ASH writes, since those carry counts and
      no findings array.
    * ``error``: the file cannot be read as results, or the directory holds the
      results put back after a scan that ended without any
      (:func:`restored_results_refusal`), which are not this scan's. The
      put-back check runs before the read and again after it: a restore
      writes its marker first and moves the previous results back after, so a
      restore that lands between the check and the read leaves a marker to
      see once the read is done.

    ``findings_count`` has one meaning in every state: the non-suppressed
    findings, SummaryStats' ``total``. For a completed scan it is
    ``metadata.summary_stats.total`` when the document carries one, else the
    SARIF results less the suppressed ones; counted as every SARIF result it
    rose by the suppressed count the moment the scan completed.
    ``findings_summary`` has one shape in every state: the severity buckets
    (``SEVERITY_BUCKETS`` and ``unknown``). For a completed scan they are
    ``metadata.summary_stats``' counts, or, with no summary stats, the SARIF
    results graded by ``result_severity``, a suppressed result counted in
    ``suppressed`` and not by its severity, so the buckets other than
    ``suppressed`` add up to ``findings_count``. The summary stats themselves
    are returned as ``summary_stats``.

    ``scanners_completed`` are the scanners whose recorded status word is
    PASSED or FAILED (:func:`_recorded_status_word`: upper-cased, an absent
    status read as PASSED as the results model reads it); an ERROR or a
    non-string status is not a completed scanner.

    Args:
        output_dir: Path to the scan output directory

    Returns:
        Dictionary containing scan progress information
    """
    if output_dir is None:
        output_dir = Path.cwd().joinpath(".ash", "ash_output")
    # Check if scan has completed
    is_complete = check_scan_completion(output_dir)

    if is_complete:
        from automated_security_helper.core.previous_results import (
            holds_restored_results,
        )
        from automated_security_helper.core.resource_management.error_handling import (
            ErrorCategory,
        )

        def put_back_results() -> Dict[str, Any]:
            return {
                "status": "error",
                "is_complete": False,
                "error": (
                    f"Scan of output_dir {output_dir} is not complete. Results are "
                    "not available: the last scan there ended without results, and "
                    "ASH put back the results of the scan before it, which are not "
                    "that scan's."
                ),
                "context": {
                    "output_dir": str(output_dir),
                    "error_category": ErrorCategory.SCAN_INCOMPLETE.value,
                    "output_holds_previous_results": True,
                },
            }

        if holds_restored_results(Path(output_dir)):
            return put_back_results()
        try:
            # Parse aggregated results for completed scans
            results = parse_aggregated_results(output_dir)
            if not isinstance(results, dict):
                results = {}

            # The check above ran before the read, and a restore can land
            # between the two. It writes its marker first and moves the
            # previous results back after it (core/previous_results.py), so
            # results read after it put them back are followed by a marker
            # that is there to see now; the same second look
            # get_scan_results_with_error_handling takes.
            if holds_restored_results(Path(output_dir)):
                return put_back_results()

            if results.get("sarif") is None and results.get("scanner_results") is None:
                # Not a results document yet; see create_scan_progress_from_files.
                return {**_partial_progress_info(output_dir), "results_pending": True}

            # Every container is read as absent when it is null or the wrong
            # type: validate_result_structure accepts a null scanner_results or
            # metadata beside a SARIF, and a run whose results is null.
            findings = [
                result for _, result in _sarif_run_results(results.get("sarif"))
            ]

            # The scanners that ran to an end, as get_scan_results counts
            # them: PASSED or FAILED, the recorded word. scanner_results names
            # every scanner ASH considered, MISSING, SKIPPED and ERROR
            # included, and listing them all here reported a tool that never
            # ran as completed; ERROR is a tool that did not run to an end
            # either, and it stays out, as it does in get_scan_results (the
            # registry's progress view folds ERROR into its FAILED status
            # column, which is a different question). The word is read as the
            # results model reads it: an absent status is PASSED, and the case
            # does not matter, so {"bandit": {}} and {"status": "passed"} count
            # here as they do there.
            scanner_results = results.get("scanner_results")
            scanners_completed = [
                name
                for name, info in (
                    scanner_results if isinstance(scanner_results, dict) else {}
                ).items()
                if isinstance(info, dict)
                and _recorded_status_word(info.get("status", "PASSED"))
                in ("PASSED", "FAILED")
            ]

            metadata = results.get("metadata")
            if not isinstance(metadata, dict):
                metadata = {}
            summary_stats = metadata.get("summary_stats")
            if not isinstance(summary_stats, dict):
                summary_stats = {}

            # Whether the scanners that ran are all the scanners that were
            # selected, by the rule get_scan_results and the registry's progress
            # view share (assess_coverage). "completed" here means the
            # aggregated file exists and parsed, which it does for a scan whose
            # tool was MISSING; without this, that scan read as a completed scan
            # with fewer scanners while get_scan_results called it incomplete.
            # None when the document is not a results model, or the assessment
            # itself fails: coverage unknown, the file still reported.
            #
            # From the document this call already parsed. This path takes no
            # lock, and a second read of the file was a second document when
            # the scan replaced the file in between, so the counts of one
            # write stood beside the coverage of the next.
            coverage_complete: Optional[bool] = None
            incomplete_scanners: List[Dict[str, Any]] = []
            try:
                model = _results_model_of(results, output_dir)
                if model is not None:
                    _, coverage = assess_coverage(model)
                    coverage_complete = not coverage_has_gap(coverage)
                    incomplete_scanners = list(coverage.get("incomplete_scanners", []))
            except Exception as e:  # noqa: BLE001 -- coverage unknown, not a failure
                _logger.warning(
                    f"Coverage of the scan in {output_dir} could not be assessed "
                    f"from its results: {error_text(e)}",
                    extra=NO_MARKUP,
                )

            findings_summary = _completed_findings_summary(summary_stats, findings)
            return {
                "status": "completed",
                "is_complete": True,
                "coverage_complete": coverage_complete,
                "incomplete_scanners": incomplete_scanners,
                "scanners_completed": scanners_completed,
                "total_scanners": len(scanners_completed),
                "findings_count": _completed_findings_count(
                    summary_stats, findings, findings_summary
                ),
                "findings": findings,
                "findings_summary": findings_summary,
                "summary_stats": summary_stats,
                "completion_time": metadata.get(
                    "generated_at", datetime.now().isoformat()
                ),
            }
        except MCPResourceError as e:
            # Handle errors parsing aggregated results
            return {
                "status": "error",
                "is_complete": True,
                "error": str(e),
                "context": e.context if hasattr(e, "context") else {},
            }
    else:
        return _partial_progress_info(output_dir)


def _completed_findings_summary(
    summary_stats: Dict[str, Any], findings: List[Dict[str, Any]]
) -> Dict[str, int]:
    """The severity buckets of a completed scan, in the shape the running view has.

    From the summary stats the results document carries when it has them: the
    ``severity_counts`` they nest, or the flat bucket keys an older document puts
    at the top. Without them, from the SARIF results; and likewise when the
    stats name no bucket at all (``total_findings`` and ``actionable`` alone, say),
    which used to give all-zero buckets beside SARIF results that were never
    graded.
    """
    summary = empty_severity_counts()
    if summary_stats:
        nested = summary_stats.get("severity_counts")
        recorded = nested if isinstance(nested, dict) else summary_stats
        named_a_bucket = False
        for severity, value in recorded.items():
            if severity in summary and isinstance(value, int):
                summary[severity] = value
                named_a_bucket = True
        if named_a_bucket:
            return summary

    from automated_security_helper.utils.sarif_utils import is_result_suppressed

    for result in findings:
        bucket = (
            "suppressed" if is_result_suppressed(result) else result_severity(result)
        ).lower()
        summary[bucket if bucket in summary else UNKNOWN_SEVERITY] += 1
    return summary


def _completed_findings_count(
    summary_stats: Dict[str, Any],
    findings: List[Dict[str, Any]],
    findings_summary: Dict[str, int],
) -> int:
    """The non-suppressed findings of a completed scan: SummaryStats' ``total``.

    From ``summary_stats.total`` when the document carries one; else what the
    buckets of ``findings_summary`` other than ``suppressed`` add up to: the SARIF
    results less the suppressed ones when the buckets were graded from them, and
    the recorded buckets' sum when they came from the summary stats. Taken from
    the SARIF alone, a document whose stats gave ``{"critical": 7}`` and no
    ``total`` read 7 critical beside a count of 0 (``findings`` is the SARIF
    results, and only the stats' buckets were counted). The running view reports
    the same quantity (the scanners' non-suppressed recorded counts), so a scan's
    count no longer rises by its suppressed findings the moment it completes.
    """
    total = summary_stats.get("total")
    if isinstance(total, int) and not isinstance(total, bool) and total >= 0:
        return total
    return sum(
        value for bucket, value in findings_summary.items() if bucket != "suppressed"
    )


def _partial_progress_info(output_dir: Path) -> Dict[str, Any]:
    """Progress from the per-scanner files, for a scan with no results document.

    ``scanners_completed`` are the scanners with a readable result document for
    at least one target, the targets ``get_scanner_progress`` lists as
    completed; a scanner whose only file is not a JSON object yet is one that
    has not finished writing (``create_scan_progress_from_files`` reports it
    as running), and listing it as completed here from the file's presence put
    the two views of one file at odds. ``total_scanners`` counts every scanner
    that has written a file, finished or not; it is still an estimate, since
    a scanner that has written nothing is not seen.
    """
    # Get partial progress for incomplete scans
    scanner_progress = get_scanner_progress(output_dir)
    completed_scanners = [
        scanner_name
        for scanner_name, scanner_info in scanner_progress.items()
        if scanner_info.get("targets_completed")
    ]

    # Aggregate findings from all scanners. The count and the summary come
    # from what each scanner recorded (get_scanner_progress), so a scanner
    # whose per-target file carries counts and no findings array is counted
    # as the scanner counted it, not as 0.
    all_findings = []
    findings_count = 0
    findings_summary = empty_severity_counts()
    for scanner_info in scanner_progress.values():
        all_findings.extend(scanner_info.get("findings", []))
        findings_count += scanner_info.get("finding_count", 0)
        for severity, value in scanner_info.get("severity_counts", {}).items():
            bucket = severity if severity in findings_summary else UNKNOWN_SEVERITY
            findings_summary[bucket] += value

    return {
        "status": "in_progress",
        "is_complete": False,
        "scanners_completed": completed_scanners,
        "total_scanners": len(scanner_progress),
        "findings_count": findings_count,
        "findings": all_findings,
        "findings_summary": findings_summary,
        "scanner_progress": scanner_progress,
    }


def extract_findings_summary(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Extract a summary of findings by severity.

    Args:
        findings: List of findings

    Returns:
        Dictionary mapping severity levels to counts, keyed by the lowercase
        buckets in SEVERITY_BUCKETS plus UNKNOWN_SEVERITY. A finding whose
        severity is missing or is not one of the named buckets counts under
        UNKNOWN_SEVERITY, so ``sum(result.values()) == len(findings)``.
    """
    summary = empty_severity_counts()

    for finding in findings:
        severity = str(finding.get("severity") or "").lower()
        # An unrecognized or missing severity goes to the catch-all rather than
        # being dropped, so sum(summary.values()) == len(findings) always holds.
        if severity not in summary:
            severity = UNKNOWN_SEVERITY
        summary[severity] += 1

    return summary


def validate_output_directory(output_dir: Path) -> Tuple[bool, Optional[str]]:
    """
    Validate that the output directory exists and has the expected structure.

    Args:
        output_dir: Path to the scan output directory

    Returns:
        Tuple of (is_valid, error_message)
    """
    from automated_security_helper.core.resource_management.error_handling import (
        validate_directory_path,
    )

    # Use validate_directory_path for robust error handling
    error = validate_directory_path(output_dir)
    if error:
        return False, str(error)

    # Check if the directory has the expected structure
    scanners_dir = output_dir / "scanners"
    if not scanners_dir.exists() and not check_scan_completion(output_dir):
        return (
            False,
            "Invalid output directory structure: missing 'scanners' directory and no aggregated results",
        )

    return True, None


def _sarif_severity_thresholds(
    results: AshAggregatedResults, sarif: Dict[str, Any]
) -> Dict[str, Optional[str]]:
    """The severity threshold each SARIF result's scanner was judged by.

    Keyed by ``properties.scanner_name``, with ``""`` for a result that names no
    scanner, and resolved by ``ScannerStatisticsCalculator.get_scanner_threshold_info``
    from the config the scan resolved, the resolver ``run_ash_scan._compute_exit_code``
    uses per result: a scanner's own ``options.severity_threshold`` when it sets
    one, else ``global_settings.severity_threshold`` (the threshold
    ``mcp_tools._judged_threshold`` reports). A threshold a client passed to
    ``run_ash_scan`` is already in both, because the scan tightened them before it
    ran. ``result_filters.filter_actionable_only`` needs this to keep the findings
    exit 2 counts, and the results dict carries no config of its own.
    """
    from automated_security_helper.core.scanner_statistics_calculator import (
        ScannerStatisticsCalculator,
    )

    names = {""}
    for run in sarif.get("runs") or []:
        for result in run.get("results") or []:
            properties = result.get("properties")
            name = (
                properties.get("scanner_name") if isinstance(properties, dict) else None
            )
            names.add(name if isinstance(name, str) else "")
    return {
        name: ScannerStatisticsCalculator.get_scanner_threshold_info(results, name)[0]
        for name in names
    }


def get_scan_results(
    output_dir: Path | None = None,
    include_sarif: bool = False,
) -> Dict[str, Any]:
    """
    Get the results of a completed scan.

    This locates a scan by output directory, not by ID, so it cannot report the
    ID the scan was registered under. The returned ``scan_id`` is minted here as
    ``scan-<timestamp>``.

    Args:
        output_dir: Path to the scan output directory. Defaults to
            ``.ash/ash_output`` under the working directory.
        include_sarif: Also return the scan's SARIF as ``raw_results["sarif"]``,
            and beside it ``raw_results["severity_thresholds"]``, the threshold
            each of its results was judged by (see
            ``_sarif_severity_thresholds``). Left out by default because the
            SARIF holds every finding and is the largest part of the file.
            ``result_filters.filter_actionable_only`` and ``add_findings_list``
            read the findings from it, so a caller that builds a findings list
            has to ask for it.

    Returns:
        Dictionary containing scan results information

    Raises:
        MCPResourceError: If the scan results cannot be retrieved
    """
    if output_dir is None:
        output_dir = Path.cwd().joinpath(".ash", "ash_output")
    from automated_security_helper.core.resource_management.error_handling import (
        validate_directory_path,
        ErrorCategory,
    )

    # Always None, and it exists only to populate the error context below, which
    # callers read and two tests assert on. It is not an input: this function takes
    # no scan id, and the returned one is minted rather than echoed. Do not wire a
    # parameter to it without reading the docstring's note about why that cannot work.
    scan_id = None

    # Validate output directory
    error = validate_directory_path(output_dir)
    if error:
        raise error

    # Check if scan has completed by looking for the aggregated results file
    is_complete = check_scan_completion(output_dir)

    if not is_complete:
        raise MCPResourceError(
            f"Scan results not available in {output_dir}.",
            context={
                # "scan_id": scan_id,
                "output_dir": str(output_dir),
                "error_category": ErrorCategory.SCAN_INCOMPLETE.value,
                "suggestions": [
                    "Wait for the scan to complete",
                    "Check if the scan process is still running",
                    "Verify that the scan was started correctly",
                    "Ensure the output directory is correct",
                ],
            },
        )

    try:
        # Parse aggregated results
        int_results_dict = parse_aggregated_results(output_dir)

        # Validate the raw document, before the model is built from it.
        #
        # Order matters both ways here. AshAggregatedResults is configured
        # extra="ignore" and supplies a default for every field, so constructing
        # it erases the distinction this check exists to make: an empty {} and a
        # full scan produce models that are indistinguishable. Validating the
        # model also took validate_result_structure's isinstance short-circuit,
        # so the check was dead on its only call path and an empty results
        # document was reported as a completed scan with total_scanners=0 -- a
        # scanner that measured nothing, reading as a scanner that found nothing.
        #
        # Validating first also means a structurally wrong document is reported
        # as invalid_format with the field named, rather than as the
        # unexpected_error that model construction would raise.
        is_valid, validation_error = validate_result_structure(int_results_dict)
        if not is_valid:
            raise MCPResourceError(
                f"Invalid result structure: {validation_error}",
                context={
                    # "scan_id": scan_id,
                    "output_dir": str(output_dir),
                    "error_category": ErrorCategory.INVALID_FORMAT.value,
                    "suggestions": [
                        "Check if the scan completed successfully",
                        "Verify that the results file was not corrupted",
                        "Ensure the scan process has proper permissions",
                    ],
                },
            )

        with warning_of_dropped_keys(
            Path(output_dir) / "ash_aggregated_results.json"
        ) as context:
            results: AshAggregatedResults = AshAggregatedResults.model_validate(
                int_results_dict, context=context
            )

        # Build comprehensive results object
        results_dict = results.model_dump(
            exclude=[
                "ash_config",
                "sarif",
                "cyclonedx",
            ],
            exclude_none=True,
            exclude_unset=True,
            by_alias=True,
            mode="json",
        )
        if include_sarif:
            if results.sarif is not None:
                results_dict["sarif"] = results.sarif.model_dump(
                    exclude_none=True, by_alias=True, mode="json"
                )
                results_dict["severity_thresholds"] = _sarif_severity_thresholds(
                    results, results_dict["sarif"]
                )
            else:
                # Asked for and absent is a fact the caller needs: a results
                # document with no SARIF has no findings to list, and a filter
                # that builds a findings list from it must say so rather than
                # return an empty list beside a nonzero actionable count.
                results_dict["sarif"] = None
        metadata = results_dict.get("metadata", {})
        scanners_completed = []
        for scanner_name, scanner_results in results_dict.get(
            "scanner_results", {}
        ).items():
            if scanner_results.get("status", "UNKNOWN") in ["PASSED", "FAILED"]:
                scanners_completed.append(scanner_name)

        # Minted unconditionally. This used to read
        # `scan_id if scan_id else f"scan-{...}"`, whose first arm was unreachable --
        # scan_id is bound to None above and nothing assigns it. The ternary advertised
        # a passthrough the function does not have, so a reader could reasonably believe
        # supplying an id would round-trip it. It cannot: this locates a scan by output
        # directory, which carries no record of the id it was registered under.
        result_scan_id = f"scan-{datetime.now().strftime('%Y%m%d%H%M%S')}"

        # "completed" or "incomplete", from the model just built, by the rule the
        # exit code uses. This used to be the literal "completed", so a scan whose
        # scanners were MISSING read here as a clean finished one. The findings
        # below are returned either way: partial results are the point of an
        # incomplete scan.
        gate_fires, coverage = assess_coverage(results)

        return {
            # Set explicitly, because "the call worked" is not inferable from the
            # rest of this payload. Only create_error_response had ever set this
            # key, always to False, so consumers testing `not
            # results.get("success")` saw the same answer on both branches: the
            # guard in cli/mcp_server.py::get_scan_results was an unconditional
            # return and filter_level, scanners, severities and actionable_only
            # were all inert on a real scan.
            "success": True,
            "scan_id": result_scan_id,
            "status": "incomplete" if gate_fires else "completed",
            "is_complete": True,
            "coverage_complete": not coverage_has_gap(coverage),
            **coverage,
            "actionable_findings": metadata.get("summary_stats", {}).get("actionable"),
            "summary_stats": metadata.get("summary_stats", {}),
            "scanner_reports": results_dict.get("additional_reports", {}),
            "total_scanners": len(scanners_completed),
            "completion_time": metadata.get("generated_at", datetime.now().isoformat()),
            "raw_results": results_dict,
        }
    except MCPResourceError as e:
        # Re-raise with additional context if needed
        if "scan_id" not in e.context:
            e.context["scan_id"] = scan_id
        if "output_dir" not in e.context:
            e.context["output_dir"] = str(output_dir)
        raise e
    except Exception as e:
        # Handle unexpected errors. The model's ValidationError, for a record
        # that does not load, is described by field rather than quoting its
        # input (utils/error_text.py), and is not chained: a traceback of the
        # chain would print it.
        message = error_text(e)
        unexpected = MCPResourceError(
            f"Unexpected error retrieving scan results: {message}",
            context={
                "scan_id": scan_id,
                "cwd": str(Path.cwd()),
                "output_dir": str(output_dir),
                "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                "error_type": type(e).__name__,
                "error_message": message,
            },
        )
        if validation_errors_in(e):
            raise unexpected from None
        raise unexpected from e


def extract_scan_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract a summary of scan results.

    Args:
        results: Dictionary containing scan results

    Returns:
        Dictionary containing a summary of the scan results
    """
    findings = results.get("findings", [])
    severity_counts = extract_findings_summary(findings)

    # Group findings by scanner
    findings_by_scanner: Dict[str, List[Dict[str, Any]]] = {}
    for finding in findings:
        scanner = finding.get("scanner", "unknown")
        if scanner not in findings_by_scanner:
            findings_by_scanner[scanner] = []
        findings_by_scanner[scanner].append(finding)

    # Create scanner summaries
    scanner_summaries = {}
    for scanner, scanner_findings in findings_by_scanner.items():
        scanner_summaries[scanner] = {
            "finding_count": len(scanner_findings),
            "severity_counts": extract_findings_summary(scanner_findings),
        }

    return {
        "findings_count": len(findings),
        "severity_counts": severity_counts,
        "scanners_completed": results.get("scanners_completed", []),
        "scanner_summaries": scanner_summaries,
        # extract_findings_summary keys its counts by the lowercase buckets in
        # SEVERITY_BUCKETS; read with uppercase keys these were always False.
        "has_critical": severity_counts.get("critical", 0) > 0,
        "has_high": severity_counts.get("high", 0) > 0,
        "completion_time": results.get("completion_time"),
    }


def validate_result_structure(
    results: Dict[str, Any],
) -> Tuple[bool, Optional[str]]:
    """
    Validate the structure of scan results.

    Takes the raw parsed document, not an AshAggregatedResults. It previously
    accepted either and returned ``(True, None)`` for any instance of the model
    on its first line, which made the whole body below unreachable from
    ``get_scan_results`` -- its only caller. The model cannot be validated
    meaningfully anyway: every field has a default and unknown keys are ignored,
    so by the time a document has become a model there is nothing left to check.

    Args:
        results: Dictionary containing the raw parsed scan results

    Returns:
        Tuple of (is_valid, error_message)
    """
    # A key present but explicitly null is absent for our purposes. A document
    # can carry "sarif": null, and rejecting that outright would fail scans whose
    # results are entirely in scanner_results.
    has_sarif = results.get("sarif") is not None
    has_scanner_results = results.get("scanner_results") is not None

    # Check for required fields - we need either sarif or scanner_results
    if not has_sarif and not has_scanner_results:
        return (
            False,
            "Missing required fields: either 'sarif' or 'scanner_results' must be present",
        )

    # If sarif is present, validate its structure
    if has_sarif:
        sarif = results["sarif"]
        if not isinstance(sarif, dict):
            return False, "SARIF data must be a dictionary"

        if "runs" not in sarif:
            return False, "SARIF data is missing 'runs' field"

        if not isinstance(sarif["runs"], list):
            return False, "SARIF 'runs' must be a list"

    # If scanner_results is present, validate its structure
    if has_scanner_results:
        scanner_results = results["scanner_results"]
        if not isinstance(scanner_results, dict):
            return False, "scanner_results must be a dictionary"

    return True, None


def resolve_output_directory(source_dir=None, output_dir=None):
    """
    Resolve the output directory path based on the provided parameters.

    Args:
        source_dir: Path to the source directory that was scanned
        output_dir: Path to the scan output directory

    Returns:
        Resolved absolute Path object to the output directory
    """
    # Start with the current working directory as a base
    cwd = Path.cwd()

    # Case 1: Both source_dir and output_dir are provided
    if source_dir and output_dir:
        # If output_dir is absolute, use it directly
        if Path(output_dir).is_absolute():
            return Path(output_dir)
        # If output_dir is relative, resolve it relative to source_dir
        else:
            # If source_dir is absolute, use it directly
            if Path(source_dir).is_absolute():
                return Path(source_dir) / output_dir
            # If source_dir is relative, resolve it relative to cwd
            else:
                return (cwd / source_dir) / output_dir

    # Case 2: Only source_dir is provided
    elif source_dir:
        # If source_dir is absolute, use it directly
        if Path(source_dir).is_absolute():
            return Path(source_dir) / ".ash" / "ash_output"
        # If source_dir is relative, resolve it relative to cwd
        else:
            return (cwd / source_dir) / ".ash" / "ash_output"

    # Case 3: Only output_dir is provided
    elif output_dir:
        # If output_dir is absolute, use it directly
        if Path(output_dir).is_absolute():
            return Path(output_dir)
        # If output_dir is relative, resolve it relative to cwd
        else:
            return cwd / output_dir

    # Case 4: Neither is provided, use default in current directory
    else:
        return cwd / ".ash" / "ash_output"


def restored_results_refusal(
    output_dir: Path, operation: str
) -> Optional[Dict[str, Any]]:
    """The error a results reader returns for put-back results, or None.

    An MCP scan that ended without results has the previous scan's results put
    back with a marker beside them (core/previous_results.py). They are complete
    and parseable, and they are not the last scan's, so a tool that reads results
    from a directory, with no scan id to tell it whose they are, answers as it did
    when such a scan left the directory empty: not complete. The previous results
    stay on disk for anyone who reads the files themselves.
    """
    from automated_security_helper.core.previous_results import (
        holds_restored_results,
    )
    from automated_security_helper.core.resource_management.error_handling import (
        ErrorCategory,
        create_error_response,
    )

    if not holds_restored_results(Path(output_dir)):
        return None
    return create_error_response(
        error=MCPResourceError(
            f"Scan of output_dir {output_dir} is not complete. Results are not "
            "available: the last scan there ended without results, and ASH put "
            "back the results of the scan before it, which are not that scan's.",
            context={
                "output_dir": str(output_dir),
                "error_category": ErrorCategory.SCAN_INCOMPLETE.value,
                "output_holds_previous_results": True,
            },
        ),
        operation=operation,
        suggestions=[
            "Run the scan again",
            "get_scan_progress with the scan's id says how it ended",
        ],
    )


def get_scan_results_with_error_handling(
    output_dir: Path,
    include_sarif: bool = False,
) -> Dict[str, Any]:
    """
    Get scan results with comprehensive error handling.

    This function wraps get_scan_results with additional error handling to provide
    more detailed error information and graceful degradation for various failure scenarios.

    Args:
        output_dir: Path to the scan output directory
        include_sarif: Passed to :func:`get_scan_results`.

    Returns:
        Dictionary containing scan results or error information
    """
    from automated_security_helper.core.resource_management.error_handling import (
        validate_directory_path,
        ErrorCategory,
        create_error_response,
    )

    try:
        # Validate output directory
        error = validate_directory_path(output_dir)
        if error:
            return create_error_response(
                error=error,
                operation="get_scan_results",
                suggestions=[
                    "Check that the output directory exists",
                    "Verify that the output directory path is correct",
                    "Ensure the output directory has proper permissions",
                ],
            )

        refusal = restored_results_refusal(output_dir, "get_scan_results")
        if refusal is not None:
            return refusal

        # Check if scan has completed
        is_complete = check_scan_completion(output_dir)
        if not is_complete:
            return create_error_response(
                error=MCPResourceError(
                    f"Scan of output_dir {output_dir} is not complete. Results are not available.",
                    context={
                        # "scan_id": scan_id,
                        "output_dir": str(output_dir),
                        "error_category": ErrorCategory.SCAN_INCOMPLETE.value,
                    },
                ),
                operation="get_scan_results",
                suggestions=[
                    "Wait for the scan to complete",
                    "Check if the scan process is still running",
                    "Verify that the scan was started correctly",
                ],
            )

        # Get scan results
        results = get_scan_results(output_dir, include_sarif=include_sarif)

        # The check above ran before the read, and a restore can run between the
        # two. It writes its marker first and moves the previous results back
        # after it (core/previous_results.py), so results read after it put them
        # back are followed by a marker that is there to see now.
        refusal = restored_results_refusal(output_dir, "get_scan_results")
        if refusal is not None:
            return refusal
        return results

    except MCPResourceError as e:
        # Handle MCPResourceError with enhanced context
        return create_error_response(
            error=e,
            operation="get_scan_results",
        )
    except Exception as e:
        # Handle unexpected errors, describing a ValidationError by field rather
        # than quoting its input, in the log's traceback too (utils/error_text.py).
        log_unexpected_error(_logger, e, "Unexpected error getting scan results")
        message = error_text(e)
        return create_error_response(
            error=MCPResourceError(
                f"Unexpected error getting scan results: {message}",
                context={
                    # "scan_id": scan_id,
                    "cwd": str(Path.cwd()),
                    "output_dir": str(output_dir),
                    "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                    "error_type": type(e).__name__,
                    "error_message": message,
                },
            ),
            operation="get_scan_results",
        )
