"""Module containing the ScanResultsContainer class for wrapping scanner results."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Dict, Literal, List, Optional

from pydantic import BaseModel, Field

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import ScannerSeverityCount


class ScanResultsContainer(BaseModel):
    """Container for scanner results with metadata."""

    scanner_name: str = "unknown"
    report_type: Annotated[
        Literal[
            "text",
            "json",
            "yaml",
            "sarif",
            "cyclonedx",
            "cyclonedx_xml",
            "html",
            "junitxml",
            "spdx",
            "pdf",
        ],
        Field(
            description="Type of report, e.g., 'static_analysis', 'sarif', etc.",
        ),
    ] = "text"
    path: Annotated[
        str | None,
        Field(
            description="Path to the report file in the output directory, if there is a physical report.",
        ),
    ] = None
    target: Path | None = None
    target_type: str | None = None
    exit_code: int = 0
    finding_count: int = 0
    start_time: datetime | None = None
    end_time: datetime | None = None
    duration: float | None = 0
    metadata: Dict[str, Any] = {}
    raw_results: Any | None = None
    severity_counts: ScannerSeverityCount = Field(default_factory=ScannerSeverityCount)
    scanner_severity_threshold: (
        Literal["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None
    ) = None
    status: ScannerStatus = ScannerStatus.PASSED
    dependencies_satisfied: bool = True
    excluded: bool = False
    errors: List[str] = Field(default_factory=list)
    exception: str | None = None
    stack_trace: str | None = None

    # How much work the scanner set out to do, and how much of it failed.
    #
    # Without these, status can only be derived from findings, and "found nothing" is
    # indistinguishable from "scanned nothing". A scanner whose every target failed then
    # reports PASSED with zero findings, which reads exactly like a clean project. These two
    # counters are what let ``determine_status`` tell those apart.
    #
    # Scanners that do not track per-target outcomes leave both at 0, which preserves their
    # existing behavior: the guard only triggers once a scanner has said it attempted work.
    targets_attempted: int = 0
    targets_failed: int = 0

    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata to the container.

        Args:
            key: Metadata key
            value: Metadata value
        """
        self.metadata[key] = value

    def add_error(self, error: str) -> None:
        """Add an error message to the container.

        Args:
            error: Error message to add
        """
        if error not in self.errors:
            self.errors.append(error)

    def record_target_attempt(self, count: int = 1) -> None:
        """Record that the scanner is about to process ``count`` more targets."""
        self.targets_attempted += count

    def record_target_failure(self, target: Any, error: str) -> None:
        """Record that one target could not be scanned.

        Callers must use this rather than a local list. A local accumulator is invisible to
        status computation, so appending to one and never reading it produces a scanner that
        fails on every target and still reports success -- which is exactly the defect this
        method exists to make impossible to reintroduce quietly.
        """
        self.targets_failed += 1
        self.add_error(f"{target}: {error}")

    @property
    def scan_succeeded(self) -> bool:
        """False when the scanner attempted targets and failed all of them.

        Feeds SARIF ``executionSuccessful``. A report claiming success while carrying no
        results is worse than an absent report, because a consumer cannot tell the difference
        between a clean scan and one that never ran.
        """
        if self.targets_attempted <= 0:
            return True
        return self.targets_failed < self.targets_attempted

    def set_exception(self, exception: Exception) -> None:
        """Set exception information including stack trace.

        Args:
            exception: Exception that occurred
        """
        import traceback

        self.exception = str(exception)
        self.stack_trace = traceback.format_exc()
        self.add_error(str(exception))
        self.status = ScannerStatus.FAILED

    # ---- Factory methods ------------------------------------------------

    @classmethod
    def for_excluded(cls, scanner_name: str) -> "ScanResultsContainer":
        """Build a container for a scanner that was excluded via configuration."""
        return cls(
            scanner_name=scanner_name,
            excluded=True,
            status=ScannerStatus.SKIPPED,
            duration=None,
        )

    @classmethod
    def for_missing_deps(cls, scanner_name: str) -> "ScanResultsContainer":
        """Build a container for a scanner whose dependencies were not satisfied."""
        return cls(
            scanner_name=scanner_name,
            dependencies_satisfied=False,
            status=ScannerStatus.MISSING,
            duration=None,
        )

    @classmethod
    def for_failure(
        cls,
        scanner_name: str,
        errors: Optional[List[str]] = None,
        exception: Optional[BaseException] = None,
    ) -> "ScanResultsContainer":
        """Build a container for a scanner that failed to execute cleanly."""
        container = cls(
            scanner_name=scanner_name,
            status=ScannerStatus.FAILED,
        )
        if errors:
            for err in errors:
                container.add_error(err)
        if exception is not None:
            container.set_exception(exception)
            # set_exception already sets status to FAILED
        return container

    # ---- Threshold evaluation ------------------------------------------

    def determine_status(self, threshold: str | None) -> ScannerStatus:
        """Determine PASSED/FAILED status by comparing severity_counts to threshold.

        Any finding at or above the configured severity threshold fails the
        scanner. Does not mutate the container's current status — the caller
        assigns the result.

        The gate itself lives in ``utils.severity_ladder``, shared with the
        junitxml reporter so the two cannot disagree about the same finding.
        Two properties worth knowing before changing anything here: raising the
        threshold LOOSENS the gate, and a None/empty threshold is more
        permissive than ``CRITICAL`` rather than equivalent to it — it is how an
        operator turns the gate off, so even a critical finding passes.
        """
        from automated_security_helper.utils.severity_ladder import (
            severity_fails_threshold,
        )

        # Checked BEFORE the severity gate, and this ordering is the whole point.
        #
        # Everything below reasons about finding counts, where zero means "nothing to
        # report". For a scanner that failed on every target, zero means "nothing was
        # examined" -- the same number carrying the opposite meaning. Deciding on findings
        # first would return PASSED and discard that distinction permanently.
        #
        # ERROR rather than FAILED: FAILED means the scanner worked and found problems, which
        # a consumer may legitimately gate or waive on. This did not work, and there is
        # nothing to waive.
        if self.targets_attempted > 0 and self.targets_failed >= self.targets_attempted:
            return ScannerStatus.ERROR

        counts = self.severity_counts
        counts_by_severity = (
            ("CRITICAL", counts.critical),
            ("HIGH", counts.high),
            ("MEDIUM", counts.medium),
            ("LOW", counts.low),
            ("INFO", counts.info),
        )

        for severity, count in counts_by_severity:
            if count > 0 and severity_fails_threshold(severity, threshold):
                return ScannerStatus.FAILED
        return ScannerStatus.PASSED
