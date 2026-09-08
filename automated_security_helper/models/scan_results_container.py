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
    # ``targets_attempted`` is deliberately tri-state, because two counters cannot carry three
    # distinct facts:
    #
    #   None -- the scanner makes no claim about targets. It does not track per-target
    #           outcomes, so nothing can be concluded from the count and status falls through
    #           to the severity gate exactly as it always has. bandit, checkov, semgrep, grype,
    #           syft, detect-secrets, opengrep, cfn-nag and npm-audit are all in this state, so
    #           this is the case that must stay untouched.
    #   0    -- the scanner tracks targets and attempted none. It ran, evaluated nothing, and
    #           has no findings because it had no input -- not because the input was clean.
    #   > 0  -- the scanner tracks targets and attempted some. ``targets_failed`` is then
    #           meaningful relative to it.
    #
    # A plain ``int`` default of 0 would collapse the first two, which is the whole hazard
    # here: treating "no claim" as "attempted zero" would flip every non-tracking scanner from
    # PASSED to SKIPPED and turn an entire clean report yellow. That is a worse defect than the
    # one this distinction exists to fix.
    #
    # ``targets_failed`` stays a plain int because it has no independent meaning: it is only
    # ever read against ``targets_attempted``, and a failure count with no attempt count is a
    # caller bug rather than a third state.
    targets_attempted: int | None = None
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
        """Record that the scanner is about to process ``count`` more targets.

        Calling this at all is the claim. A scanner that never calls it leaves
        ``targets_attempted`` at None and is read as making no claim; the first call moves it
        off None even when ``count`` is 0, which is how a scanner says "I looked, there was
        nothing to look at" rather than staying silent.
        """
        self.targets_attempted = (self.targets_attempted or 0) + count

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

        Stays True for a tracked-but-zero scan, and that is intentional. SARIF defines the
        field as "specifies whether the tool's execution completed successfully" -- it is about
        the run, not about the yield. A scanner that started, found no applicable input and
        exited cleanly did complete successfully; reporting False would tell every consumer
        that gates on ``executionSuccessful`` that the run broke, which would start failing
        builds on repositories that simply contain no CloudFormation. "Nothing was evaluated"
        is a different fact, and it belongs in ``status`` (SKIPPED), which is the field the
        summary table renders and a human reads.

        The falsy test covers both None (no claim) and 0 (tracked, attempted none). Comparing
        with ``<= 0`` would raise TypeError on None.
        """
        if not self.targets_attempted:
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
        """Determine status from per-target outcomes first, then severity_counts vs threshold.

        Returns ERROR when a tracking scanner failed every target, SKIPPED when a tracking
        scanner attempted none, and otherwise PASSED/FAILED from the severity gate: any finding
        at or above the configured severity threshold fails the scanner. Does not mutate the
        container's current status — the caller assigns the result.

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

        # Both per-target guards are checked BEFORE the severity gate, and that ordering is the
        # whole point.
        #
        # Everything below reasons about finding counts, where zero means "nothing to
        # report". For a scanner that failed on every target, or one that attempted none, zero
        # means "nothing was examined" -- the same number carrying the opposite meaning.
        # Deciding on findings first would return PASSED and discard that distinction
        # permanently.
        #
        # ERROR rather than FAILED: FAILED means the scanner worked and found problems, which
        # a consumer may legitimately gate or waive on. This did not work, and there is
        # nothing to waive.
        #
        # ``self.targets_attempted and ...`` rather than ``> 0 and ...``: the field is now
        # tri-state, and comparing None with an int raises TypeError. Truthiness rejects both
        # None and 0, which are exactly the two values that must not reach this comparison.
        if self.targets_attempted and self.targets_failed >= self.targets_attempted:
            return ScannerStatus.ERROR

        # Tracked, and attempted nothing. PASSED has to mean "evaluated and clean"; it must
        # never mean "evaluated nothing", because those render identically -- green, no
        # findings -- and an operator reads the first one off a report that shows the second.
        #
        # Ordered after the ERROR guard on purpose, and the order is observable rather than
        # cosmetic. The two conditions overlap on a negative count: the guard above tests
        # truthiness, so -1 is truthy and ``0 >= -1`` holds, and a miscounted scanner reports
        # ERROR instead of reaching this line. That is the intended precedence -- ERROR is the
        # louder and more actionable of the two, because "it tried and everything broke" tells
        # an operator more than "it evaluated nothing", and a negative counter means something
        # is genuinely wrong with the scanner rather than with its input.
        #
        # The overlap is also why this guard keeps ``<= 0`` instead of ``== 0``: narrowing the
        # ERROR guard to an explicit ``> 0`` later would send negatives here, rather than past
        # both guards and into the severity gate.
        #
        # That is worth less than an earlier version of this comment claimed. It said the ``<= 0``
        # prevents "PASSED off a broken counter", and PASSED off a broken counter is in fact the
        # outcome today, by the only route negatives actually travel. Counters reach this model
        # through ``_target_count_attr`` in the executor, which rejects anything below zero and
        # hands over None -- so a plugin exposing ``targets_attempted = -1`` arrives here as a
        # no-claim scanner, reaches the severity gate, and reports PASSED no matter what these two
        # guards say. That boundary now logs a warning naming the plugin and the value, which is
        # where a broken counter is actually made visible; these guards are not what does it.
        # A negative only gets in front of this line from a caller constructing the container
        # directly, which today means tests and any future in-process producer.
        #
        # ``is not None`` is the load-bearing half of this condition. Dropping it would fire on
        # every scanner that does not track targets -- bandit, checkov, semgrep, grype, syft,
        # detect-secrets, opengrep, cfn-nag, npm-audit -- and turn an entire clean report
        # yellow.
        if self.targets_attempted is not None and self.targets_attempted <= 0:
            return ScannerStatus.SKIPPED

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
