"""Module containing the ScanResultsContainer class for wrapping scanner results."""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Dict, Iterable, Literal, List, Optional

from pydantic import BaseModel, Field, field_validator

from automated_security_helper.core.enums import ScannerStatus

# InputNotScanned is defined beside ReportMetadata, which records the scan-level ones;
# imported here, where each scanner's own are recorded, under the name it always had.
from automated_security_helper.models.asharp_model import (
    InputNotScanned,
    ScannerSeverityCount,
)
from automated_security_helper.utils.get_shortest_name import home_as_tilde

__all__ = ["InputNotScanned", "ScanResultsContainer"]


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
    # The tool's own exit code, or None for a scanner whose tool never ran: a
    # MISSING row, or one whose scan started no tool. The executor assigns it
    # only for a tool that did start, so a default of 0 would make every row
    # that ran nothing claim a clean exit.
    exit_code: int | None = None
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
    # Why this container is MISSING or SKIPPED, in words an operator can act on.
    # Assigned, never appended to, so ``exclude_unset`` dumps keep it: that dump is
    # the per-target ASH.ScanResults.json and the additional_reports entry
    # ``core.unified_metrics`` reads the scanner row's reason from.
    missing_reason: str | None = None
    skipped_reason: str | None = None
    # The recorded reason a run of this scanner ended with a tool ASH could not
    # stop (naming the process id), or None. Assigned, never appended to, for the
    # same reason as the two above: the ``exclude_unset`` per-target dump is the
    # report ``run_ash_scan.scanners_that_could_not_stop`` reads this key from.
    # Set only from the run's recorded state, never from text the tool printed,
    # and it fails the run whatever ``fail_on_incomplete_scanners`` says: the
    # tool may still write into the output directory after the gate reads it.
    could_not_stop: str | None = None
    # The content databases whose staleness turned a clean result into ERROR, under
    # ``content_db_staleness: fail``. Set only then, and assigned for the same reason
    # as the two above. It is what lets the exit-1 message, the MCP payload and
    # ``ash merge`` tell this ERROR, which is the stale database and is reported as
    # one, from a scanner that failed to run (see
    # ``utils.content_db_staleness.scanners_in_error_for_a_stale_database``).
    rejected_content_databases: List[str] | None = None

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
    #           syft, detect-secrets and opengrep are all in this state (cdk-nag, cfn-nag and
    #           npm-audit track targets), so this is the case that must stay untouched.
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
    #
    # Strict: lax coercion turned a producer bug into an invented count. A string
    # "3" read as 3 attempted targets, a float 1.0 as one, and True as one -- while
    # False coerced to 0, which is FALSY, so a container carrying
    # ``targets_failed=False`` beside real attempts slipped past the ERROR guard in
    # ``determine_status`` and graded by the severity gate as if nothing failed.
    # ``None`` stays legitimate for ``targets_attempted`` only: it is the no-claim
    # state; a failure count has no no-claim state of its own.
    targets_attempted: int | None = Field(default=None, strict=True)
    targets_failed: int = Field(default=0, strict=True)

    @field_validator("errors", mode="after")
    @classmethod
    def _errors_without_the_home_directory(cls, errors: List[str]) -> List[str]:
        """Each error with the home directory written as ``~``.

        Covers errors passed to the constructor (scan_phase builds containers
        with ``errors=[...]`` from import and construction failures whose text
        can name files under the home directory). ``add_error`` applies the
        same rule itself, because a plain field assignment does not run
        validators here.
        """
        return [home_as_tilde(error) for error in errors]

    @field_validator("exception", "stack_trace", mode="after")
    @classmethod
    def _text_without_the_home_directory(cls, text: str | None) -> str | None:
        """The same rule for the other persisted failure texts.

        ``set_exception`` applies it itself for the assignment path, like
        ``add_error`` does.
        """
        return None if text is None else home_as_tilde(text)

    # Inputs the scanner found and did not scan, each with the reason: npm-audit's
    # lockfiles in offline mode, which it cannot audit without the registry's advisory
    # service. Rendered beside the summary table and markdown summary
    # (unified_metrics.inputs_not_scanned), because no status value says which input
    # went unexamined. Empty for a scanner that scanned everything it found.
    inputs_not_scanned: List[InputNotScanned] = Field(default_factory=list)

    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata to the container.

        Reassigned rather than written into the default dict, for the reason
        ``add_error`` gives: a key set inside the default never marks the field
        set, and the results row is dumped with ``exclude_unset=True``.

        Args:
            key: Metadata key
            value: Metadata value
        """
        self.metadata = {**self.metadata, key: value}

    def add_error(self, error: str) -> None:
        """Add an error message to the container.

        Reassigned rather than appended: appending into the default list never
        marks the field as set, and the results row is dumped with
        ``exclude_unset=True``, so an appended error was left out of the saved
        results.

        The home directory is written as ``~`` here, in the one place every
        caller passes through, because these errors go into the results and
        reports rather than ash.log (the rule scanner_executor states beside
        home_as_tilde).

        Args:
            error: Error message to add

        Assigned rather than appended: appending to the default list does not mark
        ``errors`` as set, so ``model_dump(exclude_unset=True)`` (ScanResultProcessor)
        would leave the reason out of ``additional_reports`` and
        ``ASH.ScanResults.json``.
        """
        error = home_as_tilde(error)
        if error not in self.errors:
            self.errors = [*self.errors, error]

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
        """False when the scanner attempted targets and failed any of them.

        States the counter half of the rule SARIF ``executionSuccessful`` follows, fail-closed
        over the attempted targets: a run that could not evaluate one of its targets did not
        complete successfully, and a report claiming success while some of its targets were
        never evaluated is worse than an absent report, because a consumer cannot tell the
        partial run from a clean one.

        The scanners derive the flag from the same counters and then add what only the live
        plugin knows, through ``ScannerPluginBase._sarif_execution_successful``: a recorded stop
        cause (``scan_kept_flag``: timed out, cancelled, rejected, signaled; or
        ``scan_post_run_error``) and the exit code. This property reads neither. The container
        is the saved results model and holds counters only, and ``ScannerExecutor`` grades a
        stopped run ERROR from the plugin's flag, so a run stopped before it counted a target
        is True here, False in the SARIF flag, and ERROR in the status. Whenever this property
        is False the SARIF flag is False too.
        (An earlier rule, ``targets_failed < targets_attempted``, went False only when ALL
        attempted targets failed, so one clean target masked every failed one.)

        Stays True for a tracked-but-zero scan, and that is intentional. SARIF defines the
        field as "specifies whether the tool's execution completed successfully" -- it is about
        the run, not about the yield. A scanner that started, found no applicable input and
        exited cleanly did complete successfully; reporting False would tell every consumer
        that gates on ``executionSuccessful`` that the run broke, which would start failing
        builds on repositories that simply contain no CloudFormation. "Nothing was evaluated"
        is a different fact, and it belongs in ``status`` (SKIPPED), which is the field the
        summary table renders and a human reads.

        The falsy test covers both None (no claim) and 0 (tracked, attempted none). A
        miscounted scan -- a negative in either counter, or a failure count recorded with
        no attempt count at all or with an attempt count of zero -- is False too, so this
        property agrees with the status's ERROR instead of contradicting it, and SARIF
        ``executionSuccessful`` and the rendered status cannot disagree about the same run.
        Any failure count other than zero is checked first, so no attempt count can turn a
        recorded failure, or a negative failure count, into success.
        """
        if self.targets_failed != 0:
            return False
        # The failure count is known to be zero here, so None (no claim) and 0 (attempted
        # nothing) both complete successfully; a negative attempt count does not.
        if not self.targets_attempted:
            return True
        return self.targets_attempted > 0

    def set_exception(
        self, exception: BaseException, values: Iterable[str] = ()
    ) -> None:
        """Set exception information including stack trace.

        Args:
            exception: Exception that occurred
            values: Text to redact from what is recorded: the config's
                environment values (``utils.error_text.config_environment_values``).
        """
        self.add_error(self._record_exception(exception, values))

    def _record_exception(
        self, exception: BaseException, values: Iterable[str] = ()
    ) -> str:
        """Record ``exception`` and its stack trace and mark the container FAILED.

        Returns the exception's text, which :meth:`set_exception` adds to the
        errors; :meth:`for_failure` decides whether the caller's own errors
        already say it.
        """
        # Described, not quoted: these go into the results file, and a pydantic
        # error's own text quotes the refused input (utils/error_text.py).
        from automated_security_helper.utils.error_text import (
            error_text,
            traceback_text,
        )
        from automated_security_helper.utils.redacted_model import value_tuple

        values = value_tuple(values)
        text = error_text(exception, values)
        # Tilded like add_error's entries: both fields persist in the saved
        # results, and a stack trace names files by their full paths. The
        # environment values are redacted first; a value under the home
        # directory no longer matches once it is written as ~. The trace is the
        # one of the exception given, not of whatever the caller is handling,
        # unless the one given was never raised: it has no traceback, and its
        # trace would be one line. That is an exception built to wrap the one
        # being handled (``ScannerError(f"...: {e}")``), so the handled one's
        # trace is the only trace there is.
        trace_of = exception
        if exception.__traceback__ is None:
            handled = sys.exc_info()[1]
            if handled is not None and handled is not exception:
                trace_of = handled
        self.exception = home_as_tilde(text)
        self.stack_trace = home_as_tilde(traceback_text(trace_of, values=values))
        self.status = ScannerStatus.FAILED
        return text

    # ---- Factory methods ------------------------------------------------

    @classmethod
    def for_excluded(
        cls, scanner_name: str, reason: str | None = None
    ) -> "ScanResultsContainer":
        """Build a container for a scanner that was excluded via configuration."""
        return cls(
            scanner_name=scanner_name,
            excluded=True,
            status=ScannerStatus.SKIPPED,
            duration=None,
            skipped_reason=reason,
        )

    @classmethod
    def for_missing_deps(
        cls, scanner_name: str, reason: str | None = None
    ) -> "ScanResultsContainer":
        """Build a container for a scanner whose dependencies were not satisfied."""
        return cls(
            scanner_name=scanner_name,
            dependencies_satisfied=False,
            status=ScannerStatus.MISSING,
            duration=None,
            missing_reason=reason,
        )

    @classmethod
    def for_failure(
        cls,
        scanner_name: str,
        errors: Optional[List[str]] = None,
        exception: Optional[BaseException] = None,
        values: Iterable[str] = (),
    ) -> "ScanResultsContainer":
        """Build a container for a scanner that failed to execute cleanly.

        *values* are redacted from what is recorded of *exception*, as
        :meth:`set_exception` does; *errors* go through :meth:`add_error`,
        which writes the home directory in each entry as ``~``. The exception's
        own text is added to the errors only when none of *errors* already says
        it, so a failure given as both is listed once. An error says it when it
        is the text or ends in ``: `` and the text; one that only contains the
        text does not.

        The duration is None, as for the excluded and missing containers: no
        timed run is recorded here, and 0 would claim a run of no time.
        """
        container = cls(
            scanner_name=scanner_name,
            status=ScannerStatus.FAILED,
            duration=None,
        )
        if errors:
            for err in errors:
                container.add_error(err)
        if exception is not None:
            # _record_exception also sets status to FAILED
            text = home_as_tilde(container._record_exception(exception, values))
            # Said already when an error is the text, or ends in it after a
            # ``label: `` as the callers write it. Not when the text is only
            # somewhere inside one: ``timed out`` is in every "... timed out
            # after 300s", and is not that error.
            if not any(
                recorded == text or recorded.endswith(f": {text}")
                for recorded in container.errors
            ):
                container.add_error(text)
        return container

    # ---- Threshold evaluation ------------------------------------------

    def determine_status(self, threshold: str | None) -> ScannerStatus:
        """Determine status from per-target outcomes first, then severity_counts vs threshold.

        For a tracking scanner that failed every attempted target, or carries a
        negative count, returns ERROR, and so does any recorded failure beside no
        attempt count or an attempt count of zero. For one that failed SOME targets,
        the severity gate runs first: FAILED when the findings from the evaluated
        targets fail it, ERROR otherwise. SKIPPED when a tracking scanner attempted
        none and no finding of it fails the gate (FAILED when one does), and
        otherwise PASSED/FAILED from the severity gate: any finding
        at or above the configured severity threshold fails the scanner. Does not mutate the
        container's current status — the caller assigns the result.

        The gate itself lives in ``utils.severity_ladder``, shared with the
        junitxml reporter so the two cannot disagree about the same finding.
        Two properties worth knowing before changing anything here: raising the
        threshold LOOSENS the gate, and a None/empty threshold is more
        permissive than ``CRITICAL`` rather than equivalent to it — it is how an
        operator turns the gate off, so even a critical finding passes.
        """

        # Both per-target guards are checked BEFORE the severity gate, and that ordering is the
        # whole point.
        #
        # Everything below reasons about finding counts, where zero means "nothing to
        # report". For a scanner that failed on any of its targets, or one that attempted
        # none, zero can mean "it was not examined" -- the same number carrying the opposite
        # meaning. Deciding on findings first would return PASSED and discard that
        # distinction permanently. Fail-closed over the attempted targets (the rule
        # ``scan_succeeded`` states): one target that was never evaluated carries no verdict,
        # and a PASSED over it reads as "evaluated and clean" for a file nothing examined.
        #
        # ERROR rather than FAILED -- but only when there is nothing else to say. FAILED
        # means the scanner worked and found problems, which a consumer may legitimately
        # gate or waive on, and the executor promotes only PASSED and SKIPPED rows. A
        # scanner that evaluated MOST of its targets and found gate-failing problems on
        # them did work: grading that run ERROR hides the findings from everything that
        # gates on FAILED, so on a partial loss the severity gate runs first, and ERROR is
        # the answer only when the surviving findings pass it (there is then nothing to
        # waive, and the loss is the loudest fact). A scanner whose every attempted target
        # failed evaluated nothing, so it stays at unconditional ERROR: a zero finding
        # count there means "not examined", not "clean".
        #
        # Any nonzero failure count enters this guard, whatever the attempt count says. A
        # failure count beside NO attempt count (None) or beside an attempt count of ZERO is a
        # contradiction, not a claim: something recorded failed targets while nothing
        # recorded attempting any, so the accounting is wrong and the severity gate below
        # would be grading findings against coverage nobody vouched for. The zero case is
        # reachable through the recording API itself: ``record_target_attempt(0)`` moves the
        # attempt count off None, and ``record_target_failure`` raises the failure count
        # without touching it. Both grade ERROR, as a negative count does: the counters are
        # evidence of a defect in the producer, not of a clean scan. A zero failure count
        # beside None stays the plain no-claim state every non-tracking scanner is in.
        #
        # ``self.targets_attempted and ...`` in the negative arm, rather than ``< 0`` alone:
        # the field is tri-state, and comparing None with an int raises TypeError. The
        # explicit negative arm keeps a miscounted scanner (a negative attempted count built
        # directly, past the executor's boundary) at ERROR, as the old all-failed comparison
        # did by accident of ``0 >= -1``. Only the partial arm reaches the severity gate, and
        # it requires both counts positive and ordered, so neither a poisoned counter nor a
        # contradiction is ever graded on its findings.
        if self.targets_failed != 0 or (
            self.targets_attempted and self.targets_attempted < 0
        ):
            partial = (
                self.targets_attempted is not None
                and self.targets_attempted > 0
                and 0 < self.targets_failed < self.targets_attempted
            )
            if partial and self._severity_gate(threshold) == ScannerStatus.FAILED:
                return ScannerStatus.FAILED
            return ScannerStatus.ERROR

        # Tracked, and attempted nothing. PASSED has to mean "evaluated and clean"; it must
        # never mean "evaluated nothing", because those render identically -- green, no
        # findings -- and an operator reads the first one off a report that shows the second.
        #
        # Ordered after the ERROR guard on purpose, and the order is observable rather than
        # cosmetic. The two conditions overlap on a negative count: the guard above tests
        # truthiness, so -1 is truthy, its explicit negative arm holds, and a miscounted
        # scanner reports ERROR instead of reaching this line. That is the intended
        # precedence -- ERROR is the louder and more actionable of the two, because "it tried
        # and everything broke" tells an operator more than "it evaluated nothing", and a
        # negative counter means something is genuinely wrong with the scanner rather than
        # with its input.
        #
        # The overlap is also why this guard keeps ``<= 0`` instead of ``== 0``: narrowing
        # the ERROR guard's negative arm away later would send negatives here, rather than
        # past both guards and into the severity gate.
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
        # detect-secrets, opengrep -- and turn an entire clean report yellow.
        #
        # SKIPPED says nothing was evaluated, so it holds only while no finding fails the
        # gate. Findings that do fail it beside no attempts are a contradiction of the
        # counters, as a failure count beside no attempts is, and the gate is not skipped
        # on the strength of a counter: FAILED, so the findings reach whatever gates on it.
        if self.targets_attempted is not None and self.targets_attempted <= 0:
            if self._severity_gate(threshold) == ScannerStatus.FAILED:
                return ScannerStatus.FAILED
            return ScannerStatus.SKIPPED

        return self._severity_gate(threshold)

    def _severity_gate(self, threshold: str | None) -> ScannerStatus:
        """PASSED or FAILED from ``severity_counts`` against *threshold*.

        The gate half of :meth:`determine_status`, factored out because the
        partial-loss arm asks it too: a run that lost some targets but found
        gate-failing problems on the rest reports FAILED, not ERROR.
        """
        from automated_security_helper.utils.severity_ladder import (
            severity_fails_threshold,
        )

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
