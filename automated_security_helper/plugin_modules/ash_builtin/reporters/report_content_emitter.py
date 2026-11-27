# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime, timedelta, timezone
from enum import Enum
import json
import re
from typing import Dict, List, Any, Optional, Sequence, TYPE_CHECKING

import polars as pl

from automated_security_helper.models.flat_vulnerability import (
    FlatVulnerability,
    _extract_snippet_from_message,
)
from automated_security_helper.models.vocab import Disposition
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.unified_metrics import (
    fit_error_reason,
    get_unified_scanner_metrics,
    recorded_error_sentence,
)
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.core.constants import ASH_DEFAULT_SEVERITY_LEVEL
from automated_security_helper.models.workspace import is_workspace_scan
from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_section import (
    workspace_policy_gates,
    workspace_project_scanner_thresholds,
    workspace_project_thresholds,
)
from automated_security_helper.utils.finding_clusters import (
    clusters_by_project,
    fold_enabled,
    fold_positions,
    provenance_entries,
    provenance_note,
)
from automated_security_helper.utils.policy_origin import is_policy_origin
from automated_security_helper.utils.short_reason import (
    SHORT_REASON_LIMIT,
    is_short_reason,
    short_error_reason,  # noqa: F401 -- written here first, so still read from here
)
from automated_security_helper.utils.severity_ladder import (
    SEVERITY_COUNT_KEYS,
    SEVERITY_DISPLAY_ORDER,
    severity_fails_threshold,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters._report_frames import (
    active_level_counts,
    flag_total,
    graded_frame,
    severity_order,
    top_locations,
)


def coverage_shortfall_text(attempted: int | None, failed: int | None) -> str:
    """The sentence after a scanner's name in an "Incomplete coverage" row.

    One renderer for the HTML, Markdown and text reports, because the three
    each computed ``attempted - failed`` inline, and ``coverage_shortfalls``
    yields ``(name, None, None)`` for a scanner whose stored target counters
    could not be read. Each report then raised TypeError on that row and the
    whole document was lost, for the one scanner whose coverage most needs
    stating. The console renderer already printed "unknown" for it; this is
    the same reading for the files.

    Two causes land on an unknown-size row: stored counters that cannot be
    read, and a coverage claim filed under another scanner's key, whose
    counters are perfectly readable. The sentence names neither, so it is true
    of both.
    """
    if attempted is None or failed is None:
        return (
            "coverage unknown; how many targets it evaluated could not be "
            "determined, so that count is not known"
        )
    # A record whose failed count exceeds its attempted count is inconsistent;
    # the evaluated count is never printed below zero.
    return (
        f"evaluated {max(attempted - failed, 0)} of {attempted} target(s); "
        f"{failed} could not be evaluated"
    )


def deduplicated_summary_text(summary: Dict[str, Any]) -> str | None:
    """The line that gives the fold's counts, or None when it has none to give.

    One sentence for the HTML, Markdown, text and Bedrock summary reports. It
    follows the per-scanner figures and says they are unchanged: the fold's
    counts sit beside them, never in their place. None when the fold is off,
    and when it is on but folded nothing: "(0 duplicate rows folded)" told the
    reader nothing the per-scanner counts did not. The folded count is of live
    (unsuppressed) rows, which the sentence says, since the cards also fold
    suppressed duplicates under a suppressed representative.
    """
    folded = summary.get("deduplicated")
    if not folded or not folded["folded_rows"]:
        return None
    rows = folded["folded_rows"]
    noun = "row" if rows == 1 else "rows"
    return (
        f"Deduplicated: {folded['actionable']} actionable, {folded['active']} active "
        f"({rows} live duplicate {noun} folded into the finding that stands for it; "
        "suppressed duplicates fold apart). "
        "The per-scanner counts are unchanged."
    )


def refuse_negative_limit(value: int) -> int:
    """*value* if it is 0 or more; otherwise refuse it.

    For the reporters' ``max_detailed_findings`` and ``top_hotspots_limit``: a
    negative number slices a list from its end, so it dropped the last findings
    and hotspots instead of meaning none, and the text report printed
    "Showing -1 of N".
    """
    if value < 0:
        raise ValueError(
            "must be 0 or more: 0 lists none, and a negative number would drop "
            "the last items instead"
        )
    return value


#: The layouts a scan time is recorded in, once its offset and fractional
#: seconds are taken off.
_SCAN_TIME_FORMATS = (
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d - %H:%M (UTC)",
    "%Y-%m-%d %H:%M:%S",
)

#: A trailing ``+HH:MM`` or ``-HH:MM`` UTC offset.
_UTC_OFFSET = re.compile(r"([+-])(\d{2}):(\d{2})$")

#: The place of each severity in a findings list, most severe first: the
#: ladder's display order, whose source (``vocab.Severity`` member order) is the
#: same one the EnumColumn marker on ``FlatVulnerability.severity`` records, so
#: it is not a local ladder copy -- and this module no longer keys into the
#: frame marker at import time, where a marker move would have KeyError'd every
#: builtin reporter through ``reporters/__init__``. A severity the ladder does
#: not name sorts after all of them.
_SEVERITY_ORDER = dict(SEVERITY_DISPLAY_ORDER)

#: The keys of the summary's two disposition counts that are not severities. The
#: emitter writes them and the text, markdown and HTML reporters read them back:
#: derived from the ``Disposition`` members, so a rename reaches every consumer.
SUMMARY_ACTIONABLE = Disposition.ACTIONABLE.summary_key
SUMMARY_SUPPRESSED = Disposition.SUPPRESSED.summary_key
SUMMARY_BELOW_THRESHOLD = Disposition.BELOW_THRESHOLD.summary_key
SUMMARY_POLICY_NOT_GATING = Disposition.POLICY_NOT_GATING.summary_key


class OutcomeTone(str, Enum):
    """How serious the scan outcome reads, and how each report draws it.

    The value is the summary's ``tone`` text and the report stylesheet's
    ``outcome--<tone>`` class. Each member also answers its HTML masthead
    symbol and its Markdown alert type, read from one table keyed by the member
    (a module-level check refuses a member the table has no row for), so a
    report looks both up on the member and a new tone cannot reach a table that
    lacks a row for it.
    """

    DANGER = "danger"
    WARNING = "warning"
    SUCCESS = "success"

    @property
    def symbol(self) -> str:
        return _TONE_PRESENTATION[self][0]

    @property
    def alert(self) -> str:
        return _TONE_PRESENTATION[self][1]


_TONE_PRESENTATION: Dict[OutcomeTone, tuple[str, str]] = {
    OutcomeTone.DANGER: ("!", "CAUTION"),
    OutcomeTone.WARNING: ("!", "WARNING"),
    OutcomeTone.SUCCESS: ("\u2713", "TIP"),
}
if set(_TONE_PRESENTATION) != set(OutcomeTone):
    raise RuntimeError("an OutcomeTone has no presentation row")


_UNLISTED_SEVERITY_PLACE = len(_SEVERITY_ORDER)


def _severity_level(severity: Any) -> str:
    """The bucket name a finding of *severity* is counted under.

    A row with no severity is ``unknown``, the name the grading and the finding
    lists give it, not an empty name.
    """
    return str(severity or "UNKNOWN").lower()


def _add_level_counts(counts: Dict[str, int], graded: pl.DataFrame) -> None:
    """Add the unsuppressed findings of *graded* to *counts* by severity bucket."""
    for level, found in active_level_counts(graded):
        counts[level] = counts.get(level, 0) + found


def parse_scan_time(text: str) -> datetime | None:
    """The instant a recorded scan time names, timezone-aware, or None.

    A trailing ``Z`` and a ``+HH:MM`` or ``-HH:MM`` offset are read as the zone
    the time was written in, so the instant is the one the writer meant. A time
    with no offset, and the explicitly UTC layout (``2026-01-15 - 12:00 (UTC)``),
    is UTC. Fractional seconds are dropped. Dropping the offset and labelling
    the local wall time UTC, as this did, made ``time_delta`` wrong by the
    offset; leaving the UTC layout without a zone made its subtraction from an
    aware ``now`` raise and ``time_delta`` come back None.
    """
    cleaned = text.strip()
    zone = timezone.utc
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1]
    else:
        match = _UTC_OFFSET.search(cleaned)
        if match:
            sign = -1 if match.group(1) == "-" else 1
            try:
                zone = timezone(
                    sign
                    * timedelta(hours=int(match.group(2)), minutes=int(match.group(3)))
                )
            except ValueError:
                return None
            cleaned = cleaned[: match.start()]
    cleaned = cleaned.split(".")[0]
    for layout in _SCAN_TIME_FORMATS:
        try:
            return datetime.strptime(cleaned, layout).replace(tzinfo=zone)
        except ValueError:
            continue
    return None


class ReportContentEmitter:
    """
    A reusable class for generating report content from AshAggregatedResults.
    This class provides methods to generate different sections of a report
    that can be used by different reporter implementations.
    """

    def __init__(
        self, model: "AshAggregatedResults", *, human_presentation: bool = False
    ):
        """Initialize with an AshAggregatedResults.

        ``human_presentation`` is accepted from the human reporters and grades
        nothing differently: every report, the flat exports included, grades a
        finding by the gate's rule (``utils.severity_ladder.result_severity``),
        which the flattened findings already carry. It gives the emitter its own
        copy of each row, as the model memoizes them for every reporter of a
        run: a human report that writes one changes no later report's rows.
        It also has the scanner rows say "no duration" (None) where a person
        would read a measured zero (see :meth:`get_scanner_results`); the
        machine-readable exports keep the number the results recorded.
        """
        self.model = model
        self._human_presentation = human_presentation
        self.flat_vulns = model.to_flat_vulnerabilities()
        if human_presentation:
            self.flat_vulns = [vuln.model_copy() for vuln in self.flat_vulns]
        self.ash_conf = model.ash_config
        # Opt-in fold of duplicate clusters (``global_settings.deduplication.fold``),
        # for the human reports only: the machine-readable exports built on this
        # emitter never fold. The clusters are computed once, over the whole list,
        # and each view (hotspots, findings tables, cards) folds what it shows.
        self.fold = human_presentation and fold_enabled(model)
        self._clusters = clusters_by_project(self.flat_vulns) if self.fold else []
        self._positions = (
            {id(vuln): position for position, vuln in enumerate(self.flat_vulns)}
            if self.fold
            else {}
        )
        # The positions a fold prefers as a cluster's representative (the
        # actionable rows), filled on first fold: grading needs the threshold
        # tables read below.
        self._fold_prefer: set[int] | None = None
        # Each project's recorded gate, read once: is_finding_actionable runs
        # several times per finding (summary, hotspots, cards, detailed
        # findings), and the project list is scanned here instead of there.
        self._project_thresholds = workspace_project_thresholds(model)
        # The per-scanner gates each project's outcome recorded (a scanner whose
        # threshold the scan read from an environment variable is listed at the
        # strictest gate), read once for the same reason.
        self._project_scanner_thresholds = workspace_project_scanner_thresholds(model)
        # The gate each (project, scanner) pair resolves to, filled on first use.
        self._threshold_cache: Dict[tuple[Any, ...], str] = {}
        # The projects whose policy-scanner findings were reported and left out
        # of the outcome (policy_scanners_gate explicitly off). The JUnit report
        # reads the same table, so the reports and the exit code grade alike.
        self._policy_not_gating = {
            project
            for project, gate in workspace_policy_gates(model).items()
            if gate is False
        }

        # Get unified scanner metrics - always compute from the model to ensure consistency
        # The scanner_results in the model contain ScannerStatusInfo objects, not ScannerMetrics
        self.scanner_metrics = get_unified_scanner_metrics(model)

        # Get global severity threshold
        self.global_threshold = ASH_DEFAULT_SEVERITY_LEVEL
        if (
            self.ash_conf
            and hasattr(self.ash_conf, "global_settings")
            and hasattr(self.ash_conf.global_settings, "severity_threshold")
        ):
            self.global_threshold = self.ash_conf.global_settings.severity_threshold

    def fold_findings(
        self, vulns: List[FlatVulnerability]
    ) -> tuple[List[FlatVulnerability], Dict[int, str]]:
        """*vulns* with each foldable duplicate cluster shown once.

        Returns the rows that stay, in the order given, and a note for each row
        that stands for others, keyed by ``id(row)``. With the fold off the rows
        come back as they are and there are no notes. Only the rows in *vulns*
        fold, so a view that is already filtered (the actionable findings) folds
        what it holds; the note names those rows only. The representative of a
        cluster with an actionable member in the view is actionable, so a
        finding the gate fails the scan for is never hidden under a
        below-threshold or not-gating card. *vulns* are this emitter's own
        rows; a copied or foreign row is refused by name rather than raising a
        bare KeyError.
        """
        if not self.fold:
            return list(vulns), {}
        try:
            shown = [self._positions[id(vuln)] for vuln in vulns]
        except KeyError:
            raise ValueError(
                "fold_findings folds this emitter's own rows; a copied or "
                "foreign row has no position in the model's finding list"
            ) from None
        if self._fold_prefer is None:
            self._fold_prefer = {
                position
                for position, vuln in enumerate(self.flat_vulns)
                if self.is_finding_actionable(vuln)
            }
        kept = fold_positions(
            self.flat_vulns, self._clusters, shown, prefer=self._fold_prefer
        )
        notes = {}
        for position, others in kept:
            note = provenance_note(provenance_entries(self.flat_vulns, others))
            if note:
                notes[id(self.flat_vulns[position])] = note
        return [self.flat_vulns[position] for position, _ in kept], notes

    def actionable_finding_count(self) -> int:
        """How many actionable rows the findings lists draw from.

        The figure of a "Showing N of M" note: one per duplicate cluster when the
        fold is on, so it matches the rows the list can show.
        """
        actionable = [v for v in self.flat_vulns if self.is_finding_actionable(v)]
        return len(self.fold_findings(actionable)[0])

    def policy_not_gating_count(self) -> int:
        """How many rows the not-gating list draws from, folded like the list.

        The "of M" of that section's "Showing N of M": the summary's own
        not-gating figure counts every row unfolded, so against the folded list
        it read as a truncation, and the note then sent the reader to an HTML
        report that folds the same way.
        """
        left_out = [v for v in self.flat_vulns if self.is_policy_not_gating(v)]
        return len(self.fold_findings(left_out)[0])

    def _deduplicated_counts(self) -> Dict[str, Any]:
        """The fold's counts, for the line beside the per-scanner counts.

        Active (unsuppressed) rows and actionable rows, each counting a cluster
        once, with how many live rows were folded away (the cards also fold
        suppressed duplicates, which this count leaves out and the summary line
        says so). Counted over the finding rows, so they sit beside the scanner
        figures and never replace them. No per-severity breakdown: no reporter
        rendered the one this used to carry, and a dict nothing reads is a
        schema to keep for nobody.
        """
        live = [v for v in self.flat_vulns if not v.is_suppressed]
        active_rows, _ = self.fold_findings(live)
        actionable_rows, _ = self.fold_findings(
            [v for v in live if self.is_finding_actionable(v)]
        )
        return {
            "active": len(active_rows),
            "actionable": len(actionable_rows),
            "folded_rows": len(live) - len(active_rows),
        }

    def get_metadata(self) -> Dict[str, Any]:
        """Get report metadata as a dictionary."""
        # Get current time for report generation
        current_time = datetime.now(timezone.utc)
        current_time_str = current_time.isoformat(timespec="seconds")

        # Parse the scan generation time if available
        scan_time_str = self.model.metadata.generated_at or "Unknown"
        time_delta = None

        if scan_time_str != "Unknown":
            try:
                scan_time = parse_scan_time(scan_time_str)
                if scan_time is not None:
                    time_delta = current_time - scan_time
            except Exception:
                ASH_LOGGER.debug(
                    "Report parsing has failed, showing what had been resolved"
                )

        return {
            "project": self.model.metadata.project_name or "Unknown",
            "scan_time": scan_time_str,
            "report_time": current_time_str,
            "tool_version": self.model.metadata.tool_version or "Unknown",
            "time_delta": time_delta,
        }

    def get_scanner_results(self) -> List[Dict[str, Any]]:
        """Get scanner results with pass/fail status based on severity thresholds."""
        # Convert scanner metrics to dictionary format for reporters
        results = []
        # The merged file of a workspace scan carries no per-scanner duration,
        # so the metrics default every scanner to 0.0 there.
        durations_unrecorded = is_workspace_scan(self.model)
        for metrics in self.scanner_metrics:
            # In a report for people, a scanner that did not run took no time,
            # and a duration the results never recorded is not a measured
            # zero: both are None, which the reports show as "N/A". The
            # metrics default to 0.0, so these rows read "<1ms" as if the
            # scanner had run and been fast. A machine-readable export keeps
            # the recorded number.
            did_not_run = self._human_presentation and metrics.status in (
                ScannerStatus.SKIPPED,
                ScannerStatus.MISSING,
            )
            unrecorded = (
                self._human_presentation
                and durations_unrecorded
                and not metrics.duration
            )
            # The metrics hold only a pair that passed the check when they read it
            # back; it is checked again where it is copied into the flat outputs,
            # so a row built any other way cannot put a path or a malformed code
            # into ash.flat.json or the YAML report. A pair that fails is dropped
            # whole: a sentence is never shown under a code it was not recorded with.
            fit_pair = fit_error_reason(metrics.error_reason_code, metrics.error_reason)
            reason_fit_to_copy = (
                (fit_pair[1], fit_pair[0]) if fit_pair is not None else (None, None)
            )
            results.append(
                {
                    "scanner_name": metrics.scanner_name,
                    "suppressed": metrics.suppressed,
                    "critical": metrics.critical,
                    "high": metrics.high,
                    "medium": metrics.medium,
                    "low": metrics.low,
                    "info": metrics.info,
                    "total": metrics.total,
                    "passed": metrics.passed,
                    "threshold": metrics.threshold,
                    "threshold_source": metrics.threshold_source,
                    "actionable": metrics.actionable,
                    "status": metrics.status,
                    "excluded": metrics.excluded,
                    "dependencies_missing": metrics.dependencies_missing,
                    # Why a SKIPPED or MISSING scanner did not run, the same text as
                    # its scanner_results row in ash_aggregated_results.json. None
                    # for every other status.
                    "missing_reason": metrics.missing_reason,
                    "skipped_reason": metrics.skipped_reason,
                    # Why an ERROR scanner failed and the kind of failure it was, the
                    # same two strings as its scanner_results row in
                    # ash_aggregated_results.json. None for every other status, and
                    # for an ERROR row whose cause nothing recorded. The reports for
                    # people show the sentence only after get_scanners_not_run has
                    # checked it again.
                    "error_reason": reason_fit_to_copy[0],
                    "error_reason_code": reason_fit_to_copy[1],
                    # Seconds the scanner took; None, in a report for people, when
                    # it did not run or the results record no duration for it. The
                    # text and html reporters render a Duration column from this
                    # key with format_duration(result.get("duration", 0)); while
                    # the key was missing that default made every row read "<1ms".
                    "duration": None if did_not_run or unrecorded else metrics.duration,
                    # How much of its input the scanner actually evaluated. Every other key here
                    # describes what was found; these two describe how much was looked at, and
                    # without them a report cannot distinguish a clean scan from one that
                    # examined a fraction of its targets. ``determine_status`` only reports ERROR
                    # once every attempted target failed, so a partial loss leaves ``status`` to
                    # the severity gate -- PASSED or FAILED depending only on what the targets it
                    # DID read contained -- and reached these rows as nothing at all.
                    #
                    # ``targets_attempted`` is None for a scanner that does not track per-target
                    # outcomes, and is serialized as null rather than 0 so a consumer can tell
                    # "made no claim" from "attempted none".
                    "targets_attempted": metrics.targets_attempted,
                    "targets_failed": metrics.targets_failed,
                    # True when the stored counters could not be read; both counts are then
                    # null and the status is ERROR.
                    "counters_unusable": metrics.counters_unusable,
                }
            )

        return results

    def get_scanners_not_run(self) -> List[Dict[str, Any]]:
        """Why the scanners that did not run or failed did so, in scanner-results order.

        The SKIPPED, MISSING and ERROR rows of :meth:`get_scanner_results` that
        have a reason, grouped by status and reason: each entry has the
        ``scanners`` that share them, the ``status``, and the ``reason``. For
        SKIPPED and MISSING it is the ``skipped_reason`` or ``missing_reason`` of
        their rows in ``ash_aggregated_results.json``. The scanner table shows only
        the status, so without this list a report says that npm-audit was skipped
        and leaves "no lockfile beside a package.json" in the log.

        For ERROR it is the reason recorded for the scanner (the ``error_reason``
        of its row, one sentence the scan phase and the executor wrote with no
        path in it) when that still passes :func:`is_short_reason` here, because a
        results file read back by ``ash report`` can hold any text in that field.
        When none is recorded, or it does not pass, it is :func:`short_error_reason`
        of the first error recorded in the scanner's per-target reports: one
        sentence with no path, no stderr and no validation details, since a summary
        can be posted where the machine's paths and the tool's output should not
        be. A scanner with neither has no entry, and a scanner in ERROR only for a
        stale content database has none either: it is reported under its own
        heading.

        Scanners are grouped because one option often leaves many out: a run
        with ``--scanners npm-audit`` skips every other scanner for the one
        reason, which is one line here and not fifteen. A row that records no
        reason has no entry: the table already says all there is.
        """
        from automated_security_helper.utils.content_db_staleness import (
            scanners_in_error_for_a_stale_database,
        )

        stale = None
        groups: Dict[tuple[str, str], Dict[str, Any]] = {}
        for result in self.get_scanner_results():
            status = result["status"]
            if status == ScannerStatus.SKIPPED:
                reason = result["skipped_reason"] or result["missing_reason"]
            elif status == ScannerStatus.MISSING:
                reason = result["missing_reason"] or result["skipped_reason"]
            elif status == ScannerStatus.ERROR:
                if stale is None:
                    stale = scanners_in_error_for_a_stale_database(self.model)
                if result["scanner_name"] in stale:
                    continue
                reason = self._error_reason(result)
            else:
                continue
            if not reason:
                continue
            group = groups.setdefault(
                (status, str(reason)),
                {"scanners": [], "status": status, "reason": str(reason)},
            )
            group["scanners"].append(result["scanner_name"])
        return list(groups.values())

    def _error_reason(self, result: Dict[str, Any]) -> Optional[str]:
        """The short reason an ERROR scanner is listed with, or None.

        *result* is the scanner's row of :meth:`get_scanner_results`. Its recorded
        ``error_reason`` is shown when it is still a short reason: this is where a
        results file's text first reaches a reader, so it is held to the rule the
        scan phase writes by (``utils/short_reason.py``) here too, and a recorded
        sentence that names a local path, or is not one printable line, is not
        shown. Otherwise the first sentence of the first error the scanner's
        reports record, which is how a results file written before reasons were
        recorded is read, and an error nobody gave a reason.
        """
        recorded = result.get("error_reason")
        if is_short_reason(recorded):
            return str(recorded).strip()
        return self._first_error_sentence(result["scanner_name"])

    def _first_error_sentence(self, scanner_name: str) -> Optional[str]:
        """The short reason of the first error the scanner's reports record.

        Read by ``recorded_error_sentence``, the reading the unified metrics decide
        on: the scanner's own reports in the order ``recorded_error`` reads them,
        each one's own ``errors`` and then the ``errors`` of its ``raw_results``,
        which is where the executor also leaves the failure it recorded. The
        metrics leave an ERROR row's ``error_reason`` empty when this has a
        sentence, so the counts do not take its place; the report and the row agree
        on which of the two a scanner has.
        """
        return recorded_error_sentence(self.model, scanner_name)

    def get_scan_summary(self) -> Dict[str, Any]:
        """Describe the outcome for people without changing the scan's exit policy.

        A zero finding count is not a clean scan when no scanner completed, a
        dependency is missing, a target failed, or a content database is stale.
        Keep those conditions visible in every human-readable report.
        """
        from automated_security_helper.core.unified_metrics import coverage_shortfalls
        from automated_security_helper.utils.content_db_staleness import (
            scanners_in_error_for_a_stale_database,
            stale_content_databases,
        )
        from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_skipped_rows import (
            skipped_projects,
        )
        from automated_security_helper.interactions.run_ash_scan import (
            scan_incompleteness,
        )

        results = self.get_scanner_results()
        # A scanner recorded ERROR only because a content database the policy
        # rejects gave a clean result did run and reach an answer; that ERROR is
        # the stale database, reported under its own heading with its refresh
        # advice. The exit code and the console count such a scanner as having
        # run (scan_incompleteness drops its row), so the summary does too:
        # otherwise a run whose one scanner was stale read "No scanners
        # completed" and listed it as needing attention beside the notice that
        # already named it.
        ran_against_stale = scanners_in_error_for_a_stale_database(self.model)
        shortfalls = coverage_shortfalls(self.model)
        # A scanner that evaluated SOME of its targets (a partial loss, real
        # counts, failed below attempted) ran. Its status can still read ERROR when
        # one of its target reports errored, and the status alone then counted it
        # as not completed and listed it as needing attention beside the
        # "Incomplete coverage" row that already names it with its counts.
        # Unknown-size and total-loss shortfalls stay as they were: nothing there
        # says any target was evaluated.
        partial_scanners = {
            name
            for name, attempted, failed in shortfalls
            if attempted is not None and failed is not None and failed < attempted
        }

        def ran(result: Dict[str, Any]) -> bool:
            return result["status"] in (
                ScannerStatus.PASSED,
                ScannerStatus.FAILED,
            ) or (
                result["status"] == ScannerStatus.ERROR
                and (
                    result["scanner_name"] in ran_against_stale
                    or result["scanner_name"] in partial_scanners
                )
            )

        counts = {
            level: sum(result[level] for result in results)
            for level in SEVERITY_COUNT_KEYS
        }
        actionable = sum(result["actionable"] for result in results)
        suppressed = sum(result["suppressed"] for result in results)
        # A FAILED row is a scanner the resolver graded as carrying findings at
        # or above its threshold; the "Review required" title reads it below so
        # a run whose rows fail reads as such even when the counts disagree.
        rows_failed = any(
            result["status"] == ScannerStatus.FAILED for result in results
        )
        workspace = is_workspace_scan(self.model)
        # Every finding is graded once, into one frame the counts below read.
        # Whether a row's actionable grading is read depends on the branch: a
        # workspace scan recounts every finding, a scan with no scanner rows
        # counts every finding, and otherwise only the findings an additional
        # report lists are counted beside the scanner rows. A row nobody reads
        # is left ungraded (null), so no hook runs for it.
        in_extras = [False] * len(self.flat_vulns)
        if results:
            extra_ids = {id(vuln) for vuln in self._additional_report_findings()}
            in_extras = [id(vuln) in extra_ids for vuln in self.flat_vulns]
        every = self._graded_frame(
            self.flat_vulns,
            grade_actionable=(
                [True] * len(self.flat_vulns) if workspace or not results else in_extras
            ),
        )
        if workspace:
            # The scanner rows grade each finding by the scanner resolver's
            # answer, which with the merged file's missing ash_config is ASH's
            # default for every project. The cards, the hotspots and the
            # "Showing N of M" notes grade by the project's recorded gate
            # (is_finding_actionable), so a headline summed from the rows could
            # name one count while the cards below it showed another. The
            # headline counts the findings as the cards do.
            actionable = flag_total(every, "actionable")
            # The rows' FAILED status is that same resolver grading, so it
            # cannot decide the title here either: a project whose recorded
            # gate is stricter than ASH's default (HIGH, with one MEDIUM
            # finding) has a FAILED bandit row and a recount of 0, and reading
            # the row made the headline "Review required" over "0 findings at
            # or above the configured scanner thresholds". The title follows
            # the recount, the one grading the whole document shares.
            rows_failed = False
        if not results:
            # Imported SARIF can contain findings without execution metadata.
            # Count those findings while making no completion claim.
            counts = dict.fromkeys(counts, 0)
            _add_level_counts(counts, every)
            actionable = flag_total(every, "actionable")
            suppressed = flag_total(every, "is_suppressed")
        else:
            # The scanner rows count SARIF results. Findings an additional
            # report lists (a plugin's own list of finding dicts) reach the
            # cards and the hotspots, and a headline that left them out read
            # "No actionable findings" above cards marked Actionable.
            extras = every.filter(pl.Series(in_extras, dtype=pl.Boolean))
            _add_level_counts(counts, extras)
            suppressed += flag_total(extras, "is_suppressed")
            if not workspace:
                # A workspace scan counted every finding above, these included.
                actionable += flag_total(extras, "actionable")
        completed = sum(ran(result) for result in results)
        skipped = sum(result["status"] == ScannerStatus.SKIPPED for result in results)
        unavailable = [
            result["scanner_name"]
            for result in results
            if result["status"] != ScannerStatus.SKIPPED and not ran(result)
        ]
        stale = stale_content_databases(self.model)
        # A project skipped as no-changes was examined: nothing under it changed,
        # which is a successful no-op the workspace exit code treats as clean. Only
        # a project skipped by an error is coverage the scan did not have.
        skipped_workspace = [
            entry for entry in skipped_projects(self.model) if entry.reason.is_error
        ]
        coverage = scan_incompleteness(self.model, gate=True)
        shortfall_scanners = {name for name, _, _ in shortfalls}
        unavailable.extend(
            name
            for name, _ in coverage.scanners
            if name not in unavailable and name not in shortfall_scanners
        )
        # A scanner that ran can still be named for attention (a FAILED scanner
        # missing a dependency on one tree); it is counted as completed, so the
        # masthead's unavailable figure leaves it out, or completed, disabled
        # and unavailable would add up to more than the scanners there are.
        completed_names = {result["scanner_name"] for result in results if ran(result)}
        unavailable_count = sum(name not in completed_names for name in unavailable)
        active = sum(counts.values())
        # Policy-scanner findings the project's outcome left out are counted
        # apart: they are active, not actionable, and not below any threshold.
        policy_not_gating = flag_total(every, "left_out")
        # A tool ASH could not stop fails the run whatever the gate says, and it
        # may still be writing into the output directory after this report is
        # rendered, so the report is not final. The exit code reads it from the
        # same ScanIncompleteness; a summary that ignored it read "No actionable
        # findings" for a run that exits 1.
        could_not_stop = list(coverage.could_not_stop)
        incomplete = bool(
            unavailable
            or shortfalls
            or skipped_workspace
            or coverage.converters
            or coverage.unevaluated_rules
            or coverage.no_scanner_ran
            or could_not_stop
        )
        finding_label = "finding" if actionable == 1 else "findings"
        # A coverage gap is a warning, but not when findings at the gate are also
        # on the page: the run fails on them, and a warning tone read as the
        # lesser of the two. The gate is read as the title reads it (the
        # recount, and the rows' FAILED status only outside a workspace), so a
        # project gated above ASH's default does not turn its gap into a danger.
        gap_tone = (
            OutcomeTone.DANGER if actionable or rows_failed else OutcomeTone.WARNING
        )

        if not completed:
            title, tone = "No scanners completed", OutcomeTone.WARNING
            description = "Scanner coverage is unavailable."
            next_step = (
                "Check scanner results and dependencies, then run the scan again."
            )
        elif could_not_stop:
            title, tone = "Scan incomplete", gap_tone
            description = (
                f"{actionable} actionable {finding_label}. A scanner tool could not be "
                "stopped and may still be writing, so this report may not be final."
            )
            next_step = "Stop the named tool, then run the scan again."
        elif incomplete:
            title, tone = "Scan incomplete", gap_tone
            description = f"{actionable} actionable {finding_label}. Some inputs or scanners were not evaluated."
            next_step = "Review findings, resolve coverage gaps, and scan again."
        elif stale:
            title, tone = "Scan needs attention", gap_tone
            description = f"{actionable} actionable {finding_label}. Content database freshness needs review."
            next_step = "Review the database notices, refresh the affected scanners, and scan again."
        elif actionable or rows_failed:
            title, tone = "Review required", OutcomeTone.DANGER
            description = f"{actionable} {finding_label} at or above the configured scanner thresholds."
            next_step = "Review findings by severity, then inspect the source."
        else:
            title, tone = "No actionable findings", OutcomeTone.SUCCESS
            if policy_not_gating:
                # A finding the workspace policy added, in a project whose
                # policy_scanners_gate is off, can sit above the threshold and
                # still decide nothing. The sentence below would deny it exists
                # beside the "Not gating" figure, so say what was left out.
                policy_noun = "finding is" if policy_not_gating == 1 else "findings are"
                description = (
                    "Completed scanners reported no findings that count toward the "
                    f"outcome. {policy_not_gating} workspace-policy {policy_noun} "
                    "reported and left out of it because policy_scanners_gate is off."
                )
                next_step = (
                    "Review the workspace-policy findings left out of the outcome, "
                    "then scanner coverage and findings below the threshold."
                )
            else:
                description = "Completed scanners reported no findings at or above their configured thresholds."
                next_step = "Review scanner coverage and findings below the threshold."

        summary = {
            "title": title,
            "tone": tone.value,
            "description": description,
            "next_step": next_step,
            SUMMARY_ACTIONABLE: actionable,
            "active": active,
            SUMMARY_BELOW_THRESHOLD: max(0, active - actionable - policy_not_gating),
            SUMMARY_POLICY_NOT_GATING: policy_not_gating,
            SUMMARY_SUPPRESSED: suppressed,
            "counts": counts,
            "completed": completed,
            "scanners": len(results),
            "skipped": skipped,
            "unavailable": unavailable,
            # How many of those did not complete: the figure for a count of
            # scanners, where the list above is for naming them.
            "unavailable_count": unavailable_count,
            "shortfalls": shortfalls,
            "stale": stale,
            "converter_gaps": coverage.converters,
            "unevaluated_rules": coverage.unevaluated_rules,
            # (scanner, reason) rows, the reason naming the process id.
            "could_not_stop": could_not_stop,
        }
        if self.fold:
            # Beside the figures above, which stay as the scanners counted them.
            summary["deduplicated"] = self._deduplicated_counts()
        return summary

    def _graded_frame(
        self,
        vulns: List[FlatVulnerability],
        *,
        grade_actionable: Sequence[bool] | None = None,
    ) -> pl.DataFrame:
        """The findings as a frame of severity bucket and yes/no gradings.

        Each finding's grading is one lookup against the model's recorded
        gates (:meth:`is_finding_actionable`, :meth:`is_policy_not_gating`),
        made here row by row; the counting over the result is the frame's.
        ``grade_actionable`` names, one flag per finding, the rows whose
        actionable grading the caller reads: the others are left null, since
        the threshold lookup costs a call per finding. Every grading enters the
        frame through ``bool``, as the suppression flag does, because a hook
        that answers 1 or 0 is not a Boolean cell to the frame.
        """
        return graded_frame(
            levels=[_severity_level(vuln.severity) for vuln in vulns],
            is_suppressed=[bool(vuln.is_suppressed) for vuln in vulns],
            left_out=[bool(self.is_policy_not_gating(vuln)) for vuln in vulns],
            actionable=(
                None
                if grade_actionable is None
                else [
                    bool(self.is_finding_actionable(vuln)) if grade else None
                    for vuln, grade in zip(vulns, grade_actionable, strict=True)
                ]
            ),
        )

    def _additional_report_findings(self) -> List[FlatVulnerability]:
        """The flattened findings that came from list-form additional reports.

        The scanner rows count SARIF results only, so these are the findings a
        row-based summary does not see. Each is read by the ``source_report``
        the flattening marks it with (the key of the additional report it was
        listed under), wherever it sits in the list; a row with no marker is a
        SARIF result. The reading by position and count that preceded the
        marker is gone: it took a SARIF row of the same scanner that sat in the
        tail for a listed finding, and dropped a listed finding that did not.
        """
        reports = self.model.additional_reports
        names = {name for name, found in reports.items() if isinstance(found, list)}
        if not names:
            return []
        return [
            vuln
            for vuln in self.flat_vulns
            if getattr(vuln, "source_report", None) in names
        ]

    def get_top_hotspots(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top hotspots (files with most findings)."""
        if not self.flat_vulns:
            return []

        # Count findings by file location, but only include actionable findings
        actionable, _ = self.fold_findings(
            [vuln for vuln in self.flat_vulns if self.is_finding_actionable(vuln)]
        )
        locations = [vuln.file_path for vuln in actionable if vuln.file_path]
        return [
            {"location": location, "count": count}
            for location, count in top_locations(locations, limit)
        ]

    def is_finding_actionable(self, vuln: FlatVulnerability) -> bool:
        """Determine if a finding is actionable based on severity threshold."""
        # If finding is suppressed, it's not actionable
        if vuln.is_suppressed:
            return False

        # Get scanner name
        scanner_name = vuln.scanner or "Unknown"

        # A finding from a scanner only the workspace policy added, in a project
        # whose policy_scanners_gate is off, is reported and left out of that
        # project's outcome, so it is not actionable here either. It is not
        # below the threshold either: see is_policy_not_gating.
        if self.is_policy_not_gating(vuln):
            return False

        threshold = self._threshold_for(vuln.workspace_project, scanner_name)

        # Get the severity of the finding
        severity = vuln.severity or "UNKNOWN"

        # Determine if the finding is actionable based on the threshold
        return self._is_severity_actionable(severity, threshold)

    def is_policy_not_gating(self, vuln: FlatVulnerability) -> bool:
        """Whether *vuln* is reported but left out of its project's outcome.

        A finding of a scanner only the workspace policy added, in a project
        whose ``policy_scanners_gate`` is off. Such a finding is not actionable,
        and it is not "below threshold" either: its severity may be CRITICAL,
        and it is left out because of where it came from, not how severe it is.
        A report that filed it under "Below threshold" hid it from the default
        view and counted it with the low-severity findings the threshold exists
        to set aside, where the merged JUnit report gives it its own skip type.
        The reports show it under its own status and count it apart.
        """
        if vuln.is_suppressed:
            return False
        return (
            vuln.workspace_project in self._policy_not_gating
            and self._is_policy_origin_finding(vuln)
        )

    def disposition(self, vuln: FlatVulnerability) -> Disposition:
        """What the report does with *vuln*: the one answer the cards show.

        In the order the gates are asked: suppressed first, then left out of
        the project's outcome by where it came from, then actionable, and
        what remains is below the threshold.
        """
        if vuln.is_suppressed:
            return Disposition.SUPPRESSED
        if self.is_policy_not_gating(vuln):
            return Disposition.POLICY_NOT_GATING
        if self.is_finding_actionable(vuln):
            return Disposition.ACTIONABLE
        return Disposition.BELOW_THRESHOLD

    def _threshold_for(self, project: str | None, scanner_name: str) -> str:
        """The gate a finding of *scanner_name* in *project* is graded by.

        The gate the finding's own outcome used. In a workspace the merged
        results carry no ash_config, so the scanner resolver answers ASH's
        default for every project; each project's record carries the gate
        threshold its outcome was judged against, and a finding attributed to
        a project is graded by that, as the project's outcome and the exit
        code graded it. A single-directory scan reads the scanner's threshold
        from the recorded configuration, as before. Within a project the
        scanner's own recorded gate comes first, then the project's gate: the
        order the project's outcome and the merged JUnit report resolve them
        in, so a scanner the project tightened, relaxed or withheld is graded
        here as it was there.

        Answered once per (project, scanner): the resolver dumps the whole
        scanners section on every call, and the summary, the hotspots, the
        cards and the detailed findings each grade every finding. The recorded
        tables are read once at construction, so the pair is all the answer
        depends on.
        """
        key = (project, scanner_name)
        if key not in self._threshold_cache:
            threshold = None
            if project:
                threshold = self._project_scanner_thresholds.get(project, {}).get(
                    scanner_name
                )
                if threshold is None:
                    threshold = self._project_thresholds.get(project)
            if threshold is None:
                threshold, _ = ScannerStatisticsCalculator.get_scanner_threshold_info(
                    self.model, scanner_name
                )
            self._threshold_cache[key] = threshold
        return self._threshold_cache[key]

    @staticmethod
    def _is_policy_origin_finding(vuln: FlatVulnerability) -> bool:
        """Whether *vuln*'s recorded properties mark it policy-origin.

        Read from the flattened finding's property bag, as the project's outcome
        reads the result's: the ``origin`` property alone, never a tag.
        """
        recorded = getattr(vuln, "properties", None)
        if not recorded:
            return False
        try:
            properties = json.loads(recorded)
        except (TypeError, ValueError):
            return False
        return is_policy_origin(properties)

    def _is_severity_actionable(self, severity: str, threshold: str) -> bool:
        """Whether a finding of *severity* is actionable under *threshold*.

        The gate's own comparison (``utils.severity_ladder``), which fails
        closed on a severity it does not recognise: such a finding fails every
        configured threshold. This method used to map an unrecognised severity
        (and ``UNKNOWN``) onto the INFO count, or onto nothing, so a finding the
        exit code failed the scan for was labelled "Below threshold" and hidden
        by the default view of the HTML report.
        """
        return severity_fails_threshold(severity, threshold)

    @staticmethod
    def _overview_row(vuln: FlatVulnerability) -> Dict[str, Any]:
        """The row of a findings table for *vuln*."""
        return {
            "severity": vuln.severity or "UNKNOWN",
            "scanner": vuln.scanner or "Unknown",
            "rule_id": vuln.rule_id or "N/A",
            "title": vuln.title or "Unknown Issue",
            "file_path": vuln.file_path or "N/A",
        }

    @staticmethod
    def _severity_sort_key(vuln: FlatVulnerability) -> tuple[Any, ...]:
        """Most severe first, then by file, line and rule."""
        return (
            _SEVERITY_ORDER.get(str(vuln.severity).upper(), _UNLISTED_SEVERITY_PLACE),
            vuln.file_path or "",
            vuln.line_start or 0,
            vuln.rule_id or "",
        )

    @classmethod
    def by_severity(
        cls,
        vulns: List[FlatVulnerability],
        *,
        suppressed: Sequence[bool] | None = None,
    ) -> List[FlatVulnerability]:
        """*vulns* most severe first; findings equal on every key keep their order.

        With *suppressed*, one flag per finding, the unsuppressed ones come
        first (the HTML cards' order); each group is ordered as above. The line
        in each key is ``line_start or 0``, always an int, which the frame
        ordering needs.
        """
        return [
            vulns[position]
            for position in severity_order(
                [cls._severity_sort_key(v) for v in vulns], suppressed
            )
        ]

    def get_findings_overview(self) -> List[Dict[str, Any]]:
        """Get overview of all findings."""
        shown, notes = self.fold_findings(self.flat_vulns)
        return [
            self._with_note(self._overview_row(vuln), vuln, notes) for vuln in shown
        ]

    @staticmethod
    def _with_note(
        row: Dict[str, Any], vuln: FlatVulnerability, notes: Dict[int, str]
    ) -> Dict[str, Any]:
        """*row* with the fold's note under ``duplicate_note`` when *vuln* has one.

        A row with no note is returned as it is, so with the fold off no row has
        the key.
        """
        note = notes.get(id(vuln))
        if note:
            row["duplicate_note"] = note
        return row

    def get_detailed_findings(self, max_findings: int = 20) -> List[Dict[str, Any]]:
        """Get detailed information for actionable findings, limited to max_findings."""
        if not self.flat_vulns:
            return []

        # Filter to only include actionable findings
        actionable_findings = [
            vuln for vuln in self.flat_vulns if self.is_finding_actionable(vuln)
        ]
        actionable_findings, notes = self.fold_findings(actionable_findings)

        # Limit the number of detailed findings
        actionable_findings = self.by_severity(actionable_findings)
        # A negative limit would slice from the end and drop the last findings
        # instead of none; the reporters refuse one, and a caller that passes
        # one anyway gets none.
        findings_to_show = actionable_findings[: max(max_findings, 0)]

        return [
            self._with_note(self._create_detailed_finding(vuln), vuln, notes)
            for vuln in findings_to_show
        ]

    def get_policy_not_gating_findings(
        self, max_findings: int = 20
    ) -> List[Dict[str, Any]]:
        """The findings reported and left out of their project's outcome.

        The rows of :meth:`get_findings_overview` for the findings
        :meth:`is_policy_not_gating` names, most severe first, limited to
        *max_findings*. :meth:`get_detailed_findings` lists the actionable
        findings only, so without this list a report that counts these findings
        in its summary names none of them.
        """
        left_out = [vuln for vuln in self.flat_vulns if self.is_policy_not_gating(vuln)]
        left_out, notes = self.fold_findings(left_out)
        left_out = self.by_severity(left_out)
        return [
            self._with_note(self._overview_row(vuln), vuln, notes)
            for vuln in left_out[: max(max_findings, 0)]
        ]

    def _create_detailed_finding(self, vuln: FlatVulnerability) -> Dict[str, Any]:
        """Create a detailed finding dictionary from a vulnerability."""
        # Format location
        location = vuln.file_path or "N/A"
        if vuln.file_path and vuln.line_start:
            location += f":{vuln.line_start}"
            if vuln.line_end and vuln.line_end != vuln.line_start:
                location += f"-{vuln.line_end}"

        # Get code snippet
        code_snippet = self._extract_code_snippet(vuln)

        # Create finding dictionary
        return {
            "title": vuln.title or "Unknown Issue",
            "severity": vuln.severity or "UNKNOWN",
            "scanner": vuln.scanner or "Unknown",
            "rule_id": vuln.rule_id or "N/A",
            "location": location,
            "description": vuln.description or "",
            "cve_id": vuln.cve_id,
            "cwe_id": vuln.cwe_id,
            "code_snippet": code_snippet,
        }

    def _extract_code_snippet(self, vuln: FlatVulnerability) -> str | None:
        """Extract code snippet from a vulnerability.

        Returns text or None, never another type: the raw data is a scanner's
        own report, and a ``snippet`` there can be an object (SARIF's
        ``artifactContent``, with ``text`` inside) or anything else the scanner
        wrote. The Markdown renderer passes the snippet to the shown-text
        helpers, which take a string, so a non-string snippet raised TypeError
        and lost the whole report.
        """
        # Use the code_snippet field if available
        if vuln.code_snippet:
            return vuln.code_snippet

        # If no snippet is directly available, try to extract from raw data
        if not vuln.raw_data:
            return None

        try:
            raw_data = json.loads(vuln.raw_data)
            if not isinstance(raw_data, dict):
                return None

            # Try to find snippet in common locations. A ``snippet`` key with
            # no text in it (an empty object, a number) ends nothing: the
            # locations and the code flows below may still carry the text.
            found = _snippet_text(raw_data.get("snippet"))
            if found:
                return found

            # SARIF puts a snippet in a location's physicalLocation, under its
            # context region (or its region), never on the result or on a
            # thread-flow location itself.
            locations = raw_data.get("locations")
            if isinstance(locations, list):
                for location in locations:
                    found = _location_snippet(location)
                    if found:
                        return found

            # Check in code flows
            if "codeFlows" in raw_data and raw_data["codeFlows"]:
                for flow in raw_data["codeFlows"]:
                    if "threadFlows" in flow and flow["threadFlows"]:
                        for thread in flow["threadFlows"]:
                            if "locations" in thread and thread["locations"]:
                                for loc in thread["locations"]:
                                    found = _snippet_text(loc.get("snippet"))
                                    if found:
                                        return found
                                    # A thread-flow location wraps a SARIF
                                    # location: ``{"location": {...}}``.
                                    found = _location_snippet(loc.get("location"))
                                    if found:
                                        return found

            # Check in message: the same reader the flattener uses, so the
            # fence's info string (the language name) and the block's own
            # newlines are left out here as they are there. This branch's own
            # split returned the raw block, so a report built from a record
            # flattened without a snippet showed "python" as its first line.
            if "message" in raw_data and "text" in raw_data["message"]:
                message_text = raw_data["message"]["text"]
                if isinstance(message_text, str):
                    return _extract_snippet_from_message(message_text)

        except (json.JSONDecodeError, AttributeError, KeyError, TypeError):
            # If we can't parse the raw data or find a snippet, return None
            pass

        return None


def _location_snippet(location: Any) -> str | None:
    """The snippet text of a SARIF location object, or None.

    Read from ``physicalLocation.contextRegion.snippet`` and then
    ``physicalLocation.region.snippet``, where SARIF 2.1.0 puts it: the order the
    flattener reads the first location's snippet in, because the context region
    exists to give a viewer the surrounding lines. A secret finding's snippets
    are masked whole in every one of its locations (``secret_masking`` masks the
    physical locations of its locations, related locations and code flows) before
    any reporter runs, so what is read here is already the masked text.
    """
    if not isinstance(location, dict):
        return None
    physical = location.get("physicalLocation")
    if not isinstance(physical, dict):
        return None
    for key in ("contextRegion", "region"):
        region = physical.get(key)
        if isinstance(region, dict):
            text = _snippet_text(region.get("snippet"))
            if text:
                return text
    return None


def _snippet_text(snippet: Any) -> str | None:
    """The text of a raw ``snippet`` value: a string as it is, an object's
    ``text`` when that is a string, otherwise None."""
    if isinstance(snippet, str):
        return snippet
    if isinstance(snippet, dict):
        text = snippet.get("text")
        return text if isinstance(text, str) else None
    return None


#: The longest reason shown; a longer first sentence is not a short reason. The
#: limit, and the rest of the check ``short_error_reason`` makes (one printable
#: line, no local path), are the ones a scanner's recorded reason is held to
#: (``utils/short_reason.py``, where ``short_error_reason`` lives since the unified
#: metrics read it too; it is imported above and so still comes from this module).
SHORT_ERROR_REASON_LIMIT = SHORT_REASON_LIMIT
