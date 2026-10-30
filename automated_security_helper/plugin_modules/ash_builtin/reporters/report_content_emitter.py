# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime, timedelta, timezone
import json
import re
from typing import Dict, List, Any, TYPE_CHECKING

from automated_security_helper.models.flat_vulnerability import (
    FlatVulnerability,
    _extract_snippet_from_message,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.core.unified_metrics import get_unified_scanner_metrics
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.core.constants import ASH_DEFAULT_SEVERITY_LEVEL
from automated_security_helper.models.workspace import is_workspace_scan
from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_section import (
    workspace_project_thresholds,
)
from automated_security_helper.utils.severity_ladder import severity_fails_threshold
from collections import Counter


def coverage_shortfall_text(attempted: int | None, failed: int | None) -> str:
    """The sentence after a scanner's name in an "Incomplete coverage" row.

    One renderer for the HTML, Markdown and text reports, because the three
    each computed ``attempted - failed`` inline, and ``coverage_shortfalls``
    yields ``(name, None, None)`` for a scanner whose stored target counters
    could not be read. Each report then raised TypeError on that row and the
    whole document was lost, for the one scanner whose coverage most needs
    stating. The console renderer already printed "unknown" for it; this is
    the same reading for the files.
    """
    if attempted is None or failed is None:
        return (
            "coverage unknown; its recorded target counters could not be read, "
            "so how many targets it evaluated is not known"
        )
    # A record whose failed count exceeds its attempted count is inconsistent;
    # the evaluated count is never printed below zero.
    return (
        f"evaluated {max(attempted - failed, 0)} of {attempted} target(s); "
        f"{failed} could not be evaluated"
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


def _count_severity(counts: Dict[str, int], severity: Any) -> None:
    """Count one finding under its severity's bucket.

    The buckets are ASH's five levels. A finding rated outside them (a plugin's
    own list can carry any text) is counted under ``unknown``, a bucket that
    exists only while such a finding does: the gate fails closed on it, so it
    is actionable, and a count that dropped it read more actionable findings
    than active ones and clamped the below-threshold figure to zero.
    """
    level = str(severity or "").lower()
    if level not in counts and level != "unknown":
        level = "unknown"
    counts[level] = counts.get(level, 0) + 1


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
        # Each project's recorded gate, read once: is_finding_actionable runs
        # several times per finding (summary, hotspots, cards, detailed
        # findings), and the project list is scanned here instead of there.
        self._project_thresholds = workspace_project_thresholds(model)

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
                "SKIPPED",
                "MISSING",
            )
            unrecorded = (
                self._human_presentation
                and durations_unrecorded
                and not metrics.duration
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
            return result["status"] in ("PASSED", "FAILED") or (
                result["status"] == "ERROR"
                and (
                    result["scanner_name"] in ran_against_stale
                    or result["scanner_name"] in partial_scanners
                )
            )

        counts = {
            level: sum(result[level] for result in results)
            for level in ("critical", "high", "medium", "low", "info")
        }
        actionable = sum(result["actionable"] for result in results)
        suppressed = sum(result["suppressed"] for result in results)
        # A FAILED row is a scanner the resolver graded as carrying findings at
        # or above its threshold; the "Review required" title reads it below so
        # a run whose rows fail reads as such even when the counts disagree.
        rows_failed = any(result["status"] == "FAILED" for result in results)
        if is_workspace_scan(self.model):
            # The scanner rows grade each finding by the scanner resolver's
            # answer, which with the merged file's missing ash_config is ASH's
            # default for every project. The cards, the hotspots and the
            # "Showing N of M" notes grade by the project's recorded gate
            # (is_finding_actionable), so a headline summed from the rows could
            # name one count while the cards below it showed another. The
            # headline counts the findings as the cards do.
            actionable = sum(
                self.is_finding_actionable(vuln) for vuln in self.flat_vulns
            )
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
            for vuln in self.flat_vulns:
                if not vuln.is_suppressed:
                    _count_severity(counts, vuln.severity)
            actionable = sum(
                self.is_finding_actionable(vuln) for vuln in self.flat_vulns
            )
            suppressed = sum(vuln.is_suppressed for vuln in self.flat_vulns)
        else:
            # The scanner rows count SARIF results. Findings an additional
            # report lists (a plugin's own list of finding dicts) reach the
            # cards and the hotspots, and a headline that left them out read
            # "No actionable findings" above cards marked Actionable.
            extras = self._additional_report_findings()
            for vuln in extras:
                if vuln.is_suppressed:
                    suppressed += 1
                else:
                    _count_severity(counts, vuln.severity)
            if not is_workspace_scan(self.model):
                # A workspace scan counted every finding above, these included.
                actionable += sum(self.is_finding_actionable(vuln) for vuln in extras)
        completed = sum(ran(result) for result in results)
        skipped = sum(result["status"] == "SKIPPED" for result in results)
        unavailable = [
            result["scanner_name"]
            for result in results
            if result["status"] != "SKIPPED" and not ran(result)
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
        gap_tone = "danger" if actionable or rows_failed else "warning"

        if not completed:
            title, tone = "No scanners completed", "warning"
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
            title, tone = "Review required", "danger"
            description = f"{actionable} {finding_label} at or above the configured scanner thresholds."
            next_step = "Review findings by severity, then inspect the source."
        else:
            title, tone = "No actionable findings", "success"
            description = "Completed scanners reported no findings at or above their configured thresholds."
            next_step = "Review scanner coverage and findings below the threshold."

        return {
            "title": title,
            "tone": tone,
            "description": description,
            "next_step": next_step,
            "actionable": actionable,
            "active": active,
            "below_threshold": max(0, active - actionable),
            "suppressed": suppressed,
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

    def _additional_report_findings(self) -> List[FlatVulnerability]:
        """The flattened findings that came from list-form additional reports.

        The scanner rows count SARIF results only, so these are the findings a
        row-based summary does not see. A row the flattening marks with
        ``source_report`` (the key of the additional report it was listed
        under; None for a SARIF result) is read by that key wherever it sits.
        Rows without the marker are read as ``to_flat_vulnerabilities`` laid
        them out: appended after the SARIF results, one per dict in a scanner's
        list.
        """
        reports = self.model.additional_reports
        names = {name for name, found in reports.items() if isinstance(found, list)}
        if not names:
            return []
        if any(hasattr(vuln, "source_report") for vuln in self.flat_vulns):
            return [
                vuln
                for vuln in self.flat_vulns
                if getattr(vuln, "source_report", None) in names
            ]
        count = sum(
            1 for name in names for entry in reports[name] if isinstance(entry, dict)
        )
        if not count:
            return []
        tail = self.flat_vulns[-count:]
        if len(tail) != count or any(vuln.scanner not in names for vuln in tail):
            return []
        return tail

    def get_top_hotspots(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top hotspots (files with most findings)."""
        if not self.flat_vulns:
            return []

        # Count findings by file location, but only include actionable findings
        location_counts = Counter()
        for vuln in self.flat_vulns:
            # Check if the finding is actionable based on severity threshold
            if vuln.file_path and self.is_finding_actionable(vuln):
                location_counts[vuln.file_path] += 1

        # Get top hotspots
        top_hotspots = location_counts.most_common(limit)

        return [
            {"location": location, "count": count} for location, count in top_hotspots
        ]

    def is_finding_actionable(self, vuln: FlatVulnerability) -> bool:
        """Determine if a finding is actionable based on severity threshold."""
        # If finding is suppressed, it's not actionable
        if vuln.is_suppressed:
            return False

        # Get scanner name
        scanner_name = vuln.scanner or "Unknown"

        # The gate the finding's own outcome used. In a workspace the merged
        # results carry no ash_config, so the scanner resolver answers ASH's
        # default for every project; each project's record carries the gate
        # threshold its outcome was judged against, and a finding attributed to
        # a project is graded by that, as the project's outcome and the exit
        # code graded it. A single-directory scan reads the scanner's threshold
        # from the recorded configuration, as before.
        threshold = None
        if vuln.workspace_project:
            threshold = self._project_thresholds.get(vuln.workspace_project)
        if threshold is None:
            threshold, _ = ScannerStatisticsCalculator.get_scanner_threshold_info(
                self.model, scanner_name
            )

        # Get the severity of the finding
        severity = vuln.severity or "UNKNOWN"

        # Determine if the finding is actionable based on the threshold
        return self._is_severity_actionable(severity, threshold)

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

    def get_findings_overview(self) -> List[Dict[str, Any]]:
        """Get overview of all findings."""
        findings = []
        for vuln in self.flat_vulns:
            findings.append(
                {
                    "severity": vuln.severity or "UNKNOWN",
                    "scanner": vuln.scanner or "Unknown",
                    "rule_id": vuln.rule_id or "N/A",
                    "title": vuln.title or "Unknown Issue",
                    "file_path": vuln.file_path or "N/A",
                }
            )
        return findings

    def get_detailed_findings(self, max_findings: int = 20) -> List[Dict[str, Any]]:
        """Get detailed information for actionable findings, limited to max_findings."""
        if not self.flat_vulns:
            return []

        # Filter to only include actionable findings
        actionable_findings = [
            vuln for vuln in self.flat_vulns if self.is_finding_actionable(vuln)
        ]

        # Limit the number of detailed findings
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        actionable_findings.sort(
            key=lambda vuln: (
                severity_order.get(str(vuln.severity).upper(), 5),
                vuln.file_path or "",
                vuln.line_start or 0,
                vuln.rule_id or "",
            )
        )
        # A negative limit would slice from the end and drop the last findings
        # instead of none; the reporters refuse one, and a caller that passes
        # one anyway gets none.
        findings_to_show = actionable_findings[: max(max_findings, 0)]

        return [self._create_detailed_finding(vuln) for vuln in findings_to_show]

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

            # Try to find snippet in common locations
            if "snippet" in raw_data:
                return _snippet_text(raw_data["snippet"])

            # SARIF puts a snippet in a location's physicalLocation, under its
            # region (or its context region), never on the result or on a
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
                                    if "snippet" in loc:
                                        return _snippet_text(loc["snippet"])
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

    Read from ``physicalLocation.region.snippet`` and then
    ``physicalLocation.contextRegion.snippet``, where SARIF 2.1.0 puts it.
    """
    if not isinstance(location, dict):
        return None
    physical = location.get("physicalLocation")
    if not isinstance(physical, dict):
        return None
    for key in ("region", "contextRegion"):
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
