# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime, timezone
import json
from typing import Dict, List, Any, TYPE_CHECKING

from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.core.unified_metrics import get_unified_scanner_metrics
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.core.constants import ASH_DEFAULT_SEVERITY_LEVEL
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
    return (
        f"evaluated {attempted - failed} of {attempted} target(s); "
        f"{failed} could not be evaluated"
    )


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
        """
        self.model = model
        self.flat_vulns = model.to_flat_vulnerabilities()
        if human_presentation:
            self.flat_vulns = [vuln.model_copy() for vuln in self.flat_vulns]
        self.ash_conf = model.ash_config

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
                # Strip timezone offset or fractional seconds from the
                # timestamp so strptime can parse the date/time portion.
                # Handles +HH:MM, -HH:MM, Z suffix, and .fractional seconds.
                import re as _re

                cleaned = scan_time_str
                # Remove trailing Z (Zulu/UTC indicator)
                cleaned = cleaned.rstrip("Z")
                # Remove timezone offset (+HH:MM or -HH:MM) at the end
                cleaned = _re.sub(r"[+-]\d{2}:\d{2}$", "", cleaned)
                # Remove fractional seconds
                cleaned = cleaned.split(".")[0]

                # Try to parse the scan time string to calculate delta
                # Handle different possible formats
                for fmt in [
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d - %H:%M (UTC)",
                    "%Y-%m-%d %H:%M:%S",
                ]:
                    try:
                        scan_time = datetime.strptime(cleaned, fmt)
                        if fmt != "%Y-%m-%d - %H:%M (UTC)":
                            scan_time = scan_time.replace(tzinfo=timezone.utc)
                        time_delta = current_time - scan_time
                        break
                    except ValueError:
                        continue
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
        for metrics in self.scanner_metrics:
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
                    # Seconds the scanner took, or None when it did not run. The
                    # text and html reporters render a Duration column from this
                    # key with format_duration(result.get("duration", 0)); while
                    # the key was missing that default made every row read "<1ms".
                    "duration": metrics.duration,
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

        def ran(result: Dict[str, Any]) -> bool:
            return result["status"] in ("PASSED", "FAILED") or (
                result["status"] == "ERROR"
                and result["scanner_name"] in ran_against_stale
            )

        counts = {
            level: sum(result[level] for result in results)
            for level in ("critical", "high", "medium", "low", "info")
        }
        actionable = sum(result["actionable"] for result in results)
        suppressed = sum(result["suppressed"] for result in results)
        if not results:
            # Imported SARIF can contain findings without execution metadata.
            # Count those findings while making no completion claim.
            counts = {
                level: sum(
                    not vuln.is_suppressed and vuln.severity.lower() == level
                    for vuln in self.flat_vulns
                )
                for level in counts
            }
            actionable = sum(
                self.is_finding_actionable(vuln) for vuln in self.flat_vulns
            )
            suppressed = sum(vuln.is_suppressed for vuln in self.flat_vulns)
        completed = sum(ran(result) for result in results)
        skipped = sum(result["status"] == "SKIPPED" for result in results)
        unavailable = [
            result["scanner_name"]
            for result in results
            if result["status"] != "SKIPPED" and not ran(result)
        ]
        shortfalls = coverage_shortfalls(self.model)
        stale = stale_content_databases(self.model)
        # A project skipped as no-changes was examined: nothing under it changed,
        # which is a successful no-op the workspace exit code treats as clean. Only
        # a project skipped by an error is coverage the scan did not have.
        skipped_workspace = [
            entry for entry in skipped_projects(self.model) if entry.reason.is_error
        ]
        coverage = scan_incompleteness(self.model, gate=True)
        partial_scanners = {name for name, _, _ in shortfalls}
        unavailable.extend(
            name
            for name, _ in coverage.scanners
            if name not in unavailable and name not in partial_scanners
        )
        active = sum(counts.values())
        incomplete = bool(
            unavailable
            or shortfalls
            or skipped_workspace
            or coverage.converters
            or coverage.unevaluated_rules
            or coverage.no_scanner_ran
        )
        finding_label = "finding" if actionable == 1 else "findings"

        if not completed:
            title, tone = "No scanners completed", "warning"
            description = "Scanner coverage is unavailable."
            next_step = (
                "Check scanner results and dependencies, then run the scan again."
            )
        elif incomplete:
            title, tone = "Scan incomplete", "warning"
            description = f"{actionable} actionable {finding_label}. Some inputs or scanners were not evaluated."
            next_step = "Review findings, resolve coverage gaps, and scan again."
        elif stale:
            title, tone = "Scan needs attention", "warning"
            description = f"{actionable} actionable {finding_label}. Content database freshness needs review."
            next_step = "Review the database notices, refresh the affected scanners, and scan again."
        elif actionable or any(result["status"] == "FAILED" for result in results):
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
            "shortfalls": shortfalls,
            "stale": stale,
            "converter_gaps": coverage.converters,
            "unevaluated_rules": coverage.unevaluated_rules,
        }

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

        from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_section import (
            workspace_project_threshold,
        )

        # Get scanner name
        scanner_name = vuln.scanner or "Unknown"

        # The gate the finding's own outcome used. In a workspace the merged
        # results carry no ash_config, so the scanner resolver answers ASH's
        # default for every project; each project's record carries the gate
        # threshold its outcome was judged against, and a finding attributed to
        # a project is graded by that, as the project's outcome and the exit
        # code graded it. A single-directory scan reads the scanner's threshold
        # from the recorded configuration, as before.
        threshold = workspace_project_threshold(self.model, vuln.workspace_project)
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
        findings_to_show = actionable_findings[:max_findings]

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

            # Check in code flows
            if "codeFlows" in raw_data and raw_data["codeFlows"]:
                for flow in raw_data["codeFlows"]:
                    if "threadFlows" in flow and flow["threadFlows"]:
                        for thread in flow["threadFlows"]:
                            if "locations" in thread and thread["locations"]:
                                for loc in thread["locations"]:
                                    if "snippet" in loc:
                                        return _snippet_text(loc["snippet"])

            # Check in message
            if "message" in raw_data and "text" in raw_data["message"]:
                message_text = raw_data["message"]["text"]
                if isinstance(message_text, str) and "```" in message_text:
                    parts = message_text.split("```")
                    if len(parts) >= 3:  # Has at least one code block
                        return parts[1]

        except (json.JSONDecodeError, AttributeError, KeyError, TypeError):
            # If we can't parse the raw data or find a snippet, return None
            pass

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
