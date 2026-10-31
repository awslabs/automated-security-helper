# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime, timezone
from typing import Literal, TYPE_CHECKING

from pydantic import field_validator

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_section import (
    text_workspace_section,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.utils.terminal_text import (
    commands_broken,
    shown_not_obeyed,
    shown_on_one_line,
)
from automated_security_helper.utils.ui_theme import FOOTER_CREDIT
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
    coverage_shortfall_text,
    refuse_negative_limit,
)
from automated_security_helper.utils.display_text import escape_controls
from automated_security_helper.core.unified_metrics import (
    format_duration,
    inputs_not_scanned,
)
from automated_security_helper.utils.content_db_staleness import (
    stale_content_databases,
)
from automated_security_helper.utils.converter_refusals import (
    converter_refusals,
    summary_lines,
)


class TextReporterConfigOptions(ReporterOptionsBase):
    """Configuration options for the Text reporter."""

    include_summary: bool = True
    include_findings_table: bool = False  # This can be lengthy, default to False
    include_detailed_findings: bool = False
    max_detailed_findings: int = (
        20  # Limit detailed findings to avoid overly large reports
    )
    top_hotspots_limit: int = (
        20  # Number of top hotspots (files with most findings) to include
    )

    @field_validator("max_detailed_findings", "top_hotspots_limit")
    @classmethod
    def _limits_are_not_negative(cls, value: int) -> int:
        return refuse_negative_limit(value)


class TextReporterConfig(ReporterPluginConfigBase):
    """Configuration for the Text reporter."""

    name: Literal["text"] = "text"
    extension: str = "summary.txt"
    enabled: bool = True
    options: TextReporterConfigOptions = TextReporterConfigOptions()


def _coverage_sections(model: "AshAggregatedResults") -> list[str]:
    """The sections that say what the scan did not examine, as lines.

    Inputs a scanner found and did not scan, stale content databases, and
    converter inputs nobody read. No scanner status carries them, so they stay
    in the report whether or not its summary tables are on.
    """
    lines: list[str] = []

    # See the matching section in the markdown reporter: no status value says
    # which input went unexamined.
    not_scanned = inputs_not_scanned(model)
    if not_scanned:
        lines.append("INPUTS NOT SCANNED")
        lines.append("------------------")
        # The path is the scanned repository's; its control characters are
        # escaped so it stays on its line (see utils/display_text.py) and
        # its CI command forms are broken, as this report lands in a job
        # log. The scanner's name and the reason are the results file's
        # text: each is one shown line.
        for scanner_name, path, reason in not_scanned:
            lines.append(
                f"- {shown_on_one_line(scanner_name)}: "
                f"{commands_broken(escape_controls(path))}: "
                f"{shown_on_one_line(reason)}"
            )
        lines.append("")

    # See the matching section in the markdown reporter: no status value carries this.
    stale_dbs = stale_content_databases(model)
    if stale_dbs:
        lines.append("STALE CONTENT DATABASES")
        lines.append("-----------------------")
        for record in stale_dbs:
            verdict = "FAILED THE SCAN" if record.enforced else "WARNING"
            lines.append(str(shown_on_one_line(f"- [{verdict}] {record.message()}")))
        lines.append("")

    # See the matching section in the markdown reporter.
    refusals = converter_refusals(model)
    if refusals:
        lines.append("CONVERTER INPUTS NOT SCANNED")
        lines.append("----------------------------")
        for line in summary_lines(refusals):
            # A converter input's name is the scanned tree's text. The line
            # holds its controls as escapes already, so only the CI command
            # forms are left to break.
            lines.append(commands_broken(f"- {line}"))
        lines.append("")

    return lines


@ash_reporter_plugin
class TextReporter(ReporterPluginBase[TextReporterConfig]):
    """Formats results as a human-readable plain text document.

    Workspace mode: one merged artefact with a per-project section. This is what
    ends up in a CI job log, so the section is fixed-width and aligned like the
    scanner table beside it -- a workspace summary that a reader has to count
    columns in is worse than no summary.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = TextReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model as a plain text string."""
        # Use the content emitter to get report data
        emitter = ReportContentEmitter(model, human_presentation=True)

        # Build the text report
        text_parts = []

        # Add report header
        text_parts.append("ASH SECURITY SCAN REPORT")
        text_parts.append("=======================")
        metadata = emitter.get_metadata()
        summary = emitter.get_scan_summary()
        text_parts.extend(
            [
                "",
                summary["title"].upper(),
                summary["description"],
                (
                    f"{summary['actionable']} actionable | {summary['below_threshold']} below threshold | "
                    # Findings the project's outcome left out are counted apart
                    # from the ones the threshold sets aside, only when present.
                    + (
                        f"{summary['policy_not_gating']} not gating (workspace policy) | "
                        if summary.get("policy_not_gating")
                        else ""
                    )
                    + f"{summary['suppressed']} suppressed | {summary['completed']}/{summary['scanners']} scanners completed"
                ),
                f"Next: {summary['next_step']}",
                "",
            ]
        )
        # A scanner's name can be a results file's text (``ash report`` renders
        # one a repository committed), so each line naming one is one shown line.
        if summary["shortfalls"]:
            text_parts.extend(["INCOMPLETE COVERAGE", "-------------------"])
            for scanner, attempted, failed in summary["shortfalls"]:
                text_parts.append(
                    str(
                        shown_on_one_line(
                            f"- {scanner}: {coverage_shortfall_text(attempted, failed)}"
                        )
                    )
                )
            text_parts.append("")
        if summary["unavailable"]:
            text_parts.extend(
                [
                    str(
                        shown_on_one_line(
                            "Scanners needing attention: "
                            + ", ".join(summary["unavailable"])
                        )
                    ),
                    "",
                ]
            )
        if summary["converter_gaps"]:
            text_parts.extend(
                [
                    "CONVERTERS NEEDING ATTENTION",
                    "Some inputs could not be prepared for scanning. Resolve these gaps and scan again.",
                ]
            )
            text_parts.extend(
                # IncompleteConverter rows carry (name, reason, kinds). Each row
                # is one shown line: the name and reason come from the tool.
                str(shown_on_one_line(f"- {name}: {reason}"))
                for name, reason, *_ in summary["converter_gaps"]
            )
            text_parts.append("")
        if summary["unevaluated_rules"]:
            text_parts.extend(
                [
                    "RULES NOT EVALUATED",
                    str(shown_on_one_line(", ".join(summary["unevaluated_rules"]))),
                    "These rules reached no verdict. Review the scanner logs before accepting this scan.",
                    "",
                ]
            )
        if summary.get("could_not_stop"):
            text_parts.extend(
                [
                    "SCANNER TOOLS NOT STOPPED",
                    "These tools could not be stopped and may still be writing, so this report may not be final.",
                ]
            )
            text_parts.extend(
                # The name and the reason come from the run's own record: one
                # shown line each.
                str(shown_on_one_line(f"- {name}: {reason}"))
                for name, reason in summary["could_not_stop"]
            )
            text_parts.append("")

        # Add metadata section
        text_parts.append("SCAN METADATA")
        text_parts.append("------------")
        # The project name and tool version come from the results file, which
        # a repository can commit: each line is one shown line. The timestamps
        # are validated as timestamps when the file is read.
        text_parts.append(str(shown_on_one_line(f"Project: {metadata['project']}")))
        text_parts.append(f"Scan executed: {metadata['scan_time']}")
        text_parts.append(
            str(shown_on_one_line(f"ASH version: {metadata['tool_version']}"))
        )
        # Which files the scanners read depends on the repository's ignore files, and
        # no scanner's own result can say that some were left out.
        ignore_file_exclusions = model.metadata.ignore_file_exclusions
        if ignore_file_exclusions is not None:
            text_parts.append(f"Ignore files: {ignore_file_exclusions.summary_text()}")
        text_parts.append("")

        # The per-project table, ahead of the summary because in a workspace the
        # first question is which project failed and a merged count cannot answer
        # it. Empty for a single-directory scan.
        text_parts.extend(text_workspace_section(model))

        # Add summary section if enabled
        if isinstance(self.config, dict):
            self.config = TextReporterConfig.model_validate(self.config)
        # Coverage facts no scanner row carries: they follow the summary's
        # tables when it is on and stand in its place when it is off.
        coverage_parts = _coverage_sections(model)
        if self.config.options.include_summary:
            text_parts.append("SUMMARY")
            text_parts.append("-------")

            # Generate scanner results table
            text_parts.append("Scanner Results:")
            # Format scanner results as a text table
            scanner_results = emitter.get_scanner_results()

            # Create header row with proper spacing
            text_parts.append(
                f"{'Scanner':<20} {'Suppressed':>10} {'Critical':>8} {'High':>8} {'Medium':>8} {'Low':>8} {'Info':>8} {'Duration':>10} {'Actionable':>10} {'Result':<8} {'Threshold':<15}"
            )
            text_parts.append(
                f"{'-' * 20} {'-' * 10} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 10} {'-' * 10} {'-' * 8} {'-' * 15}"
            )

            # Add scanner result rows
            for result in scanner_results:
                # Use the status field directly from the unified metrics
                status = result["status"]

                # Format duration using the unified format_duration function
                duration = format_duration(result.get("duration", 0))

                threshold_text = f"{result['threshold']} ({result['threshold_source']})"
                scanner_name = str(shown_on_one_line(result["scanner_name"]))

                text_parts.append(
                    f"{scanner_name:<20} "
                    f"{result['suppressed']:>10} "
                    f"{result['critical']:>8} "
                    f"{result['high']:>8} "
                    f"{result['medium']:>8} "
                    f"{result['low']:>8} "
                    f"{result['info']:>8} "
                    f"{duration:>10} "
                    f"{result['actionable']:>10} "
                    f"{status:<8} "
                    f"{threshold_text:<15}"
                )

            text_parts.append("")

            text_parts.extend(
                [
                    "Actionable findings meet or exceed the scanner threshold. Suppressed findings are separate.",
                    "PASSED/FAILED describe the severity gate; MISSING/ERROR need attention; SKIPPED did not run (disabled, or nothing to scan).",
                    "Threshold sources: global settings, scanner config, or scanner default.",
                    "",
                ]
            )

            text_parts.extend(coverage_parts)

            # Add top hotspots (files with most findings)
            top_hotspots = emitter.get_top_hotspots(
                self.config.options.top_hotspots_limit
            )
            if top_hotspots:
                text_parts.append(f"Top {len(top_hotspots)} Hotspots:")
                text_parts.append("Files with the highest number of security findings:")
                text_parts.append("")
                text_parts.append(f"{'Finding Count':>13} {'File Location':<60}")
                text_parts.append(f"{'-' * 13} {'-' * 60}")
                for hotspot in top_hotspots:
                    # A path from the scanned repository: shown on one line.
                    location = str(shown_on_one_line(hotspot["location"]))
                    text_parts.append(f"{hotspot['count']:>13} {location:<60}")
                text_parts.append("")
        else:
            # The disclosures stay when the summary is off.
            text_parts.extend(coverage_parts)

        # Add findings table if enabled
        if self.config.options.include_findings_table:
            findings = emitter.get_findings_overview()
            if findings:
                text_parts.append("FINDINGS OVERVIEW")
                text_parts.append("----------------")
                text_parts.append(
                    f"{'Severity':<10} {'Scanner':<15} {'Rule ID':<15} {'Title':<30} {'File':<30}"
                )
                text_parts.append(
                    f"{'-' * 10} {'-' * 15} {'-' * 15} {'-' * 30} {'-' * 30}"
                )

                for finding in findings:
                    # Truncate long fields to fit in the table
                    # The scanner, rule ID, title and path come from the scan:
                    # each is shown on one line before it is cut to its column.
                    scanner = str(shown_on_one_line(finding["scanner"]))[:15]
                    rule_id = str(shown_on_one_line(finding["rule_id"]))[:15]
                    title = str(shown_on_one_line(finding["title"]))[:30]
                    file_path = str(shown_on_one_line(finding["file_path"]))[:30]

                    # An additional report's severity is the results file's text.
                    severity = str(shown_on_one_line(finding["severity"]))
                    text_parts.append(
                        f"{severity:<10} "
                        f"{scanner:<15} "
                        f"{rule_id:<15} "
                        f"{title:<30} "
                        f"{file_path:<30}"
                    )
                text_parts.append("")

        # Add detailed findings if enabled
        if self.config.options.include_detailed_findings:
            detailed_findings = emitter.get_detailed_findings(
                self.config.options.max_detailed_findings
            )
            if detailed_findings:
                text_parts.append("DETAILED FINDINGS")
                text_parts.append("----------------")

                # Add each finding
                for i, finding in enumerate(detailed_findings):
                    # The title, scanner, rule ID, location, CVE, CWE and
                    # description come from the scan: shown, not obeyed, the
                    # description keeping its lines.
                    text_parts.append(
                        str(shown_on_one_line(f"Finding {i + 1}: {finding['title']}"))
                    )
                    text_parts.append(
                        str(shown_on_one_line(f"Severity: {finding['severity']}"))
                    )
                    text_parts.append(
                        str(shown_on_one_line(f"Scanner: {finding['scanner']}"))
                    )
                    text_parts.append(
                        str(shown_on_one_line(f"Rule ID: {finding['rule_id']}"))
                    )
                    text_parts.append(
                        str(shown_on_one_line(f"Location: {finding['location']}"))
                    )

                    if finding["cve_id"]:
                        text_parts.append(
                            str(shown_on_one_line(f"CVE: {finding['cve_id']}"))
                        )

                    if finding["cwe_id"]:
                        text_parts.append(
                            str(shown_on_one_line(f"CWE: {finding['cwe_id']}"))
                        )

                    text_parts.append("")
                    text_parts.append("Description:")
                    text_parts.append(str(shown_not_obeyed(finding["description"])))
                    text_parts.append("")

                    # Add a separator between findings
                    if i < len(detailed_findings) - 1:
                        text_parts.append("-" * 80)
                        text_parts.append("")

                # Add note if findings were limited. The list above holds the
                # ACTIONABLE findings, so the note counts those; counting every
                # finding (suppressed and below-threshold included) printed a
                # cut that never happened, with numbers the list did not match.
                total_actionable = sum(
                    emitter.is_finding_actionable(vuln) for vuln in emitter.flat_vulns
                )
                if total_actionable > len(detailed_findings):
                    text_parts.append(
                        f"Note: Showing {len(detailed_findings)} of {total_actionable} "
                        f"actionable findings. Configure 'max_detailed_findings' to adjust this limit."
                    )
                    text_parts.append("")

            # The list above is the actionable findings. A finding the project's
            # outcome left out is counted in the summary, so it is named here.
            left_out = emitter.get_policy_not_gating_findings(
                self.config.options.max_detailed_findings
            )
            if left_out:
                text_parts.append("NOT GATING (WORKSPACE POLICY)")
                text_parts.append("-----------------------------")
                text_parts.append(
                    f"Showing {len(left_out)} of {summary['policy_not_gating']} "
                    "findings reported and left out of the outcome because "
                    "policy_scanners_gate is off."
                )
                text_parts.append(
                    f"{'Severity':<10} {'Scanner':<15} {'Rule ID':<15} {'Title':<30} {'File':<30}"
                )
                text_parts.append(
                    f"{'-' * 10} {'-' * 15} {'-' * 15} {'-' * 30} {'-' * 30}"
                )
                for finding in left_out:
                    # Each field comes from the scan: shown on one line before it
                    # is cut to its column, as the findings overview does.
                    severity = str(shown_on_one_line(finding["severity"]))
                    scanner = str(shown_on_one_line(finding["scanner"]))[:15]
                    rule_id = str(shown_on_one_line(finding["rule_id"]))[:15]
                    title = str(shown_on_one_line(finding["title"]))[:30]
                    file_path = str(shown_on_one_line(finding["file_path"]))[:30]
                    text_parts.append(
                        f"{severity:<10} "
                        f"{scanner:<15} "
                        f"{rule_id:<15} "
                        f"{title:<30} "
                        f"{file_path:<30}"
                    )
                text_parts.append("")

        # Add footer
        text_parts.append("-" * 80)
        text_parts.append(
            f"Report generated by Automated Security Helper (ASH) at {datetime.now(timezone.utc).isoformat(timespec='seconds')}"
        )
        text_parts.append(FOOTER_CREDIT)

        # Join all parts with newlines
        return "\n".join(text_parts)
