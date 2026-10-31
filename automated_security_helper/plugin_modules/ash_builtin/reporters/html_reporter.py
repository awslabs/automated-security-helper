# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import base64
import html
from datetime import datetime
from importlib import resources
from string import Template
from typing import Dict, List, Literal, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults

from automated_security_helper.models.flat_vulnerability import (
    recorded_artifact_path,
)
from automated_security_helper.schemas.sarif_schema_model import Result
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_section import (
    html_workspace_section,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
    coverage_shortfall_text,
)
from automated_security_helper.core.unified_metrics import format_duration
from automated_security_helper.utils.sarif_utils import (
    is_result_suppressed,
    suppressions_in_effect,
)
from automated_security_helper.utils.severity_ladder import SEVERITIES, result_severity
from automated_security_helper.utils.terminal_text import (
    commands_broken,
    is_shown_as_escape,
    shown_not_obeyed,
    shown_on_one_line,
)
from automated_security_helper.utils.ui_theme import FOOTER_CREDIT

#: Most severe first, for the "Findings by Severity" list.
_SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITIES)}


def _is_plain(text: str, allowed: str = "") -> bool:
    """Whether *text* holds nothing a viewer acts on.

    No control or format character, and no CI command form. The characters of
    *allowed* are admitted as layout, and a carriage return before a line feed
    when the line feed is allowed. Multi-line text allows tab and line feed; a
    location allows nothing.
    """
    if commands_broken(text) != text:
        return False
    for index, character in enumerate(text):
        if character in allowed:
            continue
        if character == "\r" and "\n" in allowed and text.startswith("\n", index + 1):
            continue
        if is_shown_as_escape(character):
            return False
    return True


#: What a block of scan text may hold and still be printed as written.
_TEXT_LAYOUT = "\t\n"


def _shown_text(text: Any) -> str:
    """Multi-line scan text as the report prints it.

    Text with nothing in it a viewer acts on is printed as written. Showing it
    anyway doubles the backslash of text that reads as an escape (a code
    sample's ``\\x41``), so a reader sees a character the source does not hold.
    Any other text is shown, not obeyed, keeping its lines.
    """
    value = "" if text is None else str(text)
    return value if _is_plain(value, _TEXT_LAYOUT) else str(shown_not_obeyed(value))


def _shown_note(text: Any) -> str:
    """The note that says a block was shown, not printed as written, or ``""``.

    Showing a block writes its controls as escapes and doubles every backslash
    in it, on lines that hold nothing unusual too, so a copy of the block is not
    the source. The reader is told when that is the case.
    """
    value = "" if text is None else str(text)
    if _is_plain(value, _TEXT_LAYOUT):
        return ""
    return (
        '<p class="shown-note"><small>Shown, not as written: control characters '
        "are written as escapes and backslashes are doubled.</small></p>"
    )


def _shown_location(location: str) -> str:
    """A file location as one shown line, as written when it needs no change.

    A name with no control and no command form is printed as written: showing
    it would only double the backslash of text that reads as an escape (a
    Windows path's ``\\x64``), and the copy would name no file.
    """
    return location if _is_plain(location) else str(shown_on_one_line(location))


def _scanner_label(name: Any) -> str:
    """A scanner's name as one shown line; never empty.

    The scanner filter's "All scanners" entry has the empty value, so no
    scanner may have it: an unnamed one is listed as ``unknown``.
    """
    return str(shown_on_one_line(name)) or "unknown"


class HTMLReporterConfigOptions(ReporterOptionsBase):
    pass


class HTMLReporterConfig(ReporterPluginConfigBase):
    name: Literal["html"] = "html"
    extension: str = "html"
    enabled: bool = True
    options: HTMLReporterConfigOptions = HTMLReporterConfigOptions()


@ash_reporter_plugin
class HtmlReporter(ReporterPluginBase[HTMLReporterConfig]):
    """Formats results as HTML.

    Workspace mode: one merged artefact with a per-project section. A human
    reading a workspace report is asking "which project is in trouble", so the
    project has to be the top-level structure and not a column buried in the
    findings table.

    The workspace section is added ahead of the existing content rather than
    replacing it. The whole-workspace severity and scanner tables stay useful --
    they answer "how bad is it overall" -- and reshaping the entire document
    around projects would have made a workspace report and a single-project
    report two different things to read.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = HTMLReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "AshAggregatedResults") -> str:
        """Render a self-contained, accessible report that works without a server."""
        emitter = ReportContentEmitter(model, human_presentation=True)
        metadata = emitter.get_metadata()
        summary = emitter.get_scan_summary()
        assets = resources.files(__package__).joinpath("assets")
        font_faces = []
        for family, filename, license_name in (
            ("Open Sans", "open-sans.woff2", "open-sans-OFL.txt"),
        ):
            encoded = base64.b64encode(
                assets.joinpath("fonts", filename).read_bytes()
            ).decode("ascii")
            license_text = (
                assets.joinpath("fonts", license_name)
                .read_text(encoding="utf-8")
                .replace("*/", "* /")
            )
            font_faces.append(
                f"/* {family} font license\n{license_text}\n*/\n"
                "@font-face { "
                f'font-family: "{family}"; font-style: normal; '
                "font-weight: 300 800; font-display: swap; "
                f'src: url("data:font/woff2;base64,{encoded}") format("woff2"); '
                "}\n"
            )
        workspace = html_workspace_section(model)
        if workspace:
            workspace = workspace.replace(
                "<table>",
                '<div class="table-scroll" role="region" aria-label="Project results" tabindex="0"><table>',
            ).replace("</table>", "</table></div>")
            workspace = (
                f'<div id="projects" class="workspace-section">{workspace}</div>'
            )
        counts = self._format_severity_counts(summary["counts"])
        # A scanner's name can be a results file's text (``ash report`` renders
        # one a repository committed), so it is one shown line wherever it is
        # printed. The filter's values are the same shown names the cards'
        # data-scanner attributes hold, so the filter still matches.
        scanners = sorted(
            {_scanner_label(finding.scanner) for finding in emitter.flat_vulns}
        )
        scanner_options = "".join(
            f'<option value="{html.escape(scanner, quote=True)}">{html.escape(scanner)}</option>'
            for scanner in scanners
        )
        data = {
            # The project name and tool version come from the results file,
            # which a repository can commit: each is one shown line.
            **{
                key: html.escape(str(shown_on_one_line(str(metadata[key]))))
                for key in ("project", "tool_version")
            },
            "scan_time": self._format_timestamp(metadata["scan_time"]),
            "report_time": self._format_timestamp(metadata["report_time"]),
            "report_css": "".join(font_faces)
            + assets.joinpath("ash-report.css").read_text(encoding="utf-8"),
            "report_script": assets.joinpath("ash-report.js").read_text(
                encoding="utf-8"
            ),
            "tone": summary["tone"],
            "outcome_symbol": {"danger": "!", "warning": "!", "success": "✓"}[
                summary["tone"]
            ],
            "outcome_title": summary["title"],
            "outcome_description": summary["description"],
            "next_step": summary["next_step"],
            "actionable": summary["actionable"],
            "below_threshold": summary["below_threshold"],
            "policy_not_gating_tile": self._format_policy_not_gating_tile(
                summary.get("policy_not_gating", 0)
            ),
            "suppressed": summary["suppressed"],
            "completed": summary["completed"],
            "scanners": summary["scanners"],
            "skipped": summary["skipped"],
            "unavailable": summary["unavailable_count"],
            "severity_counts": counts,
            "coverage_notices": self._format_coverage_notices(summary),
            "workspace_nav": '<a href="#projects">Projects</a>' if workspace else "",
            "workspace_section": workspace,
            "finding_count": len(emitter.flat_vulns),
            "scanner_options": scanner_options,
            "finding_cards": self._format_finding_cards(emitter),
            "scanner_results_table": self._format_scanner_results_table(
                emitter.get_scanner_results()
            ),
            "hotspots_section": self._format_hotspots_section(
                emitter.get_top_hotspots(10)
            ),
            "metadata_section": self._format_metadata(model.metadata),
            "footer_credit": html.escape(FOOTER_CREDIT),
        }
        return Template(
            assets.joinpath("ash-report.html").read_text(encoding="utf-8")
        ).substitute(data)

    @staticmethod
    def _format_policy_not_gating_tile(count: int) -> str:
        """The masthead tile for findings the project's outcome left out.

        Present only when there are such findings, so a report without any is
        the page it always was.
        """
        if not count:
            return ""
        return (
            f"<div><dl><dt>Not gating</dt><dd>{count}"
            '<span class="metric-description">Workspace policy findings, '
            "reported and left out of the outcome</span></dd></dl></div>"
        )

    @staticmethod
    def _format_severity_counts(counts: Dict[str, int]) -> str:
        """The severity chips of the masthead, one per bucket of *counts*.

        The buckets are an open set (a row rated outside the five levels counts
        under its own name), so each key is escaped where it becomes a class
        name and where it is shown.
        """
        return "".join(
            f'<span class="severity-{html.escape(level, quote=True)}">'
            f"<strong>{count}</strong> {html.escape(level.title())}</span>"
            for level, count in counts.items()
        )

    @staticmethod
    def _format_timestamp(value: Any) -> str:
        """Keep the report masthead readable and leave the full scan record intact."""
        raw = str(value)
        try:
            instant = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return html.escape(raw)
        months = (
            "Jan",
            "Feb",
            "Mar",
            "Apr",
            "May",
            "Jun",
            "Jul",
            "Aug",
            "Sep",
            "Oct",
            "Nov",
            "Dec",
        )
        zone = instant.tzname()
        label = (
            f"{instant.day} {months[instant.month - 1]} {instant.year} at "
            f"{instant.hour:02}:{instant.minute:02}"
        )
        if zone:
            label += f" {zone}"
        return html.escape(label)

    @staticmethod
    def _format_coverage_notices(summary: dict) -> str:
        notices = []
        if summary["shortfalls"]:
            rows = "".join(
                f"<li><strong>{html.escape(str(shown_on_one_line(scanner)))}</strong>: "
                f"{html.escape(coverage_shortfall_text(attempted, failed))}.</li>"
                for scanner, attempted, failed in summary["shortfalls"]
            )
            notices.append(
                '<div class="notice"><h3>Incomplete coverage</h3>'
                "<p>The findings reported are real, but the set is known to be partial.</p>"
                f"<ul>{rows}</ul></div>"
            )
        if summary["unavailable"]:
            names = ", ".join(
                html.escape(str(shown_on_one_line(name)))
                for name in summary["unavailable"]
            )
            notices.append(
                '<div class="notice"><h3>Scanners needing attention</h3>'
                f"<p>{names}. Check their dependencies and execution logs, then scan again.</p></div>"
            )
        if summary["converter_gaps"]:
            # A converter's name and reason come from the tool that ran, so they
            # are shown on one line: controls written as escapes, CI commands
            # broken.
            rows = "".join(
                f"<li><strong>{html.escape(str(shown_on_one_line(name)))}</strong>: "
                f"{html.escape(str(shown_on_one_line(reason)))}</li>"
                # IncompleteConverter rows carry (name, reason, kinds).
                for name, reason, *_ in summary["converter_gaps"]
            )
            notices.append(
                '<div class="notice"><h3>Converters needing attention</h3>'
                "<p>Some inputs could not be prepared for scanning. Resolve these gaps and scan again.</p>"
                f"<ul>{rows}</ul></div>"
            )
        if summary["unevaluated_rules"]:
            rules = ", ".join(
                html.escape(str(shown_on_one_line(rule)))
                for rule in summary["unevaluated_rules"]
            )
            notices.append(
                '<div class="notice"><h3>Rules not evaluated</h3>'
                f"<p>{rules}. These rules reached no verdict. Review the scanner logs before accepting this scan.</p></div>"
            )
        if summary.get("could_not_stop"):
            # The scanner's name and the reason (it names the process id) come
            # from the run's own record: each is one shown line.
            rows = "".join(
                f"<li><strong>{html.escape(str(shown_on_one_line(name)))}</strong>: "
                f"{html.escape(str(shown_on_one_line(reason)))}</li>"
                for name, reason in summary["could_not_stop"]
            )
            notices.append(
                '<div class="notice"><h3>Scanner tools not stopped</h3>'
                "<p>These tools could not be stopped and may still be writing into the "
                "output directory, so this report may not be final. The scan fails for them "
                "whatever the severity gate says.</p>"
                f"<ul>{rows}</ul></div>"
            )
        if summary["stale"]:
            rows = "".join(
                f"<li><strong>{html.escape(str(shown_on_one_line(record.name)))}</strong> "
                f"({html.escape(str(shown_on_one_line(record.scanner)))}): "
                f"{html.escape(str(shown_on_one_line(record.message())))}</li>"
                for record in summary["stale"]
            )
            notices.append(
                '<div class="notice"><h3>Stale content databases</h3>'
                "<p>A clean result from these scanners is not evidence of a clean target.</p>"
                f"<ul>{rows}</ul></div>"
            )
        return "".join(notices)

    @staticmethod
    def _format_finding_cards(emitter: ReportContentEmitter) -> str:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings = sorted(
            emitter.flat_vulns,
            key=lambda finding: (
                finding.is_suppressed,
                order.get(finding.severity.upper(), 5),
                finding.file_path or "",
                finding.line_start or 0,
                finding.rule_id or "",
            ),
        )
        if not findings:
            return '<p class="notice">No findings in this report. Check the scan outcome and scanner coverage above.</p>'
        cards = []
        for index, finding in enumerate(findings, 1):
            severity = finding.severity.upper()
            severity_class = severity.lower() if severity in order else "unknown"
            if finding.is_suppressed:
                status, label = "suppressed", "Suppressed"
            elif emitter.is_policy_not_gating(finding):
                # Left out of the project's outcome by where it came from, at
                # any severity: its own status, shown by the default view,
                # never "Below threshold".
                status, label = "policy-not-gating", "Not gating (workspace policy)"
            elif emitter.is_finding_actionable(finding):
                status, label = "actionable", "Actionable"
            else:
                status, label = "below-threshold", "Below threshold"
            location = finding.file_path or "N/A"
            # A line number locates a file; with no file it would read "N/A:12".
            if finding.file_path and finding.line_start is not None:
                location += f":{finding.line_start}"
            # The location comes from a file name in the scanned repository and
            # is offered for copying, so it is one shown line, as written when
            # it needs no change.
            copied = _shown_location(location)
            safe_location = html.escape(copied, quote=True)
            # Each context value can be the scan's text: the project from the
            # results, the CVE and CWE from a scanner's report, the package and
            # its version from the scanned manifests. Each is one shown line.
            context = "".join(
                f"<p><strong>{name}:</strong> {html.escape(str(shown_on_one_line(str(value))))}</p>"
                for name, value in (
                    ("Project", finding.workspace_project),
                    ("CVE", finding.cve_id),
                    ("CWE", finding.cwe_id),
                    ("Package", finding.package_name),
                    ("Version", finding.package_version),
                )
                if value is not None
            )
            snippet = (
                # Shown, not obeyed: the snippet keeps its lines, and its
                # controls and CI command forms are written out. Source that
                # holds none of them is printed as written.
                f'<pre role="region" tabindex="0" aria-label="Code snippet for finding {index}"><code>{html.escape(_shown_text(finding.code_snippet))}</code></pre>'
                f"{_shown_note(finding.code_snippet)}"
                if finding.code_snippet
                else ""
            )
            reason = finding.suppression_justification or "No reason provided"
            suppression = (
                '<p class="suppression-reason"><strong>Suppression reason:</strong> '
                # The reason can come from the scan: shown, keeping its lines.
                f"{html.escape(_shown_text(reason))}</p>{_shown_note(reason)}"
                if finding.is_suppressed
                else ""
            )
            # The scanner's name, as the filter's options show it.
            scanner = _scanner_label(finding.scanner)
            cards.append(
                f'<article class="finding-card" aria-labelledby="finding-{index}" '
                f'data-severity="{severity_class}" data-status="{status}" '
                f'data-scanner="{html.escape(scanner, quote=True)}">'
                '<div class="finding-card__inner">'
                '<div class="finding-top">'
                # An additional report's severity is the results file's text.
                f'<span class="pill severity-{severity_class}">{html.escape(str(shown_on_one_line(severity)))}</span>'
                f'<span class="finding-status">{label}</span>'
                f'<span class="finding-scanner">{html.escape(scanner)}</span></div>'
                # The title (the rule ID) and the description come from the
                # scan: shown, not obeyed, the description keeping its lines.
                f'<h3 id="finding-{index}">{html.escape(str(shown_on_one_line(finding.title)))}</h3>'
                '<p class="finding-meta">'
                f"<code>{html.escape(str(shown_on_one_line(finding.rule_id or 'N/A')))}</code>"
                f"<span><code>{safe_location}</code> "
                f'<button type="button" class="quiet-button copy-location js-only" '
                f'aria-label="Copy location for finding {index}" data-copy-location="{safe_location}">Copy</button></span></p>'
                f'<details><summary>Finding details</summary><div class="finding-body">'
                f'<p class="finding-description">{html.escape(_shown_text(finding.description))}</p>'
                f"{_shown_note(finding.description)}"
                f"{context}{suppression}{snippet}</div></details></div></article>"
            )
        return "\n".join(cards)

    def _format_scanner_results_table(
        self, scanner_results: List[Dict[str, Any]]
    ) -> str:
        """Format the scanner results table."""
        if not scanner_results:
            return "<p>No scanner results available.</p>"

        table = """
        <table>
            <tr>
                <th scope="col">Scanner</th>
                <th scope="col">S</th>
                <th scope="col">C</th>
                <th scope="col">H</th>
                <th scope="col">M</th>
                <th scope="col">L</th>
                <th scope="col">I</th>
                <th scope="col">Duration</th>
                <th scope="col">Actionable</th>
                <th scope="col">Result</th>
                <th scope="col">Threshold</th>
            </tr>
        """

        for result in scanner_results:
            # Format duration
            duration = html.escape(format_duration(result.get("duration", 0)))

            # Format status with appropriate CSS class
            status = result.get("status", "UNKNOWN")
            status_class = (
                f"status-{status.lower()}"
                if status in {"PASSED", "FAILED", "MISSING", "SKIPPED", "ERROR"}
                else "status-unknown"
            )

            # Format threshold
            threshold = f"{result.get('threshold', 'UNKNOWN')} ({result.get('threshold_source', 'unknown')})"

            # Format actionable count with color
            actionable = result.get("actionable", 0)
            actionable_class = "status-failed" if actionable > 0 else "status-passed"

            table += f"""
            <tr>
                <td>{html.escape(str(shown_on_one_line(result.get("scanner_name", "Unknown"))))}</td>
                <td>{result.get("suppressed", 0)}</td>
                <td>{result.get("critical", 0)}</td>
                <td>{result.get("high", 0)}</td>
                <td>{result.get("medium", 0)}</td>
                <td>{result.get("low", 0)}</td>
                <td>{result.get("info", 0)}</td>
                <td>{duration}</td>
                <td class="{actionable_class}">{actionable}</td>
                <td class="{status_class}">{html.escape(status)}</td>
                <td>{html.escape(threshold)}</td>
            </tr>
            """

        table += "</table>"
        return table

    def _format_hotspots_section(self, hotspots: List[Dict[str, Any]]) -> str:
        """Format the hotspots section."""
        if not hotspots:
            return ""

        section = f'<div class="hotspots"><h3>Top {len(hotspots)} hotspots</h3>'
        section += '<p>Files with the most actionable findings.</p><div class="table-scroll" role="region" aria-label="Top hotspots" tabindex="0">'
        section += """
        <table>
            <tr>
                <th scope="col">Finding count</th>
                <th scope="col">File location</th>
            </tr>
        """

        for hotspot in hotspots:
            # A path from the scanned repository: shown on one line, with the
            # backslash of text that reads as an escape doubled, so a name the
            # record writes as an escape (a file name that is not UTF-8) cannot
            # be taken for the escape itself. The finding card's code element
            # and copy attribute keep the path as recorded, as data.
            location = html.escape(
                str(shown_on_one_line(hotspot.get("location", "Unknown")))
            )
            section += f"""
            <tr>
                <td>{hotspot.get("count", 0)}</td>
                <td>{location}</td>
            </tr>
            """

        section += "</table></div></div>"
        return section

    @staticmethod
    def _is_suppressed(result: Result) -> bool:
        """Whether the result carries a suppression that is in effect.

        Read through ``sarif_utils.is_result_suppressed``, the one answer every
        consumer gives: a suppression ``rejected`` by the reviewer or still
        ``underReview`` has not taken effect (SARIF 3.35.4), the gate still fails
        the scan on the finding, and the report used to file it under Suppressed
        on the presence of the entry alone.
        """
        return is_result_suppressed(result)

    def _group_results_by_severity(
        self, results: List[Result]
    ) -> Dict[str, List[Result]]:
        """Group results by their severity level.

        Suppressed findings are separated into their own "SUPPRESSED" bucket
        so they don't inflate the active severity counts.
        """
        severity_groups: Dict[str, List[Result]] = {}
        for result in results:
            if self._is_suppressed(result):
                severity_groups.setdefault("SUPPRESSED", []).append(result)
                continue
            # The gate's severity, not the SARIF level ("ERROR", "WARNING"), so
            # the page agrees with the summary counts.
            severity = result_severity(result)
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(result)
        return severity_groups

    def _group_results_by_rule(self, results: List[Result]) -> Dict[str, List[Result]]:
        """Group results by their rule ID."""
        rule_groups = {}
        for result in results:
            rule_id = result.ruleId or "UNKNOWN"
            if rule_id not in rule_groups:
                rule_groups[rule_id] = []
            rule_groups[rule_id].append(result)
        return rule_groups

    def _format_severity_summary(self, findings_by_severity: dict) -> str:
        """Format the severity summary section.

        Suppressed findings are listed separately from active severities so
        they don't distort the actionable count.
        """
        active = {k: v for k, v in findings_by_severity.items() if k != "SUPPRESSED"}
        suppressed = findings_by_severity.get("SUPPRESSED", [])

        summary = "<h3>Findings by Severity</h3>"
        summary += (
            "<p>Statistics are calculated from the final aggregated SARIF report:</p>"
        )
        summary += "<ul>"
        for severity, findings in sorted(
            active.items(), key=lambda item: _SEVERITY_ORDER.get(item[0], 99)
        ):
            severity_class = f"severity-{severity.lower()}"
            summary += f'<li class="{severity_class}"><strong>{severity}</strong>: {len(findings)} finding(s)</li>'
        if suppressed:
            summary += f'<li style="color:#6c757d"><strong>SUPPRESSED</strong>: {len(suppressed)} finding(s)</li>'
        summary += "</ul>"
        return summary

    def _format_type_summary(self, findings_by_type: dict) -> str:
        """Format the type summary section."""
        summary = "<h3>Findings by Type</h3><ul>"
        for type_name, findings in findings_by_type.items():
            summary += f"<li>{html.escape(str(type_name or 'UNKNOWN'))}: {len(findings)} finding(s)</li>"
        summary += "</ul>"
        return summary

    def _format_findings_table(self, findings: List[Result]) -> str:
        """Format the findings table.

        Active findings are shown first.  Suppressed findings are placed in a
        separate section so they don't crowd the actionable list.  Each
        suppressed row includes the justification when available.
        """
        active = [f for f in findings if not self._is_suppressed(f)]
        suppressed = [f for f in findings if self._is_suppressed(f)]

        # --- active findings table ---
        table = """
        <table>
            <tr>
                <th scope="col">Severity</th>
                <th scope="col">Rule</th>
                <th scope="col">Message</th>
                <th scope="col">Location</th>
            </tr>
        """

        if not active:
            table += """
            <tr>
                <td colspan="4">No active findings to display</td>
            </tr>
            """

        for finding in active:
            severity = result_severity(finding)
            severity_class = f"severity-{severity.lower()}"

            location_str = self._location_str(finding)

            table += f"""
            <tr>
                <td class="{severity_class}">{html.escape(severity)}</td>
                <td>{html.escape(finding.ruleId or "N/A")}</td>
                <td>{html.escape((finding.message.root.text if finding.message else None) or "N/A")}</td>
                <td>{html.escape(location_str)}</td>
            </tr>
            """

        table += "</table>"

        # --- suppressed findings table ---
        if suppressed:
            table += f"""
            <h3>Suppressed Findings ({len(suppressed)})</h3>
            <p>These findings have been explicitly suppressed and do not affect the scanner result.</p>
            <table>
                <tr>
                    <th scope="col">Severity</th>
                    <th scope="col">Rule</th>
                    <th scope="col">Message</th>
                    <th scope="col">Location</th>
                    <th scope="col">Status</th>
                    <th scope="col">Reason</th>
                </tr>
            """
            for finding in suppressed:
                severity = result_severity(finding)
                severity_class = f"severity-{severity.lower()}"
                location_str = self._location_str(finding)
                # The reasons of the suppressions in effect: a rejected one did
                # not hide the finding, so its justification is not why the row
                # is here.
                reasons = [
                    s.justification
                    for s in suppressions_in_effect(finding.suppressions)
                    if getattr(s, "justification", None)
                ]
                reason = "; ".join(reasons) if reasons else ""

                table += f"""
                <tr>
                    <td class="{severity_class}">{html.escape(severity)}</td>
                    <td>{html.escape(finding.ruleId or "N/A")}</td>
                    <td>{html.escape((finding.message.root.text if finding.message else None) or "N/A")}</td>
                    <td>{html.escape(location_str)}</td>
                    <td style="color:#6c757d">Suppressed</td>
                    <td>{html.escape(reason)}</td>
                </tr>
                """
            table += "</table>"

        return table

    @staticmethod
    def _location_str(finding: Result) -> str:
        """Extract a human-readable location string from a Result."""
        if finding.locations and finding.locations[0].physicalLocation:
            phys_loc = finding.locations[0].physicalLocation
            if phys_loc.root.artifactLocation and phys_loc.root.artifactLocation.uri:
                location = phys_loc.root.artifactLocation.uri
                # A workspace scan writes a rebased uri percent-encoded and
                # records the path it names; show the path.
                location = recorded_artifact_path(finding, location) or location
                if phys_loc.root.region:
                    location += f":{phys_loc.root.region.startLine or 'N/A'}"
                return location
        return "N/A"

    def _format_metadata(self, metadata) -> str:
        """Format the metadata section.

        The dump holds the results file's text, extra fields included, so each
        key and value is one shown line.
        """
        metadata_dict = metadata.model_dump(by_alias=True)
        formatted = "<div class='metadata-section'>"

        for key, value in metadata_dict.items():
            shown_key = html.escape(str(shown_on_one_line(str(key))))
            shown_value = html.escape(str(shown_on_one_line(str(value))))
            formatted += f"""
            <div class="metadata-item">
                <strong>{shown_key}:</strong> {shown_value}
            </div>
            """

        formatted += "</div>"
        return formatted
