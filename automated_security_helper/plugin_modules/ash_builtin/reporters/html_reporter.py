# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import html
from typing import Dict, List, Literal, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults

from automated_security_helper.schemas.sarif_schema_model import Result
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)
from automated_security_helper.core.unified_metrics import format_duration


class HTMLReporterConfigOptions(ReporterOptionsBase):
    pass


class HTMLReporterConfig(ReporterPluginConfigBase):
    name: Literal["html"] = "html"
    extension: str = "html"
    enabled: bool = True
    options: HTMLReporterConfigOptions = HTMLReporterConfigOptions()


@ash_reporter_plugin
class HtmlReporter(ReporterPluginBase[HTMLReporterConfig]):
    """Formats results as HTML."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = HTMLReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model as HTML string with comprehensive styling and organization."""
        # Use the content emitter to get report data
        emitter = ReportContentEmitter(model)

        # Get metadata and scanner results
        metadata = emitter.get_metadata()
        scanner_results = emitter.get_scanner_results()

        # Get results from SARIF report for backward compatibility
        results = (
            model.sarif.runs[0].results if model.sarif and model.sarif.runs else []
        )

        # Group results by severity and rule
        findings_by_severity = self._group_results_by_severity(results)
        findings_by_type = self._group_results_by_rule(results)

        # Generate HTML sections
        findings_table = self._format_findings_table(results)
        severity_summary = self._format_severity_summary(findings_by_severity)
        type_summary = self._format_type_summary(findings_by_type)
        metadata_section = self._format_metadata(model.metadata)
        scanner_results_table = self._format_scanner_results_table(scanner_results)

        # Get top hotspots
        top_hotspots = emitter.get_top_hotspots(10)
        hotspots_section = self._format_hotspots_section(top_hotspots)

        template = f"""
<!DOCTYPE html>
<html>
<head>
    <title>ASH Security Scan Results</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1, h2, h3 {{
            color: #333;
            margin-top: 20px;
        }}
        .summary-box {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 15px;
            margin: 10px 0;
        }}
        .severity-error {{ color: #dc3545; }}
        .severity-warning {{ color: #fd7e14; }}
        .severity-note {{ color: #ffc107; }}
        .severity-none {{ color: #28a745; }}
        .status-passed {{ color: #28a745; font-weight: bold; }}
        .status-failed {{ color: #dc3545; font-weight: bold; }}
        .status-skipped {{ color: #6c757d; font-weight: bold; }}
        .status-missing {{ color: #fd7e14; font-weight: bold; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border: 1px solid #dee2e6;
        }}
        th {{
            background: #f8f9fa;
            font-weight: bold;
        }}
        tr:nth-child(even) {{
            background: #f8f9fa;
        }}
        .metadata-item {{
            margin: 10px 0;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 4px;
        }}
        .help-text {{
            background: #e9f5ff;
            border: 1px solid #b8daff;
            border-radius: 4px;
            padding: 15px;
            margin: 15px 0;
            font-size: 0.9em;
        }}
        .help-text h4 {{
            margin-top: 0;
            color: #0056b3;
        }}
        .help-text ul {{
            margin-bottom: 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>ASH Security Scan Results</h1>

        <div class="metadata-section">
            <p><strong>Project:</strong> {html.escape(metadata["project"])}</p>
            <p><strong>Scan executed:</strong> {html.escape(metadata["scan_time"])}</p>
            <p><strong>Report generated:</strong> {html.escape(metadata["report_time"])}</p>
            <p><strong>ASH version:</strong> {html.escape(metadata["tool_version"])}</p>
        </div>

        <h2>Scanner Results</h2>
        <div class="help-text">
            <h4>How to read scanner results</h4>
            <ul>
                <li><strong>Severity levels:</strong>
                    <ul>
                        <li><strong>Suppressed (S):</strong> Findings that have been explicitly suppressed and don't affect scanner status</li>
                        <li><strong>Critical (C):</strong> Highest severity findings that require immediate attention</li>
                        <li><strong>High (H):</strong> Serious findings that should be addressed soon</li>
                        <li><strong>Medium (M):</strong> Moderate risk findings</li>
                        <li><strong>Low (L):</strong> Lower risk findings</li>
                        <li><strong>Info (I):</strong> Informational findings with minimal risk</li>
                    </ul>
                </li>
                <li><strong>Duration:</strong> Time taken by the scanner to complete its execution</li>
                <li><strong>Actionable:</strong> Number of findings at or above the threshold severity level that require attention</li>
                <li><strong>Result:</strong>
                    <ul>
                        <li class="status-passed">PASSED = No findings at or above threshold</li>
                        <li class="status-failed">FAILED = Findings at or above threshold</li>
                        <li class="status-missing">MISSING = Required dependencies not available</li>
                        <li class="status-skipped">SKIPPED = Scanner explicitly disabled</li>
                    </ul>
                </li>
                <li><strong>Threshold:</strong> The minimum severity level that will cause a scanner to fail</li>
                <li><strong>Statistics calculation:</strong>
                    <ul>
                        <li>All statistics are calculated from the final aggregated SARIF report</li>
                        <li>Suppressed findings are counted separately and do not contribute to actionable findings</li>
                        <li>Scanner status is determined by comparing actionable findings to the threshold</li>
                    </ul>
                </li>
            </ul>
        </div>
        {scanner_results_table}

        <h2>Summary</h2>
        <div class="summary-box">
            {severity_summary}
            {type_summary}
            {hotspots_section}
        </div>

        <h2>Detailed Findings</h2>
        {findings_table}

        <h2>Scan Metadata</h2>
        {metadata_section}
    </div>
</body>
</html>
"""

        return template

    def _format_scanner_results_table(
        self, scanner_results: List[Dict[str, Any]]
    ) -> str:
        """Format the scanner results table."""
        if not scanner_results:
            return "<p>No scanner results available.</p>"

        table = """
        <table>
            <tr>
                <th>Scanner</th>
                <th>S</th>
                <th>C</th>
                <th>H</th>
                <th>M</th>
                <th>L</th>
                <th>I</th>
                <th>Duration</th>
                <th>Actionable</th>
                <th>Result</th>
                <th>Threshold</th>
            </tr>
        """

        for result in scanner_results:
            # Format duration
            duration = format_duration(result.get("duration", 0))

            # Format status with appropriate CSS class
            status = result.get("status", "UNKNOWN")
            status_class = f"status-{status.lower()}"

            # Format threshold
            threshold = f"{result.get('threshold', 'UNKNOWN')} ({result.get('threshold_source', 'unknown')})"

            # Format actionable count with color
            actionable = result.get("actionable", 0)
            actionable_class = "status-failed" if actionable > 0 else "status-passed"

            table += f"""
            <tr>
                <td>{html.escape(result.get("scanner_name", "Unknown"))}</td>
                <td>{result.get("suppressed", 0)}</td>
                <td>{result.get("critical", 0)}</td>
                <td>{result.get("high", 0)}</td>
                <td>{result.get("medium", 0)}</td>
                <td>{result.get("low", 0)}</td>
                <td>{result.get("info", 0)}</td>
                <td>{duration}</td>
                <td class="{actionable_class}">{actionable}</td>
                <td class="{status_class}">{status}</td>
                <td>{html.escape(threshold)}</td>
            </tr>
            """

        table += "</table>"
        return table

    def _format_hotspots_section(self, hotspots: List[Dict[str, Any]]) -> str:
        """Format the hotspots section."""
        if not hotspots:
            return ""

        section = f"<h3>Top {len(hotspots)} Hotspots</h3>"
        section += "<p>Files with the highest number of security findings:</p>"
        section += """
        <table>
            <tr>
                <th>Finding Count</th>
                <th>File Location</th>
            </tr>
        """

        for hotspot in hotspots:
            section += f"""
            <tr>
                <td>{hotspot.get("count", 0)}</td>
                <td>{html.escape(hotspot.get("location", "Unknown"))}</td>
            </tr>
            """

        section += "</table>"
        return section

    def _group_results_by_severity(
        self, results: List[Result]
    ) -> Dict[str, List[Result]]:
        """Group results by their severity level."""
        severity_groups = {}
        for result in results:
            result_level = (
                result.level.value
                if result.level and hasattr(result.level, "value")
                else str(result.level)
                if result.level
                else "UNKNOWN"
            )
            severity = result_level.upper() if result.level else "UNKNOWN"
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
        """Format the severity summary section."""
        summary = "<h3>Findings by Severity</h3>"
        summary += (
            "<p>Statistics are calculated from the final aggregated SARIF report:</p>"
        )
        summary += "<ul>"
        for severity, findings in findings_by_severity.items():
            severity_class = f"severity-{severity.lower()}"
            summary += f'<li class="{severity_class}"><strong>{severity}</strong>: {len(findings)} finding(s)</li>'
        summary += "</ul>"
        return summary

    def _format_type_summary(self, findings_by_type: dict) -> str:
        """Format the type summary section."""
        summary = "<h3>Findings by Type</h3><ul>"
        for type_name, findings in findings_by_type.items():
            summary += f"<li>{type_name}: {len(findings)} finding(s)</li>"
        summary += "</ul>"
        return summary

    def _format_findings_table(self, findings: List[Result]) -> str:
        """Format the findings table."""
        table = """
        <table>
            <tr>
                <th>Severity</th>
                <th>Rule</th>
                <th>Message</th>
                <th>Location</th>
            </tr>
        """

        if not findings:
            table += """
            <tr>
                <td colspan="4">No findings to display</td>
            </tr>
            """

        for finding in findings:
            finding_level = (
                finding.level.value
                if finding.level and hasattr(finding.level, "value")
                else str(finding.level)
            )
            severity_class = (
                f"severity-{finding_level.lower() if finding.level else 'none'}"
            )

            # Get location information
            location_str = "N/A"

            if finding.locations and finding.locations[0].physicalLocation:
                phys_loc = finding.locations[0].physicalLocation
                if (
                    phys_loc.root.artifactLocation
                    and phys_loc.root.artifactLocation.uri
                ):
                    location = phys_loc.root.artifactLocation.uri
                    if phys_loc.root.region:
                        location += f":{phys_loc.root.region.startLine or 'N/A'}"
                    location_str = location

            table += f"""
            <tr>
                <td class="{severity_class}">{html.escape(finding_level.upper() if finding.level else "NONE")}</td>
                <td>{html.escape(finding.ruleId or "N/A")}</td>
                <td>{html.escape(finding.message.root.text if finding.message else "N/A")}</td>
                <td>{html.escape(location_str)}</td>
            </tr>
            """

        table += "</table>"
        return table

    def _format_metadata(self, metadata) -> str:
        """Format the metadata section."""
        metadata_dict = metadata.model_dump(by_alias=True)
        formatted = "<div class='metadata-section'>"

        for key, value in metadata_dict.items():
            formatted += f"""
            <div class="metadata-item">
                <strong>{html.escape(str(key))}:</strong> {html.escape(str(value))}
            </div>
            """

        formatted += "</div>"
        return formatted
