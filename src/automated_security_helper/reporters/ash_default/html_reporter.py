# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import html
from typing import Any, Dict, List, Literal

from automated_security_helper.schemas.sarif_schema_model import Result
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)


class HTMLReporterConfigOptions(ReporterOptionsBase):
    pass


class HTMLReporterConfig(ReporterPluginConfigBase):
    name: Literal["html"] = "html"
    extension: str = "html"
    enabled: bool = True


class HTMLReporter(ReporterPluginBase[HTMLReporterConfig]):
    """Formats results as HTML."""

    def report(self, model: Any) -> str:
        """Format ASH model as HTML string with comprehensive styling and organization."""
        from automated_security_helper.models.asharp_model import ASHARPModel

        if not isinstance(model, ASHARPModel):
            raise ValueError(f"{self.__class__.__name__} only supports ASHARPModel")

        # Get results from SARIF report
        results = (
            model.sarif.runs[0].results if model.sarif and model.sarif.runs else []
        )

        # Group results by severity and rule
        findings_by_severity = self._group_results_by_severity(results)
        findings_by_type = self._group_results_by_rule(results)

        findings_table = self._format_findings_table(results)
        severity_summary = self._format_severity_summary(findings_by_severity)
        type_summary = self._format_type_summary(findings_by_type)
        metadata_section = self._format_metadata(model.metadata)

        template = f"""
<!DOCTYPE html>
<html>
<head>
    <title>ASH Results</title>
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
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Scan Results</h1>

        <h2>Summary</h2>
        <div class="summary-box">
            {severity_summary}
            {type_summary}
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
        summary = "<h3>Findings by Severity</h3><ul>"
        for severity, findings in findings_by_severity.items():
            summary += f'<li class="severity-{severity.lower()}">{severity}: {len(findings)} finding(s)</li>'
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
        if not findings:
            return "<p>No findings to display.</p>"

        table = """
        <table>
            <tr>
                <th>Severity</th>
                <th>Rule</th>
                <th>Message</th>
                <th>Location</th>
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
