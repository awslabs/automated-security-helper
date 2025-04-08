# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import html

from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.models.interfaces import IOutputReporter


class HTMLReporter(IOutputReporter):
    """Formats results as HTML."""

    def format(self, model: ASHARPModel) -> str:
        """Format ASH model as HTML string with comprehensive styling and organization."""
        findings_by_severity = model.group_findings_by_severity()
        findings_by_type = model.group_findings_by_type()

        findings_table = self._format_findings_table(model.findings)
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
                .severity-critical {{ color: #dc3545; }}
                .severity-high {{ color: #fd7e14; }}
                .severity-medium {{ color: #ffc107; }}
                .severity-low {{ color: #28a745; }}
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

    def _format_findings_table(self, findings: list) -> str:
        """Format the findings table."""
        if not findings:
            return "<p>No findings to display.</p>"

        table = """
        <table>
            <tr>
                <th>Severity</th>
                <th>Title</th>
                <th>Description</th>
                <th>Location</th>
                <th>Rule ID</th>
            </tr>
        """

        for finding in findings:
            finding_data = finding.model_dump()
            severity_class = f"severity-{finding_data['severity'].lower()}"

            location = finding_data.get("location", {})
            location_str = (
                f"{location.get('path', 'N/A')}:{location.get('line', 'N/A')}"
            )

            table += f"""
            <tr>
                <td class="{severity_class}">{html.escape(finding_data["severity"])}</td>
                <td>{html.escape(finding_data["title"])}</td>
                <td>{html.escape(finding_data["description"])}</td>
                <td>{html.escape(location_str)}</td>
                <td>{html.escape(finding_data["rule_id"])}</td>
            </tr>
            """

        table += "</table>"
        return table

    def _format_metadata(self, metadata) -> str:
        """Format the metadata section."""
        metadata_dict = metadata.model_dump()
        formatted = "<div class='metadata-section'>"

        for key, value in metadata_dict.items():
            formatted += f"""
            <div class="metadata-item">
                <strong>{html.escape(str(key))}:</strong> {html.escape(str(value))}
            </div>
            """

        formatted += "</div>"
        return formatted
