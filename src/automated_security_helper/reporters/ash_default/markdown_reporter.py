# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime, timezone
from typing import Any, Literal
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.reporters.ash_default.report_content_emitter import (
    ReportContentEmitter,
)


class MarkdownReporterConfigOptions(ReporterOptionsBase):
    """Configuration options for the Markdown reporter."""

    include_summary: bool = True
    include_findings_table: bool = False  # This can be lengthy, default to False
    include_detailed_findings: bool = True
    max_detailed_findings: int = (
        20  # Limit detailed findings to avoid overly large reports
    )
    top_hotspots_limit: int = (
        10  # Number of top hotspots (files with most findings) to include
    )
    use_collapsible_details: bool = (
        True  # Use HTML details/summary tags for detailed findings
    )


class MarkdownReporterConfig(ReporterPluginConfigBase):
    """Configuration for the Markdown reporter."""

    name: Literal["markdown"] = "markdown"
    extension: str = "summary.md"
    enabled: bool = True
    options: MarkdownReporterConfigOptions = MarkdownReporterConfigOptions()


class MarkdownReporter(ReporterPluginBase[MarkdownReporterConfig]):
    """Formats results as a human-readable Markdown document."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = MarkdownReporterConfig()
        return super().model_post_init(context)

    def report(self, model: Any) -> str:
        """Format ASH model as a Markdown string."""
        from automated_security_helper.models.asharp_model import ASHARPModel

        if not isinstance(model, ASHARPModel):
            raise ValueError(f"{self.__class__.__name__} only supports ASHARPModel")

        # Use the content emitter to get report data
        emitter = ReportContentEmitter(model)

        # Build the markdown report
        md_parts = []

        # Add report header
        md_parts.append(
            f"# ASH Security Scan Report\nReport run time: {datetime.now(timezone.utc).strftime('%Y-%m-%d - %H:%M (UTC)')}\n"
        )

        # Add metadata section
        md_parts.append("## Scan Metadata\n")
        metadata = emitter.get_metadata()
        md_parts.append(f"- **Project**: {metadata['project']}")
        md_parts.append(f"- **Generated**: {metadata['generated_at']}")
        md_parts.append(f"- **Tool Version**: {metadata['tool_version']}")
        md_parts.append("")

        # Add summary section if enabled
        if self.config.options.include_summary:
            md_parts.append("## Summary\n")

            # Generate scanner results table
            md_parts.append("### Scanner Results\n")
            md_parts.append(
                "The table below shows findings by scanner, with pass/fail status based on severity thresholds:\n"
            )
            md_parts.append(
                "- **Threshold**: The minimum severity level that will cause a scanner to fail (ALL, LOW, MEDIUM, HIGH, CRITICAL)"
            )
            md_parts.append(
                "  - Values in parentheses indicate where the threshold is set: `global` (project default), `config` (scanner config), or `scanner` (scanner implementation)"
            )
            md_parts.append(
                "- **Result**: ✅ Passed = No findings at or above threshold, ❌ Failed = Findings at or above threshold"
            )
            md_parts.append(
                "- **Example**: With MEDIUM threshold, findings of MEDIUM, HIGH, or CRITICAL severity will cause a failure\n"
            )

            md_parts.append(
                "| Scanner | Critical | High | Medium | Low | Info | Total | Result | Threshold |"
            )
            md_parts.append(
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |"
            )

            # Add scanner result rows
            scanner_results = emitter.get_scanner_results()
            for result in scanner_results:
                status = "✅ Passed" if result["passed"] else "❌ Failed"
                threshold_text = f"{result['threshold']} ({result['threshold_source']})"
                md_parts.append(
                    f"| {result['scanner_name']} | {result['critical']} | {result['high']} | "
                    f"{result['medium']} | {result['low']} | {result['info']} | {result['total']} | "
                    f"{status} | {threshold_text} |"
                )

            md_parts.append("")

            # Add top hotspots (files with most findings)
            top_hotspots = emitter.get_top_hotspots(
                self.config.options.top_hotspots_limit
            )
            if top_hotspots:
                md_parts.append(f"### Top {len(top_hotspots)} Hotspots\n")
                md_parts.append("Files with the highest number of security findings:\n")
                md_parts.append("| File Location | Finding Count |")
                md_parts.append("| --- | ---: |")
                for hotspot in top_hotspots:
                    # Escape pipe characters in markdown table
                    safe_location = hotspot["location"].replace("|", "\\|")
                    md_parts.append(f"| {safe_location} | {hotspot['count']} |")
                md_parts.append("")

        # Add findings table if enabled
        if self.config.options.include_findings_table:
            findings = emitter.get_findings_overview()
            if findings:
                md_parts.append("## Findings Overview\n")
                md_parts.append("| Severity | Scanner | Rule ID | Title | File |")
                md_parts.append("| --- | --- | --- | --- | --- |")

                for finding in findings:
                    # Escape pipe characters in markdown table
                    title = finding["title"].replace("|", "\\|")
                    file_path = finding["file_path"].replace("|", "\\|")

                    md_parts.append(
                        f"| {finding['severity']} | {finding['scanner']} | {finding['rule_id']} | {title} | {file_path} |"
                    )

                md_parts.append("")

        # Add detailed findings if enabled
        if self.config.options.include_detailed_findings:
            detailed_findings = emitter.get_detailed_findings(
                self.config.options.max_detailed_findings
            )
            if detailed_findings:
                # Determine if we should use collapsible details
                use_collapsible = self.config.options.use_collapsible_details
                findings_count = len(detailed_findings)
                total_findings = len(emitter.flat_vulns)

                # Start the detailed findings section with the header outside the collapsible element
                md_parts.append("<h2>Detailed Findings</h2>\n")

                if use_collapsible:
                    # Create a collapsible section with HTML details/summary tags
                    md_parts.append("<details>")
                    md_parts.append(
                        f"<summary>Show {findings_count}{' of ' + str(total_findings) if findings_count < total_findings else ''} detailed findings</summary>\n"
                    )

                # Add each finding
                for i, finding in enumerate(detailed_findings):
                    md_parts.append(f"### Finding {i + 1}: {finding['title']}\n")
                    md_parts.append(f"- **Severity**: {finding['severity']}")
                    md_parts.append(f"- **Scanner**: {finding['scanner']}")
                    md_parts.append(f"- **Rule ID**: {finding['rule_id']}")
                    md_parts.append(f"- **Location**: {finding['location']}")

                    if finding["cve_id"]:
                        md_parts.append(f"- **CVE**: {finding['cve_id']}")

                    if finding["cwe_id"]:
                        md_parts.append(f"- **CWE**: {finding['cwe_id']}")

                    md_parts.append("\n**Description**:")
                    md_parts.append(f"{finding['description']}\n")

                    # Add a separator between findings
                    if i < len(detailed_findings) - 1:
                        md_parts.append("---\n")

                # Add note if findings were limited
                if len(emitter.flat_vulns) > self.config.options.max_detailed_findings:
                    md_parts.append(
                        f"\n> Note: Showing {self.config.options.max_detailed_findings} of {len(emitter.flat_vulns)} total findings. Configure `max_detailed_findings` to adjust this limit.\n"
                    )

                # Close the details tag if using collapsible section
                if use_collapsible:
                    md_parts.append("</details>")

        # Add footer
        md_parts.append("\n---\n")
        md_parts.append(
            f"*Report generated by [Automated Security Helper (ASH)](https://github.com/awslabs/automated-security-helper) at {datetime.now(timezone.utc).isoformat(timespec='seconds')}*"
        )

        # Join all parts with newlines
        return "\n".join(md_parts)
