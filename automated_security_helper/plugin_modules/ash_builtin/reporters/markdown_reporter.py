# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime, timezone
from typing import Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin


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


@ash_reporter_plugin
class MarkdownReporter(ReporterPluginBase[MarkdownReporterConfig]):
    """Formats results as a human-readable Markdown document."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = MarkdownReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model as a Markdown string."""

        # Use the content emitter to get report data
        emitter = ReportContentEmitter(model)

        # Build the markdown report
        md_parts = []

        # Add report header
        metadata = emitter.get_metadata()
        md_parts.append("# ASH Security Scan Report\n")
        md_parts.append(f"- **Report generated**: {metadata['report_time']}")
        # Add time delta if available
        if metadata.get("time_delta"):
            days = metadata["time_delta"].days
            hours, remainder = divmod(metadata["time_delta"].seconds, 3600)
            minutes, _ = divmod(remainder, 60)

            if days > 0:
                delta_str = f"{days} day{'s' if days != 1 else ''}, {hours} hour{'s' if hours != 1 else ''}"
            elif hours > 0:
                delta_str = f"{hours} hour{'s' if hours != 1 else ''}, {minutes} minute{'s' if minutes != 1 else ''}"
            else:
                delta_str = f"{minutes} minute{'s' if minutes != 1 else ''}"

            md_parts.append(f"- **Time since scan**: {delta_str}")
        md_parts.append("")

        # Add metadata section
        md_parts.append("## Scan Metadata\n")
        md_parts.append(f"- **Project**: {metadata['project']}")
        md_parts.append(f"- **Scan executed**: {metadata['scan_time']}")
        md_parts.append(f"- **ASH version**: {metadata['tool_version']}")
        md_parts.append("")

        # Add summary section if enabled
        if isinstance(self.config, dict):
            self.config = MarkdownReporterConfig.model_validate(self.config)
        if self.config.options.include_summary:
            md_parts.append("## Summary\n")

            # Generate scanner results table
            md_parts.append("### Scanner Results\n")
            md_parts.append(
                "The table below shows findings by scanner, with status based on severity thresholds and dependencies:\n"
            )
            md_parts.append("- **Severity levels**:")
            md_parts.append(
                "  - **Suppressed (S)**: Findings that have been explicitly suppressed and don't affect scanner status"
            )
            md_parts.append(
                "  - **Critical (C)**: Highest severity findings that require immediate attention"
            )
            md_parts.append(
                "  - **High (H)**: Serious findings that should be addressed soon"
            )
            md_parts.append("  - **Medium (M)**: Moderate risk findings")
            md_parts.append("  - **Low (L)**: Lower risk findings")
            md_parts.append(
                "  - **Info (I)**: Informational findings with minimal risk"
            )
            md_parts.append(
                "- **Duration (Time)**: Time taken by the scanner to complete its execution"
            )
            md_parts.append(
                "- **Actionable**: Number of findings at or above the threshold severity level that require attention"
            )
            md_parts.append("- **Result**:")
            md_parts.append("  - **PASSED** = No findings at or above threshold")
            md_parts.append("  - ❌ **FAILED** = Findings at or above threshold")
            md_parts.append("  - **MISSING** = Required dependencies not available")
            md_parts.append("  - ⏭️ **SKIPPED** = Scanner explicitly disabled")
            md_parts.append(
                "- **Threshold**: The minimum severity level that will cause a scanner to fail"
            )
            md_parts.append("  - Thresholds: ALL, LOW, MEDIUM, HIGH, CRITICAL")
            md_parts.append(
                "  - Source: Values in parentheses indicate where the threshold is set:"
            )
            md_parts.append(
                "    - `global` (global_settings section in the ASH_CONFIG used)"
            )
            md_parts.append(
                "    - `config` (scanner config section in the ASH_CONFIG used)"
            )
            md_parts.append(
                "    - `scanner` (default configuration in the plugin, if explicitly set)"
            )
            md_parts.append("- **Statistics calculation**:")
            md_parts.append(
                "  - All statistics are calculated from the final aggregated SARIF report"
            )
            md_parts.append(
                "  - Suppressed findings are counted separately and do not contribute to actionable findings"
            )
            md_parts.append(
                "  - Scanner status is determined by comparing actionable findings to the threshold\n"
            )

            md_parts.append(
                "| Scanner | Suppressed | Critical | High | Medium | Low | Info | Actionable | Result | Threshold |"
            )
            md_parts.append(
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |"
            )

            # Add scanner result rows
            scanner_results = emitter.get_scanner_results()
            for result in scanner_results:
                # Determine status text and emoji based on status field
                status = result["status"]
                if status == "PASSED":
                    status_text = "PASSED"
                elif status == "FAILED":
                    status_text = "❌ FAILED"
                elif status == "MISSING":
                    status_text = "MISSING"
                elif status == "SKIPPED":
                    status_text = "⏭️ SKIPPED"
                else:
                    status_text = status

                threshold_text = f"{result['threshold']} ({result['threshold_source']})"

                md_parts.append(
                    f"| {result['scanner_name']} | {result['suppressed']} | {result['critical']} | {result['high']} | "
                    f"{result['medium']} | {result['low']} | {result['info']} | {result['actionable']} | "
                    f"{status_text} | {threshold_text} |"
                )

            md_parts.append("")

            # Add top hotspots (files with most findings)
            top_hotspots = emitter.get_top_hotspots(
                self.config.options.top_hotspots_limit
            )
            if top_hotspots:
                md_parts.append(f"### Top {len(top_hotspots)} Hotspots\n")
                md_parts.append("Files with the highest number of security findings:\n")
                md_parts.append("| Finding Count | File Location |")
                md_parts.append("| ---: | --- |")
                for hotspot in top_hotspots:
                    # Escape pipe characters in markdown table
                    safe_location = hotspot["location"].replace("|", "\\|")
                    md_parts.append(f"| {hotspot['count']} | {safe_location} |")
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
                total_findings = len(
                    [v for v in emitter.flat_vulns if emitter.is_finding_actionable(v)]
                )

                # Start the detailed findings section with the header outside the collapsible element
                md_parts.append("<h2>Detailed Findings</h2>\n")

                if use_collapsible:
                    # Create a collapsible section with HTML details/summary tags
                    md_parts.append("<details>")
                    md_parts.append(
                        f"<summary>Show {findings_count}{' of ' + str(total_findings) if findings_count < total_findings else ''} actionable findings</summary>\n"
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

                    # Add code snippet if available
                    if finding.get("code_snippet"):
                        md_parts.append("**Code Snippet**:")
                        md_parts.append(f"```\n{finding['code_snippet']}\n```\n")

                    # Add a separator between findings
                    if i < len(detailed_findings) - 1:
                        md_parts.append("---\n")

                # Add note if findings were limited
                if total_findings > self.config.options.max_detailed_findings:
                    md_parts.append(
                        f"\n> Note: Showing {self.config.options.max_detailed_findings} of {total_findings} total actionable findings. Configure `max_detailed_findings` to adjust this limit.\n"
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
