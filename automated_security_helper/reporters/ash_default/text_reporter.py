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
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.reporters.ash_default.report_content_emitter import (
    ReportContentEmitter,
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


class TextReporterConfig(ReporterPluginConfigBase):
    """Configuration for the Text reporter."""

    name: Literal["text"] = "text"
    extension: str = "summary.txt"
    enabled: bool = True
    options: TextReporterConfigOptions = TextReporterConfigOptions()


@ash_reporter_plugin
class TextReporter(ReporterPluginBase[TextReporterConfig]):
    """Formats results as a human-readable plain text document."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = TextReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model as a plain text string."""
        # Use the content emitter to get report data
        emitter = ReportContentEmitter(model)

        # Build the text report
        text_parts = []

        # Add report header
        text_parts.append("ASH SECURITY SCAN REPORT")
        text_parts.append("=======================")
        metadata = emitter.get_metadata()
        text_parts.append(f"Report generated: {metadata['report_time']}")
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

            text_parts.append(f"Time since scan: {delta_str}")

        text_parts.append("")

        # Add metadata section
        text_parts.append("SCAN METADATA")
        text_parts.append("------------")
        text_parts.append(f"Project: {metadata['project']}")
        text_parts.append(f"Scan executed: {metadata['scan_time']}")
        text_parts.append(f"ASH version: {metadata['tool_version']}")
        text_parts.append("")

        # Add summary section if enabled
        if self.config.options.include_summary:
            text_parts.append("SUMMARY")
            text_parts.append("-------")

            # Generate scanner results table
            text_parts.append("Scanner Results:")
            text_parts.append(
                "The table below shows findings by scanner, with status based on severity thresholds and dependencies:"
            )
            text_parts.append(
                "- Severity levels: Suppressed (S), Critical (C), High (H), Medium (M), Low (L), Info (I)"
            )
            text_parts.append(
                "- Duration (Time): Time taken by the scanner to complete its execution"
            )
            text_parts.append(
                "- Actionable: Number of findings at or above the threshold severity level"
            )
            text_parts.append("- Result:")
            text_parts.append("  - PASSED = No findings at or above threshold")
            text_parts.append("  - FAILED = Findings at or above threshold")
            text_parts.append("  - MISSING = Required dependencies not available")
            text_parts.append("  - SKIPPED = Scanner explicitly disabled")
            text_parts.append(
                "- Threshold: The minimum severity level that will cause a scanner to fail (ALL, LOW, MEDIUM, HIGH, CRITICAL)"
            )
            text_parts.append(
                "  - Values in parentheses indicate where the threshold is set in order of precedence:"
            )
            text_parts.append(
                "    - 'env' (ASH_SEVERITY_THRESHOLD environment variable)"
            )
            text_parts.append(
                "    - 'config' (scanner config section in the ASH_CONFIG used)"
            )
            text_parts.append(
                "    - 'scanner' (default configuration in the plugin, if explicitly set)"
            )
            text_parts.append(
                "    - 'global' (global_settings section in the ASH_CONFIG used)"
            )
            text_parts.append(
                "- Example: With MEDIUM threshold, findings of MEDIUM, HIGH, or CRITICAL severity will cause a failure"
            )
            text_parts.append(
                "- Note: Suppressed findings are counted separately and do not contribute to actionable findings"
            )
            text_parts.append("")

            # Format scanner results as a text table
            scanner_results = emitter.get_scanner_results()

            # Create header row with proper spacing
            text_parts.append(
                f"{'Scanner':<20} {'Supp':>8} {'Critical':>8} {'High':>8} {'Medium':>8} {'Low':>8} {'Info':>8} {'Actionable':>10} {'Result':<8} {'Threshold':<15}"
            )
            text_parts.append(
                f"{'-' * 20} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 10} {'-' * 8} {'-' * 15}"
            )

            # Add scanner result rows
            for result in scanner_results:
                # Determine status text based on status field
                if "status" in result:
                    status = result["status"]
                else:
                    status = "PASS" if result["passed"] else "FAIL"

                threshold_text = f"{result['threshold']} ({result['threshold_source']})"

                text_parts.append(
                    f"{result['scanner_name']:<20} "
                    f"{result['suppressed']:>8} "
                    f"{result['critical']:>8} "
                    f"{result['high']:>8} "
                    f"{result['medium']:>8} "
                    f"{result['low']:>8} "
                    f"{result['info']:>8} "
                    f"{result['actionable']:>10} "
                    f"{status:<8} "
                    f"{threshold_text:<15}"
                )

            text_parts.append("")

            # Add top hotspots (files with most findings)
            top_hotspots = emitter.get_top_hotspots(
                self.config.options.top_hotspots_limit
            )
            if top_hotspots:
                text_parts.append(f"Top {len(top_hotspots)} Hotspots:")
                text_parts.append("Files with the highest number of security findings:")
                text_parts.append("")
                text_parts.append(f"{'Finding Count':>12} {'File Location':<60}")
                text_parts.append(f"{'-' * 12} {'-' * 60}")
                for hotspot in top_hotspots:
                    text_parts.append(
                        f"{hotspot['count']:>12} {hotspot['location']:<60}"
                    )
                text_parts.append("")

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
                    title = finding["title"][:30]
                    file_path = finding["file_path"][:30]

                    text_parts.append(
                        f"{finding['severity']:<10} "
                        f"{finding['scanner'][:15]:<15} "
                        f"{finding['rule_id'][:15]:<15} "
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
                    text_parts.append(f"Finding {i + 1}: {finding['title']}")
                    text_parts.append(f"Severity: {finding['severity']}")
                    text_parts.append(f"Scanner: {finding['scanner']}")
                    text_parts.append(f"Rule ID: {finding['rule_id']}")
                    text_parts.append(f"Location: {finding['location']}")

                    if finding["cve_id"]:
                        text_parts.append(f"CVE: {finding['cve_id']}")

                    if finding["cwe_id"]:
                        text_parts.append(f"CWE: {finding['cwe_id']}")

                    text_parts.append("")
                    text_parts.append("Description:")
                    text_parts.append(finding["description"])
                    text_parts.append("")

                    # Add a separator between findings
                    if i < len(detailed_findings) - 1:
                        text_parts.append("-" * 80)
                        text_parts.append("")

                # Add note if findings were limited
                if len(emitter.flat_vulns) > self.config.options.max_detailed_findings:
                    text_parts.append(
                        f"Note: Showing {self.config.options.max_detailed_findings} of {len(emitter.flat_vulns)} "
                        f"total findings. Configure 'max_detailed_findings' to adjust this limit."
                    )
                    text_parts.append("")

        # Add footer
        text_parts.append("-" * 80)
        text_parts.append(
            f"Report generated by Automated Security Helper (ASH) at {datetime.now(timezone.utc).isoformat(timespec='seconds')}"
        )

        # Join all parts with newlines
        return "\n".join(text_parts)
