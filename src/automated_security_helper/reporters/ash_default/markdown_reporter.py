# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime, timezone
from typing import Any, Literal
from collections import Counter
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.core.constants import ASH_DEFAULT_SEVERITY_LEVEL


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
    extension: str = "md"
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
        from automated_security_helper.config.ash_config import AshConfig

        if not isinstance(model, ASHARPModel):
            raise ValueError(f"{self.__class__.__name__} only supports ASHARPModel")

        # Get flattened vulnerabilities for easier processing
        flat_vulns = model.to_flat_vulnerabilities()

        # Build the markdown report
        md_parts = []

        # Add report header
        md_parts.append(
            f"# ASH Security Scan Report\nReport run time: {datetime.now(timezone.utc).strftime('%Y-%m-%d - %H:%M (UTC)')}\n"
        )

        # Add metadata section
        md_parts.append("## Scan Metadata\n")
        md_parts.append(f"- **Project**: {model.metadata.project_name or 'Unknown'}")
        md_parts.append(f"- **Generated**: {model.metadata.generated_at or 'Unknown'}")
        md_parts.append(
            f"- **Tool Version**: {model.metadata.tool_version or 'Unknown'}"
        )
        md_parts.append("")

        # Add summary section if enabled
        if self.config.options.include_summary:
            md_parts.append("## Summary\n")

            # Get global severity threshold from config
            global_threshold = ASH_DEFAULT_SEVERITY_LEVEL
            try:
                ash_conf: AshConfig = model.ash_config
            except Exception:
                ash_conf = AshConfig()

            # Check for global_settings.severity_threshold
            if (
                ash_conf
                and hasattr(ash_conf, "global_settings")
                and hasattr(ash_conf.global_settings, "severity_threshold")
            ):
                global_threshold = ash_conf.global_settings.severity_threshold

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

            # Group findings by scanner
            scanner_findings = {}
            for vuln in flat_vulns:
                scanner = vuln.scanner or "Unknown"
                if scanner not in scanner_findings:
                    scanner_findings[scanner] = {
                        "CRITICAL": 0,
                        "HIGH": 0,
                        "MEDIUM": 0,
                        "LOW": 0,
                        "INFO": 0,
                    }

                severity = vuln.severity or "UNKNOWN"
                if severity in scanner_findings[scanner]:
                    scanner_findings[scanner][severity] += 1

            # Get all scanners from ash_conf
            all_scanners = set()

            # Add scanners from findings
            for scanner in scanner_findings.keys():
                all_scanners.add(scanner)

            # Add scanners from config
            if ash_conf and hasattr(ash_conf, "scanners"):
                for scanner_name in ash_conf.scanners.model_dump(by_alias=True).keys():
                    all_scanners.add(scanner_name)

            # Process each scanner's results
            for scanner_name in sorted(all_scanners):
                # Get scanner-specific configuration
                scanner_config_entry = ash_conf.get_plugin_config(
                    plugin_type="scanner",
                    plugin_name=scanner_name,
                )

                # Skip disabled scanners
                if (
                    scanner_config_entry
                    and hasattr(scanner_config_entry, "enabled")
                    and not scanner_config_entry.enabled
                ):
                    continue

                # Initialize scanner_threshold to None
                scanner_threshold = None
                scanner_threshold_def = "global"

                # Check for scanner-specific configuration overrides
                if (
                    scanner_config_entry
                    and isinstance(scanner_config_entry, dict)
                    and "options" in scanner_config_entry
                ):
                    options = scanner_config_entry["options"]
                    if (
                        "severity_threshold" in options
                        and options["severity_threshold"] is not None
                    ):
                        scanner_threshold = options["severity_threshold"]
                        scanner_threshold_def = "config"
                elif scanner_config_entry and hasattr(scanner_config_entry, "options"):
                    if hasattr(scanner_config_entry.options, "severity_threshold"):
                        scanner_threshold_from_config = (
                            scanner_config_entry.options.severity_threshold
                        )
                        if scanner_threshold_from_config is not None:
                            scanner_threshold = scanner_threshold_from_config
                            scanner_threshold_def = "config"

                # Get severity counts for this scanner
                severity_counts = scanner_findings.get(
                    scanner_name,
                    {
                        "CRITICAL": 0,
                        "HIGH": 0,
                        "MEDIUM": 0,
                        "LOW": 0,
                        "INFO": 0,
                    },
                )

                # Calculate total findings
                critical = severity_counts.get("CRITICAL", 0)
                high = severity_counts.get("HIGH", 0)
                medium = severity_counts.get("MEDIUM", 0)
                low = severity_counts.get("LOW", 0)
                info = severity_counts.get("INFO", 0)
                total = critical + high + medium + low + info

                # Use scanner-specific threshold for evaluation if available, otherwise use global
                evaluation_threshold = (
                    scanner_threshold
                    if scanner_threshold is not None
                    else global_threshold
                )

                # Determine status based on the appropriate severity threshold
                status = "✅ Passed"
                if evaluation_threshold == "ALL":
                    if total > 0:
                        status = "❌ Failed"
                elif evaluation_threshold == "LOW":
                    if critical > 0 or high > 0 or medium > 0 or low > 0:
                        status = "❌ Failed"
                elif evaluation_threshold == "MEDIUM":
                    if critical > 0 or high > 0 or medium > 0:
                        status = "❌ Failed"
                elif evaluation_threshold == "HIGH":
                    if critical > 0 or high > 0:
                        status = "❌ Failed"
                elif evaluation_threshold == "CRITICAL":
                    if critical > 0:
                        status = "❌ Failed"

                # Format the threshold for display
                threshold_text = f"{evaluation_threshold} ({scanner_threshold_def})"

                # Add row to table
                md_parts.append(
                    f"| {scanner_name} | {critical} | {high} | {medium} | {low} | {info} | {total} | {status} | {threshold_text} |"
                )

            md_parts.append("")

            # Add top hotspots (files with most findings)
            if flat_vulns:
                # Count findings by file location
                location_counts = Counter()
                for vuln in flat_vulns:
                    if vuln.file_path:
                        location_counts[vuln.file_path] += 1

                # Get top hotspots
                top_limit = self.config.options.top_hotspots_limit
                top_hotspots = location_counts.most_common(top_limit)

                if top_hotspots:
                    md_parts.append(
                        f"### Top {min(top_limit, len(top_hotspots))} Hotspots\n"
                    )
                    md_parts.append(
                        "Files with the highest number of security findings:\n"
                    )
                    md_parts.append("| File Location | Finding Count |")
                    md_parts.append("| --- | ---: |")
                    for location, count in top_hotspots:
                        # Escape pipe characters in markdown table
                        safe_location = location.replace("|", "\\|")
                        md_parts.append(f"| {safe_location} | {count} |")
                    md_parts.append("")

        # Add findings table if enabled
        if self.config.options.include_findings_table and flat_vulns:
            md_parts.append("## Findings Overview\n")
            md_parts.append("| Severity | Scanner | Rule ID | Title | File |")
            md_parts.append("| --- | --- | --- | --- | --- |")

            for vuln in flat_vulns:
                severity = vuln.severity or "UNKNOWN"
                scanner = vuln.scanner or "Unknown"
                rule_id = vuln.rule_id or "N/A"
                title = vuln.title or "Unknown Issue"
                file_path = vuln.file_path or "N/A"

                # Escape pipe characters in markdown table
                title = title.replace("|", "\\|")
                file_path = file_path.replace("|", "\\|")

                md_parts.append(
                    f"| {severity} | {scanner} | {rule_id} | {title} | {file_path} |"
                )

            md_parts.append("")

        # Add detailed findings if enabled
        if self.config.options.include_detailed_findings and flat_vulns:
            # Determine if we should use collapsible details
            use_collapsible = self.config.options.use_collapsible_details

            # Limit the number of detailed findings to avoid overly large reports
            findings_to_show = flat_vulns[: self.config.options.max_detailed_findings]
            findings_count = len(findings_to_show)
            total_findings = len(flat_vulns)

            # Start the detailed findings section with the header outside the collapsible element
            md_parts.append("<h2>Detailed Findings</h2>\n")

            if use_collapsible:
                # Create a collapsible section with HTML details/summary tags
                md_parts.append("<details>")
                md_parts.append(
                    f"<summary>Show {findings_count}{' of ' + str(total_findings) if findings_count < total_findings else ''} detailed findings</summary>\n"
                )

            # Add each finding
            for i, vuln in enumerate(findings_to_show):
                md_parts.append(f"### Finding {i + 1}: {vuln.title}\n")
                md_parts.append(f"- **Severity**: {vuln.severity or 'UNKNOWN'}")
                md_parts.append(f"- **Scanner**: {vuln.scanner or 'Unknown'}")
                md_parts.append(f"- **Rule ID**: {vuln.rule_id or 'N/A'}")

                if vuln.file_path:
                    location = vuln.file_path
                    if vuln.line_start:
                        location += f":{vuln.line_start}"
                        if vuln.line_end and vuln.line_end != vuln.line_start:
                            location += f"-{vuln.line_end}"
                    md_parts.append(f"- **Location**: {location}")

                if vuln.cve_id:
                    md_parts.append(f"- **CVE**: {vuln.cve_id}")

                if vuln.cwe_id:
                    md_parts.append(f"- **CWE**: {vuln.cwe_id}")

                md_parts.append("\n**Description**:")
                md_parts.append(f"{vuln.description}\n")

                # Add a separator between findings
                if i < len(findings_to_show) - 1:
                    md_parts.append("---\n")

            # Add note if findings were limited
            if len(flat_vulns) > self.config.options.max_detailed_findings:
                md_parts.append(
                    f"\n> Note: Showing {self.config.options.max_detailed_findings} of {len(flat_vulns)} total findings. Configure `max_detailed_findings` to adjust this limit.\n"
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
