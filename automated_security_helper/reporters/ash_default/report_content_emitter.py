# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime, timezone
import json
from typing import Dict, List, Any, TYPE_CHECKING

from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.core.constants import ASH_DEFAULT_SEVERITY_LEVEL
from collections import Counter


class ReportContentEmitter:
    """
    A reusable class for generating report content from AshAggregatedResults.
    This class provides methods to generate different sections of a report
    that can be used by different reporter implementations.
    """

    def __init__(self, model: "AshAggregatedResults"):
        """Initialize with an AshAggregatedResults."""
        self.model = model
        self.flat_vulns = model.to_flat_vulnerabilities()
        self.ash_conf = model.ash_config

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
                # Try to parse the scan time string to calculate delta
                # Handle different possible formats
                for fmt in [
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d - %H:%M (UTC)",
                    "%Y-%m-%d %H:%M:%S",
                ]:
                    try:
                        scan_time = datetime.strptime(
                            scan_time_str.split("+")[0].split(".")[0], fmt
                        )
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
        # Group findings by scanner
        scanner_findings = {}
        for vuln in self.flat_vulns:
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

        # Get all scanners
        all_scanners = set()

        # Add scanners from findings
        for scanner in scanner_findings.keys():
            all_scanners.add(scanner)

        # Add scanners from config
        if self.ash_conf and hasattr(self.ash_conf, "scanners"):
            for scanner_name in self.ash_conf.scanners.model_dump(by_alias=True).keys():
                all_scanners.add(scanner_name)

        # Add scanners from metadata.scanner_status
        if hasattr(self.model.metadata, "scanner_status"):
            for scanner_name in self.model.metadata.scanner_status.keys():
                all_scanners.add(scanner_name)

        # Add scanners from additional_reports
        for scanner_name in self.model.additional_reports.keys():
            all_scanners.add(scanner_name)

        # Process each scanner's results
        results = []
        for scanner_name in sorted(all_scanners):
            # Get scanner-specific configuration
            scanner_config_entry = self.ash_conf.get_plugin_config(
                plugin_type="scanner",
                plugin_name=scanner_name,
            )

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
                else self.global_threshold
            )

            # Calculate actionable findings
            actionable = self.calculate_actionable_count(
                critical, high, medium, low, info, evaluation_threshold
            )

            # Get scanner results from additional_reports
            scanner_results = None
            if scanner_name in self.model.additional_reports:
                scanner_results = self.model.additional_reports[scanner_name]

            # Determine scanner status
            status, scanner_excluded, dependencies_missing = (
                self.determine_scanner_status(
                    scanner_name, scanner_results=scanner_results, actionable=actionable
                )
            )

            # Skip disabled scanners that aren't explicitly excluded or missing dependencies
            if (
                not scanner_excluded
                and not dependencies_missing
                and scanner_config_entry
                and hasattr(scanner_config_entry, "enabled")
                and not scanner_config_entry.enabled
            ):
                continue

            # Determine if passed based on status
            passed = status in ["PASSED", "SKIPPED", "MISSING"]

            # Add result to list
            results.append(
                {
                    "scanner_name": scanner_name,
                    "critical": critical,
                    "high": high,
                    "medium": medium,
                    "low": low,
                    "info": info,
                    "total": total,
                    "passed": passed,
                    "threshold": evaluation_threshold,
                    "threshold_source": scanner_threshold_def,
                    "actionable": actionable,
                    "status": status,
                    "excluded": scanner_excluded,
                    "dependencies_missing": dependencies_missing,
                }
            )

        return results

        return results

    def calculate_actionable_count(self, critical, high, medium, low, info, threshold):
        """Calculate the number of actionable findings based on the threshold."""
        if threshold == "ALL":
            return critical + high + medium + low + info
        elif threshold == "LOW":
            return critical + high + medium + low
        elif threshold == "MEDIUM":
            return critical + high + medium
        elif threshold == "HIGH":
            return critical + high
        elif threshold == "CRITICAL":
            return critical
        return 0

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

    def is_finding_actionable(self, vuln) -> bool:
        """Determine if a finding is actionable based on severity threshold."""
        # Get scanner-specific threshold if available
        scanner_name = vuln.scanner or "Unknown"
        scanner_config_entry = self.ash_conf.get_plugin_config(
            plugin_type="scanner",
            plugin_name=scanner_name,
        )

        # Initialize scanner_threshold to None
        scanner_threshold = None

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
        elif scanner_config_entry and hasattr(scanner_config_entry, "options"):
            if hasattr(scanner_config_entry.options, "severity_threshold"):
                scanner_threshold_from_config = (
                    scanner_config_entry.options.severity_threshold
                )
                if scanner_threshold_from_config is not None:
                    scanner_threshold = scanner_threshold_from_config

        # Use scanner-specific threshold for evaluation if available, otherwise use global
        evaluation_threshold = (
            scanner_threshold
            if scanner_threshold is not None
            else self.global_threshold
        )

        # Get the severity of the finding
        severity = vuln.severity or "UNKNOWN"

        # Determine if the finding is actionable based on the threshold
        if evaluation_threshold == "ALL":
            return True
        elif evaluation_threshold == "LOW":
            return severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        elif evaluation_threshold == "MEDIUM":
            return severity in ["CRITICAL", "HIGH", "MEDIUM"]
        elif evaluation_threshold == "HIGH":
            return severity in ["CRITICAL", "HIGH"]
        elif evaluation_threshold == "CRITICAL":
            return severity == "CRITICAL"

        # Default case
        return False

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
        findings_to_show = actionable_findings[:max_findings]

        detailed_findings = []
        for vuln in findings_to_show:
            location = vuln.file_path or "N/A"
            if vuln.file_path and vuln.line_start:
                location += f":{vuln.line_start}"
                if vuln.line_end and vuln.line_end != vuln.line_start:
                    location += f"-{vuln.line_end}"

            # Use the code_snippet field if available
            code_snippet = vuln.code_snippet

            # If no snippet is directly available, try to extract from raw data
            if not code_snippet and vuln.raw_data:
                try:
                    raw_data = json.loads(vuln.raw_data)
                    # Look for snippet in different possible locations based on scanner format
                    if isinstance(raw_data, dict):
                        # Try to find snippet in common locations
                        if "snippet" in raw_data:
                            code_snippet = raw_data["snippet"]
                        elif "codeFlows" in raw_data and raw_data["codeFlows"]:
                            for flow in raw_data["codeFlows"]:
                                if "threadFlows" in flow and flow["threadFlows"]:
                                    for thread in flow["threadFlows"]:
                                        if (
                                            "locations" in thread
                                            and thread["locations"]
                                        ):
                                            for loc in thread["locations"]:
                                                if "snippet" in loc:
                                                    code_snippet = loc["snippet"][
                                                        "text"
                                                    ]
                                                    break
                        # For SARIF format
                        elif "message" in raw_data and "text" in raw_data["message"]:
                            # Some scanners include snippets in the message
                            if "```" in raw_data["message"]["text"]:
                                parts = raw_data["message"]["text"].split("```")
                                if len(parts) >= 3:  # Has at least one code block
                                    code_snippet = parts[1]
                except (json.JSONDecodeError, AttributeError, KeyError, TypeError):
                    # If we can't parse the raw data or find a snippet, just continue
                    pass

            finding = {
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
            detailed_findings.append(finding)

        return detailed_findings

    def determine_scanner_status(
        self, scanner_name, scanner_results=None, scanner_plugin=None, actionable=0
    ):
        """
        Determine the status of a scanner based on metadata, results, and plugin attributes.

        Args:
            scanner_name: Name of the scanner
            scanner_results: Optional dictionary of scanner results from additional_reports
            scanner_plugin: Optional scanner plugin instance
            actionable: Number of actionable findings

        Returns:
            tuple: (status, status_text, scanner_excluded, dependencies_missing)
                status: String status (PASSED, FAILED, MISSING, SKIPPED)
                scanner_excluded: Boolean indicating if scanner was excluded
                dependencies_missing: Boolean indicating if dependencies are missing
        """
        # Default values
        status = "PASSED"
        scanner_excluded = False
        dependencies_missing = False

        # First check if scanner status is in metadata (most accurate)
        if (
            hasattr(self.model.metadata, "scanner_status")
            and scanner_name in self.model.metadata.scanner_status
        ):
            scanner_status_info = self.model.metadata.scanner_status[scanner_name]

            if scanner_status_info.status == "SKIPPED":
                scanner_excluded = True
                status = "SKIPPED"
            elif scanner_status_info.status == "MISSING":
                dependencies_missing = True
                status = "MISSING"
            elif scanner_status_info.status == "FAILED":
                status = "FAILED"

        # Then check in additional_reports if not found in metadata
        elif scanner_results:
            # Check for excluded status or missing dependencies
            for target_type, results in scanner_results.items():
                if isinstance(results, dict):
                    if results.get("excluded", False):
                        scanner_excluded = True
                        status = "SKIPPED"
                        break
                    if not results.get("dependencies_satisfied", True):
                        dependencies_missing = True
                        status = "MISSING"
                        break
                    if "scanner_status" in results:
                        scanner_status = results["scanner_status"]
                        if scanner_status == "SKIPPED":
                            scanner_excluded = True
                            status = "SKIPPED"
                            break
                        elif scanner_status == "MISSING":
                            dependencies_missing = True
                            status = "MISSING"
                            break

        # Finally, check if scanner has dependencies_satisfied attribute directly
        if (
            not scanner_excluded
            and not dependencies_missing
            and scanner_plugin
            and hasattr(scanner_plugin, "dependencies_satisfied")
        ):
            if not scanner_plugin.dependencies_satisfied:
                dependencies_missing = True
                status = "MISSING"

        # If not excluded or missing dependencies, check for actionable findings
        if not scanner_excluded and not dependencies_missing and actionable > 0:
            status = "FAILED"

        return status, scanner_excluded, dependencies_missing
