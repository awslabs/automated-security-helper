# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime, timezone
import json
from typing import Dict, List, Any, TYPE_CHECKING

from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.core.unified_metrics import get_unified_scanner_metrics
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)

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

        # Get unified scanner metrics - always compute from the model to ensure consistency
        # The scanner_results in the model contain ScannerStatusInfo objects, not ScannerMetrics
        self.scanner_metrics = get_unified_scanner_metrics(model)

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
        # Convert scanner metrics to dictionary format for reporters
        results = []
        for metrics in self.scanner_metrics:
            results.append(
                {
                    "scanner_name": metrics.scanner_name,
                    "suppressed": metrics.suppressed,
                    "critical": metrics.critical,
                    "high": metrics.high,
                    "medium": metrics.medium,
                    "low": metrics.low,
                    "info": metrics.info,
                    "total": metrics.total,
                    "passed": metrics.passed,
                    "threshold": metrics.threshold,
                    "threshold_source": metrics.threshold_source,
                    "actionable": metrics.actionable,
                    "status": metrics.status,
                    "excluded": metrics.excluded,
                    "dependencies_missing": metrics.dependencies_missing,
                }
            )

        return results

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

    def is_finding_actionable(self, vuln: FlatVulnerability) -> bool:
        """Determine if a finding is actionable based on severity threshold."""
        # If finding is suppressed, it's not actionable
        if vuln.is_suppressed:
            return False

        # Get scanner name
        scanner_name = vuln.scanner or "Unknown"

        # Get threshold for this scanner
        threshold, _ = ScannerStatisticsCalculator.get_scanner_threshold_info(
            self.model, scanner_name
        )

        # Get the severity of the finding
        severity = vuln.severity or "UNKNOWN"

        # Determine if the finding is actionable based on the threshold
        return self._is_severity_actionable(severity, threshold)

    def _is_severity_actionable(self, severity: str, threshold: str) -> bool:
        """Helper method to determine if a severity level is actionable based on threshold."""
        # Use the centralized calculator to determine if the finding is actionable
        # Map the severity to counts for the calculator
        critical = 1 if severity == "CRITICAL" else 0
        high = 1 if severity == "HIGH" else 0
        medium = 1 if severity == "MEDIUM" else 0
        low = 1 if severity == "LOW" else 0
        info = 1 if severity in ["INFO", "UNKNOWN"] else 0

        # Use the centralized calculator
        return (
            ScannerStatisticsCalculator.calculate_actionable_count(
                critical, high, medium, low, info, threshold
            )
            > 0
        )

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

        return [self._create_detailed_finding(vuln) for vuln in findings_to_show]

    def _create_detailed_finding(self, vuln: FlatVulnerability) -> Dict[str, Any]:
        """Create a detailed finding dictionary from a vulnerability."""
        # Format location
        location = vuln.file_path or "N/A"
        if vuln.file_path and vuln.line_start:
            location += f":{vuln.line_start}"
            if vuln.line_end and vuln.line_end != vuln.line_start:
                location += f"-{vuln.line_end}"

        # Get code snippet
        code_snippet = self._extract_code_snippet(vuln)

        # Create finding dictionary
        return {
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

    def _extract_code_snippet(self, vuln: FlatVulnerability) -> str:
        """Extract code snippet from a vulnerability."""
        # Use the code_snippet field if available
        if vuln.code_snippet:
            return vuln.code_snippet

        # If no snippet is directly available, try to extract from raw data
        if not vuln.raw_data:
            return None

        try:
            raw_data = json.loads(vuln.raw_data)
            if not isinstance(raw_data, dict):
                return None

            # Try to find snippet in common locations
            if "snippet" in raw_data:
                return raw_data["snippet"]

            # Check in code flows
            if "codeFlows" in raw_data and raw_data["codeFlows"]:
                for flow in raw_data["codeFlows"]:
                    if "threadFlows" in flow and flow["threadFlows"]:
                        for thread in flow["threadFlows"]:
                            if "locations" in thread and thread["locations"]:
                                for loc in thread["locations"]:
                                    if "snippet" in loc:
                                        return loc["snippet"]["text"]

            # Check in message
            if "message" in raw_data and "text" in raw_data["message"]:
                message_text = raw_data["message"]["text"]
                if "```" in message_text:
                    parts = message_text.split("```")
                    if len(parts) >= 3:  # Has at least one code block
                        return parts[1]

        except (json.JSONDecodeError, AttributeError, KeyError, TypeError):
            # If we can't parse the raw data or find a snippet, return None
            pass

        return None
