# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime, timezone
from typing import Dict, List, Any
from collections import Counter


class ReportContentEmitter:
    """
    A reusable class for generating report content from ASHARPModel.
    This class provides methods to generate different sections of a report
    that can be used by different reporter implementations.
    """

    def __init__(self, model: Any):
        """Initialize with an ASHARPModel."""
        from automated_security_helper.models.asharp_model import ASHARPModel

        if not isinstance(model, ASHARPModel):
            raise ValueError("ReportContentEmitter only supports ASHARPModel")

        from automated_security_helper.core.constants import ASH_DEFAULT_SEVERITY_LEVEL
        from automated_security_helper.config.ash_config import AshConfig

        self.model = model
        self.flat_vulns = model.to_flat_vulnerabilities()

        # Try to get ASH config from model
        try:
            self.ash_conf: AshConfig = model.ash_config
        except Exception:
            self.ash_conf = AshConfig()

        # Get global severity threshold
        self.global_threshold = ASH_DEFAULT_SEVERITY_LEVEL
        if (
            self.ash_conf
            and hasattr(self.ash_conf, "global_settings")
            and hasattr(self.ash_conf.global_settings, "severity_threshold")
        ):
            self.global_threshold = self.ash_conf.global_settings.severity_threshold

    def get_metadata(self) -> Dict[str, str]:
        """Get report metadata as a dictionary."""
        return {
            "project": self.model.metadata.project_name or "Unknown",
            "generated_at": self.model.metadata.generated_at or "Unknown",
            "tool_version": self.model.metadata.tool_version or "Unknown",
            "current_time": datetime.now(timezone.utc).strftime(
                "%Y-%m-%d - %H:%M (UTC)"
            ),
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

        # Process each scanner's results
        results = []
        for scanner_name in sorted(all_scanners):
            # Get scanner-specific configuration
            scanner_config_entry = self.ash_conf.get_plugin_config(
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
                else self.global_threshold
            )

            # Determine status based on the appropriate severity threshold
            passed = True
            if evaluation_threshold == "ALL":
                if total > 0:
                    passed = False
            elif evaluation_threshold == "LOW":
                if critical > 0 or high > 0 or medium > 0 or low > 0:
                    passed = False
            elif evaluation_threshold == "MEDIUM":
                if critical > 0 or high > 0 or medium > 0:
                    passed = False
            elif evaluation_threshold == "HIGH":
                if critical > 0 or high > 0:
                    passed = False
            elif evaluation_threshold == "CRITICAL":
                if critical > 0:
                    passed = False

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
                }
            )

        return results

    def get_top_hotspots(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top hotspots (files with most findings)."""
        if not self.flat_vulns:
            return []

        # Count findings by file location
        location_counts = Counter()
        for vuln in self.flat_vulns:
            if vuln.file_path:
                location_counts[vuln.file_path] += 1

        # Get top hotspots
        top_hotspots = location_counts.most_common(limit)

        return [
            {"location": location, "count": count} for location, count in top_hotspots
        ]

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
        """Get detailed information for findings, limited to max_findings."""
        if not self.flat_vulns:
            return []

        # Limit the number of detailed findings
        findings_to_show = self.flat_vulns[:max_findings]

        detailed_findings = []
        for vuln in findings_to_show:
            location = vuln.file_path or "N/A"
            if vuln.file_path and vuln.line_start:
                location += f":{vuln.line_start}"
                if vuln.line_end and vuln.line_end != vuln.line_start:
                    location += f"-{vuln.line_end}"

            finding = {
                "title": vuln.title or "Unknown Issue",
                "severity": vuln.severity or "UNKNOWN",
                "scanner": vuln.scanner or "Unknown",
                "rule_id": vuln.rule_id or "N/A",
                "location": location,
                "description": vuln.description or "",
                "cve_id": vuln.cve_id,
                "cwe_id": vuln.cwe_id,
            }
            detailed_findings.append(finding)

        return detailed_findings
