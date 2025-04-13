"""Module containing aggregation functionality for security findings."""

from datetime import datetime
from typing import Dict, List

from automated_security_helper.models.core import BaseFinding


class FindingAggregator:
    """Aggregates and correlates findings from multiple scans."""

    def __init__(self):
        self.findings: List[BaseFinding] = []
        self._finding_keys = set()

    def add_finding(self, finding: BaseFinding) -> None:
        """Add a finding to be aggregated."""
        key = (
            finding.location.file_path,
            finding.location.start_line,
            finding.title,
            finding.description,
        )
        if key not in self._finding_keys:
            self.findings.append(finding)
            self._finding_keys.add(key)

    def deduplicate(self) -> List[BaseFinding]:
        """Remove duplicate findings based on key attributes.

        Deduplication is based on matching:
        - Location information
        - Scanner and rule information
        - Finding title and description
        """
        unique_findings = {}
        for finding in self.findings:
            key = (
                finding.location.file_path,
                finding.location.start_line,
                finding.title,
                finding.description,
            )
            if key not in unique_findings:
                unique_findings[key] = finding
        return list(unique_findings.values())

    def group_by_type(self) -> Dict[str, List[BaseFinding]]:
        """Group findings by their scanner rule ID."""
        groups = {}
        for finding in self.findings:
            rule_id = finding.id
            if rule_id not in groups:
                groups[rule_id] = []
            groups[rule_id].append(finding)
        return groups

    def group_by_severity(self) -> Dict[str, List[BaseFinding]]:
        """Group findings by their severity level."""
        groups = {}
        for finding in self.findings:
            if finding.severity not in groups:
                groups[finding.severity] = []
            groups[finding.severity].append(finding)
        return groups


class TrendAnalyzer:
    """Analyzes finding trends over time."""

    def __init__(self):
        self.scan_history: Dict[datetime, List[BaseFinding]] = {}
        self._finding_keys: Dict[datetime, set] = {}

    def add_scan_findings(
        self, scan_time: datetime, findings: List[BaseFinding]
    ) -> None:
        """Add findings from a scan at a specific time."""
        self.scan_history[scan_time] = []
        self._finding_keys[scan_time] = set()

        for finding in findings:
            key = (
                finding.location.file_path,
                finding.location.start_line,
                finding.title,
                finding.description,
            )
            if key not in self._finding_keys[scan_time]:
                self.scan_history[scan_time].append(finding)
                self._finding_keys[scan_time].add(key)

    def get_finding_counts_over_time(self) -> Dict[datetime, int]:
        """Get the count of findings at each scan time."""
        return {time: len(findings) for time, findings in self.scan_history.items()}

    def get_severity_trends(self) -> Dict[str, Dict[datetime, int]]:
        """Get finding counts by severity over time."""
        trends = {}
        for scan_time, findings in self.scan_history.items():
            for finding in findings:
                if finding.severity not in trends:
                    trends[finding.severity] = {}
                if scan_time not in trends[finding.severity]:
                    trends[finding.severity][scan_time] = 0
                trends[finding.severity][scan_time] += 1
        return trends

    def get_new_findings(
        self, previous_scan: datetime, current_scan: datetime
    ) -> List[BaseFinding]:
        """Get findings that appeared in current scan but not in previous scan."""
        if (
            previous_scan not in self.scan_history
            or current_scan not in self.scan_history
        ):
            raise KeyError("Scan times not found in history")

        prev_findings = set(
            (
                f.location.file_path,
                f.location.start_line,
                f.title,
                f.description,
            )
            for f in self.scan_history[previous_scan]
        )
        current_findings = self.scan_history[current_scan]

        return [
            f
            for f in current_findings
            if (
                f.location.file_path,
                f.location.start_line,
                f.title,
                f.description,
            )
            not in prev_findings
        ]

    def get_resolved_findings(
        self, previous_scan: datetime, current_scan: datetime
    ) -> List[BaseFinding]:
        """Get findings that were in previous scan but not in current scan."""
        if (
            previous_scan not in self.scan_history
            or current_scan not in self.scan_history
        ):
            raise KeyError("Scan times not found in history")

        current_findings = set(
            (
                f.location.file_path,
                f.location.start_line,
                f.title,
                f.description,
            )
            for f in self.scan_history[current_scan]
        )
        prev_findings = self.scan_history[previous_scan]

        return [
            f
            for f in prev_findings
            if (
                f.location.file_path,
                f.location.start_line,
                f.title,
                f.description,
            )
            not in current_findings
        ]
