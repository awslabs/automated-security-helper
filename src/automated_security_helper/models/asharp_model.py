# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime, timezone
from pydantic import ConfigDict, Field
from automated_security_helper.models.data_interchange import (
    SecurityReport,
    ReportMetadata,
)
from typing import Annotated, List, Dict, Any, Union, Optional
from automated_security_helper.models.core import BaseFinding, Scanner

__all__ = ["ASHARPModel"]


from automated_security_helper.models.aggregation import (
    FindingAggregator,
    TrendAnalyzer,
)


class ASHARPModel(SecurityReport):
    """Main model class for parsing security scan reports from ASH tooling.

    This model is the primary interface for handling aggregated security findings from
    various scanners. It supports both legacy scanner formats and the newer
    scanners_used format.

    Example:

    ```python
    with open('aggregated_results.json', 'r') as f:
        report = ASHARPModel.from_json(f.read())
    print(f"Found {len(report.findings)} security findings")
    for scanner in report.scanners_used:
        print(f"Used scanner: {scanner['name']} v{scanner['version']}")
    ```
    """

    model_config = ConfigDict(str_strip_whitespace=True, arbitrary_types_allowed=True)

    name: str = Field(default="ASHARP Report", description="Name of the report")
    description: str = Field(
        default="AWS Security Hub Aggregated Report",
        description="Description of the report",
    )
    metadata: ReportMetadata = Field(
        default_factory=lambda: ReportMetadata(
            report_id="ASHARP-" + datetime.now(timezone.utc).strftime("%Y%M%d"),
            project_name="ASHARP",
            tool_name="ASHARP",
            tool_version="1.0.0",
            description="AWS Security Hub Aggregated Report Post-processor",
        )
    )
    findings: List[BaseFinding] = Field(
        default_factory=list, description="List of security findings from all scanners"
    )
    scanners_used: Annotated[
        List[Scanner], Field(description="List of scanners used in this report")
    ] = []
    _scanners_used_raw: Optional[List[Dict[str, str]]] = None

    def __init__(self, **data):
        super().__init__(**data)
        self._aggregator = FindingAggregator()
        self._trend_analyzer = TrendAnalyzer()
        for finding in self.findings:
            self._aggregator.add_finding(finding)

    def deduplicate_findings(self) -> List[BaseFinding]:
        """Remove duplicate findings based on key attributes."""
        deduped = self._aggregator.deduplicate()
        self.findings = deduped
        return deduped

    def group_findings_by_type(self) -> Dict[str, List[BaseFinding]]:
        """Group findings by their scanner rule ID."""
        return self._aggregator.group_by_type()

    def group_findings_by_severity(self) -> Dict[str, List[BaseFinding]]:
        """Group findings by their severity level."""
        return self._aggregator.group_by_severity()

    def add_scan_findings(self, scan_time: datetime):
        """Add current findings to trend analysis."""
        self._trend_analyzer.add_scan_findings(scan_time, self.findings)

    def get_finding_counts_over_time(self) -> Dict[datetime, int]:
        """Get the count of findings at each scan time."""
        return self._trend_analyzer.get_finding_counts_over_time()

    def get_severity_trends(self) -> Dict[str, Dict[datetime, int]]:
        """Get finding counts by severity over time."""
        return self._trend_analyzer.get_severity_trends()

    def get_new_findings(
        self, previous_scan: datetime, current_scan: datetime
    ) -> List[BaseFinding]:
        """Get findings that appeared in current scan but not in previous scan."""
        return self._trend_analyzer.get_new_findings(previous_scan, current_scan)

    def get_resolved_findings(
        self, previous_scan: datetime, current_scan: datetime
    ) -> List[BaseFinding]:
        """Get findings that were in previous scan but not in current scan."""
        return self._trend_analyzer.get_resolved_findings(previous_scan, current_scan)

    def _convert_to_scanner(self, scanner_dict: Dict[str, str]) -> Scanner:
        """Convert a scanner dictionary to Scanner object."""
        # Ensure required fields with defaults
        scanner_dict_copy = scanner_dict.copy()
        required_fields = {
            "type": "SAST",
            "version": "1.0.0",
            "description": "Security scanner",
        }
        for field, default in required_fields.items():
            if field not in scanner_dict_copy:
                scanner_dict_copy[field] = default

        return Scanner(
            name=scanner_dict_copy["name"],
            version=scanner_dict_copy["version"],
            type=scanner_dict_copy["type"],
            description=scanner_dict_copy["description"],
            rule_id=scanner_dict_copy["rule_id"],
        )

    @property
    def scanners(self) -> List[Scanner]:
        """Get scanners as Scanner objects for backward compatibility.

        Returns:
            List[Scanner]: List of Scanner objects converted from scanners_used data.
                Returns empty list if no scanners are defined.
        """
        if not hasattr(self, "_scanners"):
            self._scanners = self.scanners_used if self.scanners_used else []
        return self._scanners.copy()  # Return copy to prevent modification

    @classmethod
    def from_json(cls, json_data: Union[str, Dict[str, Any]]) -> "ASHARPModel":
        """Parse JSON data into an ASHARPModel instance.

        Args:
            json_data: Either a JSON string or dictionary containing the report data.
                Must include metadata and findings fields.

        Returns:
            ASHARPModel instance populated with the report data.

        Raises:
            ValidationError: If the JSON data is missing required fields or has invalid values.
        """
        if isinstance(json_data, str):
            return cls.model_validate_json(json_data)
        return cls.model_validate(json_data)
