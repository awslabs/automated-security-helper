# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime, timezone
from pydantic import BaseModel, ConfigDict, Field, field_validator

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_DOCS_URL, ASH_REPO_URL
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport
from automated_security_helper.schemas.data_interchange import (
    ReportMetadata,
)
from typing import Annotated, List, Dict, Any, Union
from automated_security_helper.models.core import BaseFinding, Scanner
from automated_security_helper.schemas.sarif_schema_model import (
    PropertyBag,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.log import ASH_LOGGER

__all__ = ["ASHARPModel"]


from automated_security_helper.models.aggregation import (
    FindingAggregator,
    TrendAnalyzer,
)


class ASHARPModel(BaseModel):
    """Main model class for parsing security scan reports from ASH tooling."""

    model_config = ConfigDict(str_strip_whitespace=True, arbitrary_types_allowed=True)

    name: str = Field(default="ASH Scan Report", description="Name of the report")
    description: str = Field(
        default="Automated Security Helper - Aggregated Report",
        description="The description of the generated report.",
    )
    metadata: ReportMetadata = Field(
        default_factory=lambda: ReportMetadata(
            report_id="ASH-" + datetime.now(timezone.utc).strftime("%Y%M%d"),
            project_name="ASH",
            tool_name="ASH",
            tool_version=get_ash_version(),
            description="Automated Security Helper Aggregated Report Post-processor",
        )
    )
    ash_config: Annotated[
        Any,
        Field(description="The full ASH configuration used during this scan."),
    ] = None
    sarif: Annotated[
        SarifReport | None,
        Field(description="The SARIF formatted vulnerability report"),
    ] = SarifReport(
        properties=PropertyBag(),
        runs=[
            Run(
                tool=Tool(
                    driver=ToolComponent(
                        name="ASH Aggregated Results",
                        fullName="awslabs/automated-security-helper",
                        version=get_ash_version(),
                        organization="Amazon Web Services",
                        downloadUri=ASH_REPO_URL,
                        informationUri=ASH_DOCS_URL,
                    )
                ),
                results=[],
                invocations=[],
                properties=PropertyBag(),
            )
        ],
    )
    sbom: Annotated[
        CycloneDXReport | None,
        Field(description="The CycloneDXReport formatted SBOM report"),
    ] = CycloneDXReport()
    additional_reports: Annotated[
        Dict[str, Any],
        Field(
            description="Dictionary of additional reports where the keys are the scanner name and the values are the outputs of the scanner."
        ),
    ] = {}
    scanners_used: Annotated[
        List[Scanner], Field(description="List of scanners used in this report")
    ] = []

    @field_validator("ash_config")
    def validate_ash_config(cls, v: any):
        from automated_security_helper.config.ash_config import ASHConfig

        try:
            return ASHConfig.model_validate(v)
        except Exception as e:
            ASH_LOGGER.error(f"Failed to validate ASH config: {e}")
        return get_default_config()

    def model_post_init(self, context):
        self._aggregator = FindingAggregator()
        self._trend_analyzer = TrendAnalyzer()
        # for finding in self.findings:
        #     self._aggregator.add_finding(finding)
        return super().model_post_init(context)

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

    def add_report(self, reporter: str, report: SarifReport | CycloneDXReport | str):
        """Add a report to the model.

        Args:
            report: The report to add. Can be a SarifReport, CycloneDXReport, or a JSON string.
        """
        if isinstance(report, SarifReport):
            self.sarif.merge_sarif_report(report)
        elif isinstance(report, CycloneDXReport):
            self.sbom = report
        elif isinstance(report, str):
            self.additional_reports[reporter] = report
        else:
            raise ValueError("Invalid report type")


if __name__ == "__main__":
    model = ASHARPModel()
    print(model.model_dump_json(indent=2))
