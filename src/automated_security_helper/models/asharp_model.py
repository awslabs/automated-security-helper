# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime, timezone
import json
from pathlib import Path
from pydantic import BaseModel, ConfigDict, Field, field_validator

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_DOCS_URL, ASH_REPO_URL
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport
from typing import Annotated, List, Dict, Any, Optional, Union
from automated_security_helper.models.core import ExportFormat
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


class ReportMetadata(BaseModel):
    """Metadata for security reports."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="allow",
        arbitrary_types_allowed=True,
        json_encoders={
            datetime: lambda v: v.isoformat(),
            ExportFormat: lambda v: str(v),
        },
    )

    report_id: Annotated[
        str,
        Field(
            min_length=1,
            pattern=r"^[A-Za-z][\/\.\w-]+$",
            description="Unique identifier for the report",
        ),
    ] = None
    generated_at: Annotated[str, Field()] = None
    project_name: Annotated[
        str, Field(min_length=1, description="Name of the project being scanned")
    ] = None
    tool_version: Annotated[
        str, Field(min_length=1, description="Version of the security tool")
    ] = None
    description: Annotated[
        str, Field(min_length=1, description="Description of the tool/scan")
    ] = None
    summary_stats: Annotated[
        Dict[str, int],
        Field(description="Summary statistics (e.g., count by severity)"),
    ] = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    @field_validator("project_name")
    @classmethod
    def validate_non_empty_str(cls, v: str, info) -> str:
        """Validate string fields are not empty."""
        v = v.strip()
        if not v:
            raise ValueError(f"{info.field_name} cannot be empty")
        return v

    @field_validator("generated_at")
    @classmethod
    def validate_datetime(cls, v: Union[str, datetime] = None) -> str:
        """Validate that value is timestamp or, if empty, set to current datetime"""
        if not v:
            v = datetime.now(timezone.utc)
        if isinstance(v, str):
            v = datetime.fromisoformat(v.strip())
        return v.isoformat(timespec="seconds")

    def model_post_init(self, context):
        super().model_post_init(context)
        default_timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if not self.generated_at:
            self.generated_at = default_timestamp
        if not self.report_id:
            self.report_id = (
                f"ASH-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
            )


# from automated_security_helper.models.aggregation import (
#     FindingAggregator,
#     TrendAnalyzer,
# )


class ASHARPModel(BaseModel):
    """Main model class for parsing security scan reports from ASH tooling."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        exclude={"_aggregator", "_trend_analyzer", "_scanners"},
    )

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
                    ),
                    extensions=[
                        # Tool(
                        #     driver=ToolComponent(
                        #         name="Bandit",
                        #         organization="PyCQA",
                        #         version=version("bandit"),
                        #         language="Python",
                        #         rules=[
                        #             ReportingDescriptor(
                        #                 id="B101",
                        #                 shortDescription="Assert used",
                        #                 fullDescription="Use of assert detected. The enclosed code will be removed when compiling to optimized byte code.",
                        #                 properties=PropertyBag(
                        #                     tags=["security", "bandit", "B101"]
                        #                 ),
                        #             ),
                        #             ReportingDescriptor(
                        #                 id="B103",
                        #                 shortDescription="Assert always true",
                        #                 fullDescription="Assert always true",
                        #                 properties=PropertyBag(
                        #                     tags=["security", "bandit", "B103"]
                        #                 ),
                        #             ),
                        #         ],
                        #     ),
                        # ),
                        # Tool(
                        #     driver=ToolComponent(
                        #         name="Checkov",
                        #         organization="Bridgecrew",
                        #         version=version("checkov"),
                        #         language="all",
                        #     ),
                        # ),
                    ],
                ),
                results=[],
                invocations=[],
                properties=PropertyBag(),
            )
        ],
    )
    cyclonedx: Annotated[
        CycloneDXReport | None,
        Field(description="The CycloneDXReport formatted SBOM report"),
    ] = CycloneDXReport()
    additional_reports: Annotated[
        Dict[str, Any],
        Field(
            description="Dictionary of additional reports where the keys are the scanner name and the values are the outputs of the scanner."
        ),
    ] = {}

    @field_validator("ash_config")
    def validate_ash_config(cls, v: any):
        from automated_security_helper.config.ash_config import ASHConfig

        try:
            return ASHConfig.model_validate(v)
        except Exception as e:
            ASH_LOGGER.error(f"Failed to validate ASH config: {e}")
        return get_default_config()

    def model_post_init(self, context):
        """Initialize aggregator and trend analyzer with current findings."""
        # self._aggregator = FindingAggregator()
        # self._trend_analyzer = TrendAnalyzer()
        # for finding in self.findings:
        #     self._aggregator.add_finding(finding)
        return super().model_post_init(context)

    # def add_finding(self, finding: BaseFinding) -> None:
    #     """Add a new finding to both the findings list and aggregator."""
    #     self.findings.append(finding)
    #     self._aggregator.add_finding(finding)

    # def deduplicate_findings(self) -> List[BaseFinding]:
    #     """Remove duplicate findings based on key attributes."""
    #     deduped = self._aggregator.deduplicate()
    #     self.findings = deduped
    #     return deduped

    # def group_findings_by_type(self) -> Dict[str, List[BaseFinding]]:
    #     """Group findings by their scanner rule ID."""
    #     return self._aggregator.group_by_type()

    # def group_findings_by_severity(self) -> Dict[str, List[BaseFinding]]:
    #     """Group findings by their severity level."""
    #     return self._aggregator.group_by_severity()

    # def add_scan_findings(self, scan_time: datetime):
    #     """Add current findings to trend analysis."""
    #     self._trend_analyzer.add_scan_findings(scan_time, self.findings)

    # def get_finding_counts_over_time(self) -> Dict[datetime, int]:
    #     """Get the count of findings at each scan time."""
    #     return self._trend_analyzer.get_finding_counts_over_time()

    # def get_severity_trends(self) -> Dict[str, Dict[datetime, int]]:
    #     """Get finding counts by severity over time."""
    #     return self._trend_analyzer.get_severity_trends()

    # def get_new_findings(
    #     self, previous_scan: datetime, current_scan: datetime
    # ) -> List[BaseFinding]:
    #     """Get findings that appeared in current scan but not in previous scan."""
    #     return self._trend_analyzer.get_new_findings(previous_scan, current_scan)

    # def get_resolved_findings(
    #     self, previous_scan: datetime, current_scan: datetime
    # ) -> List[BaseFinding]:
    #     """Get findings that were in previous scan but not in current scan."""
    #     return self._trend_analyzer.get_resolved_findings(previous_scan, current_scan)

    # def _convert_to_scanner(self, scanner_dict: Dict[str, str]) -> Scanner:
    #     """Convert a scanner dictionary to Scanner object."""
    #     # Ensure required fields with defaults
    #     scanner_dict_copy = scanner_dict.copy()
    #     required_fields = {
    #         "type": "SAST",
    #         "version": "1.0.0",
    #         "description": "Security scanner",
    #     }
    #     for field, default in required_fields.items():
    #         if field not in scanner_dict_copy:
    #             scanner_dict_copy[field] = default

    #     return Scanner(
    #         name=scanner_dict_copy["name"],
    #         version=scanner_dict_copy["version"],
    #         type=scanner_dict_copy["type"],
    #         description=scanner_dict_copy["description"],
    #     )

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

    def save_model(self, output_dir: Path) -> None:
        """Save ASHARPModel as JSON alongside aggregated results."""
        if not output_dir.exists():
            output_dir.mkdir(parents=True)

        # Save aggregated results as JSON
        json_path = output_dir.joinpath("ash_aggregated_results.json")
        with open(json_path, "w") as f:
            json.dump(self.model_dump(by_alias=True), f, indent=2, default=str)

        # Save model.sarif as ash.sarif (JSON formatted SARIF report)
        json_path = output_dir.joinpath("ash.sarif")
        with open(json_path, "w") as f:
            json.dump(self.sarif.model_dump(by_alias=True), f, indent=2, default=str)

        # Save model.sbom as ash.cdx.json (JSON formatted CycloneDX report)
        json_path = output_dir.joinpath("ash.cdx.json")
        with open(json_path, "w") as f:
            json.dump(
                self.cyclonedx.model_dump(by_alias=True), f, indent=2, default=str
            )

    @classmethod
    def load_model(cls, json_path: Path) -> Optional["ASHARPModel"]:
        """Load ASHARPModel from JSON file."""
        if not json_path.exists():
            return None

        with open(json_path) as f:
            json_data = json.load(f)

        return cls.from_json(json_data)

    def report(
        self, output_formats: List[ExportFormat], output_dir: Path | None = None
    ) -> str:
        """Format ASH model using specified reporter."""
        from automated_security_helper.reporters.ash_default import (
            ASFFReporter,
            CSVReporter,
            CycloneDXReporter,
            HTMLReporter,
            JSONReporter,
            JUnitXMLReporter,
            SARIFReporter,
            SPDXReporter,
            TextReporter,
            YAMLReporter,
        )

        reporters = {
            "asff": {"reporter": ASFFReporter(), "ext": "asff"},
            "csv": {"reporter": CSVReporter(), "ext": "csv"},
            "cyclonedx": {"reporter": CycloneDXReporter(), "ext": "cdx.json"},
            "html": {"reporter": HTMLReporter(), "ext": "html"},
            "json": {"reporter": JSONReporter(), "ext": "json"},
            "junitxml": {"reporter": JUnitXMLReporter(), "ext": "junit.xml"},
            "sarif": {"reporter": SARIFReporter(), "ext": "sarif"},
            "spdx": {"reporter": SPDXReporter(), "ext": "spdx.json"},
            "text": {"reporter": TextReporter(), "ext": "txt"},
            "yaml": {"reporter": YAMLReporter(), "ext": "yaml"},
        }
        for fmt in output_formats:
            if f"{fmt.value}" not in reporters:
                raise ValueError(f"Unsupported output format: {fmt}")

            formatted = reporters[fmt.value]["reporter"].report(self)
            if formatted is None:
                ASH_LOGGER.error(
                    f"Failed to format report with {fmt.value} reporter, returned empty string"
                )
            if output_dir is None:
                return formatted
            else:
                output_dir = Path(output_dir)
                output_dir.mkdir(parents=True, exist_ok=True)
                output_filename = f"ash.{reporters[fmt.value]['ext']}"
                output_file = output_dir.joinpath(output_filename)
                with open(output_file, "w") as f:
                    ASH_LOGGER.info(f"Writing {fmt.value} report to {output_file}")
                    f.write(formatted)


if __name__ == "__main__":
    model = ASHARPModel()
    print(model.model_dump_json(indent=2))
