# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime, timezone
import json
from pathlib import Path
from pydantic import BaseModel, ConfigDict, Field, field_validator

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_DOCS_URL, ASH_REPO_URL
from automated_security_helper.core.enums import ExportFormat, ScannerStatus
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport
from typing import TYPE_CHECKING, Annotated, Dict, Any, Optional, Union, List
from automated_security_helper.schemas.sarif_schema_model import (
    PropertyBag,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig

__all__ = ["AshAggregatedResults"]


class ScannerSeverityCount(BaseModel):
    """Information about scanner status."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="allow",
        arbitrary_types_allowed=True,
    )
    suppressed: int = (
        0  # Suppressed findings take precedence over other severity levels
    )
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class SummaryStats(ScannerSeverityCount):
    """Summary statistics for the final report"""

    total: int = 0
    actionable: int = 0
    passed: int = 0
    failed: int = 0
    missing: int = 0
    skipped: int = 0
    suppressed: int = 0  # Add suppressed count to summary stats

    def bump(self, key: str, amount: int = 1) -> int:
        setattr(self, key, getattr(self, key) + amount)
        return getattr(self, key)


class ScannerTargetStatusInfo(BaseModel):
    """Information about scanner status."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="allow",
        arbitrary_types_allowed=True,
    )

    status: ScannerStatus = ScannerStatus.PASSED
    dependencies_satisfied: bool = True
    excluded: bool = False
    severity_counts: ScannerSeverityCount = ScannerSeverityCount()
    finding_count: int | None = 0
    actionable_finding_count: int | None = 0
    suppressed_finding_count: int | None = 0
    exit_code: int | None = 0
    duration: float | None = 0.0


class ScannerStatusInfo(BaseModel):
    """Information about scanner status."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="allow",
        arbitrary_types_allowed=True,
    )

    severity_threshold: str | None = None
    status: ScannerStatus | None = None
    dependencies_satisfied: bool = True
    excluded: bool = False

    source: ScannerTargetStatusInfo = ScannerTargetStatusInfo()
    converted: ScannerTargetStatusInfo = ScannerTargetStatusInfo()


class ConverterStatusInfo(BaseModel):
    """Information about converter status."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="allow",
        arbitrary_types_allowed=True,
    )

    dependencies_satisfied: bool = True
    excluded: bool = False

    converted_paths: List[str] = []


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
        SummaryStats,
        Field(description="Summary statistics (e.g., count by severity)"),
    ] = SummaryStats()

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


class AshAggregatedResults(BaseModel):
    """Main model class for parsing security scan reports from ASH tooling."""

    model_config = ConfigDict(
        extra="ignore",
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
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
            scanner_status={},
        )
    )
    ash_config: Annotated[
        "AshConfig",
        Field(description="The full ASH configuration used during this scan."),
    ] = None
    scanner_results: Dict[str, ScannerStatusInfo] = Field(default_factory=dict)
    converter_results: Dict[str, ConverterStatusInfo] = Field(default_factory=dict)
    sarif: Annotated[
        SarifReport | None,
        Field(description="The SARIF formatted vulnerability report"),
    ] = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(
                    driver=ToolComponent(
                        name="AWS Labs - Automated Security Helper",
                        fullName="awslabs/automated-security-helper",
                        version=get_ash_version(),
                        organization="Amazon Web Services",
                        downloadUri=ASH_REPO_URL,
                        informationUri=ASH_DOCS_URL,
                    ),
                    extensions=[],
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
        from automated_security_helper.config.ash_config import AshConfig

        try:
            return AshConfig.model_validate(v)
        except Exception as e:
            ASH_LOGGER.error(f"Failed to validate ASH config: {e}")
        return get_default_config()

    def model_post_init(self, context):
        """Initialize aggregator and trend analyzer with current findings."""
        if self.scanner_results is None:
            self.scanner_results = {}
        return super().model_post_init(context)

    def to_simple_dict(self) -> dict:
        """Convert the AshAggregatedResults to a simple dictionary representation.

        Returns:
            dict: A simple dictionary representation of the AshAggregatedResults
        """
        conf = self.ash_config.model_dump(by_alias=True, exclude_unset=True)
        if len(conf.keys()) == 0:
            conf = get_default_config()
        simple_dict = {
            "name": self.name,
            "description": self.description,
            "metadata": self.metadata.model_dump(by_alias=True, exclude_unset=True),
            "converter_results": {
                k: v.model_dump(by_alias=True, exclude_unset=True)
                for k, v in sorted(self.converter_results.items())
            },
            "scanner_results": {
                k: v.model_dump(by_alias=True, exclude_unset=True)
                for k, v in sorted(self.scanner_results.items())
            },
            "ash_config": conf,
        }
        return simple_dict

    def to_flat_vulnerabilities(self) -> List[FlatVulnerability]:
        """Convert the AshAggregatedResults to a list of flattened vulnerability objects.

        Returns:
            List[FlatVulnerability]: A list of flattened vulnerability objects
        """
        flat_vulns = []

        # Process SARIF results if available
        if self.sarif and self.sarif.runs and len(self.sarif.runs) > 0:
            for run in self.sarif.runs:
                if not run.results:
                    continue

                # Get tool information
                tool_name = "Unknown"
                tool_type = "UNKNOWN"

                if run.tool and run.tool.driver:
                    tool_name = run.tool.driver.name
                    # Try to determine tool type from properties
                    if run.tool.driver.properties and hasattr(
                        run.tool.driver.properties, "tags"
                    ):
                        for tag in run.tool.driver.properties.tags:
                            if tag.upper() in [
                                "SAST",
                                "DAST",
                                "SCA",
                                "IAC",
                                "SECRETS",
                                "CONTAINER",
                                "SBOM",
                            ]:
                                tool_type = tag.upper()
                                break

                # Process each result
                for result in run.results:
                    # Extract basic information
                    severity = "UNKNOWN"
                    if result.level:
                        level_map = {
                            "error": "HIGH",
                            "warning": "MEDIUM",
                            "note": "LOW",
                            "none": "INFO",
                        }
                        severity = level_map.get(str(result.level).lower(), "MEDIUM")

                    # Extract message
                    description = ""
                    if result.message:
                        if hasattr(result.message, "text"):
                            description = result.message.text
                        elif hasattr(result.message, "root") and hasattr(
                            result.message.root, "text"
                        ):
                            description = result.message.root.text

                    # Extract location information
                    file_path = None
                    line_start = None
                    line_end = None
                    code_snippet = None
                    # region: Region | None = None
                    # contextRegion: Region | None = None

                    if result.locations and len(result.locations) > 0:
                        location = result.locations[0]
                        if location.physicalLocation:
                            # try:
                            #     region = location.physicalLocation.root.region
                            #     contextRegion = (
                            #         location.physicalLocation.root.contextRegion
                            #     )
                            # except Exception as exc:
                            #     ASH_LOGGER.debug(
                            #         f"Hit error parsing region/contextRegion: {exc}"
                            #     )
                            if (
                                hasattr(location.physicalLocation, "root")
                                and location.physicalLocation.root
                                and hasattr(
                                    location.physicalLocation.root, "artifactLocation"
                                )
                                and location.physicalLocation.root.artifactLocation
                                and location.physicalLocation.root.artifactLocation.uri
                            ):
                                file_path = (
                                    location.physicalLocation.root.artifactLocation.uri
                                )

                            if (
                                hasattr(location.physicalLocation, "root")
                                and location.physicalLocation.root
                                and hasattr(
                                    location.physicalLocation.root, "contextRegion"
                                )
                                and location.physicalLocation.root.contextRegion
                            ):
                                line_start = location.physicalLocation.root.contextRegion.startLine
                                line_end = (
                                    location.physicalLocation.root.contextRegion.endLine
                                )
                                if (
                                    location.physicalLocation.root.contextRegion.snippet
                                    is not None
                                    and location.physicalLocation.root.contextRegion.snippet.text
                                    is not None
                                ):
                                    code_snippet = location.physicalLocation.root.contextRegion.snippet.text

                            elif (
                                hasattr(location.physicalLocation, "root")
                                and location.physicalLocation.root
                                and hasattr(location.physicalLocation.root, "region")
                                and location.physicalLocation.root.region
                            ):
                                line_start = (
                                    location.physicalLocation.root.region.startLine
                                )
                                line_end = location.physicalLocation.root.region.endLine
                                if (
                                    location.physicalLocation.root.region.snippet
                                    is not None
                                    and location.physicalLocation.root.region.snippet.text
                                    is not None
                                ):
                                    code_snippet = location.physicalLocation.root.region.snippet.text

                    # Extract additional properties
                    properties = {}
                    if result.properties:
                        properties = result.properties.model_dump(exclude_none=True)

                    # Extract tags
                    tags = []
                    if result.properties and hasattr(result.properties, "tags"):
                        tags = result.properties.tags

                    # Try to get the actual scanner name from properties
                    actual_scanner = tool_name
                    if result.properties and hasattr(result.properties, "scanner_name"):
                        actual_scanner = result.properties.scanner_name
                    elif result.properties and hasattr(
                        result.properties, "scanner_details"
                    ):
                        if hasattr(result.properties.scanner_details, "tool_name"):
                            actual_scanner = result.properties.scanner_details.tool_name

                    # If we have tags that might indicate the scanner, use those as a fallback
                    if (
                        actual_scanner == "AWS Labs - Automated Security Helper"
                        and tags
                    ):
                        for tag in tags:
                            # Common scanner names that might appear in tags
                            if tag.lower() in [
                                "bandit",
                                "semgrep",
                                "checkov",
                                "cfn-nag",
                                "cdk-nag",
                                "detect-secrets",
                                "grype",
                                "syft",
                                "npm-audit",
                            ]:
                                actual_scanner = tag
                                break

                    # Check if finding is suppressed
                    is_suppressed = False
                    supp_kind = None
                    supp_reas = None
                    if (
                        hasattr(result, "suppressions")
                        and result.suppressions
                        and len(result.suppressions) > 0
                    ):
                        is_suppressed = True
                        supp = result.suppressions[0]
                        supp_kind = supp.kind or None
                        supp_reas = supp.justification or None

                        # Update suppressed count in summary stats
                        self.metadata.summary_stats.bump("suppressed")

                        # Update scanner status info if available
                        scanner_name = (
                            actual_scanner.lower() if actual_scanner else None
                        )
                        if scanner_name and scanner_name in self.scanner_results:
                            target_type = "source"  # Default to source
                            if file_path and "converted" in file_path.lower():
                                target_type = "converted"

                            # Update suppressed finding count
                            target_info = getattr(
                                self.scanner_results[scanner_name], target_type
                            )
                            if target_info:
                                if target_info.suppressed_finding_count is None:
                                    target_info.suppressed_finding_count = 1
                                else:
                                    target_info.suppressed_finding_count += 1

                                # Update severity counts
                                if not hasattr(
                                    target_info.severity_counts, "suppressed"
                                ):
                                    target_info.severity_counts.suppressed = 1
                                else:
                                    target_info.severity_counts.suppressed += 1

                    # Extract code snippet if available and not already extracted
                    if code_snippet is None:
                        if result.properties and hasattr(result.properties, "snippet"):
                            code_snippet = result.properties.snippet

                        # Try to extract snippet from message if not found in properties
                        if not code_snippet and description and "```" in description:
                            # Some scanners include snippets in the message text
                            try:
                                parts = description.split("```")
                                if len(parts) >= 3:  # Has at least one code block
                                    code_snippet = parts[1].strip()
                            except Exception as e:
                                ASH_LOGGER.debug(e)

                        # Try to extract from locations
                        if (
                            not code_snippet
                            and result.locations
                            and len(result.locations) > 0
                        ):
                            location = result.locations[0]
                            if (
                                location.physicalLocation
                                and hasattr(location.physicalLocation, "root")
                                and location.physicalLocation.root
                                and hasattr(location.physicalLocation.root, "snippet")
                                and location.physicalLocation.root.snippet
                            ):
                                code_snippet = location.physicalLocation.root.snippet

                    # Tags already extracted above

                    # Extract references
                    references = []
                    if hasattr(result, "relatedLocations") and result.relatedLocations:
                        for loc in result.relatedLocations:
                            if (
                                loc.physicalLocation
                                and loc.physicalLocation.root
                                and loc.physicalLocation.root.artifactLocation
                                and loc.physicalLocation.root.artifactLocation.uri
                            ):
                                references.append(
                                    loc.physicalLocation.root.artifactLocation.uri
                                )

                    # Extract tags
                    tags = []
                    if result.properties and hasattr(result.properties, "tags"):
                        tags = result.properties.tags

                    # Try to get the actual scanner name from properties
                    actual_scanner = tool_name
                    if result.properties and hasattr(result.properties, "scanner_name"):
                        actual_scanner = result.properties.scanner_name
                    elif result.properties and hasattr(
                        result.properties, "scanner_details"
                    ):
                        if hasattr(result.properties.scanner_details, "tool_name"):
                            actual_scanner = result.properties.scanner_details.tool_name

                    # If we have tags that might indicate the scanner, use those as a fallback
                    if (
                        actual_scanner == "AWS Labs - Automated Security Helper"
                        and tags
                    ):
                        for tag in tags:
                            # Common scanner names that might appear in tags
                            if tag.lower() in [
                                "bandit",
                                "semgrep",
                                "checkov",
                                "cfn-nag",
                                "cdk-nag",
                                "detect-secrets",
                                "grype",
                                "syft",
                                "npm-audit",
                            ]:
                                actual_scanner = tag
                                break

                    # Create the flattened vulnerability
                    flat_vuln = FlatVulnerability(
                        id=f"{actual_scanner}-{result.ruleId or 'unknown'}-{hash(description) % 10000}",
                        title=result.ruleId or "Unknown Issue",
                        description=description,
                        severity=severity,
                        is_suppressed=is_suppressed,
                        suppression_kind=supp_kind,
                        suppression_justification=supp_reas,
                        scanner=actual_scanner,
                        scanner_type=tool_type,
                        rule_id=result.ruleId,
                        file_path=file_path,
                        line_start=line_start,
                        line_end=line_end,
                        code_snippet=code_snippet,
                        tags=json.dumps(tags, default=str) if tags else None,
                        properties=json.dumps(properties, default=str)
                        if properties
                        else None,
                        references=json.dumps(references, default=str)
                        if references
                        else None,
                        detected_at=datetime.now(timezone.utc).isoformat(),
                        raw_data=result.model_dump_json(exclude_none=True),
                    )

                    flat_vulns.append(flat_vuln)

        # Process additional reports if available
        for scanner_name, report_data in self.additional_reports.items():
            if report_data is None:
                continue
            for target_type, results in report_data.items():
                if isinstance(results, dict) and "severity_counts" in results:
                    # This is a summary report, not individual findings
                    continue

                # Try to extract findings from the report data
                # This is a simplified approach - in a real implementation,
                # you would need to handle different report formats
                if isinstance(results, list):
                    for finding in results:
                        if not isinstance(finding, dict):
                            continue

                        flat_vuln = FlatVulnerability(
                            id=f"{scanner_name}-{finding.get('id', hash(str(finding)) % 10000)}",
                            title=finding.get("title", "Unknown Issue"),
                            description=finding.get(
                                "description", "No description available"
                            ),
                            severity=finding.get("severity", "MEDIUM").upper(),
                            scanner=scanner_name,
                            scanner_type=finding.get("type", "UNKNOWN"),
                            rule_id=finding.get("rule_id"),
                            file_path=finding.get("file_path"),
                            line_start=finding.get("line_start"),
                            line_end=finding.get("line_end"),
                            cve_id=finding.get("cve_id"),
                            cwe_id=finding.get("cwe_id"),
                            fix_available=finding.get("fix_available"),
                            detected_at=finding.get(
                                "detected_at", datetime.now(timezone.utc).isoformat()
                            ),
                            raw_data=json.dumps(finding, default=str),
                        )

                        flat_vulns.append(flat_vuln)

        return flat_vulns

    @classmethod
    def from_json(cls, json_data: Union[str, Dict[str, Any]]) -> "AshAggregatedResults":
        """Parse JSON data into an AshAggregatedResults instance.

        Args:
            json_data: Either a JSON string or dictionary containing the report data.
                Must include metadata and findings fields.

        Returns:
            AshAggregatedResults instance populated with the report data.

        Raises:
            ValidationError: If the JSON data is missing required fields or has invalid values.
        """
        if isinstance(json_data, str):
            return cls.model_validate_json(json_data)
        return cls.model_validate(json_data)

    def save_model(self, output_dir: Path) -> None:
        """Save AshAggregatedResults as JSON alongside aggregated results."""

        report_dir = output_dir.joinpath("reports")
        report_dir.mkdir(parents=True, exist_ok=True)

        # Save aggregated results as JSON
        json_path = output_dir.joinpath("ash_aggregated_results.json")
        json_path.write_text(
            self.model_dump_json(
                by_alias=True,
                exclude_unset=True,
                exclude_none=True,
            )
        )

    @classmethod
    def load_model(cls, json_path: Path) -> Optional["AshAggregatedResults"]:
        """Load AshAggregatedResults from JSON file."""
        if not json_path.exists():
            return None

        with open(json_path) as f:
            json_data = json.load(f)

        return cls.from_json(json_data)


if __name__ == "__main__":
    model = AshAggregatedResults()
    print(model.model_dump_json(indent=2))
