# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Models and interfaces for data interchange and report generation."""

from datetime import datetime, timezone
from typing import Dict, List, Any, Union, Annotated
from enum import Enum
from pydantic import BaseModel, Field, field_validator, ConfigDict

from automated_security_helper.models.core import BaseFinding


class ExportFormat(str, Enum):
    """Supported export formats."""

    TEXT = "text"
    JSON = "json"
    YAML = "yaml"
    CSV = "csv"
    HTML = "html"
    DICT = "dict"
    JUNITXML = "junitxml"
    SARIF = "sarif"
    ASFF = "asff"
    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"


class DataInterchange(BaseModel):
    """Base model for data interchange capabilities."""

    model_config = ConfigDict(
        str_strip_whitespace=True, arbitrary_types_allowed=True, extra="allow"
    )

    name: Annotated[
        str, Field(..., min_length=1, description="Name of the data interchange format")
    ]
    description: Annotated[
        str, Field(min_length=1, description="Description of the data")
    ] = None
    timestamp: Annotated[
        str,
        Field(
            description="Timestamp of the export in UTC",
        ),
    ] = None
    version: Annotated[str, Field(description="Version of the export format")] = "1.0"
    metadata: Annotated[
        Dict[str, Any],
        Field(description="Additional metadata about the export"),
    ] = {}

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate name is not empty."""
        v = v.strip()
        if not v:
            raise ValueError("Name cannot be empty")
        return v

    @field_validator("timestamp")
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
        if not self.timestamp:
            self.timestamp = default_timestamp


class ReportMetadata(BaseModel):
    """Metadata for security reports."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="allow")

    report_id: Annotated[
        str,
        Field(
            ...,
            min_length=1,
            pattern=r"^[\w-]+$",
            description="Unique identifier for the report",
        ),
    ]
    tool_name: Annotated[
        str, Field(..., min_length=1, description="Name of the security tool")
    ]
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

    @field_validator("report_id", "project_name", "tool_name")
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


class SecurityReport(DataInterchange):
    """Model for comprehensive security reports."""

    model_config = ConfigDict(
        str_strip_whitespace=True, arbitrary_types_allowed=True, extra="forbid"
    )

    metadata: Annotated[ReportMetadata, Field(description="Report metadata")]
    findings: Annotated[
        List[BaseFinding], Field(description="List of security findings")
    ] = []
    scanners_used: Annotated[
        List[Dict[str, str]], Field(description="List of scanners used in this report")
    ] = []
    scan_type: Annotated[str, Field(description="Type of security scan")] = "security"
    description: Annotated[
        str, Field(description="Description of the security scan report")
    ] = "Security scan report"

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v: str) -> str:
        """Validate scan type."""
        valid_types = {
            "security",
            "vulnerability",
            "container",
            "iac",
            "sbom",
            "dependency",
            "sast",
            "dast",
        }
        if v.lower() not in valid_types:
            raise ValueError(f"Scan type must be one of {sorted(valid_types)}")
        return v.lower()

    def export(
        self, format: ExportFormat = ExportFormat.JSON
    ) -> Union[str, Dict[str, Any]]:
        """Export the report in the specified format."""
        if format == ExportFormat.JSON:
            return self.model_dump_json(indent=2, serialize_as_any=True)
        elif format == ExportFormat.YAML:
            import yaml

            return yaml.dump(self.model_dump())
        elif format == ExportFormat.CSV:
            # Basic CSV export of findings
            import csv
            import io

            output = io.StringIO()
            if self.findings:
                writer = csv.DictWriter(output, fieldnames=self.findings[0].keys())
                writer.writeheader()
                writer.writerows(self.findings)
            return output.getvalue()
        elif format == ExportFormat.HTML:
            # Basic HTML report
            findings_html = "\n".join(
                f"<li><strong>{f.get('title', 'Unknown')}</strong>: {f.get('severity', 'Unknown')}</li>"
                for f in self.findings
            )
            return f"""
            <html>
            <body>
                <h1>Security Report</h1>
                <h2>Project: {self.metadata.project_name}</h2>
                <p>Generated: {self.metadata.generated_at}</p>
                <h3>Findings:</h3>
                <ul>{findings_html}</ul>
            </body>
            </html>
            """
        elif format == ExportFormat.DICT:
            return self.model_dump()

        raise ValueError(f"Unsupported export format: {format}")

    @classmethod
    def from_json(cls, json_data: Union[str, Dict[str, Any]]) -> "SecurityReport":
        """Import a report from JSON data."""
        if isinstance(json_data, str):
            return cls.model_validate_json(json_data)
        return cls.model_validate(json_data)

    def track_history(self, previous_report: "SecurityReport") -> Dict[str, Any]:
        """Compare with a previous report to track changes."""
        current_findings_set = {(f.id, f.severity) for f in self.findings}
        previous_findings_set = {(f.id, f.severity) for f in previous_report.findings}

        new_findings = current_findings_set - previous_findings_set
        resolved_findings = previous_findings_set - current_findings_set

        return {
            "new_findings": len(new_findings),
            "resolved_findings": len(resolved_findings),
            "total_active_findings": len(current_findings_set),
            "comparison_date": previous_report.metadata.generated_at,
        }
