# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Core models for security findings."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Optional, Dict, Literal, Annotated, Union
from pydantic import BaseModel, Field, field_validator, ConfigDict

from automated_security_helper.base.options import BaseConverterOptions
from automated_security_helper.base.options import BaseParserOptions
from automated_security_helper.base.options import BaseReporterOptions
from automated_security_helper.core.constants import SCANNER_TYPES
from automated_security_helper.core.constants import VALID_SEVERITY_VALUES


# Define valid severity levels at module level for use across all finding types
SeverityLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class Location(BaseModel):
    """Represents the location of a finding in the codebase."""

    file_path: Annotated[
        str, Field(..., description="Path to the file containing the finding")
    ]
    start_line: Annotated[
        Optional[int], Field(None, description="Starting line number of the finding")
    ]
    end_line: Annotated[
        Optional[int], Field(None, description="Ending line number of the finding")
    ]
    snippet: Annotated[
        Optional[str], Field(None, description="Code snippet related to the finding")
    ]


class Scanner(BaseModel):
    """Represents metadata about the security scanner."""

    name: Annotated[
        str,
        Field(
            min_length=1, pattern=r"^[a-zA-Z][\w-]*$", description="Name of the scanner"
        ),
    ]
    version: Annotated[str, Field(description="Version of the scanner")] = "1.0.0"
    type: Annotated[
        SCANNER_TYPES,
        Field(description="Type of scanner (e.g., SAST, DAST, SBOM)"),
    ] = "SAST"
    description: Annotated[str, Field(description="Description of the scanner")] = None

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="allow",
        arbitrary_types_allowed=True,
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate scanner name is not empty."""
        if not v.strip():
            raise ValueError("Scanner name cannot be empty")
        return v.strip()


class BaseFinding(BaseModel):
    """Base model for all security findings."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        extra="allow",
        json_encoders={datetime: lambda v: v.isoformat()},
    )

    id: Annotated[
        str,
        Field(
            ...,
            min_length=1,
            pattern=r"^[A-Za-z][\/\.\w-]+$",
            description="Unique identifier for the finding",
            # alias="finding_id"
        ),
    ]

    # @model_validator(mode='before')
    # @classmethod
    # def handle_id_finding_id(cls, data: Any) -> Any:
    #     """Convert between id and finding_id."""
    #     if isinstance(data, dict):
    #         if 'finding_id' in data and 'id' not in data:
    #             data['id'] = data['finding_id']
    #         elif 'id' in data:
    #             data['finding_id'] = data['id']
    #     return data

    title: Annotated[
        str, Field(..., min_length=1, description="Title or name of the finding")
    ]
    severity: Annotated[
        SeverityLevel, Field(..., description="Severity level of the finding")
    ]
    location: Annotated[
        Location, Field(..., description="Location information for the finding")
    ]
    link: Annotated[
        str, Field(description="Link to more information about the finding")
    ] = None
    timestamp: Annotated[
        str,
        Field(
            description="When the finding was created",
        ),
    ] = None
    description: Annotated[
        str, Field(description="Detailed description of the finding")
    ] = None
    status: Annotated[
        Literal[
            "OPEN",
            "CLOSED",
            "IN_PROGRESS",
            "FALSE_POSITIVE",
            "RISK_ACCEPTED",
            "INFORMATIONAL",
        ],
        Field(description="Current status of the finding"),
    ] = "OPEN"

    created_at: Annotated[
        str,
        Field(
            description="When the finding was first detected (in UTC)",
        ),
    ] = None
    updated_at: Annotated[
        str,
        Field(
            description="When the finding was last updated (in UTC)",
        ),
    ] = None
    remediation: Annotated[
        str, Field(description="Guidance for fixing the finding")
    ] = None
    metadata: Annotated[
        Dict,
        Field(description="Additional scanner-specific metadata"),
    ] = {}
    raw: Annotated[
        Any,
        Field(description="Raw result from the scanner"),
    ] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        """Validate that severity is one of the allowed values."""
        if v not in VALID_SEVERITY_VALUES:
            raise ValueError(f"Severity must be one of {sorted(VALID_SEVERITY_VALUES)}")
        return v.upper()

    @field_validator("id", "title", "description")
    @classmethod
    def validate_non_empty_str(cls, v: str, info) -> str:
        """Validate string fields are not empty."""
        v = v.strip()
        if not v:
            raise ValueError(f"{info.field_name} cannot be empty")
        return v

    @field_validator("timestamp", "created_at", "updated_at")
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
        if not self.created_at:
            self.created_at = default_timestamp
        if not self.updated_at:
            self.updated_at = default_timestamp
        if not self.timestamp:
            self.timestamp = default_timestamp


# Define exports at the bottom after all classes are defined
__all__ = ["Location", "Scanner", "BaseFinding"]


class FileInvocationConfig(BaseModel):
    """Configuration for file scanning."""

    model_config = ConfigDict(extra="forbid")

    include: Annotated[
        List[str],
        Field(
            description="List of file patterns to include. Defaults to an empty list, which includes all files.",
            examples=[
                "**/*",
            ],
        ),
    ] = []
    exclude: Annotated[
        List[str],
        Field(
            description="List of file patterns to exclude. Defaults to an empty list, which excludes no files.",
            examples=[
                "tests/",
            ],
        ),
    ] = []


class ToolExtraArg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str
    value: str | int | float | bool | None = None


class ConverterBaseConfig(BaseModel):
    """Base converter configuration model with common settings."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        extra="allow",
    )

    name: Annotated[
        str,
        Field(
            min_length=1,
            description="Name of the component using letters, numbers, underscores and hyphens. Must begin with a letter.",
            pattern=r"^[a-zA-Z][\w-]+$",
        ),
    ] = None
    enabled: Annotated[bool, Field(description="Whether the component is enabled")] = (
        True
    )
    options: Annotated[BaseConverterOptions, Field(description="Converter options")] = (
        BaseConverterOptions()
    )


class ParserBaseConfig(BaseModel):
    """Base parser configuration model with common settings."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        extra="allow",
    )

    name: Annotated[
        str,
        Field(
            min_length=1,
            description="Name of the component using letters, numbers, underscores and hyphens. Must begin with a letter.",
            pattern=r"^[a-zA-Z][\w-]+$",
        ),
    ] = None
    enabled: Annotated[bool, Field(description="Whether the component is enabled")] = (
        True
    )
    options: Annotated[BaseParserOptions, Field(description="Parser options")] = (
        BaseParserOptions()
    )


class ReporterBaseConfig(BaseModel):
    """Base reporter configuration model with common settings."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        extra="allow",
    )

    name: Annotated[
        str,
        Field(
            min_length=1,
            description="Name of the component using letters, numbers, underscores and hyphens. Must begin with a letter.",
            pattern=r"^[a-zA-Z][\w-]+$",
        ),
    ] = None
    enabled: Annotated[bool, Field(description="Whether the component is enabled")] = (
        True
    )
    options: Annotated[BaseReporterOptions, Field(description="Reporter options")] = (
        BaseReporterOptions()
    )


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


class ScanStatistics(BaseModel):
    """Statistics for static analysis scan results."""

    files_scanned: Annotated[
        int, Field(description="Total number of files scanned")
    ] = 0
    lines_of_code: Annotated[
        int, Field(description="Total number of lines of code")
    ] = 0
    total_findings: Annotated[int, Field(description="Total number of findings")] = 0
    findings_by_type: Annotated[
        dict, Field(description="Count of findings by severity level")
    ] = {}
    scan_duration_seconds: Annotated[
        float, Field(description="Duration of scan in seconds")
    ] = 0.0
