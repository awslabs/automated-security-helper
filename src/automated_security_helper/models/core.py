# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Core models for security findings."""

from datetime import datetime, timezone
from typing import Optional, Dict, Literal, Annotated, Union
from pydantic import BaseModel, Field, field_validator, ConfigDict

# Define valid severity levels at module level for use across all finding types
SeverityLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
VALID_SEVERITY_VALUES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})


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
        Field(min_length=1, pattern=r"^[\w-]+$", description="Name of the scanner"),
    ]
    version: Annotated[str, Field(description="Version of the scanner")] = "1.0.0"
    type: Annotated[
        Literal[
            "SAST",
            "DAST",
            "SBOM",
            "CONTAINER",
            "IAC",
            "DEPENDENCY",
            "VULNERABILITY",
            "SECURITY",
            "STATIC",
            "DYNAMIC",
            "SECRET",
        ],
        Field(description="Type of scanner (e.g., SAST, DAST, SBOM)"),
    ] = "SAST"
    rule_id: Annotated[
        str,
        Field(
            min_length=1,
            pattern=r"^[\w-]+$",
            description="Unique identifier for the scanner rule",
        ),
    ] = None
    description: Annotated[str, Field(description="Description of the scanner")] = None

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="allow",
        arbitrary_types_allowed=True,
    )

    @field_validator("type")
    @classmethod
    def validate_scanner_type(cls, v: str) -> str:
        """Validate scanner type."""
        valid_types = {
            "SAST",
            "DAST",
            "SBOM",
            "CONTAINER",
            "IAC",
            "DEPENDENCY",
            "VULNERABILITY",
            "SECURITY",
            "STATIC",
            "DYNAMIC",
            "SECRET",
        }
        type_mapping = {
            "SAST": "STATIC",
            "DAST": "DYNAMIC",
            "CONTAINER_SCAN": "CONTAINER",
            "SECURITY_SCAN": "SECURITY",
        }
        v = v.upper()
        if v.endswith("_SCAN"):
            v = v[:-5]
        if v in type_mapping:
            v = type_mapping[v]
        if v not in valid_types:
            raise ValueError(f"Scanner type must be one of {sorted(valid_types)}")
        return v

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate scanner name is not empty."""
        if not v.strip():
            raise ValueError("Scanner name cannot be empty")
        return v.strip()

    @field_validator("rule_id")
    @classmethod
    def validate_rule_id(cls, v: str) -> str:
        """Validate rule ID is not empty."""
        v = v.strip()
        if not v:
            raise ValueError("Rule ID cannot be empty")
        # Ensure valid format
        import re

        if not re.match(r"^[\w-]*$", v):
            raise ValueError(
                "Rule ID must start with alphanumeric and contain only alphanumeric, underscore or hyphen"
            )
        return v


class BaseFinding(BaseModel):
    """Base model for all security findings."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        extra="allow",
    )

    id: Annotated[
        str,
        Field(
            ...,
            min_length=1,
            pattern=r"^[\w-]+$",
            description="Unique identifier for the finding",
        ),
    ]
    title: Annotated[
        str, Field(..., min_length=1, description="Title or name of the finding")
    ]
    severity: Annotated[
        SeverityLevel, Field(..., description="Severity level of the finding")
    ]
    location: Annotated[
        Location, Field(..., description="Location information for the finding")
    ]
    scanner: Annotated[
        Scanner,
        Field(..., description="Information about the scanner that found the issue"),
    ]
    timestamp: Annotated[
        datetime,
        Field(
            description="When the finding was created",
        ),
    ] = None
    description: Annotated[
        str, Field(description="Detailed description of the finding")
    ] = None
    status: Annotated[str, Field(description="Current status of the finding")] = "OPEN"

    created_at: Annotated[
        datetime,
        Field(
            description="When the finding was first detected (in UTC)",
        ),
    ] = None
    updated_at: Annotated[
        datetime,
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

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        """Validate that severity is one of the allowed values."""
        if v not in VALID_SEVERITY_VALUES:
            raise ValueError(f"Severity must be one of {sorted(VALID_SEVERITY_VALUES)}")
        return v.upper()

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        """Validate finding status."""
        valid_statuses = {
            "OPEN",
            "CLOSED",
            "IN_PROGRESS",
            "FALSE_POSITIVE",
            "RISK_ACCEPTED",
        }
        if v.upper() not in valid_statuses:
            raise ValueError(f"Status must be one of {sorted(valid_statuses)}")
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
    def validate_datetime(cls, v: Union[str, datetime] = None) -> datetime:
        """Validate that value is timestamp or, if empty, set to current datetime"""
        if not v:
            return datetime.now(timezone.utc)
        if isinstance(v, datetime):
            return v
        v = v.strip()
        return datetime.strptime(v)

    def model_post_init(self, context):
        super().model_post_init(context)
        default_timestamp = datetime.now(timezone.utc)
        if not self.created_at:
            self.created_at = default_timestamp
        if not self.updated_at:
            self.updated_at = default_timestamp
        if not self.timestamp:
            self.timestamp = default_timestamp


# Define exports at the bottom after all classes are defined
__all__ = ["Location", "Scanner", "BaseFinding"]
