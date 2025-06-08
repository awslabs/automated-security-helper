# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Core models for security findings."""

from typing import List, Annotated
from pydantic import BaseModel, Field, ConfigDict, field_validator
from datetime import datetime, date


class ToolExtraArg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str
    value: str | int | float | bool | None = None


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


class IgnorePathWithReason(BaseModel):
    """Represents a path exclusion entry."""

    path: Annotated[str, Field(..., description="Path or pattern to exclude")]
    reason: Annotated[str, Field(..., description="Reason for exclusion")]
    expiration: Annotated[
        str | None, Field(None, description="(Optional) Expiration date (YYYY-MM-DD)")
    ] = None


class ToolArgs(BaseModel):
    """Base class for tool argument dictionaries."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)

    output_arg: str | None = None
    scan_path_arg: str | None = None
    format_arg: str | None = None
    format_arg_value: str | None = None
    extra_args: List[ToolExtraArg] = []


class Suppression(IgnorePathWithReason):
    """Represents a finding suppression rule."""

    rule_id: Annotated[str, Field(..., description="Rule ID to suppress")]
    line_start: Annotated[
        int | None, Field(None, description="(Optional) Starting line number")
    ] = None
    line_end: Annotated[
        int | None, Field(None, description="(Optional) Ending line number")
    ] = None

    @field_validator("line_end")
    def validate_line_range(cls, v, values):
        """Validate that line_end is greater than or equal to line_start if both are provided."""
        if (
            v is not None
            and hasattr(values, "data")
            and values.data.get("line_start") is not None
            and v < values.data["line_start"]
        ):
            raise ValueError("line_end must be greater than or equal to line_start")
        return v

    @field_validator("expiration")
    def validate_expiration_date(cls, v):
        """Validate that expiration date is in the correct format and is a valid date."""
        if v is not None:
            try:
                # Parse the date string to ensure it's a valid date
                expiration_date = datetime.strptime(v, "%Y-%m-%d").date()
                # Check if the date is in the future
                if expiration_date < date.today():
                    raise ValueError("expiration date must be in the future")
                return v
            except ValueError as e:
                raise ValueError(
                    f"Invalid expiration date format. Use YYYY-MM-DD: {str(e)}"
                )
        return v
