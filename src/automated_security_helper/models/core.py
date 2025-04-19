# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Core models for security findings."""

from typing import List, Annotated
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict


class ToolExtraArg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str
    value: str | int | float | bool | None = None


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


class PathExclusionEntry(BaseModel):
    """Represents a path exclusion entry."""

    path: Annotated[str, Field(..., description="Path or pattern to exclude")]
    reason: Annotated[str, Field(..., description="Reason for exclusion")]


class ToolArgs(BaseModel):
    """Base class for tool argument dictionaries."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)

    output_arg: str | None = None
    scan_path_arg: str | None = None
    format_arg: str | None = None
    format_arg_value: str | None = None
    extra_args: List[ToolExtraArg] = []
