# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Core models for security findings."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, List, Optional, Dict, Literal, Annotated, Union
from pydantic import BaseModel, Field, field_validator, ConfigDict


# Define valid severity levels at module level for use across all finding types
SeverityLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
VALID_SEVERITY_VALUES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})
SCANNER_TYPES = Literal[
    # Standard scanner types
    "CONTAINER",
    "DAST",
    "DEPENDENCY",
    "IAC",
    "SAST",
    "SBOM",
    "SECRETS",
    "UNKNOWN",
    "CUSTOM",
]


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


class BaseScannerOptions(BaseModel):
    """Base class for scanner options."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)


class BaseConverterOptions(BaseModel):
    """Base class for converter options."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)


class BaseParserOptions(BaseModel):
    """Base class for parser options."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)


class BaseReporterOptions(BaseModel):
    """Base class for reporter options."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)


class ScannerBaseConfig(BaseModel):
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
    type: Annotated[
        SCANNER_TYPES,
        Field(description=f"Type of scanner. Valid options include: {SCANNER_TYPES}"),
    ] = "UNKNOWN"
    options: Annotated[BaseScannerOptions, Field(description="Scanner options")] = (
        BaseScannerOptions()
    )


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


class ScannerPluginConfig(ScannerBaseConfig):
    """Configuration model for scanner plugins."""

    command: Annotated[
        str,
        Field(
            description="The command to invoke the scanner, typically the binary or path to a script"
        ),
    ] = None
    args: Annotated[
        List[str],
        Field(
            description="List of arguments to pass to the scanner command. Defaults to an empty list."
        ),
    ] = []
    invocation_mode: Annotated[
        Literal["directory", "file"],
        Field(
            description="Whether to run the scanner on a directory or a file. Defaults to 'directory' to scan the entire directory. If set to 'file', uses the file_config values to identify the files to scan and scan each one individually."
        ),
    ] = "directory"
    file_config: Annotated[
        FileInvocationConfig,
        Field(
            description="Configuration for file scanning. Required if invocation_mode is 'file'."
        ),
    ] = FileInvocationConfig()
    output_format: Annotated[
        ExportFormat | None,
        Field(description="Expected output format from the scanner itself."),
    ] = None
    scan_path_arg_position: Annotated[
        Literal["before_args", "after_args"],
        Field(
            description="Whether to place the scan path argument before or after the scanner command args. Defaults to 'after_args'."
        ),
    ] = "after_args"
    scan_path_arg: Annotated[
        str | None,
        Field(
            description="Argument to pass the scan path to when invoking the scanner command. Defaults to not including an arg for the scan path value, which results in the path being passed to the scanner as a positional argument at the scan_path_arg_position specified. If the ",
            examples=[
                "-f",
                "--file",
                "-p",
                "--path",
            ],
        ),
    ] = None
    format_arg_position: Annotated[
        Literal["before_args", "after_args"],
        Field(
            description="Whether to place the format argument before or after the scanner command args. Defaults to 'before_args'."
        ),
    ] = "before_args"
    format_arg: Annotated[
        str | None,
        Field(
            description="Argument to pass the format option to when invoking the scanner command. Defaults to not including an arg for the format value, which results in the format option being passed to the scanner as a positional argument at the format_arg_position specified. If a value is provided, the value will be passed into the runtime args prior to the format option.",
            examples=[
                "--format",
                "-f",
                "--output-format",
            ],
        ),
    ] = None
    format_arg_value: Annotated[
        str | None,
        Field(
            description="Value to pass to the format argument when invoking the scanner command. Defaults to 'json', but typically is explicitly set in ScannerPlugin implementations as a frozen property.",
            examples=[
                "json",
                "sarif",
                "cyclonedx",
            ],
        ),
    ] = "json"
    output_arg: Annotated[
        str | None,
        Field(
            description="Argument to pass the output option to when invoking the scanner command. Defaults to not including an arg for the output value, which results in the output option being passed to the scanner as a positional argument at the format_arg_position specified. If a value is provided, the value will be passed into the runtime args prior to the output option.",
            examples=[
                "--output",
                "-o",
                "--outfile",
            ],
        ),
    ] = None
    output_arg_position: Annotated[
        Literal["before_args", "after_args"],
        Field(
            description="Whether to place the output argument before or after the scanner command args. Defaults to 'before_args'."
        ),
    ] = "before_args"
    get_tool_version_command: Annotated[
        List[str] | Callable[[], str] | None,
        Field(description="Command to run that should return the scanner version"),
    ] = None
    output_stream: Annotated[
        Literal["stdout", "stderr", "file"],
        Field(
            description="Where to read scanner output from. Can be 'stdout', 'stderr' or 'file'. Defaults to 'stdout' to capture the output of the scanner directly."
        ),
    ] = "stdout"

    @field_validator("get_tool_version_command", check_fields=False)
    @classmethod
    def resolve_tool_version(
        cls, get_tool_version_command: List[str] | Callable[[], str]
    ) -> List[str] | str:
        if callable(get_tool_version_command):
            return get_tool_version_command()
        else:
            return get_tool_version_command

    @field_validator("type", mode="before")
    @classmethod
    def normalize_scanner_type(cls, scanner_type: Any) -> str:
        """Normalize scanner type value before validation."""
        # Type checking
        if not isinstance(scanner_type, str):
            raise ValueError(f"Scanner type must be string, got {type(scanner_type)}")

        # Convert/normalize value
        scanner_type = str(scanner_type).strip().upper()
        if scanner_type == "STATIC":
            scanner_type = "SAST"

        return scanner_type

    def model_post_init(self, context):
        super().model_post_init(context)
        if not hasattr(self, "name"):
            self.name = self.command


class ConverterPluginConfig(ScannerPluginConfig):
    """Configuration model for converter plugins."""

    pass


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


class ParserConfig(ScannerBaseConfig):
    """Configuration model for scanner result parsers."""

    output_format: Annotated[
        str,
        Field(description="Expected output format from the scanner"),
    ]
    finding_key: Annotated[
        str,
        Field(description="Key used to identify individual findings in the output"),
    ] = "findings"
    severity_mapping: Annotated[
        Dict[str, str],
        Field(
            description="Mapping of scanner-specific severity levels to standardized levels"
        ),
    ] = {}
    location_mapping: Annotated[
        Dict[str, str],
        Field(
            description="Mapping of scanner-specific location fields to standardized fields"
        ),
    ] = {}
