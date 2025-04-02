from enum import Enum
from pydantic import BaseModel, ConfigDict, Field
from typing import Annotated, List, Dict, Literal, Optional


class BaseConfig(BaseModel):
    """Base configuration model with common settings."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        extra="allow",
    )

    enabled: Annotated[bool, Field(description="Whether the component is enabled")] = (
        True
    )
    name: Annotated[
        str,
        Field(min_length=1, description="Name of the component. Required"),
    ] = None


class ScannerConfig(BaseConfig):
    """Configuration model for security scanners."""

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
    output_format: Annotated[
        str,
        Field(
            description="Expected output format from the scanner itself. Defaults to JSON"
        ),
    ] = "JSON"
    missing_command_preference: Annotated[
        Literal["error", "warning", "ignore"],
        Field(
            description="How to handle scanner configurations that are missing commands. 'error' will raise an error, 'warning' will raise a warning, and 'ignore' will skip the scanner with an INFO log added to the aggregated results indicating that the scanner was skipped. Defaults to 'error'."
        ),
    ] = "error"
    can_be_overridden: Annotated[
        bool,
        Field(
            description="Whether the scanner configuration can be overridden by runtime configuration"
        ),
    ] = True
    overridable_properties: Annotated[
        List[str],
        Field(
            description="List of properties that can be overridden by runtime configuration"
        ),
    ] = []

    def model_post_init(self, context):
        super().model_post_init(context)
        if not hasattr(self, "name"):
            self.name = self.command


class ParserConfig(BaseConfig):
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


class OutputFormat(str, Enum):
    """Supported output formats."""

    JSON = "json"
    YAML = "yaml"
    TEXT = "text"


class ASHConfig(BaseModel):
    """Main configuration model for Automated Security Helper."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        extra="allow",
    )

    # General configuration
    project_name: Annotated[str, Field(description="Name of the project being scanned")]
    output_format: Annotated[
        OutputFormat, Field(description="Format for scan results output")
    ] = OutputFormat.JSON
    output_file: Annotated[
        Optional[str],
        Field(
            description="Path to write scan results. If not specified, outputs to stdout"
        ),
    ] = None

    # Scanner configurations
    static_analysis: Annotated[
        List[ScannerConfig],
        Field(description="Configuration for static analysis scanners"),
    ] = []
    dependency_scan: Annotated[
        List[ScannerConfig],
        Field(description="Configuration for dependency scanning tools"),
    ] = []
    container_scan: Annotated[
        List[ScannerConfig],
        Field(description="Configuration for container scanning tools"),
    ] = []
    iac_scan: Annotated[
        List[ScannerConfig],
        Field(description="Configuration for Infrastructure as Code scanning tools"),
    ] = []

    # Additional metadata
    scan_paths: Annotated[List[str], Field(description="List of paths to scan")] = ["."]
    exclude_paths: Annotated[
        List[str], Field(description="List of paths to exclude from scanning")
    ] = []
    severity_threshold: Annotated[
        str, Field(description="Minimum severity level to report")
    ] = "LOW"
    fail_on_findings: Annotated[
        bool,
        Field(
            description="Whether to exit with non-zero code if findings are detected"
        ),
    ] = True
    max_concurrent_scanners: Annotated[
        int, Field(description="Maximum number of scanners to run concurrently", ge=1)
    ] = 4
