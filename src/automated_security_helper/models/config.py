from enum import Enum
from pydantic import BaseModel, ConfigDict, Field
from typing import Annotated, List, Dict, Literal, Union
from automated_security_helper.models.scanner_types import (
    BanditScanner,
    CfnNagScanner,
    CheckovScanner,
    CustomScanner,
    GitSecretsScanner,
    NpmAuditScanner,
    SemgrepScanner,
    CdkNagScanner,
    GrypeScanner,
    SyftScanner,
)


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
        Field(description="Expected output format from the scanner itself."),
    ] = None
    output_stream: Annotated[
        Literal["stdio", "stderr", "file"],
        Field(
            description="Where to read scanner output from. Can be 'stdio', 'stderr' or 'file'. Defaults to 'stdio' to capture the output of the scanner directly."
        ),
    ] = "stdio"
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

    def model_post_init(self, context):
        super().model_post_init(context)
        if not hasattr(self, "name"):
            self.name = self.command


class BuildToolInstall(BaseModel):
    """Configuration model for tool installation during build."""

    model_config = ConfigDict(extra="allow")
    script: Annotated[str, Field(description="Installation script for the tool")] = ""


class CustomBuildScannerConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    __pydantic_extra__: Dict[str, List[ScannerConfig]] = Field(init=False)

    sast: Annotated[
        Dict[str, List[ScannerConfig]],
        Field(description="Scanner configurations by type"),
    ] = {}

    sbom: Annotated[
        Dict[str, List[ScannerConfig]],
        Field(description="Scanner configurations by type"),
    ] = {}


class BuildConfig(BaseModel):
    """Configuration model for build-time settings."""

    model_config = ConfigDict(extra="allow")

    mode: Annotated[
        Literal["ASH_MODE_ONLINE", "ASH_MODE_OFFLINE"],
        Field(description="Build mode for the container"),
    ] = "ASH_MODE_ONLINE"
    tool_install_scripts: Annotated[
        Dict[str, List[str]],
        Field(description="Map of tool names to their installation scripts"),
    ] = {}
    custom_scanners: Annotated[
        CustomBuildScannerConfig,
        Field(description="Scanner configurations by type"),
    ] = CustomBuildScannerConfig()


class ScannerTypeConfig(BaseModel):
    """Configuration model for scanner type specific settings."""

    model_config = ConfigDict(extra="allow")
    enabled: Annotated[
        bool, Field(description="Whether this scanner type is enabled")
    ] = True


class SecurityScanConfig(BaseModel):
    """Configuration model for security scanning settings."""

    model_config = ConfigDict(extra="allow")
    sast: Annotated[
        List[
            Union[
                CustomScanner,
                BanditScanner,
                SemgrepScanner,
                CdkNagScanner,
                GrypeScanner,
            ]
        ],
        Field(description="List of SAST scanners to enable"),
    ] = [
        BanditScanner(),
        CdkNagScanner(),
        GrypeScanner(),
        SemgrepScanner(),
    ]
    sbom: Annotated[
        List[
            Union[
                CustomScanner,
                SyftScanner,
            ]
        ],
        Field(description="List of SBOM scanners to enable"),
    ] = [
        SyftScanner(),
    ]


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
    SARIF = "sarif"
    CYCLONEDX = "cyclonedx"


class ScannerClassConfig(BaseModel):
    """Configuration model for scanner classes."""

    model_config = ConfigDict(extra="allow")


class SASTScannerConfig(ScannerClassConfig):
    """Configuration model for SAST scanners."""

    # Additional optional settings
    output_formats: Annotated[
        List[Literal["json", "yaml", "text", "html", "junitxml", "sarif", "asff"]],
        Field(description="Format for SAST scan results output"),
    ] = [
        "text",
        "junitxml",
        "html",
    ]

    scanners: Annotated[
        List[
            Union[
                # Custom scanners
                CustomScanner,
                # Built-in scanners
                BanditScanner,
                CdkNagScanner,
                CfnNagScanner,
                CheckovScanner,
                GitSecretsScanner,
                GrypeScanner,
                NpmAuditScanner,
                SemgrepScanner,
            ]
        ],
        Field(description="List of SAST scanners to enable"),
    ] = [
        BanditScanner(),
        CdkNagScanner(),
        CfnNagScanner(),
        CheckovScanner(),
        GitSecretsScanner(),
        GrypeScanner(),
        NpmAuditScanner(),
        SemgrepScanner(),
    ]


class SBOMScannerConfig(ScannerClassConfig):
    """Configuration model for SBOM scanners."""

    # Additional optional settings
    output_formats: Annotated[
        List[Literal["json", "yaml", "text", "html", "cyclonedx", "spdx"]],
        Field(description="Format for SAST scan results output"),
    ] = [
        "cyclonedx",
        "html",
    ]

    scanners: Annotated[
        List[
            Union[
                CustomScanner,
                SyftScanner,
            ]
        ],
        Field(description="List of SBOM scanners to enable"),
    ] = [
        SyftScanner(),
    ]


class ASHConfig(BaseModel):
    """Main configuration model for Automated Security Helper."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        extra="allow",
    )

    # Project information
    project_name: Annotated[str, Field(description="Name of the project being scanned")]

    # Build configuration
    build: Annotated[
        BuildConfig,
        Field(description="Build-time configuration settings"),
    ] = BuildConfig()

    # Scanner type configurations
    sast: Annotated[
        SASTScannerConfig,
        Field(description="SAST scanner configuration"),
    ] = SASTScannerConfig()

    sbom: Annotated[
        SBOMScannerConfig,
        Field(description="SBOM scanner configuration"),
    ] = SBOMScannerConfig()

    # General scan settings
    fail_on_findings: Annotated[
        bool,
        Field(
            description="Whether to exit with non-zero code if findings are detected"
        ),
    ] = True

    ignore_paths: Annotated[
        List[str],
        Field(description="List of paths to ignore during scanning"),
    ] = []

    output_dir: Annotated[
        str,
        Field(description="Directory to store scan outputs"),
    ] = "ash_output"

    scan_paths: Annotated[List[str], Field(description="List of paths to scan")] = ["."]

    severity_threshold: Annotated[
        str, Field(description="Minimum severity level to report")
    ] = "LOW"

    max_concurrent_scanners: Annotated[
        int, Field(description="Maximum number of scanners to run concurrently", ge=1)
    ] = 4
