from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing import Annotated, Any, Callable, List, Dict, Literal
from automated_security_helper.models.data_interchange import ExportFormat
from automated_security_helper.config.scanner_types import (
    BanditScannerConfig,
    ScannerBaseConfig,
    CfnNagScannerConfig,
    CheckovScannerConfig,
    CustomScannerConfig,
    GitSecretsScannerConfig,
    NpmAuditScannerConfig,
    SemgrepScannerConfig,
    CdkNagScannerConfig,
    GrypeScannerConfig,
    SyftScannerConfig,
)


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
        List[str],
        Field(description="Command to run that should return the scanner version"),
    ] = []
    output_stream: Annotated[
        Literal["stdout", "stderr", "file"],
        Field(
            description="Where to read scanner output from. Can be 'stdout', 'stderr' or 'file'. Defaults to 'stdout' to capture the output of the scanner directly."
        ),
    ] = "stdout"

    @field_validator("get_tool_version_command", check_fields=False)
    @classmethod
    def resolve_tool_version(
        cls, get_tool_version_command: List[str] | Callable[[], List[str]]
    ) -> List[str]:
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


class BuildToolInstall(BaseModel):
    """Configuration model for tool installation during build."""

    model_config = ConfigDict(extra="allow")
    script: Annotated[str, Field(description="Installation script for the tool")] = ""


class CustomBuildScannerConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    __pydantic_extra__: Dict[str, List[ScannerPluginConfig]] = Field(init=False)

    sast: Annotated[
        List[ScannerPluginConfig],
        Field(description="Scanner configurations by type"),
    ] = []

    sbom: Annotated[
        List[ScannerPluginConfig],
        Field(description="Scanner configurations by type"),
    ] = []


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


# class SecurityScanConfig(BaseModel):
#     """Configuration model for security scanning settings."""

#     model_config = ConfigDict(extra="allow")
#     sast: Annotated[
#         List[
#             Union[
#                 CustomScannerConfig,
#                 BanditScannerConfig,
#                 SemgrepScannerConfig,
#                 CdkNagScannerConfig,
#                 GrypeScannerConfig,
#             ]
#         ],
#         Field(description="List of SAST scanners to enable"),
#     ] = [
#         BanditScannerConfig(),
#         CdkNagScannerConfig(),
#         GrypeScannerConfig(),
#         SemgrepScannerConfig(),
#     ]
#     sbom: Annotated[
#         List[
#             Union[
#                 CustomScannerConfig,
#                 SyftScannerConfig,
#             ]
#         ],
#         Field(description="List of SBOM scanners to enable"),
#     ] = [
#         SyftScannerConfig(),
#     ]


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


class ScannerClassConfig(BaseModel):
    """Configuration model for scanner classes."""

    model_config = ConfigDict(extra="allow")


class ScannerListConfig(ScannerClassConfig):
    __pydantic_extra__: Dict[str, CustomScannerConfig | bool]


class SASTScannerListConfig(ScannerListConfig):
    bandit: Annotated[BanditScannerConfig | bool, Field()] = BanditScannerConfig()
    cdknag: Annotated[CdkNagScannerConfig | bool, Field()] = CdkNagScannerConfig()
    cfnnag: Annotated[CfnNagScannerConfig | bool, Field()] = CfnNagScannerConfig()
    checkov: Annotated[CheckovScannerConfig | bool, Field()] = CheckovScannerConfig()
    gitsecrets: Annotated[GitSecretsScannerConfig | bool, Field()] = (
        GitSecretsScannerConfig()
    )
    grype: Annotated[GrypeScannerConfig | bool, Field()] = GrypeScannerConfig()
    npmaudit: Annotated[NpmAuditScannerConfig | bool, Field()] = NpmAuditScannerConfig()
    semgrep: Annotated[SemgrepScannerConfig | bool, Field()] = SemgrepScannerConfig()


class SBOMScannerListConfig(ScannerListConfig):
    syft: Annotated[SyftScannerConfig | bool, Field()] = SyftScannerConfig()


class SASTScannerConfig(ScannerClassConfig):
    """Configuration model for SAST scanners."""

    # Additional optional settings
    output_formats: Annotated[
        List[ExportFormat],
        Field(description="Format for SAST scan results output"),
    ] = [
        ExportFormat.TEXT,
        ExportFormat.JSON,
        ExportFormat.JUNITXML,
        ExportFormat.HTML,
    ]

    scanners: Annotated[
        SASTScannerListConfig,
        Field(
            description="SAST scanners to enable and their corresponding configurations."
        ),
    ] = SASTScannerListConfig()


class SBOMScannerConfig(ScannerClassConfig):
    """Configuration model for SBOM scanners."""

    # Additional optional settings
    output_formats: Annotated[
        List[
            Literal[
                ExportFormat.TEXT,
                ExportFormat.YAML,
                ExportFormat.JSON,
                ExportFormat.JUNITXML,
                ExportFormat.HTML,
                ExportFormat.CYCLONEDX,
                ExportFormat.SPDX,
            ]
        ],
        Field(description="Format for SBOM scan results output"),
    ] = [
        ExportFormat.JSON,
        ExportFormat.HTML,
        ExportFormat.CYCLONEDX,
    ]

    scanners: Annotated[
        SBOMScannerListConfig,
        Field(
            description="SBOM scanners to enable and their corresponding configurations."
        ),
    ] = SBOMScannerListConfig()


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
