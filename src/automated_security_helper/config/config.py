from pathlib import Path
from pydantic import BaseModel, ConfigDict, Field
from typing import Annotated, List, Dict, Literal

import yaml
from automated_security_helper.models.core import ScannerBaseConfig, ScannerPluginConfig
from automated_security_helper.models.core import ExportFormat
from automated_security_helper.config.scanner_types import (
    CfnNagScannerConfig,
    CheckovScannerConfig,
    CustomScannerConfig,
    GitSecretsScannerConfig,
    NpmAuditScannerConfig,
    SemgrepScannerConfig,
    GrypeScannerConfig,
    SyftScannerConfig,
)
from automated_security_helper.scanners.bandit_scanner import BanditScannerConfig
from automated_security_helper.scanners.cdk_nag_scanner import CdkNagScannerConfig


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
        List[ScannerPluginConfig],
        Field(description="Scanner configurations by type"),
    ] = []


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


class OutputConfig(BaseModel):
    """Configuration model for output formats."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
    )

    formats: Annotated[
        List[str],
        Field(
            description="List of output formats to generate",
            default_factory=lambda: ["json"],
        ),
    ]

    def __init__(self, **data):
        super().__init__(**data)
        self.validate_formats()

    def validate_formats(self):
        """Validate output formats."""
        valid_formats = [
            "json",
            "text",
            "html",
            "csv",
            "yaml",
            "junitxml",
            "sarif",
            "asff",
            "cyclonedx",
            "spdx",
        ]
        invalid_formats = [fmt for fmt in self.formats if fmt not in valid_formats]
        if invalid_formats:
            raise ValueError(f"Invalid output formats: {invalid_formats}")


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

    # Output configuration
    output: Annotated[
        OutputConfig,
        Field(description="Output configuration settings"),
    ] = OutputConfig()

    converters: Annotated[
        Dict[str, bool],
        Field(
            description="The map of converters and a boolean value indicating whether they should be enabled or disabled"
        ),
    ] = {
        "jupyter": True,
        "archive": True,
    }

    scanners: Annotated[
        List[
            # Base/custom/generic types
            ScannerBaseConfig
            | CustomScannerConfig
            |
            # Known scanner types
            BanditScannerConfig
            | CdkNagScannerConfig
            | CfnNagScannerConfig
            | CheckovScannerConfig
            | GitSecretsScannerConfig
            | GrypeScannerConfig
            | NpmAuditScannerConfig
            | SemgrepScannerConfig
            | SyftScannerConfig
        ],
        Field(description="Scanner configurations by type"),
    ] = [
        BanditScannerConfig(),
        CdkNagScannerConfig(),
        CfnNagScannerConfig(),
        CheckovScannerConfig(),
        GitSecretsScannerConfig(),
        GrypeScannerConfig(),
        NpmAuditScannerConfig(),
        SemgrepScannerConfig(),
        SyftScannerConfig(),
    ]

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

    @classmethod
    def from_file(cls, config_path: Path) -> "ASHConfig":
        """Load configuration from a file."""
        with open(config_path, "r") as f:
            # Using `yaml.safe_load()` as it handles both JSON and YAML data the same.
            config_data = yaml.safe_load(f)
        return cls(**config_data)

    def save(self, config_path: Path):
        """Save configuration to a file."""
        with open(config_path, "w") as f:
            yaml.safe_dump(self.model_dump(), f, indent=2)

    def get_scanners(self) -> Dict[str, ScannerPluginConfig]:
        """Get a dictionary of scanners and their corresponding configurations."""
        scanner_configs: Dict[str, ScannerPluginConfig] = {
            scanner.name: scanner for scanner in self.build.custom_scanners
        }
        for scanner in self.scanners:
            scanner_configs[scanner.name] = scanner

        return scanner_configs
