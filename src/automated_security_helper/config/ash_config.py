from pathlib import Path
from pydantic import BaseModel, ConfigDict, Field
from typing import Annotated, Any, List, Dict, Literal

import yaml
from automated_security_helper.base.scanner_plugin import ScannerPlugin
from automated_security_helper.config.scanner_types import (
    CfnNagScannerConfig,
    CustomScannerConfig,
    GitSecretsScannerConfig,
    NpmAuditScannerConfig,
    SemgrepScannerConfig,
    GrypeScannerConfig,
    SyftScannerConfig,
)
from automated_security_helper.scanners.bandit_scanner import BanditScannerConfig
from automated_security_helper.scanners.cdk_nag_scanner import (
    CdkNagScannerConfig,
)
from automated_security_helper.scanners.checkov_scanner import (
    CheckovScannerConfig,
)


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
        List[ScannerPlugin],
        Field(description="Scanner configurations by type"),
    ] = []


class ScannerTypeConfig(BaseModel):
    """Configuration model for scanner type specific settings."""

    model_config = ConfigDict(extra="allow")
    enabled: Annotated[
        bool, Field(description="Whether this scanner type is enabled")
    ] = True


class ScannerConfigSegment(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        use_enum_values=True,
        extra="allow",
    )

    __pydantic_extra__: Dict[str, CustomScannerConfig] = {}

    bandit: Annotated[
        BanditScannerConfig, Field(description="Configure the options for Bandit")
    ] = BanditScannerConfig()
    cdk_nag: Annotated[
        CdkNagScannerConfig,
        Field(description="Configure the options for CdkNag", alias="cdk-nag"),
    ] = CdkNagScannerConfig()
    cfn_nag: Annotated[
        CfnNagScannerConfig,
        Field(description="Configure the options for CfnNag", alias="cfn-nag"),
    ] = CfnNagScannerConfig()
    checkov: Annotated[
        CheckovScannerConfig, Field(description="Configure the options for Checkov")
    ] = CheckovScannerConfig()
    git_secrets: Annotated[
        GitSecretsScannerConfig,
        Field(description="Configure the options for GitSecrets", alias="git-secrets"),
    ] = GitSecretsScannerConfig()
    grype: Annotated[
        GrypeScannerConfig, Field(description="Configure the options for Grype")
    ] = GrypeScannerConfig()
    npm_audit: Annotated[
        NpmAuditScannerConfig,
        Field(description="Configure the options for NpmAudit", alias="npm-audit"),
    ] = NpmAuditScannerConfig()
    semgrep: Annotated[
        SemgrepScannerConfig, Field(description="Configure the options for Semgrep")
    ] = SemgrepScannerConfig()
    syft: Annotated[
        SyftScannerConfig, Field(description="Configure the options for Syft")
    ] = SyftScannerConfig()


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

    output_formats: Annotated[
        List[
            Literal[
                "text",
                "yaml",
                "json",
                "junitxml",
                "html",
                "cyclonedx",
                "spdx",
                "sarif",
                "csv",
            ]
        ],
        Field(description="Format for scanner results output"),
    ] = [
        "text",
        "yaml",
        "json",
        "junitxml",
        "html",
        "cyclonedx",
        "spdx",
        "sarif",
        "csv",
    ]

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
        ScannerConfigSegment,
        Field(description="Scanner configurations by type"),
    ] = ScannerConfigSegment()

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

    severity_threshold: Annotated[
        Literal["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        Field(
            description="Minimum severity level to raise unsuccessful exit codes from ASH if found"
        ),
    ] = "MEDIUM"

    max_concurrent_scanners: Annotated[
        int, Field(description="Maximum number of scanners to run concurrently", ge=1)
    ] = 4

    no_cleanup: Annotated[
        bool, Field(description="Whether to keep the work directory after scanning")
    ] = False

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

    def get_scanners(self) -> Dict[str, Any]:
        """Get a dictionary of scanners and their corresponding configurations."""
        scanner_configs: Dict[str, Any] = {
            scanner.config.name: scanner for scanner in self.build.custom_scanners
        }
        scanner: (
            CustomScannerConfig
            | BanditScannerConfig
            | CdkNagScannerConfig
            | CfnNagScannerConfig
            | CheckovScannerConfig
            | GitSecretsScannerConfig
            | GrypeScannerConfig
            | NpmAuditScannerConfig
            | SemgrepScannerConfig
            | SyftScannerConfig
        )
        for scanner in self.scanners.model_dump().values():
            scanner_configs[scanner.name] = scanner

        return scanner_configs
