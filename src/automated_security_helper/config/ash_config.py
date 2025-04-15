from pathlib import Path
import re
from pydantic import BaseModel, ConfigDict, Field
from typing import Annotated, Any, List, Dict, Literal

import yaml
from automated_security_helper.base.converter_plugin import ConverterPluginConfigBase
from automated_security_helper.base.reporter_plugin import ReporterPluginConfigBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.config.scanner_types import (
    CfnNagScannerConfig,
    NpmAuditScannerConfig,
    SemgrepScannerConfig,
    GrypeScannerConfig,
    SyftScannerConfig,
)
from automated_security_helper.scanners.ash_default.bandit_scanner import (
    BanditScannerConfig,
)
from automated_security_helper.scanners.ash_default.cdk_nag_scanner import (
    CdkNagScannerConfig,
)
from automated_security_helper.scanners.ash_default.checkov_scanner import (
    CheckovScannerConfig,
)
from automated_security_helper.scanners.ash_default.custom_scanner import (
    CustomScannerConfig,
)
from automated_security_helper.scanners.ash_default.detect_secrets_scanner import (
    DetectSecretsScannerConfig,
)
from automated_security_helper.utils.log import ASH_LOGGER


class BuildConfig(BaseModel):
    """Configuration model for build-time settings."""

    model_config = ConfigDict(extra="allow")

    build_mode: Annotated[
        Literal["ONLINE", "OFFLINE"],
        Field(
            description="Build mode for the container image build. If enabled, also enables offline mode during the scan phase without any explicit directive when scanning."
        ),
    ] = "OFFLINE"
    tool_install_scripts: Annotated[
        Dict[str, List[str]],
        Field(description="Map of tool names to their installation scripts"),
    ] = {}
    custom_scanners: Annotated[
        List[ScannerPluginBase],
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

    __pydantic_extra__: Dict[str, Any | CustomScannerConfig] = {}

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
    detect_secrets: Annotated[
        DetectSecretsScannerConfig,
        Field(
            description="Configure the options for DetectSecrets",
            alias="detect-secrets",
        ),
    ] = DetectSecretsScannerConfig()
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
            | DetectSecretsScannerConfig
            | GrypeScannerConfig
            | NpmAuditScannerConfig
            | SemgrepScannerConfig
            | SyftScannerConfig
        )
        for scanner in self.scanners.model_dump().values():
            scanner_configs[scanner.name] = scanner

        return scanner_configs

    def get_plugin_config(
        self,
        plugin_type: Literal["converter", "scanner", "reporter"],
        plugin_name: str,
    ):
        found = None
        # Reduce the provided plugin_name in case the class name was passed in,
        # as the config itself uses kebab-case keys while the classes use PascalCase
        # for class names.
        og_plugin_name = plugin_name
        plugin_name = re.sub(
            r"Scanner(Config)?", "", plugin_name, flags=re.IGNORECASE
        ).lower()
        # if plugin_type == "builder":
        #     for item in self.build.custom_scanners:
        #         if isinstance(item, dict):
        #             item = ScannerPluginBase(**item)
        #         if plugin_name in [
        #             item.name,
        #             item.__class__.__name__,
        #         ]:
        #             found = item
        #             break
        if plugin_type == "scanner":
            item_dict = self.scanners.model_dump()
            key_map = {}
            for item_name, item in item_dict.items():
                if found is not None:
                    break
                for possible in list(
                    sorted(
                        set(
                            [
                                item_name,
                                re.sub(
                                    r"[^a-z0-9+]+", "", item_name, flags=re.IGNORECASE
                                ).lower(),
                            ]
                        )
                    )
                ):
                    key_map[possible] = item_name
            if plugin_name in key_map:
                ASH_LOGGER.debug(
                    f"Found {plugin_type} plugin {og_plugin_name} under config key {key_map[plugin_name]}"
                )
                found = item_dict[key_map[plugin_name]]
            # else:
            #     item: ScannerPluginConfigBase
            #     for item_name, item in self.scanners.model_dump().items():
            #         if isinstance(item, dict):
            #             item = ScannerPluginConfigBase(**item)
            #         possible = list(
            #             sorted(
            #                 set(
            #                     [
            #                         item_name,
            #                         item.name,
            #                         re.sub(
            #                             r"\W", "", item_name, flags=re.IGNORECASE
            #                         ).lower(),
            #                         re.sub(
            #                             r"\W", "", item.name, flags=re.IGNORECASE
            #                         ).lower(),
            #                     ]
            #                 )
            #             )
            #         )
            #         ASH_LOGGER.debug(
            #             f"(item_name: {item_name}) Searching from plugin_name '{plugin_name}' in possible members: {possible}"
            #         )
            #         if plugin_name in possible:
            #             found = item
            #             break
        if plugin_type == "converter":
            item_dict = self.converters
            key_map = {}
            for item_name, item in item_dict.items():
                if found is not None:
                    break
                for possible in list(
                    sorted(
                        set(
                            [
                                item_name,
                                re.sub(
                                    r"[^a-z0-9+]+", "", item_name, flags=re.IGNORECASE
                                ).lower(),
                            ]
                        )
                    )
                ):
                    key_map[possible] = item_name
            if plugin_name in key_map:
                ASH_LOGGER.debug(
                    f"Found {plugin_type} plugin {og_plugin_name} under config key {key_map[plugin_name]}"
                )
                found = ConverterPluginConfigBase(
                    name=item_name, enabled=item_dict[key_map[plugin_name]]["enabled"]
                )
            # for item_name, enabled in self.converters.items():
            #     if plugin_name == item_name:
            #         found = ConverterPluginConfigBase(name=item_name, enabled=enabled)
            #         break
        if plugin_type == "reporter":
            for item_name in self.output_formats:
                if plugin_name in list(
                    sorted(
                        set(
                            [
                                item_name,
                                re.sub(
                                    r"\W", "", item_name, flags=re.IGNORECASE
                                ).lower(),
                            ]
                        )
                    )
                ):
                    found = ReporterPluginConfigBase(name=item_name, enabled=True)
                    break

        if found is not None:
            ASH_LOGGER.debug(
                f"Found config for {plugin_type} plugin {og_plugin_name}: {found}"
            )

        return found
