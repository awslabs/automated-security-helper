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
from automated_security_helper.core.constants import ASH_DEFAULT_SEVERITY_LEVEL
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.reporters.ash_default.asff_reporter import (
    ASFFReporterConfig,
)
from automated_security_helper.reporters.ash_default.csv_reporter import (
    CSVReporterConfig,
)
from automated_security_helper.reporters.ash_default.cyclonedx_reporter import (
    CycloneDXReporterConfig,
)
from automated_security_helper.reporters.ash_default.html_reporter import (
    HTMLReporterConfig,
)
from automated_security_helper.reporters.ash_default.json_reporter import (
    JSONReporterConfig,
)
from automated_security_helper.reporters.ash_default.junitxml_reporter import (
    JUnitXMLReporterConfig,
)
from automated_security_helper.reporters.ash_default.ocsf_reporter import (
    OCSFReporterConfig,
)
from automated_security_helper.reporters.ash_default.spdx_reporter import (
    SPDXReporterConfig,
)
from automated_security_helper.reporters.ash_default.text_reporter import (
    TextReporterConfig,
)
from automated_security_helper.reporters.ash_default.yaml_reporter import (
    YAMLReporterConfig,
)
from automated_security_helper.reporters.ash_default.sarif_reporter import (
    SARIFReporterConfig,
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


class ReporterConfigSegment(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        use_enum_values=True,
        extra="allow",
    )

    __pydantic_extra__: Dict[str, Any | ReporterPluginConfigBase] = {}

    asff: Annotated[
        ASFFReporterConfig,
        Field(description="Configure the options for the ASFF reporter"),
    ] = ASFFReporterConfig()
    csv: Annotated[
        CSVReporterConfig,
        Field(description="Configure the options for the CSV reporter"),
    ] = CSVReporterConfig()
    cyclonedx: Annotated[
        CycloneDXReporterConfig,
        Field(description="Configure the options for the CycloneDX reporter"),
    ] = CycloneDXReporterConfig()
    # Do the same for html, json, junitxml, ocsf, sarif, spdx, text, and yaml
    html: Annotated[
        HTMLReporterConfig,
        Field(description="Configure the options for the HTML reporter"),
    ] = HTMLReporterConfig()
    json: Annotated[
        JSONReporterConfig,
        Field(description="Configure the options for the JSON reporter"),
    ] = JSONReporterConfig()
    junitxml: Annotated[
        JUnitXMLReporterConfig,
        Field(description="Configure the options for the JUnit XML reporter"),
    ] = JUnitXMLReporterConfig()
    ocsf: Annotated[
        OCSFReporterConfig,
        Field(description="Configure the options for the OCSF reporter"),
    ] = OCSFReporterConfig()
    sarif: Annotated[
        SARIFReporterConfig,
        Field(description="Configure the options for the SARIF reporter"),
    ] = SARIFReporterConfig()
    spdx: Annotated[
        SPDXReporterConfig,
        Field(description="Configure the options for the SPDX reporter"),
    ] = SPDXReporterConfig()
    text: Annotated[
        TextReporterConfig,
        Field(description="Configure the options for the Text reporter"),
    ] = TextReporterConfig()
    yaml: Annotated[
        YAMLReporterConfig,
        Field(description="Configure the options for the YAML reporter"),
    ] = YAMLReporterConfig()


class AshGlobalDefaultsConfigSection(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )

    severity_threshold: Annotated[
        Literal["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        Field(
            description="Global minimum severity level to consider findings as failures across all scanners"
        ),
    ] = ASH_DEFAULT_SEVERITY_LEVEL

    ignore_paths: Annotated[
        List[IgnorePathWithReason],
        Field(
            description="Global list of IgnorePaths. Each path requires a reason for ignoring, e.g. 'Folder contains test data only and is not committed'."
        ),
    ] = []


class ASHConfig(BaseModel):
    """Main configuration model for Automated Security Helper."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        extra="allow",
    )

    # Project information
    project_name: Annotated[
        str, Field(description="Name of the project being scanned")
    ] = "ash-target"

    # Build configuration
    build: Annotated[
        BuildConfig,
        Field(description="Build-time configuration settings"),
    ] = BuildConfig()

    # output_formats: Annotated[
    #     List[
    #         Literal[
    #             "asff",
    #             "csv",
    #             "cyclonedx",
    #             "html",
    #             "json",
    #             "junitxml",
    #             "ocsf",
    #             "sarif",
    #             "spdx",
    #             "text",
    #             "yaml",
    #         ] | str
    #     ],
    #     Field(description="Format for scanner results output"),
    # ] = [
    #     "asff",
    #     "csv",
    #     "cyclonedx",
    #     "html",
    #     "json",
    #     "junitxml",
    #     "ocsf",
    #     "sarif",
    #     "spdx",
    #     "text",
    #     "yaml",
    # ]

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
        Field(description="Scanner configurations by name."),
    ] = ScannerConfigSegment()

    reporters: Annotated[
        ReporterConfigSegment,
        Field(description="Reporter configurations by name."),
    ] = ReporterConfigSegment()

    # General scan settings
    fail_on_findings: Annotated[
        bool,
        Field(
            description="Whether to exit with non-zero code if findings are detected"
        ),
    ] = True

    # Legacy global settings (deprecated)
    global_settings: Annotated[
        AshGlobalDefaultsConfigSection,
        Field(
            description="Global default settings for ASH shared across scanners. If the same setting exists at the scanner level and is set in both places, the scanner level settings take precedence."
        ),
    ] = AshGlobalDefaultsConfigSection()

    external_reports_to_include: Annotated[
        List[str],
        Field(
            description="List of external reports to include in the final report. These can be SARIF, CycloneDX, or CDK synth paths that have produced NagReport CSVs or JSON files.",
        ),
    ] = []

    output_dir: Annotated[
        str,
        Field(description="Directory to store scan outputs"),
    ] = "ash_output"

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
            yaml.safe_dump(self.model_dump(by_alias=True), f, indent=2)

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
        for scanner in self.scanners.model_dump(by_alias=True).values():
            sname = (
                scanner.name
                if hasattr(scanner, "name")
                else scanner["name"]
                if isinstance(scanner, dict)
                else None
            )
            scanner_configs[sname] = scanner

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
            r"(Converter|Scanner|Reporter)(Config)?",
            "",
            plugin_name,
            flags=re.IGNORECASE,
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
        if plugin_type in ["scanner", "reporter"]:
            item_dict = (
                self.scanners.model_dump(by_alias=True)
                if plugin_type == "scanner"
                else (
                    self.reporters.model_dump(by_alias=True)
                    if plugin_type == "reporter"
                    else {}
                )
            )
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
            # Try direct match first
            if plugin_name in item_dict:
                ASH_LOGGER.debug(
                    f"Found {plugin_type} plugin {og_plugin_name} with direct match"
                )
                found = item_dict[plugin_name]
            # Then try normalized match
            elif plugin_name in key_map:
                ASH_LOGGER.debug(
                    f"Found {plugin_type} plugin {og_plugin_name} under config key {key_map[plugin_name]}"
                )
                found = item_dict[key_map[plugin_name]]

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
                    name=item_name, enabled=item_dict[key_map[plugin_name]]
                )

        # if plugin_type == "reporter":
        #     item_dict = self.reporters.model_dump(by_alias=True)
        #     key_map = {}
        #     for item_name, item in item_dict.items():
        #         if found is not None:
        #             break
        #         for possible in list(
        #             sorted(
        #                 set(
        #                     [
        #                         item_name,
        #                         re.sub(
        #                             r"[^a-z0-9+]+", "", item_name, flags=re.IGNORECASE
        #                         ).lower(),
        #                     ]
        #                 )
        #             )
        #         ):
        #             key_map[possible] = item_name
        #     # Try direct match first
        #     if plugin_name in item_dict:
        #         ASH_LOGGER.debug(
        #             f"Found {plugin_type} plugin {og_plugin_name} with direct match"
        #         )
        #         found = item_dict[plugin_name]
        #     # Then try normalized match
        #     elif plugin_name in key_map:
        #         ASH_LOGGER.debug(
        #             f"Found {plugin_type} plugin {og_plugin_name} under config key {key_map[plugin_name]}"
        #         )
        #         found = item_dict[key_map[plugin_name]]
        if found is not None:
            ASH_LOGGER.debug(
                f"Found config for {plugin_type} plugin {og_plugin_name}: {found}"
            )

        return found
