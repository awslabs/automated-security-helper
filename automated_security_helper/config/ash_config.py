import json
import os
from pathlib import Path
import re
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from typing import Annotated, Any, List, Dict, Literal

import yaml
from automated_security_helper.base.converter_plugin import ConverterPluginConfigBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import ReporterPluginConfigBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
    JupyterConverterConfig,
)
from automated_security_helper.core.constants import (
    ASH_CONFIG_FILE_NAMES,
    ASH_DEFAULT_SEVERITY_LEVEL,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import IgnorePathWithReason, AshSuppression
from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
    CSVReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.cyclonedx_reporter import (
    CycloneDXReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_sast_reporter import (
    GitLabSASTReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HTMLReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
    FlatJSONReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
    JUnitXMLReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
    OCSFReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.spdx_reporter import (
    SPDXReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.yaml_reporter import (
    YAMLReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
    SARIFReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    CdkNagScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
    CfnNagScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
    GrypeScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
    SyftScannerConfig,
)
from automated_security_helper.utils.log import ASH_LOGGER


# Define BuildConfig class
class BuildConfig(BaseModel):
    """Configuration model for build-time settings."""

    model_config = ConfigDict(extra="forbid")

    build_mode: Annotated[
        Literal["ONLINE", "OFFLINE"],
        Field(
            description="Build mode for the container image build. If enabled, also enables offline mode during the scan phase without any explicit directive when scanning."
        ),
    ] = "ONLINE"
    tool_install_scripts: Annotated[
        Dict[str, List[str]],
        Field(description="Map of tool names to their installation scripts"),
    ] = {}
    custom_scanners: Annotated[
        List[ScannerPluginBase],
        Field(description="Scanner configurations by type"),
    ] = []


class ConverterConfigSegment(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        use_enum_values=True,
        extra="allow",
    )

    __pydantic_extra__: Dict[str, Any | ConverterPluginConfigBase] = {}

    archive: Annotated[
        ArchiveConverterConfig,
        Field(description="Configure the options for the ArchiveConverter"),
    ] = ArchiveConverterConfig()
    jupyter: Annotated[
        JupyterConverterConfig,
        Field(description="Configure the options for the JupyterConverter"),
    ] = JupyterConverterConfig()


class ScannerConfigSegment(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        use_enum_values=True,
        extra="allow",
    )

    __pydantic_extra__: Dict[str, Any | ScannerPluginConfigBase] = {}

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
    opengrep: Annotated[
        OpengrepScannerConfig, Field(description="Configure the options for Opengrep")
    ] = OpengrepScannerConfig()
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
    flat_json: Annotated[
        FlatJSONReporterConfig,
        Field(
            description="Configure the options for the Flat JSON reporter",
            alias="flat-json",
        ),
    ] = FlatJSONReporterConfig()
    gitlab_sast: Annotated[
        GitLabSASTReporterConfig,
        Field(
            description="Configure the options for the GitLab SAST reporter",
            alias="gitlab-sast",
        ),
    ] = GitLabSASTReporterConfig()
    junitxml: Annotated[
        JUnitXMLReporterConfig,
        Field(description="Configure the options for the JUnit XML reporter"),
    ] = JUnitXMLReporterConfig()
    markdown: Annotated[
        MarkdownReporterConfig,
        Field(description="Configure the options for the Markdown reporter"),
    ] = MarkdownReporterConfig()
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


class MCPResourceManagementConfig(BaseModel):
    """Configuration model for MCP resource management settings."""

    model_config = ConfigDict(extra="forbid")

    # Concurrent operation limits
    max_concurrent_scans: Annotated[
        int,
        Field(
            description="Maximum number of concurrent scans allowed",
            ge=1,
            le=10,
        ),
    ] = 3

    max_concurrent_tasks: Annotated[
        int,
        Field(
            description="Maximum number of concurrent async tasks allowed",
            ge=1,
            le=50,
        ),
    ] = 20

    # Thread pool configuration
    thread_pool_max_workers: Annotated[
        int,
        Field(
            description="Maximum number of worker threads in the shared thread pool",
            ge=1,
            le=20,
        ),
    ] = 4

    # Timeout configuration (in seconds)
    scan_timeout_seconds: Annotated[
        int,
        Field(
            description="Maximum time allowed for a single scan operation in seconds",
            ge=60,
            le=7200,  # 2 hours max
        ),
    ] = 1800  # 30 minutes default

    operation_timeout_seconds: Annotated[
        int,
        Field(
            description="Default timeout for general operations in seconds",
            ge=30,
            le=600,  # 10 minutes max
        ),
    ] = 180  # 3 minutes default

    shutdown_timeout_seconds: Annotated[
        int,
        Field(
            description="Maximum time to wait for graceful shutdown in seconds",
            ge=5,
            le=300,  # 5 minutes max
        ),
    ] = 30

    # Resource monitoring thresholds
    memory_warning_threshold_mb: Annotated[
        int,
        Field(
            description="Memory usage threshold in MB that triggers warnings",
            ge=100,
            le=8192,  # 8GB max
        ),
    ] = 1024  # 1GB default

    memory_critical_threshold_mb: Annotated[
        int,
        Field(
            description="Memory usage threshold in MB that triggers protective actions",
            ge=200,
            le=16384,  # 16GB max
        ),
    ] = 2048  # 2GB default

    task_count_warning_threshold: Annotated[
        int,
        Field(
            description="Active task count that triggers warnings",
            ge=5,
            le=100,
        ),
    ] = 15

    # Message size limits
    max_message_size_bytes: Annotated[
        int,
        Field(
            description="Maximum size of MCP messages in bytes",
            ge=1024,  # 1KB min
            le=100 * 1024 * 1024,  # 100MB max
        ),
    ] = 10 * 1024 * 1024  # 10MB default

    # Path validation limits
    max_path_length: Annotated[
        int,
        Field(
            description="Maximum allowed path length for security validation",
            ge=256,
            le=8192,
        ),
    ] = 4096

    # Directory size limits
    max_directory_size_mb: Annotated[
        int,
        Field(
            description="Maximum directory size in MB that can be scanned",
            ge=10,
            le=10240,  # 10GB max
        ),
    ] = 1000  # 1GB default

    # Health check configuration
    enable_health_checks: Annotated[
        bool,
        Field(
            description="Enable periodic health checks and resource monitoring",
        ),
    ] = True

    health_check_interval_seconds: Annotated[
        int,
        Field(
            description="Interval between health checks in seconds",
            ge=10,
            le=300,  # 5 minutes max
        ),
    ] = 60  # 1 minute default

    # Logging configuration
    enable_resource_logging: Annotated[
        bool,
        Field(
            description="Enable detailed resource management logging",
        ),
    ] = True

    log_resource_operations: Annotated[
        bool,
        Field(
            description="Log individual resource operations for debugging",
        ),
    ] = False


class AshConfigGlobalSettingsSection(BaseModel):
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

    suppressions: Annotated[
        List[AshSuppression],
        Field(
            description="Global list of suppression rules. Each rule specifies findings to suppress based on rule ID, file path, and optional line numbers."
        ),
    ] = []


class AshConfig(BaseModel):
    """Main configuration model for Automated Security Helper."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        extra="ignore",
    )

    # Project information
    project_name: Annotated[
        str,
        Field(
            description="Name of the project being scanned",
        ),
    ] = os.environ.get("ASH_PROJECT_NAME", "ash-scan")

    global_settings: Annotated[
        AshConfigGlobalSettingsSection,
        Field(
            description="Global default settings for ASH shared across scanners. If the same setting exists at the scanner level and is set in both places, the scanner level settings take precedence."
        ),
    ] = AshConfigGlobalSettingsSection()

    fail_on_findings: Annotated[
        bool,
        Field(
            description="Whether to exit with non-zero code if findings are detected"
        ),
    ] = True

    ash_plugin_modules: Annotated[
        List[str],
        Field(
            description="List of Python modules to import containing ASH plugins and/or event subscribers. These are loaded in addition to the default modules.",
        ),
    ] = []

    external_reports_to_include: Annotated[
        List[str],
        Field(
            description="List of external reports to include in the final report. These can be paths to SARIF or CycloneDX reports produced by other tools.",
        ),
    ] = []

    # Build configuration - use a default instance instead of calling the constructor
    build: Annotated[
        BuildConfig | None,
        Field(description="Build-time configuration settings"),
    ] = None

    converters: Annotated[
        ConverterConfigSegment,
        Field(description="Converter configurations by name."),
    ] = ConverterConfigSegment()

    scanners: Annotated[
        ScannerConfigSegment,
        Field(description="Scanner configurations by name."),
    ] = ScannerConfigSegment()

    reporters: Annotated[
        ReporterConfigSegment,
        Field(description="Reporter configurations by name."),
    ] = ReporterConfigSegment()

    # MCP resource management configuration
    mcp_resource_management: Annotated[
        MCPResourceManagementConfig,
        Field(
            description="Configuration for MCP server resource management and limits",
            alias="mcp-resource-management",
        ),
    ] = MCPResourceManagementConfig()

    @classmethod
    def from_file(cls, config_path: Path) -> "AshConfig":
        """Load configuration from a file."""
        with open(config_path, mode="r", encoding="utf-8") as f:
            if str(config_path).endswith(".json"):
                config_data = json.load(f)
            else:
                pattern = re.compile(r"^\${(\w+):?(.*)?}")
                loader = yaml.SafeLoader
                loader.add_implicit_resolver("!ENV", pattern, None)

                def constructor_env_variables(loader, node):
                    value = loader.construct_scalar(node)
                    match = pattern.findall(value)  # to find all env variables in line
                    if match:
                        full_value = value
                        for g in match:
                            ASH_LOGGER.debug(f"Evaluating env var match: {g}")
                            var_name = g[0] if isinstance(g, tuple) else g
                            default_val = g[1] if isinstance(g, tuple) else None
                            if default_val == "None":
                                default_val = None
                            resolved_var = os.environ.get(var_name, None)
                            if resolved_var is None:
                                ASH_LOGGER.warning(
                                    f"Environment variable {var_name} not set"
                                    + (
                                        f", using default value of {default_val}"
                                        if isinstance(g, tuple)
                                        else ""
                                    )
                                )
                                if default_val is None:
                                    resolved_var = ""
                                else:
                                    resolved_var = default_val
                            rep_val = ":".join(g) if isinstance(g, tuple) else g
                            full_value = full_value.replace(
                                f"${{{rep_val}}}", resolved_var
                            )
                        if full_value.strip() == "":
                            return None
                        return full_value.strip()
                    return value

                loader.add_constructor("!ENV", constructor_env_variables)
                config_data = yaml.load(f, Loader=loader)  # nosec B506 - This is using a custom SafeLoader to enable support of !ENV tag evaluation
        return cls.model_validate(config_data, strict=True)

    @classmethod
    def load_config(
        cls,
        config_path: Path | str | None = None,
        source_dir: Path | None = Path.cwd(),
    ) -> "AshConfig":
        """Load configuration from file or return default configuration."""
        try:
            config = get_default_config()
            if not config_path:
                ASH_LOGGER.verbose(
                    "No configuration file provided, checking for default paths"
                )
                for item in ASH_CONFIG_FILE_NAMES:
                    possible_config_paths = [
                        source_dir.joinpath(item),
                        source_dir.joinpath(".ash", item),
                    ]
                    for possible_config_path in possible_config_paths:
                        if possible_config_path.exists():
                            config_path = possible_config_path
                            ASH_LOGGER.verbose(
                                f"Found configuration file at: {possible_config_path.as_posix()}"
                            )
                            break
                    if config_path:
                        break
                ASH_LOGGER.verbose(
                    "Configuration file not found or provided, using default config"
                )

            # We *always* want to evaluate this after the inverse block above runs, in
            # case self.config_path is resolved from a default location.
            # Do not use `else:` here!
            if config_path:
                ASH_LOGGER.verbose(
                    f"Loading configuration from {config_path.as_posix()}"
                )
                try:
                    with open(config_path, mode="r", encoding="utf-8") as f:
                        if str(config_path).endswith(".json"):
                            config_data = json.load(f)
                        else:
                            config_data = yaml.safe_load(f)

                    if not isinstance(config_data, dict):
                        raise ValueError("Configuration must be a dictionary")

                    ASH_LOGGER.verbose("Validating file config")
                    config = cls.model_validate(config_data)
                    ASH_LOGGER.debug(f"Loaded config from file: {config}")
                except (IOError, yaml.YAMLError, json.JSONDecodeError) as e:
                    ASH_LOGGER.error(f"Failed to load configuration file: {str(e)}")
                    raise ASHConfigValidationError(
                        f"Failed to load configuration: {str(e)}"
                    )
                except ValidationError as e:
                    ASH_LOGGER.error(f"Configuration validation failed: {str(e)}")
                    raise ASHConfigValidationError(
                        f"Configuration validation failed: {str(e)}"
                    )

            return config
        except Exception as e:
            raise e

    def save(self, config_path: Path):
        """Save configuration to a file."""
        with open(config_path, mode="w", encoding="utf-8") as f:
            yaml.safe_dump(self.model_dump(by_alias=True), f, indent=2)

    def get_scanners(self) -> Dict[str, Any]:
        """Get a dictionary of scanners and their corresponding configurations."""
        scanner_configs: Dict[str, Any] = {
            scanner.config.name: scanner for scanner in self.build.custom_scanners
        }
        scanner: (
            BanditScannerConfig
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
        item_dict = (
            self.scanners.model_dump(by_alias=True)
            if plugin_type == "scanner"
            else (
                self.reporters.model_dump(by_alias=True)
                if plugin_type == "reporter"
                else (
                    self.converters.model_dump(by_alias=True)
                    if plugin_type == "converter"
                    else {}
                )
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

        if found is not None:
            ASH_LOGGER.debug(
                f"Found config for {plugin_type} plugin {og_plugin_name}: {found}"
            )

        return found


BuildConfig.model_rebuild()
ConverterConfigSegment.model_rebuild()
ScannerConfigSegment.model_rebuild()
ReporterConfigSegment.model_rebuild()
PluginContext.model_rebuild()
AshAggregatedResults.model_rebuild()
