import os
from datetime import date, datetime, timezone
from pathlib import Path
import re
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    field_validator,
    model_validator,
)
from typing import Annotated, Any, Callable, List, Dict, Literal, Optional, Tuple

import yaml
from automated_security_helper.base.converter_plugin import ConverterPluginConfigBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import ReporterPluginConfigBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    EXTRACTION_LIMIT_OPTIONS,
    ArchiveConverterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
    JupyterConverterConfig,
)
from automated_security_helper.core.constants import (
    ASH_CONFIG_ENV_VAR_ALLOWLIST,
    ASH_CONFIG_ENV_VAR_PREFIX,
    ASH_DEFAULT_SEVERITY_LEVEL,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import IgnorePathWithReason, AshSuppression
from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
    CSVReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.cyclonedx_reporter import (
    CycloneDXReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_cyclonedx_reporter import (
    GitLabCycloneDXReporterConfig,
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
from automated_security_helper.plugin_modules.ash_builtin.reporters.github_ghas_reporter import (
    GHASReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
    UnusedSuppressionsReporterConfig,
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


def config_env_var_is_interpolatable(var_name: str) -> bool:
    """Whether a config file's ``!ENV`` reference to ``var_name`` may read it.

    The set and the reasoning behind it live on
    ``ASH_CONFIG_ENV_VAR_PREFIX`` / ``ASH_CONFIG_ENV_VAR_ALLOWLIST`` in
    ``core/constants.py``. This function is the single place that consults them,
    so ``constructor_env_variables`` below cannot drift from the tests.

    The comparison is against the name exactly as the config file wrote it, with
    no case folding.

    Case folding was tried and withdrawn. The argument for it was Windows, which
    ASH v3 supports directly in local mode and where ``os.environ`` upper-cases
    its keys, so ``os.environ.get("aws_secret_access_key")`` returns what
    ``AWS_SECRET_ACCESS_KEY`` holds. That is true of ``os.environ`` and changes
    nothing here, because the names this function admits are those beginning with
    a literal ``ASH_`` plus three exact upper-case entries, and on Windows each of
    those reads back the variable it names. No spelling passes the check and then
    reads something outside it, so folding admitted more spellings without
    excluding any.

    The consequence is worth naming rather than hiding: on Windows a config
    writing ``${aws_region:None}`` does not resolve, even though Windows itself
    would find that variable. The reference is left as a literal and a warning
    names it, the docs and ASH's own config write these names in upper case, and
    ``tests/unit/config/test_config_env_interpolation.py`` pins both directions so
    that reintroducing folding is a decision rather than a drift.
    """
    return (
        var_name.startswith(ASH_CONFIG_ENV_VAR_PREFIX)
        or var_name in ASH_CONFIG_ENV_VAR_ALLOWLIST
    )


ENV_REFERENCE_PATTERN = re.compile(r"^\${(\w+):?(.*)?}")


def resolve_env_references(value: str) -> Optional[str]:
    """Resolve the ``${VAR:default}`` reference a config scalar starts with.

    This is the body of the YAML ``!ENV`` constructor, shared so that a TOML
    config source resolves references by exactly the same rule. Only names
    ``config_env_var_is_interpolatable`` admits are read; any other reference is
    left as written.
    """
    pattern = ENV_REFERENCE_PATTERN
    match = pattern.findall(value)  # to find all env variables in line
    if match:
        full_value = value
        for g in match:
            ASH_LOGGER.debug(f"Evaluating env var match: {g}")
            var_name = g[0] if isinstance(g, tuple) else g
            if not config_env_var_is_interpolatable(var_name):
                # Left exactly as written rather than replaced
                # with its default. A literal that still reads
                # as a reference is visible in the artifact and
                # refused by any typed field, whereas the
                # default is indistinguishable from the variable
                # simply not being set. See
                # ASH_CONFIG_ENV_VAR_ALLOWLIST in
                # core/constants.py for which names resolve.
                ASH_LOGGER.warning(
                    f"Not reading environment variable {var_name} "
                    "into the configuration. A configuration file "
                    "may reference names beginning with "
                    f"{ASH_CONFIG_ENV_VAR_PREFIX} and these names: "
                    f"{', '.join(ASH_CONFIG_ENV_VAR_ALLOWLIST)}. "
                    "The reference is left as written."
                )
                continue
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
            full_value = full_value.replace(f"${{{rep_val}}}", resolved_var)
        if full_value.strip() == "":
            return None
        return full_value.strip()
    return value


class _NoAliasSafeLoader(yaml.SafeLoader):
    """``yaml.SafeLoader`` that refuses YAML aliases; see ``load_config_yaml``."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.events.AliasEvent):
            event = self.peek_event()
            raise yaml.composer.ComposerError(
                None,
                None,
                f"found the alias *{event.anchor}; ASH configuration does not "
                "accept YAML aliases, so write the value out where it is used",
                event.start_mark,
            )
        return super().compose_node(parent, index)


def _load_single_document(loader_class: type, stream: Any) -> Any:
    # What yaml.load does, with the loader class given: one document, then the
    # loader's resources released.
    loader = loader_class(stream)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def load_config_yaml(stream: Any) -> Any:
    """Parse YAML that configures ASH: safe tags only, and no aliases.

    Every reader of an ASH config file, workspace policy, MCP profile or
    client-supplied config fragment parses with this, or with
    ``load_yaml_config``, which adds ``!ENV`` on top of it.

    Why no aliases: an alias is a reference to an anchored node, and a few
    hundred bytes of nested aliases stand for gigabytes once the parsed config
    is walked or serialized. A scan writes its config into its results, and MCP
    ``get_config`` returns it, so such a file exhausted memory in the process
    reading it; an MCP server resolves a client's config in the process every
    session shares. Parsing does not expand aliases, so a read-size bound cannot
    stop this. None of the YAML files in ASH's repository uses an alias, and a
    config that repeats a value can write it out where it is used. Anchors with
    no alias referring to them are harmless and still parse.
    """
    return _load_single_document(_NoAliasSafeLoader, stream)


def load_yaml_config(stream: Any) -> Any:
    """Parse an ASH YAML config, resolving ``!ENV`` references as it goes.

    Aliases are refused, as in ``load_config_yaml``.
    """

    # Use a local subclass to avoid mutating the global SafeLoader
    class _AshConfigLoader(_NoAliasSafeLoader):
        pass

    _AshConfigLoader.add_implicit_resolver("!ENV", ENV_REFERENCE_PATTERN, None)

    def constructor_env_variables(loader, node):
        return resolve_env_references(loader.construct_scalar(node))

    _AshConfigLoader.add_constructor("!ENV", constructor_env_variables)
    # !ENV is bounded to ASH_CONFIG_ENV_VAR_PREFIX/ASH_CONFIG_ENV_VAR_ALLOWLIST by
    # resolve_env_references above.
    return _load_single_document(_AshConfigLoader, stream)


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


def _merge_config_values(base: Any, overlay: Any) -> Any:
    """Merge two raw config values, ``overlay`` winning key by key.

    Model instances are dumped first so that a value built in Python merges the
    same way as one read from YAML. Anything that is not a mapping on both sides
    is replaced by ``overlay`` whole.
    """
    if isinstance(base, BaseModel):
        base = base.model_dump()
    if isinstance(overlay, BaseModel):
        overlay = overlay.model_dump()
    if not (isinstance(base, dict) and isinstance(overlay, dict)):
        return overlay
    merged = dict(base)
    for key, value in overlay.items():
        merged[key] = (
            _merge_config_values(merged[key], value) if key in merged else value
        )
    return merged


def field_name_spellings(segment_cls: type[BaseModel]) -> Dict[str, str]:
    """Map each declared field name to its alias, where the two differ.

    Read from ``model_fields``, so a plugin field declared with an alias later is
    covered without being listed anywhere. The config linter reads this too, so
    its warning about the field-name spelling says what actually happens to it.
    """
    return {
        field_name: info.alias
        for field_name, info in segment_cls.model_fields.items()
        if info.alias and info.alias != field_name
    }


class _PluginConfigSegment(BaseModel):
    """Base for the scanner, reporter and converter config segments.

    A plugin field declared with a hyphenated alias (``gitlab-sast``) differs from
    its Python field name (``gitlab_sast``), and these segments do not set
    ``populate_by_name``. Without the validator below, a key written with the
    field name landed in the ``extra="allow"`` bucket, unvalidated, while the
    declared field kept its defaults. ``get_plugin_config`` by the alias then
    returned the defaults, while the runtime lookup by class name could reach the
    extras copy -- for a scanner it did not, so ``cdk_nag: {enabled: false}``
    left cdk-nag enabled.

    ``populate_by_name`` is not the fix, because of the case where both keys are
    present. That happens on every ``--config-overrides`` run that touches an
    aliased plugin, not only in a hand-written config: ``apply_config_overrides``
    round-trips through ``model_dump()``, which is keyed by field name, so the
    file's settings come back under ``gitlab_sast`` while the override adds
    ``gitlab-sast`` holding only the overridden key. Pydantic would keep one of
    the two whole, silently reverting either the override or the rest of the
    file. They are merged key by key instead, the alias -- the documented
    spelling -- winning where both set the same key. A hand-written config with
    both is also flagged by ``ash config lint``.
    """

    @model_validator(mode="before")
    @classmethod
    def _read_field_name_spellings_as_aliases(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        for field_name, alias in field_name_spellings(cls).items():
            if field_name not in data:
                continue
            data = dict(data)
            field_name_value = data.pop(field_name)
            if alias in data:
                data[alias] = _merge_config_values(field_name_value, data[alias])
            else:
                data[alias] = field_name_value
        return data


class ConverterConfigSegment(_PluginConfigSegment):
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


class ScannerConfigSegment(_PluginConfigSegment):
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


class ReporterConfigSegment(_PluginConfigSegment):
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
    gitlab_cyclonedx: Annotated[
        GitLabCycloneDXReporterConfig,
        Field(
            description="Configure the options for the GitLab CycloneDX dependency scanning reporter",
            alias="gitlab-cyclonedx",
        ),
    ] = GitLabCycloneDXReporterConfig()
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
    github_ghas: Annotated[
        GHASReporterConfig,
        Field(
            description="Configure the options for the GitHub Advanced Security (GHAS) SARIF reporter",
            alias="github-ghas",
        ),
    ] = GHASReporterConfig()
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
    unused_suppressions: Annotated[
        UnusedSuppressionsReporterConfig,
        Field(
            description="Configure the options for the Unused Suppressions reporter",
            alias="unused-suppressions",
        ),
    ] = UnusedSuppressionsReporterConfig()
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


#: The archive converter's extraction limits as runtime-override pointers. They bound
#: what extracting an archive in the scanned tree may write, so no client may raise
#: them; they are part of ALWAYS_DENIED_PATHS. A write at an ancestor
#: (``/converters/archive``, ``/converters``) is refused too, as for any denied_paths
#: entry.
ARCHIVE_LIMIT_RUNTIME_PATHS: Tuple[str, ...] = tuple(
    f"/converters/archive/options/{name}" for name in EXTRACTION_LIMIT_OPTIONS
)

#: Runtime-override denials no profile can remove: RuntimeOverridesConfig adds any of
#: them its denied_paths leaves out. A client override that gets past the gate is
#: replayed as the operator's own setting (resolve_config, the session's profile), so
#: these are the settings that trust depends on. The scanner sandbox. Plugin modules,
#: imported into ASH's own process. The detect-secrets settings that turn on secret
#: verification (each candidate secret is sent to its issuer) or import a plugin or
#: filter from a file, and the baseline that can carry both. The archive extraction
#: limits. And every plugin that sends data off the host, each a whole section, so a
#: client can neither turn one on or off nor change what it sends or where (``**``
#: also matches the section itself): the reporters that send the results, and the
#: scanners that send the source (snyk-code), dependency lists (npm-audit,
#: trivy-repo), candidate secrets (detect-secrets) or usage metrics (semgrep,
#: opengrep). tests/unit/config/test_off_host_plugins_are_operator_only.py lists what
#: each one sends and classifies every plugin.
#:
#: A floor rather than the default alone: denied_paths was replaced whole by a
#: profile's own list, so adding one entry dropped every shipped one.
ALWAYS_DENIED_PATHS = (
    "/sandbox",
    "/sandbox/**",
    "/ash_plugin_modules",
    "/ash_plugin_modules/**",
    "/scanners/detect-secrets/options/scan_settings/filters_used",
    "/scanners/detect-secrets/options/scan_settings/filters_used/**",
    "/scanners/detect-secrets/options/scan_settings/plugins_used",
    "/scanners/detect-secrets/options/scan_settings/plugins_used/**",
    "/scanners/detect-secrets/options/baseline_file",
    *ARCHIVE_LIMIT_RUNTIME_PATHS,
    "/reporters/s3/**",
    "/reporters/aws-security-hub/**",
    "/reporters/cloudwatch-logs/**",
    "/reporters/bedrock-summary-reporter/**",
    "/scanners/detect-secrets/**",
    "/scanners/npm-audit/**",
    "/scanners/opengrep/**",
    "/scanners/semgrep/**",
    "/scanners/snyk-code/**",
    "/scanners/trivy-repo/**",
)


class RuntimeOverridesConfig(BaseModel):
    """Allowlist + denylist controlling which JSON-Patch ops the MCP server accepts.

    The MCP server's streamable-HTTP transport lets clients apply JSON-Patch ops
    to a profile-resolved config at session-bind time. This object is the security
    boundary: by default, runtime overrides are disabled. When enabled, only ops
    whose `path` matches `allowed_paths` AND does not match `denied_paths` are
    accepted. `denied_value_patterns` blocks values that match a regex on a
    per-path basis (e.g. shell metacharacters in extra_args).
    """

    model_config = ConfigDict(extra="forbid")

    enabled: Annotated[
        bool,
        Field(description="Master switch — runtime patches are rejected unless True."),
    ] = False

    allowed_paths: Annotated[
        List[str],
        Field(
            description=(
                "JSON-Pointer glob patterns the client may target. `*` matches one segment, "
                "`**` matches any subtree. Example: '/scanners/*/options/severity_threshold'."
            )
        ),
    ] = []

    denied_paths: Annotated[
        List[str],
        Field(
            description=(
                "JSON-Pointer glob patterns that are NEVER allowed (denied wins over allowed). "
                "Defaults block the most dangerous fields on the real AshConfig schema. "
                "A list set here replaces the defaults, except for the entries ASH "
                "always denies (the scanner sandbox, ash_plugin_modules, the "
                "detect-secrets verification, plugin and baseline settings, the "
                "archive converter's extraction limits, and the sections of the "
                "plugins that send data off the host: the s3, aws-security-hub, "
                "cloudwatch-logs and bedrock-summary-reporter reporters and the "
                "detect-secrets, npm-audit, opengrep, semgrep, snyk-code and "
                "trivy-repo scanners): those are added to any list."
            )
        ),
    ] = [
        # Top-level safety: never let a runtime patch flip the failure semantics.
        "/fail_on_findings",
        # Same class of field, same reason: a client that could turn the
        # completeness gate off could make a scan where nothing ran report clean.
        "/fail_on_incomplete_scanners",
        # And the staleness policy: flipping it to warn would let a scan against an
        # out-of-date vulnerability database pass.
        "/content_db_staleness",
        "/content_db_staleness_overrides",
        # Turning the scanned repository's ignore files off or on changes which
        # files are scanned; it is the operator's choice.
        "/honor_ignore_files",
        # The scanner sandbox: a client must not be able to switch it off, hand a
        # scanner a network, or widen what it can read.
        "/sandbox",
        "/sandbox/**",
        # Plugin modules are imported into ASH's own process, unsandboxed.
        "/ash_plugin_modules",
        "/ash_plugin_modules/**",
        # detect-secrets settings the trust checks count as the operator's: the
        # verification filter sends each candidate secret to the service that issued
        # it, plugins and filters named by file are imported, and a baseline file can
        # carry both.
        "/scanners/detect-secrets/options/scan_settings/filters_used",
        "/scanners/detect-secrets/options/scan_settings/filters_used/**",
        "/scanners/detect-secrets/options/scan_settings/plugins_used",
        "/scanners/detect-secrets/options/scan_settings/plugins_used/**",
        "/scanners/detect-secrets/options/baseline_file",
        # Suppressions and ignore paths can hide findings outright.
        "/global_settings/ignore_paths",
        "/global_settings/suppressions",
        # AWS-credential-bearing reporter options (plugin-provided, hyphenated names).
        "/reporters/bedrock-summary-reporter/options/aws_*",
        # The reporters that send results off the host, whole: turning one on or
        # choosing its destination is the operator's call (also in
        # ALWAYS_DENIED_PATHS).
        "/reporters/cloudwatch-logs/**",
        "/reporters/aws-security-hub/**",
        "/reporters/s3/**",
        "/reporters/bedrock-summary-reporter/**",
        # The scanners that send data off the host, whole, for the same reason: the
        # source (snyk-code), dependency lists (npm-audit, trivy-repo), candidate
        # secrets (detect-secrets) or usage metrics (semgrep, opengrep). Also in
        # ALWAYS_DENIED_PATHS.
        "/scanners/detect-secrets/**",
        "/scanners/npm-audit/**",
        "/scanners/opengrep/**",
        "/scanners/semgrep/**",
        "/scanners/snyk-code/**",
        "/scanners/trivy-repo/**",
        # The archive converter's extraction limits bound what extracting an
        # archive in the scanned tree may write, so a client may not raise them.
        # A write at an ancestor (/converters/archive, /converters) is refused too.
        # Listed for the operator reading the default; a profile's own list keeps
        # them too (ALWAYS_DENIED_PATHS).
        *ARCHIVE_LIMIT_RUNTIME_PATHS,
    ]

    denied_value_patterns: Annotated[
        Dict[str, str],
        Field(
            description=(
                "Map of JSON-Pointer pattern → regex. add/replace ops are rejected when "
                "any string leaf reachable from the op's value matches the regex; lists "
                "and dicts are walked recursively so a forbidden token cannot be hidden "
                "inside a nested structure. The `test` op is exempt because it is "
                "read-only."
            )
        ),
    ] = {}

    @model_validator(mode="after")
    def _keep_the_always_denied_paths(self) -> "RuntimeOverridesConfig":
        """Add each ALWAYS_DENIED_PATHS entry the list leaves out, at its end.

        Assigned only when one is missing, so a default policy (which holds them all)
        is the shipped list unchanged and keeps its serialized shape.
        """
        missing = [
            entry for entry in ALWAYS_DENIED_PATHS if entry not in self.denied_paths
        ]
        if missing:
            self.denied_paths = [*self.denied_paths, *missing]
        return self


class SandboxConfig(BaseModel):
    """OS-level sandboxing of scanner subprocesses. Off by default.

    See docs/content/docs/scanner-sandbox.md for the policy each scanner gets.
    """

    model_config = ConfigDict(extra="forbid")

    mode: Annotated[
        Literal["off", "auto", "bwrap", "firejail", "landlock", "sandbox-exec"],
        Field(
            description=(
                "How scanner subprocesses are confined. 'off' runs them as plain "
                "subprocesses. 'auto' uses the best sandbox available (Linux: bwrap, "
                "then firejail, then landlock; macOS: sandbox-exec). Any other value "
                "requires that backend. A scanner that cannot be sandboxed as requested "
                "is recorded MISSING with the reason; it is never run unsandboxed. "
                "A mode that --sandbox, ASH_CONFIG or the operator's config file sets "
                "is a floor: a config file inside a git checkout or the scanned "
                "directory cannot turn it off or switch backends. "
                "Ignored in container mode, where the container is the boundary."
            )
        ),
    ] = "off"

    network_scanners: Annotated[
        Optional[List[str]],
        Field(
            description=(
                "Scanners allowed a network when the scan is online. Null (the default) "
                "uses each scanner's declared need: semgrep, opengrep, grype, trivy, "
                "npm-audit and snyk-code fetch rules, databases or audit data. A list "
                "replaces those defaults. Under --offline no scanner gets a network. "
                "Honored only from --config-overrides or a config file outside every "
                "git checkout and the scanned directory; set by any other config file, "
                "a list can only remove network."
            )
        ),
    ] = None

    extra_read_paths: Annotated[
        List[str],
        Field(
            description=(
                "Additional host paths every sandboxed scanner may read, for example a "
                "corporate CA bundle or a shared rule directory. '~' and $VARS expand. "
                "Honored only from --config-overrides or a config file outside every "
                "git checkout and the scanned directory."
            )
        ),
    ] = []

    read_path_scanners: Annotated[
        List[str],
        Field(
            description=(
                "Scanners allowed the extra host paths their own options ask for "
                "(a rules file or baseline outside the source tree, for example). "
                "Under a sandbox, without this, a scanner whose read paths come from "
                "its options gets only the default policy, and ASH does not read a "
                "detect-secrets baseline_file outside the source tree. With it, a "
                "granted path, that baseline included, is used only when it resolves "
                "inside the source tree or an extra_read_paths entry. "
                "Honored only from --config-overrides or a config file outside every "
                "git checkout and the scanned directory."
            )
        ),
    ] = []

    env_scanners: Annotated[
        List[str],
        Field(
            description=(
                "Scanners allowed the environment variables their own options ask "
                "for (a token for an online check, for example). Without this, such "
                "variables are not passed. Honored only from --config-overrides or a "
                "config file outside every git checkout and the scanned directory."
            )
        ),
    ] = []

    # Set by config/sandbox_grants.py from a network_scanners list that a config
    # file the scanned repository could have written. Private, so no config file
    # can set it.
    _network_limit: Optional[List[str]] = PrivateAttr(default=None)

    @property
    def network_limit(self) -> Optional[List[str]]:
        """Scanners a config file in the scanned tree allows a network, or None.

        Only ever narrows: a scanner outside this list gets no network whatever
        network_scanners says. See config/sandbox_grants.py.
        """
        return self._network_limit

    @network_limit.setter
    def network_limit(self, value: Optional[List[str]]) -> None:
        self._network_limit = value


class AshMcpConfig(BaseModel):
    """MCP-server-specific config bundle (transport-agnostic)."""

    model_config = ConfigDict(extra="forbid")

    runtime_overrides: Annotated[
        RuntimeOverridesConfig,
        Field(description="Allowlist for runtime JSON-Patch overrides."),
    ] = RuntimeOverridesConfig()


class AshConfigGlobalSettingsSection(BaseModel):
    # validate_default is here because `severity_threshold`'s default is derived
    # from an environment variable, and pydantic does not validate a default no
    # caller supplied. Without it an off-table `ASH_DEFAULT_SEVERITY_LEVEL` landed
    # in a Literal-typed field that forbids it, and the ladder in
    # utils.severity_ladder read the result as CRITICAL -- the strictest gate --
    # for an operator who had asked for the loosest. core.constants now normalizes
    # at the boundary, so this guards the other direction: a future default written
    # in this file that the Literal does not admit fails at construction instead of
    # travelling into the exit code.
    model_config = ConfigDict(
        extra="forbid",
        validate_default=True,
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

    mcp: Annotated[
        AshMcpConfig,
        Field(
            description="MCP-server-specific configuration (runtime override allowlist, etc.)."
        ),
    ] = AshMcpConfig()


# Distinguishes "caller did not pass cpu_count" from "caller passed None", which
# is a real value here: os.cpu_count() returns None on hosts that cannot report it,
# and a test needs to be able to say so explicitly.
_UNSET_CPU_COUNT: Any = object()


class WorkspaceExecutionConfig(BaseModel):
    """How many projects a workspace scan runs at once, and how long each may take.

    Why this is not read from the .code-workspace file
    --------------------------------------------------
    ``automated_security_helper.workspace.workspace_file`` deliberately ignores
    that file's ``settings`` block, because it belongs to another tool whose
    schema ASH does not control. So every ASH knob, including these two, lives in
    ASH's own config -- here, in the config resolved for the workspace root.

    Why these two land before the workspace policy block
    ----------------------------------------------------
    Neither can change any project's verdict. ``max_parallel_projects`` decides
    scheduling and ``project_timeout`` decides how long to wait; the findings a
    project reports and the threshold they are judged against are untouched. The
    workspace-level *policy* fields -- a severity ceiling, workspace-wide
    suppressions -- can change a verdict, and they arrive separately and visibly
    rather than riding in on an execution change.

    Wall clock is ``ceil(projects / bound)`` waves, and that is arithmetic
    -----------------------------------------------------------------------
    A workspace of N projects at a bound of B runs in ``ceil(N / B)`` waves, so
    its wall clock is roughly that multiple of one project's. Reproduce with
    ``scripts/measure_workspace_parallelism.py``; measured on a 192-CPU Linux
    host on 2026-08-25, five projects, bound 4, three timed runs per arm, the
    whole child process timed:

    * five equal projects -- one alone 21.3s median (19.4-22.7), the workspace
      43.4s median (41.5-45.8). Ratio of medians **2.036x**, range 1.823-2.365x.
    * one larger project plus four small -- one alone 20.7s median (20.7-26.3),
      the workspace 40.5s median (39.3-46.0). Ratio **1.958x**, range
      1.495-2.227x.

    Both sit on the ``ceil(5/4) = 2`` floor, so neither says much about the
    implementation: an operator who wants a workspace to finish in about the time
    of its slowest project has to set ``max_parallel_projects`` to at least the
    project count and accept the thread product below. The default stays at 4
    because that product is the thing worth defaulting conservatively.

    Two earlier figures for this were wrong and are withdrawn. A reported 0.88x at
    bound 5 -- a five-project workspace beating one project alone -- was an
    artefact of timing a cold single-project arm against a warm workspace arm,
    because ``uv_tool_runner`` caches tool probing across invocations. The
    measurement script now runs a discard pass first and alternates the arms, and
    nothing close to a sub-1.0 ratio reappears. A reported 2.35x at bound 4 was a
    single unrepeated run; it lands at the top of the range measured here rather
    than at its centre, which is why the figures above are medians with a spread.

    The second shape did not do what it was designed to do, and that is worth
    knowing before anyone repeats it. It gave one project five times the files, on
    the theory that "the slowest project alone" would then be a real baseline and
    the small projects could hide inside its wave. But 60 files scanned in 20.7s
    and 12 files in 21.3s -- indistinguishable. Scan wall clock here is dominated
    by per-scanner startup, not by file count, so the fixture produced no dominant
    project and its number is really the equal case again. Testing the RFC's 1.5x
    criterion properly needs a project large enough to be file-bound rather than
    startup-bound, which is thousands of files, not sixty.

    On this evidence the 1.5x criterion is not met at the default bound in either
    shape, and for five projects at bound 4 it cannot be: two waves is 2.0x before
    any implementation cost.

    Failure modes and known limitations
    -----------------------------------
    * ``project_timeout`` bounds the *verdict*, not the worker. Python cannot
      preempt a thread, so a timed-out project is recorded FAILED and the
      workspace continues, but the abandoned worker keeps running -- and keeps
      its pool slot. Once every slot is held by an abandoned project, nothing
      still queued can start, so those projects are cancelled and recorded
      FAILED rather than waited on. A workspace with more projects than
      ``max_parallel_projects`` can therefore report several failures from one
      slow project; raising either knob avoids it.
    * The process still does not exit until every abandoned worker finishes,
      because the interpreter joins them. Scanners run as subprocesses with
      their own timeouts, so the residual exposure is a genuinely wedged
      in-process scanner.
    * The outer bound multiplies with the inner scanner pool. That pool is
      ``min(32, cpu_count + 4)`` in ``ScanExecutionEngine.__init__``, not 4, and
      not the unrelated ``thread_pool_max_workers`` MCP setting, so the
      worst-case thread count is ``max_parallel_projects * min(32, cpu + 4)``.
      On the 192-CPU host above, the default bound of 4 already permits up to
      128 concurrent scanner threads.
    """

    model_config = ConfigDict(extra="forbid")

    max_parallel_projects: Annotated[
        Optional[int],
        Field(
            None,
            ge=1,
            le=64,
            description=(
                "Maximum number of projects scanned concurrently. Unset means "
                "min(4, cpu_count). This is an outer bound over each project's "
                "own scanner thread pool, not a replacement for it."
            ),
        ),
    ] = None

    project_timeout: Annotated[
        Optional[float],
        Field(
            None,
            gt=0,
            description=(
                "Seconds to allow a single project. Unset means no limit. On "
                "timeout that project is recorded as failed and the remaining "
                "projects still complete."
            ),
        ),
    ] = None

    def resolved_max_parallel_projects(
        self, cpu_count: Optional[int] = _UNSET_CPU_COUNT
    ) -> int:
        """The bound to use, deriving the default when none is configured.

        Stored as ``None`` and derived here rather than defaulted to 4 in the
        field, so that a one-CPU host gets one worker instead of four and a
        serialised config still shows the operator did not choose a number.

        Args:
            cpu_count: Override for the host CPU count, for tests. ``None`` and
                ``0`` are both treated as one CPU, because ``os.cpu_count()``
                can return ``None`` and a pool of zero workers never runs.
        """
        if self.max_parallel_projects is not None:
            return self.max_parallel_projects
        if cpu_count is _UNSET_CPU_COUNT:
            cpu_count = os.cpu_count()
        return max(1, min(4, cpu_count or 1))


class ContentDbStalenessOverride(BaseModel):
    """One content database held to a different staleness policy, until a fixed date.

    ``content_db_staleness`` decides for every database at once. This narrows a
    relaxation to the one database that needs it -- typically one whose upstream
    publisher has stopped publishing for a while -- so every other database is still
    held to the scan-wide policy. ``expiration`` and ``reason`` are required, the
    same two fields a time-boxed suppression carries: an exception to a freshness
    gate that has no end date is a permanent one. On and after ``expiration``
    (00:00 UTC) the entry is ignored, with a warning in the log, and the database
    falls back to ``content_db_staleness``.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    database: Annotated[
        str,
        Field(
            description=(
                "The content database's registry name, as listed in "
                "automated_security_helper/utils/content_databases.py: grype-db, "
                "trivy-db, semgrep-offline-rules or opengrep-offline-rules."
            )
        ),
    ]
    policy: Annotated[
        Literal["fail", "warn"],
        Field(
            description="The policy this database is held to while the entry is in effect."
        ),
    ]
    expiration: Annotated[
        str,
        Field(
            description=(
                "Required. The date (YYYY-MM-DD, UTC) from which the entry no longer "
                "applies: at 00:00 UTC that day the database returns to "
                "content_db_staleness."
            )
        ),
    ]
    reason: Annotated[
        str,
        Field(
            min_length=1, description="Required. Why this database is held differently."
        ),
    ]

    @field_validator("database")
    @classmethod
    def _database_must_be_declared(cls, v: str) -> str:
        from automated_security_helper.utils.content_databases import (
            CONTENT_DATABASES,
        )

        names = sorted(entry.name for entry in CONTENT_DATABASES)
        if v not in names:
            raise ValueError(
                f"unknown content database {v!r}; declared databases: {', '.join(names)}"
            )
        return v

    @field_validator("expiration")
    @classmethod
    def _expiration_must_be_a_date(cls, v: str) -> str:
        try:
            datetime.strptime(v, "%Y-%m-%d")
        except ValueError:
            raise ValueError(f"Invalid expiration date format. Use YYYY-MM-DD: {v}")
        return v

    @property
    def expires_at(self) -> datetime:
        """00:00 UTC on ``expiration``, the first instant the entry no longer applies."""
        day = date.fromisoformat(self.expiration)
        return datetime(day.year, day.month, day.day, tzinfo=timezone.utc)

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """True on and after 00:00 UTC on ``expiration``."""
        return (now or datetime.now(timezone.utc)) >= self.expires_at


class AshConfig(BaseModel):
    """Main configuration model for Automated Security Helper."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        extra="ignore",
        # Accept BOTH the alias (e.g., 'mcp-resource-management') and the
        # Python field name (e.g., 'mcp_resource_management') as input.
        # Pydantic v2 default is alias-only when an alias is declared,
        # which surfaced as an MCP-profile-loading error: the strict-extra
        # gate accepted both spellings but model_validate(strict=True)
        # accepted only the alias. See DA r6 #3.
        populate_by_name=True,
    )

    # Internal field to track config resolution warnings (not serialized)
    _resolution_warnings: List[str] = PrivateAttr(default_factory=list)

    # The tree a scan with this config covers, when it is wider than the source
    # directory: workspace mode sets the workspace root. config/path_trust.py
    # refuses tool config files inside it. None means the source directory's tree.
    _scanned_root: Optional[Path] = PrivateAttr(default=None)

    # Which tool paths in this config the operator named
    # (config/path_trust.OperatorPaths), recorded by resolve_config. None means
    # no option value counts as the operator's.
    _operator_paths: Optional[Any] = PrivateAttr(default=None)

    # What the detect-secrets settings of this config may turn on, when a file the
    # scanned repository or an MCP client wrote built it (an
    # UntrustedDetectSecretsSettings from config/secret_verification_trust.py), or
    # None when the operator's own sources built it. Private, so no config file can
    # set or clear it.
    _untrusted_detect_secrets_settings: Optional[Any] = PrivateAttr(default=None)

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

    fail_on_incomplete_scanners: Annotated[
        bool,
        Field(
            description=(
                "Whether to exit with a non-zero code when a selected scanner did "
                "not complete -- status ERROR (ran and failed) or MISSING "
                "(dependencies unavailable, never ran). SKIPPED scanners are not "
                "selected and never trip this. Independent of fail_on_findings: "
                "one answers 'was anything found', this one answers 'did what I "
                "asked for actually run'. Selects on the scanner's status, so it "
                "covers only a failure that reached that status. Defaults to True, "
                "so a scanner recorded ERROR or MISSING does not report the exit "
                "code of a clean scan. Converters count too: one that crashed, one "
                "that could not convert some of its inputs, and one whose tool is "
                "missing while it had inputs make the scan exit non-zero the same "
                "way. Set it to False, or pass "
                "--no-fail-on-incomplete-scanners, to accept a partial scan's exit "
                "code; excluding the scanner whose tool is unavailable is usually "
                "better, because an excluded scanner is recorded SKIPPED and the "
                "report then says what was not measured."
            )
        ),
    ] = True

    honor_ignore_files: Annotated[
        bool,
        Field(
            description=(
                "Whether the .gitignore and .ignore files in the scanned tree decide "
                "which files are left out of ASH's scan set, the file list "
                "detect-secrets, cfn-nag, cdk-nag, npm-audit and the converters "
                "read. True (the default) leaves out every file they match. False "
                "scans those files too; ASH's own exclusions (.git, CDK assets, "
                "its own output directory) still apply. An operator setting: a config file inside the scanned "
                "tree, or one an MCP client supplied, cannot change it, and its "
                "value there is ignored with a warning. Set it in a config file "
                "outside the tree, with --config-overrides, or with "
                "--no-honor-ignore-files / --honor-ignore-files. Every scan records "
                "the outcome in metadata.ignore_file_exclusions."
            )
        ),
    ] = True

    sandbox: Annotated[
        SandboxConfig,
        Field(description="OS-level sandboxing of scanner subprocesses."),
    ] = SandboxConfig()

    content_db_staleness: Annotated[
        Literal["fail", "warn"],
        Field(
            description=(
                "What a scan does when a scanner's content database (grype's or "
                "trivy's vulnerability database, the offline semgrep/opengrep "
                "rulesets) was built longer ago than the bound declared for it in "
                "automated_security_helper/utils/content_databases.py. 'fail' (the "
                "default) keeps the scanner's findings and exits 1, naming the "
                "database, its build time, its age and the bound. 'warn' lets the scan "
                "pass and records the same warning in the log and in the reports "
                "(summary, SARIF invocation notifications, flat JSON). The CLI flag "
                "--allow-stale-content-db sets 'warn' for one scan and takes "
                "precedence over this value; --no-allow-stale-content-db sets 'fail'."
            )
        ),
    ] = "fail"

    content_db_staleness_overrides: Annotated[
        List[ContentDbStalenessOverride],
        Field(
            description=(
                "Per-database exceptions to content_db_staleness, each with a required "
                "expiration date and reason. An entry holds one named database to its "
                "own policy until 00:00 UTC on its expiration date, and every database "
                "not named keeps content_db_staleness. An expired entry is ignored with "
                "a warning. Empty by default. Either form of --allow-stale-content-db "
                "clears this list for that scan, so the flag still decides for every "
                "database."
            )
        ),
    ] = []

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

    workspace: Annotated[
        WorkspaceExecutionConfig,
        Field(
            description=(
                "Workspace-mode execution settings. Read from the config "
                "resolved for the workspace root; a project's own copy of this "
                "block is ignored, because how many projects run at once is not "
                "a project's decision."
            ),
        ),
    ] = WorkspaceExecutionConfig()

    # `extends` and `patch` are read by the config loader (config/config_sources.py)
    # and removed before validation, so a loaded config always has both as None.
    # They are declared here so the JSON schema documents them, and excluded from
    # every dump so that saving a resolved config never writes them back.
    extends: Annotated[
        str | List[str] | None,
        Field(
            exclude=True,
            description=(
                "Base config file(s) this config extends: a path, or a list of "
                "paths applied in order, relative to this file. Mappings merge key "
                "by key; lists and scalars from this file replace the base's. Paths "
                "must stay inside the repository being scanned; URLs are refused."
            ),
        ),
    ] = None

    patch: Annotated[
        List[Dict[str, Any]] | None,
        Field(
            exclude=True,
            description=(
                "RFC 6902 JSON-Patch operations (add, remove, replace, test) applied "
                "after this file is merged over its bases. Use 'add' at "
                "'/global_settings/suppressions/-' to append to a base's list."
            ),
        ),
    ] = None

    @field_validator("content_db_staleness_overrides")
    @classmethod
    def _one_override_per_database(
        cls, v: List[ContentDbStalenessOverride]
    ) -> List[ContentDbStalenessOverride]:
        seen: set[str] = set()
        for entry in v:
            if entry.database in seen:
                raise ValueError(
                    f"content database {entry.database!r} is named by more than one "
                    "content_db_staleness_overrides entry; which one applies would be "
                    "ambiguous"
                )
            seen.add(entry.database)
        return v

    @model_validator(mode="after")
    def _extends_must_be_resolved(self) -> "AshConfig":
        # Reached only when a dict carrying these keys is validated directly,
        # bypassing the loader. Ignoring them would run with the child alone and
        # none of its bases' settings, so it fails instead.
        if self.extends is not None or self.patch is not None:
            raise ValueError(
                "'extends' and 'patch' are resolved when a config file is loaded; "
                "load the file with AshConfig.from_file or resolve_config instead of "
                "validating its contents directly"
            )
        return self

    @classmethod
    def from_file(
        cls,
        config_path: Path,
        confine_to: Optional[Path] = None,
        permit_base: Optional[Callable[[Path], bool]] = None,
    ) -> "AshConfig":
        """Load configuration from a file, following any ``extends`` chain.

        ``config_path`` may be YAML, JSON, an ``ashrc.toml``-style TOML file, or a
        ``pyproject.toml`` (whose ``[tool.ash]`` table is read). ``extends`` and
        ``patch`` are resolved by ``config/config_sources.py``, which documents
        the merge rules and the confinement of base paths to ``confine_to`` and
        ``permit_base``.
        """
        from automated_security_helper.config.config_sources import (
            load_config_document,
        )

        config_data = load_config_document(
            Path(config_path), confine_to=confine_to, permit_base=permit_base
        )
        return cls.model_validate(config_data, strict=True)

    def save(self, config_path: Path):
        """Save configuration to a file."""
        with open(config_path, mode="w", encoding="utf-8") as f:
            yaml.safe_dump(self.model_dump(by_alias=True), f, indent=2)

    def get_plugin_config(
        self,
        plugin_type: Literal["converter", "scanner", "reporter"],
        plugin_name: str,
    ):
        found = None
        # Reduce the provided plugin_name in case the class name was passed in,
        # as the config itself uses kebab-case keys while the classes use PascalCase
        # for class names.
        #
        # Punctuation is stripped as well as the type word. Stripping only the type
        # word left a caller who passed the *config-key* spelling with a dangling
        # separator -- "bedrock-summary-reporter" reduced to "bedrock-summary-",
        # which matches no key and no candidate -- so the lookup missed even though
        # the key was spelled exactly right. cli/report.py passes
        # plugin_name=report_format straight from --output-format, and
        # scanner_statistics_calculator passes the registered scanner name, so this
        # is the spelling real callers use, not a hypothetical one.
        og_plugin_name = plugin_name
        plugin_name = reduced_plugin_name(plugin_name)
        match plugin_type:
            case "scanner":
                item_dict = self.scanners.model_dump(by_alias=True)
            case "reporter":
                item_dict = self.reporters.model_dump(by_alias=True)
            case "converter":
                item_dict = self.converters.model_dump(by_alias=True)
            case _:
                item_dict = {}
        # Exact and punctuation-stripped spellings of each config key, in that
        # order of preference.
        #
        # (The previous version of this loop opened with `if found is not None:
        # break`, but nothing assigns `found` before the loop ends, so it never
        # fired.)
        key_map = {}
        for item_name in item_dict:
            for possible in sorted(
                {
                    item_name,
                    _PLUGIN_NAME_PUNCTUATION.sub("", item_name).lower(),
                }
            ):
                key_map[possible] = item_name

        # The same suffix removal that was applied to plugin_name above, applied
        # to the config keys. Without this the two forms can never meet: a query
        # for BedrockSummaryReporter reduces to "bedrocksummary", while the key
        # "bedrock-summary-reporter" reduces only to "bedrocksummaryreporter", so
        # any plugin whose config key contains the plugin-type word was
        # unreachable and silently fell back to its defaults. `csv` matched only
        # because its key does not contain "reporter", which is why this looked
        # like an external-plugin problem.
        #
        # setdefault, not assignment: a stripped spelling must never shadow a real
        # key. With both "bedrock-summary" and "bedrock-summary-reporter" present,
        # the second one's stripped form collides with the first, and adding a
        # plugin should not repoint another plugin's config.
        for item_name in item_dict:
            stripped = reduced_plugin_name(item_name)
            if stripped:
                key_map.setdefault(stripped, item_name)
        # The caller's spelling, before any reduction, wins. This is checked
        # against og_plugin_name rather than plugin_name: by this point plugin_name
        # has had its type word and punctuation removed, so an exactly-correct
        # config key such as "bedrock-summary-reporter" no longer resembles itself
        # and could never match item_dict here.
        if og_plugin_name in item_dict:
            ASH_LOGGER.debug(
                f"Found {plugin_type} plugin {og_plugin_name} with direct match"
            )
            found = item_dict[og_plugin_name]
        # Then the reduced form, against the reduced spellings of each key.
        elif plugin_name in item_dict:
            ASH_LOGGER.debug(
                f"Found {plugin_type} plugin {og_plugin_name} with direct match"
            )
            found = item_dict[plugin_name]
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


_PLUGIN_TYPE_WORD = re.compile(r"(Converter|Scanner|Reporter)(Config)?", re.IGNORECASE)
_PLUGIN_NAME_PUNCTUATION = re.compile(r"[^a-z0-9+]+", re.IGNORECASE)


def reduced_plugin_name(name: str) -> str:
    """``name`` as ``AshConfig.get_plugin_config`` compares it.

    The Converter/Scanner/Reporter word (and a following "Config") and every
    character outside ``[a-z0-9+]`` are removed, then the rest is lowercased, so
    ``BedrockSummaryReporter`` and ``bedrock-summary-reporter`` both become
    ``bedrocksummary``.
    """
    return _PLUGIN_NAME_PUNCTUATION.sub("", _PLUGIN_TYPE_WORD.sub("", name)).lower()


def plugin_key_lookup_names(key: str) -> set[str]:
    """Every reduced plugin name under which ``get_plugin_config`` finds section ``key``.

    The key as written, the key with punctuation removed and lowercased, and the
    key reduced the way a plugin name is. A plugin whose
    ``reduced_plugin_name`` is in this set reads ``key`` as its config when no
    section uses its exact name. ``runtime_patch`` uses the same set so a denial
    on a plugin's section holds for each of these spellings.
    """
    names = {key, _PLUGIN_NAME_PUNCTUATION.sub("", key).lower()}
    reduced = reduced_plugin_name(key)
    if reduced:
        names.add(reduced)
    return names


def add_suppression_to_config(config_path: Path, suppression: AshSuppression) -> None:
    """Add a suppression to the suppressions list in an .ash.yaml config file.

    Comment- and formatting-preserving by construction: the new entry is
    serialized with PyYAML (so quoting and escaping are correct) and inserted as
    text. A full ``yaml.safe_dump`` rewrite -- which drops every comment in the
    file -- is a last resort, reached only for a brand-new file or a structure
    that cannot be edited as text (an inline ``global_settings: {...}`` mapping),
    i.e. a file with no comments to preserve or a shape that essentially never
    occurs in practice.
    """
    entry = suppression.model_dump(exclude_none=True)
    if config_path.name.endswith(".toml"):
        raise ValueError(
            f"Suppressions are saved by editing YAML; {config_path} is TOML. Add "
            "the suppression to its global_settings.suppressions by hand."
        )
    config_path.parent.mkdir(parents=True, exist_ok=True)

    # A brand-new file has no comments to lose, so a fresh dump is fine.
    if not config_path.exists():
        _rewrite_config_with_entry(config_path, {}, entry)
        return

    text = config_path.read_text(encoding="utf-8")
    data = load_config_yaml(text) or {}

    # A file that extends a base and has no suppressions list of its own gets
    # its suppressions from the base. Writing a list here would replace that
    # list (lists from the extending file win; see config/config_sources.py) and
    # silently drop the base's suppressions.
    if (
        isinstance(data, dict)
        and "extends" in data
        and not isinstance(
            (data.get("global_settings") or {}).get("suppressions"), list
        )
    ):
        raise ValueError(
            f"{config_path} extends another config and has no suppressions list "
            "of its own, so writing one would replace the base's suppressions. "
            "Add it as a patch instead: patch: [{op: add, path: "
            "/global_settings/suppressions/-, value: {...}}]"
        )

    # Duplicate detection: skip if this rule_id+path is already suppressed.
    if isinstance(data, dict):
        existing = (data.get("global_settings") or {}).get("suppressions") or []
        for existing_entry in existing:
            if (
                isinstance(existing_entry, dict)
                and existing_entry.get("rule_id") == entry.get("rule_id")
                and existing_entry.get("path") == entry.get("path")
            ):
                return  # already suppressed

    lines = text.splitlines(keepends=True)

    # Case A: a suppressions list already exists -> insert the item at its end.
    insert_idx, list_indent = _find_suppressions_append_point(lines)
    if insert_idx is not None:
        for line in reversed(_serialize_entry_lines(entry, list_indent)):
            lines.insert(insert_idx, line)
        config_path.write_text("".join(lines), encoding="utf-8")
        return

    # Case B: a block-style global_settings exists but has no suppressions key ->
    # insert the key plus the item at the end of that block. This is the common
    # first-suppression case, and the one the old full-rewrite fallback silently
    # stripped every comment from.
    gs_insert_idx, gs_child_indent = _find_global_settings_insert_point(lines)
    if gs_insert_idx is not None:
        block = [f"{gs_child_indent}suppressions:\n"]
        block += _serialize_entry_lines(entry, gs_child_indent + "  ")
        for line in reversed(block):
            lines.insert(gs_insert_idx, line)
        config_path.write_text("".join(lines), encoding="utf-8")
        return

    # Case C: content, but no global_settings key at all -> append a fresh block
    # at EOF, leaving every existing line (and comment) untouched.
    if not _has_top_level_key(lines, "global_settings"):
        block: list[str] = []
        if lines and not lines[-1].endswith("\n"):
            block.append("\n")
        block.append("global_settings:\n")
        block.append("  suppressions:\n")
        block += _serialize_entry_lines(entry, "    ")
        config_path.write_text("".join(lines) + "".join(block), encoding="utf-8")
        return

    # Case D (last resort): a shape we cannot safely edit as text, e.g. an inline
    # `global_settings: {...}` mapping. Fall back to a full rewrite. This loses
    # comments, but only for a structure that essentially never occurs.
    _rewrite_config_with_entry(
        config_path, data if isinstance(data, dict) else {}, entry
    )


def _serialize_entry_lines(entry: dict, item_indent: str) -> list[str]:
    """Render one suppression entry as indented YAML lines.

    Serialized with ``yaml.safe_dump`` so a reason (or any value) containing
    ``"``, ``\\``, ``:`` or ``#`` is quoted and escaped correctly.
    ``safe_dump([entry])`` emits the item at column 0 (``- key: value`` then
    ``  key: value``); each line is prefixed with ``item_indent``.
    """
    dumped = yaml.safe_dump([entry], default_flow_style=False, sort_keys=False)
    return [f"{item_indent}{line}\n" for line in dumped.splitlines()]


def _rewrite_config_with_entry(config_path: Path, data: dict, entry: dict) -> None:
    """Full ``safe_dump`` rewrite. Only for files with no comments to preserve."""
    if not isinstance(data, dict):
        data = {}
    global_settings = data.setdefault("global_settings", {})
    if not isinstance(global_settings, dict):
        global_settings = {}
        data["global_settings"] = global_settings
    suppressions_list = global_settings.setdefault("suppressions", [])
    if not isinstance(suppressions_list, list):
        suppressions_list = []
        global_settings["suppressions"] = suppressions_list
    suppressions_list.append(entry)
    with open(config_path, mode="w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)


def _has_top_level_key(lines: list, key: str) -> bool:
    prefix = f"{key}:"
    return any(
        (len(line) - len(line.lstrip())) == 0 and line.lstrip().startswith(prefix)
        for line in lines
    )


def _find_global_settings_insert_point(lines: list) -> tuple:
    """End-of-block index and child indent for a block-style global_settings.

    Returns ``(insert_index, child_indent)`` for a top-level ``global_settings:``
    that has block children, or ``(None, None)`` if it is absent, inline
    (``global_settings: {...}``), or has no children to anchor indentation on.
    """
    in_global = False
    block_end = None
    child_indent = None
    for idx, line in enumerate(lines):
        stripped = line.lstrip()
        indent_len = len(line) - len(stripped)
        if not in_global:
            if indent_len == 0 and stripped.startswith("global_settings:"):
                # An inline mapping value after the colon is not text-insertable.
                if stripped[len("global_settings:") :].strip():
                    return (None, None)
                in_global = True
                block_end = idx + 1
            continue
        if stripped == "" or stripped.startswith("#"):
            continue  # inside the block, but not a child to anchor on
        if indent_len == 0:
            break  # a following top-level key: the block has ended
        if child_indent is None:
            child_indent = line[:indent_len]
        block_end = idx + 1
    if not in_global or child_indent is None:
        return (None, None)
    return (block_end, child_indent)


def _find_suppressions_append_point(lines: list) -> tuple:
    """Find the line index and indentation for appending a new suppression.

    Returns (insert_index, list_item_indent) or (None, None).
    """
    in_global = False
    in_suppressions = False
    last_item_end = None
    list_indent = "    "  # default: 4 spaces

    for idx, line in enumerate(lines):
        stripped = line.lstrip()
        indent_len = len(line) - len(line.lstrip())

        if stripped.startswith("global_settings:"):
            in_global = True
            continue

        if in_global and indent_len == 0 and stripped and not stripped.startswith("#"):
            in_global = False
            if in_suppressions:
                return (last_item_end, list_indent) if last_item_end else (None, None)
            continue

        if in_global and stripped.startswith("suppressions:"):
            in_suppressions = True
            last_item_end = idx + 1
            continue

        if in_suppressions:
            if stripped.startswith("- "):
                list_indent = line[:indent_len]
                last_item_end = idx + 1
                continue
            if (
                indent_len > 0
                and not stripped.startswith("- ")
                and not stripped.startswith("#")
            ):
                last_item_end = idx + 1
                continue
            if stripped == "" or stripped.startswith("#"):
                continue
            return (last_item_end, list_indent)

    if in_suppressions:
        return (last_item_end, list_indent)
    return (None, None)


BuildConfig.model_rebuild()
ConverterConfigSegment.model_rebuild()
ScannerConfigSegment.model_rebuild()
ReporterConfigSegment.model_rebuild()
PluginContext.model_rebuild()
# Load-bearing, and not obviously so: AshAggregatedResults.ash_config is annotated
# Optional["AshConfig"] as a string, and this is the line that resolves it for any
# process that imports this module -- AshConfig is in scope here, which is all
# model_rebuild() needs. models/asharp_model.py resolves it a second way, on first
# use, for the import orders that never reach this line. Either mechanism alone
# suffices, so this one looks like dead duplication; deleting it narrows the fix to
# one mechanism and puts model_json_schema() back at the mercy of import order.
AshAggregatedResults.model_rebuild()
