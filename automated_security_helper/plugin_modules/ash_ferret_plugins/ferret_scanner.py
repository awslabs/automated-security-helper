# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module containing the Ferret Scan sensitive data detection scanner implementation."""

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Annotated, Any, List, Literal, Optional, Tuple

from pydantic import Field, model_validator

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.models.core import ToolArgs, ToolExtraArg
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    SarifReport,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.sarif_utils import attach_scanner_details
from automated_security_helper.utils.subprocess_utils import find_executable
from automated_security_helper.utils.log import ASH_LOGGER

# Path to the default ferret-scan config bundled with this plugin
DEFAULT_FERRET_CONFIG = Path(__file__).parent / "ferret-config.yaml"

# ============================================================================
# VERSION COMPATIBILITY
# ============================================================================
# This plugin is tested and compatible with the following ferret-scan versions.
# Using versions outside this range may result in unexpected behavior.
#
# When ferret-scan releases breaking changes, update these constants and
# add appropriate version-specific handling in the code.
# ============================================================================

# Minimum supported ferret-scan version (inclusive)
MIN_SUPPORTED_VERSION = "0.1.0"

# Maximum supported ferret-scan version (exclusive - versions >= this may have breaking changes)
MAX_SUPPORTED_VERSION = "2.0.0"

# Default version constraint for installation (if using uv tool)
DEFAULT_VERSION_CONSTRAINT = ">=0.1.0,<2.0.0"

# Recommended version for best compatibility
RECOMMENDED_VERSION = "1.0.0"

# ============================================================================
# UNSUPPORTED OPTIONS DOCUMENTATION
# ============================================================================
# The following ferret-scan CLI options are NOT supported in the ASH plugin
# because they conflict with ASH conventions or are not applicable:
#
# OUTPUT FORMAT OPTIONS (ASH requires SARIF):
#   --format text/json/csv/yaml/junit/gitlab-sast
#       Reason: ASH requires SARIF format for result aggregation. Other formats
#       are handled by ASH's reporter plugins.
#
# WEB SERVER OPTIONS (Not applicable for ASH):
#   --web, --port
#       Reason: Web server mode is for interactive use, not batch scanning.
#
# REDACTION OPTIONS (Post-processing, not scanning):
#   --enable-redaction, --redaction-output-dir, --redaction-strategy,
#   --redaction-audit-log, --memory-scrub
#       Reason: Redaction is a post-processing step. ASH focuses on detection.
#
# SUPPRESSION OPTIONS (ASH has its own suppression system):
#   --generate-suppressions, --show-suppressed, --suppressions-file
#       Reason: ASH manages suppressions centrally via .ash/suppressions.yaml
#
# TEXT EXTRACTION MODE (Preprocessing, not scanning):
#   --extract-text
#       Reason: This is a utility mode, not a scanning mode.
#
# DEBUG/VERBOSE OPTIONS (Not applicable):
#   --debug, --verbose
#       Reason: ASH manages its own logging. These ferret-scan options are not
#       applicable in the ASH integration context.
# ============================================================================

# List of unsupported ferret-scan options that should not be used
UNSUPPORTED_FERRET_OPTIONS = {
    # Output format options - ASH requires SARIF
    "format": "ASH requires SARIF format for result aggregation. Use ASH reporter plugins for other formats.",
    "output_format": "ASH requires SARIF format for result aggregation. Use ASH reporter plugins for other formats.",
    
    # Web server options - not applicable
    "web": "Web server mode is not supported in ASH integration. Use ferret-scan CLI directly for web mode.",
    "port": "Web server mode is not supported in ASH integration. Use ferret-scan CLI directly for web mode.",
    
    # Redaction options - post-processing
    "enable_redaction": "Redaction is not supported in ASH integration. Use ferret-scan CLI directly for redaction.",
    "redaction_output_dir": "Redaction is not supported in ASH integration. Use ferret-scan CLI directly for redaction.",
    "redaction_strategy": "Redaction is not supported in ASH integration. Use ferret-scan CLI directly for redaction.",
    "redaction_audit_log": "Redaction is not supported in ASH integration. Use ferret-scan CLI directly for redaction.",
    "memory_scrub": "Redaction is not supported in ASH integration. Use ferret-scan CLI directly for redaction.",
    
    # Suppression options - ASH has its own system
    "generate_suppressions": "ASH manages suppressions centrally. Use .ash/suppressions.yaml instead.",
    "show_suppressed": "ASH manages suppressions centrally. Use 'ash inspect suppressions' instead.",
    "suppressions_file": "ASH manages suppressions centrally. Use .ash/suppressions.yaml instead.",
    
    # Text extraction mode - not scanning
    "extract_text": "Text extraction mode is not supported. Use ferret-scan CLI directly for text extraction.",
    
    # Debug/verbose - not applicable in ASH context
    "debug": "Debug mode is not applicable in ASH integration. ASH manages its own logging.",
    "verbose": "Verbose mode is not applicable in ASH integration. ASH manages its own logging.",
}


def parse_version(version_str: str) -> Tuple[int, ...]:
    """Parse a version string into a tuple of integers for comparison.
    
    Args:
        version_str: Version string like "1.2.3" or "1.2.3-beta"
        
    Returns:
        Tuple of integers representing the version (e.g., (1, 2, 3))
    """
    # Remove any pre-release suffixes (e.g., -beta, -rc1)
    version_str = re.split(r'[-+]', version_str)[0]
    # Extract numeric parts
    parts = re.findall(r'\d+', version_str)
    return tuple(int(p) for p in parts) if parts else (0,)


def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings.
    
    Args:
        v1: First version string
        v2: Second version string
        
    Returns:
        -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
    """
    v1_parts = parse_version(v1)
    v2_parts = parse_version(v2)
    
    # Pad shorter version with zeros
    max_len = max(len(v1_parts), len(v2_parts))
    v1_parts = v1_parts + (0,) * (max_len - len(v1_parts))
    v2_parts = v2_parts + (0,) * (max_len - len(v2_parts))
    
    if v1_parts < v2_parts:
        return -1
    elif v1_parts > v2_parts:
        return 1
    return 0


def is_version_compatible(version: str, min_version: str, max_version: str) -> bool:
    """Check if a version is within the compatible range.
    
    Args:
        version: Version to check
        min_version: Minimum supported version (inclusive)
        max_version: Maximum supported version (exclusive)
        
    Returns:
        True if version is compatible, False otherwise
    """
    return (compare_versions(version, min_version) >= 0 and 
            compare_versions(version, max_version) < 0)


class FerretScannerConfigOptions(ScannerOptionsBase):
    """Configuration options for the Ferret scanner.
    
    Unsupported options that will raise errors if used:
    - format/output_format: ASH requires SARIF format
    - web/port: Web server mode not applicable
    - enable_redaction and related: Post-processing not supported
    - generate_suppressions and related: ASH has its own suppression system
    - extract_text: Utility mode not supported
    - debug/verbose: Not applicable; ASH manages its own logging
    """

    confidence_levels: Annotated[
        Literal["all", "high", "medium", "low", "high,medium", "high,low", "medium,low"],
        Field(
            description="Confidence levels to display: 'high', 'medium', 'low', or combinations"
        ),
    ] = "all"

    checks: Annotated[
        str,
        Field(
            description="Specific checks to run, comma-separated: CREDIT_CARD, EMAIL, "
            "INTELLECTUAL_PROPERTY, IP_ADDRESS, METADATA, PASSPORT, PERSON_NAME, "
            "PHONE, SECRETS, SOCIAL_MEDIA, SSN, or 'all'"
        ),
    ] = "all"

    recursive: Annotated[
        bool,
        Field(description="Recursively scan directories"),
    ] = True

    config_file: Annotated[
        Path | str | None,
        Field(
            description="Path to Ferret configuration file (YAML). "
            "If not specified, uses the default config bundled with this plugin. "
            "Set to a custom path to override the default configuration."
        ),
    ] = None

    use_default_config: Annotated[
        bool,
        Field(
            description="Use the default ferret-config.yaml bundled with this plugin. "
            "Set to False to disable the default config and rely only on ferret-scan's built-in defaults."
        ),
    ] = True

    profile: Annotated[
        str | None,
        Field(
            description="Profile name to use from config file (e.g., 'quick', 'ci', "
            "'security-audit', 'comprehensive')"
        ),
    ] = None

    exclude_patterns: Annotated[
        List[str],
        Field(
            description="File patterns to exclude from scanning (glob patterns)"
        ),
    ] = []

    # Tool-specific behavior options (these affect ferret-scan behavior, not ASH logging)
    show_match: Annotated[
        bool,
        Field(
            description="Display the actual matched text in findings. "
            "Note: This affects ferret-scan output, not ASH logging."
        ),
    ] = False

    enable_preprocessors: Annotated[
        bool,
        Field(
            description="Enable text extraction from documents (PDF, Office files). "
            "This allows scanning content within binary document formats."
        ),
    ] = True

    # Version control options
    tool_version: Annotated[
        str | None,
        Field(
            description=f"Version constraint for ferret-scan installation "
            f"(e.g., '>=1.0.0,<2.0.0', '==1.2.0'). If not specified, uses the plugin's "
            f"default compatible version range: {DEFAULT_VERSION_CONSTRAINT}. "
            f"Supported versions: {MIN_SUPPORTED_VERSION} to {MAX_SUPPORTED_VERSION} (exclusive)."
        ),
    ] = None

    skip_version_check: Annotated[
        bool,
        Field(
            description="Skip version compatibility check. Use with caution - "
            "incompatible versions may cause unexpected behavior or errors."
        ),
    ] = False

    @model_validator(mode="before")
    @classmethod
    def validate_no_unsupported_options(cls, data: Any) -> Any:
        """Validate that no unsupported options are being used."""
        if isinstance(data, dict):
            for key in data.keys():
                # Normalize key to snake_case for comparison
                normalized_key = key.lower().replace("-", "_")
                if normalized_key in UNSUPPORTED_FERRET_OPTIONS:
                    error_msg = UNSUPPORTED_FERRET_OPTIONS[normalized_key]
                    raise ValueError(
                        f"Unsupported option '{key}' in ferret-scan plugin configuration. {error_msg}"
                    )
        return data


class FerretScannerConfig(ScannerPluginConfigBase):
    """Configuration for the Ferret scanner.
    
    Important: This plugin follows ASH conventions:
    - Output format is always SARIF (required by ASH)
    - Debug/verbose modes are not passed to ferret-scan
    - Suppressions are managed by ASH centrally
    
    Version Compatibility:
    - Minimum supported version: {MIN_SUPPORTED_VERSION}
    - Maximum supported version: {MAX_SUPPORTED_VERSION} (exclusive)
    - Default version constraint: {DEFAULT_VERSION_CONSTRAINT}
    
    See FerretScannerConfigOptions for supported configuration options.
    """.format(
        MIN_SUPPORTED_VERSION=MIN_SUPPORTED_VERSION,
        MAX_SUPPORTED_VERSION=MAX_SUPPORTED_VERSION,
        DEFAULT_VERSION_CONSTRAINT=DEFAULT_VERSION_CONSTRAINT,
    )

    name: Literal["ferret-scan"] = "ferret-scan"
    enabled: bool = True
    options: Annotated[
        FerretScannerConfigOptions,
        Field(description="Configure Ferret Scan sensitive data detector"),
    ] = FerretScannerConfigOptions()


@ash_scanner_plugin
class FerretScanScanner(ScannerPluginBase[FerretScannerConfig]):
    """Implementation of a sensitive data detection scanner using Ferret Scan.

    Ferret Scan detects sensitive information such as:
    - Credit card numbers (15+ card brands with mathematical validation)
    - Passport numbers (multi-country formats including MRZ)
    - Social Security Numbers (domain-aware validation)
    - Email addresses (RFC-compliant with domain validation)
    - Phone numbers (international and domestic formats)
    - API keys and secrets (40+ patterns including AWS, GitHub, etc.)
    - IP addresses (IPv4 and IPv6)
    - Social media profiles and handles
    - Intellectual property (patents, trademarks, copyrights)
    - Document metadata (EXIF, document properties)
    
    ASH Convention Compliance:
    - Output format: Always SARIF (required by ASH for aggregation)
    - Debug/verbose: Not passed to ferret-scan; ASH manages its own logging
    - Offline mode: Respects ASH_OFFLINE environment variable
    - Output directory: Uses ASH conventions (.ash/ash_output/scanners/ferret-scan/)
    - Suppressions: Managed by ASH centrally (not ferret-scan's suppression system)
    
    Version Compatibility:
    - Supported versions: {MIN_SUPPORTED_VERSION} to {MAX_SUPPORTED_VERSION} (exclusive)
    - Use tool_version option to pin to a specific version
    - Use skip_version_check to bypass version validation (not recommended)
    """.format(
        MIN_SUPPORTED_VERSION=MIN_SUPPORTED_VERSION,
        MAX_SUPPORTED_VERSION=MAX_SUPPORTED_VERSION,
    )

    def model_post_init(self, context):
        if self.config is None:
            self.config = FerretScannerConfig()
        elif not isinstance(self.config, FerretScannerConfig):
            # When config comes from get_plugin_config() it's a raw dict or
            # a ScannerPluginConfigBase instance.  Validate it through our
            # typed config so the unsupported-options validator fires.
            config_data = (
                self.config.model_dump(by_alias=True)
                if hasattr(self.config, "model_dump")
                else self.config
            )
            self.config = FerretScannerConfig.model_validate(config_data)

        self.command = "ferret-scan"
        self.tool_type = "Secrets"
        self.tool_description = (
            "Ferret Scan is a sensitive data detection tool that scans files "
            "for potential sensitive information such as credit card numbers, "
            "passport numbers, SSNs, API keys, and other secrets."
        )

        self.args = ToolArgs(
            format_arg="--format",
            format_arg_value="sarif",  # Always SARIF - required by ASH
            output_arg="--output",
            scan_path_arg="--file",
            extra_args=[],
        )

        super().model_post_init(context)

    def _get_tool_version_constraint(self) -> Optional[str]:
        """Get version constraint for ferret-scan installation.
        
        This method is called by the base class when installing tools via UV.
        
        Returns:
            Version constraint string (e.g., ">=1.0.0,<2.0.0") or None for latest
        """
        # User-specified version takes priority
        if self.config and self.config.options.tool_version:
            return self.config.options.tool_version
        
        # Return default version constraint
        return DEFAULT_VERSION_CONSTRAINT

    def _get_installed_version(self) -> Optional[str]:
        """Get the currently installed ferret-scan version.
        
        Returns:
            Version string (e.g., "1.2.3") or None if not installed or version unknown
        """
        try:
            ferret_binary = find_executable("ferret-scan")
            if not ferret_binary:
                return None
            
            result = subprocess.run(
                [ferret_binary, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            
            if result.returncode == 0:
                # Parse version from output (e.g., "ferret-scan version 1.2.3")
                output = result.stdout.strip()
                # Try to extract version number
                version_match = re.search(r'(\d+\.\d+\.\d+(?:-[\w.]+)?)', output)
                if version_match:
                    return version_match.group(1)
                # If no match, return the whole output as version
                return output
            return None
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError) as e:
            self._plugin_log(
                f"Failed to get ferret-scan version: {e}",
                level=logging.DEBUG,
            )
            return None

    def _check_version_compatibility(self) -> Tuple[bool, Optional[str], Optional[str]]:
        """Check if the installed ferret-scan version is compatible.
        
        Returns:
            Tuple of (is_compatible, installed_version, warning_message)
        """
        installed_version = self._get_installed_version()
        
        if not installed_version:
            return True, None, None  # Can't check, assume compatible
        
        # Store version for later use
        self.tool_version = installed_version
        
        if is_version_compatible(installed_version, MIN_SUPPORTED_VERSION, MAX_SUPPORTED_VERSION):
            return True, installed_version, None
        
        # Version is outside supported range
        if compare_versions(installed_version, MIN_SUPPORTED_VERSION) < 0:
            warning = (
                f"ferret-scan version {installed_version} is older than the minimum "
                f"supported version {MIN_SUPPORTED_VERSION}. Some features may not work correctly. "
                f"Please upgrade to version {RECOMMENDED_VERSION} or later."
            )
        else:
            warning = (
                f"ferret-scan version {installed_version} is newer than the maximum "
                f"tested version {MAX_SUPPORTED_VERSION}. This plugin may not be compatible "
                f"with breaking changes in newer versions. Consider pinning to a compatible "
                f"version using tool_version option, or set skip_version_check=true to proceed."
            )
        
        return False, installed_version, warning

    def validate_plugin_dependencies(self) -> bool:
        """Validate scanner configuration and dependencies.

        Returns:
            bool: True if validation passes
        """
        if self._is_offline_mode():
            self._plugin_log(
                f"Offline mode detected. Checking for pre-installed {self.__class__.__name__}",
                level=logging.INFO,
            )

        ferret_binary = find_executable("ferret-scan")
        if not ferret_binary:
            self._plugin_log(
                "ferret-scan binary not found. Please install it from "
                "https://github.com/awslabs/ferret-scan or via 'pip install ferret-scan'",
                level=logging.ERROR,
            )
            return False

        # Check version compatibility
        is_compatible, installed_version, warning = self._check_version_compatibility()
        
        if installed_version:
            self._plugin_log(
                f"Detected ferret-scan version: {installed_version}",
                level=logging.DEBUG,
            )
        
        if not is_compatible:
            if self.config.options.skip_version_check:
                self._plugin_log(
                    f"Version compatibility check skipped (skip_version_check=true). {warning}",
                    level=logging.WARNING,
                )
            else:
                self._plugin_log(
                    warning,
                    level=logging.WARNING,
                )
                # Log additional guidance
                self._plugin_log(
                    f"Supported versions: {MIN_SUPPORTED_VERSION} to {MAX_SUPPORTED_VERSION} (exclusive). "
                    f"To use this version anyway, set skip_version_check=true in plugin options.",
                    level=logging.INFO,
                )

        self.dependencies_satisfied = True
        return True

    def _process_config_options(self):
        """Process configuration options into command line arguments.
        
        This method translates plugin configuration into ferret-scan CLI arguments.
        
        Note: This method clears extra_args before populating them to prevent
        argument duplication when called multiple times (e.g., via _resolve_arguments).
        
        Debug/verbose flags are NOT passed to ferret-scan. ASH handles its own
        logging independently of the underlying tool's verbosity. This is consistent
        with how other built-in scanners (Semgrep, Checkov, Grype, detect-secrets)
        handle logging.
        """
        # Clear extra_args to prevent duplication on repeated calls
        self.args.extra_args = []

        options = self.config.options

        # Confidence levels
        if options.confidence_levels and options.confidence_levels != "all":
            self.args.extra_args.append(
                ToolExtraArg(key="--confidence", value=options.confidence_levels)
            )

        # Specific checks
        if options.checks and options.checks != "all":
            self.args.extra_args.append(
                ToolExtraArg(key="--checks", value=options.checks)
            )

        # Recursive scanning
        if options.recursive:
            self.args.extra_args.append(
                ToolExtraArg(key="--recursive", value=None)
            )

        # Config file
        config_file_path = self._find_config_file(options.config_file)
        if config_file_path:
            self.args.extra_args.append(
                ToolExtraArg(key="--config", value=str(config_file_path))
            )

        # Profile
        if options.profile:
            self.args.extra_args.append(
                ToolExtraArg(key="--profile", value=options.profile)
            )

        # Exclude patterns
        for pattern in options.exclude_patterns:
            self.args.extra_args.append(
                ToolExtraArg(key="--exclude", value=pattern)
            )

        # Show match (tool-specific behavior option)
        if options.show_match:
            self._plugin_log(
                "show_match is enabled — matched sensitive data (credit cards, SSNs, "
                "API keys, etc.) will appear in SARIF output and log files. "
                "Disable this option in production environments.",
                level=logging.WARNING,
            )
            self.args.extra_args.append(
                ToolExtraArg(key="--show-match", value=None)
            )

        # Enable preprocessors (tool-specific behavior option)
        if options.enable_preprocessors:
            self.args.extra_args.append(
                ToolExtraArg(key="--enable-preprocessors", value=None)
            )

        # Always disable color in ferret-scan output (ASH handles formatting)
        self.args.extra_args.append(
            ToolExtraArg(key="--no-color", value=None)
        )

        return super()._process_config_options()

    def _find_config_file(self, config_file: Path | str | None) -> Path | None:
        """Find the Ferret configuration file.

        Priority order:
        1. Explicitly specified config file (via config_file option)
        2. Config file in source directory (ferret.yaml, .ferret.yaml, etc.)
        3. Default config bundled with this plugin (if use_default_config is True)

        Args:
            config_file: Explicitly specified config file path

        Returns:
            Path to config file if found, None otherwise
        """
        # 1. Check explicitly specified config file
        if config_file:
            path = Path(config_file)
            if path.is_absolute():
                if path.exists():
                    self._plugin_log(
                        f"Using explicitly specified config file: {path}",
                        level=logging.DEBUG,
                    )
                    return path
                else:
                    self._plugin_log(
                        f"Specified config file not found: {path}",
                        level=logging.WARNING,
                    )
                    return None
            # Relative to source directory
            full_path = self.context.source_dir / path
            if full_path.exists():
                self._plugin_log(
                    f"Using config file relative to source: {full_path}",
                    level=logging.DEBUG,
                )
                return full_path
            else:
                self._plugin_log(
                    f"Specified config file not found: {full_path}",
                    level=logging.WARNING,
                )
                return None

        # 2. Search for config files in source directory
        possible_paths = [
            self.context.source_dir / "ferret.yaml",
            self.context.source_dir / "ferret.yml",
            self.context.source_dir / ".ferret.yaml",
            self.context.source_dir / ".ferret.yml",
            self.context.source_dir / ".ash" / "ferret.yaml",
            self.context.source_dir / ".ash" / "ferret-scan.yaml",
        ]

        for path in possible_paths:
            if path.exists():
                self._plugin_log(
                    f"Found Ferret config file in source directory: {path}",
                    level=logging.DEBUG,
                )
                return path

        # 3. Use default config bundled with this plugin
        if self.config.options.use_default_config and DEFAULT_FERRET_CONFIG.exists():
            self._plugin_log(
                f"Using default Ferret config bundled with plugin: {DEFAULT_FERRET_CONFIG}",
                level=logging.DEBUG,
            )
            return DEFAULT_FERRET_CONFIG

        return None

    def _resolve_arguments(
        self, target: Path, results_file: Path | None = None
    ) -> List[str]:
        """Resolve arguments for Ferret scan command.

        Args:
            target: Target to scan
            results_file: Path to write SARIF results

        Returns:
            List[str]: Arguments to pass to Ferret
        """
        # Process configuration options
        self._process_config_options()

        # Build command
        args = [self.command]

        # Add format argument (always SARIF for ASH compatibility)
        if self.args.format_arg and self.args.format_arg_value:
            args.extend([self.args.format_arg, self.args.format_arg_value])

        # Add output file argument
        if results_file and self.args.output_arg:
            args.extend([self.args.output_arg, Path(results_file).as_posix()])

        # Add extra args
        for tool_extra_arg in self.args.extra_args:
            args.append(tool_extra_arg.key)
            if tool_extra_arg.value is not None:
                args.append(str(tool_extra_arg.value))

        # Add target path
        if self.args.scan_path_arg:
            args.append(self.args.scan_path_arg)
        args.append(Path(target).as_posix())

        return args

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[Any] = [],
        config: FerretScannerConfig | None = None,
        *args,
        **kwargs,
    ) -> SarifReport | dict | bool | None:
        """Execute Ferret scan and return results.

        Return convention (matches all built-in ASH scanners):
            SarifReport — happy path, validated SARIF
            True        — nothing to scan (empty/missing target)
            False       — _pre_scan failed or dependencies not satisfied
            None        — results file missing or unparseable JSON
            raw dict    — JSON parsed but SARIF validation failed (fallback)
            raise ScannerError — fatal failure

        See docs/_investigation/ash-scanner-return-contract.md for the full
        contract derived from all built-in and community scanners.

        Args:
            target: Path to scan
            target_type: Type of target (source or converted)
            global_ignore_paths: List of paths to ignore
            config: Scanner configuration

        Returns:
            SarifReport on success; True/False/None/dict on skip/error conditions

        Raises:
            ScannerError: If the scan fails fatally
        """
        # Check if the target directory is empty or doesn't exist
        if not target.exists() or (target.is_dir() and not any(target.iterdir())):
            message = (
                f"Target directory {target} is empty or doesn't exist. Skipping scan."
            )
            self._plugin_log(
                message,
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self._post_scan(target=target, target_type=target_type)
            return True

        try:
            validated = self._pre_scan(
                target=target,
                target_type=target_type,
                config=config,
            )
            if not validated:
                self._post_scan(target=target, target_type=target_type)
                return False
        except ScannerError as exc:
            raise exc

        if not self.dependencies_satisfied:
            self._post_scan(target=target, target_type=target_type)
            return False

        try:
            target_results_dir = self.results_dir.joinpath(target_type)
            results_file = target_results_dir.joinpath("ferret-scan.sarif")
            target_results_dir.mkdir(exist_ok=True, parents=True)

            # Add exclude patterns for global ignore paths (use a local copy to
            # avoid mutating self.config.options.exclude_patterns across calls)
            exclude_patterns = list(self.config.options.exclude_patterns)
            for ignore_path in global_ignore_paths:
                if hasattr(ignore_path, "path"):
                    exclude_patterns.append(str(ignore_path.path))

            # Temporarily swap in the extended list for argument resolution
            original_patterns = self.config.options.exclude_patterns
            self.config.options.exclude_patterns = exclude_patterns

            final_args = self._resolve_arguments(target=target, results_file=results_file)

            # Restore original patterns to prevent state pollution
            self.config.options.exclude_patterns = original_patterns

            self._plugin_log(
                f"Running command: {' '.join(final_args)}",
                target_type=target_type,
                level=logging.DEBUG,
            )

            # Run ferret-scan with output to file
            self._run_subprocess(
                command=final_args,
                results_dir=target_results_dir,
                stdout_preference="write",
                stderr_preference="write",
            )

            self._post_scan(target=target, target_type=target_type)

            # Read SARIF output from file
            if not results_file.exists():
                self._plugin_log(
                    f"No results file found at {results_file}",
                    target_type=target_type,
                    level=logging.WARNING,
                    append_to_stream="stderr",
                )
                return

            scanner_results = None
            try:
                with open(results_file, "r", encoding="utf-8") as f:
                    scanner_results = json.load(f)

                sarif_report: SarifReport = SarifReport.model_validate(scanner_results)

                # Attach scanner details
                sarif_report = attach_scanner_details(
                    sarif_report=sarif_report,
                    scanner_name=self.config.name,
                    scanner_version=getattr(self, "tool_version", None),
                    invocation_details={
                        "command_line": " ".join(final_args),
                        "arguments": final_args[1:],
                        "working_directory": get_shortest_name(input=target),
                        "start_time": self.start_time.isoformat() if self.start_time else None,
                        "end_time": self.end_time.isoformat() if self.end_time else None,
                        "exit_code": self.exit_code,
                    },
                )

                sarif_report.runs[0].invocations = [
                    Invocation(
                        commandLine=" ".join(final_args),
                        arguments=final_args[1:],
                        startTimeUtc=self.start_time,
                        endTimeUtc=self.end_time,
                        executionSuccessful=self.exit_code == 0,
                        exitCode=self.exit_code,
                        exitCodeDescription="\n".join(self.errors) if self.errors else None,
                        workingDirectory=ArtifactLocation(
                            uri=get_shortest_name(input=target),
                        ),
                    )
                ]

                return sarif_report

            except json.JSONDecodeError as e:
                self._plugin_log(
                    f"Failed to parse Ferret output as JSON: {e}",
                    target_type=target_type,
                    level=logging.ERROR,
                    append_to_stream="stderr",
                )
                return

            except Exception as e:
                self._plugin_log(
                    f"Failed to parse Ferret results as SARIF: {e}",
                    target_type=target_type,
                    level=logging.WARNING,
                    append_to_stream="stderr",
                )
                return scanner_results

        except Exception as e:
            raise ScannerError(f"Ferret scan failed: {e}")
