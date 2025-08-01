"""Module containing the Semgrep security scanner implementation."""

import json
import logging
import os
from pathlib import Path
import platform
from typing import Annotated, List, Literal

from pydantic import Field
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.core.constants import ASH_ASSETS_DIR
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ToolExtraArg,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    SarifReport,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.sarif_utils import attach_scanner_details
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.subprocess_utils import find_executable


class SemgrepScannerConfigOptions(ScannerOptionsBase):
    config: Annotated[
        str,
        Field(
            description="YAML configuration file, directory of YAML files ending in .yml|.yaml, URL of a configuration file, or Semgrep registry entry name. Use 'auto' to automatically obtain rules tailored to this project. Defaults to 'auto'.",
        ),
    ] = "auto"

    exclude: Annotated[
        List[str],
        Field(
            description="Skip any file or directory whose path matches the pattern.",
        ),
    ] = ["*-converted.py", "*_report_result.txt"]

    exclude_rule: Annotated[
        List[str],
        Field(
            description="Skip any rule with the given id.",
        ),
    ] = []

    severity: Annotated[
        List[Literal["INFO", "WARNING", "ERROR"]],
        Field(
            description="Report findings only from rules matching the supplied severity level.",
        ),
    ] = []

    metrics: Annotated[
        Literal["auto", "on", "off"],
        Field(
            description="Configures how usage metrics are sent to the Semgrep server.",
        ),
    ] = "auto"

    offline: Annotated[
        bool,
        Field(
            description="Run in offline mode, using locally cached rules.",
        ),
    ] = str(os.environ.get("ASH_OFFLINE", "NO")).upper() in ["YES", "TRUE", "1"]

    tool_version: Annotated[
        str | None,
        Field(
            description="Specific version constraint for semgrep installation (e.g., '>=1.125.0')"
        ),
    ] = None

    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation"),
    ] = 300


class SemgrepScannerConfig(ScannerPluginConfigBase):
    name: Literal["semgrep"] = "semgrep"
    # Semgrep does not support Windows at all
    enabled: bool = platform.system().lower() != "windows"
    options: Annotated[
        SemgrepScannerConfigOptions, Field(description="Configure Semgrep scanner")
    ] = SemgrepScannerConfigOptions()


@ash_scanner_plugin
class SemgrepScanner(ScannerPluginBase[SemgrepScannerConfig]):
    """SemgrepScanner implements code scanning using Semgrep."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = SemgrepScannerConfig()
        self.command = "semgrep"
        self.use_uv_tool = True  # Enable UV tool execution
        self.subcommands = ["scan"]
        self.tool_type = "SAST"

        # Set up explicit UV tool installation commands
        self._setup_uv_tool_install_commands()

        # Update tool version detection to work with explicit installation
        self.tool_version = self._get_uv_tool_version("semgrep")
        self.args = ToolArgs(
            format_arg=None,
            format_arg_value=None,
            output_arg="--sarif-output",
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    def _get_tool_version_constraint(self) -> str | None:
        """Get version constraint for semgrep installation.

        Returns:
            Version constraint string for semgrep (e.g., ">=1.125.0") or None for latest
        """
        # Use configured tool version if available, otherwise use default
        if self.config and self.config.options.tool_version:
            return self.config.options.tool_version

        # Use semgrep-specific version constraint - semgrep 1.125.0+ has improved stability
        return ">=1.125.0,<2.0.0"

    def validate_plugin_dependencies(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        # Check if running on Windows (Semgrep doesn't support Windows)
        if platform.system().lower() == "windows":
            self._plugin_log(
                "Semgrep is not supported on Windows and will be skipped",
                level=logging.INFO,
            )
            return False

        # First validate UV tool availability if required
        if not self._validate_uv_tool_availability():
            # If UV tool is not available, try direct executable fallback
            self._plugin_log(
                "UV tool not available, attempting direct executable detection",
                level=logging.WARNING,
            )
            found = find_executable(self.command)
            if found is None:
                return False
            # If direct executable is found, disable UV tool for this instance
            self.use_uv_tool = False
            self._plugin_log(
                f"Using direct semgrep execution at {found}",
                level=logging.WARNING,
            )
            self.dependencies_satisfied = True
            return True

        # For UV tool-based scanners, attempt explicit installation if needed
        if self.use_uv_tool:
            # Check if tool is already installed
            if not self._is_uv_tool_installed():
                self._plugin_log(
                    "Semgrep not found via UV tool, attempting explicit installation..."
                )

                # Attempt explicit tool installation with configured timeout
                timeout = (
                    getattr(self.config.options, "install_timeout", 300)
                    if self.config
                    else 300
                )
                if self._install_uv_tool(timeout=timeout):
                    self._plugin_log("Successfully installed semgrep via UV tool")
                    self.dependencies_satisfied = True
                    return True
                else:
                    self._plugin_log(
                        "UV tool installation failed for semgrep, trying direct executable detection",
                        level=logging.WARNING,
                    )
                    # Enhanced fallback logic: try direct executable detection
                    found = find_executable(self.command)
                    if found is None:
                        self._plugin_log(
                            "Direct executable detection also failed for semgrep",
                            level=logging.ERROR,
                        )
                        return False
                    # If direct executable is found, disable UV tool for this instance
                    self.use_uv_tool = False
                    self._plugin_log(
                        f"Using direct semgrep execution at {found} as fallback",
                        level=logging.WARNING,
                    )
            else:
                self._plugin_log("Semgrep already installed via UV tool")

        self.dependencies_satisfied = True
        return True

    def _process_config_options(self):
        ash_stargrep_rules = [
            item
            for item in ASH_ASSETS_DIR.joinpath("ash_stargrep_rules").glob("*")
            if (item.as_posix().endswith(".yaml") or item.as_posix().endswith(".yml"))
        ]
        if ash_stargrep_rules:
            ASH_LOGGER.verbose(f"Found ASH *grep rulesets: {ash_stargrep_rules}")
            self.args.extra_args.extend(
                [
                    ToolExtraArg(
                        key="--config",
                        value=item.as_posix(),
                    )
                    for item in ash_stargrep_rules
                ]
            )
        if self.config.options.offline:
            # In offline mode, use metrics=off
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--metrics",
                    value="off",
                )
            )

            # Validate offline mode requirements
            from automated_security_helper.utils.offline_mode_validator import (
                validate_semgrep_offline_mode,
            )

            offline_valid, offline_messages = validate_semgrep_offline_mode()

            # Check if SEMGREP_RULES_CACHE_DIR is set in environment
            semgrep_rules_cache_dir = os.environ.get("SEMGREP_RULES_CACHE_DIR")
            if semgrep_rules_cache_dir:
                semgrep_rules = [
                    item
                    for item in Path(semgrep_rules_cache_dir).glob("**/*")
                    if (item.name.endswith(".yaml") or item.name.endswith(".yml"))
                ]
                if semgrep_rules:
                    ASH_LOGGER.info(
                        f"Semgrep offline mode: Found {len(semgrep_rules)} rule files in cache"
                    )
                    self.args.extra_args.extend(
                        [
                            ToolExtraArg(
                                key="--config",
                                value=item.as_posix(),
                            )
                            for item in semgrep_rules
                        ]
                    )
                else:
                    self._plugin_log(
                        "🔴 Semgrep offline mode: No rules found in cache directory, falling back to p/ci",
                        level=logging.WARNING,
                    )
                    self.args.extra_args.append(
                        ToolExtraArg(
                            key="--config",
                            value="p/ci",
                        )
                    )
            else:
                self._plugin_log(
                    "🔴 Semgrep offline mode: SEMGREP_RULES_CACHE_DIR not set, falling back to p/ci",
                    level=logging.WARNING,
                )
                self.args.extra_args.append(
                    ToolExtraArg(
                        key="--config",
                        value="p/ci",
                    )
                )
        else:
            # In online mode, use config=auto
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--config",
                    value=self.config.options.config,
                )
            )
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--metrics",
                    value=self.config.options.metrics,
                )
            )

        # Add exclude patterns
        for exclude_pattern in self.config.options.exclude:
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--exclude",
                    value=exclude_pattern,
                )
            )

        # Add exclude rules
        for exclude_rule in self.config.options.exclude_rule:
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--exclude-rule",
                    value=exclude_rule,
                )
            )

        # Add severity filters
        for severity in self.config.options.severity:
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--severity",
                    value=severity,
                )
            )

        # Add SARIF output format
        self.args.extra_args.append(
            ToolExtraArg(
                key="--sarif",
                value="",
            )
        )

        return super()._process_config_options()

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] = [],
        config: SemgrepScannerConfig | None = None,
    ) -> SarifReport | bool | None:
        """Execute Semgrep scan and return results.

        Args:
            target: Path to scan
            target_type: Type of target (source or converted)
            global_ignore_paths: List of paths to ignore
            config: Scanner configuration

        Returns:
            SarifReport containing the scan findings and metadata

        Raises:
            ScannerError: If the scan fails or results cannot be parsed
        """
        # Check if the target directory is empty or doesn't exist
        if not target.exists() or not any(target.iterdir()):
            message = (
                f"Target directory {target} is empty or doesn't exist. Skipping scan."
            )
            self._plugin_log(
                message,
                target_type=target_type,
                level=20,
                append_to_stream="stderr",  # This will add the message to self.errors
            )
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return True

        try:
            validated = self._pre_scan(
                target=target,
                target_type=target_type,
                config=config,
            )
            if not validated:
                self._post_scan(
                    target=target,
                    target_type=target_type,
                )
                return False
        except ScannerError as exc:
            raise exc

        if not self.dependencies_satisfied:
            # Logging of this has been done in the central self._pre_scan() method.
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return False

        try:
            target_results_dir = self.results_dir.joinpath(target_type)
            results_file = target_results_dir.joinpath("results_sarif.sarif")
            target_results_dir.mkdir(exist_ok=True, parents=True)

            # Add global ignore paths as exclude patterns
            # for ignore_path in global_ignore_paths:
            #     self.args.extra_args.append(
            #         ToolExtraArg(
            #             key="--exclude",
            #             value=ignore_path.path,
            #         )
            #     )

            final_args = self._resolve_arguments(
                target=target,
                results_file=results_file,
            )

            # Semgrep expects the target directory at the end of the command
            # final_args.append(str(target))
            self._plugin_log(
                f"Running command: {' '.join(final_args)}",
                target_type=target_type,
                level=15,
            )

            # Set environment variables for offline mode if needed
            env_vars = {}
            if self.config.options.offline and "SEMGREP_RULES_CACHE_DIR" in os.environ:
                env_vars["SEMGREP_RULES"] = f"{os.environ['SEMGREP_RULES_CACHE_DIR']}/*"

            # Run the subprocess with the environment variables
            if env_vars:
                # Need to modify environment for the subprocess
                orig_env = os.environ.copy()
                for k, v in env_vars.items():
                    os.environ[k] = v

                self._run_subprocess(
                    command=final_args,
                    results_dir=target_results_dir,
                )

                # Restore original environment
                for k in env_vars.keys():
                    if k in orig_env:
                        os.environ[k] = orig_env[k]
                    else:
                        del os.environ[k]
            else:
                # No environment modifications needed
                self._run_subprocess(
                    command=final_args,
                    results_dir=target_results_dir,
                )

            self._post_scan(
                target=target,
                target_type=target_type,
            )

            semgrep_results = {}
            if Path(results_file).exists():
                with open(results_file, mode="r", encoding="utf-8") as f:
                    semgrep_results = json.load(f)
                try:
                    sarif_report: SarifReport = SarifReport.model_validate(
                        semgrep_results
                    )

                    # Attach scanner details for proper identification
                    sarif_report = attach_scanner_details(
                        sarif_report=sarif_report,
                        scanner_name=self.config.name,
                        scanner_version=getattr(self, "tool_version", None),
                        invocation_details={
                            "command_line": " ".join(final_args),
                            "arguments": final_args[1:],
                            "working_directory": get_shortest_name(input=target),
                            "start_time": self.start_time.isoformat()
                            if self.start_time
                            else None,
                            "end_time": self.end_time.isoformat()
                            if self.end_time
                            else None,
                            "exit_code": self.exit_code,
                        },
                    )

                    sarif_report.runs[0].invocations = [
                        Invocation(
                            commandLine=" ".join(final_args),
                            arguments=final_args[1:],
                            startTimeUtc=self.start_time,
                            endTimeUtc=self.end_time,
                            executionSuccessful=True,
                            exitCode=self.exit_code,
                            exitCodeDescription="\n".join(self.errors),
                            workingDirectory=ArtifactLocation(
                                uri=get_shortest_name(input=target),
                            ),
                        )
                    ]
                    self._post_scan(
                        target=target,
                        target_type=target_type,
                    )
                    return sarif_report
                except Exception as e:
                    self._plugin_log(
                        f"Failed to parse {self.__class__.__name__} results as SARIF: {str(e)}",
                        target_type=target_type,
                        level=logging.ERROR,
                        append_to_stream="stderr",
                    )
                    self._post_scan(
                        target=target,
                        target_type=target_type,
                    )
            else:
                self._plugin_log(
                    f"No results file found at {results_file}",
                    target_type=target_type,
                    level=logging.WARNING,
                    append_to_stream="stderr",
                )
                self._post_scan(
                    target=target,
                    target_type=target_type,
                )

        except Exception as e:
            # Check if there are useful error details
            raise ScannerError(f"Semgrep scan failed: {str(e)}")
