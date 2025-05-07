"""Module containing the Opengrep security scanner implementation."""

import json
import logging
import os
from pathlib import Path
from typing import Annotated, List, Literal

from pydantic import Field, model_validator
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
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.download_utils import (
    create_url_download_command,
    get_opengrep_url,
)
from automated_security_helper.utils.subprocess_utils import find_executable


class OpengrepScannerConfigOptions(ScannerOptionsBase):
    config: Annotated[
        str,
        Field(
            description="YAML configuration file, directory of YAML files ending in .yml|.yaml, URL of a configuration file, or Opengrep registry entry name. Use 'auto' to automatically obtain rules tailored to this project. Defaults to 'auto'.",
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
            description="Configures how usage metrics are sent to the Opengrep server.",
        ),
    ] = "auto"

    offline: Annotated[
        bool,
        Field(
            description="Run in offline mode, using locally cached rules.",
        ),
    ] = False

    patterns: Annotated[
        List[str],
        Field(
            description="Patterns to search for with OpenGrep.",
        ),
    ] = []

    version: Annotated[
        str,
        Field(
            description="Version of OpenGrep to use.",
        ),
    ] = "v1.1.5"


class OpengrepScannerConfig(ScannerPluginConfigBase):
    name: Literal["opengrep"] = "opengrep"
    enabled: bool = True
    options: Annotated[
        OpengrepScannerConfigOptions, Field(description="Configure Opengrep scanner")
    ] = OpengrepScannerConfigOptions()


@ash_scanner_plugin
class OpengrepScanner(ScannerPluginBase[OpengrepScannerConfig]):
    """OpengrepScanner implements code scanning using Opengrep."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = OpengrepScannerConfig()
        self.command = "opengrep"
        self.subcommands = ["scan"]
        self.tool_type = "SAST"
        self.args = ToolArgs(
            format_arg=None,
            format_arg_value=None,
            output_arg="--sarif-output",
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "OpengrepScanner":
        """Set up custom installation commands for opengrep."""
        # Get version and linux_type from config
        version = self.config.options.version
        # TODO - Check if linux and determine whether manylinux or musllinux is needed
        linux_type = "manylinux"

        # Linux
        if "linux" not in self.custom_install_commands:
            self.custom_install_commands["linux"] = {}

        self.custom_install_commands["linux"]["amd64"] = [
            create_url_download_command(
                url=get_opengrep_url(
                    "linux", "amd64", version=version, linux_type=linux_type
                ),
                rename_to="opengrep",
            )
        ]

        self.custom_install_commands["linux"]["arm64"] = [
            create_url_download_command(
                url=get_opengrep_url(
                    "linux", "arm64", version=version, linux_type=linux_type
                ),
                rename_to="opengrep",
            )
        ]

        # macOS
        if "darwin" not in self.custom_install_commands:
            self.custom_install_commands["darwin"] = {}

        self.custom_install_commands["darwin"]["amd64"] = [
            create_url_download_command(
                url=get_opengrep_url("darwin", "amd64", version=version),
                rename_to="opengrep",
            )
        ]

        self.custom_install_commands["darwin"]["arm64"] = [
            create_url_download_command(
                url=get_opengrep_url("darwin", "arm64", version=version),
                rename_to="opengrep",
            )
        ]

        # Windows
        if "windows" not in self.custom_install_commands:
            self.custom_install_commands["windows"] = {}

        self.custom_install_commands["windows"]["amd64"] = [
            create_url_download_command(
                url=get_opengrep_url("windows", "amd64", version=version),
                rename_to="opengrep.exe",
            )
        ]

        return self

    def validate(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        found = find_executable(self.command)
        return found is not None
        # try:
        #     result = self._run_subprocess(
        #         [self.command, "--version"],
        #         stdout_preference="return",
        #         stderr_preference="return",
        #     )
        #     if result.get("returncode", 1) != 0:
        #         self._scanner_log(
        #             f"OpenGrep is not installed or not working properly: {result.get('stderr', '')}",
        #             level=logging.ERROR,
        #         )
        #         return False

        #     self.tool_version = result.get("stdout", "").strip()
        #     self._scanner_log(
        #         f"OpenGrep version: {self.tool_version}", level=logging.INFO
        #     )
        #     return True
        # except Exception as e:
        #     self._scanner_log(f"Error validating OpenGrep: {e}", level=logging.ERROR)
        #     return False

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
            # Check if OPENGREP_RULES_CACHE_DIR is set in environment
            opengrep_rules_cache_dir = os.environ.get("OPENGREP_RULES_CACHE_DIR")
            if opengrep_rules_cache_dir:
                opengrep_rules = [
                    item
                    for item in [
                        *Path(opengrep_rules_cache_dir).glob("**/*"),
                        *Path(opengrep_rules_cache_dir).glob("*"),
                    ]
                    if (item.name.endswith(".yaml") or item.name.endswith(".yml"))
                ]
                if opengrep_rules:
                    self.args.extra_args.extend(
                        [
                            ToolExtraArg(
                                key="--config",
                                value=item.as_posix(),
                            )
                            for item in opengrep_rules
                        ]
                    )
                else:
                    self._scanner_log(
                        "No Opengrep rules found in cache directory, falling back to p/ci",
                        level=logging.WARNING,
                    )
                    self.args.extra_args.append(
                        ToolExtraArg(
                            key="--config",
                            value="p/ci",
                        )
                    )
            else:
                self._scanner_log(
                    "OPENGREP_RULES_CACHE_DIR not set but offline mode enabled, falling back to p/ci",
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

        # Add patterns if using direct pattern search mode
        if self.config.options.patterns:
            # Switch to pattern search mode
            self.args.extra_args = [ToolExtraArg(key="--json", value="")]

            # Add patterns
            for pattern in self.config.options.patterns:
                self.args.extra_args.append(
                    ToolExtraArg(
                        key="--pattern",
                        value=pattern,
                    )
                )

        return super()._process_config_options()

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] = [],
        config: OpengrepScannerConfig | None = None,
    ) -> SarifReport:
        """Execute Opengrep scan and return results.

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
            self._scanner_log(
                message,
                target_type=target_type,
                level=20,
                append_to_stream="stderr",  # This will add the message to self.errors
            )
            return

        try:
            self._pre_scan(
                target=target,
                target_type=target_type,
                config=config,
            )
        except ScannerError as exc:
            raise exc

        if not self.dependencies_satisfied:
            # Logging of this has been done in the central self._pre_scan() method.
            return

        try:
            target_results_dir = self.results_dir.joinpath(target_type)
            results_file = target_results_dir.joinpath("results_sarif.sarif")
            target_results_dir.mkdir(exist_ok=True, parents=True)

            # If using pattern search mode, use a different results file
            if self.config.options.patterns:
                results_file = target_results_dir.joinpath("opengrep_results.json")

            final_args = self._resolve_arguments(
                target=target,
                results_file=results_file,
            )

            self._scanner_log(
                f"Running command: {' '.join(final_args)}",
                target_type=target_type,
                level=15,
            )

            # Set environment variables for offline mode if needed
            env_vars = {}
            if self.config.options.offline and "OPENGREP_RULES_CACHE_DIR" in os.environ:
                env_vars["OPENGREP_RULES"] = (
                    f"{os.environ['OPENGREP_RULES_CACHE_DIR']}/*"
                )

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

            # Handle different result formats based on mode
            if self.config.options.patterns:
                # Pattern search mode - parse JSON results
                if results_file.exists():
                    try:
                        with open(results_file, mode="r", encoding="utf-8") as f:
                            results_data = json.load(f)

                        # Convert OpenGrep results to findings format
                        findings = []
                        for match in results_data.get("matches", []):
                            findings.append(
                                {
                                    "file": match.get("file", ""),
                                    "line": match.get("line", 0),
                                    "column": match.get("column", 0),
                                    "message": f"Found pattern: {match.get('pattern', '')}",
                                    "severity": "MEDIUM",  # Default severity
                                    "code": match.get("content", ""),
                                }
                            )
                        return {"findings": findings}
                    except Exception as e:
                        self._scanner_log(
                            f"Error parsing OpenGrep results: {e}", level=logging.ERROR
                        )
                        return {"findings": []}
                else:
                    self._scanner_log(
                        f"No results file found at {results_file}",
                        level=logging.WARNING,
                    )
                    return {"findings": []}
            else:
                # SARIF mode - parse SARIF results
                if Path(results_file).exists():
                    with open(results_file, mode="r", encoding="utf-8") as f:
                        opengrep_results = json.load(f)
                    try:
                        sarif_report: SarifReport = SarifReport.model_validate(
                            opengrep_results
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
                                properties=PropertyBag(
                                    tool=sarif_report.runs[0].tool,
                                ),
                            )
                        ]
                        return sarif_report
                    except Exception as e:
                        self._scanner_log(
                            f"Failed to parse {self.__class__.__name__} results as SARIF: {str(e)}",
                            target_type=target_type,
                            level=logging.ERROR,
                            append_to_stream="stderr",
                        )
                        return
                else:
                    self._scanner_log(
                        f"No results file found at {results_file}",
                        target_type=target_type,
                        level=logging.WARNING,
                        append_to_stream="stderr",
                    )
                    return

        except Exception as e:
            # Check if there are useful error details
            raise ScannerError(f"Opengrep scan failed: {str(e)}")
