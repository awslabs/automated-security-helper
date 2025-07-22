# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import logging
import os
from pathlib import Path
from typing import Annotated, Any, Literal
from pydantic import Field

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.models.core import (
    ToolExtraArg,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
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


class SnykCodeScannerConfigOptions(ScannerOptionsBase):
    pass


class SnykCodeScannerConfig(ScannerPluginConfigBase):
    """Configuration for the Snyk code scanner."""

    name: Literal["snyk-code"] = "snyk-code"
    enabled: bool = True
    options: Annotated[
        SnykCodeScannerConfigOptions,
        Field(description="Configure snyk-code"),
    ] = SnykCodeScannerConfigOptions()


@ash_scanner_plugin
class SnykCodeScanner(ScannerPluginBase[SnykCodeScannerConfig]):
    """Example scanner plugin that demonstrates the decorator pattern."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = SnykCodeScannerConfig()
        self.command = "snyk"
        self.subcommands = ["code", "test"]
        self.tool_type = "SAST"
        self.args = ToolArgs(
            format_arg=None,
            format_arg_value=None,
            output_arg="--sarif-file-output",
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        """Validate scanner configuration.

        Returns:
            bool: True if validation passes
        """
        if self.config.options.snyk_token_env_var_name is None:
            return False
        if os.environ.get("SNYK_TOKEN", "") == "":
            self._plugin_log(
                f"SNYK_TOKEN env var is not set! Unable to run {self.__class__.__name__}"
            )
            return False
        snyk_binary = find_executable("snyk")
        if not snyk_binary or snyk_binary is None:
            return False
        return True

    def _process_config_options(self):
        if not (
            self.config.options.severity_threshold == "ALL"
            or self.config.options.severity_threshold is None
        ):
            snyk_severity = (
                str(self.config.options.severity_threshold).lower()
                if self.config.options.severity_threshold != "CRITICAL"
                else "high"
            )
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--severity-threshold",
                    value=snyk_severity,
                )
            )

        return super()._process_config_options()

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        config: Any | None = None,
        *args,
        **kwargs,
    ) -> dict:
        """Scan a target file/directory.

        This example scanner simply logs the target and returns a mock finding.

        Args:
            target: Target file or directory to scan
            target_type: Type of target (source or converted)
            global_ignore_paths: List of paths to ignore
            config: Scanner configuration

        Returns:
            dict: Scan results
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

            final_args = self._resolve_arguments(
                target=target,
                results_file=results_file,
            )

            self._plugin_log(
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

            # SARIF mode - parse SARIF results
            if Path(results_file).exists():
                with open(results_file, mode="r", encoding="utf-8") as f:
                    scanner_results = json.load(f)
                try:
                    sarif_report: SarifReport = SarifReport.model_validate(
                        scanner_results
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
                    return
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
            raise ScannerError(f"Opengrep scan failed: {str(e)}")
