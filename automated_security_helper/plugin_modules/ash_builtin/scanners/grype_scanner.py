"""Module containing the Grype security scanner implementation."""

import json
import os
from pathlib import Path
from typing import Annotated, List, Literal

from pydantic import Field, model_validator
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ToolExtraArg,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.subprocess_utils import find_executable


class GrypeScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        Path | str | None,
        Field(
            description="Path to Grype configuration file, relative to current source directory. Defaults to searching for `.grype.yaml` and `.grype.yml` in the root of the source directory.",
        ),
    ] = None
    severity_threshold: Literal["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = (
        None
    )
    offline: Annotated[
        bool,
        Field(
            description="Run in offline mode, disabling database updates and validation",
        ),
    ] = str(os.environ.get("ASH_OFFLINE", "NO")).upper() in ["YES", "TRUE", "1"]


class GrypeScannerConfig(ScannerPluginConfigBase):
    name: Literal["grype"] = "grype"
    enabled: bool = True
    options: Annotated[
        GrypeScannerConfigOptions, Field(description="Configure Grype scanner")
    ] = GrypeScannerConfigOptions()


@ash_scanner_plugin
class GrypeScanner(ScannerPluginBase[GrypeScannerConfig]):
    """GrypeScanner implements IaC scanning using Grype."""

    check_conf: str = "NOT_PROVIDED"

    def model_post_init(self, context):
        if self.config is None:
            self.config = GrypeScannerConfig()
        self.command = "grype"
        self.tool_type = "SAST"
        self.args = ToolArgs(
            format_arg="--output",
            format_arg_value="sarif",
            output_arg="--file",
            scan_path_arg=None,
            extra_args=[
                # ToolExtraArg(key="--skip-framework", value="cloudformation"),
            ],
        )
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "GrypeScanner":
        """Set up custom installation commands for Grype."""
        # Get version and linux_type from config
        # Linux
        if "linux" not in self.custom_install_commands:
            self.custom_install_commands["linux"] = {}
        self.custom_install_commands["linux"]["amd64"] = []
        self.custom_install_commands["linux"]["arm64"] = []
        # macOS
        if "darwin" not in self.custom_install_commands:
            self.custom_install_commands["darwin"] = {}
        self.custom_install_commands["darwin"]["amd64"] = []
        self.custom_install_commands["darwin"]["arm64"] = []
        # Windows
        if "windows" not in self.custom_install_commands:
            self.custom_install_commands["windows"] = {}
        self.custom_install_commands["windows"]["amd64"] = []

        return self

    def validate_plugin_dependencies(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        found = find_executable(self.command)
        if not found:
            ASH_LOGGER.warning(
                "Grype executable not found in PATH. Please ensure grype is installed."
            )
        return found is not None

    def _process_config_options(self):
        # Grype config path
        possible_config_paths = [
            item
            for item in [
                self.config.options.config_file,
                ".grype.yaml",
                ".grype/config.yaml",
                ".ash/.grype.yaml",
                ".ash/grype.yaml",
            ]
            if item is not None
        ]

        for conf_path in possible_config_paths:
            if Path(conf_path).exists():
                self.args.extra_args.append(
                    ToolExtraArg(
                        key="--config",
                        value=get_shortest_name(input=conf_path),
                    )
                )
                break

        # Handle offline mode
        if self.config.options.offline:
            # Add environment variables for offline mode
            os.environ["GRYPE_DB_VALIDATE_AGE"] = "false"
            os.environ["GRYPE_DB_AUTO_UPDATE"] = "false"
            os.environ["GRYPE_CHECK_FOR_APP_UPDATE"] = "false"

            # Validate offline mode requirements
            from automated_security_helper.utils.offline_mode_validator import (
                validate_grype_offline_mode,
            )

            offline_valid, offline_messages = validate_grype_offline_mode()

            ASH_LOGGER.info(
                "Running Grype in offline mode - database updates and validation disabled"
            )

        return super()._process_config_options()

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] = [],
        config: GrypeScannerConfig | None = None,
    ) -> SarifReport | bool:
        """Execute Grype scan and return results.

        Args:
            target: Path to scan

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
            results_file.parent.mkdir(exist_ok=True, parents=True)
            final_args = self._resolve_arguments(
                # Grype expects directory scans to have the target begin with `dir:`
                target=f"dir:{target.as_posix()}",
                results_file=results_file,
            )
            self._run_subprocess(
                command=final_args,
                results_dir=target_results_dir,
            )

            self._post_scan(
                target=target,
                target_type=target_type,
            )

            grype_results = {}
            with open(results_file, mode="r", encoding="utf-8") as f:
                grype_results = json.load(f)

            ASH_LOGGER.debug(
                f"Grype results structure: runs count = {len(grype_results.get('runs', []))}"
            )

            try:
                sarif_report: SarifReport = SarifReport.model_validate(grype_results)

                # Ensure we have at least one run before accessing it
                if not sarif_report.runs:
                    ASH_LOGGER.warning(
                        "Grype SARIF report has no runs, creating empty run"
                    )
                    from automated_security_helper.schemas.sarif_schema_model import (
                        Run,
                        Tool,
                        ToolComponent,
                    )

                    sarif_report.runs = [
                        Run(
                            tool=Tool(
                                driver=ToolComponent(name="grype", version="unknown")
                            ),
                            results=[],
                        )
                    ]

                # Safely access the first run
                first_run = sarif_report.runs[0]
                first_run.invocations = [
                    Invocation(
                        commandLine=final_args[0],
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
                            tool=first_run.tool,
                        ),
                    )
                ]

                clean_runs = []
                for run in sarif_report.runs:
                    # Always include runs, even if they have no results
                    clean_results = []
                    if run.results:
                        for result in run.results:
                            try:
                                # Process locations
                                if result.locations:
                                    for location in result.locations:
                                        if (
                                            location.physicalLocation
                                            and location.physicalLocation.root
                                            and location.physicalLocation.root.artifactLocation
                                        ):
                                            uri = location.physicalLocation.root.artifactLocation.uri
                                            if uri:
                                                uri = uri.lstrip("/")
                                                location.physicalLocation.root.artifactLocation.uri = uri

                                # Process related locations if present
                                if (
                                    hasattr(result, "relatedLocations")
                                    and result.relatedLocations
                                ):
                                    for related in result.relatedLocations:
                                        if (
                                            related.physicalLocation
                                            and related.physicalLocation.root
                                            and related.physicalLocation.root.artifactLocation
                                        ):
                                            uri = related.physicalLocation.root.artifactLocation.uri
                                            if uri:
                                                uri = uri.lstrip("/")
                                                related.physicalLocation.root.artifactLocation.uri = uri

                                # Process analysis target if present
                                if result.analysisTarget and result.analysisTarget.uri:
                                    uri = result.analysisTarget.uri
                                    uri = uri.lstrip("/")
                                    result.analysisTarget.uri = uri
                                clean_results.append(result)
                            except Exception as e:
                                ASH_LOGGER.warning(
                                    f"Error processing Grype result: {e}"
                                )
                                # Still append the result even if processing failed
                                clean_results.append(result)

                    run.results = clean_results
                    clean_runs.append(run)
                sarif_report.runs = clean_runs
            except Exception as e:
                ASH_LOGGER.warning(
                    f"Failed to parse {self.__class__.__name__} results as SARIF: {str(e)}"
                )
                ASH_LOGGER.debug(f"Grype SARIF processing error details: {e}")
                # Return the raw results if SARIF processing fails
                sarif_report = grype_results

            return sarif_report

        except Exception as e:
            # Check if there are useful error details
            raise ScannerError(f"Grype scan failed: {str(e)}")
