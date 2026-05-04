"""Module containing the Grype security scanner implementation."""

import json
import logging
import os
from pathlib import Path
from typing import Annotated, List, Literal

from pydantic import Field
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ToolExtraArg,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.core.constants import is_offline_mode
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
            default_factory=is_offline_mode,
        ),
    ]


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
    # Env vars to layer onto the subprocess. Populated by
    # _process_config_options (e.g. offline-mode flags). Kept local to the
    # scanner instance so concurrent scanners don't race on os.environ.
    extra_env: Annotated[dict, Field(default_factory=dict)]

    def model_post_init(self, context):
        if self.config is None:
            self.config = GrypeScannerConfig()
        self.command = "grype"
        self.tool_type = ScannerToolType.SCA
        self.args = ToolArgs(
            format_arg="--output",
            format_arg_value="sarif",
            output_arg="--file",
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

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

    @staticmethod
    def _strip_leading_slash_from_uri(location) -> None:
        """Strip leading slashes from the artifact location URI, if present."""
        if (
            location.physicalLocation
            and location.physicalLocation.root
            and location.physicalLocation.root.artifactLocation
        ):
            uri = location.physicalLocation.root.artifactLocation.uri
            if uri:
                location.physicalLocation.root.artifactLocation.uri = uri.lstrip("/")

    def _normalize_result_uris(self, result) -> None:
        """Strip leading slashes from all URIs in a single SARIF result."""
        try:
            for loc in result.locations or []:
                self._strip_leading_slash_from_uri(loc)

            for rel in getattr(result, "relatedLocations", None) or []:
                self._strip_leading_slash_from_uri(rel)

            if result.analysisTarget and result.analysisTarget.uri:
                result.analysisTarget.uri = result.analysisTarget.uri.lstrip("/")
        except Exception as e:
            ASH_LOGGER.warning(f"Error processing Grype result: {e}")

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

        # Handle offline mode. Stash offline-mode env vars on the instance
        # rather than writing to os.environ — scanners run concurrently
        # in thread pools and would race on the shared parent env.
        if self.config.options.offline:
            self.extra_env.update(
                {
                    "GRYPE_DB_VALIDATE_AGE": "false",
                    "GRYPE_DB_AUTO_UPDATE": "false",
                    "GRYPE_CHECK_FOR_APP_UPDATE": "false",
                }
            )

            # Validate offline mode requirements
            from automated_security_helper.utils.offline_mode_validator import (
                validate_grype_offline_mode,
            )

            offline_valid, offline_messages = validate_grype_offline_mode()
            if not offline_valid:
                for msg in offline_messages:
                    self._plugin_log(msg, level=logging.WARNING)

            ASH_LOGGER.info(
                "Running Grype in offline mode - database updates and validation disabled"
            )

        return super()._process_config_options()

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
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
        if global_ignore_paths is None:
            global_ignore_paths = []
        # Check if the target directory is empty or doesn't exist
        if not target.exists() or not any(target.iterdir()):
            message = (
                f"Target directory {target} is empty or doesn't exist. Skipping scan."
            )
            self._plugin_log(
                message,
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return True

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


        if not self.dependencies_satisfied:
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
            subprocess_env = (
                {**os.environ, **self.extra_env} if self.extra_env else None
            )
            self._run_subprocess(
                command=final_args,
                results_dir=target_results_dir,
                env=subprocess_env,
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
                        executionSuccessful=(self.exit_code in (0, 2)),
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

                for run in sarif_report.runs:
                    for result in run.results or []:
                        self._normalize_result_uris(result)
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
