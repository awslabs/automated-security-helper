"""Module containing the Grype security scanner implementation."""

import json
from pathlib import Path
import shutil
from typing import Annotated, List, Literal

from pydantic import Field
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
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.normalizers import get_normalized_filename


class GrypeScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        Path | str | None,
        Field(
            description="Path to Grype configuration file, relative to current source directory. Defaults to searching for `.grype.yaml` and `.grype.yml` in the root of the source directory.",
        ),
    ] = None
    skip_path: Annotated[
        List[IgnorePathWithReason],
        Field(
            description='Path (file or directory) to skip, using regular expression logic, relative to current working directory. Word boundaries are not implicit; i.e., specifying "dir1" will skip any directory or subdirectory named "dir1". Ignored with -f. Can be specified multiple times.',
        ),
    ] = []


class GrypeScannerConfig(ScannerPluginConfigBase):
    name: Literal["grype"] = "grype"
    enabled: bool = True
    options: Annotated[
        GrypeScannerConfigOptions, Field(description="Configure Grype scanner")
    ] = GrypeScannerConfigOptions()


class GrypeScanner(ScannerPluginBase[GrypeScannerConfig]):
    """GrypeScanner implements IaC scanning using Grype."""

    check_conf: str = "NOT_PROVIDED"

    def model_post_init(self, context):
        if self.config is None:
            self.config = GrypeScannerConfig()
        self.command = "grype"
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

    def validate(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        return shutil.which(self.command) is not None

    def _process_config_options(self):
        # Grype config path
        possible_config_paths = [
            item
            for item in [
                self.config.options.config_file,
                ".grype.yaml",
                ".grype.yml",
            ]
            if item is not None
        ]

        for conf_path in possible_config_paths:
            if Path(conf_path).exists():
                self.args.extra_args.append(
                    ToolExtraArg(
                        key="--config-file",
                        value=get_shortest_name(input=conf_path),
                    )
                )
                break

        for item in self.config.options.skip_path:
            ASH_LOGGER.debug(
                f"Path '{item.path}' excluded from {self.config.name} scan for reason: {item.reason}"
            )
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--exclude",
                    value=item.path,
                )
            )

        return super()._process_config_options()

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "temp"],
        global_ignore_paths: List[IgnorePathWithReason] = [],
        config: GrypeScannerConfig | None = None,
    ) -> SarifReport:
        """Execute Grype scan and return results.

        Args:
            target: Path to scan

        Returns:
            SarifReport containing the scan findings and metadata

        Raises:
            ScannerError: If the scan fails or results cannot be parsed
        """
        try:
            self._pre_scan(
                target=target,
                config=config,
            )
        except ScannerError as exc:
            raise exc

        try:
            normalized_file_name = get_normalized_filename(str_to_normalize=target)
            target_results_dir = Path(self.results_dir).joinpath(normalized_file_name)
            results_file = target_results_dir.joinpath("results_sarif.sarif")
            results_file.parent.mkdir(exist_ok=True, parents=True)
            final_args = self._resolve_arguments(
                target=target,
                results_file=results_file,
            )
            self._run_subprocess(
                command=final_args,
                results_dir=target_results_dir,
            )

            self._post_scan(target=target)

            grype_results = {}
            Path(results_file).parent.mkdir(exist_ok=True, parents=True)
            with open(results_file, "r") as f:
                grype_results = json.load(f)
            try:
                sarif_report: SarifReport = SarifReport.model_validate(grype_results)
                sarif_report.runs[0].invocations = [
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
                            tool=sarif_report.runs[0].tool,
                        ),
                    )
                ]
            except Exception as e:
                ASH_LOGGER.warning(
                    f"Failed to parse {self.__class__.__name__} results as SARIF: {str(e)}"
                )
                sarif_report = grype_results

            return sarif_report

        except Exception as e:
            # Check if there are useful error details
            raise ScannerError(f"Grype scan failed: {str(e)}")
