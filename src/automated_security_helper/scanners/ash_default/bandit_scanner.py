"""Module containing the Bandit security scanner implementation."""

from importlib.metadata import version
import json
import logging
from pathlib import Path
import shutil
from typing import Annotated, Dict, List, Literal

from pydantic import Field
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ToolExtraArg,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginConfigBase,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER


class BanditScannerConfigOptions(ScannerOptionsBase):
    confidence_level: Annotated[
        Literal["all", "low", "medium", "high"],
        Field(description="Confidence level for Bandit findings"),
    ] = "all"
    ignore_nosec: Annotated[
        bool,
        Field(
            description="If True, do not skip lines with # nosec comments. Defaults to False."
        ),
    ] = False
    excluded_paths: Annotated[
        List[IgnorePathWithReason],
        Field(
            description="List of excluded paths and their corresponding reason to exclude from scanning"
        ),
    ] = []
    additional_formats: Annotated[
        List[
            Literal[
                "csv",
                "custom",
                "html",
                "json",
                "sarif",
                "txt",
                "xml",
                "yaml",
            ]
        ],
        Field(description="List of additional formats to output"),
    ] = []


class BanditScannerConfig(ScannerPluginConfigBase):
    name: Literal["bandit"] = "bandit"
    enabled: bool = True
    options: Annotated[
        BanditScannerConfigOptions, Field(description="Configure Bandit scanner")
    ] = BanditScannerConfigOptions()


class BanditScanner(ScannerPluginBase[BanditScannerConfig]):
    """Implementation of a Python security scanner using Bandit.

    This scanner uses Bandit to perform static security analysis of Python code
    and returns results in a structured format using the StaticAnalysisReport model.
    """

    def model_post_init(self, context):
        if self.config is None:
            self.config = BanditScannerConfig()
        self.command = "bandit"
        self.description = "Bandit is a Python source code security analyzer."
        self.tool_type = "SAST"
        self.tool_version = version("bandit")
        extra_args = [
            ToolExtraArg(
                key="--recursive",
                value=None,
            ),
        ]
        if ASH_LOGGER.level == logging.DEBUG:
            extra_args.append(
                ToolExtraArg(
                    key="--verbose",
                    value=None,
                )
            )
        self.args = ToolArgs(
            format_arg="--format",
            format_arg_value="sarif",
            output_arg="--output",
            scan_path_arg=None,
            extra_args=extra_args,
        )
        super().model_post_init(context)

    def configure(self, config: ScannerPluginBase | None = None):
        """Configure the scanner with the provided configuration.

        Args:
            config: Scanner configuration

        Raises:
            ScannerError: If configuration fails
        """
        try:
            if config is not None:
                self.config = config

        except Exception as e:
            raise ScannerError(
                f"Failed to configure {self.__class__.__name__}: {str(e)}"
            )

    def validate(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        # Bandit is a direct dependency of this Python package. If the Python import
        # reached this point then we know we're in a valid runtime for this scanner.
        return shutil.which(self.command) is not None

    def _process_config_options(self):
        # Bandit config path
        possible_config_paths: Dict[str, Dict[str, str | int | float | bool | None]] = {
            f"{self.context.source_dir}/.bandit": [
                ToolExtraArg(key="--ini", value=f"{self.context.source_dir}/.bandit")
            ],
            f"{self.context.source_dir}/bandit.yaml": [
                ToolExtraArg(
                    key="--configfile", value=f"{self.context.source_dir}/bandit.yaml"
                )
            ],
            f"{self.context.source_dir}/bandit.toml": [
                ToolExtraArg(
                    key="--configfile", value=f"{self.context.source_dir}/bandit.toml"
                )
            ],
        }

        for conf_path, extra_arg_list in possible_config_paths.items():
            if Path(conf_path).exists():
                self.args.extra_args.extend(extra_arg_list)
                break

        for item in ['--exclude="*venv/*"', '--exclude=".venv/*"']:
            self.args.extra_args.append(ToolExtraArg(key=item, value=None))
        self.args.extra_args.append(
            ToolExtraArg(
                key="--confidence-level", value=self.config.options.confidence_level
            )
        )
        self.args.extra_args.append(ToolExtraArg(key="--severity-level", value="all"))
        for fmt in self.config.options.additional_formats:
            self.args.extra_args.append(ToolExtraArg(key="--format", value=fmt))
        if self.config.options.ignore_nosec:
            self.args.extra_args.append(ToolExtraArg(key="--ignore-nosec", value=None))
        for item in self.config.options.excluded_paths:
            ASH_LOGGER.debug(
                f"Path '{item.path}' excluded from {self.config.name} scan for reason: {item.reason}"
            )
            self.args.extra_args.append(
                ToolExtraArg(
                    key=f'--exclude="{item.path}"',
                )
            )

        return super()._process_config_options()

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] = [],
        config: BanditScannerConfig | None = None,
    ) -> SarifReport:
        """Execute Bandit scan and return results.

        Args:
            target: Path to scan

        Returns:
            StaticAnalysisReport containing the scan findings and metadata

        Raises:
            ScannerError: If the scan fails or results cannot be parsed
        """
        try:
            try:
                self._pre_scan(
                    target=target,
                    target_type=target_type,
                    config=config,
                )
            except ScannerError as exc:
                raise exc

            target_results_dir = Path(self.results_dir).joinpath(target_type)
            results_file = target_results_dir.joinpath("bandit.sarif")
            Path(results_file).parent.mkdir(exist_ok=True, parents=True)
            self.config.options.excluded_paths.extend(global_ignore_paths)

            final_args = self._resolve_arguments(
                target=target, results_file=results_file
            )
            self._run_subprocess(
                command=final_args,
                results_dir=target_results_dir,
            )

            self._post_scan(
                target=target,
                target_type=target_type,
            )

            bandit_results = {}
            with open(results_file, "r") as f:
                bandit_results = json.load(f)
            try:
                sarif_report: SarifReport = SarifReport.model_validate(bandit_results)
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
                ASH_LOGGER.warning(f"Failed to parse Bandit results as SARIF: {str(e)}")
                sarif_report = bandit_results

            return sarif_report

        except Exception as e:
            # Check if there are useful error details
            raise ScannerError(f"Bandit scan failed: {str(e)}")


if __name__ == "__main__":
    ASH_LOGGER.debug("Running Bandit via __main__")
    scanner = BanditScanner(
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(
                confidence_level="all",
                severity_level="all",
                ignore_nosec=False,
                excluded_paths=[],
                additional_formats=[],
            )
        )
    )
    report = scanner.scan(target=Path("."), target_type="source")

    print(
        report.model_dump_json(
            indent=2,
            by_alias=True,
            exclude_unset=True,
        )
    )
