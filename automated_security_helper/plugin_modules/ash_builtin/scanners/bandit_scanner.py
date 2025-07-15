"""Module containing the Bandit security scanner implementation."""

import json
import logging
from pathlib import Path
from typing import Annotated, List, Literal

from pydantic import Field
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.core.constants import KNOWN_IGNORE_PATHS
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
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    SarifReport,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER


class BanditScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        Path | str | None,
        Field(
            description="Path to Bandit configuration file, relative to current source directory. Defaults to searching for `.bandit` (ini format), `bandit.yaml`, and `bandit.toml` in the root of the source directory if this is left empty.",
        ),
    ] = None
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
    tool_version: Annotated[
        str | None,
        Field(
            description="Specific version constraint for bandit installation (e.g., '>=1.7.0,<2.0.0')"
        ),
    ] = ">=1.7.0,<2.0.0"
    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation"),
    ] = 300


class BanditScannerConfig(ScannerPluginConfigBase):
    name: Literal["bandit"] = "bandit"
    enabled: bool = True
    options: Annotated[
        BanditScannerConfigOptions, Field(description="Configure Bandit scanner")
    ] = BanditScannerConfigOptions()


@ash_scanner_plugin
class BanditScanner(ScannerPluginBase[BanditScannerConfig]):
    """Implementation of a Python security scanner using Bandit.

    This scanner uses Bandit to perform static security analysis of Python code
    and returns results in a structured format using the StaticAnalysisReport model.
    """

    def model_post_init(self, context):
        if self.config is None:
            self.config = BanditScannerConfig()
        self.command = "bandit"
        self.tool_type = "SAST"
        self.use_uv_tool = True  # Enable UV tool execution

        # Set up explicit UV tool installation commands
        self._setup_uv_tool_install_commands()

        # Update tool version detection to work with explicit installation
        self.tool_version = self._get_uv_tool_version("bandit")
        self.description = "Bandit is a Python source code security analyzer."
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

    def _get_tool_version_constraint(self) -> str | None:
        """Get version constraint for bandit installation.

        Returns:
            Version constraint string for bandit (e.g., ">=1.7.0") or None for latest
        """
        # Use bandit-specific version constraint - bandit 1.7.0+ has better SARIF support
        return self.config.options.tool_version

    def _get_tool_package_extras(self) -> List[str] | None:
        """Get package extras for bandit installation.

        Returns:
            List of package extras needed for bandit (sarif and toml support)
        """
        # Bandit needs sarif extra for SARIF output format and toml extra for TOML config support
        return ["sarif", "toml"]

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

    def validate_plugin_dependencies(self) -> bool:
        """Enhanced validation with explicit tool installation.

        This method implements the enhanced validation workflow that:
        1. Checks if UV tool is available when required
        2. Attempts explicit tool installation if tool is not found
        3. Falls back to base class validation if installation fails
        4. Provides detailed logging for all validation steps

        Returns:
            True if validation passes, False otherwise
        """
        # First validate UV tool availability if required
        if not self._validate_uv_tool_availability():
            self._plugin_log(
                "UV tool validation failed - UV is not available but required",
                level=logging.ERROR,
            )
            return False

        # For UV tool-based scanners, attempt explicit installation if needed
        if self.use_uv_tool:
            # Check if tool is already installed
            if not self._is_uv_tool_installed():
                self._plugin_log(
                    "Bandit not found via UV tool, attempting explicit installation...",
                    level=logging.INFO,
                )

                # Attempt explicit tool installation with configured timeout
                timeout = self.config.options.install_timeout if self.config else 300
                retry_config = {
                    "max_retries": 3,
                    "base_delay": 1.0,
                    "max_delay": 60.0,
                }

                if self._install_uv_tool(timeout=timeout, retry_config=retry_config):
                    self._plugin_log(
                        "Successfully installed bandit via UV tool", level=logging.INFO
                    )
                    self.dependencies_satisfied = True
                    return True
                else:
                    self._plugin_log(
                        "UV tool installation failed for bandit, falling back to base validation",
                        level=logging.WARNING,
                    )
                    # Fall back to base class validation which includes pre-installed tool detection
                    return super().validate_plugin_dependencies()
            else:
                self._plugin_log(
                    "Bandit already installed via UV tool", level=logging.INFO
                )
                self.dependencies_satisfied = True
                return True

        # Fall back to base class validation for non-UV tool scenarios
        return super().validate_plugin_dependencies()

    def _process_config_options(self):
        # Bandit config path
        possible_config_paths = {
            f"{self.context.source_dir}/.bandit": [
                ToolExtraArg(key="--ini", value=f"{self.context.source_dir}/.bandit")
            ],
            f"{self.context.source_dir}/.ash/.bandit": [
                ToolExtraArg(
                    key="--ini", value=f"{self.context.source_dir}/.ash/.bandit"
                )
            ],
            f"{self.context.source_dir}/bandit.yaml": [
                ToolExtraArg(
                    key="--configfile", value=f"{self.context.source_dir}/bandit.yaml"
                )
            ],
            f"{self.context.source_dir}/.ash/bandit.yaml": [
                ToolExtraArg(
                    key="--configfile",
                    value=f"{self.context.source_dir}/.ash/bandit.yaml",
                )
            ],
            f"{self.context.source_dir}/bandit.toml": [
                ToolExtraArg(
                    key="--configfile", value=f"{self.context.source_dir}/bandit.toml"
                )
            ],
            f"{self.context.source_dir}/.ash/bandit.toml": [
                ToolExtraArg(
                    key="--configfile",
                    value=f"{self.context.source_dir}/.ash/bandit.toml",
                )
            ],
        }

        if self.config.options.config_file is not None:
            config_file_path = Path(self.config.options.config_file)
            if config_file_path.name == ".bandit":
                self.args.extra_args.append(
                    ToolExtraArg(key="--ini", value=config_file_path.as_posix())
                )
            else:
                self.args.extra_args.append(
                    ToolExtraArg(key="--configfile", value=config_file_path.as_posix())
                )
        else:
            for conf_path, extra_arg_list in possible_config_paths.items():
                if Path(conf_path).exists():
                    self.args.extra_args.extend(extra_arg_list)
                    break

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

        bandit_excludes = []
        for item in KNOWN_IGNORE_PATHS:
            bandit_excludes.append(str(Path(item).joinpath("**")))
            bandit_excludes.append(str(Path("**").joinpath(item, "**")))
        for item in self.config.options.excluded_paths:
            ASH_LOGGER.debug(
                f"Path '{item.path}' excluded from {self.config.name} scan for reason: {item.reason}"
            )
            bandit_excludes.append(str(Path("**").joinpath(item.path, "**")))

        self.args.extra_args.append(
            ToolExtraArg(key=f'--exclude="{",".join(bandit_excludes)}"', value=None)
        )

        return super()._process_config_options()

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] = [],
        config: BanditScannerConfig | None = None,
    ) -> SarifReport | bool:
        """Execute Bandit scan and return results.

        Args:
            target: Path to scan

        Returns:
            StaticAnalysisReport containing the scan findings and metadata

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
                level=15,
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

        target_results_dir = Path(self.results_dir).joinpath(target_type)
        results_file = target_results_dir.joinpath("bandit.sarif")
        Path(results_file).parent.mkdir(exist_ok=True, parents=True)
        self.config.options.excluded_paths.extend(global_ignore_paths)

        final_args = self._resolve_arguments(target=target, results_file=results_file)
        self._run_subprocess(
            command=final_args,
            results_dir=target_results_dir,
        )

        self._post_scan(
            target=target,
            target_type=target_type,
        )

        bandit_results = {}
        with open(results_file, mode="r", encoding="utf-8") as f:
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
                )
            ]
        except Exception as e:
            ASH_LOGGER.warning(f"Failed to parse Bandit results as SARIF: {str(e)}")
            sarif_report = bandit_results

        return sarif_report


if __name__ == "__main__":
    ASH_LOGGER.debug("Running Bandit via __main__")
    scanner = BanditScanner(
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(
                confidence_level="all",
                severity_threshold="ALL",
                ignore_nosec=False,
                excluded_paths=[],
                additional_formats=[],
            )
        )
    )
    report = scanner.scan(target=Path("."), target_type="source")

    if isinstance(report, SarifReport):
        print(
            report.model_dump_json(
                indent=2,
                by_alias=True,
                exclude_unset=True,
            )
        )
