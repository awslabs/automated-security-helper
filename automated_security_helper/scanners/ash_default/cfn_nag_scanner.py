"""Module containing the Checkov security scanner implementation."""

import logging
from pathlib import Path
from typing import Annotated, List, Literal

from pydantic import Field, model_validator
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.core.constants import ASH_ASSETS_DIR
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ToolArgs,
    ToolExtraArg,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    PropertyBag,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.cfn_template_model import get_model_from_template
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.normalizers import get_normalized_filename
from automated_security_helper.utils.subprocess_utils import find_executable


class CfnNagScannerConfigOptions(ScannerOptionsBase):
    pass


class CfnNagScannerConfig(ScannerPluginConfigBase):
    name: Literal["cfn-nag"] = "cfn-nag"
    enabled: bool = True
    options: Annotated[
        CfnNagScannerConfigOptions,
        Field(description="Configure CFN Nag scanner"),
    ] = CfnNagScannerConfigOptions()


@ash_scanner_plugin
class CfnNagScanner(ScannerPluginBase[CfnNagScannerConfig]):
    """CfnNagScanner implements SECRET scanning using CFN Nag."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = CfnNagScannerConfig()
        self.command = "cfn_nag_scan"
        self.tool_type = "IAC"
        self.rule_directory = ASH_ASSETS_DIR.joinpath("appsec_cfn_rules")
        extra_args = [
            ToolExtraArg(
                key="--print-suppression",
                value=None,
            ),
            ToolExtraArg(
                key="--ignore-fatal",
                value=None,
            ),
            ToolExtraArg(
                key="--rule-directory",
                value=self.rule_directory.as_posix(),
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
            format_arg="--output-format",
            format_arg_value="sarif",
            scan_path_arg="--input-path",
            extra_args=extra_args,
        )

        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "CfnNagScanner":
        """Set up custom installation commands for opengrep."""
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
        #     tool_version = self._run_subprocess(
        #         command=[self.command, "--version"],
        #         results_dir=self.context.output_dir,
        #         stdout_preference="return",
        #         stderr_preference="return",
        #     )
        #     if isinstance(tool_version, dict):
        #         self.tool_version = tool_version.get("stdout", "").strip()
        #     else:
        #         self.tool_version = None

        #     return self.tool_version is not None
        # except Exception as e:
        #     self._scanner_log(
        #         f"Error validating {self.config.name} scanner: {e}", level=logging.ERROR
        #     )
        #     return False

    def _process_config_options(self):
        # Add any additional config option parsing here, if necessary
        # For Python-based scanners, this typically won't be needed as we will access
        # the configuration directly from the self.config object.
        return super()._process_config_options()

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] = [],
        config: CfnNagScannerConfig | None = None,
    ) -> SarifReport | bool:
        """Execute CFN Nag scan and return results.

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

            orig_scannable = (
                [item for item in self.context.work_dir.glob("**/*.*")]
                if target_type == "converted"
                else scan_set(
                    source=self.context.source_dir,
                    output=self.context.output_dir,
                    # filter_pattern=r"\.(yaml|yml|json)$",
                )
            )
            ASH_LOGGER.debug(
                f"Found {len(orig_scannable)} files in scan set. Checking for possible CloudFormation templates"
            )

            scannable = []
            for f in orig_scannable:
                pf = Path(f)
                if (
                    pf.name.endswith(".json")
                    or pf.name.endswith(".yaml")
                    or pf.name.endswith(".yml")
                ):
                    scannable.append(pf.as_posix())
            joined_files = "\n- ".join(scannable)
            ASH_LOGGER.debug(
                f"Found {len(scannable)} JSON/YAML files:\n- {joined_files}"
            )

            if len(scannable) == 0:
                self._plugin_log(
                    f"No JSON/YAML files found in {target_type} directory to scan. Exiting.",
                    target_type=target_type,
                    level=logging.WARNING,
                    append_to_stream="stderr",
                )
                self._post_scan(
                    target=target,
                    target_type=target_type,
                )
                return True

            # Process each template file
            failed_files = []
            sarif_tool = Tool(
                driver=ToolComponent(
                    name="cfn-nag",
                    fullName="stelligent/cfn_nag",
                    version=self.tool_version,
                    informationUri="https://github.com/stelligent/cfn_nag",
                    rules=[],
                )
            )
            sarif_report = None
            sarif_output_file = target_results_dir.joinpath("cfn_nag.sarif")
            sarif_output_file.parent.mkdir(exist_ok=True, parents=True)
            for cfn_file in scannable:
                try:
                    cfn_model = get_model_from_template(template_path=Path(cfn_file))
                except Exception as e:
                    ASH_LOGGER.trace(
                        f"Not a CloudFormation file: {cfn_file}. Exception: {e}"
                    )
                    continue
                if cfn_model is None:
                    ASH_LOGGER.trace(f"Not a CloudFormation file: {cfn_file}")
                    continue
                normalized_filename = get_normalized_filename(str_to_normalize=cfn_file)
                results_file_dir = target_results_dir.joinpath(normalized_filename)
                results_file_dir.mkdir(exist_ok=True, parents=True)
                final_args = self._resolve_arguments(
                    target=cfn_file, results_file=results_file_dir
                )
                proc_resp = self._run_subprocess(
                    command=final_args,
                    results_dir=results_file_dir,
                    stdout_preference="both",
                    stderr_preference="both",
                )
                try:
                    file_sarif = SarifReport.model_validate_json(
                        json_data=proc_resp["stdout"]
                    )
                    if sarif_report is None and file_sarif is not None:
                        sarif_report = file_sarif
                    elif file_sarif is not None:
                        sarif_report.merge_sarif_report(
                            sarif_report=file_sarif,
                            include_invocation=False,
                            include_driver=False,
                            # CFN Nag includes the full rule list regardless if there were
                            # results matching the rule ID.
                            # Since `include_driver=True`, it will include the rule list
                            # when it attaches the initial driver.
                            include_rules=False,
                        )
                except Exception as e:
                    ASH_LOGGER.warning(
                        f"Failed to parse CFN Nag results as SARIF: {str(e)}"
                    )
                    failed_files.append((cfn_file, str(e)))
                    continue

            self._post_scan(
                target=target,
                target_type=target_type,
            )

            sarif_invocation: Invocation = Invocation(
                commandLine="ash-CFN Nag-scanner",
                arguments=[
                    "--target",
                    get_shortest_name(input=target),
                    "--scanner",
                ],
                startTimeUtc=self.start_time,
                endTimeUtc=self.end_time,
                executionSuccessful=True,
                exitCode=self.exit_code,
                exitCodeDescription="\n".join(self.errors),
                workingDirectory=ArtifactLocation(
                    uri=get_shortest_name(input=target),
                ),
                properties=PropertyBag(
                    tool=sarif_tool,
                ),
            )
            sarif_report.runs[0].invocations = [sarif_invocation]
            with open(sarif_output_file, mode="w", encoding="utf-8") as fp:
                report_str = sarif_report.model_dump_json(
                    exclude_none=True,
                    exclude_unset=True,
                )
                fp.write(report_str)

            return sarif_report

        except Exception as e:
            # Check if there are useful error details
            raise ScannerError(f"{self.__class__.__name__} failed: {str(e)}")


if __name__ == "__main__":
    scanner = CfnNagScanner(
        source_dir=Path.cwd(),
        output_dir=Path.cwd().joinpath(".ash", "ash_output"),
    )
    report = scanner.scan(target=scanner.source_dir)

    report_json = report.model_dump_json(
        indent=2,
        by_alias=True,
        exclude_unset=True,
    )
    with open(
        Path.cwd().joinpath(".ash", "ash_output").joinpath("cfn_nag_results.sarif"), "w"
    ) as f:
        f.write(report_json)
