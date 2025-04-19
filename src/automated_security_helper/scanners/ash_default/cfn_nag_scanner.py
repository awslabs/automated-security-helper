"""Module containing the Checkov security scanner implementation."""

import logging
from pathlib import Path
import shutil
from typing import Annotated, List, Literal

from pydantic import Field
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
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

from detect_secrets import SecretsCollection


class CfnNagScannerConfigOptions(ScannerOptionsBase):
    pass


class CfnNagScannerConfig(ScannerPluginConfigBase):
    name: Literal["cfn-nag"] = "cfn-nag"
    enabled: bool = True
    options: Annotated[
        CfnNagScannerConfigOptions,
        Field(description="Configure CFN Nag scanner"),
    ] = CfnNagScannerConfigOptions()


class CfnNagScanner(ScannerPluginBase[CfnNagScannerConfig]):
    """CfnNagScanner implements SECRET scanning using CFN Nag."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = CfnNagScannerConfig()
        self.command = "cfn_nag_scan"
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
        tool_version = self._run_subprocess(
            command=[self.command, "--version"],
            results_dir=self.output_dir,
            stdout_preference="return",
            stderr_preference="return",
        )
        if isinstance(tool_version, dict):
            self.tool_version = tool_version.get("stdout", None)
        else:
            self.tool_version = None

        super().model_post_init(context)
        super().model_post_init(context)

        self._secrets_collection = SecretsCollection()

    def validate(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        return shutil.which(self.command) is not None

    def _process_config_options(self):
        # Add any additional config option parsing here, if necessary
        # For Python-based scanners, this typically won't be needed as we will access
        # the configuration directly from the self.config object.
        return super()._process_config_options()

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "temp"],
        global_ignore_paths: List[IgnorePathWithReason] = [],
        config: CfnNagScannerConfig | None = None,
    ) -> SarifReport:
        """Execute CFN Nag scan and return results.

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
            # Set up target path for scan results for target path
            normalized_target_dir_name = get_normalized_filename(
                str_to_normalize=target
            )
            target_results_dir = Path(self.results_dir).joinpath(
                normalized_target_dir_name
            )

            # Find all files to scan from the scan set
            scannable = scan_set(
                source=target,
                output=self.output_dir if target == self.source_dir else self.work_dir,
                # filter_pattern=r"\.(yaml|yml|json)$",
            )
            ASH_LOGGER.debug(
                f"Found {len(scannable)} files in scan set. Checking for possible CloudFormation templates"
            )
            scannable = [
                f.strip()
                for f in scannable
                if (
                    f.strip().endswith(".json")
                    or f.strip().endswith(".yaml")
                    or f.strip().endswith(".yml")
                )
            ]
            joined_files = "\n- ".join(scannable)
            ASH_LOGGER.debug(
                f"Found {len(scannable)} JSON/YAML files:\n- {joined_files}"
            )

            if len(scannable) == 0:
                self._scanner_log(
                    f"No JSON/YAML files found in {target_type} directory to scan. Exiting.",
                    target_type=target_type,
                    level=logging.WARNING,
                    append_to_stream="stderr",
                )
                return

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
                    cfn_model = get_model_from_template(template_path=cfn_file)
                except Exception as e:
                    ASH_LOGGER.debug(
                        f"Not a CloudFormation file: {cfn_file}. Exception: {e}"
                    )
                    continue
                if cfn_model is None:
                    ASH_LOGGER.debug(f"Not a CloudFormation file: {cfn_file}")
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

            self._post_scan(target=target)

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
            with open(sarif_output_file, "w") as fp:
                report_str = sarif_report.model_dump_json()
                fp.write(report_str)

            return sarif_report

        except Exception as e:
            # Check if there are useful error details
            raise ScannerError(f"{self.__class__.__name__} failed: {str(e)}")


if __name__ == "__main__":
    scanner = CfnNagScanner(
        source_dir=Path.cwd(),
        output_dir=Path.cwd().joinpath("ash_output"),
    )
    report = scanner.scan(target=scanner.source_dir)

    report_json = report.model_dump_json(
        indent=2,
        by_alias=True,
        exclude_unset=True,
    )
    with open(
        Path.cwd().joinpath("ash_output").joinpath("cfn_nag_results.sarif"), "w"
    ) as f:
        f.write(report_json)
