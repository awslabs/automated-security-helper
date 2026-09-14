"""Module containing the Checkov security scanner implementation."""

import logging
from pathlib import Path
from typing import Annotated, ClassVar, List, Literal

from pydantic import Field, model_validator
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_base import CustomCommand
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.core.constants import ASH_ASSETS_DIR
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
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
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.cfn_template_model import get_model_from_template
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.download_utils import current_bin_path
from automated_security_helper.utils.normalizers import get_normalized_filename
from automated_security_helper.utils.tool_downloads import CFN_NAG_GEM_VERSION


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

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    def model_post_init(self, context):
        if self.config is None:
            self.config = CfnNagScannerConfig()
        self.command = "cfn_nag_scan"
        self.tool_type = ScannerToolType.IAC
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
        """Set up the installation command for cfn-nag.

        cfn-nag is a Ruby gem, not a release binary, so it does not go through the
        pinned-digest download path the way grype, syft and trivy do. Forcing it
        into that path would mean pinning a digest for every gem in its dependency
        closure, which is what a lockfile is for.

        What that costs, stated plainly: this command pins cfn-nag itself exactly
        and lets RubyGems resolve the closure within cfn-nag's own constraints.
        The committed ``assets/Gemfile.lock`` pins the whole closure and remains
        the stricter artifact -- it is what the container image builds against.
        ``bundle install --gemfile`` was tried instead and rejected: that lock's
        PLATFORMS section lists only ``ruby``, so on Windows and macOS bundler
        needs the platform added before it will resolve, and an installer that
        works on one platform and errors on two is worse than one that pins
        slightly less.

        A Ruby interpreter is a prerequisite, not something ASH installs. Where
        ruby is absent this command fails with a nonzero exit and the installer
        reports it as a failure -- which is the point. Previously cfn-nag had no
        install command at all, so it stayed absent and the installer said
        everything succeeded.
        """
        # --user-install and --bindir together, and both are load-bearing.
        #
        # --user-install because a plain `gem install` writes to the interpreter's
        # GEM_HOME, which on a stock Linux runner is root-owned; without it the
        # install needs sudo and fails without it.
        #
        # --bindir because the binstub otherwise lands in whichever bin directory
        # that Ruby installation happens to use, and ASH looks on PATH and in
        # ASH_BIN_PATH -- not in a user gem bin. Pointing it at ASH_BIN_PATH makes
        # cfn-nag findable without depending on how the host arranges its Ruby.
        # Verified that a relocated binstub still activates the gem from the user
        # directory, since Gem.path includes it by default.
        command = CustomCommand(
            args=[
                "gem",
                "install",
                "cfn-nag",
                "-v",
                CFN_NAG_GEM_VERSION,
                "--no-document",
                "--user-install",
                "--bindir",
                str(current_bin_path()),
            ],
            shell=False,
        )
        for target_platform in ("linux", "darwin", "windows"):
            for arch in ("amd64", "arm64"):
                self.custom_install_commands.setdefault(target_platform, {})[arch] = [
                    command
                ]
        return self

    def _process_config_options(self):
        # Add any additional config option parsing here, if necessary
        # For Python-based scanners, this typically won't be needed as we will access
        # the configuration directly from the self.config object.
        return super()._process_config_options()

    def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
        """Abstract stub — CfnNag overrides scan() directly; this is unreachable."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
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
        if global_ignore_paths is None:
            global_ignore_paths = []
        tool_component = ToolComponent(
            name="cfn_nag",
            semanticVersion=self.tool_version,
            version=self.tool_version,
            informationUri="https://github.com/stelligent/cfn_nag",
        )
        sarif_report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=tool_component),
                    results=[],
                    invocations=[
                        Invocation(
                            commandLine=self.command,
                            executionSuccessful=True,
                            workingDirectory=ArtifactLocation(
                                uri=get_shortest_name(input=target)
                            ),
                        )
                    ],
                )
            ],
        )
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
            return sarif_report

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
                    level=logging.INFO,
                    append_to_stream="stderr",
                )
                self._post_scan(
                    target=target,
                    target_type=target_type,
                )
                return sarif_report

            # Process each template file
            failed_files = []
            sarif_tool = Tool(driver=tool_component)
            sarif_output_file = target_results_dir.joinpath("cfn_nag.sarif")
            sarif_output_file.parent.mkdir(exist_ok=True, parents=True)
            for cfn_file in scannable:
                try:
                    self._plugin_log(
                        f"Checking if file is CloudFormation: {cfn_file}",
                        target_type=target_type,
                        level=logging.DEBUG,
                    )
                    cfn_model = get_model_from_template(template_path=Path(cfn_file))
                    if cfn_model:
                        self._plugin_log(
                            f"File *is* CloudFormation: {cfn_file}",
                            target_type=target_type,
                            level=logging.DEBUG,
                        )
                    else:
                        self._plugin_log(
                            f"cfn_model is falsey, but no error was thrown: {cfn_file}",
                            target_type=target_type,
                            level=logging.DEBUG,
                        )
                except Exception as e:
                    self._plugin_log(
                        f"Not a CloudFormation file: {cfn_file}. Exception: {e}",
                        target_type=target_type,
                        level=logging.TRACE,
                    )
                    continue
                if cfn_model is None:
                    self._plugin_log(
                        f"Not a CloudFormation file: {cfn_file}",
                        target_type=target_type,
                        level=logging.TRACE,
                    )
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
                    timeout=self._effective_scan_timeout(),
                )
                try:
                    stdout = proc_resp.get("stdout", "")
                    if not stdout or not stdout.strip():
                        ASH_LOGGER.debug(
                            f"CFN Nag returned no stdout for {cfn_file} "
                            f"(exit code {proc_resp.get('returncode', '?')})"
                        )
                        failed_files.append((cfn_file, "empty stdout"))
                        continue
                    file_sarif = SarifReport.model_validate_json(json_data=stdout)
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
                executionSuccessful=(self.exit_code == 0 or self.exit_code == 1),
                exitCode=self.exit_code,
                exitCodeDescription="\n".join(self.errors),
                workingDirectory=ArtifactLocation(
                    uri=get_shortest_name(input=target),
                ),
                properties=PropertyBag(
                    tool=sarif_tool,
                ),
            )
            if sarif_report.runs:
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
