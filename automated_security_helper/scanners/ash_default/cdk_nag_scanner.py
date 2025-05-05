"""Module containing the CDK Nag security scanner implementation."""

from importlib.metadata import version
import logging
from typing import Annotated, List, Literal
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from automated_security_helper.core.constants import ASH_DOCS_URL, ASH_REPO_URL
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    MultiformatMessageString,
    PropertyBag,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.utils.cdk_nag_wrapper import (
    run_cdk_nag_against_cfn_template,
)
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.models.core import IgnorePathWithReason


class CdkNagPacks(BaseModel):
    model_config = ConfigDict(extra="allow")

    AwsSolutionsChecks: Annotated[
        bool,
        Field(description="Runs the AwsSolutionsChecks NagPack included with CDK Nag."),
    ] = True
    HIPAASecurityChecks: Annotated[
        bool,
        Field(
            description="Runs the HIPAASecurityChecks NagPack included with CDK Nag."
        ),
    ] = False
    NIST80053R4Checks: Annotated[
        bool,
        Field(description="Runs the NIST80053R4Checks NagPack included with CDK Nag."),
    ] = False
    NIST80053R5Checks: Annotated[
        bool,
        Field(description="Runs the NIST80053R5Checks NagPack included with CDK Nag."),
    ] = False
    PCIDSS321Checks: Annotated[
        bool,
        Field(description="Runs the PCIDSS321Checks NagPack included with CDK Nag."),
    ] = False


class CdkNagScannerConfigOptions(ScannerOptionsBase):
    """CDK Nag IAC SAST scanner options."""

    nag_packs: Annotated[
        CdkNagPacks,
        Field(
            description="CDK Nag packs to enable",
        ),
    ] = CdkNagPacks()


class CdkNagScannerConfig(ScannerPluginConfigBase):
    name: Literal["cdk-nag"] = "cdk-nag"
    enabled: bool = True
    options: Annotated[
        CdkNagScannerConfigOptions, Field(description="Configure Bandit scanner")
    ] = CdkNagScannerConfigOptions()


@ash_scanner_plugin
class CdkNagScanner(ScannerPluginBase[CdkNagScannerConfig]):
    """CDK Nag security scanner, custom CDK-CLI-less implementation."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = CdkNagScannerConfig()
        self.command = "python"
        self.description = "CDK Nag is a security scanner for AWS CloudFormation templates that applies industry standard checks against AWS infrastructure-as-code."
        self.tool_type = "IAC"
        self.tool_version = version("cdk_nag")
        return super().model_post_init(context)

    def validate(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        # CDK Nag scanner is built into this Python module, if the Python import got
        # this far then we know we're in a valid runtime for this scanner.
        return True

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] = [],
        config: CdkNagScannerConfig | None = None,
    ) -> SarifReport:
        """Scan the target and return findings.

        Args:
            target: Path to scan. Can be a file or directory.

        Returns:
            IaC scan report containing findings

        Raises:
            ScannerError: If scanning fails
        """
        try:
            self._pre_scan(
                target=target,
                target_type=target_type,
                config=config,
            )
        except ScannerError as exc:
            raise exc

        # Find all files to scan from the scan set
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
        ASH_LOGGER.debug(f"Found {len(scannable)} JSON/YAML files:\n- {joined_files}")

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
        target_rel_path = get_shortest_name(input=target)

        outdir = self.results_dir.joinpath(target_type)
        sarif_results: List[Result] = []
        for cfn_file in scannable:
            try:
                # Run CDK synthesis for this file
                config_options: CdkNagScannerConfigOptions = (
                    CdkNagScannerConfigOptions.model_validate(self.config.options)
                )
                nag_packs = config_options.nag_packs
                if isinstance(config_options.nag_packs, CdkNagPacks):
                    nag_packs = nag_packs.model_dump(by_alias=True)

                nag_result_dict = run_cdk_nag_against_cfn_template(
                    template_path=Path(cfn_file),
                    nag_packs=[
                        item
                        for item, value in nag_packs.items()
                        if item in nag_packs and bool(value)
                    ],
                    outdir=outdir,
                )
                if nag_result_dict is None:
                    ASH_LOGGER.trace(f"Not a CloudFormation file: {cfn_file}")
                    failed_files.append(cfn_file)
                    continue

                for pack, findings in nag_result_dict.results.items():
                    ASH_LOGGER.debug(
                        f"Found {len(findings)} findings for {pack} on template {cfn_file}"
                    )
                    sarif_results.extend(findings)
            except Exception as e:
                if "could not determine a constructor for the tag" not in str(e):
                    ASH_LOGGER.warning(f"Error scanning {cfn_file}: {e}")
                failed_files.append((cfn_file, str(e)))

        self._post_scan(
            target=target,
            target_type=target_type,
        )
        # Create SARIF report
        rules: List[ReportingDescriptor] = []
        rule_map = {}
        for result in sarif_results:
            if result.ruleId in rule_map:
                continue
            rule_map[result.ruleId] = result

            finding_props = result.properties.model_extra.get("cdk_nag_finding", {})

            rules.append(
                ReportingDescriptor(
                    id=result.ruleId,
                    shortDescription=MultiformatMessageString(
                        text=result.message.root.text,
                    ),
                    fullDescription=MultiformatMessageString(
                        text=result.message.root.text,
                        markdown=result.message.root.markdown,
                    ),
                    helpUri=f"https://github.com/cdklabs/cdk-nag/blob/main/RULES.md#{str(finding_props.get('rule_level', 'rule')).lower()}s",
                    properties=PropertyBag(
                        rule_level=finding_props.get("rule_level", "unknown"),
                        rule_info=finding_props.get("rule_info", "unknown"),
                        tags=finding_props.get("tags", []),
                    ),
                    # help,
                )
            )
        tool = Tool(
            driver=ToolComponent(
                name="ash-cdk-nag-wrapper",
                fullName="awslabs/automated-security-helper",
                organization="Amazon Web Services",
                version=get_ash_version(),
                informationUri=ASH_DOCS_URL,
                downloadUri=ASH_REPO_URL,
                rules=rules,
            ),
        )
        report = SarifReport(
            runs=[
                Run(
                    tool=tool,
                    results=sarif_results,
                    invocations=[
                        Invocation(
                            commandLine="ash",
                            arguments=[
                                "--scanner",
                                "cdk-nag",
                                "--source-dir",
                                target_rel_path,
                            ],
                            startTimeUtc=self.start_time,
                            endTimeUtc=self.end_time,
                            executionSuccessful=True,
                            exitCode=0,
                            exitCodeDescription="\n".join(self.errors),
                            workingDirectory=ArtifactLocation(
                                uri=get_shortest_name(input=self.context.source_dir),
                            ),
                            properties=PropertyBag(
                                tool=tool,
                            ),
                        ),
                    ],
                )
            ]
        )
        with open(outdir.joinpath("ash-cdk-nag.sarif"), "w") as fp:
            report_str = report.model_dump_json(
                exclude_none=True,
                exclude_unset=True,
            )
            fp.write(report_str)

        return report

        # return IaCScanReport(
        #     name="CDK Nag",
        #     iac_framework="CloudFormation",
        #     scanners_used=[
        #         Scanner(
        #             name="cdk-nag",
        #             description="CDK Nag - AWS Solutions Rules applied against rendered CloudFormation templates.",
        #             type="IAC",
        #             version=version("cdk_nag"),
        #         ),
        #     ],
        #     resources_checked={},
        #     scanner_name="cdk-nag",
        #     template_path=str(target_path),
        #     findings=all_findings,
        #     template_format="CloudFormation",
        #     metadata=ReportMetadata(
        #         report_id=f"ASH-CDK-Nag-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%s')}",
        #         tool_name="cdk-nag",
        #     ),
        # )


if __name__ == "__main__":
    ASH_LOGGER.debug("Running cdk-nag via __main__")
    scanner = CdkNagScanner(
        source_dir=Path.cwd(),
        output_dir=Path.cwd().joinpath(".ash", "ash_output"),
        config=CdkNagScannerConfig(
            options=CdkNagScannerConfigOptions(
                nag_packs=CdkNagPacks(
                    AwsSolutionsChecks=True,
                    HIPAASecurityChecks=True,
                    NIST80053R4Checks=True,
                    NIST80053R5Checks=True,
                    PCIDSS321Checks=True,
                )
            )
        ),
    )
    report = scanner.scan(target=scanner.source_dir)

    print(
        report.model_dump_json(
            indent=2,
            by_alias=True,
            exclude_unset=True,
        )
    )
