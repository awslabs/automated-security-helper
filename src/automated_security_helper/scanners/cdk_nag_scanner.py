"""Module containing the CDK Nag security scanner implementation."""

from importlib.metadata import version
from typing import Annotated, List, Literal
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from automated_security_helper.core.constants import ASH_DOCS_URL, ASH_REPO_URL
from automated_security_helper.base.scanner import ScannerBaseConfig
from automated_security_helper.base.options import BaseScannerOptions
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    Kind,
    Level,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPlugin,
)
from automated_security_helper.utils.cdk_nag_wrapper import (
    run_cdk_nag_against_cfn_template,
)
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.log import ASH_LOGGER


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


class CdkNagScannerConfigOptions(BaseScannerOptions):
    """CDK Nag IAC SAST scanner options."""

    nag_packs: Annotated[
        CdkNagPacks,
        Field(
            description="CDK Nag packs to enable",
        ),
    ] = CdkNagPacks()


class CdkNagScannerConfig(ScannerBaseConfig):
    name: Literal["cdk-nag"] = "cdk-nag"
    enabled: bool = True
    options: Annotated[
        CdkNagScannerConfigOptions, Field(description="Configure Bandit scanner")
    ] = CdkNagScannerConfigOptions()


class CdkNagScanner(ScannerPlugin[CdkNagScannerConfig]):
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

    def _map_severity_to_level(self, severity: str) -> Level:
        """Map severity to SARIF level."""
        if severity == "CRITICAL":
            return Level.error
        elif severity == "MEDIUM":
            return Level.warning
        return Level.note

    def _map_status_to_kind(self, status: str) -> Kind:
        """Map IaCVulnerability status to SARIF kind."""
        status_to_kind = {
            "OPEN": Kind.fail,
            "RISK_ACCEPTED": Kind.review,
            "INFORMATIONAL": Kind.informational,
        }
        return status_to_kind.get(status, Kind.fail)

    def scan(
        self,
        target: Path,
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
                options=self.config.options,
            )
        except ScannerError as exc:
            raise exc
        ASH_LOGGER.debug(f"self.config: {self.config}")
        ASH_LOGGER.debug(f"config: {config}")

        # Find all JSON/YAML files to scan from the scan set
        cfn_files = scan_set(
            source=self.source_dir,
            output=self.output_dir,
            # filter_pattern=r"\.(yaml|yml|json)$",
        )
        ASH_LOGGER.debug(
            f"Found {len(cfn_files)} files in scan set. Checking for possible CloudFormation templates"
        )
        cfn_files = [
            f.strip()
            for f in cfn_files
            if (
                f.strip().endswith(".json")
                or f.strip().endswith(".yaml")
                or f.strip().endswith(".yml")
            )
        ]
        joined_files = "\n- ".join(cfn_files)
        ASH_LOGGER.debug(
            f"Found {len(cfn_files)} possible CloudFormation templates:\n- {joined_files}"
        )

        if len(cfn_files) == 0:
            raise ScannerError(f"No CloudFormation templates found in {target}")

        # Process each template file
        failed_files = []
        target_rel_path = Path(target).absolute().relative_to(Path.cwd()).as_posix()

        outdir = self.output_dir.joinpath("scanners").joinpath("cdk-nag")
        sarif_results: List[Result] = []
        for cfn_file in cfn_files:
            try:
                # Run CDK synthesis for this file
                config_options: CdkNagScannerConfigOptions = (
                    CdkNagScannerConfigOptions.model_validate(self.config.options)
                )
                nag_packs = config_options.nag_packs
                if isinstance(config_options.nag_packs, CdkNagPacks):
                    nag_packs = nag_packs.model_dump()

                nag_result_dict = run_cdk_nag_against_cfn_template(
                    template_path=cfn_file,
                    nag_packs=[
                        item
                        for item, value in nag_packs.items()
                        if item in nag_packs and bool(value)
                    ],
                    outdir=outdir,
                )
                if nag_result_dict is None:
                    ASH_LOGGER.debug(f"Not a CloudFormation file: {cfn_file}")
                    failed_files.append(cfn_file)
                    continue

                nag_result = nag_result_dict.get("results", None)

                findings: List[Result]
                for pack_name, findings in nag_result.items():
                    ASH_LOGGER.debug(f"Found {len(findings)} findings in {pack_name}")
                    for finding in findings:
                        # sarif_result = Result(
                        #     ruleId=finding.rule_id,
                        #     level=self._map_severity_to_level(finding.severity),
                        #     kind=self._map_status_to_kind(finding.status),
                        #     message=Message(text=finding.description),
                        #     analysisTarget=ArtifactLocation(
                        #         uri=cfn_file_rel_path,
                        #     ),
                        #     locations=[
                        #         Location(
                        #             physicalLocation=PhysicalLocation(
                        #                 artifactLocation=ArtifactLocation(
                        #                     uri=finding.location.file_path
                        #                 ),
                        #                 region=Region(
                        #                     startLine=finding.location.start_line,
                        #                     endLine=finding.location.end_line,
                        #                     snippet=ArtifactContent(
                        #                         text=finding.location.snippet
                        #                     ),
                        #                 ),
                        #             )
                        #         )
                        #     ],
                        #     properties=PropertyBag(
                        #         tags=[
                        #             pack_name,
                        #         ],
                        #         resourceName=finding.resource_name,
                        #         resourceType=finding.resource_type,
                        #     ),
                        # )
                        sarif_results.append(finding)

            except Exception as e:
                if "could not determine a constructor for the tag" not in str(e):
                    ASH_LOGGER.warning(f"Error scanning {cfn_file}: {e}")
                failed_files.append((cfn_file, str(e)))

        self._post_scan(target=target)
        # Create SARIF report
        tool = Tool(
            driver=ToolComponent(
                name="ash-cdk-nag-wrapper",
                version=get_ash_version(),
                informationUri=ASH_DOCS_URL,
                downloadUri=ASH_REPO_URL,
            )
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
                                uri=self.source_dir.as_posix(),
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
            report_str = report.model_dump_json()
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
