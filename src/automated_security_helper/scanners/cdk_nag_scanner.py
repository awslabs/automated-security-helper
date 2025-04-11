"""Module containing the CDK Nag security scanner implementation."""

from importlib.metadata import version
from datetime import datetime, timezone
from typing import Annotated, Literal
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from automated_security_helper.models.core import BaseScannerOptions, ExportFormat
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import (
    SCANNER_TYPES,
    Scanner,
    ScannerBaseConfig,
)
from automated_security_helper.models.data_interchange import (
    ReportMetadata,
)
from automated_security_helper.models.iac_scan import (
    IaCScanReport,
)
from automated_security_helper.models.scanner_plugin import (
    ScannerPlugin,
)
from automated_security_helper.models.core import ScannerPluginConfig
from automated_security_helper.utils.cdk_nag_wrapper import (
    run_cdk_nag_against_cfn_template,
)
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
    """CDK Nag IAC SAST scanner configuration."""

    name: Literal["cdknag"] = "cdknag"
    type: SCANNER_TYPES = "IAC"
    options: CdkNagScannerConfigOptions = CdkNagScannerConfigOptions()


class CDKNagScanner(ScannerPlugin, CdkNagScannerConfig):
    """CDK Nag security scanner implementation."""

    _default_config = ScannerPluginConfig(
        name="cdknag",
        enabled=True,
        type="SAST",
        command="cdk",
        args=[
            "synth",
            "--quiet",
        ],
        scan_path_arg="--context",
        scan_path_arg_position="after_args",
        invocation_mode="directory",
        output_stream="file",
        output_format=ExportFormat.CSV,
    )

    def configure(
        self,
        config: ScannerPluginConfig | None = None,
        options: CdkNagScannerConfigOptions | None = None,
    ) -> None:
        """Configure the scanner with provided settings."""
        super().configure(config=config, options=options)

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

    def scan(self, target: Path) -> IaCScanReport:
        """Scan the target and return findings.

        Args:
            target: Path to scan. Can be a file or directory.

        Returns:
            IaC scan report containing findings

        Raises:
            ScannerError: If scanning fails
        """
        try:
            self._pre_scan(target, self.options)
        except ScannerError as exc:
            raise exc
        target_path = Path(target)
        if not target_path.exists():
            raise ScannerError(f"Target {target} does not exist")

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
        all_findings = []
        failed_files = []

        for cfn_file in cfn_files:
            try:
                # Copy template to work dir with clean filename
                outdir = self.output_dir.joinpath("scanners").joinpath("cdknag")

                # Run CDK synthesis for this file
                self.options: CdkNagScannerConfigOptions
                nag_result = run_cdk_nag_against_cfn_template(
                    template_path=cfn_file,
                    nag_packs=[
                        item
                        for item in self.options.nag_packs.model_dump().keys()
                        if self.options.nag_packs.model_dump()[item]
                    ],
                    outdir=outdir,
                )
                if nag_result is None:
                    ASH_LOGGER.debug(f"Not a CloudFormation file: {cfn_file}")
                    failed_files.append(cfn_file)
                    continue

                for pack_name, findings in nag_result.items():
                    ASH_LOGGER.debug(f"Found {len(findings)} findings in {pack_name}")
                    all_findings.extend(findings)

            except Exception as e:
                ASH_LOGGER.warning(f"Error scanning {cfn_file}: {e}")
                failed_files.append((cfn_file, str(e)))

        return IaCScanReport(
            name="CDK Nag",
            iac_framework="CloudFormation",
            scanners_used=[
                Scanner(
                    name="cdk-nag",
                    description="CDK Nag - AWS Solutions Rules applied against rendered CloudFormation templates.",
                    type="IAC",
                    version=version("cdk_nag"),
                ),
            ],
            resources_checked={},
            scanner_name="cdk-nag",
            template_path=str(target_path),
            findings=all_findings,
            template_format="CloudFormation",
            metadata=ReportMetadata(
                report_id=f"ASH-CDK-Nag-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%s')}",
                tool_name="cdk-nag",
            ),
        )
