"""Module containing the CDK Nag security scanner implementation."""

from importlib.metadata import version
import logging
from datetime import datetime, timezone
import re
from typing import Dict, Any, List, Optional
import csv
from pathlib import Path

from automated_security_helper.exceptions import ScannerError
from automated_security_helper.models.core import Location, Scanner
from automated_security_helper.models.data_interchange import (
    ExportFormat,
    ReportMetadata,
)
from automated_security_helper.models.iac_scan import (
    IaCScanReport,
    IaCVulnerability,
)
from automated_security_helper.scanners.scanner_plugin import (
    ScannerPlugin,
)
from automated_security_helper.config.config import ScannerPluginConfig
from automated_security_helper.utils.cdk_nag_wrapper import (
    run_cdk_nag_against_cfn_template,
)
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.log import ASH_LOGGER


class CDKNagScanner(ScannerPlugin):
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

    def __init__(
        self,
        source_dir: Path,
        output_dir: Path,
        logger: Optional[logging.Logger] = logging.Logger(__name__),
    ) -> None:
        super().__init__(source_dir=source_dir, output_dir=output_dir, logger=logger)

    def configure(
        self,
        config: ScannerPluginConfig = None,
    ) -> None:
        """Configure the scanner with provided settings."""
        super().configure(config)

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
        self, target: str, options: Optional[Dict[str, Any]] = None
    ) -> IaCScanReport:
        """Scan the target and return findings.

        Args:
            target: Path to scan. Can be a file or directory.

        Returns:
            IaC scan report containing findings

        Raises:
            ScannerError: If scanning fails
        """
        try:
            self._pre_scan(target, options)
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
                nag_result = run_cdk_nag_against_cfn_template(
                    template_path=cfn_file,
                    nag_packs=[
                        "AwsSolutionsChecks",
                        # "HIPAASecurityChecks",
                        # "NIST80053R4Checks",
                        # "NIST80053R5Checks",
                        # "PCIDSS321Checks",
                    ],
                    outdir=outdir,
                )
                if nag_result is None:
                    ASH_LOGGER.debug(f"Not a CloudFormation file: {cfn_file}")
                    failed_files.append(cfn_file)
                    continue

                # Add findings from this file
                # file_findings = self._parse_findings()
                for pack_name, findings in nag_result.items():
                    ASH_LOGGER.debug(f"Found {len(findings)} findings in {pack_name}")
                    all_findings.extend(findings)
            except Exception as e:
                failed_files.append((cfn_file, str(e)))

        # If any scans failed, include in report
        # if failed_files:
        #     for f in failed_files:
        #         all_findings.append(
        #             IaCVulnerability(
        #                 id=re.sub(pattern=r"\W+", repl="-", string=f[0].as_posix()),
        #                 severity="CRITICAL",
        #                 scanner=Scanner(
        #                     name="cdk-nag",
        #                     type="IAC",
        #                     rule_id="CDK_NAG_SCAN_ERROR",
        #                 ),
        #                 resource_name=f[0].as_posix(),
        #                 rule_id="CDK_NAG_SCAN_ERROR",
        #                 title="Scan failures occurred",
        #                 level="ERROR",
        #                 description=f"Failed to scan file {f[0]}: {f[1]}",
        #                 location=Location(
        #                     file_path=f[0].as_posix(),
        #                 ),
        #             )
        #         )

        return IaCScanReport(
            name="CDK Nag",
            iac_framework="CloudFormation",
            scanners_used=[{"cdk_nag": version("cdk_nag")}],
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

    def _parse_findings(self, specific_csv: str = None) -> List[IaCVulnerability]:
        """Parse CDK nag findings from output CSV files.

        Returns:
            List of IaC findings
        """
        findings = []
        if specific_csv:
            files = [specific_csv]
        else:
            files = self.work_dir.glob("*NagReport.csv")
        for csv_file in files:
            with open(csv_file, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    finding_id = re.sub(
                        pattern=r"\W+",
                        repl="-",
                        string=row.get("Rule ID", "UnknownRule"),
                        flags=re.IGNORECASE,
                    )
                    finding = IaCVulnerability(
                        id=finding_id,
                        title=row.get("Rule ID", "Unknown Rule"),
                        description=row.get("Rule Info", ""),
                        resource_id=row.get("Resource ID", ""),
                        rule_id=row.get("Rule ID", ""),
                        resource_name=row.get("Resource ID", "NA").split("/")[-1],
                        compliance_frameworks=[
                            "CDKNag.AwsSolutionsChecks",
                        ],
                        location=Location(
                            file_path=row.get("Resource ID", csv_file),
                        ),
                        scanner=Scanner(
                            name="cdk-nag",
                            description="CDK Nag - AWS Solutions Rules applied against rendered CloudFormation templates.",
                            rule_id=row.get("Rule ID", ""),
                            type="IAC",
                            # version=   # # TODO implement tool version cataloguing
                        ),
                        severity=(
                            "CRITICAL"
                            if (
                                row.get("Compliance", "Non-Compliant")
                                == "Non-Compliant"
                                and row.get("Rule Level", "Error") == "Error"
                            )
                            else (
                                "MEDIUM"
                                if (
                                    row.get("Compliance", "Non-Compliant")
                                    == "Non-Compliant"
                                    and row.get("Rule Level", "Error") != "Error"
                                )
                                else "INFO"
                            )
                        ),
                    )
                    findings.append(finding)
        return findings
