"""Module containing the CDK Nag security scanner implementation."""

import os
from datetime import datetime, timezone
import re
from typing import Dict, Any, List, Optional
import csv
import shutil
from pathlib import Path
import subprocess

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
    ScannerError,
)
from automated_security_helper.config.config import ScannerPluginConfig


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

    def __init__(self) -> None:
        super().__init__()
        self._config = self._default_config

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
        try:
            # Check if CDK is installed and available
            subprocess.run(
                ["npx", "cdk", "--version"], check=True, capture_output=True, text=True
            )
            # Check if cdk-nag-scan project exists
            cdk_project = Path("utils/cdk-nag-scan")
            if not cdk_project.exists() or not cdk_project.is_dir():
                raise ScannerError("CDK nag scanner requires cdk-nag-scan project")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            raise ScannerError(
                "CDK dependencies not found. Please ensure CDK is installed."
            ) from e

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

        # Find all CFN files to scan
        cfn_files = []
        if target_path.is_file():
            cfn_files = [target_path]
        else:
            # If directory, find all yaml/yml files (potential CloudFormation templates)
            cfn_files = list(target_path.glob("**/*.y*ml"))

        if not cfn_files:
            raise ScannerError(f"No CloudFormation templates found in {target}")

        # Set up scanner directory from environment or default
        scanner_dir = Path(os.getenv("SCANNER_DIR", target_path.parent))
        if not scanner_dir.exists():
            scanner_dir.mkdir(parents=True)

        # Set up working directory with unique name based on timestamp
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.work_dir = scanner_dir.joinpath(f"cdk_nag_results_{timestamp}")
        if self.work_dir.exists():
            shutil.rmtree(str(self.work_dir))
        self.work_dir.mkdir(exist_ok=True)

        # Clean up any existing CDK work directory using env var if set
        cdk_work_dir = Path(os.getenv("CDK_WORK_DIR", str(scanner_dir.joinpath("cdk"))))
        if cdk_work_dir.exists():
            shutil.rmtree(str(cdk_work_dir))

        # Process each template file
        all_findings = []
        failed_files = []

        for cfn_file in cfn_files:
            try:
                # Copy template to work dir with clean filename
                clean_name = str(cfn_file).replace("/", ".").lstrip(".")
                work_file = self.work_dir.joinpath(clean_name)
                shutil.copy2(cfn_file, work_file)

                # Run CDK synthesis for this file
                self._run_cdk_synthesis(clean_name, scanner_dir)

                # Add findings from this file
                file_findings = self._parse_findings()
                all_findings.extend(file_findings)
            except Exception as e:
                failed_files.append((cfn_file, str(e)))

        # Clean up CDK work directory after synthesis
        if cdk_work_dir.exists():
            shutil.rmtree(str(cdk_work_dir))

        # If any scans failed, include in report
        if failed_files:
            for f in failed_files:
                all_findings.append(
                    IaCVulnerability(
                        id=re.sub(pattern=r"\W+", repl="-", string=f[0].as_posix()),
                        severity="CRITICAL",
                        scanner=Scanner(
                            name="cdk-nag",
                            type="IAC",
                            rule_id="CDK_NAG_SCAN_ERROR",
                        ),
                        resource_name=f[0].as_posix(),
                        rule_id="CDK_NAG_SCAN_ERROR",
                        title="Scan failures occurred",
                        level="ERROR",
                        description=f"Failed to scan file {f[0]}: {f[1]}",
                        location=Location(
                            file_path=f[0].as_posix(),
                        ),
                    )
                )

        return IaCScanReport(
            name="CDK Nag",
            iac_framework="CDK",
            scanners_used=[
                {"cdk": "1.0.0"}  # TODO - Extract tool version on validate step
            ],
            resources_checked={},
            scanner_name="cdk-nag",
            template_path=str(target_path),
            findings=all_findings,
            template_format="CloudFormation",
            metadata=ReportMetadata(
                report_id=timestamp,
                tool_name="cdk-nag",
            ),
        )

    def _run_cdk_synthesis(self, target_filename: str, scanner_dir: Path) -> None:
        """Run CDK synthesis for the target file.

        Args:
            target_filename: Name of the target file to synthesize

        Raises:
            ScannerError: If CDK project setup or synthesis fails
        """
        cdk_project = Path("utils/cdk-nag-scan")
        if not cdk_project.exists() or not cdk_project.is_dir():
            raise ScannerError("CDK nag scanner template project not found")

        try:
            # Copy the template project to scanner directory like the shell script
            template_dir = scanner_dir.joinpath("cdk-nag-scan")
            if template_dir.exists():
                shutil.rmtree(str(template_dir))
            shutil.copytree(cdk_project, template_dir)

            # Copy template project contents to work directory
            shutil.copytree(template_dir, self.work_dir, dirs_exist_ok=True)

            # Clean up template directory after copying
            shutil.rmtree(str(template_dir))

            # Run CDK synthesis in the work directory
            subprocess.run(
                [
                    "npx",
                    "cdk",
                    "synth",
                    "--context",
                    f"fileName={target_filename}",
                    "--quiet",
                ],
                cwd=self.work_dir,  # Run in work_dir instead of cdk_project
                check=True,
                capture_output=True,
                text=True,
            )

            # Process report files from the work directory
            reports = list(self.work_dir.glob("*NagReport.csv"))
            if not reports:
                raise ScannerError("No CDK nag reports generated during synthesis")

        except subprocess.CalledProcessError as e:
            raise ScannerError(f"CDK synthesis failed: {e.stderr}") from e
        except (OSError, IOError) as e:
            raise ScannerError(
                f"Failed to process CDK nag scanner files: {str(e)}"
            ) from e

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
