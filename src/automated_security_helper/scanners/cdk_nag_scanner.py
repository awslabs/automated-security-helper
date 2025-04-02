"""Module containing the CDK Nag security scanner implementation."""

from datetime import datetime, timezone
import re
from typing import Dict, Any, List
import csv
import shutil
from pathlib import Path
import subprocess

from automated_security_helper.models.core import Location, Scanner
from automated_security_helper.models.iac_scan import (
    IaCReport,
    IaCFinding,
)
from automated_security_helper.scanners.abstract_scanner import (
    AbstractScanner,
    ScannerError,
)
from automated_security_helper.models.interfaces import IScanner
from automated_security_helper.models.config import ScannerConfig


class CDKNagScanner(AbstractScanner, IScanner):
    """CDK Nag security scanner implementation."""

    def __init__(self) -> None:
        """Initialize the CDK Nag scanner."""
        super().__init__()
        self.config: Dict[str, Any] = {}
        self.work_dir: Path = None

    def configure(self, config: ScannerConfig) -> None:
        """Configure the scanner with the provided configuration.

        Args:
            config: Scanner configuration
        """
        self.config = config

    def validate(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        # Check if cdk-nag-scan project exists
        cdk_project = Path("utils/cdk-nag-scan")
        if not cdk_project.exists() or not cdk_project.is_dir():
            raise ScannerError("CDK nag scanner requires cdk-nag-scan project")
        return True

    def scan(self, target: str) -> IaCReport:
        """Scan the target and return findings.

        Args:
            target: Path to scan

        Returns:
            IaC scan report containing findings
        """
        target_path = Path(target)
        if not target_path.exists():
            raise ScannerError(f"Target file {target} does not exist")

        # Set up working directory
        self.work_dir = target_path.parent.joinpath(
            f"{target_path.name}_cdk_nag_results"
        )
        if self.work_dir.exists():
            shutil.rmtree(self.work_dir)
        self.work_dir.mkdir()

        # Copy target to work dir
        shutil.copy2(target_path, self.work_dir)

        # Run CDK synthesis with the target file
        self._run_cdk_synthesis(target_path.name)

        # Parse and return findings
        findings = self._parse_findings()
        return IaCReport(
            scanner_name="cdk-nag",
            template_path=target,
            scan_timestamp=datetime.now(timezone.utc).strftime("%Y-%M-%d"),
            findings=findings,
            template_format="CloudFormation",
        )

    def _run_cdk_synthesis(self, target_filename: str) -> None:
        """Run CDK synthesis for the target file.

        Args:
            target_filename: Name of the target file to synthesize
        """
        cdk_project = Path("utils/cdk-nag-scan")
        # Copy the `cdk_project` directory recursively to the work directory
        shutil.copytree(cdk_project, self.work_dir, dirs_exist_ok=True)

        # Run CDK synthesis
        subprocess.run(
            [
                "npx",
                "cdk",
                "synth",
                "--context",
                f"fileName={target_filename}",
                "--quiet",
            ],
            cwd=cdk_project,
            check=True,
            capture_output=True,
        )

        # Move output files to work directory
        for report_file in cdk_project.glob("*NagReport.csv"):
            shutil.move(str(report_file), self.work_dir)

    def _parse_findings(self, specific_csv: str = None) -> List[IaCFinding]:
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
                    finding = IaCFinding(
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
