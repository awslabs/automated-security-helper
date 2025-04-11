"""Module containing the Checkov security scanner implementation."""

from importlib.metadata import version
import json
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Dict, List, Literal

from pydantic import Field
from automated_security_helper.models.core import (
    SCANNER_TYPES,
    BaseScannerOptions,
    Location,
    ScanStatistics,
    Scanner,
    ScannerBaseConfig,
)
from automated_security_helper.models.core import ExportFormat
from automated_security_helper.models.iac_scan import (
    IaCScanReport,
    IaCVulnerability,
    CheckResultType,
)
from automated_security_helper.models.scanner_plugin import (
    ScannerPlugin,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import ScannerPluginConfig
from automated_security_helper.models.static_analysis import (
    StaticAnalysisReport,
)


class CheckovScannerConfigOptions(BaseScannerOptions):
    pass


class CheckovScannerConfig(ScannerBaseConfig):
    """Checkov SAST scanner configuration."""

    name: Literal["checkov"] = "checkov"
    type: SCANNER_TYPES = "IAC"
    options: Annotated[
        CheckovScannerConfigOptions, Field(description="Configure Checkov scanner")
    ] = CheckovScannerConfigOptions()


class CheckovScanner(ScannerPlugin, CheckovScannerConfig):
    """CheckovScanner implements IaC scanning using Checkov."""

    _default_config = ScannerPluginConfig(
        name="checkov",
        type="IAC",
        command="checkov",
        output_arg="-o",
        scan_path_arg="-r",
        scan_path_arg_position="before_args",
        format_arg="-f",
        format_arg_value="json",
        format_arg_position="before_args",
        invocation_mode="directory",
        output_stream="file",
        enabled=True,
        output_format="json",
    )
    _output_format: ExportFormat = ExportFormat.JSON
    tool_version: str = version("checkov")

    def configure(
        self,
        config: ScannerPluginConfig | None = None,
        options: CheckovScannerConfigOptions | None = None,
    ) -> None:
        """Configure the scanner with provided settings."""
        super().configure(config=config, options=options)

    def _create_finding_from_check(
        self, result: Dict[str, Any], check_type: CheckResultType
    ) -> IaCVulnerability:
        """Create an IaCVulnerability from a check result."""
        finding_id = "/".join(
            [
                item
                for item in [
                    result.get("check_id", None),
                    result.get("repo_file_path", None),
                    result.get("resource", None),
                    result.get("resource_address", None),
                ]
                if item
            ]
        )

        # Extract location information from the result
        file_path = result.get("file_path", "")
        file_line_range = result.get("file_line_range", [0, 0])
        location = Location(
            path=file_path,
            start_line=file_line_range[0] if file_line_range else 0,
            end_line=file_line_range[1] if file_line_range else 0,
        )

        return IaCVulnerability(
            id=finding_id,
            title=result.get("check_name", "Unknown Check"),
            description=result.get("check_name", ""),
            location=location,
            resource_name=result.get("resource", ""),
            resource_type=(
                result.get("resource", "").split(".")[0]
                if result.get("resource", "")
                else None
            ),
            rule_id=result.get("check_id", ""),
            check_result_type=check_type,
            violation_details={
                "check_class": result.get("check_class", ""),
                "guideline": result.get("guideline", ""),
                "evaluated_keys": result.get("check_result", {}).get(
                    "evaluated_keys", []
                ),
                "result_details": result.get("check_result", {}).get("result", ""),
                "bc_category": result.get("bc_category", ""),
            },
        )

    def validate(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        # Checkov is a dependency this Python module, if the Python import got
        # this far then we know we're in a valid runtime for this scanner.
        return True

    def scan(
        self,
        target: Path,
    ) -> StaticAnalysisReport:
        """Execute Checkov scan and return results.

        Args:
            target: Path to scan

        Returns:
            StaticAnalysisReport containing the scan findings and metadata

        Raises:
            ScannerError: If the scan fails or results cannot be parsed
        """
        try:
            self._pre_scan(target, self.options)
        except ScannerError as exc:
            raise exc

        try:
            start_time = datetime.now()
            final_args = self._resolve_arguments(target=target)
            self._run_subprocess(final_args)
            end_time = datetime.now()
            scan_duration = (end_time - start_time).total_seconds()

            # Parse Checkov JSON output
            checkov_results = json.loads("".join(self.output))
            results = checkov_results.get("results", {})

            # Create findings list for all result types
            findings: List[IaCVulnerability] = []

            # Process failed checks
            for result in results.get("failed_checks", []):
                findings.append(
                    self._create_finding_from_check(result, CheckResultType.FAILED)
                )

            # Process passed checks
            for result in results.get("passed_checks", []):
                findings.append(
                    self._create_finding_from_check(result, CheckResultType.PASSED)
                )

            # Process skipped checks
            for result in results.get("skipped_checks", []):
                findings.append(
                    self._create_finding_from_check(result, CheckResultType.SKIPPED)
                )

            # Process parsing errors
            for result in results.get("parsing_errors", []):
                findings.append(
                    self._create_finding_from_check(result, CheckResultType.ERROR)
                )

            # Create statistics
            metrics = checkov_results.get("metrics", {})

            # Count findings by severity
            severity_counts = {}
            for finding in findings:
                severity = finding.severity
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            stats = ScanStatistics(
                files_scanned=metrics.get("_totals", {}).get("loc", 0),
                lines_of_code=metrics.get("_totals", {}).get("loc", 0),
                total_findings=len(findings),
                findings_by_type=severity_counts,
                scan_duration_seconds=scan_duration,
            )

            # Create and return report
            return IaCScanReport(
                name="checkov",
                description="Checkov security scan report",
                scanners_used=[
                    Scanner(name="checkov", version=version("checkov"), type="IAC"),
                ],
                findings=findings,
                statistics=stats,
                scan_config=self._config,
            )

        except Exception as e:
            # Check if there are useful error details
            error_output = "".join(self.errors())
            raise ScannerError(f"Checkov scan failed: {str(e)}\nErrors: {error_output}")
