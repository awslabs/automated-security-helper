"""Module containing the Checkov security scanner implementation."""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from automated_security_helper.models.core import Location
from automated_security_helper.scanners.scanner_plugin import (
    ScannerPlugin,
    ScannerError,
)
from automated_security_helper.config.config import ScannerPluginConfig
from automated_security_helper.models.static_analysis import (
    StaticAnalysisFinding,
    StaticAnalysisReport,
    StaticAnalysisStatistics,
)


class CheckovScanner(ScannerPlugin):
    """ """

    def __init__(self) -> None:
        super().__init__()
        self._output_format = "json"
        self._config = ScannerPluginConfig(
            name="checkov",
            type="SAST",
            command="checkov",
            output_format="json",
        )

    def configure(self, config: ScannerPluginConfig = None) -> None:
        """Configure the scanner with provided settings."""
        super().configure(config)
        # Allow output format override through config
        self._output_format = (
            self._config.output_format
            if self._config.output_format in ["json", "sarif"]
            else "json"
        )

    def scan(
        self, target: str, options: Optional[Dict[str, Any]] = None
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
            self._pre_scan(target, options)
        except ScannerError as exc:
            raise exc

        try:
            start_time = datetime.now()
            final_args = self._resolve_arguments(target=target)
            self._run_subprocess(final_args)
            end_time = datetime.now()
            scan_duration = (end_time - start_time).total_seconds()

            # Parse Checkov JSON output
            if self._output_format == "json":
                checkov_results = json.loads("".join(self.output()))

                # Create findings list
                findings: List[StaticAnalysisFinding] = []
                for result in checkov_results.get("results", []):
                    finding = StaticAnalysisFinding(
                        title=result.get("test_name", "Unknown Issue"),
                        description=result.get("issue_text", ""),
                        severity=result.get("issue_severity", "UNKNOWN").upper(),
                        source_file=result.get("filename", ""),
                        line_number=result.get("line_number"),
                        code_snippet=result.get("code", ""),
                        remediation_advice=result.get("more_info", ""),
                        confidence=result.get("issue_confidence", "UNKNOWN").upper(),
                    )
                    findings.append(finding)

                # Create statistics
                metrics = checkov_results.get("metrics", {})

                # Count findings by severity
                severity_counts = {}
                for finding in findings:
                    severity = finding.severity
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1

                stats = StaticAnalysisStatistics(
                    files_scanned=metrics.get("_totals", {}).get("loc", 0),
                    lines_of_code=metrics.get("_totals", {}).get("loc", 0),
                    total_findings=len(findings),
                    findings_by_type=severity_counts,
                    scan_duration_seconds=scan_duration,
                )

                # Create and return report
                return StaticAnalysisReport(
                    scanner_name="checkov",
                    project_name=target,
                    findings=findings,
                    statistics=stats,
                    scan_timestamp=datetime.now(timezone.utc).isoformat(
                        timespec="seconds"
                    ),
                    scan_config=self._config,
                )

            # For other formats, create basic report with raw output
            return StaticAnalysisReport(
                scanner_name="checkov",
                project_name=target,
                findings=[
                    StaticAnalysisFinding(
                        id="raw_output",
                        severity="HIGH",
                        location=Location(
                            file_path="test/bad_path.py",
                            start_line=1,
                            end_line=10,
                        ),
                        title="Raw Checkov Output",
                        description="".join(self.output()),
                        source_file=target,
                    )
                ],
                scan_timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                scan_config=self._config,
            )

        except Exception as e:
            # Check if there are useful error details
            error_output = "".join(self.errors())
            raise ScannerError(f"Checkov scan failed: {str(e)}\nErrors: {error_output}")
