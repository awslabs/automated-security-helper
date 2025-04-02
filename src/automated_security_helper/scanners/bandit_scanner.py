"""Module containing the Bandit security scanner implementation."""

import json
from datetime import datetime, timezone
from automated_security_helper.models.core import Location, Scanner
from automated_security_helper.scanners.abstract_scanner import (
    AbstractScanner,
    ScannerError,
)
from automated_security_helper.models.interfaces import IScanner
from automated_security_helper.models.config import ScannerConfig
from automated_security_helper.models.static_analysis import (
    StaticAnalysisFinding,
    StaticAnalysisReport,
    StaticAnalysisStatistics,
)


class BanditScanner(AbstractScanner, IScanner):
    """Implementation of a Python security scanner using Bandit.

    This scanner uses Bandit to perform static security analysis of Python code
    and returns results in a structured format using the StaticAnalysisReport model.
    """

    def __init__(self) -> None:
        super().__init__()
        self._config: ScannerConfig = None
        self._output_format = "json"

    def configure(self, config: ScannerConfig) -> None:
        """Configure the scanner with provided settings."""
        self._config = config
        # Allow output format override through config
        self._output_format = config.output_format

    def validate(self) -> bool:
        """Verify scanner configuration and requirements."""
        # Minimal validation - could add bandit binary check here
        return self._config is not None

    def scan(self, target: str) -> StaticAnalysisReport:
        """Execute Bandit scan and return results.

        Args:
            target: Path to scan

        Returns:
            StaticAnalysisReport containing the scan findings and metadata

        Raises:
            ScannerError: If the scan fails or results cannot be parsed
        """
        cmd = ["bandit", "-f", self._output_format, "-r", target]

        # Add config-specific args if provided
        if self._config:
            if "confidence-level" in self._config:
                cmd.extend(["-l", self._config["confidence-level"]])
            if "severity-level" in self._config:
                cmd.extend(["-i", self._config["severity-level"]])

        try:
            start_time = datetime.now()
            self._run_subprocess(cmd)
            end_time = datetime.now()
            scan_duration = (end_time - start_time).total_seconds()

            # Parse Bandit JSON output
            if self._output_format == "json":
                bandit_results = json.loads("".join(self.output()))

                # Create findings list
                findings = []
                for result in bandit_results.get("results", []):
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
                metrics = bandit_results.get("metrics", {})

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
                    scanner_name="bandit",
                    project_name=target,
                    findings=findings,
                    statistics=stats,
                    scan_timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    scan_config=self._config,
                )

            # For other formats, create basic report with raw output
            return StaticAnalysisReport(
                scanner_name="bandit",
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
                        scanner=Scanner(
                            name="bandit",
                            type="SAST",
                            rule_id="XXXX",
                            version="1.0.0",
                        ),
                        title="Raw Bandit Output",
                        description="".join(self.output()),
                        source_file=target,
                    )
                ],
                scan_timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                scan_config=self._config,
            )

        except Exception as e:
            # Check if there are useful error details
            error_output = "".join(self.errors())
            raise ScannerError(f"Bandit scan failed: {str(e)}\nErrors: {error_output}")
