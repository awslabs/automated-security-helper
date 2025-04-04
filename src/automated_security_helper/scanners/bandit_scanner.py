"""Module containing the Bandit security scanner implementation."""

import json
from datetime import datetime, timezone
import logging
import shutil
from typing import Any, Dict, Optional
from automated_security_helper.models.core import Location, Scanner
from automated_security_helper.models.data_interchange import ExportFormat
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


logger = logging.Logger(__name__, logging.INFO)


class BanditScanner(ScannerPlugin):
    """Implementation of a Python security scanner using Bandit.

    This scanner uses Bandit to perform static security analysis of Python code
    and returns results in a structured format using the StaticAnalysisReport model.
    """

    _default_config = ScannerPluginConfig(
        name="bandit",
        type="SAST",
        command="bandit",
        scan_path_arg="-r",
        scan_path_arg_position="before_args",
        format_arg="-f",
        format_arg_position="before_args",
        format_arg_value="json",
        invocation_mode="directory",
        args=[],
        output_stream="stdout",
        enabled=True,
        output_format="json",
    )
    _output_format = ExportFormat.JSON

    def __init__(self) -> None:
        super().__init__()
        self._config = self._default_config

    def configure(
        self,
        config: ScannerPluginConfig = None,
    ) -> None:
        """Configure the scanner with provided settings."""
        super().configure(config)
        # Allow output format override through config
        self._default_config.format_arg_value = self._output_format.value
        self._output_format = (
            self._config.output_format
            if self._config and self._config.output_format
            else ExportFormat.JSON
        )

    def validate(self) -> bool:
        """Verify scanner configuration and requirements."""
        try:
            exists = (
                self._config.command and shutil.which(self._config.command) is not None
            )
            return exists and self._config is not None
        except Exception as e:
            raise ScannerError(f"Error validating scanner: {str(e)}") from e

    def scan(
        self, target: str, options: Optional[Dict[str, Any]] = None
    ) -> StaticAnalysisReport:
        """Execute Bandit scan and return results.

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

        # Add config-specific args if provided
        if self._config:
            if "confidence" in self._config:
                self._config.args.extend(["-l", self._config["confidence"]])
            if "severity" in self._config:
                self._config.args.extend(["-i", self._config["severity"]])

        try:
            start_time = datetime.now()
            final_args = self._resolve_arguments(target=target)
            self._run_subprocess(final_args)
            end_time = datetime.now()
            scan_duration = (end_time - start_time).total_seconds()

            # Parse Bandit JSON output
            if self._output_format == "json":
                bandit_results = json.loads("".join(self.output))

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
                    scan_timestamp=datetime.now(timezone.utc).isoformat(
                        timespec="seconds"
                    ),
                    scan_config=self._config,
                )

            # For other formats, create basic report with raw output
            return StaticAnalysisReport(
                name=target,
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
                scan_timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                scan_config=self._config,
            )

        except Exception as e:
            # Check if there are useful error details
            raise ScannerError(f"Bandit scan failed: {str(e)}")
