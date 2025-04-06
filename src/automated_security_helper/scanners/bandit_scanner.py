"""Module containing the Bandit security scanner implementation."""

from importlib.metadata import version
import json
from datetime import datetime, timezone
import logging
from pathlib import Path
from typing import Any, Dict, Optional
from automated_security_helper.models.core import Location
from automated_security_helper.models.data_interchange import ExportFormat
from automated_security_helper.models.security_vulnerability import (
    SecurityVulnerability,
)
from automated_security_helper.exceptions import ScannerError
from automated_security_helper.scanners.scanner_plugin import (
    ScannerPlugin,
)
from automated_security_helper.config.config import (
    ScannerPluginConfig,
)
from automated_security_helper.models.static_analysis import (
    StaticAnalysisReport,
    ScanStatistics,
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
        output_arg="-o",
        output_arg_position="before_args",
        scan_path_arg="-r",
        scan_path_arg_position="after_args",
        format_arg="-f",
        format_arg_value="json",
        format_arg_position="before_args",
        invocation_mode="directory",
        get_tool_version_command=["bandit", "--version"],
        output_stream="file",
        enabled=True,
        output_format="json",
    )
    _output_format = ExportFormat.JSON
    tool_version = version("bandit")

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
        # Allow output format override through config
        super().configure(config)

    def validate(self) -> bool:
        """Verify scanner configuration and requirements."""
        self._is_valid = self._config is not None and self.tool_version is not None
        return self._is_valid

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

        possible_config_paths = {
            f"{self.source_dir}/.bandit": [
                "--ini",
                f"{self.source_dir}/.bandit",
            ],
            f"{self.source_dir}/bandit.yaml": [
                "-c",
                f"{self.source_dir}/bandit.yaml",
            ],
            f"{self.source_dir}/bandit.toml": [
                "-c",
                f"{self.source_dir}/bandit.toml",
            ],
        }

        for conf_path, new_args in possible_config_paths.items():
            if Path(conf_path).exists():
                self._config.args.extend(new_args)
                break
        self._config.args.extend(
            ['--exclude="*venv/*"', '--exclude=".venv/*"', "--severity-level=all"]
        )

        start_time = datetime.now()

        # Add config-specific args if provided
        if self._config:
            if "confidence" in self._config:
                self._config.args.extend(["-l", self._config["confidence"]])
            if "severity" in self._config:
                self._config.args.extend(["-i", self._config["severity"]])

        try:
            Path(self.results_file).parent.mkdir(exist_ok=True, parents=True)
            final_args = self._resolve_arguments(target=target)
            self.logger.debug(f"Running Bandit with args: {final_args}")
            self._run_subprocess(final_args)
            end_time = datetime.now()
            scan_duration = (end_time - start_time).total_seconds()
            self.logger.debug(f"Bandit completed in {scan_duration} seconds")

            self._output = self._parse_outputs(scan_duration=scan_duration)
            return self._output

        except Exception as e:
            # Check if there are useful error details
            raise ScannerError(f"Bandit scan failed: {str(e)}")

    def _parse_outputs(self, *args, **kwargs):
        # Parse Bandit JSON output
        with open(self.results_file, "r") as f:
            bandit_results = json.load(f)

        # Create findings list
        findings = []
        for result in bandit_results.get("results", []):
            finding = SecurityVulnerability(
                id=result.get("filename") + "/" + result.get("test_id"),
                location=Location(
                    file_path=result.get("filename", ""),
                    start_line=result.get("line_range", [0, 0])[0],
                    end_line=result.get("line_range", [0, 0])[1],
                    snippet=result.get("code", None),
                ),
                title=result.get("test_name", "Unknown Issue"),
                description=" ".join(
                    [item for item in [result.get("issue_text", False)] if item]
                ),
                link=result.get("more_info", None),
                cwe_id=result.get("issue_cwe", {}).get("id", None),
                cwe_link=result.get("issue_cwe", {}).get("link", None),
                severity=result.get("issue_severity", "UNKNOWN").upper(),
                source_file=result.get("filename", None),
                line_number=result.get("line_number", None),
                code_snippet=result.get("code", None),
                remediation_advice=result.get("more_info", None),
                confidence=result.get("issue_confidence", "UNKNOWN").upper(),
                # raw=result,
            )
            findings.append(finding)

        # Create statistics
        metrics = bandit_results.get("metrics", {})

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
            scan_duration_seconds=kwargs["scan_duration"],
        )

        # Create and return report
        return StaticAnalysisReport(
            name=self.name,
            scanner_name="bandit",
            scanners_used=[{"bandit": version("bandit")}],
            project_name=self.name,
            findings=findings,
            statistics=stats,
            scan_timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            scan_config=self._config,
        )
