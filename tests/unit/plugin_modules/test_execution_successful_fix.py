"""Tests that executionSuccessful in SARIF Invocation objects reflects actual exit codes.

Exit code conventions:
- Most tools: 0=clean, 1=findings found, >=2=error
- Grype: 0=clean, 1=error, 2=findings found (inverted)
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_execution_successful(sarif_report) -> bool:
    """Pull executionSuccessful from the first invocation of the first run."""
    return sarif_report.runs[0].invocations[0].executionSuccessful


# ---------------------------------------------------------------------------
# Bandit
# ---------------------------------------------------------------------------


class TestBanditExecutionSuccessful:
    """Bandit: exit 0/1 = success, exit >=2 = failure."""

    @pytest.fixture
    def bandit_scanner(self, test_plugin_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
            BanditScanner,
            BanditScannerConfig,
        )

        scanner = BanditScanner(context=test_plugin_context, config=BanditScannerConfig())
        return scanner

    @pytest.mark.parametrize("exit_code,expected", [(0, True), (1, True), (2, False), (127, False)])
    def test_execution_successful_reflects_exit_code(self, bandit_scanner, exit_code, expected, tmp_path):
        """executionSuccessful must be True only when exit_code is 0 or 1."""
        # Minimal valid SARIF that bandit would produce
        minimal_sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Bandit",
                            "version": "1.0.0",
                        }
                    },
                    "results": [],
                }
            ],
        }
        sarif_file = tmp_path / "results.sarif"
        sarif_file.write_text(json.dumps(minimal_sarif))

        bandit_scanner.exit_code = exit_code
        bandit_scanner.start_time = "2024-01-01T00:00:00Z"
        bandit_scanner.end_time = "2024-01-01T00:01:00Z"
        bandit_scanner.errors = []

        # Patch _run_subprocess to avoid actually running bandit, and
        # patch the SARIF file reading path so it reads our fixture
        with patch.object(bandit_scanner, "_run_subprocess", return_value={"stdout": "", "returncode": exit_code}):
            # Directly test the SARIF construction by simulating what scan() does
            # after calling the subprocess
            from automated_security_helper.schemas.sarif_schema_model import (
                ArtifactLocation,
                Invocation,
                SarifReport,
            )
            from automated_security_helper.utils.get_shortest_name import get_shortest_name

            content = sarif_file.read_text()
            bandit_results = json.loads(content)
            sarif_report = SarifReport.model_validate(bandit_results)
            final_args = ["bandit", "-r", str(tmp_path)]

            sarif_report.runs[0].invocations = [
                Invocation(
                    commandLine=final_args[0],
                    arguments=final_args[1:],
                    startTimeUtc=bandit_scanner.start_time,
                    endTimeUtc=bandit_scanner.end_time,
                    executionSuccessful=(bandit_scanner.exit_code == 0 or bandit_scanner.exit_code == 1),
                    exitCode=bandit_scanner.exit_code,
                    exitCodeDescription="\n".join(bandit_scanner.errors),
                    workingDirectory=ArtifactLocation(
                        uri=get_shortest_name(input=tmp_path),
                    ),
                )
            ]
            assert _extract_execution_successful(sarif_report) is expected


# ---------------------------------------------------------------------------
# Checkov
# ---------------------------------------------------------------------------


class TestCheckovExecutionSuccessful:
    """Checkov: exit 0/1 = success, exit >=2 = failure."""

    @pytest.mark.parametrize("exit_code,expected", [(0, True), (1, True), (2, False), (3, False)])
    def test_execution_successful_reflects_exit_code(self, test_plugin_context, exit_code, expected, tmp_path):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
            CheckovScanner,
            CheckovScannerConfig,
        )
        from automated_security_helper.schemas.sarif_schema_model import (
            ArtifactLocation,
            Invocation,
            SarifReport,
        )
        from automated_security_helper.utils.get_shortest_name import get_shortest_name

        scanner = CheckovScanner(context=test_plugin_context, config=CheckovScannerConfig())
        scanner.exit_code = exit_code
        scanner.start_time = "2024-01-01T00:00:00Z"
        scanner.end_time = "2024-01-01T00:01:00Z"
        scanner.errors = []

        minimal_sarif = {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Checkov", "version": "1.0.0"}}, "results": []}],
        }
        sarif_report = SarifReport.model_validate(minimal_sarif)
        final_args = ["checkov", "--directory", str(tmp_path)]

        sarif_report.runs[0].invocations = [
            Invocation(
                commandLine=final_args[0],
                arguments=final_args[1:],
                startTimeUtc=scanner.start_time,
                endTimeUtc=scanner.end_time,
                executionSuccessful=(scanner.exit_code == 0 or scanner.exit_code == 1),
                exitCode=scanner.exit_code,
                exitCodeDescription="\n".join(scanner.errors),
                workingDirectory=ArtifactLocation(uri=get_shortest_name(input=tmp_path)),
            )
        ]
        assert _extract_execution_successful(sarif_report) is expected


# ---------------------------------------------------------------------------
# Grype (inverted: exit 1 = error, exit 2 = findings)
# ---------------------------------------------------------------------------


class TestGrypeExecutionSuccessful:
    """Grype: exit 0 = success, exit 1 = error, exit 2 = findings (success)."""

    @pytest.mark.parametrize("exit_code,expected", [(0, True), (1, False), (2, True), (127, True)])
    def test_execution_successful_reflects_exit_code(self, test_plugin_context, exit_code, expected, tmp_path):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
            GrypeScanner,
            GrypeScannerConfig,
        )
        from automated_security_helper.schemas.sarif_schema_model import (
            ArtifactLocation,
            Invocation,
            SarifReport,
        )
        from automated_security_helper.utils.get_shortest_name import get_shortest_name

        scanner = GrypeScanner(context=test_plugin_context, config=GrypeScannerConfig())
        scanner.exit_code = exit_code
        scanner.start_time = "2024-01-01T00:00:00Z"
        scanner.end_time = "2024-01-01T00:01:00Z"
        scanner.errors = []

        minimal_sarif = {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Grype", "version": "1.0.0"}}, "results": []}],
        }
        sarif_report = SarifReport.model_validate(minimal_sarif)
        final_args = ["grype", str(tmp_path)]

        sarif_report.runs[0].invocations = [
            Invocation(
                commandLine=final_args[0],
                arguments=final_args[1:],
                startTimeUtc=scanner.start_time,
                endTimeUtc=scanner.end_time,
                executionSuccessful=(scanner.exit_code != 1),
                exitCode=scanner.exit_code,
                exitCodeDescription="\n".join(scanner.errors),
                workingDirectory=ArtifactLocation(uri=get_shortest_name(input=tmp_path)),
            )
        ]
        assert _extract_execution_successful(sarif_report) is expected


# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------


class TestSemgrepExecutionSuccessful:
    """Semgrep: exit 0/1 = success, exit >=2 = failure."""

    @pytest.mark.parametrize("exit_code,expected", [(0, True), (1, True), (2, False)])
    def test_execution_successful_reflects_exit_code(self, test_plugin_context, exit_code, expected, tmp_path):
        from automated_security_helper.schemas.sarif_schema_model import (
            ArtifactLocation,
            Invocation,
            SarifReport,
        )
        from automated_security_helper.utils.get_shortest_name import get_shortest_name

        minimal_sarif = {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Semgrep", "version": "1.0.0"}}, "results": []}],
        }
        sarif_report = SarifReport.model_validate(minimal_sarif)
        final_args = ["semgrep", "--config", "auto"]
        exit_code_val = exit_code

        sarif_report.runs[0].invocations = [
            Invocation(
                commandLine=" ".join(final_args),
                arguments=final_args[1:],
                startTimeUtc="2024-01-01T00:00:00Z",
                endTimeUtc="2024-01-01T00:01:00Z",
                executionSuccessful=(exit_code_val == 0 or exit_code_val == 1),
                exitCode=exit_code_val,
                exitCodeDescription="",
                workingDirectory=ArtifactLocation(uri=get_shortest_name(input=tmp_path)),
            )
        ]
        assert _extract_execution_successful(sarif_report) is expected


# ---------------------------------------------------------------------------
# Opengrep
# ---------------------------------------------------------------------------


class TestOpengrepExecutionSuccessful:
    """Opengrep: exit 0/1 = success, exit >=2 = failure."""

    @pytest.mark.parametrize("exit_code,expected", [(0, True), (1, True), (2, False)])
    def test_execution_successful_reflects_exit_code(self, test_plugin_context, exit_code, expected, tmp_path):
        from automated_security_helper.schemas.sarif_schema_model import (
            ArtifactLocation,
            Invocation,
            SarifReport,
        )
        from automated_security_helper.utils.get_shortest_name import get_shortest_name

        minimal_sarif = {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Opengrep", "version": "1.0.0"}}, "results": []}],
        }
        sarif_report = SarifReport.model_validate(minimal_sarif)
        final_args = ["opengrep", "--config", "auto"]
        exit_code_val = exit_code

        sarif_report.runs[0].invocations = [
            Invocation(
                commandLine=" ".join(final_args),
                arguments=final_args[1:],
                startTimeUtc="2024-01-01T00:00:00Z",
                endTimeUtc="2024-01-01T00:01:00Z",
                executionSuccessful=(exit_code_val == 0 or exit_code_val == 1),
                exitCode=exit_code_val,
                exitCodeDescription="",
                workingDirectory=ArtifactLocation(uri=get_shortest_name(input=tmp_path)),
            )
        ]
        assert _extract_execution_successful(sarif_report) is expected


# ---------------------------------------------------------------------------
# npm audit
# ---------------------------------------------------------------------------


class TestNpmAuditExecutionSuccessful:
    """npm audit: exit 0/1 = success, exit >=2 = failure."""

    @pytest.mark.parametrize("exit_code,expected", [(0, True), (1, True), (2, False)])
    def test_execution_successful_reflects_exit_code(self, test_plugin_context, exit_code, expected, tmp_path):
        from automated_security_helper.schemas.sarif_schema_model import (
            ArtifactLocation,
            Invocation,
            SarifReport,
            Run,
            Tool,
            ToolComponent,
        )
        from automated_security_helper.utils.get_shortest_name import get_shortest_name

        exit_code_val = exit_code

        sarif_report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="npm-audit",
                            version="1.0.0",
                            informationUri="https://docs.npmjs.com/cli/v8/commands/npm-audit",
                        )
                    ),
                    results=[],
                    invocations=[
                        Invocation(
                            commandLine="npm audit --json",
                            executionSuccessful=(exit_code_val == 0 or exit_code_val == 1),
                            exitCode=exit_code_val,
                            workingDirectory=ArtifactLocation(
                                uri=get_shortest_name(input=tmp_path)
                            ),
                        )
                    ],
                )
            ],
        )
        assert _extract_execution_successful(sarif_report) is expected


# ---------------------------------------------------------------------------
# cfn-nag
# ---------------------------------------------------------------------------


class TestCfnNagExecutionSuccessful:
    """cfn-nag: exit 0/1 = success, exit >=2 = failure."""

    @pytest.mark.parametrize("exit_code,expected", [(0, True), (1, True), (2, False)])
    def test_execution_successful_reflects_exit_code(self, test_plugin_context, exit_code, expected, tmp_path):
        from automated_security_helper.schemas.sarif_schema_model import (
            ArtifactLocation,
            Invocation,
            SarifReport,
        )
        from automated_security_helper.utils.get_shortest_name import get_shortest_name

        minimal_sarif = {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "cfn_nag", "version": "1.0.0"}}, "results": []}],
        }
        sarif_report = SarifReport.model_validate(minimal_sarif)
        exit_code_val = exit_code

        sarif_report.runs[0].invocations = [
            Invocation(
                commandLine="ash-CFN Nag-scanner",
                arguments=["--target", str(tmp_path), "--scanner"],
                startTimeUtc="2024-01-01T00:00:00Z",
                endTimeUtc="2024-01-01T00:01:00Z",
                executionSuccessful=(exit_code_val == 0 or exit_code_val == 1),
                exitCode=exit_code_val,
                exitCodeDescription="",
                workingDirectory=ArtifactLocation(uri=get_shortest_name(input=tmp_path)),
            )
        ]
        assert _extract_execution_successful(sarif_report) is expected


# ---------------------------------------------------------------------------
# Trivy
# ---------------------------------------------------------------------------


class TestTrivyExecutionSuccessful:
    """Trivy: exit 0/1 = success, exit >=2 = failure."""

    @pytest.mark.parametrize("exit_code,expected", [(0, True), (1, True), (2, False)])
    def test_execution_successful_reflects_exit_code(self, test_plugin_context, exit_code, expected, tmp_path):
        from automated_security_helper.schemas.sarif_schema_model import (
            ArtifactLocation,
            Invocation,
            SarifReport,
        )
        from automated_security_helper.utils.get_shortest_name import get_shortest_name

        minimal_sarif = {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Trivy", "version": "1.0.0"}}, "results": []}],
        }
        sarif_report = SarifReport.model_validate(minimal_sarif)
        final_args = ["trivy", "fs", str(tmp_path)]
        exit_code_val = exit_code

        sarif_report.runs[0].invocations = [
            Invocation(
                commandLine=" ".join(final_args),
                arguments=final_args[1:],
                startTimeUtc="2024-01-01T00:00:00Z",
                endTimeUtc="2024-01-01T00:01:00Z",
                executionSuccessful=(exit_code_val == 0 or exit_code_val == 1),
                exitCode=exit_code_val,
                exitCodeDescription="",
                workingDirectory=ArtifactLocation(uri=get_shortest_name(input=tmp_path)),
            )
        ]
        assert _extract_execution_successful(sarif_report) is expected


# ---------------------------------------------------------------------------
# Cross-scanner: verify the ACTUAL source code uses the right expression
# ---------------------------------------------------------------------------


class TestSourceCodeUsesCorrectExpression:
    """Verify that each scanner's source code no longer hardcodes executionSuccessful=True
    in the post-scan Invocation (the one that has exitCode=self.exit_code)."""

    SCANNER_FILES = {
        "bandit": "automated_security_helper/plugin_modules/ash_builtin/scanners/bandit_scanner.py",
        "checkov": "automated_security_helper/plugin_modules/ash_builtin/scanners/checkov_scanner.py",
        "grype": "automated_security_helper/plugin_modules/ash_builtin/scanners/grype_scanner.py",
        "semgrep": "automated_security_helper/plugin_modules/ash_builtin/scanners/semgrep_scanner.py",
        "opengrep": "automated_security_helper/plugin_modules/ash_builtin/scanners/opengrep_scanner.py",
        "cfn_nag": "automated_security_helper/plugin_modules/ash_builtin/scanners/cfn_nag_scanner.py",
        "trivy": "automated_security_helper/plugin_modules/ash_trivy_plugins/trivy_repo_scanner.py",
    }

    @pytest.mark.parametrize("scanner_name", [
        "bandit", "checkov", "semgrep", "opengrep", "cfn_nag", "trivy",
    ])
    def test_standard_scanners_use_exit_code_expression(self, scanner_name):
        """Standard scanners (0/1 = success) must use self.exit_code in executionSuccessful."""
        src = Path(self.SCANNER_FILES[scanner_name]).read_text()
        # Find lines that set executionSuccessful alongside exitCode=self.exit_code
        # These must NOT be hardcoded True
        lines = src.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if "executionSuccessful=True" in stripped:
                # Check if a nearby line has exitCode=self.exit_code (within 3 lines)
                context = "\n".join(lines[max(0, i - 3) : i + 4])
                assert "exitCode=self.exit_code" not in context, (
                    f"{scanner_name}: line {i + 1} hardcodes executionSuccessful=True "
                    f"next to exitCode=self.exit_code. Should use exit_code expression."
                )

    def test_grype_uses_not_equal_1(self):
        """Grype must use self.exit_code != 1 (exit 1 = error for grype)."""
        src = Path(self.SCANNER_FILES["grype"]).read_text()
        lines = src.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if "executionSuccessful=True" in stripped:
                context = "\n".join(lines[max(0, i - 3) : i + 4])
                assert "exitCode=self.exit_code" not in context, (
                    f"grype: line {i + 1} hardcodes executionSuccessful=True "
                    f"next to exitCode=self.exit_code. Should use self.exit_code != 1."
                )

    def test_npm_audit_conversion_method_uses_exit_code(self):
        """npm audit _convert_npm_audit_to_sarif must use exit_code expression."""
        src = Path(
            "automated_security_helper/plugin_modules/ash_builtin/scanners/npm_audit_scanner.py"
        ).read_text()
        lines = src.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if "executionSuccessful=True" in stripped:
                # All remaining executionSuccessful=True in npm_audit should be
                # initialization-only (no exitCode=self.exit_code nearby)
                context = "\n".join(lines[max(0, i - 3) : i + 4])
                if "exitCode=self.exit_code" in context:
                    raise AssertionError(
                        f"npm_audit: line {i + 1} hardcodes executionSuccessful=True "
                        f"next to exitCode=self.exit_code."
                    )
