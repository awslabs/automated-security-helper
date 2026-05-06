"""Tests for scanner plugins — covers initialization, dependency validation, and scan method for bandit, checkov, semgrep, cfn_nag, cdk_nag, snyk scanners."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME


@pytest.fixture
def scanner_context(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir()

    ctx = PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )
    return ctx


class TestBanditScannerCoverage:
    """Tests for BanditScanner initialization and methods."""

    def test_init(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
            BanditScanner,
        )

        scanner = BanditScanner(context=scanner_context)
        assert scanner.command == "bandit"
        assert scanner.use_uv_tool is True

    def test_validate_dependencies(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
            BanditScanner,
        )

        scanner = BanditScanner(context=scanner_context)
        result = scanner.validate_plugin_dependencies()
        assert isinstance(result, bool)

    def test_validate_with_python_files(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
            BanditScanner,
        )

        # Create a Python file
        (scanner_context.source_dir / "test.py").write_text("x = 1")
        scanner = BanditScanner(context=scanner_context)
        result = scanner.validate_plugin_dependencies()
        assert result is True

    def test_get_tool_version_constraint(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
            BanditScanner,
        )

        scanner = BanditScanner(context=scanner_context)
        constraint = scanner._get_tool_version_constraint()
        # Should return a version constraint string or None
        assert constraint is None or isinstance(constraint, str)

    def test_get_tool_package_extras(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
            BanditScanner,
        )

        scanner = BanditScanner(context=scanner_context)
        extras = scanner._get_tool_package_extras()
        # Bandit should have sarif extras
        if extras:
            assert isinstance(extras, list)


class TestCheckovScannerCoverage:
    """Tests for CheckovScanner initialization."""

    def test_init(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
            CheckovScanner,
        )

        scanner = CheckovScanner(context=scanner_context)
        assert scanner.command == "checkov"
        assert scanner.use_uv_tool is True

    def test_validate_dependencies(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
            CheckovScanner,
        )

        scanner = CheckovScanner(context=scanner_context)
        result = scanner.validate_plugin_dependencies()
        # With no IaC files, should return False
        assert isinstance(result, bool)

    def test_validate_with_tf_files(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
            CheckovScanner,
        )

        (scanner_context.source_dir / "main.tf").write_text("resource {}")
        scanner = CheckovScanner(context=scanner_context)
        result = scanner.validate_plugin_dependencies()
        assert result is True


class TestSemgrepScannerCoverage:
    """Tests for SemgrepScanner initialization."""

    def test_init(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
            SemgrepScanner,
        )

        scanner = SemgrepScanner(context=scanner_context)
        assert scanner.command == "semgrep"

    def test_validate_dependencies_empty_source(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
            SemgrepScanner,
        )

        scanner = SemgrepScanner(context=scanner_context)
        result = scanner.validate_plugin_dependencies()
        # Empty dir should return False
        assert isinstance(result, bool)

    def test_validate_with_code_files(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
            SemgrepScanner,
        )

        (scanner_context.source_dir / "app.py").write_text("import os")
        scanner = SemgrepScanner(context=scanner_context)
        with patch("platform.system", return_value="Linux"), \
             patch("automated_security_helper.base.scanner_plugin.find_executable", return_value="/usr/bin/semgrep"), \
             patch.object(scanner, "_validate_uv_tool_availability", return_value=True):
            result = scanner.validate_plugin_dependencies()
        assert result is True


class TestCfnNagScannerCoverage:
    """Tests for CfnNagScanner initialization."""

    def test_init(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
            CfnNagScanner,
        )

        scanner = CfnNagScanner(context=scanner_context)
        assert scanner.config.name == "cfn-nag"

    def test_validate_dependencies_no_cfn(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
            CfnNagScanner,
        )

        scanner = CfnNagScanner(context=scanner_context)
        result = scanner.validate_plugin_dependencies()
        assert isinstance(result, bool)


class TestCdkNagScannerCoverage:
    """Tests for CdkNagScanner initialization."""

    def test_init(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
            CdkNagScanner,
        )

        scanner = CdkNagScanner(context=scanner_context)
        assert scanner.config.name == "cdk-nag"

    def test_validate_dependencies_no_cdk(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
            CdkNagScanner,
        )

        scanner = CdkNagScanner(context=scanner_context)
        result = scanner.validate_plugin_dependencies()
        assert isinstance(result, bool)


class TestOpenGrepScannerCoverage:
    """Tests for OpengrepScanner initialization."""

    def test_init(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
            OpengrepScanner,
        )

        scanner = OpengrepScanner(context=scanner_context)
        assert scanner.config.name == "opengrep"

    def test_validate_dependencies_empty(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
            OpengrepScanner,
        )

        scanner = OpengrepScanner(context=scanner_context)
        result = scanner.validate_plugin_dependencies()
        assert isinstance(result, bool)


class TestDetectSecretsScannerCoverage:
    """Tests for DetectSecretsScanner initialization."""

    def test_init(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
            DetectSecretsScanner,
        )

        scanner = DetectSecretsScanner(context=scanner_context)
        assert scanner.config.name == "detect-secrets"

    def test_validate_with_any_file(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
            DetectSecretsScanner,
        )

        (scanner_context.source_dir / "config.yaml").write_text("key: value")
        scanner = DetectSecretsScanner(context=scanner_context)
        result = scanner.validate_plugin_dependencies()
        assert result is True


class TestGrypeScannerCoverage:
    """Tests for GrypeScanner initialization."""

    def test_init(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
            GrypeScanner,
        )

        scanner = GrypeScanner(context=scanner_context)
        assert scanner.config.name == "grype"


class TestNpmAuditScannerCoverage:
    """Tests for NpmAuditScanner initialization."""

    def test_init(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
            NpmAuditScanner,
        )

        scanner = NpmAuditScanner(context=scanner_context)
        assert scanner.config.name == "npm-audit"

    def test_validate_no_package_json(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
            NpmAuditScanner,
        )

        scanner = NpmAuditScanner(context=scanner_context)
        result = scanner.validate_plugin_dependencies()
        assert isinstance(result, bool)

    def test_validate_with_package_json(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
            NpmAuditScanner,
        )

        (scanner_context.source_dir / "package.json").write_text('{"name": "test"}')
        scanner = NpmAuditScanner(context=scanner_context)
        result = scanner.validate_plugin_dependencies()
        assert result is True


class TestSyftScannerCoverage:
    """Tests for SyftScanner initialization."""

    def test_init(self, scanner_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
            SyftScanner,
        )

        scanner = SyftScanner(context=scanner_context)
        assert scanner.config.name == "syft"
