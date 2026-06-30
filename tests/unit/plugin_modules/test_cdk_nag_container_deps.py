"""Regression tests for #373: cdk-nag scanner must install CDK deps in container/local mode.

Before the fix, the Dockerfile installed ASH without the [cdk] optional extra,
and `ash dependencies install` had no way to install CDK deps because the
cdk-nag scanner did not override `get_installation_commands()`. This caused
cdk-nag to be marked as MISSING in container mode.
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    CdkNagScanner,
    CdkNagScannerConfig,
)

AshConfig.model_rebuild()
CdkNagScannerConfig.model_rebuild()
CdkNagScanner.model_rebuild()


@pytest.fixture
def scanner_context(tmp_path):
    """Create a PluginContext for the scanner."""
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir()

    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )


class TestCdkNagInstallationCommands:
    """get_installation_commands must emit pip install for CDK extra when deps are missing."""

    def test_returns_pip_install_cdk_extra_when_unavailable(self, scanner_context):
        """When _CDK_AVAILABLE is False, must include pip install automated-security-helper[cdk]."""
        with patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner._CDK_AVAILABLE",
            False,
        ):
            scanner = CdkNagScanner(context=scanner_context)
            commands = scanner.get_installation_commands("linux", "amd64")

            # Should contain exactly one command that installs the [cdk] extra
            cdk_install_cmds = [
                cmd for cmd in commands if "automated-security-helper[cdk]" in cmd
            ]
            assert len(cdk_install_cmds) == 1, (
                f"Expected exactly one CDK install command, got: {commands}"
            )

            # Verify it's a pip install command
            cmd = cdk_install_cmds[0]
            assert cmd[0] == sys.executable
            assert cmd[1] == "-m"
            assert cmd[2] == "pip"
            assert cmd[3] == "install"

    def test_no_pip_install_when_cdk_available(self, scanner_context):
        """When _CDK_AVAILABLE is True, must NOT emit pip install for CDK extra."""
        with patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner._CDK_AVAILABLE",
            True,
        ):
            scanner = CdkNagScanner(context=scanner_context)
            commands = scanner.get_installation_commands("linux", "amd64")

            cdk_install_cmds = [
                cmd for cmd in commands if "automated-security-helper[cdk]" in cmd
            ]
            assert len(cdk_install_cmds) == 0, (
                f"Should not install CDK extra when already available, got: {commands}"
            )

    def test_validate_deps_fails_when_cdk_unavailable(self, scanner_context):
        """validate_plugin_dependencies must return False when CDK is not installed."""
        with patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner._CDK_AVAILABLE",
            False,
        ):
            scanner = CdkNagScanner(context=scanner_context)
            result = scanner.validate_plugin_dependencies()
            assert result is False
            assert scanner.dependencies_satisfied is False
