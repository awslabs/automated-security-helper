"""Unit tests for Opengrep scanner version detection and metrics flag handling."""

import pytest
from unittest.mock import MagicMock, patch
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
)


@pytest.fixture
def opengrep_scanner(test_plugin_context):
    """Create a test Opengrep scanner."""
    return OpengrepScanner(
        context=test_plugin_context,
        config=OpengrepScannerConfig(),
    )


def test_get_opengrep_version_success(opengrep_scanner):
    """Test successful version detection."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "opengrep 1.15.1"

    with patch("subprocess.run", return_value=mock_result):
        version = opengrep_scanner._get_opengrep_version()
        assert version == (1, 15, 1)


def test_get_opengrep_version_with_v_prefix(opengrep_scanner):
    """Test version detection with 'v' prefix."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "v1.6.0"

    with patch("subprocess.run", return_value=mock_result):
        version = opengrep_scanner._get_opengrep_version()
        assert version == (1, 6, 0)


def test_get_opengrep_version_failure(opengrep_scanner):
    """Test version detection failure."""
    with patch("subprocess.run", side_effect=Exception("Command failed")):
        version = opengrep_scanner._get_opengrep_version()
        assert version is None


def test_should_use_metrics_flag_old_version(opengrep_scanner):
    """Test metrics flag should be used for versions < 1.7.0."""
    with patch.object(
        opengrep_scanner, "_get_opengrep_version", return_value=(1, 6, 0)
    ):
        assert opengrep_scanner._should_use_metrics_flag() is True


def test_should_use_metrics_flag_new_version(opengrep_scanner):
    """Test metrics flag should not be used for versions >= 1.7.0."""
    with patch.object(
        opengrep_scanner, "_get_opengrep_version", return_value=(1, 7, 0)
    ):
        assert opengrep_scanner._should_use_metrics_flag() is False


def test_should_use_metrics_flag_newer_version(opengrep_scanner):
    """Test metrics flag should not be used for versions > 1.7.0."""
    with patch.object(
        opengrep_scanner, "_get_opengrep_version", return_value=(1, 15, 1)
    ):
        assert opengrep_scanner._should_use_metrics_flag() is False


def test_should_use_metrics_flag_unknown_version(opengrep_scanner):
    """Test metrics flag defaults to False when version cannot be determined."""
    with patch.object(opengrep_scanner, "_get_opengrep_version", return_value=None):
        assert opengrep_scanner._should_use_metrics_flag() is False


def test_process_config_options_offline_old_version(test_plugin_context):
    """Test offline mode with old version includes metrics flag."""
    scanner = OpengrepScanner(
        context=test_plugin_context,
        config=OpengrepScannerConfig(
            options=OpengrepScannerConfigOptions(offline=True)
        ),
    )

    with patch.object(scanner, "_should_use_metrics_flag", return_value=True):
        scanner._process_config_options()

        metrics_args = [
            arg for arg in scanner.args.extra_args if arg.key == "--metrics"
        ]
        assert len(metrics_args) == 1
        assert metrics_args[0].value == "off"


def test_process_config_options_offline_new_version(test_plugin_context):
    """Test offline mode with new version excludes metrics flag."""
    scanner = OpengrepScanner(
        context=test_plugin_context,
        config=OpengrepScannerConfig(
            options=OpengrepScannerConfigOptions(offline=True)
        ),
    )

    with patch.object(scanner, "_should_use_metrics_flag", return_value=False):
        scanner._process_config_options()

        metrics_args = [
            arg for arg in scanner.args.extra_args if arg.key == "--metrics"
        ]
        assert len(metrics_args) == 0


def test_process_config_options_online_old_version(test_plugin_context):
    """Test online mode with old version includes metrics flag."""
    scanner = OpengrepScanner(
        context=test_plugin_context,
        config=OpengrepScannerConfig(
            options=OpengrepScannerConfigOptions(offline=False, metrics="auto")
        ),
    )

    with patch.object(scanner, "_should_use_metrics_flag", return_value=True):
        scanner._process_config_options()

        metrics_args = [
            arg for arg in scanner.args.extra_args if arg.key == "--metrics"
        ]
        assert len(metrics_args) == 1
        assert metrics_args[0].value == "auto"


def test_process_config_options_online_new_version(test_plugin_context):
    """Test online mode with new version excludes metrics flag."""
    scanner = OpengrepScanner(
        context=test_plugin_context,
        config=OpengrepScannerConfig(
            options=OpengrepScannerConfigOptions(offline=False, metrics="auto")
        ),
    )

    with patch.object(scanner, "_should_use_metrics_flag", return_value=False):
        scanner._process_config_options()

        metrics_args = [
            arg for arg in scanner.args.extra_args if arg.key == "--metrics"
        ]
        assert len(metrics_args) == 0
