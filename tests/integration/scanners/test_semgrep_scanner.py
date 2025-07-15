"""Tests for Semgrep scanner."""

import pytest
from pathlib import Path
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
    SemgrepScannerConfig,
    SemgrepScannerConfigOptions,
)


@pytest.fixture
def test_semgrep_scanner(test_plugin_context):
    """Create a test Semgrep scanner."""
    return SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(),
    )


def test_semgrep_scanner_init(test_plugin_context):
    """Test SemgrepScanner initialization."""
    scanner = SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(),
    )
    assert scanner.config.name == "semgrep"
    assert scanner.command == "semgrep"
    assert scanner.tool_type == "SAST"
    assert scanner.use_uv_tool is True  # Verify UV tool is enabled


def test_semgrep_scanner_validate(test_semgrep_scanner):
    """Test SemgrepScanner validation."""
    assert test_semgrep_scanner.validate() is True


def test_semgrep_scanner_uv_tool_integration(test_plugin_context):
    """Test SemgrepScanner UV tool integration."""
    import unittest.mock

    scanner = SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(),
    )

    # Verify UV tool is enabled
    assert scanner.use_uv_tool is True
    assert scanner.command == "semgrep"

    # Test UV tool version detection
    with unittest.mock.patch(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
    ) as mock_runner:
        mock_runner_instance = unittest.mock.MagicMock()
        mock_runner.return_value = mock_runner_instance
        mock_runner_instance.is_uv_available.return_value = True
        mock_runner_instance.get_tool_version.return_value = "1.125.0"

        # Test version detection
        version = scanner._get_uv_tool_version("semgrep")
        assert version == "1.125.0"
        mock_runner_instance.get_tool_version.assert_called_with("semgrep")

    # Test validation with UV tool available
    with unittest.mock.patch(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
    ) as mock_runner:
        mock_runner_instance = unittest.mock.MagicMock()
        mock_runner.return_value = mock_runner_instance
        mock_runner_instance.is_uv_available.return_value = True

        assert scanner.validate() is True

    # Test validation with UV tool unavailable but direct executable available
    with (
        unittest.mock.patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_runner,
        unittest.mock.patch(
            "automated_security_helper.utils.subprocess_utils.find_executable"
        ) as mock_find,
    ):
        mock_runner_instance = unittest.mock.MagicMock()
        mock_runner.return_value = mock_runner_instance
        mock_runner_instance.is_uv_available.return_value = False
        mock_find.return_value = "/usr/local/bin/semgrep"

        assert scanner.validate() is True
        assert scanner.use_uv_tool is False  # Should be disabled after fallback

    # Test validation with neither UV tool nor direct executable available
    with (
        unittest.mock.patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_runner,
        unittest.mock.patch(
            "automated_security_helper.utils.subprocess_utils.find_executable"
        ) as mock_find,
    ):
        mock_runner_instance = unittest.mock.MagicMock()
        mock_runner.return_value = mock_runner_instance
        mock_runner_instance.is_uv_available.return_value = False
        mock_find.return_value = None

        assert scanner.validate() is False


def test_semgrep_scanner_configure(test_plugin_context):
    """Test SemgrepScanner configuration."""
    scanner = SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(
            options=SemgrepScannerConfigOptions(
                config="p/security-audit",
                exclude=["*.test.py", "test_*"],
                exclude_rule=["generic.secrets.security.detected-private-key"],
                severity=["ERROR", "WARNING"],
                metrics="off",
                offline=True,
            )
        ),
    )
    assert scanner.config.options.config == "p/security-audit"
    assert "*.test.py" in scanner.config.options.exclude
    assert (
        "generic.secrets.security.detected-private-key"
        in scanner.config.options.exclude_rule
    )
    assert "ERROR" in scanner.config.options.severity
    assert scanner.config.options.metrics == "off"
    assert scanner.config.options.offline is True


def test_semgrep_scanner_scan(test_semgrep_scanner, test_data_dir):
    """Test SemgrepScanner scan method."""
    # Mock the scan to avoid actual execution
    import unittest.mock

    with (
        unittest.mock.patch.object(test_semgrep_scanner, "_run_subprocess"),
        unittest.mock.patch("builtins.open", unittest.mock.mock_open(read_data="{}")),
        unittest.mock.patch("json.load", return_value={}),
    ):
        # Run the scan
        results = test_semgrep_scanner.scan(test_data_dir, target_type="source")

    # Check that results were returned
    assert results is not None


def test_semgrep_scanner_scan_error(test_semgrep_scanner):
    """Test SemgrepScanner scan method with error."""
    # Try to scan a non-existent directory
    resp = test_semgrep_scanner.scan(Path("nonexistent"), target_type="source")
    assert resp is not None
    assert resp is True
    assert (
        "(semgrep) Target directory nonexistent is empty or doesn't exist. Skipping scan."
        in test_semgrep_scanner.errors
    )


def test_process_config_options_offline_mode(test_plugin_context):
    """Test processing of offline mode options."""
    scanner = SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(
            options=SemgrepScannerConfigOptions(
                offline=True,
            )
        ),
    )
    scanner._process_config_options()

    # Check that offline mode arguments were added
    extra_args = [arg.key for arg in scanner.args.extra_args]
    assert "--metrics" in extra_args


def test_process_config_options_exclude_patterns(test_plugin_context):
    """Test processing of exclude pattern options."""
    scanner = SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(
            options=SemgrepScannerConfigOptions(
                exclude=["*.test.py", "test_*", "examples/*"],
            )
        ),
    )
    scanner._process_config_options()

    # Check that exclude arguments were added
    exclude_args = [arg.key for arg in scanner.args.extra_args]
    assert "--exclude" in exclude_args


def test_process_config_options_severity_filters(test_plugin_context):
    """Test processing of severity filter options."""
    scanner = SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(
            options=SemgrepScannerConfigOptions(
                severity=["ERROR", "WARNING"],
            )
        ),
    )
    scanner._process_config_options()

    # Check that severity arguments were added
    severity_args = [arg.key for arg in scanner.args.extra_args]
    assert "--severity" in severity_args
