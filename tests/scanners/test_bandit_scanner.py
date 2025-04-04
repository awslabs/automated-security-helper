"""Test module for BanditScanner implementation."""

import pytest
from automated_security_helper.scanners import BanditScanner, ScannerError
from automated_security_helper.config.config import ScannerPluginConfig


def test_bandit_scanner_init():
    """Test BanditScanner initialization."""
    scanner = BanditScanner()
    scanner.configure()
    assert scanner._config is None
    scanner.configure(scanner.default_config)
    assert scanner._config is not None
    assert scanner._output_format == "json"


def test_bandit_scanner_configure():
    """Test scanner configuration."""
    scanner = BanditScanner()
    config = ScannerPluginConfig(name="bandit", output_format="text")
    scanner.configure(config)
    assert scanner._config == config
    assert scanner._output_format == "text"


def test_bandit_scanner_validate():
    """Test validation logic."""
    scanner = BanditScanner()
    assert scanner.validate()
    scanner._set_config(scanner.default_config)
    assert scanner.validate()


def test_bandit_scanner_scan_json(mocker):
    """Test scanning with JSON output."""
    scanner = BanditScanner()
    scanner.configure(scanner.default_config)

    # Mock subprocess execution
    mock_run = mocker.patch.object(scanner, "_run_subprocess")
    mock_output = mocker.patch.object(scanner, "_output")
    mock_output.return_value = ['{"results": []}']

    result = scanner.scan("/test/path")

    # Verify command construction
    mock_run.assert_called_once_with(["bandit", "-f", "json", "-r", "/test/path"])
    assert len(result.findings) == 1


def test_bandit_scanner_scan_with_config(mocker):
    """Test scanning with additional config options."""
    scanner = BanditScanner()
    scanner.configure(scanner.default_config)

    # Mock subprocess execution
    mock_run = mocker.patch.object(scanner, "_run_subprocess")
    mock_output = mocker.patch.object(scanner, "_output")
    mock_output.return_value = ['{"results": []}']

    scanner.scan("/test/path")

    # Verify command includes config options
    mock_run.assert_called_once_with(
        [
            "bandit",
            "-f",
            "json",
            "-r",
            "/test/path",
        ]
    )


def test_bandit_scanner_scan_error(mocker):
    """Test error handling during scan."""
    scanner = BanditScanner()

    # Mock subprocess failure
    mock_run = mocker.patch.object(scanner, "_run_subprocess")
    mock_run.side_effect = Exception("Command failed")
    mock_errors = mocker.patch.object(scanner, "_errors")
    mock_errors.return_value = ["Error: Invalid path"]

    with pytest.raises(ScannerError) as exc:
        scanner.scan("/test/path")

    assert " " in str(exc.value)
    assert "Bandit scan failed: Command failed" in str(exc.value)
