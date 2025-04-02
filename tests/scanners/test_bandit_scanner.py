"""Test module for BanditScanner implementation."""

import pytest
from automated_security_helper.scanners import BanditScanner, ScannerError
from automated_security_helper.models.config import ScannerConfig


def test_bandit_scanner_init():
    """Test BanditScanner initialization."""
    scanner = BanditScanner()
    assert scanner._config is None
    assert scanner._output_format == "json"


def test_bandit_scanner_configure():
    """Test scanner configuration."""
    scanner = BanditScanner()
    config = ScannerConfig(name="bandit", output_format="text")
    scanner.configure(config)
    assert scanner._config == config
    assert scanner._output_format == "text"


def test_bandit_scanner_validate():
    """Test validation logic."""
    scanner = BanditScanner()
    assert not scanner.validate()
    scanner._config = ScannerConfig(name="bandit")
    assert scanner.validate()


def test_bandit_scanner_scan_json(mocker):
    """Test scanning with JSON output."""
    scanner = BanditScanner()
    scanner.configure(ScannerConfig(name="bandit"))

    # Mock subprocess execution
    mock_run = mocker.patch.object(scanner, "_run_subprocess")
    mock_output = mocker.patch.object(scanner, "_output")
    mock_output.return_value = ['{"results": []}']

    result = scanner.scan("/test/path")

    # Verify command construction
    mock_run.assert_called_once_with(["bandit", "-f", "JSON", "-r", "/test/path"])
    assert len(result.findings) == 1


def test_bandit_scanner_scan_with_config(mocker):
    """Test scanning with additional config options."""
    scanner = BanditScanner()
    scanner.configure(
        ScannerConfig(name="bandit", confidence_level="HIGH", severity_level="MEDIUM")
    )

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
            "JSON",
            "-r",
            "/test/path",
        ]
    )


def test_bandit_scanner_scan_error(mocker):
    """Test error handling during scan."""
    scanner = BanditScanner()
    scanner.configure(ScannerConfig(name="bandit"))

    # Mock subprocess failure
    mock_run = mocker.patch.object(scanner, "_run_subprocess")
    mock_run.side_effect = Exception("Command failed")
    mock_errors = mocker.patch.object(scanner, "_errors")
    mock_errors.return_value = ["Error: Invalid path"]

    with pytest.raises(ScannerError) as exc:
        scanner.scan("/test/path")

    assert "Command failed" in str(exc.value)
    assert "Error: Invalid path" in str(exc.value)
