"""Test module for BanditScanner implementation."""

import pytest
from automated_security_helper.scanners import BanditScanner
from automated_security_helper.exceptions import ScannerError
from automated_security_helper.config.config import ScannerPluginConfig


def test_bandit_scanner_init(test_source_dir, test_output_dir):
    """Test BanditScanner initialization."""
    scanner = BanditScanner(source_dir=test_source_dir, output_dir=test_output_dir)
    scanner.configure()
    assert scanner._config is None
    scanner.configure(scanner.default_config)
    assert scanner._config is not None
    assert scanner._output_format == "json"


def test_bandit_scanner_configure(test_source_dir, test_output_dir):
    """Test scanner configuration."""
    scanner = BanditScanner(source_dir=test_source_dir, output_dir=test_output_dir)
    config = ScannerPluginConfig(name="bandit", output_format="text")
    scanner.configure(config)
    assert scanner._config == config
    # We have to force standardization of output format at the scanner level so we
    # know what format to parse from and what data is available for a particular scanner
    assert scanner._output_format == "json"


def test_bandit_scanner_validate(test_source_dir, test_output_dir):
    """Test validation logic."""
    scanner = BanditScanner(source_dir=test_source_dir, output_dir=test_output_dir)
    scanner._config = None
    assert scanner.validate() is False
    scanner._set_config(scanner.default_config)
    assert scanner.validate() is True


def test_bandit_scanner_scan_json(mocker, test_source_dir, test_output_dir):
    """Test scanning with JSON output."""

    scanner = BanditScanner(source_dir=test_source_dir, output_dir=test_output_dir)
    scanner.configure(scanner.default_config)

    # Mock subprocess execution
    mock_run = mocker.patch.object(scanner, "_run_subprocess")
    mock_parse_outputs = mocker.patch.object(scanner, "_parse_outputs")
    mock_output = mocker.patch.object(scanner, "_output")
    mock_output.return_value = ['{"results": []}']

    result = scanner.scan("/test/path")

    # Verify command construction
    mock_run.assert_called_once()
    mock_parse_outputs.assert_called_once()
    assert len(result.findings) == 0


def test_bandit_scanner_scan_with_config(mocker, test_source_dir, test_output_dir):
    """Test scanning with additional config options."""
    scanner = BanditScanner(source_dir=test_source_dir, output_dir=test_output_dir)
    scanner.configure(scanner.default_config)

    # Mock subprocess execution
    mock_run = mocker.patch.object(scanner, "_run_subprocess")
    mock_parse_outputs = mocker.patch.object(scanner, "_parse_outputs")
    mock_output = mocker.patch.object(scanner, "_output")
    mock_output.return_value = ['{"results": []}']

    scanner.scan("/test/path")

    # Verify command includes config options
    mock_run.assert_called_once()
    mock_parse_outputs.assert_called_once()


def test_bandit_scanner_scan_error(mocker, test_source_dir, test_output_dir):
    """Test error handling during scan."""
    scanner = BanditScanner(source_dir=test_source_dir, output_dir=test_output_dir)

    # Mock subprocess failure
    mock_run = mocker.patch.object(scanner, "_run_subprocess")
    mock_run.side_effect = Exception("Command failed")
    mock_errors = mocker.patch.object(scanner, "_errors")
    mock_errors.return_value = ["Error: Invalid path"]

    with pytest.raises(ScannerError) as exc:
        scanner.scan("/test/path")

    assert " " in str(exc.value)
    assert "Bandit scan failed: Command failed" in str(exc.value)
