"""Test module for BanditScanner implementation."""

import pytest
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.scanners.ash_default.bandit_scanner import BanditScanner
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import ExportFormat


def test_bandit_scanner_init(test_source_dir, test_output_dir):
    """Test BanditScanner initialization and configuration."""
    # Test default initialization
    scanner = BanditScanner(source_dir=test_source_dir, output_dir=test_output_dir)
    # scanner.configure(scanner.default_config)
    assert scanner.name == "bandit"
    assert scanner.type == "SAST"
    assert scanner.options == {"severity": "high"}
    assert scanner.validate() is True
    assert scanner.tool_version is not None

    # Test explicit configuration
    config = ScannerPluginBase(
        name="bandit", type="SAST", command="bandit", enabled=True, output_format="json"
    )
    # scanner.configure(config)
    assert scanner._config == config
    assert scanner.validate() is True


def test_bandit_scanner_configure(test_source_dir, test_output_dir):
    """Test scanner configuration."""
    scanner = BanditScanner(source_dir=test_source_dir, output_dir=test_output_dir)
    config = ScannerPluginBase(name="bandit", output_format="text")
    # scanner.configure(config)
    assert scanner._config == config
    # We have to force standardization of output format at the scanner level so we
    # know what format to parse from and what data is available for a particular scanner
    assert scanner._default_config.output_format == ExportFormat.SARIF
    assert scanner._config.output_format == ExportFormat.TEXT


def test_bandit_scanner_validate(test_source_dir, test_output_dir):
    """Test validation logic."""
    scanner = BanditScanner(source_dir=test_source_dir, output_dir=test_output_dir)
    scanner._config = None
    assert scanner.validate() is False
    scanner._set_config(scanner.default_config)
    assert scanner.validate() is True


def test_bandit_scanner_scan_json(mocker, test_source_dir, test_output_dir):
    """Test scanning with JSON output format."""
    scanner = BanditScanner(source_dir=test_source_dir, output_dir=test_output_dir)
    # scanner.configure(
    #     ScannerPluginConfig(
    #         name="bandit",
    #         type="SAST",
    #         command="bandit",
    #         enabled=True,
    #         output_format="json",
    #     )
    # )

    # Mock scanning methods
    mocker.patch.object(scanner, "_pre_scan")
    mock_parse = mocker.patch.object(scanner, "_parse_outputs")
    mock_parse.return_value = {"findings": [], "metadata": {}}
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
    # scanner.configure(scanner.default_config)

    # Mock subprocess execution
    mock_run = mocker.patch.object(scanner, "_run_subprocess")
    mock_parse_outputs = mocker.patch.object(scanner, "_parse_outputs")
    mock_output = mocker.patch.object(scanner, "_output")
    mock_output.return_value = ['{"results": []}']

    scanner.scan("/test/path")

    # Verify command includes config options
    mock_run.assert_called_once()
    mock_parse_outputs.assert_called_once()


def test_bandit_scanner_errors(mocker, test_source_dir, test_output_dir):
    """Test scanner error handling."""
    scanner = BanditScanner(source_dir=test_source_dir, output_dir=test_output_dir)

    # Test target validation
    with pytest.raises(ScannerError) as exc:
        scanner.scan(None)
    assert "No target specified" in str(exc.value)

    # Test command execution failure
    mocker.patch.object(scanner, "_pre_scan")  # Mock pre-scan to avoid validation
    mock_run = mocker.patch.object(scanner, "_run_subprocess")
    mock_run.side_effect = Exception("Command failed")

    with pytest.raises(ScannerError) as exc:
        scanner.scan(str(test_source_dir))
    assert "Command failed" in str(exc.value)
