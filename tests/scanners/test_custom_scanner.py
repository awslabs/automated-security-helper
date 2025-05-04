"""Tests for Custom scanner."""

import pytest
import tempfile
from pathlib import Path
from automated_security_helper.scanners.ash_default.custom_scanner import (
    CustomScanner,
    CustomScannerConfig,
    CustomScannerConfigOptions,
)


@pytest.fixture
def test_custom_scanner(test_plugin_context):
    """Create a test Custom scanner."""
    return CustomScanner(
        context=test_plugin_context,
        config=CustomScannerConfig(
            name="test-scanner",
            enabled=True,
            type="CUSTOM",
        ),
        command="echo",
    )


def test_custom_scanner_init(test_plugin_context):
    """Test CustomScanner initialization."""
    scanner = CustomScanner(
        context=test_plugin_context,
        config=CustomScannerConfig(
            name="test-scanner",
            enabled=True,
            type="CUSTOM",
        ),
        command="echo",
    )
    assert scanner.config.name == "test-scanner"
    assert scanner.command == "echo"


def test_custom_scanner_validate(test_custom_scanner):
    """Test CustomScanner validation."""
    assert test_custom_scanner.validate() is True


def test_custom_scanner_configure(test_plugin_context):
    """Test CustomScanner configuration."""
    scanner = CustomScanner(
        context=test_plugin_context,
        command="custom-scan",
        config=CustomScannerConfig(
            name="test-scanner",
            enabled=True,
            type="CUSTOM",
            options=CustomScannerConfigOptions(),
        ),
    )
    assert scanner.config.name == "test-scanner"
    assert scanner.command == "custom-scan"


def test_custom_scanner_scan(test_custom_scanner, test_source_dir):
    """Test CustomScanner scan method."""
    # Run the scan
    results = test_custom_scanner.scan(test_source_dir, target_type="source")

    # Check that results were returned
    assert results is not None


def test_custom_scanner_scan_error(test_plugin_context):
    """Test CustomScanner scan method with error."""
    from automated_security_helper.core.exceptions import ScannerError
    import unittest.mock

    scanner = CustomScanner(
        context=test_plugin_context,
        config=CustomScannerConfig(
            name="test-scanner",
            enabled=True,
            type="CUSTOM",
        ),
        command="nonexistent-command",
    )

    # Mock _run_subprocess to raise an exception
    with unittest.mock.patch.object(
        scanner, "_run_subprocess", side_effect=Exception("Command not found")
    ):
        # Try to scan with a non-existent command
        with pytest.raises(ScannerError):
            scanner.scan(Path("nonexistent_dir"), target_type="source")


def test_custom_scanner_with_empty_results(test_custom_scanner, test_source_dir):
    """Test CustomScanner with empty results."""
    # Run the scan
    results = test_custom_scanner.scan(test_source_dir, target_type="source")

    # Check that empty results were handled properly
    assert results is not None
    assert len(results.runs[0].results) == 0


def test_custom_scanner_sarif_metadata(test_plugin_context):
    """Test CustomScanner SARIF metadata."""
    scanner = CustomScanner(
        context=test_plugin_context,
        config=CustomScannerConfig(
            name="test-scanner",
            enabled=True,
            type="CUSTOM",
        ),
        command="echo",
    )

    # Create a temporary directory for testing
    temp_dir = Path(tempfile.gettempdir()) / "ash_test_dir"
    temp_dir.mkdir(exist_ok=True)

    # Run the scan
    results = scanner.scan(temp_dir, target_type="source")

    # Check SARIF metadata
    assert results.runs[0].tool.driver.name is not None
    assert results.runs[0].tool.driver.version is not None


def test_custom_scanner_with_multiple_findings(test_plugin_context, tmp_path):
    """Test CustomScanner with multiple findings."""
    # Create a test file with JSON output
    test_file = tmp_path.joinpath("test_output.json")
    test_file.write_text(
        '{"results": [{"id": "TEST001", "message": "Test finding 1"}, {"id": "TEST002", "message": "Test finding 2"}]}'
    )

    scanner = CustomScanner(
        context=test_plugin_context,
        config=CustomScannerConfig(
            name="test-scanner",
            enabled=True,
            type="CUSTOM",
        ),
        command="cat",
        args={"scan_path_arg": "", "output_arg": ""},
    )

    # Run the scan
    results = scanner.scan(test_file, target_type="source")

    # Check that results were returned
    assert results is not None
