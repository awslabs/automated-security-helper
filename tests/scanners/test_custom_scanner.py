"""Tests for the Custom scanner implementation."""

import json
from datetime import datetime
from pathlib import Path
import pytest
from unittest.mock import MagicMock, patch

from automated_security_helper.scanners.ash_default.custom_scanner import (
    CustomScanner,
    CustomScannerConfig,
    CustomScannerConfigOptions,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.utils.get_ash_version import get_ash_version


@pytest.fixture
def custom_scanner():
    """Create a CustomScanner instance for testing."""
    scanner = CustomScanner(command="custom-scan")
    return scanner


@pytest.fixture
def mock_subprocess_run():
    """Mock subprocess.run for testing."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        yield mock_run


def test_custom_scanner_init(custom_scanner):
    """Test CustomScanner initialization."""
    assert custom_scanner.command == "custom-scan"
    assert custom_scanner.tool_type == "UNKNOWN"
    assert isinstance(custom_scanner.config, CustomScannerConfig)


def test_custom_scanner_validate(custom_scanner):
    """Test CustomScanner validation."""
    custom_scanner.command = "python"
    assert custom_scanner.validate() is True


def test_custom_scanner_no_command():
    """Test CustomScanner with no command specified."""
    with pytest.raises(ScannerError) as exc_info:
        CustomScanner()
        assert "(custom) Command not provided for custom scanner!" in exc_info


def test_custom_scanner_configure():
    """Test CustomScanner configuration."""
    scanner = CustomScanner(
        command="custom-scan",
        config=CustomScannerConfig(
            name="test-scanner",
            enabled=True,
            type="CUSTOM",
            options=CustomScannerConfigOptions(),
        ),
    )
    assert scanner.config.name == "test-scanner"
    assert scanner.config.enabled is True
    assert scanner.config.type == "CUSTOM"


@pytest.mark.asyncio
async def test_custom_scanner_scan(custom_scanner, mock_subprocess_run, tmp_path):
    """Test CustomScanner scan execution with mock results."""
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    # Mock scanner output
    mock_results = {
        "results": [
            {
                "check_id": "TEST-001",
                "check_name": "Test finding",
                "file_path": "test.py",
                "file_line_range": [10, 15],
            }
        ]
    }
    custom_scanner.output = [json.dumps(mock_results)]

    result = custom_scanner.scan(target_dir, target_type="source")

    assert result is not None
    assert len(result.runs) == 1
    assert result.runs[0].tool.driver.name == custom_scanner.config.name
    assert result.runs[0].tool.driver.version == get_ash_version()

    # Verify SARIF report structure
    assert result.runs[0].results
    finding = result.runs[0].results[0]
    assert finding.ruleId == "TEST-001"
    assert finding.message.root.text == "Test finding"
    assert finding.locations[0].physicalLocation.root.artifactLocation.uri == "test.py"
    assert finding.locations[0].physicalLocation.root.region.startLine == 10
    assert finding.locations[0].physicalLocation.root.region.endLine == 15


def test_custom_scanner_scan_error(custom_scanner, mock_subprocess_run):
    """Test CustomScanner scan with error."""
    mock_subprocess_run.side_effect = Exception("Scan failed")
    custom_scanner.errors = ["Error details"]

    with pytest.raises(ScannerError) as exc_info:
        custom_scanner.scan(Path("/nonexistent"), target_type="source")
    assert "Target /nonexistent does not exist!" in str(exc_info.value)


def test_custom_scanner_with_empty_results(custom_scanner, tmp_path):
    """Test CustomScanner with empty results."""
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    # Mock empty results
    mock_results = {"results": []}
    custom_scanner.output = [json.dumps(mock_results)]

    result = custom_scanner.scan(target_dir, target_type="source")

    assert result is not None
    assert len(result.runs) == 1
    assert len(result.runs[0].results) == 0


def test_custom_scanner_sarif_metadata(custom_scanner, tmp_path):
    """Test CustomScanner SARIF metadata."""
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    mock_results = {"results": []}
    custom_scanner.output = [json.dumps(mock_results)]

    result = custom_scanner.scan(target_dir, target_type="source")

    # Verify SARIF metadata
    assert result.properties.ashVersion == get_ash_version()
    assert result.properties.timestamp is not None
    assert isinstance(datetime.fromisoformat(result.properties.timestamp), datetime)
    assert result.properties.scannerConfig == custom_scanner.config.model_dump(
        by_alias=True
    )


def test_custom_scanner_with_multiple_findings(custom_scanner, tmp_path):
    """Test CustomScanner with multiple findings."""
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    # Mock multiple findings
    mock_results = {
        "results": [
            {
                "check_id": "TEST-001",
                "check_name": "First finding",
                "file_path": "test1.py",
                "file_line_range": [10, 15],
            },
            {
                "check_id": "TEST-002",
                "check_name": "Second finding",
                "file_path": "test2.py",
                "file_line_range": [20, 25],
            },
        ]
    }
    custom_scanner.output = [json.dumps(mock_results)]

    result = custom_scanner.scan(target_dir, target_type="source")

    assert result is not None
    assert len(result.runs[0].results) == 2
    assert result.runs[0].results[0].ruleId == "TEST-001"
    assert result.runs[0].results[1].ruleId == "TEST-002"
