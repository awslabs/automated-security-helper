"""Tests for ExecutionEngine result handling."""

from pathlib import Path
from typing import Dict, Any

import pytest

from automated_security_helper.execution_engine import ScanExecutionEngine
from automated_security_helper.models.scan_results import ScanResultsContainer


@pytest.fixture
def mock_scanner_results() -> Dict[str, Any]:
    """Fixture providing mock scanner results."""
    return {
        "findings": [{"id": 1, "severity": "HIGH"}, {"id": 2, "severity": "LOW"}],
        "metadata": {"version": "1.0.0", "scanner": "test_scanner"},
    }


def test_execution_engine_wraps_results(
    tmp_path: Path, mock_scanner_results: Dict[str, Any]
):
    """Test that ExecutionEngine properly wraps scanner results."""
    engine = ScanExecutionEngine()

    # Mock scanner plugin that returns our test results
    class MockScanner:
        def scan(self):
            return mock_scanner_results

    result = engine._execute_scanner((MockScanner(), None))

    assert "container" in result
    assert isinstance(result["container"], ScanResultsContainer)
    assert result["container"].findings == mock_scanner_results["findings"]
    assert result["container"].metadata == mock_scanner_results["metadata"]
    assert result["container"].raw_results == mock_scanner_results
