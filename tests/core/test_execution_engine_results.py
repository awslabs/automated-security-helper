"""Tests for ExecutionEngine result handling."""

from pathlib import Path
from typing import Dict, Any

import pytest

from automated_security_helper.core.execution_engine import ScanExecutionEngine
from automated_security_helper.models.scan_results_container import ScanResultsContainer


@pytest.fixture
def mock_scanner_results() -> Dict[str, Any]:
    """Fixture providing mock scanner results."""
    return {
        "findings": [{"id": 1, "severity": "HIGH"}, {"id": 2, "severity": "LOW"}],
        "metadata": {"version": "1.0.0", "scanner": "test_scanner"},
    }


def test_execution_engine_wraps_results(
    mock_scanner_plugin, tmp_path: Path, mock_scanner_results: Dict[str, Any]
):
    """Test that ExecutionEngine properly wraps scanner results."""
    engine = ScanExecutionEngine()

    result = engine._execute_scanner("mock", mock_scanner_plugin(), None)

    assert "container" in result
    assert isinstance(result, ScanResultsContainer)
    assert result.metadata == mock_scanner_results["metadata"]
    assert result.raw_results == mock_scanner_results
