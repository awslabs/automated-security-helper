"""Unit tests for result processor module."""

import json
import pytest
from typing import Any, Dict, List, Union
from automated_security_helper.schemas.data_interchange import ReportMetadata
from automated_security_helper.core.result_processor import (
    ResultProcessor,
    IResultParser,
    ASHARPModel,
)


class MockParser(IResultParser):
    def parse(
        self, raw_results: str
    ) -> Dict[str, Union[List[Dict[str, Any]], Dict[str, str]]]:
        """Parse raw results and return findings and metadata."""
        default_data = {
            "findings": [
                {
                    "id": "TEST-1",
                    "severity": "HIGH",
                    "description": "Test finding",
                    "location": "test.py:10",
                }
            ],
            "metadata": {"scanner": "mock-scanner", "version": "1.0.0"},
        }
        try:
            data = json.loads(raw_results)
            if "findings" in data:
                default_data["findings"] = data["findings"]
            if "metadata" in data:
                default_data["metadata"].update(data["metadata"])
        except json.JSONDecodeError:
            pass  # Use default data on invalid JSON
        return default_data


def test_ash_model():
    """Test ASHARPModel initialization and property assignment."""
    model = ASHARPModel()
    assert isinstance(model.metadata, ReportMetadata)
    assert len(model.metadata.__dict__.keys()) == 6

    # Test property assignment
    test_metadata = {"scanner": "test"}
    model.metadata = test_metadata
    assert model.metadata["scanner"] == "test"


def test_result_processor_registration():
    """Test parser registration."""
    processor = ResultProcessor()
    processor.register_parser("mock-scanner", MockParser)
    parser = processor.get_parser("mock-scanner")
    assert isinstance(parser, MockParser)


def test_get_parser():
    """Test get_parser with invalid scanner type."""
    processor = ResultProcessor()
    with pytest.raises(ValueError):
        processor.get_parser("invalid-scanner")


def test_process_results_invalid_scanner():
    processor = ResultProcessor()
    with pytest.raises(ValueError):
        processor.process_results("invalid-scanner", "{}")
