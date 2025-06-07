"""Unit tests for analyze_sarif_file module to increase coverage."""

import json
from unittest.mock import patch, mock_open

import pytest

from automated_security_helper.utils.meta_analysis.analyze_sarif_file import (
    analyze_sarif_file,
)


def test_analyze_sarif_file():
    """Test analyze_sarif_file function."""
    # Create mock SARIF data
    sarif_data = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "TestTool",
                        "rules": [
                            {"id": "rule1", "name": "Rule 1"},
                            {"id": "rule2", "name": "Rule 2"},
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "rule1",
                        "message": {"text": "Finding 1"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "file1.py"},
                                    "region": {"startLine": 10},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "rule2",
                        "message": {"text": "Finding 2"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "file2.py"},
                                    "region": {"startLine": 20},
                                }
                            }
                        ],
                    },
                ],
            }
        ],
    }

    # Mock open to return the SARIF data
    with patch("builtins.open", mock_open(read_data=json.dumps(sarif_data))):
        # Call analyze_sarif_file
        result = analyze_sarif_file("test.sarif")

        # Verify result
        assert result["version"] == "2.1.0"
        assert len(result["results"]) == 2
        assert result["results"][0]["ruleId"] == "rule1"
        assert result["results"][1]["ruleId"] == "rule2"
        assert result["tool_name"] == "TestTool"
        assert len(result["rules"]) == 2
        assert result["rules"][0]["id"] == "rule1"
        assert result["rules"][1]["id"] == "rule2"


def test_analyze_sarif_file_with_invalid_json():
    """Test analyze_sarif_file function with invalid JSON."""
    # Mock open to return invalid JSON
    with patch("builtins.open", mock_open(read_data="invalid json")):
        # Call analyze_sarif_file
        with pytest.raises(ValueError):
            analyze_sarif_file("test.sarif")


def test_analyze_sarif_file_with_file_not_found():
    """Test analyze_sarif_file function with file not found."""
    # Mock open to raise FileNotFoundError
    with patch("builtins.open", side_effect=FileNotFoundError):
        # Call analyze_sarif_file
        with pytest.raises(FileNotFoundError):
            analyze_sarif_file("test.sarif")
