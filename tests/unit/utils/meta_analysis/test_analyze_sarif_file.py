import pytest
import json
import tempfile
from pathlib import Path
from automated_security_helper.utils.meta_analysis.analyze_sarif_file import (
    analyze_sarif_file,
)


@pytest.fixture
def sample_sarif_file():
    """Create a sample SARIF file for testing."""
    sarif_content = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "TestScanner", "version": "1.0.0"}},
                "results": [
                    {
                        "ruleId": "TEST001",
                        "level": "error",
                        "message": {"text": "Test finding"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "test.py"},
                                    "region": {"startLine": 10, "endLine": 15},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }

    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
        f.write(json.dumps(sarif_content).encode("utf-8"))
        return Path(f.name)


def test_analyze_sarif_file(sample_sarif_file):
    """Test analyzing a SARIF file."""
    try:
        field_paths, scanner_name = analyze_sarif_file(str(sample_sarif_file))

        # Check scanner name detection
        assert scanner_name == "TestScanner"

        # Check that field paths were extracted
        assert len(field_paths) > 0

        # Check that some expected fields were found
        assert any("version" in path for path in field_paths.keys())
        assert any("runs[0].tool.driver.name" in path for path in field_paths.keys())
        assert any("runs[0].results[0].ruleId" in path for path in field_paths.keys())
        assert any("runs[0].results[0].level" in path for path in field_paths.keys())

        # Check that scanner name was added to each field
        for path_info in field_paths.values():
            assert "scanners" in path_info
            assert "TestScanner" in path_info["scanners"]
    finally:
        # Clean up the temporary file
        sample_sarif_file.unlink()
