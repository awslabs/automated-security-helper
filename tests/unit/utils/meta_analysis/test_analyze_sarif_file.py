import pytest
import json
import tempfile
from pathlib import Path
from automated_security_helper.utils.meta_analysis.sarif_analysis import (
    analyze_sarif_file,
)

pytestmark = pytest.mark.unit


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


def test_a_real_report_yields_its_field_paths_whatever_its_file_name(tmp_path):
    """The paths come from the parsed report. A file whose name did not start with
    "tmp" got an empty dict (only "tmp" names got hard-coded test data)."""
    report = tmp_path / "bandit.sarif"
    report.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "Bandit"}},
                        "results": [
                            {
                                "ruleId": "B101",
                                "level": "warning",
                                "message": {"text": "assert used"},
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    field_paths, scanner_name = analyze_sarif_file(str(report))

    assert scanner_name == "bandit"  # mapped through SCANNER_NAME_MAP
    assert "runs[0].results[0].ruleId" in field_paths
    assert "runs[0].results[0].message.text" in field_paths
    assert field_paths["version"]["scanners"] == {"bandit"}
