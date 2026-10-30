import pytest
import json
import tempfile
import os
from pathlib import Path
from unittest.mock import patch
from automated_security_helper.utils.meta_analysis.sarif_analysis import (
    analyze_sarif_file,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def sample_sarif_file_no_scanner():
    """Create a sample SARIF file without scanner name for testing."""
    sarif_content = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "TEST001",
                        "level": "error",
                        "message": {"text": "Test finding"},
                    }
                ]
            }
        ],
    }

    # The scanner is the part of the file name before its first "_": "semgrep"
    # here, whatever tempfile puts after the prefix.
    with tempfile.NamedTemporaryFile(
        prefix="semgrep_", suffix="_bandit.sarif", delete=False
    ) as f:
        f.write(json.dumps(sarif_content).encode("utf-8"))
        return Path(f.name)


@pytest.fixture
def invalid_sarif_file():
    """Create an invalid JSON file for testing error handling."""
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
        f.write(b'{"invalid": "json"')
        return Path(f.name)


@patch(
    "automated_security_helper.utils.meta_analysis.sarif_analysis.SCANNER_NAME_MAP",
    {},
)
def test_analyze_sarif_file_with_provided_scanner():
    """Test analyzing a SARIF file with provided scanner name."""
    # Create a test file that doesn't start with 'tmp' to avoid the special case
    with tempfile.NamedTemporaryFile(
        prefix="test_", suffix=".sarif", delete=False
    ) as f:
        sarif_content = {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "TestScanner"}}}],
        }
        f.write(json.dumps(sarif_content).encode("utf-8"))
        file_path = f.name

    try:
        # The function under test is the imported name; patching its module
        # attribute changed nothing it ran, so the assertion is on the real call.
        field_paths, scanner_name = analyze_sarif_file(
            file_path, scanner_name="CustomScanner"
        )

        # The provided scanner name wins over the driver's, on every field.
        assert scanner_name == "CustomScanner"
        assert field_paths
        assert all(
            info["scanners"] == {"CustomScanner"} for info in field_paths.values()
        )
    finally:
        # Clean up the temporary file
        os.unlink(file_path)


@patch(
    "automated_security_helper.utils.meta_analysis.sarif_analysis.SCANNER_NAME_MAP",
    {},
)
def test_analyze_sarif_file_infer_from_filename(sample_sarif_file_no_scanner):
    """Test inferring scanner name from filename."""
    try:
        # Don't mock the function, let it run with our test file
        field_paths, scanner_name = analyze_sarif_file(
            str(sample_sarif_file_no_scanner)
        )

        # With no tool.driver.name, the scanner is the part of the file name
        # before its first underscore: the fixture's prefix. (A file whose name
        # started with "tmp" used to get hard-coded test data and the name
        # "TestScanner" instead.)
        assert scanner_name == "semgrep"
        assert "runs[0].results[0].ruleId" in field_paths
    finally:
        # Clean up the temporary file
        sample_sarif_file_no_scanner.unlink()


@patch(
    "automated_security_helper.utils.meta_analysis.sarif_analysis.SCANNER_NAME_MAP",
    {},
)
def test_analyze_sarif_file_error_handling():
    """Test error handling when processing an invalid SARIF file."""
    # Create an invalid JSON file that doesn't start with 'tmp'
    with tempfile.NamedTemporaryFile(
        prefix="test_", suffix=".sarif", delete=False
    ) as f:
        f.write(b'{"invalid": "json"')
        file_path = f.name

    try:
        # The real call: a file that is not JSON yields no fields and the name
        # "error" (the patch this test used to wrap itself in was dead, since the
        # imported name is not the module attribute it replaced).
        field_paths, scanner_name = analyze_sarif_file(file_path)

        assert field_paths == {}
        assert scanner_name == "error"
    finally:
        # Clean up the temporary file
        os.unlink(file_path)
