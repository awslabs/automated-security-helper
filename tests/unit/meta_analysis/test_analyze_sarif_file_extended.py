import pytest
import json
import tempfile
import os
from pathlib import Path
from automated_security_helper.utils.meta_analysis.analyze_sarif_file import analyze_sarif_file


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
                        "message": {
                            "text": "Test finding"
                        }
                    }
                ]
            }
        ]
    }

    with tempfile.NamedTemporaryFile(suffix='_bandit.sarif', delete=False) as f:
        f.write(json.dumps(sarif_content).encode('utf-8'))
        return Path(f.name)


@pytest.fixture
def invalid_sarif_file():
    """Create an invalid JSON file for testing error handling."""
    with tempfile.NamedTemporaryFile(suffix='.sarif', delete=False) as f:
        f.write(b'{"invalid": "json"')
        return Path(f.name)


def test_analyze_sarif_file_with_provided_scanner():
    """Test analyzing a SARIF file with provided scanner name."""
    # Create a test file that doesn't start with 'tmp' to avoid the special case
    with tempfile.NamedTemporaryFile(suffix='.sarif', delete=False) as f:
        sarif_content = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "TestScanner"
                        }
                    }
                }
            ]
        }
        f.write(json.dumps(sarif_content).encode('utf-8'))
        file_path = f.name

    try:
        field_paths, scanner_name = analyze_sarif_file(file_path, scanner_name="CustomScanner")

        # Check that the provided scanner name was used
        assert scanner_name == "CustomScanner"
    finally:
        # Clean up the temporary file
        os.unlink(file_path)


def test_analyze_sarif_file_infer_from_filename(sample_sarif_file_no_scanner):
    """Test inferring scanner name from filename."""
    try:
        # Create a modified version of the file that doesn't start with 'tmp'
        with open(sample_sarif_file_no_scanner, 'r') as f:
            content = f.read()

        new_file_path = str(sample_sarif_file_no_scanner).replace('tmp', 'test')
        with open(new_file_path, 'w') as f:
            f.write(content)

        field_paths, scanner_name = analyze_sarif_file(new_file_path)

        # Check that scanner name was inferred from filename
        assert scanner_name == "bandit"
    finally:
        # Clean up the temporary files
        sample_sarif_file_no_scanner.unlink()
        try:
            os.unlink(new_file_path)
        except:
            pass


def test_analyze_sarif_file_error_handling():
    """Test error handling when processing an invalid SARIF file."""
    # Create an invalid JSON file that doesn't start with 'tmp'
    with tempfile.NamedTemporaryFile(prefix='test', suffix='.sarif', delete=False) as f:
        f.write(b'{"invalid": "json"')
        file_path = f.name

    try:
        field_paths, scanner_name = analyze_sarif_file(file_path)

        # Check that empty results are returned on error
        assert field_paths == {}
        assert scanner_name == "error"
    finally:
        # Clean up the temporary file
        os.unlink(file_path)