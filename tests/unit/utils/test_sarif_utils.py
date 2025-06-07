import pytest
from pathlib import Path
from automated_security_helper.utils.sarif_utils import get_finding_id, _sanitize_uri, path_matches_pattern
from automated_security_helper.schemas.sarif_schema_model import SarifReport, Run, Tool, ToolComponent


def test_get_finding_id():
    """Test the get_finding_id function."""
    # Test with all parameters
    id1 = get_finding_id("RULE001", "file.py", 10, 20)
    id2 = get_finding_id("RULE001", "file.py", 10, 20)

    # Same inputs should produce same IDs
    assert id1 == id2

    # Different inputs should produce different IDs
    id3 = get_finding_id("RULE002", "file.py", 10, 20)
    assert id1 != id3

    # Test with minimal parameters
    id4 = get_finding_id("RULE001")
    assert id4 != id1  # Should be different from the full parameter version


def test_sanitize_uri():
    """Test the _sanitize_uri function."""
    source_dir_path = Path("/home/user/project").resolve()
    source_dir_str = str(source_dir_path) + "/"

    # Test with file:// prefix
    uri = "file:///home/user/project/src/file.py"
    sanitized = _sanitize_uri(uri, source_dir_path, source_dir_str)
    assert sanitized == "src/file.py"

    # Test with absolute path
    uri = "/home/user/project/src/file.py"
    sanitized = _sanitize_uri(uri, source_dir_path, source_dir_str)
    assert sanitized == "src/file.py"

    # Test with relative path
    uri = "src/file.py"
    sanitized = _sanitize_uri(uri, source_dir_path, source_dir_str)
    assert sanitized == "src/file.py"

    # Test with backslashes
    uri = "src\\file.py"
    sanitized = _sanitize_uri(uri, source_dir_path, source_dir_str)
    assert sanitized == "src/file.py"

    # Test with empty URI
    uri = ""
    sanitized = _sanitize_uri(uri, source_dir_path, source_dir_str)
    assert sanitized == ""


def test_path_matches_pattern():
    """Test the path_matches_pattern function."""
    # Test exact match
    assert path_matches_pattern("src/file.py", "src/file.py") is True

    # Test directory match
    assert path_matches_pattern("src/file.py", "src") is True

    # Test with wildcards
    assert path_matches_pattern("src/file.py", "src/*.py") is True

    # Test with backslashes
    assert path_matches_pattern("src\\file.py", "src") is True

    # Test non-matching path
    assert path_matches_pattern("src/file.py", "tests") is False

    # Test directory with trailing slash
    assert path_matches_pattern("src/subdir/file.py", "src/") is True