"""Unit tests for core models."""

from automated_security_helper.models.core import Location, Scanner


def test_location_creation():
    """Test creation of Location objects."""
    loc = Location(file_path="/path/to/file", start_line=10, end_line=20)
    assert loc.file_path == "/path/to/file"
    assert loc.start_line == 10
    assert loc.end_line == 20


def test_scanner_creation():
    """Test creation of Scanner objects."""
    scanner = Scanner(name="test_scanner", version="1.0.0", type="SAST")
    assert scanner.name == "test_scanner"
    assert scanner.version == "1.0.0"
