"""Unit tests for core models."""

import pytest
from automated_security_helper.models.core import Location, Scanner, BaseFinding


def test_location_creation():
    """Test creation of Location objects."""
    loc = Location(file_path="/path/to/file", start_line=10, end_line=20)
    assert loc.file_path == "/path/to/file"
    assert loc.start_line == 10
    assert loc.end_line == 20


def test_scanner_creation():
    """Test creation of Scanner objects."""
    scanner = Scanner(
        name="test_scanner", version="1.0.0", rule_id="RULE-001", type="SAST"
    )
    assert scanner.name == "test_scanner"
    assert scanner.version == "1.0.0"
    assert scanner.rule_id == "RULE-001"


def test_base_finding_creation():
    """Test creation of BaseFinding objects."""
    scanner = Scanner(
        name="test_scanner", version="1.0.0", rule_id="RULE-001", type="SAST"
    )
    location = Location(file_path="/path/to/file", start_line=10, end_line=20)
    finding = BaseFinding(
        id="TEST-001",
        title="Test Finding",
        description="This is a test finding",
        severity="HIGH",
        scanner=scanner,
        location=location,
    )
    assert finding.title == "Test Finding"
    assert finding.description == "This is a test finding"
    assert finding.severity == "HIGH"
    assert finding.scanner == scanner
    assert finding.location == location


def test_base_finding_invalid_severity():
    """Test that invalid severity values raise ValidationError."""
    scanner = Scanner(
        name="test_scanner", version="1.0.0", rule_id="RULE-001", type="SAST"
    )
    location = Location(file_path="/path/to/file", start_line=10, end_line=20)
    with pytest.raises(ValueError):
        BaseFinding(
            id="TEST-002",
            title="Test Finding",
            description="This is a test finding",
            severity="INVALID",  # Invalid severity value
            scanner=scanner,
            location=location,
        )
