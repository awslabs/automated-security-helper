"""Unit tests for ASHARP model."""

import pytest
from datetime import datetime, timezone
from automated_security_helper.models.core import Location, Scanner, BaseFinding
from automated_security_helper.models.asharp_model import ASHARPModel


@pytest.fixture
def sample_scanner_dict():
    """Create a sample scanner dictionary."""
    return {
        "name": "test_scanner",
        "version": "1.0.0",
        "type": "SAST",
        "description": "Security scanner",
    }


@pytest.fixture
def sample_finding():
    """Create a sample finding for testing."""
    scanner = Scanner(name="test_scanner", version="1.0.0")
    location = Location(file_path="/path/to/file", start_line=10, end_line=20)
    return BaseFinding(
        id="RULE-001",
        title="Test Finding",
        description="This is a test finding",
        severity="HIGH",
        scanner=scanner,
        location=location,
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


def test_asharp_model_creation():
    """Test creation of ASHARPModel."""
    model = ASHARPModel(name="Test Report", description="Test description", findings=[])
    assert model.name == "Test Report"
    assert model.description == "Test description"
    assert len(model.findings) == 0


def test_asharp_model_findings_management(sample_finding):
    """Test findings management functionality."""
    model = ASHARPModel(
        name="Test Report",
        description="Test description",
        findings=[],
    )

    # Test adding findings
    model.add_finding(sample_finding)
    assert len(model.findings) == 1
    assert model.findings[0] == sample_finding

    # Test deduplication
    model.add_finding(sample_finding)  # Add duplicate
    deduplicated = model.deduplicate_findings()
    assert len(deduplicated) == 1
    assert len(model.findings) == 1  # Check that model.findings was updated

    # Test grouping
    by_type = model.group_findings_by_type()
    assert len(by_type) == 1
    assert "RULE-001" in by_type

    by_severity = model.group_findings_by_severity()
    assert len(by_severity) == 1
    assert "HIGH" in by_severity


def test_asharp_model_scanner_conversion(sample_scanner_dict):
    """Test scanner conversion functionality."""
    model = ASHARPModel(name="Test Report", description="Test")
    scanner = model._convert_to_scanner(sample_scanner_dict)
    assert scanner.name == sample_scanner_dict["name"]
    assert scanner.version == sample_scanner_dict["version"]


def test_asharp_model_scanners_property(sample_finding):
    """Test scanners property."""
    model = ASHARPModel(
        name="Test Report",
        description="Test description",
        findings=[],
        scanners_used=[sample_finding.scanner],
    )
    scanners = model.scanners
    assert len(scanners) == 1
    assert scanners[0].name == sample_finding.scanner.name


def test_asharp_model_trend_analysis(sample_finding):
    """Test trend analysis functionality."""
    model = ASHARPModel(
        name="Test Report",
        description="Test description",
        findings=[],
    )

    # Add findings and record scan time
    model.add_finding(sample_finding)
    scan_time = datetime.now(timezone.utc)
    model.add_scan_findings(scan_time)

    # Test finding counts
    counts = model.get_finding_counts_over_time()
    assert len(counts) == 1
    assert counts[scan_time] == 1

    # Test severity trends
    trends = model.get_severity_trends()
    assert "HIGH" in trends
    assert scan_time in trends["HIGH"]
    assert trends["HIGH"][scan_time] == 1


def test_asharp_model_from_json():
    """Test model creation from JSON."""
    json_data = {
        "name": "Test Report",
        "description": "Test description",
        "findings": [],
    }
    model = ASHARPModel.from_json(json_data)
    assert model.name == "Test Report"
    assert model.description == "Test description"
    assert len(model.findings) == 0
