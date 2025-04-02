"""Unit tests for ASHARP model."""

import pytest
from datetime import datetime
from automated_security_helper.models.core import Location, Scanner, BaseFinding
from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.models.data_interchange import ExportFormat


@pytest.fixture
def sample_scanner_dict():
    """Create a sample scanner dictionary."""
    return {
        "name": "test_scanner",
        "version": "1.0.0",
        "type": "STATIC",
        "rule_id": "RULE-001",
        "description": "Security scanner",
    }


@pytest.fixture
def sample_finding():
    """Create a sample finding for testing."""
    scanner = Scanner(name="test_scanner", version="1.0.0", rule_id="RULE-001")
    location = Location(file_path="/path/to/file", start_line=10, end_line=20)
    return BaseFinding(
        id="ash-1",
        title="Test Finding",
        description="This is a test finding",
        severity="HIGH",
        scanner=scanner,
        location=location,
        timestamp=datetime.now(),
    )


def test_asharp_model_creation():
    """Test creation of ASHARPModel."""
    model = ASHARPModel(
        name="Test Report", version="1.0.0", description="Test description", findings=[]
    )
    assert model.name == "Test Report"
    assert model.version == "1.0.0"
    assert model.description == "Test description"
    assert len(model.findings) == 0


def test_asharp_model_findings_management(sample_finding):
    """Test findings management functionality."""
    model = ASHARPModel(
        name="Test Report",
        version="1.0.0",
        description="Test description",
        findings=[sample_finding],
    )

    # Test deduplication
    model.findings.append(sample_finding)  # Add duplicate
    deduplicated = model.deduplicate_findings()
    assert len(deduplicated) == 1

    # Test grouping
    by_type = model.group_findings_by_type()
    assert len(by_type) == 1
    assert sample_finding.scanner.rule_id in by_type

    by_severity = model.group_findings_by_severity()
    assert len(by_severity) == 1
    assert "HIGH" in by_severity


def test_asharp_model_scanner_conversion(sample_scanner_dict):
    """Test scanner conversion functionality."""
    model = ASHARPModel(name="Test Report", version="1.0.0", description="Test")
    scanner = model._convert_to_scanner(sample_scanner_dict)
    assert scanner.name == sample_scanner_dict["name"]
    assert scanner.version == sample_scanner_dict["version"]
    assert scanner.rule_id == sample_scanner_dict["rule_id"]


def test_asharp_model_scanners_property(sample_finding):
    """Test scanners property."""
    model = ASHARPModel(
        name="Test Report",
        version="1.0.0",
        description="Test description",
        findings=[sample_finding],
        scanners_used=[sample_finding.scanner],
    )
    scanners = model.scanners
    assert len(scanners) == 1
    assert scanners[0].name == sample_finding.scanner.name


def test_asharp_model_export():
    """Test model export functionality."""
    model = ASHARPModel(name="Test Report", version="1.0.0", description="Test")

    # Test JSON export
    json_export = model.export(format=ExportFormat.JSON)
    assert isinstance(json_export, str)
    assert "Test Report" in json_export

    # Test dict export
    dict_export = model.export(format=ExportFormat.DICT)
    assert isinstance(dict_export, dict)
    assert dict_export["name"] == "Test Report"


def test_asharp_model_from_json():
    """Test model creation from JSON."""
    json_data = {
        "name": "Test Report",
        "version": "1.0.0",
        "description": "Test description",
        "findings": [],
    }
    model = ASHARPModel.from_json(json_data)
    assert model.name == "Test Report"
    assert model.version == "1.0.0"
    assert model.description == "Test description"


def test_asharp_model_validate_findings_scanners(sample_finding):
    """Test findings scanners validation."""
    model = ASHARPModel(
        name="Test Report",
        version="1.0.0",
        description="Test description",
        findings=[sample_finding],
    )
    # Should not raise any exceptions
    model.validate_findings_scanners()
