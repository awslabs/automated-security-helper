"""Unit tests for data interchange functionality."""

import pytest
import json
from datetime import datetime, timezone
from automated_security_helper.models.core import Location, Scanner, BaseFinding
from automated_security_helper.models.data_interchange import (
    ExportFormat,
    DataInterchange,
    ReportMetadata,
    SecurityReport,
)


@pytest.fixture
def sample_metadata():
    """Create a sample report metadata for testing."""
    return ReportMetadata(
        report_id="report-1",
        tool_name="ash",
        source="test-source",
        scan_type="security",
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


@pytest.fixture
def sample_finding():
    """Create a sample finding for testing."""
    scanner = Scanner(name="test_scanner", version="1.0.0")
    location = Location(file_path="/path/to/file", start_line=10, end_line=20)
    return BaseFinding(
        id="finding-1",
        title="Test Finding",
        description="This is a test finding",
        severity="HIGH",
        scanner=scanner,
        location=location,
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


def test_export_format_values():
    """Test ExportFormat enum values."""
    assert ExportFormat.JSON == "json"
    assert ExportFormat.DICT == "dict"
    assert ExportFormat.SARIF == "sarif"


def test_data_interchange_creation():
    """Test creation of DataInterchange objects."""
    data = DataInterchange(
        name="Test Data", version="1.0.0", description="Test description"
    )
    assert data.name == "Test Data"
    assert data.version == "1.0.0"
    assert data.description == "Test description"


def test_report_metadata_creation(sample_metadata):
    """Test creation of ReportMetadata objects."""
    assert sample_metadata.source == "test-source"
    assert sample_metadata.scan_type == "security"
    assert isinstance(sample_metadata.timestamp, str)


def test_security_report_creation(sample_finding, sample_metadata):
    """Test creation of SecurityReport objects."""
    report = SecurityReport(
        name="Test Report",
        version="1.0.0",
        description="Test security report",
        metadata=sample_metadata,
        findings=[sample_finding],
    )
    assert report.name == "Test Report"
    assert report.metadata == sample_metadata
    assert len(report.findings) == 1
    assert report.findings[0] == sample_finding


def test_security_report_export_json(sample_finding, sample_metadata):
    """Test JSON export functionality."""
    report = SecurityReport(
        name="Test Report",
        version="1.0.0",
        description="Test security report",
        metadata=sample_metadata,
        findings=[sample_finding],
    )
    json_output = report.export(format=ExportFormat.JSON)
    assert isinstance(json_output, str)
    # Verify JSON is valid
    parsed = json.loads(json_output)
    assert parsed["name"] == "Test Report"
    assert len(parsed["findings"]) == 1
    assert "timestamp" in parsed["findings"][0]  # Verify timestamp is in output
    assert "finding_id" not in parsed["findings"][0]  # Verify id is not in output


def test_security_report_export_dict(sample_finding, sample_metadata):
    """Test dictionary export functionality."""
    report = SecurityReport(
        name="Test Report",
        version="1.0.0",
        description="Test security report",
        metadata=sample_metadata,
        findings=[sample_finding],
    )
    dict_output = report.export(format=ExportFormat.DICT)
    assert isinstance(dict_output, dict)
    assert dict_output["name"] == "Test Report"
    assert len(dict_output["findings"]) == 1


def test_security_report_from_json():
    """Test creation of SecurityReport from JSON."""
    json_data = {
        "name": "Test Report",
        "version": "1.0.0",
        "description": "Test security report",
        "metadata": {
            "report_id": "report-1",
            "tool_name": "ash",
            "source": "test-source",
            "scan_type": "security",
            "timestamp": datetime.now().isoformat(timespec="seconds"),
        },
        "findings": [],
    }
    report = SecurityReport.from_json(json_data)
    assert report.name == "Test Report"
    assert report.version == "1.0.0"
    assert report.metadata.source == "test-source"


def test_security_report_track_history(sample_finding):
    """Test history tracking between reports."""
    # Create two reports with different findings
    report1 = SecurityReport(
        name="Test Report",
        version="1.0.0",
        description="Test report 1",
        metadata=ReportMetadata(
            report_id="report-1",
            tool_name="ash",
            source="test-source",
            scan_type="security",
            timestamp=datetime.now().isoformat(timespec="seconds"),
        ),
        findings=[sample_finding],
    )

    report2 = SecurityReport(
        name="Test Report",
        version="1.0.0",
        description="Test report 2",
        metadata=ReportMetadata(
            report_id="report-2",
            tool_name="ash",
            source="test-source",
            scan_type="security",
            timestamp=datetime.now().isoformat(timespec="seconds"),
        ),
        findings=[],  # No findings in second report
    )

    history = report2.track_history(report1)
    assert history["resolved_findings"] == 1  # One finding was resolved
    assert history["new_findings"] == 0  # No new findings
