"""Unit tests for dependency scanning functionality."""

import pytest
from datetime import datetime, timezone
from automated_security_helper.models.core import Location
from automated_security_helper.models.dependency_scan import (
    DependencyVulnerability,
    DependencyScanReport,
)


@pytest.fixture
def sample_location():
    """Create a sample location for testing."""
    return Location(file_path="requirements.txt", start_line=10, end_line=11)


@pytest.fixture
def sample_vulnerability(base_scanner, sample_location):
    """Create a sample dependency vulnerability for testing."""
    return DependencyVulnerability(
        id="test_id",
        package_version="1.0.0",
        ecosystem="python",
        title="Test Dependency Vulnerability",
        description="A test dependency vulnerability",
        severity="HIGH",
        scanner=base_scanner,
        location=sample_location,
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        package_name="requests",
        installed_version="2.25.0",
        fixed_version="2.26.0",
        dependency_type="direct",
    )


def test_dependency_vulnerability_creation(base_scanner, sample_location):
    """Test creation of DependencyVulnerability objects."""
    vuln = DependencyVulnerability(
        id="test_id",
        package_version="1.0.0",
        ecosystem="python",
        title="Test Dependency Vulnerability",
        description="A test dependency vulnerability",
        severity="HIGH",
        scanner=base_scanner,
        location=sample_location,
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        package_name="requests",
        installed_version="2.25.0",
        fixed_version="2.26.0",
        dependency_type="direct",
    )
    assert vuln.title == "Test Dependency Vulnerability"
    assert vuln.description == "A test dependency vulnerability"
    assert vuln.severity == "HIGH"
    assert vuln.package_name == "requests"
    assert vuln.installed_version == "2.25.0"
    assert vuln.fixed_version == "2.26.0"
    assert vuln.dependency_type == "direct"


def test_dependency_vulnerability_inheritance(sample_vulnerability):
    """Test that DependencyVulnerability inherits correctly from BaseFinding."""
    assert hasattr(sample_vulnerability, "title")
    assert hasattr(sample_vulnerability, "description")
    assert hasattr(sample_vulnerability, "severity")
    assert hasattr(sample_vulnerability, "scanner")
    assert hasattr(sample_vulnerability, "location")
    assert hasattr(sample_vulnerability, "timestamp")


def test_dependency_vulnerability_invalid_dependency_type(
    base_scanner, sample_location
):
    """Test that invalid dependency type raises ValidationError."""
    with pytest.raises(ValueError):
        DependencyVulnerability(
            title="Test Vulnerability",
            description="A test vulnerability",
            severity="HIGH",
            scanner=base_scanner,
            location=sample_location,
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            package_name="requests",
            installed_version="2.25.0",
            fixed_version="2.26.0",
            dependency_type="invalid",  # Invalid dependency type
        )


def test_dependency_scan_report_creation(sample_vulnerability):
    """Test creation of DependencyScanReport objects."""
    report = DependencyScanReport(
        scanner_name="deps",
        manifest_file="npmaudit.json",
        scan_timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        findings=[sample_vulnerability],
        dependencies={"requests": "2.25.0", "urllib3": "1.26.5"},
    )
    assert len(report.findings) == 1
    assert report.findings[0] == sample_vulnerability
    assert len(report.dependencies) == 2
    assert report.dependencies["requests"] == "2.25.0"


def test_dependency_scan_report_empty():
    """Test creation of empty DependencyScanReport."""
    report = DependencyScanReport(
        scanner_name="deps",
        manifest_file="npmaudit.json",
        scan_timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        findings=[],
        dependencies={},
    )
    assert len(report.findings) == 0
    assert len(report.dependencies) == 0


def test_dependency_scan_report_multiple_vulnerabilities(sample_vulnerability):
    """Test DependencyScanReport with multiple vulnerabilities."""
    vuln2 = DependencyVulnerability(
        id="test_id",
        package_version="1.0.0",
        ecosystem="python",
        title="Another Vulnerability",
        description="Another test vulnerability",
        severity="MEDIUM",
        scanner=sample_vulnerability.scanner,
        location=sample_vulnerability.location,
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        package_name="urllib3",
        installed_version="1.26.5",
        fixed_version="1.26.6",
        dependency_type="transitive",
    )
    report = DependencyScanReport(
        scanner_name="deps",
        manifest_file="npmaudit.json",
        scan_timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        findings=[sample_vulnerability, vuln2],
        dependencies={"requests": "2.25.0", "urllib3": "1.26.5"},
    )
    assert len(report.findings) == 2
    assert any(v.severity == "HIGH" for v in report.findings)
    assert any(v.severity == "MEDIUM" for v in report.findings)
    assert any(v.dependency_type == "direct" for v in report.findings)
    assert any(v.dependency_type == "transitive" for v in report.findings)
