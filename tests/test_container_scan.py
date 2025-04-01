"""Unit tests for container scan functionality."""

import pytest
from datetime import datetime, timezone
from automated_security_helper.models.core import Location, Scanner
from automated_security_helper.models.container_scan import (
    ContainerVulnerability,
    ContainerScanReport,
)


@pytest.fixture
def sample_location(base_location):
    """Create a sample location for testing."""
    return Location(file_path="Dockerfile", start_line=10, end_line=11)


@pytest.fixture
def sample_vulnerability(base_scanner, sample_location):
    """Create a sample container vulnerability for testing."""
    return ContainerVulnerability(
        id=f"CVE-{round(datetime.now().timestamp())}",
        title="Test Vulnerability",
        description="A test container vulnerability",
        severity="HIGH",
        scanner=base_scanner,
        location=sample_location,
        package_name="test-package",
        package_version="1.0.0",
        installed_version="1.0.0",
        fix_version="1.1.0",
    )


def test_container_vulnerability_creation(base_scanner, sample_location):
    """Test creation of ContainerVulnerability objects."""
    vuln = ContainerVulnerability(
        id=f"CVE-{round(datetime.now().timestamp())}",
        title="Test Vulnerability",
        description="A test container vulnerability",
        severity="HIGH",
        scanner=base_scanner,
        location=sample_location,
        package_name="test-package",
        package_version="1.0.0",
        installed_version="1.0.0",
        fix_version="1.1.0",
    )
    assert vuln.title == "Test Vulnerability"
    assert vuln.description == "A test container vulnerability"
    assert vuln.severity == "HIGH"
    assert vuln.package_name == "test-package"
    assert vuln.package_version == "1.0.0"
    assert vuln.fix_version == "1.1.0"


def test_container_vulnerability_inheritance(sample_vulnerability):
    """Test that ContainerVulnerability inherits correctly from BaseFinding."""
    assert hasattr(sample_vulnerability, "title")
    assert hasattr(sample_vulnerability, "description")
    assert hasattr(sample_vulnerability, "severity")
    assert hasattr(sample_vulnerability, "scanner")
    assert hasattr(sample_vulnerability, "location")
    assert hasattr(sample_vulnerability, "timestamp")


def test_container_scan_report_creation(sample_vulnerability):
    """Test creation of ContainerScanReport objects."""
    report = ContainerScanReport(
        image_name="test-image",
        image_tag="latest",
        scan_timestamp=datetime.now(timezone.utc).strftime("%Y-%M-%d"),
        scanner_name="test",
        findings=[sample_vulnerability],
    )
    assert report.image_name == "test-image"
    assert report.image_tag == "latest"
    assert len(report.findings) == 1
    assert report.findings[0] == sample_vulnerability


def test_container_scan_report_empty():
    """Test creation of empty ContainerScanReport."""
    report = ContainerScanReport(
        scan_timestamp=datetime.now(timezone.utc).strftime("%Y-%M-%d"),
        scanner_name="test",
        image_name="test-image",
        image_tag="latest",
        findings=[],
    )
    assert report.image_name == "test-image"
    assert report.image_tag == "latest"
    assert len(report.findings) == 0


def test_container_scan_report_multiple_vulnerabilities(sample_vulnerability):
    """Test ContainerScanReport with multiple vulnerabilities."""
    vuln2 = ContainerVulnerability(
        id=f"CVE-{round(datetime.now().timestamp())}",
        title="Another Vulnerability",
        description="Another test vulnerability",
        severity="MEDIUM",
        scanner=sample_vulnerability.scanner,
        location=sample_vulnerability.location,
        timestamp=datetime.now(),
        package_name="another-package",
        package_version="2.0.0",
        installed_version="2.0.0",
        fix_version="2.1.0",
    )
    report = ContainerScanReport(
        image_name="test-image",
        image_tag="latest",
        scan_timestamp=datetime.now(timezone.utc).strftime("%Y-%M-%d"),
        scanner_name="test",
        findings=[sample_vulnerability, vuln2],
    )
    assert len(report.findings) == 2
    assert any(v.severity == "HIGH" for v in report.findings)
    assert any(v.severity == "MEDIUM" for v in report.findings)
