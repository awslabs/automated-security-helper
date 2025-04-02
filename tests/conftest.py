"""Common test fixtures for ASHARP tests."""

import pytest

from automated_security_helper.models.core import Location, Scanner
from automated_security_helper.models.security_vulnerability import (
    SecurityVulnerability,
)


@pytest.fixture
def base_location():
    """Create a base location instance for testing."""
    return Location(file_path="/path/to/file", start_line=10, end_line=5)


@pytest.fixture
def base_scanner():
    """Create a base scanner instance for testing."""
    return Scanner(
        name="base_scanner", version="1.0.0", rule_id="TEST-001", type="SAST"
    )


@pytest.fixture
def container_scanner():
    """Create a container scanner instance."""
    return Scanner(
        name="container_scanner",
        version="1.0.0",
        rule_id="CVE-2023-001",
        type="CONTAINER",
    )


@pytest.fixture
def dependency_scanner():
    """Create a dependency scanner instance."""
    return Scanner(
        name="dependency_scanner",
        version="1.0.0",
        rule_id="CVE-2023-1234",
        type="DEPENDENCY",
    )


@pytest.fixture
def iac_scanner():
    """Create an IAC scanner instance."""
    return Scanner(name="iac_scanner", version="1.0.0", rule_id="IAC-001", type="IAC")


# Legacy fixtures for backward compatibility
@pytest.fixture
def sample_scanner():
    """Create a sample scanner instance for testing."""
    return base_scanner()


@pytest.fixture
def sample_location():
    """Create a sample location instance for testing."""
    return base_location()


@pytest.fixture
def sample_vulnerability(sample_scanner, sample_location):
    """Create a sample vulnerability instance for testing."""
    return SecurityVulnerability(
        scanner=sample_scanner,
        location=sample_location,
        title="Test Vulnerability",
        severity="HIGH",
        description="A test vulnerability",
        recommendation="Fix the vulnerability",
    )
