"""Unit tests for Software Bill of Materials (SBOM) functionality."""

import pytest
from datetime import datetime, timezone
from automated_security_helper.models.core import Location, Scanner
from automated_security_helper.models.sbom import (
    SBOMComponent,
    SBOMMetadata,
    SBOMPackage,
    SBOMReport,
)


@pytest.fixture
def sample_package():
    """Create a sample package for testing."""
    dep1 = SBOMPackage(
        name="urllib3",
        version="1.26.6",
        type="pypi",
        dependencies=[],
        license="MIT",
        publisher="urllib3",
    )
    dep2 = SBOMPackage(
        name="certifi",
        version="2021.5.30",
        type="pypi",
        dependencies=[],
        license="MPL-2.0",
        publisher="certifi",
    )
    return SBOMPackage(
        name="requests",
        version="2.26.0",
        type="pypi",
        dependencies=[dep1, dep2],
        license="Apache-2.0",
        publisher="Kenneth Reitz",
        metadata={
            "description": "Python HTTP for Humans",
            "homepage": "https://requests.readthedocs.io",
        },
    )


def test_sbom_package_creation(sample_package):
    """Test creation of SBOMPackage objects."""
    assert sample_package.name == "requests"
    assert sample_package.version == "2.26.0"
    assert sample_package.type == "pypi"
    assert len(sample_package.dependencies) == 2
    assert sample_package.license == "Apache-2.0"
    assert sample_package.publisher == "Kenneth Reitz"


def test_sbom_package_invalid_type():
    """Test that invalid package type raises ValidationError."""
    with pytest.raises(ValueError):
        SBOMPackage(
            name="requests",
            version="2.26.0",
            type="invalid",  # Invalid package type
            dependencies=[],
            metadata={},
        )


def test_sbom_report_creation(sample_package):
    """Test creation of SBOMReport objects."""
    report = SBOMReport(
        name="test-sbom",
        project_name="test-project",
        version=datetime.now(timezone.utc).strftime("%Y.%m.%d"),
        generated_at=datetime.now(),
        packages=[sample_package],
        metadata=[SBOMMetadata(
            component=SBOMComponent(
                name="requests",
                version="2.26.0",
                license="Apache-2.0",
                type="pypi",
                publisher="Kenneth Reitz",
            )
        )]
    )
    assert report.project_name == "test-project"
    assert len(report.packages) == 1
    assert report.packages[0] == sample_package


def test_sbom_report_empty():
    """Test creation of empty SBOMReport."""
    report = SBOMReport(
        name="test-sbom",
        project_name="test-project",
        version=datetime.now(timezone.utc).strftime("%Y.%m.%d"),
        generated_at=datetime.now(),
        packages=[],
        metadata=[
            SBOMMetadata(
                component=SBOMComponent(
                    name="requests",
                    version="2.26.0",
                    license="Apache-2.0",
                    type="pypi",
                    publisher="Kenneth Reitz",
                )
            )
        ],
    )
    assert report.project_name == "test-project"
    assert len(report.packages) == 0


def test_sbom_report_multiple_packages(sample_package):
    """Test SBOMReport with multiple packages."""
    package2 = SBOMPackage(
        name="flask",
        version="2.0.1",
        type="pypi",
        dependencies=[
            {"name": "werkzeug", "version": "2.0.1", "type": "pypi"},
            {"name": "jinja2", "version": "3.0.1", "type": "pypi"},
        ],
        metadata={
            "author": "Armin Ronacher",
            "license": "BSD-3-Clause",
            "description": "Python micro framework",
        },
    )

    report = SBOMReport(
        name="test-sbom",
        project_name="test-project",
        version=datetime.now(timezone.utc).strftime("%Y.%m.%d"),
        generated_at=datetime.now(),
        packages=[sample_package, package2],
        metadata=[
            SBOMMetadata(
                component=SBOMComponent(
                    name="requests",
                    version="2.26.0",
                    license="Apache-2.0",
                    type="pypi",
                    publisher="Kenneth Reitz",
                )
            )
        ],
    )
    assert len(report.packages) == 2
    assert any(p.name == "requests" for p in report.packages)
    assert any(p.name == "flask" for p in report.packages)


def test_sbom_package_license_check(sample_package):
    """Test package license validation."""
    # Test valid licenses
    valid_licenses = ["MIT", "Apache 2.0", "GPL-3.0", "BSD-3-Clause"]
    for license in valid_licenses:
        package = SBOMPackage(
            name="test",
            version="1.0.0",
            type="pypi",
            dependencies=[],
            metadata={"license": license},
        )
        assert package.metadata["license"] == license


def test_sbom_package_version_validation():
    """Test package version format validation."""
    valid_versions = ["1.0.0", "2.3.4-alpha", "0.1.0-rc1", "1.0.0.dev0"]
    for version in valid_versions:
        package = SBOMPackage(
            name="test", version=version, type="pypi", dependencies=[], metadata={}
        )
        assert package.version == version


def test_sbom_report_dependency_tree(sample_package):
    """Test dependency tree generation in SBOM report."""
    report = SBOMReport(
        name="test-sbom",
        project_name="test-project",
        generated_at=datetime.now(),
        version=datetime.now(timezone.utc).strftime("%Y.%m.%d"),
        packages=[sample_package],
        metadata=[
            SBOMMetadata(
                component=SBOMComponent(
                    name="requests",
                    version="2.26.0",
                    license="Apache-2.0",
                    type="pypi",
                    publisher="Kenneth Reitz",
                )
            )
        ],
    )

    dep_tree = report.get_dependency_tree()
    assert "requests" in dep_tree
    assert "urllib3" in str(dep_tree)  # Should be in the nested structure
    assert "certifi" in str(dep_tree)  # Should be in the nested structure


def test_sbom_report_export(sample_package):
    """Test SBOM report export functionality."""
    report = SBOMReport(
        project_name="test-project",
        name="test-sbom",
        version=datetime.now(timezone.utc).strftime("%Y.%m.%d"),
        generated_at=datetime.now(),
        packages=[sample_package],
        metadata=[
            SBOMMetadata(
                component=SBOMComponent(
                    name="requests",
                    version="2.26.0",
                    license="Apache-2.0",
                    type="pypi",
                    publisher="Kenneth Reitz",
                )
            )
        ],
    )

    # Test CycloneDX format export
    cyclonedx = report.export(format="cyclonedx")
    assert isinstance(cyclonedx, dict)
    assert "requests" in cyclonedx["packages"][0]["name"]
    assert "2.26.0" in cyclonedx["packages"][0]["version"]

    # Test SPDX format export
    spdx = report.export(format="spdx")
    assert isinstance(spdx, dict)
    assert "requests" in spdx["packages"][0]["name"]
    assert "2.26.0" in spdx["packages"][0]["version"]
