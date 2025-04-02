"""Common test fixtures for ASHARP tests."""

import pytest
from automated_security_helper.models.config import (
    ASHConfig,
    BuildConfig,
    SASTScannerConfig,
    SBOMScannerConfig,
    ScannerConfig,
)
from automated_security_helper.models.scanner_types import (
    BanditScanner,
    CdkNagPacks,
    CdkNagScannerOptions,
    CfnNagScanner,
    CheckovScanner,
    NpmAuditScanner,
    ScannerOptions,
    SemgrepScanner,
    CdkNagScanner,
    GrypeScanner,
    SyftScanner,
    CustomScanner,
)

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


@pytest.fixture
def ash_config() -> ASHConfig:
    """Create a test ASHConfig object based on default ash.yaml settings."""
    conf = ASHConfig(
        project_name="automated-security-helper",
        build=BuildConfig(
            mode="ASH_MODE_OFFLINE",
            tool_install_scripts={
                "trivy": [
                    "wget https://github.com/aquasecurity/trivy/releases/download/v0.61.0/trivy_0.61.0_Linux-64bit.deb",
                    "dpkg -i trivy_0.61.0_Linux-64bit.deb",
                ]
            },
            custom_scanners={
                "sast": [
                    ScannerConfig(
                        name="trivysast",
                        command="trivy",
                        args=["fs", "--format", "sarif"],
                        output_format="sarif",
                        output_stream="stdio",
                    )
                ],
                "sbom": [
                    ScannerConfig(
                        name="trivysbom",
                        command="trivy",
                        args=["fs", "--format", "cyclonedx"],
                        output_format="cyclonedx",
                        output_stream="stdio",
                    )
                ],
            },
        ),
        fail_on_findings=True,
        ignore_paths=["tests/**"],
        output_dir="ash_output",
        sast=SASTScannerConfig(
            output_formats=["json", "csv", "junitxml", "html"],
            scanners=[
                BanditScanner(),
                CdkNagScanner(
                    cdknag=CdkNagScannerOptions(
                        enabled=True,
                        nag_packs=CdkNagPacks(
                            AwsSolutionsChecks=True,
                            HIPAASecurityChecks=True,
                            NIST80053R4Checks=True,
                            NIST80053R5Checks=True,
                            PCIDSS321Checks=True,
                        ),
                    ),
                ),
                CfnNagScanner(),
                CheckovScanner(),
                CustomScanner(
                    gitsecrets=ScannerOptions(enabled=True),
                ),
                GrypeScanner(),
                NpmAuditScanner(),
                SemgrepScanner(),
                CustomScanner(
                    trivysast=ScannerOptions(enabled=True),
                ),
            ],
        ),
        sbom=SBOMScannerConfig(
            output_formats=["cyclonedx", "html"],
            scanners=[
                SyftScanner(),
                CustomScanner(
                    trivysbom=ScannerOptions(enabled=True),
                ),
            ],
        ),
    )
    return conf
