"""Common test fixtures for ASHARP tests."""

from pathlib import Path
import pytest
import yaml
from automated_security_helper.config.config import (
    ASHConfig,
    BuildConfig,
    SASTScannerConfig,
    SASTScannerListConfig,
    SBOMScannerConfig,
    SBOMScannerListConfig,
    ScannerPluginConfig,
)
from automated_security_helper.config.scanner_types import (
    BanditScannerConfig,
    CdkNagPacks,
    CdkNagScannerConfigOptions,
    CfnNagScannerConfig,
    CheckovScannerConfig,
    GitSecretsScannerConfig,
    NpmAuditScannerConfig,
    BaseScannerOptions,
    SemgrepScannerConfig,
    CdkNagScannerConfig,
    GrypeScannerConfig,
    SyftScannerConfig,
    CustomScannerConfig,
)

from automated_security_helper.models.core import Location, Scanner
from automated_security_helper.models.security_vulnerability import (
    SecurityVulnerability,
)


TEST_DIR = Path(__file__).parent.joinpath("pytest-temp")
TEST_SOURCE_DIR = TEST_DIR.joinpath("source")
TEST_OUTPUT_DIR = TEST_DIR.joinpath("output")


@pytest.fixture
def test_source_dir() -> Path:
    """Create a temporary source directory."""
    if not TEST_SOURCE_DIR.exists():
        TEST_SOURCE_DIR.mkdir(parents=True)
    return TEST_SOURCE_DIR


@pytest.fixture
def test_output_dir() -> Path:
    """Create a temporary output directory."""
    if not TEST_OUTPUT_DIR.exists():
        TEST_OUTPUT_DIR.mkdir(parents=True)
    return TEST_OUTPUT_DIR


@pytest.fixture
def sample_config():
    return {
        "scanners": {"bandit": {"type": "static", "config_file": "bandit.yaml"}},
        "parsers": {"bandit": {"format": "json"}},
    }


@pytest.fixture
def config_file(test_source_dir):
    # Create a temporary config file
    with open(test_source_dir.joinpath("config.yaml"), "w") as f:
        yaml.dump(
            {
                "scanners": {
                    "bandit": {"type": "static", "config_file": "bandit.yaml"}
                },
                "parsers": {"bandit": {"format": "json"}},
            },
            f,
        )
        return f.name


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
                    ScannerPluginConfig(
                        name="trivy-sast",
                        command="trivy",
                        args=["fs", "--format", "sarif"],
                        output_format="sarif",
                        output_stream="stdio",
                        get_tool_version_command=[
                            "trivy",
                            "--version",
                        ],
                        format_arg="--format",
                        format_arg_value="sarif",
                        format_arg_position="before_args",
                        scan_path_arg_position="after_args",
                        invocation_mode="directory",
                        type="SAST",
                    )
                ],
                "sbom": [
                    ScannerPluginConfig(
                        name="trivy-sbom",
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
            scanners=SASTScannerListConfig(
                bandit=BanditScannerConfig(),
                cdknag=CdkNagScannerConfig(
                    enabled=True,
                    options=CdkNagScannerConfigOptions(
                        nag_packs=CdkNagPacks(
                            AwsSolutionsChecks=True,
                            HIPAASecurityChecks=True,
                            NIST80053R4Checks=True,
                            NIST80053R5Checks=True,
                            PCIDSS321Checks=True,
                        ),
                    ),
                ),
                cfnnag=CfnNagScannerConfig(),
                checkov=CheckovScannerConfig(),
                gitsecrets=GitSecretsScannerConfig(
                    options=BaseScannerOptions(enabled=True),
                ),
                grype=GrypeScannerConfig(),
                npmaudit=NpmAuditScannerConfig(),
                semgrep=SemgrepScannerConfig(),
                trivysasy=CustomScannerConfig(
                    name="trivy-sast",
                    type="SAST",
                    custom=BaseScannerOptions(enabled=True),
                ),
            ),
        ),
        sbom=SBOMScannerConfig(
            output_formats=["cyclonedx", "html"],
            scanners=SBOMScannerListConfig(
                syft=SyftScannerConfig(),
                trivysbom=CustomScannerConfig(
                    name="trivy-sbom",
                    type="SBOM",
                    custom=BaseScannerOptions(enabled=True),
                ),
            ),
        ),
    )
    return conf
