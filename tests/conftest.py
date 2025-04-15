"""Common test fixtures for ASHARP tests."""

from pathlib import Path
import shutil
import sys
import pytest
import yaml
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.config.ash_config import (
    ASHConfig,
    BuildConfig,
    ScannerConfigSegment,
)
from automated_security_helper.config.scanner_types import (
    CfnNagScannerConfig,
    NpmAuditScannerConfig,
    SemgrepScannerConfig,
    GrypeScannerConfig,
    SyftScannerConfig,
    CustomScannerConfig,
)

from automated_security_helper.core.constants import ASH_DOCS_URL, ASH_REPO_URL
from automated_security_helper.models.core import (
    ExportFormat,
    Location,
    Scanner,
    ToolArgs,
    ToolExtraArg,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.models.security_vulnerability import (
    SecurityVulnerability,
)
from automated_security_helper.scanners.ash_default.bandit_scanner import (
    BanditScannerConfig,
)
from automated_security_helper.scanners.ash_default.cdk_nag_scanner import (
    CdkNagPacks,
    CdkNagScannerConfig,
    CdkNagScannerConfigOptions,
)
from automated_security_helper.scanners.ash_default.checkov_scanner import (
    CheckovScannerConfig,
)
from automated_security_helper.scanners.ash_default.detect_secrets_scanner import (
    DetectSecretsScannerConfig,
    DetectSecretsScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.get_ash_version import get_ash_version


TEST_DIR = Path(__file__).parent.joinpath("pytest-temp")
if TEST_DIR.exists():
    shutil.rmtree(TEST_DIR.as_posix())
TEST_DIR.mkdir(parents=True, exist_ok=True)
TEST_SOURCE_DIR = TEST_DIR.joinpath("source")
TEST_OUTPUT_DIR = TEST_DIR.joinpath("ash_output")


def is_debugging():
    return "debugpy" in sys.modules


# enable_stop_on_exceptions if the debugger is running during a test
if is_debugging():

    @pytest.hookimpl(tryfirst=True)
    def pytest_exception_interact(call):
        raise call.excinfo.value

    @pytest.hookimpl(tryfirst=True)
    def pytest_internalerror(excinfo):
        raise excinfo.value


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
    return Scanner(name="base_scanner", version="1.0.0", type="SAST")


@pytest.fixture
def container_scanner():
    """Create a container scanner instance."""
    return Scanner(
        name="container_scanner",
        version="1.0.0",
        type="CONTAINER",
    )


@pytest.fixture
def dependency_scanner():
    """Create a dependency scanner instance."""
    return Scanner(
        name="dependency_scanner",
        version="1.0.0",
        type="DEPENDENCY",
    )


@pytest.fixture
def iac_scanner():
    """Create an IAC scanner instance."""
    return Scanner(name="iac_scanner", version="1.0.0", type="IAC")


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


class MockScannerPlugin(ScannerPluginBase[ScannerPluginConfigBase]):
    def validate(self):
        return True

    def scan(self, target, config=None, *args, **kwargs):
        return SarifReport(
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="ASH Aggregated Results",
                            fullName="awslabs/automated-security-helper",
                            version=get_ash_version(),
                            organization="Amazon Web Services",
                            downloadUri=ASH_REPO_URL,
                            informationUri=ASH_DOCS_URL,
                        ),
                        extensions=[],
                    ),
                    results=[],
                    invocations=[],
                )
            ],
        )


@pytest.fixture
def mock_scanner_plugin():
    return MockScannerPlugin


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
            custom_scanners=[
                MockScannerPlugin(
                    config=ScannerPluginConfigBase(
                        name="trivy-sast",
                    ),
                    command="trivy",
                    args=ToolArgs(
                        format_arg="--format",
                        format_arg_value="sarif",
                        extra_args=[
                            ToolExtraArg(
                                key="fs",
                                value=None,
                            )
                        ],
                    ),
                ),
                MockScannerPlugin(
                    config=ScannerPluginConfigBase(
                        name="trivy-sbom",
                    ),
                    command="trivy",
                    args=ToolArgs(
                        format_arg="--format",
                        format_arg_value="cyclonedx",
                        extra_args=[
                            ToolExtraArg(
                                key="fs",
                                value=None,
                            )
                        ],
                    ),
                ),
            ],
        ),
        fail_on_findings=True,
        ignore_paths=["tests/**"],
        output_dir="ash_output",
        converters={
            "jupyter": True,
            "archive": True,
        },
        no_cleanup=True,
        output_formats=[
            ExportFormat.HTML.value,
            ExportFormat.JUNITXML.value,
            ExportFormat.SARIF.value,
            ExportFormat.CYCLONEDX.value,
        ],
        severity_threshold="ALL",
        scanners=ScannerConfigSegment(
            bandit=BanditScannerConfig(),
            cdk_nag=CdkNagScannerConfig(
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
            cfn_nag=CfnNagScannerConfig(),
            checkov=CheckovScannerConfig(),
            detect_secrets=DetectSecretsScannerConfig(
                options=DetectSecretsScannerConfigOptions(enabled=True),
            ),
            grype=GrypeScannerConfig(),
            npm_audit=NpmAuditScannerConfig(),
            semgrep=SemgrepScannerConfig(),
            trivy_sast=CustomScannerConfig(
                name="trivy-sast",
                options=ScannerOptionsBase(enabled=True),
                enabled=True,
                type="SAST",
            ),
            syft=SyftScannerConfig(),
            trivy_sbom=CustomScannerConfig(
                name="trivy-sbom",
                options=ScannerOptionsBase(enabled=True),
                enabled=True,
                type="SBOM",
            ),
        ),
    )
    return conf
