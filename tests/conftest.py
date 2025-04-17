"""Common test fixtures for ASHARP tests."""

import json
from pathlib import Path
import shutil
import pytest

# Core imports needed for basic fixtures
from automated_security_helper.core.constants import ASH_DOCS_URL, ASH_REPO_URL
from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.utils.get_ash_version import get_ash_version


# Lazy imports for specific fixtures
def lazy_import(module_path, *names):
    """Lazily import modules/objects when needed."""
    import importlib

    module = importlib.import_module(module_path)
    if not names:
        return module
    return tuple(getattr(module, name) for name in names)


TEST_DIR = Path(__file__).parent.joinpath("pytest-temp")
if TEST_DIR.exists():
    shutil.rmtree(TEST_DIR.as_posix())
TEST_DIR.mkdir(parents=True, exist_ok=True)
TEST_SOURCE_DIR = TEST_DIR.joinpath("source")
TEST_OUTPUT_DIR = TEST_DIR.joinpath("ash_output")
TEST_DATA_DIR = TEST_DIR.parent.joinpath("test_data")


@pytest.fixture
def sample_ash_model():
    sample_aggregated_results = TEST_DATA_DIR.joinpath("outputs").joinpath(
        "ash_aggregated_results.json"
    )
    with open(sample_aggregated_results, "r") as f:
        sample_aggregated_results = json.loads(f.read())
    model = ASHARPModel(**sample_aggregated_results)
    return model


# def is_debugging():
#     return "debugpy" in sys.modules


# # enable_stop_on_exceptions if the debugger is running during a test
# if is_debugging():
#     @pytest.hookimpl(tryfirst=True)
#     def pytest_exception_interact(call):
#         raise call.excinfo.value

#     @pytest.hookimpl(tryfirst=True)
#     def pytest_internalerror(excinfo):
#         raise excinfo.value


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


# @pytest.fixture
# def sample_config():
#     return {
#         "scanners": {"bandit": {"type": "static", "config_file": "bandit.yaml"}},
#         "parsers": {"bandit": {"format": "json"}},
#     }


# @pytest.fixture
# def config_file(ash_config: ASHConfig):
#     # Create a temporary config file
#     config_file = TEST_SOURCE_DIR.joinpath("ash.yaml")
#     with open(config_file, "w") as f:
#         yaml.dump(
#             ash_config.model_dump_json(),
#             f,
#         )
#     return config_file.as_posix()


@pytest.fixture
def mock_scanner_plugin():
    from automated_security_helper.schemas.sarif_schema_model import (
        SarifReport,
        Run,
        Tool,
        ToolComponent,
    )

    class MockScannerPlugin(ScannerPluginBase[ScannerPluginConfigBase]):
        config: ScannerPluginConfigBase = ScannerPluginConfigBase(
            name="mock_scanner",
            enabled=True,
        )

        def model_post_init(self, context):
            return super().model_post_init(context)

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

    return MockScannerPlugin


@pytest.fixture
def ash_config(mock_scanner_plugin):
    """Create a test ASHConfig object based on default ash.yaml settings."""
    # Lazy load required classes
    ASHConfig, BuildConfig, ScannerConfigSegment = lazy_import(
        "automated_security_helper.config.ash_config",
        "ASHConfig",
        "BuildConfig",
        "ScannerConfigSegment",
    )
    CustomScannerConfig = lazy_import(
        "automated_security_helper.config.scanner_types", "CustomScannerConfig"
    )[0]
    ExportFormat = lazy_import("automated_security_helper.models.core", "ExportFormat")[
        0
    ]
    (
        BanditScannerConfig,
        CdkNagScannerConfig,
        CdkNagScannerConfigOptions,
        CdkNagPacks,
        CheckovScannerConfig,
        DetectSecretsScannerConfig,
        DetectSecretsScannerConfigOptions,
        GrypeScannerConfig,
        NpmAuditScannerConfig,
        SemgrepScannerConfig,
        SyftScannerConfig,
        CfnNagScannerConfig,
    ) = (
        lazy_import(
            "automated_security_helper.scanners.ash_default.bandit_scanner",
            "BanditScannerConfig",
        )[0],
        *lazy_import(
            "automated_security_helper.scanners.ash_default.cdk_nag_scanner",
            "CdkNagScannerConfig",
            "CdkNagScannerConfigOptions",
            "CdkNagPacks",
        ),
        *lazy_import(
            "automated_security_helper.scanners.ash_default.checkov_scanner",
            "CheckovScannerConfig",
        ),
        *lazy_import(
            "automated_security_helper.scanners.ash_default.detect_secrets_scanner",
            "DetectSecretsScannerConfig",
            "DetectSecretsScannerConfigOptions",
        ),
        *lazy_import(
            "automated_security_helper.config.scanner_types",
            "GrypeScannerConfig",
            "NpmAuditScannerConfig",
            "SemgrepScannerConfig",
            "SyftScannerConfig",
            "CfnNagScannerConfig",
        ),
    )
    ToolArgs, ToolExtraArg = lazy_import(
        "automated_security_helper.models.core", "ToolArgs", "ToolExtraArg"
    )

    scanners_with_special_chars = {
        "trivy-sast": CustomScannerConfig(
            name="trivy-sast",
            enabled=True,
            type="SAST",
        ),
        "trivy-sbom": CustomScannerConfig(
            name="trivy-sbom",
            enabled=True,
            type="SBOM",
        ),
    }
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
                mock_scanner_plugin(
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
                mock_scanner_plugin(
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
            syft=SyftScannerConfig(),
            **scanners_with_special_chars,
        ),
    )
    return conf
