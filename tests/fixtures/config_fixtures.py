"""Configuration fixtures for ASH tests."""

import pytest
import yaml
from pathlib import Path

from automated_security_helper.config.ash_config import (
    AshConfig,
    BuildConfig,
    ScannerConfigSegment,
)
from automated_security_helper.models.core import ExportFormat, ToolArgs, ToolExtraArg
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase


@pytest.fixture
def minimal_ash_config() -> AshConfig:
    """Create a minimal AshConfig for testing."""
    return AshConfig(
        project_name="test-project",
    )


@pytest.fixture
def basic_ash_config() -> AshConfig:
    """Create a basic AshConfig with common settings for testing."""
    return AshConfig(
        project_name="test-project",
        fail_on_findings=True,
        ignore_paths=["tests/**"],
        output_dir="ash_output",
        severity_threshold="MEDIUM",
    )


@pytest.fixture
def full_ash_config(mock_scanner_plugin) -> AshConfig:
    """Create a complete AshConfig with all options for testing."""
    # Lazy load required classes to avoid circular imports
    from automated_security_helper.config.scanner_types import CustomScannerConfig
    from automated_security_helper.scanners.ash_default.bandit_scanner import (
        BanditScannerConfig,
    )
    from automated_security_helper.scanners.ash_default.cdk_nag_scanner import (
        CdkNagScannerConfig,
        CdkNagScannerConfigOptions,
        CdkNagPacks,
    )

    scanners_with_special_chars = {
        "trivy-sast": CustomScannerConfig(
            name="trivy-sast",
            enabled=True,
            type="SAST",
        ),
    }

    return AshConfig(
        project_name="automated-security-helper",
        build=BuildConfig(
            build_mode="ONLINE",
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
            ],
        ),
        fail_on_findings=True,
        ignore_paths=["tests/**"],
        output_dir="ash_output",
        converters={
            "jupyter": {"name": "jupyter", "enabled": True},
            "archive": {"name": "archive", "enabled": True},
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
            **scanners_with_special_chars,
        ),
    )


@pytest.fixture
def config_file_with_suppressions(ash_temp_path) -> Path:
    """Create a temporary ASH config file with suppressions."""
    config_file = ash_temp_path / ".ash.yaml"

    config_data = {
        "project_name": "test-project",
        "fail_on_findings": True,
        "global_settings": {
            "severity_threshold": "MEDIUM",
            "suppressions": [
                {
                    "rule_id": "TEST-001",
                    "file_path": "src/example.py",
                    "reason": "Test suppression",
                }
            ],
        },
        "scanners": {"bandit": {"enabled": True}},
        "reporters": {"sarif": {"enabled": True}},
    }

    with open(config_file, "w") as f:
        yaml.dump(config_data, f)

    return config_file
