"""Tests for CDK Nag scanner."""

import pytest
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    CdkNagScanner,
    CdkNagScannerConfig,
    CdkNagScannerConfigOptions,
    CdkNagPacks,
)


@pytest.fixture
def test_cdk_nag_scanner(test_plugin_context):
    """Create a test CDK Nag scanner."""
    return CdkNagScanner(
        context=test_plugin_context,
        config=CdkNagScannerConfig(),
    )


def test_cdk_nag_scanner_init(test_plugin_context):
    """Test CdkNagScanner initialization."""
    scanner = CdkNagScanner(
        context=test_plugin_context,
        config=CdkNagScannerConfig(),
    )
    assert scanner.config.name == "cdk-nag"
    assert scanner.tool_type == "IAC"


def test_cdk_nag_scanner_validate(test_cdk_nag_scanner):
    """Test CdkNagScanner validation."""
    assert test_cdk_nag_scanner.validate_plugin_dependencies() is True


def test_cdk_nag_scanner_configure(test_plugin_context):
    """Test CdkNagScanner configuration."""
    scanner = CdkNagScanner(
        context=test_plugin_context,
        config=CdkNagScannerConfig(
            options=CdkNagScannerConfigOptions(
                nag_packs=CdkNagPacks(
                    AwsSolutionsChecks=True,
                    HIPAASecurityChecks=True,
                    NIST80053R5Checks=True,
                )
            )
        ),
    )
    assert scanner.config.options.nag_packs.AwsSolutionsChecks is True
    assert scanner.config.options.nag_packs.HIPAASecurityChecks is True
    assert scanner.config.options.nag_packs.NIST80053R5Checks is True
