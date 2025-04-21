"""Unit tests for scanner factory module."""

import pytest

from automated_security_helper.base.scanner_plugin import (
    ScannerPluginConfigBase,
)
from automated_security_helper.scanners.ash_default.bandit_scanner import (
    BanditScanner,
)
from automated_security_helper.scanners.ash_default.cdk_nag_scanner import (
    CdkNagScanner,
)
from automated_security_helper.core.scanner_factory import ScannerFactory


class TestScannerFactory:
    """Test cases for scanner factory."""

    def test_scanner_factory_initialization(self):
        """Test that factory properly initializes."""
        factory = ScannerFactory()
        factory._scanners = {}  # Clear existing scanners

        # Register test scanners
        factory.register_scanner("bandit", BanditScanner)
        factory.register_scanner("cdknag", CdkNagScanner)

        # Check internal state
        assert hasattr(factory, "_scanners")
        assert isinstance(factory._scanners, dict)

        # Verify registered scanners
        scanners = factory.available_scanners()
        assert "bandit" in scanners
        assert "cdknag" in scanners
        assert scanners["bandit"] == BanditScanner
        assert scanners["cdknag"] == CdkNagScanner

    def test_scanner_factory_registration(self, ash_config):
        """Test scanner registration functionality."""
        factory = ScannerFactory(config=ash_config)
        factory._scanners = {}  # Start fresh

        # Register a new scanner
        factory.register_scanner("test", BanditScanner)

        # Verify registration
        assert "test" in factory._scanners
        assert factory._scanners["test"] == BanditScanner

        # Verify in available scanners
        scanners = factory.available_scanners()
        assert "test" in scanners

    def test_create_invalid_scanner(
        self, mock_scanner_plugin, ash_config, test_source_dir, test_output_dir
    ):
        """Test creating scanner with invalid configuration."""
        factory = ScannerFactory(config=ash_config)

        # Test non-existent scanner
        config = mock_scanner_plugin(name="invalid", type="UNKNOWN")
        with pytest.raises(ValueError, match="Unable to determine scanner class"):
            factory.create_scanner(
                config.name, config, test_source_dir, test_output_dir
            )

    def test_scanner_factory_config_validation(
        self, ash_config, test_source_dir, test_output_dir
    ):
        """Test scanner configuration validation."""
        factory = ScannerFactory(config=ash_config)

        # Test with missing name in dict config
        with pytest.raises(ValueError, match="Unable to determine scanner class"):
            factory.create_scanner("test", {}, test_source_dir, test_output_dir)

        # Test with None config
        with pytest.raises(ValueError, match="Unable to determine scanner class"):
            factory.create_scanner("test", None, test_source_dir, test_output_dir)

    def test_scanner_factory_default_scanners(
        self, mock_scanner_plugin, ash_config, test_source_dir, test_output_dir
    ):
        """Test that default scanners are properly registered and can be created."""
        factory = ScannerFactory(config=ash_config)

        # Check available scanners from scanners namespace
        scanners = factory.available_scanners()
        assert all(name in factory.default_scanners for name in scanners), (
            f"Confirm all factory default scanners are found as available from factory: {factory.default_scanners}"
        )
        assert "trivy-sast" in scanners, (
            f"Confirm alias keys for scanners are respected and hyphens are not converted to underscore for key compatibility: {scanners.keys()}"
        )
        # assert all(
        #     item not in scanners for item in ["cdk_nag", "cfn_nag", "npm_audit"]
        # ), f"Confirm actual field for known hyphenated scanner names is not present (e.g. cdk_nag should not exist, it should only be visible as cdk-nag): {scanners.keys()}"
        assert all(
            scanner.__name__.endswith("Scanner") for scanner in scanners.values()
        ), f"Confirm all scanner plugin classes end with Scanner: {scanners.values()}"

        # Test creating all default scanners
        for name, scanner_class in scanners.items():
            config = mock_scanner_plugin(config=ScannerPluginConfigBase(name=name))
            scanner = factory.create_scanner(
                name, config, test_source_dir, test_output_dir
            )
            assert isinstance(scanner, scanner_class)
            # assert scanner.config.name == name

    def test_scanner_factory_buildtime_scanners(
        self, mock_scanner_plugin, ash_config, test_source_dir, test_output_dir
    ):
        """Test that build-time scanners from ASHConfig are properly registered."""

        # Create factory with config
        factory = ScannerFactory(config=ash_config)

        # Verify build-time scanners are configured on the factory instance's config
        assert "trivy-sast" in [
            scanner_config.config.name
            for scanner_config in factory.config.build.custom_scanners
        ]
        assert "trivy-sbom" in [
            scanner_config.config.name
            for scanner_config in factory.config.build.custom_scanners
        ]
        # Verify build-time scanners are in the available_scanners()
        assert "trivy-sast" in factory.available_scanners()
        assert "trivy-sbom" in factory.available_scanners()

    def test_scanner_factory_config_scanners(
        self, ash_config, test_source_dir, test_output_dir
    ):
        """Test that custom scanners from ASHConfig sections are properly registered."""
        # Create config with custom scanners
        config = ash_config

        # Create factory with config
        factory = ScannerFactory(config=config)

        # Verify scanners are registered but not as defaults
        scanners = factory.available_scanners()
        assert "trivy-sast" in scanners
        assert "trivy-sbom" in scanners
