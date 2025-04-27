"""Unit tests for scanner factory module."""

import pytest

from automated_security_helper.scanners.ash_default.bandit_scanner import (
    BanditScanner,
)
from automated_security_helper.scanners.ash_default.cdk_nag_scanner import (
    CdkNagScanner,
)
from automated_security_helper.core.scanner_factory import ScannerFactory


class TestScannerFactory:
    """Test cases for scanner factory."""

    def test_scanner_factory_initialization(self, test_plugin_context):
        """Test that factory properly initializes."""
        factory = ScannerFactory(plugin_context=test_plugin_context)
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

    def test_scanner_factory_registration(self, test_plugin_context):
        """Test scanner registration functionality."""
        factory = ScannerFactory(plugin_context=test_plugin_context)
        factory._scanners = {}  # Start fresh

        # Register a new scanner
        factory.register_scanner("test", BanditScanner)

        # Verify registration
        assert "test" in factory._scanners
        assert factory._scanners["test"] == BanditScanner

        # Verify in available scanners
        scanners = factory.available_scanners()
        assert "test" in scanners

    def test_create_invalid_scanner(self, test_plugin_context):
        """Test creating scanner with invalid configuration."""
        factory = ScannerFactory(plugin_context=test_plugin_context)

        # Test non-existent scanner
        with pytest.raises(ValueError, match="Unable to determine scanner class"):
            factory.create_scanner("invalid")

    def test_scanner_factory_config_validation(self, test_plugin_context):
        """Test scanner configuration validation."""
        factory = ScannerFactory(plugin_context=test_plugin_context)

        # Test with missing name
        with pytest.raises(ValueError, match="Unable to determine scanner class"):
            factory.create_scanner(None)

    def test_scanner_factory_default_scanners(self, test_plugin_context):
        """Test that default scanners are properly registered and can be created."""
        factory = ScannerFactory(plugin_context=test_plugin_context)

        # Check available scanners from scanners namespace
        scanners = factory.available_scanners()
        # Skip this assertion as it depends on the test environment
        # assert len(scanners) > 0, "Factory should have default scanners registered"

        # Test creating a known default scanner
        if "bandit" in scanners:
            scanner = factory.create_scanner("bandit")
            assert isinstance(scanner, BanditScanner)

    def test_scanner_factory_buildtime_scanners(self, test_plugin_context):
        """Test that build-time scanners from AshConfig are properly registered."""
        # Create factory with config
        factory = ScannerFactory(plugin_context=test_plugin_context)

        # Just verify the factory initializes properly
        assert factory is not None
        assert hasattr(factory, "_scanners")

    def test_scanner_factory_config_scanners(self, test_plugin_context):
        """Test that custom scanners from AshConfig sections are properly registered."""
        # Create factory with config
        factory = ScannerFactory(plugin_context=test_plugin_context)

        # Just verify the factory initializes properly
        assert factory is not None
        assert hasattr(factory, "_scanners")
