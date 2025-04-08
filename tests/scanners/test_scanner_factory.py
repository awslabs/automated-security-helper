"""Unit tests for scanner factory module."""

import pytest

from automated_security_helper.config.config import ScannerPluginConfig
from automated_security_helper.scanners.bandit_scanner import BanditScanner
from automated_security_helper.scanners.cdk_nag_scanner import CDKNagScanner
from automated_security_helper.scanner_factory import ScannerFactory


def test_scanner_factory_initialization():
    """Test that factory properly initializes with default scanners."""
    factory = ScannerFactory()

    # Check internal state
    assert hasattr(factory, "_scanners")
    assert isinstance(factory._scanners, dict)

    # Check default scanners are registered
    scanners = factory.available_scanners()
    assert "bandit" in scanners
    assert "cdknag" in scanners
    assert scanners["bandit"] == BanditScanner
    assert scanners["cdknag"] == CDKNagScanner


def test_scanner_factory_registration():
    """Test scanner registration functionality."""
    factory = ScannerFactory()

    # Register a new scanner
    factory.register_scanner("test", BanditScanner)
    assert "test" in factory._scanners
    assert factory._scanners["test"] == BanditScanner

    # Verify it's available in scanners list
    scanners = factory.available_scanners()
    assert "test" in scanners


def test_scanner_factory_multiple_registrations():
    """Test handling of multiple scanner registrations."""
    factory = ScannerFactory()

    # First registration should succeed
    factory.register_scanner("test", BanditScanner)
    assert factory.get_scanner_class("test") == BanditScanner

    # Second registration should fail
    with pytest.raises(ValueError, match="Scanner 'test' is already registered"):
        factory.register_scanner("test", CDKNagScanner)


def test_create_bandit_scanner(test_source_dir, test_output_dir):
    """Test creation of Bandit scanner instance."""
    factory = ScannerFactory()

    # Test with ScannerConfig
    config = ScannerPluginConfig(
        name="bandit",
        type="SAST",
        source_dir=test_source_dir,
        output_dir=test_output_dir,
    )
    scanner = factory.create_scanner(
        config.name, config, test_source_dir, test_output_dir
    )
    assert isinstance(scanner, BanditScanner)
    assert scanner.name == "bandit"
    assert scanner.type == "SAST"

    # Test with dict config
    dict_config = {
        "name": "bandit",
        "type": "SAST",
        "source_dir": str(test_source_dir),
        "output_dir": str(test_output_dir),
    }
    scanner = factory.create_scanner(
        dict_config["name"], dict_config, test_source_dir, test_output_dir
    )
    assert isinstance(scanner, BanditScanner)
    assert scanner.name == "bandit"
    assert scanner.type == "SAST"


def test_create_cdk_nag_scanner(test_source_dir, test_output_dir):
    """Test creation of CDK Nag scanner instance."""
    factory = ScannerFactory()

    # Test with ScannerConfig
    config = ScannerPluginConfig(
        name="cdknag",
        type="IAC",
        source_dir=test_source_dir,
        output_dir=test_output_dir,
    )
    scanner = factory.create_scanner(
        config.name, config, test_source_dir, test_output_dir
    )
    assert isinstance(scanner, CDKNagScanner)
    assert scanner.name == "cdknag"
    assert scanner.type == "IAC"

    # Test with dict config
    dict_config = {
        "name": "cdknag",
        "type": "IAC",
        "source_dir": str(test_source_dir),
        "output_dir": str(test_output_dir),
    }
    scanner = factory.create_scanner(
        dict_config["name"], dict_config, test_source_dir, test_output_dir
    )
    assert isinstance(scanner, CDKNagScanner)
    assert scanner.name == "cdknag"
    assert scanner.type == "IAC"


def test_create_invalid_scanner(test_source_dir, test_output_dir):
    """Test creating scanner with invalid configuration."""
    factory = ScannerFactory()

    # Test non-existent scanner
    config = ScannerPluginConfig(name="invalid", type="UNKNOWN")
    with pytest.raises(ValueError, match="Unable to determine scanner class"):
        factory.create_scanner(config.name, config, test_source_dir, test_output_dir)


def test_scanner_factory_config_validation(test_source_dir, test_output_dir):
    """Test scanner configuration validation."""
    factory = ScannerFactory()

    # Test with missing name in dict config
    with pytest.raises(ValueError, match="Unable to determine scanner class"):
        factory.create_scanner("test", {}, test_source_dir, test_output_dir)

    # Test with None config
    with pytest.raises(ValueError, match="Unable to determine scanner class"):
        factory.create_scanner("test", None, test_source_dir, test_output_dir)


def test_scanner_factory_type_lookup():
    """Test lookup of scanner classes by name."""
    factory = ScannerFactory()

    # Test valid lookups
    assert factory.get_scanner_class("bandit") == BanditScanner
    assert factory.get_scanner_class("cdknag") == CDKNagScanner

    # Test invalid lookup
    with pytest.raises(ValueError, match="Unable to determine scanner class"):
        factory.get_scanner_class("invalid")


def test_scanner_factory_default_scanners(test_source_dir, test_output_dir):
    """Test that default scanners are properly registered and can be created."""
    factory = ScannerFactory()

    # Check available scanners
    scanners = factory.available_scanners()
    assert len(scanners) >= 2  # Should have at least 2 by default (Bandit and CDKNag)
    assert all(scanner.__name__.endswith("Scanner") for scanner in scanners.values())

    # Test creating all default scanners
    for name, scanner_class in scanners.items():
        config = ScannerPluginConfig(name=name, type="SAST")
        scanner = factory.create_scanner(name, config, test_source_dir, test_output_dir)
        assert isinstance(scanner, scanner_class)
        assert scanner.name == name
