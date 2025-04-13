"""Unit tests for scanner factory module."""

import pytest

from automated_security_helper.config.ash_config import ASHConfig, BuildConfig
from automated_security_helper.base.scanner_plugin import ScannerPlugin
from automated_security_helper.scanners.bandit_scanner import BanditScanner
from automated_security_helper.scanners.cdk_nag_scanner import CdkNagScanner
from automated_security_helper.core.scanner_factory import ScannerFactory


def test_scanner_factory_initialization():
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


def test_scanner_factory_registration():
    """Test scanner registration functionality."""
    factory = ScannerFactory()
    factory._scanners = {}  # Start fresh

    # Register a new scanner
    factory.register_scanner("test", BanditScanner)

    # Verify registration
    assert "test" in factory._scanners
    assert factory._scanners["test"] == BanditScanner
    assert factory.get_scanner_class("test") == BanditScanner

    # Verify in available scanners
    scanners = factory.available_scanners()
    assert "test" in scanners


def test_scanner_factory_multiple_registrations():
    """Test handling of duplicate scanner registrations."""
    factory = ScannerFactory()

    # Clear existing scanners
    factory._scanners = {}

    # First registration should succeed
    factory.register_scanner("test", BanditScanner)
    assert factory.get_scanner_class("test") == BanditScanner
    assert len(factory.available_scanners()) == 1

    # Second registration of same scanner name should silently skip and not add an additional scanner
    factory.register_scanner("test", BanditScanner)
    assert len(factory.available_scanners()) == 1

    # Verify original registration is intact
    assert factory.get_scanner_class("test") == BanditScanner


def test_create_bandit_scanner(test_source_dir, test_output_dir):
    """Test creation of Bandit scanner instance."""
    factory = ScannerFactory()

    # Test with ScannerConfig
    config = ScannerPlugin(
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
    config = ScannerPlugin(
        name="cdknag",
        type="IAC",
        source_dir=test_source_dir,
        output_dir=test_output_dir,
    )
    scanner = factory.create_scanner(
        config.name, config, test_source_dir, test_output_dir
    )
    assert isinstance(scanner, CdkNagScanner)
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
    assert isinstance(scanner, CdkNagScanner)
    assert scanner.name == "cdknag"
    assert scanner.type == "IAC"


def test_create_invalid_scanner(test_source_dir, test_output_dir):
    """Test creating scanner with invalid configuration."""
    factory = ScannerFactory()

    # Test non-existent scanner
    config = ScannerPlugin(name="invalid", type="UNKNOWN")
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
    assert factory.get_scanner_class("cdknag") == CdkNagScanner

    # Test invalid lookup
    with pytest.raises(ValueError, match="Unable to determine scanner class"):
        factory.get_scanner_class("invalid")


def test_scanner_factory_default_scanners(test_source_dir, test_output_dir):
    """Test that default scanners are properly registered and can be created."""
    factory = ScannerFactory()

    # Check available scanners from scanners namespace
    scanners = factory.available_scanners()
    assert len(scanners) >= 2  # Should have at least Bandit and CDKNag
    assert all(scanner.__name__.endswith("Scanner") for scanner in scanners.values())
    assert all(name in factory.default_scanners for name in scanners)

    # Test creating all default scanners
    for name, scanner_class in scanners.items():
        config = ScannerPlugin(name=name, type="SAST")
        scanner = factory.create_scanner(name, config, test_source_dir, test_output_dir)
        assert isinstance(scanner, scanner_class)
        assert scanner.name == name


def test_scanner_factory_buildtime_scanners(
    ash_config, test_source_dir, test_output_dir
):
    """Test that build-time scanners from ASHConfig are properly registered."""
    # Create config with build-time scanners
    config = ASHConfig(
        project_name="test",
        build=BuildConfig(
            tool_install_scripts={
                "trivy": [
                    "wget https://github.com/aquasecurity/trivy/releases/download/v0.61.0/trivy_0.61.0_Linux-64bit.deb",
                    "dpkg -i trivy_0.61.0_Linux-64bit.deb",
                ]
            },
            custom_scanners=[
                ScannerPlugin(name="trivy-sast", type="SAST"),
                ScannerPlugin(name="trivy-sbom", type="SBOM"),
            ],
        ),
    )

    # Create factory with config
    factory = ScannerFactory(config=config)

    # Verify build-time scanners are configured on the factory instance's config
    assert "trivy-sast" in [
        scanner_config.name for scanner_config in factory.config.build.custom_scanners
    ]
    assert "trivy-sbom" in [
        scanner_config.name for scanner_config in factory.config.build.custom_scanners
    ]
    # Verify build-time scanners are in the available_scanners()
    assert "trivy-sast" in factory.available_scanners()
    assert "trivy-sbom" in factory.available_scanners()


def test_scanner_factory_config_scanners(ash_config, test_source_dir, test_output_dir):
    """Test that custom scanners from ASHConfig sections are properly registered."""
    # Create config with custom scanners
    config = ash_config
    config.sast = type(
        "SASTConfig",
        (),
        {"scanners": [ScannerPlugin(name="custom-sast", type="SAST")]},
    )()
    config.sbom = type(
        "SBOMConfig",
        (),
        {"scanners": [ScannerPlugin(name="custom-sbom", type="SBOM")]},
    )()

    # Create factory with config
    factory = ScannerFactory(config=config)

    # Verify scanners are registered but not as defaults
    scanners = factory.available_scanners()
    assert "customsast" in scanners
    assert "customsbom" in scanners
    assert "customsast" not in factory.default_scanners
    assert "customsbom" not in factory.default_scanners


def test_scanner_factory_duplicate_registration(test_source_dir, test_output_dir):
    """Test that duplicate scanner registrations are handled properly."""
    # Create config with scanner that would conflict with default
    config = ASHConfig(
        project_name="test",
    )
    config.sast = type(
        "SASTConfig",
        (),
        {"scanners": [ScannerPlugin(name="bandit", type="SAST")]},
    )()

    # Create factory - should log warning but not fail
    factory = ScannerFactory(config=config)

    # Verify original bandit scanner is preserved
    scanners = factory.available_scanners()
    assert scanners["bandit"] == BanditScanner
