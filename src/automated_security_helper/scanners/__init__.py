"""Scanner module containing security scanner implementations."""

from automated_security_helper.scanners.cdk_nag_scanner import CDKNagScanner
from automated_security_helper.scanners.scanner_factory import ScannerFactory
from automated_security_helper.scanners.abstract_scanner import (
    AbstractScanner,
    ScannerError,
)
from automated_security_helper.scanners.bandit_scanner import BanditScanner

# Initialize global scanner factory
scanner_factory = ScannerFactory()

# Register available scanners
scanner_factory.register_scanner("cdk-nag", CDKNagScanner)


__all__ = ["AbstractScanner", "ScannerError", "BanditScanner", "ScannerFactory"]

# Create and configure the scanner factory
scanner_factory = ScannerFactory()

# Register available scanners
scanner_factory.register_scanner("bandit", BanditScanner)
