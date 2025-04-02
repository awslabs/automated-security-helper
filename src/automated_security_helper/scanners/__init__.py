"""Scanner module containing security scanner implementations."""

from automated_security_helper.scanners.abstract_scanner import (
    AbstractScanner,
    ScannerError,
)
from automated_security_helper.scanners.bandit_scanner import BanditScanner
from automated_security_helper.scanners.scanner_factory import ScannerFactory

__all__ = ["AbstractScanner", "ScannerError", "BanditScanner", "ScannerFactory"]

# Create and configure the scanner factory
scanner_factory = ScannerFactory()

# Register available scanners
scanner_factory.register_scanner("bandit", BanditScanner)
