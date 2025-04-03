"""Scanner module containing security scanner implementations."""

from automated_security_helper.scanners.scanner_factory import ScannerFactory
from automated_security_helper.scanners.abstract_scanner import (
    AbstractScanner,
    ScannerError,
)
from automated_security_helper.scanners.bandit_scanner import BanditScanner

# Initialize global scanner factory
scanner_factory = ScannerFactory()

# Register extra (non-default) scanners

__all__ = ["AbstractScanner", "ScannerError", "BanditScanner", "ScannerFactory"]
