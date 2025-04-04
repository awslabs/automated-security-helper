"""Scanner module containing security scanner implementations."""

from automated_security_helper.scanners.scanner_factory import ScannerFactory
from automated_security_helper.scanners.scanner_plugin import (
    ScannerPlugin,
    ScannerError,
)
from automated_security_helper.scanners.bandit_scanner import BanditScanner

# Initialize global scanner factory
scanner_factory = ScannerFactory()

# Register extra (non-default) scanners

__all__ = ["ScannerPlugin", "ScannerError", "BanditScanner", "ScannerFactory"]
