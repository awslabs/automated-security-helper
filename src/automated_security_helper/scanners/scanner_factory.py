"""Module containing the ScannerFactory class for creating scanner instances."""

from typing import Any, Dict, Optional, Type, Union

from automated_security_helper.models.config import ScannerConfig
from automated_security_helper.scanners.abstract_scanner import AbstractScanner
from automated_security_helper.scanners.bandit_scanner import BanditScanner
from automated_security_helper.scanners.cdk_nag_scanner import CDKNagScanner


class ScannerFactory:
    """Factory class for creating and configuring scanner instances."""

    def __init__(self) -> None:
        """Initialize the scanner factory."""
        self._scanners: Dict[str, Type[AbstractScanner]] = {}
        # Register default scanners
        self._register_default_scanners()

    def _register_default_scanners(self) -> None:
        """Register the default set of scanners."""
        self._scanners = {}  # Clear any existing registrations
        self.register_scanner("bandit", BanditScanner)
        self.register_scanner("cdknag", CDKNagScanner)

    def register_scanner(
        self, scanner_name: str, scanner_class: Type[AbstractScanner]
    ) -> None:
        """Register a scanner class with the factory.

        Args:
            scanner_name: Name to register the scanner under
            scanner_class: The scanner class to register

        Raises:
            ValueError: If scanner_name is already registered
        """
        if scanner_name in self._scanners:
            raise ValueError(f"Scanner '{scanner_name}' is already registered")

        self._scanners[scanner_name] = scanner_class

    def create_scanner(
        self, config: Optional[Union[Dict[str, Any], ScannerConfig]] = None
    ) -> AbstractScanner:
        """Create and configure a scanner instance.

        Args:
            config: Scanner configuration as dict or ScannerConfig object

        Returns:
            Configured scanner instance

        Raises:
            ValueError: If scanner type is not registered
            TypeError: If config is None
        """
        if config is None:
            raise TypeError("Scanner configuration cannot be None")

        scanner_name = ""
        if isinstance(config, dict):
            scanner_name = config.get("name", "")
        elif isinstance(config, ScannerConfig):
            scanner_name = config.name

        if not scanner_name or scanner_name not in self._scanners:
            raise ValueError(f"Scanner '{scanner_name}' is not registered")

        scanner_class = self._scanners[scanner_name]
        scanner = scanner_class()
        scanner.configure(config)
        return scanner

    def get_scanner_class(self, scanner_name: str) -> Type[AbstractScanner]:
        """Get scanner class by name.

        Args:
            scanner_name: Name of scanner to retrieve

        Returns:
            Scanner class

        Raises:
            ValueError: If scanner type is not registered
        """
        if scanner_name not in self._scanners:
            raise ValueError(f"Scanner type '{scanner_name}' is not registered")
        return self._scanners[scanner_name]

    def available_scanners(self) -> Dict[str, Type[AbstractScanner]]:
        """Get all registered scanner types."""
        return self._scanners.copy()
