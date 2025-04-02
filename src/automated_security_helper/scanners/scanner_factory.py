"""Module containing the ScannerFactory class for creating scanner instances."""

from typing import Any, Dict, Type

from .abstract_scanner import AbstractScanner


class ScannerFactory:
    """Factory class for creating and configuring scanner instances."""

    def __init__(self) -> None:
        """Initialize the scanner factory."""
        self._registered_scanners: Dict[str, Type[AbstractScanner]] = {}

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
        if scanner_name in self._registered_scanners:
            raise ValueError(f"Scanner '{scanner_name}' is already registered")

        self._registered_scanners[scanner_name] = scanner_class

    def create_scanner(
        self, scanner_name: str, config: Dict[str, Any]
    ) -> AbstractScanner:
        """Create and configure a scanner instance.

        Args:
            scanner_name: Name of the registered scanner to create
            config: Configuration dictionary for the scanner

        Returns:
            Configured scanner instance

        Raises:
            ValueError: If scanner_name is not registered
        """
        if scanner_name not in self._registered_scanners:
            raise ValueError(f"No scanner registered with name '{scanner_name}'")

        scanner_class = self._registered_scanners[scanner_name]
        scanner = scanner_class()

        # Apply configuration if the scanner instance has a configure method
        if hasattr(scanner, "configure"):
            scanner.configure(config)

        return scanner

    @property
    def available_scanners(self) -> Dict[str, Type[AbstractScanner]]:
        """Get the dictionary of registered scanners.

        Returns:
            Dictionary mapping scanner names to scanner classes
        """
        return self._registered_scanners.copy()
