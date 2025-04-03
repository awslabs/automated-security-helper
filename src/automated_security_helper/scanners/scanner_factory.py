"""Module containing the ScannerFactory class for creating scanner instances."""

from typing import Dict, Optional, Type, Union

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
        # Register each scanner with its normalized name
        scanner_classes = [BanditScanner, CDKNagScanner]
        for scanner_class in scanner_classes:
            name = scanner_class.__name__.lower()
            if name.endswith("scanner"):
                name = name[:-7]
            if name not in self._scanners:
                self.register_scanner(name, scanner_class)

    def register_scanner(
        self, scanner_name: str, scanner_class: Type[AbstractScanner]
    ) -> None:
        """Register a scanner class with the factory.

        Args:
            scanner_name: Name of scanner to register (will be normalized)
            scanner_class: Scanner class to register
        """
        # Always normalize both the input name and class name
        input_name = scanner_name.lower()
        if input_name.endswith("scanner"):
            input_name = input_name[:-7]

        class_name = scanner_class.__name__.lower()
        if class_name.endswith("scanner"):
            class_name = class_name[:-7]

        # Use class name if it exists, otherwise use input name
        normalized_name = class_name if class_name else input_name
        self._scanners[normalized_name] = scanner_class

    def create_scanner(
        self,
        scanner_type: Union[str, Type[AbstractScanner]],
        config: Optional[ScannerConfig] = None,
    ) -> AbstractScanner:
        """Create a scanner instance of the specified type with optional configuration.

        Args:
            scanner_type: Type of scanner to create
            config: Optional configuration for the scanner

        Returns:
            An instance of the requested scanner type

        Raises:
            ValueError: If scanner_type is not registered
        """
        if isinstance(scanner_type, str):
            scanner_name = scanner_type.lower()
            if scanner_name.endswith("scanner"):
                scanner_name = scanner_name[:-7]
            if scanner_name not in self._scanners:
                raise ValueError(f"Scanner type '{scanner_type}' not registered")
            scanner_class = self._scanners[scanner_name]
        else:
            scanner_class = scanner_type

        scanner = scanner_class()
        if config:
            scanner.configure(config)
        return scanner

    def get_scanner_class(self, scanner_name: str) -> Type[AbstractScanner]:
        """Get the scanner class for a given name.

        Args:
            scanner_name: Name of scanner to retrieve (will be normalized)

        Returns:
            The scanner class

        Raises:
            ValueError: If scanner_name is not registered
        """
        normalized_name = scanner_name.lower()
        if normalized_name.endswith("scanner"):
            normalized_name = normalized_name[:-7]
        if normalized_name not in self._scanners:
            raise ValueError(f"Scanner '{scanner_name}' not registered")
        return self._scanners[normalized_name]

    def available_scanners(self) -> Dict[str, Type[AbstractScanner]]:
        """Get dictionary of all registered scanners.

        Returns:
            Dictionary mapping scanner names to scanner classes
        """
        return dict(self._scanners)
