"""Module containing the ScannerFactory class for creating scanner instances."""

from pathlib import Path
import re
from typing import Callable, Dict, List, Type, Union

from automated_security_helper.config.config import ScannerPluginConfig
from automated_security_helper.scanners.scanner_plugin import ScannerPlugin
from automated_security_helper.scanners.bandit_scanner import BanditScanner
from automated_security_helper.scanners.cdk_nag_scanner import CDKNagScanner


class ScannerFactory:
    """Factory class for creating and configuring scanner instances."""

    default_scanners: List[Type[ScannerPlugin]] = [
        BanditScanner,
        CDKNagScanner,
    ]

    def __init__(self) -> None:
        """Initialize the scanner factory."""
        self._scanners: Dict[
            str, Union[Type[ScannerPlugin], Callable[[], ScannerPlugin]]
        ] = {}
        # Register default scanners
        self._register_default_scanners()

    def _register_default_scanners(self) -> None:
        """Register the default set of scanners."""
        # Register each scanner with its normalized name
        for scanner_class in self.default_scanners:
            name = scanner_class._default_config.name
            self.register_scanner(name, scanner_class)

    @staticmethod
    def _normalize_scanner_name(scanner_name: str) -> str:
        """Normalize the scanner name for consistent lookup."""
        normalized_name = scanner_name.lower()
        normalized_name = re.sub(
            pattern=r"scannerconfig?$",
            repl="",
            string=normalized_name,
            flags=re.IGNORECASE,
        )
        return normalized_name

    def register_scanner(
        self,
        scanner_name: str,
        scanner_input: Union[Type[ScannerPlugin], Callable[[], ScannerPlugin]],
    ) -> None:
        """Register a scanner with the factory.

        Args:
            scanner_name: Name of scanner to register (will be normalized)
            scanner_input: Scanner class or factory function to register

        Raises:
            TypeError: If scanner_input is not valid
            ValueError: If scanner already registered or name is empty
        """
        if not scanner_name:
            raise ValueError("Scanner name cannot be empty")

        # Normalize scanner name
        normalized_name = self._normalize_scanner_name(scanner_name)

        # Check for duplicate registration
        if normalized_name in self._scanners:
            raise ValueError(f"Scanner '{normalized_name}' is already registered")

        # Validate input
        try:
            if isinstance(scanner_input, type):
                if not issubclass(scanner_input, ScannerPlugin):
                    raise TypeError("Scanner class must inherit from ScannerPlugin")
                self._scanners[normalized_name] = scanner_input
            elif callable(scanner_input):
                # For factory functions, validate they return a proper scanner instance
                test_instance = scanner_input()
                if not isinstance(test_instance, ScannerPlugin):
                    raise TypeError("Scanner must be a ScannerPlugin instance")
                self._scanners[normalized_name] = type(test_instance)
            else:
                raise TypeError("Invalid scanner input")
        except Exception as e:
            raise TypeError(f"Scanner '{normalized_name}' validation failed: {str(e)}")

    def create_scanner(
        self,
        scanner_name: str,
        config: ScannerPluginConfig,
        source_dir: Path,
        output_dir: Path,
    ) -> ScannerPlugin:
        """Create a scanner instance of the specified type with optional configuration.

        Args:
            scanner_type: Type of scanner to create (name, class, config object, or dict)
            config: Optional configuration for the scanner

        Returns:
            An instance of the requested scanner type

        Raises:
            ValueError: If scanner type is not registered
            TypeError: If scanner type is invalid
        """
        if scanner_name is None:
            raise ValueError("Unable to determine scanner class")

        # Get scanner class if not already determined
        scanner_class = None
        if scanner_name:
            normalized_name = self._normalize_scanner_name(scanner_name)
            if normalized_name not in self._scanners:
                raise ValueError("Unable to determine scanner class")
            scanner_class = self._scanners[normalized_name]

        if not scanner_class:
            raise ValueError("Unable to determine scanner class")

        if not config:
            raise ValueError("No scanner config provided, unable to create scanner")

        # Create and configure scanner instance
        instance = scanner_class(
            source_dir=source_dir,
            output_dir=output_dir,
        )
        instance.configure(config)

        return instance

    def get_scanner_class(self, scanner_name: str) -> Type[ScannerPlugin]:
        """Get the scanner class for a given name.

        Args:
            scanner_name: Name of scanner to retrieve (will be normalized)

        Returns:
            The scanner class

        Raises:
            ValueError: If scanner_name is not registered
            TypeError: If stored value is not a scanner class
        """
        normalized_name = self._normalize_scanner_name(scanner_name)
        if normalized_name not in self._scanners:
            raise ValueError("Unable to determine scanner class")
        scanner = self._scanners[normalized_name]
        if not isinstance(scanner, type):
            raise TypeError("Stored scanner must be a class")
        return scanner

    def available_scanners(self) -> Dict[str, Type[ScannerPlugin]]:
        """Get dictionary of all registered scanners.

        Returns:
            Dictionary mapping scanner names to scanner classes

        Raises:
            TypeError: If scanner class cannot be determined for any scanner
        """
        result = {}
        for name, scanner_input in self._scanners.items():
            try:
                if isinstance(scanner_input, type):
                    result[name] = scanner_input
                else:
                    result[name] = scanner_input.__class__
            except Exception as e:
                raise TypeError(f"Failed to get class for scanner '{name}': {str(e)}")
        return result
