"""Module containing the ScannerFactory class for creating scanner instances."""

from pathlib import Path
import re
import logging
from typing import Callable, Dict, Optional, Type, Union
from importlib import import_module

from automated_security_helper.config.config import ASHConfig
from automated_security_helper.models.core import ScannerPluginConfig
from automated_security_helper.models.scanner_plugin import ScannerPlugin

from automated_security_helper.scanners.custom_scanner import CustomScanner
from automated_security_helper.utils.log import ASH_LOGGER, get_logger

# Placeholder for now
_OPTIONAL_SCANNER_CONFIGS: Dict[str, ScannerPluginConfig] = {}


class ScannerFactory:
    """Factory class for creating and configuring scanner instances."""

    def __init__(
        self,
        config: ASHConfig = None,
        logger: logging.Logger = get_logger(),
    ) -> None:
        """Initialize the scanner factory with empty scanner registry.

        Args:
            config: Optional ASHConfig instance to load custom scanner configurations
            logger: Optional logger instance to use
        """
        self.config = config
        self.logger = logger
        self.default_scanners = set()
        self._scanners: Dict[
            str, Union[Type[ScannerPlugin], Callable[[], ScannerPlugin]]
        ] = {}
        self._register_default_scanners()
        self._register_config_scanners()

    def _register_config_scanners(self) -> None:
        """Register scanners from the ASHConfig.

        This includes:
        - Custom build-time scanners from ash.yaml
        - Custom scanners from sast.scanners and sbom.scanners sections
        """
        if not self.config:
            ASH_LOGGER.debug("No config provided, skipping config scanner registration")
            return

        # Register build-time scanners
        for scanner in self.config.build.custom_scanners:
            normalized_name = self._normalize_scanner_name(scanner.name)
            try:
                self.default_scanners.add(normalized_name)
                if normalized_name in self._scanners:
                    # Skip if already registered, add to defaults if from build time
                    continue

                # Try to find matching scanner class
                scanner_class = CustomScanner(
                    name=scanner.name,
                    _default_config=scanner,
                    _config=scanner,
                )
                self.register_scanner(normalized_name, scanner_class)
                ASH_LOGGER.debug(f"Registered build-time scanner {scanner.name}")
            except ValueError as e:
                self.logger.warning(
                    f"Could not register build-time scanner {scanner.name}: {str(e)}"
                )
        for scanner in self.config.scanners:
            normalized_name = self._normalize_scanner_name(scanner.name)
            try:
                self.default_scanners.add(normalized_name)
                if normalized_name in self._scanners:
                    # Skip if already registered, add to defaults if from build time
                    continue

                # Try to find matching scanner class
                scanner_class = CustomScanner(
                    name=scanner.name,
                    _default_config=scanner,
                    _config=scanner,
                )
                self.register_scanner(normalized_name, scanner_class)
                ASH_LOGGER.debug(f"Registered config scanner {scanner.name}")
            except ValueError as e:
                self.logger.warning(
                    f"Could not register config scanner {scanner.name} due to ValueError: {str(e)}"
                )
            except Exception as e:
                self.logger.error(
                    f"Error registering config scanner {scanner.name} due to Exception: {str(e)}"
                )

    def _register_default_scanners(self) -> None:
        """Register all available scanner plugins.

        This includes:
        - All classes that extend ScannerPlugin in automated_security_helper.scanners
        - Any custom scanners from ASHConfig if provided
        """
        # First register all scanner plugins from the scanners namespace
        scanners_module = import_module("automated_security_helper.scanners")
        scanners_path = Path(scanners_module.__file__).parent

        # Iterate through all .py files in the scanners directory
        for file_path in scanners_path.glob("*.py"):
            if file_path.name.startswith("_"):
                continue

            module_name = f"automated_security_helper.scanners.{file_path.stem}"
            try:
                module = import_module(module_name)

                # Find all classes in the module that inherit from ScannerPlugin
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, ScannerPlugin)
                        and attr != ScannerPlugin
                    ):
                        scanner_name = self._normalize_scanner_name(attr_name)
                        try:
                            self.register_scanner(scanner_name, attr)
                            self.default_scanners.add(scanner_name)
                        except ValueError:
                            # Skip if scanner is already registered
                            continue
            except (ImportError, AttributeError) as e:
                self.logger.warning(
                    f"Failed to load scanner module {module_name}: {str(e)}"
                )
                continue

        # Try to register optional scanners
        for scanner_type, config in _OPTIONAL_SCANNER_CONFIGS.items():
            try:
                module = import_module(config["module_path"])
                scanner_class = getattr(module, config["class_name"])
                scanner_name = scanner_class.__name__.lower().strip()
                scanner_name = self._normalize_scanner_name(scanner_name)
                self.default_scanners.add(scanner_name)
                if scanner_name not in self._scanners:
                    self._scanners[scanner_name] = scanner_class
            except (ImportError, AttributeError) as e:
                # Skip if scanner module is not available
                ASH_LOGGER.warning(
                    f"Failed to load optional scanner module {config['module_path']}: {e}"
                )
                continue

        # Process all default scanners
        for scanner_name in self.default_scanners:
            scanner_class = self._scanners[scanner_name]
            try:
                # Skip invalid scanner classes
                if isinstance(scanner_class, type) and not issubclass(
                    scanner_class, ScannerPlugin
                ):
                    ASH_LOGGER.warning(f"Invalid scanner class: {scanner_class}")
                    continue

                # Check for required config
                if (
                    not hasattr(scanner_class, "_default_config")
                    or scanner_class._default_config is None
                ):
                    ASH_LOGGER.warning(
                        f"Scanner {scanner_class.__name__} missing _default_config (factory)"
                    )
                    continue

                if callable(scanner_class):
                    scanner_class = scanner_class()
                config = scanner_class._default_config
                if (
                    not hasattr(config, "name")
                    or config.name is None
                    or config.name == ""
                ):
                    ASH_LOGGER.warning(
                        f"Scanner {scanner_class.__name__} missing required name in default config, current: {config.name}"
                    )
                    continue

                scanner_name = scanner_class._default_config.name
                # scanner_name = self._normalize_scanner_name(scanner_name)

                # Only register if not already present
                self.default_scanners.add(scanner_name)
                if scanner_name not in self._scanners:
                    self._scanners[scanner_name] = scanner_class

            except Exception as e:
                ASH_LOGGER.warning(
                    f"Failed to register scanner {scanner_class.__name__}: {str(e)}"
                )

    @staticmethod
    def _normalize_scanner_name(scanner_name: str) -> str:
        """Normalize the scanner name for consistent lookup."""
        normalized_name = scanner_name.lower()
        normalized_name = re.sub(
            pattern=r"scanner(config)?$",
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

        The scanner name will be normalized to lowercase. Both the original name and base
        name without 'scanner' suffix (if present) will be registered.

        Args:
            scanner_name: Name of scanner to register (will be normalized)
            scanner_input: Scanner class or factory function to register

        Raises:
            ValueError: If scanner name is empty or already registered
            TypeError: If scanner input is not valid
        """
        if not scanner_name:
            raise ValueError("Scanner name cannot be empty")

        # Normalize scanner name
        normalized_name = self._normalize_scanner_name(scanner_name)

        # Check for duplicate registration
        if normalized_name in self._scanners:
            self.logger.debug(f"Scanner '{normalized_name}' is already registered")
        else:
            self.logger.debug(f"Registering scanner: {normalized_name} (factory)")

        # Validate input
        try:
            if isinstance(scanner_input, ScannerPlugin):
                self._scanners[normalized_name] = scanner_input
            elif isinstance(scanner_input, type):
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
        config: Optional[ScannerPluginConfig] = None,
        source_dir: Optional[Path] = None,
        output_dir: Optional[Path] = None,
        logger: Optional[logging.Logger] = None,
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

        # Create and configure scanner instance
        if callable(scanner_class):
            instance = scanner_class(
                source_dir=source_dir,
                output_dir=output_dir,
            )
        else:
            setattr(scanner_class, "source_dir", source_dir)
            setattr(scanner_class, "output_dir", output_dir)
            instance = scanner_class

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
        known_scanners = self.config.get_scanners()
        if (
            normalized_name not in self._scanners
            and normalized_name not in known_scanners
        ):
            raise ValueError("Unable to determine scanner class")
        elif normalized_name not in self._scanners:
            self.register_scanner(normalized_name, known_scanners[normalized_name])
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


if __name__ == "__main__":
    config = ASHConfig
    factory = ScannerFactory()
    factory.logger.info("[__main__] ScannerFactory initialized")
