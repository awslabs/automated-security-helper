"""Module containing the ScannerFactory class for creating scanner instances."""

from pathlib import Path
from typing import Callable, Dict, Optional, Type, Union

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import ASHConfig
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.base.scanner_plugin import ScannerPluginBase

from automated_security_helper.core.plugin_registry import RegisteredPlugin
from automated_security_helper.scanners.ash_default.custom_scanner import CustomScanner
from automated_security_helper.utils.log import ASH_LOGGER


class ScannerFactory:
    """Factory class for creating and configuring scanner instances."""

    def __init__(
        self,
        config: ASHConfig = None,
        plugin_context: PluginContext = None,
        source_dir: Path = None,
        output_dir: Path = None,
        registered_scanner_plugins: Dict[str, RegisteredPlugin] = {},
    ) -> None:
        """Initialize the scanner factory with empty scanner registry.

        Args:
            config: Optional ASHConfig instance to load custom scanner configurations
        """
        self.config = config
        self.default_scanners = set()
        self._scanners: Dict[
            str, Union[Type[ScannerPluginBase], Callable[[], ScannerPluginBase]]
        ] = {}
        self._registered_scanner_plugins = registered_scanner_plugins
        self.plugin_context = plugin_context
        self.source_dir = source_dir
        self.output_dir = output_dir
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
            try:
                self.default_scanners.add(scanner.config.name)
                if scanner.config.name in self._scanners:
                    # Skip if already registered, add to defaults if from build time
                    continue

                # Try to find matching scanner class
                scanner_model = scanner.model_dump(by_alias=True)
                if "context" in scanner_model:
                    del scanner_model[
                        "context"
                    ]  # Remove context if it exists to avoid duplicate
                scanner_class = CustomScanner(
                    **scanner_model, context=self.plugin_context
                )
                self.register_scanner(scanner.config.name, scanner_class)
                ASH_LOGGER.debug(
                    f"Registered build-time scanner {scanner.config.name} with class {scanner_class}"
                )
            except ValueError as e:
                ASH_LOGGER.warning(
                    f"Could not register build-time scanner {scanner.config.name}: {str(e)}"
                )
        for scanner_name, scanner_config in self.config.scanners.model_dump(
            by_alias=True
        ).items():
            try:
                self.default_scanners.add(scanner_name)
                if scanner_name in self._scanners:
                    # Skip if already registered, add to defaults if from build time
                    continue

                # Try to find matching scanner class
                scanner_class = CustomScanner(
                    name=scanner_name,
                    config=scanner_config,
                    context=self.plugin_context,
                    source_dir=self.source_dir,
                    output_dir=self.output_dir,
                )
                self.register_scanner(scanner_name, scanner_class)
                ASH_LOGGER.debug(
                    f"Registered config scanner {scanner_name} with class {scanner_class}"
                )
            except ValueError as e:
                ASH_LOGGER.warning(e)
            except Exception as e:
                ASH_LOGGER.error(e)

    def _register_default_scanners(self) -> None:
        """Register all available scanner plugins.

        This includes:
        - All classes that extend ScannerPlugin in automated_security_helper.base.scanner_plugin
        - Any custom scanners from ASHConfig if provided
        """
        # Iterate through all .py files in the scanners directory
        for scanner_name, reg_plugin in self._registered_scanner_plugins.items():
            try:
                scanner_class = reg_plugin.plugin_class
                self.register_scanner(scanner_name, scanner_class)
                self.default_scanners.add(scanner_name)
                if callable(scanner_class):
                    scanner_class = scanner_class(
                        context=self.plugin_context,
                        source_dir=self.source_dir,
                        output_dir=self.output_dir,
                    )
                self._scanners[scanner_name] = scanner_class
            except ValueError:
                # Skip if scanner is already registered
                continue

    def register_scanner(
        self,
        scanner_name: str,
        scanner_input: Union[Type[ScannerPluginBase], Callable[[], ScannerPluginBase]],
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

        # Check for duplicate registration
        if scanner_name in ["CustomScanner"]:
            ASH_LOGGER.debug(
                f"Scanner '{scanner_name}' is not allowed for registration"
            )
            return
        elif scanner_name in self._scanners:
            ASH_LOGGER.debug(f"Scanner '{scanner_name}' is already registered")
            return
        else:
            ASH_LOGGER.debug(f"Registering scanner: {scanner_name}")

        # Validate input
        try:
            if isinstance(scanner_input, ScannerPluginBase):
                self._scanners[scanner_name] = scanner_input
            elif isinstance(scanner_input, type):
                if not issubclass(scanner_input, ScannerPluginBase):
                    raise TypeError("Scanner class must inherit from ScannerPlugin")
                self._scanners[scanner_name] = scanner_input
            elif callable(scanner_input):
                # For factory functions, validate they return a proper scanner instance
                test_instance = scanner_input()
                if not isinstance(test_instance, ScannerPluginBase):
                    raise TypeError("Scanner must be a ScannerPlugin instance")
                self._scanners[scanner_name] = type(test_instance)
            else:
                raise TypeError("Invalid scanner input")
        except Exception as e:
            raise TypeError(f"Scanner '{scanner_name}' validation failed: {str(e)}")

    def create_scanner(
        self,
        scanner_name: str,
        config: Optional[ScannerPluginBase | ScannerPluginConfigBase] = None,
        source_dir: Optional[Path] = None,
        output_dir: Optional[Path] = None,
    ) -> ScannerPluginBase:
        """Create a scanner instance of the specified type with optional configuration.

        Args:
            scanner_name: Name of the scanner to create
            config: Optional configuration for the scanner
            source_dir: Source directory to scan
            output_dir: Output directory for results

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
            if scanner_name not in self._scanners:
                raise ValueError("Unable to determine scanner class")
            scanner_class = self._scanners[scanner_name]

        if not scanner_class:
            raise ValueError("Unable to determine scanner class")

        # Create plugin context
        from automated_security_helper.base.plugin_context import PluginContext

        context = PluginContext(
            source_dir=source_dir or self.source_dir,
            output_dir=output_dir or self.output_dir,
        )

        ASH_LOGGER.debug(
            f"Creating scanner '{scanner_name}' with context: source_dir={context.source_dir}, output_dir={context.output_dir}"
        )

        # Create and configure scanner instance
        if callable(scanner_class):
            instance = scanner_class(
                source_dir=source_dir,
                output_dir=output_dir,
                context=context,
            )
        else:
            # Create a new instance rather than modifying the class
            try:
                # Try to create a new instance of the same class
                instance = type(scanner_class)(
                    source_dir=source_dir,
                    output_dir=output_dir,
                    context=context,
                )
            except Exception as e:
                ASH_LOGGER.warning(
                    f"Failed to create new instance of {type(scanner_class).__name__}: {e}"
                )
                # Fall back to modifying the existing instance
                setattr(scanner_class, "source_dir", source_dir)
                setattr(scanner_class, "output_dir", output_dir)
                setattr(scanner_class, "context", context)
                instance = scanner_class

        # Configure the instance if needed
        if config is not None and hasattr(instance, "configure"):
            instance.configure(config)

        return instance

    def available_scanners(self) -> Dict[str, Type[ScannerPluginBase]]:
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
    ASH_LOGGER.info("[__main__] ScannerFactory initialized")
