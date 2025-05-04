"""Plugin loading mechanism for ASH."""

import importlib
from typing import Dict, List, Any

from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.discovery import discover_plugins
from automated_security_helper.utils.log import ASH_LOGGER


def load_internal_plugins():
    """Load all internal ASH plugins."""
    internal_modules = [
        "automated_security_helper.converters",
        "automated_security_helper.scanners",
        "automated_security_helper.reporters",
    ]

    loaded_plugins = {"converters": [], "scanners": [], "reporters": []}

    for module_name in internal_modules:
        try:
            module = importlib.import_module(module_name)
            ASH_LOGGER.debug(f"Loaded internal plugin module: {module_name}")

            # Track loaded plugins - these should already be auto-registered via decorators
            if hasattr(module, "ASH_CONVERTERS"):
                ASH_LOGGER.debug(
                    f"Found {len(module.ASH_CONVERTERS)} converters in {module_name}"
                )
                loaded_plugins["converters"].extend(module.ASH_CONVERTERS)

            if hasattr(module, "ASH_SCANNERS"):
                ASH_LOGGER.debug(
                    f"Found {len(module.ASH_SCANNERS)} scanners in {module_name}"
                )
                loaded_plugins["scanners"].extend(module.ASH_SCANNERS)

            if hasattr(module, "ASH_REPORTERS"):
                ASH_LOGGER.debug(
                    f"Found {len(module.ASH_REPORTERS)} reporters in {module_name}"
                )
                loaded_plugins["reporters"].extend(module.ASH_REPORTERS)

        except ImportError as e:
            ASH_LOGGER.warning(f"Failed to import internal module {module_name}: {e}")

    return loaded_plugins


def load_additional_plugin_modules(plugin_modules: List[str] = None):
    """Load additional plugin modules specified in configuration.

    Args:
        plugin_modules: List of module paths to import
    """
    if not plugin_modules:
        return

    for module_path in plugin_modules:
        try:
            ASH_LOGGER.info(f"Importing additional plugin module: {module_path}")
            importlib.import_module(module_path)
        except ImportError as e:
            ASH_LOGGER.warning(f"Failed to import plugin module {module_path}: {e}")


def load_plugins(plugin_context=None) -> Dict[str, List[Any]]:
    """Load all ASH plugins, both internal and external.

    Args:
        plugin_context: Optional plugin context containing configuration

    Returns:
        Dict[str, List[Any]]: Dictionary containing lists of loaded plugins by type
    """
    # Extract additional plugin modules from context if available
    additional_plugin_modules = []
    if plugin_context and plugin_context.config:
        additional_plugin_modules = getattr(
            plugin_context.config, "ash_plugin_modules", []
        )

    # Set the context on the plugin manager if provided
    if plugin_context:
        ash_plugin_manager.set_context(plugin_context)

    # Load any additional plugin modules specified in configuration
    if additional_plugin_modules:
        load_additional_plugin_modules(additional_plugin_modules)

    # Load internal plugins
    internal_plugins = load_internal_plugins()

    # Load external plugins
    external_plugins = discover_plugins(plugin_modules=additional_plugin_modules)

    # Combine internal and external plugins
    all_plugins = {
        "converters": internal_plugins.get("converters", [])
        + external_plugins.get("converters", []),
        "scanners": internal_plugins.get("scanners", [])
        + external_plugins.get("scanners", []),
        "reporters": internal_plugins.get("reporters", [])
        + external_plugins.get("reporters", []),
    }

    ASH_LOGGER.info(
        f"Loaded {len(all_plugins['converters'])} converters, "
        f"{len(all_plugins['scanners'])} scanners, and "
        f"{len(all_plugins['reporters'])} reporters"
    )

    # Register adapters for all plugins
    from automated_security_helper.plugins.adapters import (
        register_converter_adapters,
        register_scanner_adapters,
        register_reporter_adapters,
    )

    ASH_LOGGER.debug("Registering adapters for all loaded plugins")
    register_converter_adapters(all_plugins["converters"])
    register_scanner_adapters(all_plugins["scanners"])
    register_reporter_adapters(all_plugins["reporters"])

    return all_plugins
