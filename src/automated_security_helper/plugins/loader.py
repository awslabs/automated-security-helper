"""Plugin loading mechanism for ASH."""

import importlib
from typing import Dict, List, Any

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

            # Track loaded plugins
            if hasattr(module, "ASH_CONVERTERS"):
                loaded_plugins["converters"].extend(module.ASH_CONVERTERS)
                # Register each converter with the plugin manager
                from automated_security_helper.plugins.decorators import (
                    ash_converter_plugin,
                )

                for converter_class in module.ASH_CONVERTERS:
                    # Apply decorator if not already applied
                    if not hasattr(converter_class, "ash_plugin_type"):
                        converter_class = ash_converter_plugin(converter_class)

            if hasattr(module, "ASH_SCANNERS"):
                loaded_plugins["scanners"].extend(module.ASH_SCANNERS)
                # Register each scanner with the plugin manager
                from automated_security_helper.plugins.decorators import (
                    ash_scanner_plugin,
                )

                for scanner_class in module.ASH_SCANNERS:
                    # Apply decorator if not already applied
                    if not hasattr(scanner_class, "ash_plugin_type"):
                        scanner_class = ash_scanner_plugin(scanner_class)

            if hasattr(module, "ASH_REPORTERS"):
                loaded_plugins["reporters"].extend(module.ASH_REPORTERS)
                # Register each reporter with the plugin manager
                from automated_security_helper.plugins.decorators import (
                    ash_reporter_plugin,
                )

                for reporter_class in module.ASH_REPORTERS:
                    # Apply decorator if not already applied
                    if not hasattr(reporter_class, "ash_plugin_type"):
                        reporter_class = ash_reporter_plugin(reporter_class)

        except ImportError as e:
            ASH_LOGGER.warning(f"Failed to import internal module {module_name}: {e}")

    return loaded_plugins


def load_plugins() -> Dict[str, List[Any]]:
    """Load all ASH plugins, both internal and external.

    Returns:
        Dict[str, List[Any]]: Dictionary containing lists of loaded plugins by type
    """
    # Load internal plugins
    internal_plugins = load_internal_plugins()

    # Load external plugins
    external_plugins = discover_plugins()

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

    return all_plugins
