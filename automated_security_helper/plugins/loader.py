"""Plugin loading mechanism for ASH."""

import importlib
from typing import Dict, List, Any

from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.utils.log import ASH_LOGGER


#: Plugin modules this process failed to import, mapped to the error text.
#:
#: MODULE-LEVEL BECAUSE THE LOSS OUTLIVES THE CALL. ``load_internal_plugins``
#: returns the plugins it loaded, and four of its five call sites discard that
#: return value -- so a caller that needs to know a plugin group went missing had
#: no way to ask. ``ScanPhase`` reads this to record a MISSING row per failed
#: module, which is what puts the loss in front of the completeness gate instead
#: of in a WARNING nobody reads.
#:
#: Accumulated rather than reset per call: ``load_internal_plugins`` runs once per
#: ``ScanExecutionEngine`` and ``importlib`` caches imports, so a second call
#: re-imports nothing and would otherwise report a clean set for a process whose
#: first call lost a group.
_PLUGIN_LOAD_ERRORS: Dict[str, str] = {}


def plugin_load_errors() -> Dict[str, str]:
    """Plugin modules that failed to import in this process, with their errors.

    A copy, so a caller inspecting the failures cannot clear them for the next one.
    """
    return dict(_PLUGIN_LOAD_ERRORS)


def load_internal_plugins():
    """Load all internal ASH plugins."""
    internal_modules = [
        "automated_security_helper.plugin_modules.ash_builtin",
    ]

    loaded_plugins = {"converters": [], "scanners": [], "reporters": []}

    for module_name in internal_modules:
        try:
            # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
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

            # Register event handlers
            if hasattr(module, "ASH_EVENT_HANDLERS"):
                ASH_LOGGER.debug(
                    f"Found event handlers in {module_name}: {list(module.ASH_EVENT_HANDLERS.keys())}"
                )
                for event_type, handlers in module.ASH_EVENT_HANDLERS.items():
                    for callback in handlers:
                        ASH_LOGGER.debug(
                            f"Registering event callback {callback.__name__} for {event_type}"
                        )
                        ash_plugin_manager.subscribe(event_type, callback)

            # Per-group import failures the package isolated for us.
            #
            # ERROR, not WARNING, and recorded rather than only logged. A plugin
            # group missing from the set is the failure the completeness gate exists
            # to catch, and per-group isolation without this would make it quieter
            # than the startup crash it replaced: the run degrades and reports
            # itself complete. `plugin_load_errors()` is how ScanPhase turns each
            # one into a MISSING row.
            for failed_module, error in getattr(
                module, "ASH_PLUGIN_LOAD_ERRORS", {}
            ).items():
                _PLUGIN_LOAD_ERRORS[failed_module] = error
                ASH_LOGGER.error(
                    f"Plugin module {failed_module} failed to import, so the plugins "
                    f"it declares are not registered and will not run: {error}"
                )

        except ImportError as e:
            # Reached only when `ash_builtin` itself is unimportable -- its own
            # per-group isolation handles a single group failing. Recorded so the
            # total loss reaches the same reader as a partial one; nothing else in
            # the run can distinguish "no plugins configured" from "the plugin
            # package did not load".
            _PLUGIN_LOAD_ERRORS[module_name] = f"{type(e).__name__}: {e}"
            ASH_LOGGER.error(
                f"Failed to import internal module {module_name}, so no built-in "
                f"plugins are registered: {e}"
            )

    return loaded_plugins


_ALLOWED_MODULE_PREFIXES = (
    "automated_security_helper.",
    "ash_plugins.",
    "ash_plugins",
)

#: Suffix marking a top-level package as belonging to the ASH plugin namespace.
#:
#: ADDED BECAUSE THE PREFIX LIST REJECTED THE DOCUMENTED PATTERN. Five docs pages
#: and the shipped ``examples/ash_plugins_example`` all name ``my_ash_plugins``,
#: which starts with none of the prefixes above -- so ``load_additional_plugin_modules``
#: skipped it with a warning and every plugin in it went unregistered.
#:
#: That divergence was survivable in one path and not in the others.
#: ``execution_engine`` also calls ``discover_plugins``, which matches
#: ``name == namespace`` against ``pkgutil.iter_modules()`` and does import the
#: package -- so the single-project scan path loaded it anyway. The consumers with
#: no such fallback (``workspace.execution``, ``core.scanner_inventory``,
#: ``load_plugins`` itself) did not, so the documented arrangement worked in a
#: single-project scan and silently dropped every custom plugin in a workspace run.
#:
#: A suffix rather than removing the check. The check's purpose is to keep a config
#: file from naming an arbitrary importable module, and that purpose survives:
#: ``evil_package.backdoor`` is still refused, which is what
#: ``TestPluginLoaderNamespaceValidation`` in tests/unit/test_defense_in_depth.py
#: holds. The convention this spells out is already in use elsewhere --
#: ``core.scanner_inventory._discover_external_scanner_plugin_packages`` selects
#: installed distributions with ``startswith("ash_") and endswith("_plugins")`` --
#: so this widens the allowlist to the naming rule the rest of the codebase and the
#: documentation already share, rather than inventing one.
_ALLOWED_TOP_LEVEL_SUFFIX = "ash_plugins"


def _is_allowed_module_path(module_path: str) -> bool:
    """Whether *module_path* is inside the ASH plugin namespace.

    The top-level package is what is tested, so ``my_ash_plugins.scanners`` is
    accepted on the strength of ``my_ash_plugins`` rather than needing its own rule.
    """
    for prefix in _ALLOWED_MODULE_PREFIXES:
        if prefix.endswith("."):
            if module_path.startswith(prefix):
                return True
        elif module_path == prefix or module_path.startswith(prefix + "."):
            return True

    top_level = module_path.split(".", 1)[0]
    return top_level.endswith(_ALLOWED_TOP_LEVEL_SUFFIX)


def load_additional_plugin_modules(plugin_modules: List[str] | None = None) -> dict:
    """Load additional plugin modules specified in configuration.

    Args:
        plugin_modules: List of module paths to import
    """
    if plugin_modules is None:
        plugin_modules = []
    discovered = {"converters": [], "scanners": [], "reporters": []}

    unique = list(set(plugin_modules))
    for module_path in unique:
        # Validate module path matches expected namespace patterns
        if not _is_allowed_module_path(module_path):
            ASH_LOGGER.warning(
                f"Skipping module with unexpected namespace: {module_path}. "
                f"Module paths must start with one of: "
                f"{', '.join(_ALLOWED_MODULE_PREFIXES)}, or name a top-level "
                f"package ending in '{_ALLOWED_TOP_LEVEL_SUFFIX}'."
            )
            continue

        try:
            ASH_LOGGER.info(f"Importing additional plugin module: {module_path}")
            # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
            module = importlib.import_module(module_path)
            # The import itself should trigger plugin registration
            # via the AshPlugin metaclass
            # Track what was discovered
            if hasattr(module, "ASH_CONVERTERS"):
                discovered["converters"].extend(module.ASH_CONVERTERS)
            if hasattr(module, "ASH_SCANNERS"):
                discovered["scanners"].extend(module.ASH_SCANNERS)
            if hasattr(module, "ASH_REPORTERS"):
                discovered["reporters"].extend(module.ASH_REPORTERS)

            # Register event handlers from external modules
            if hasattr(module, "ASH_EVENT_HANDLERS"):
                ASH_LOGGER.debug(
                    f"Found event handlers in {module_path}: {list(module.ASH_EVENT_HANDLERS.keys())}"
                )
                for event_type, handlers in module.ASH_EVENT_HANDLERS.items():
                    for callback in handlers:
                        ASH_LOGGER.debug(
                            f"Registering event callback {callback.__name__} for {event_type}"
                        )
                        ash_plugin_manager.subscribe(event_type, callback)

        except ImportError as e:
            ASH_LOGGER.warning(f"Failed to import plugin module {module_path}: {e}")

    return discovered


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

    # Load internal plugins
    internal_plugins = load_internal_plugins()

    # Load any additional plugin modules specified in configuration
    external_plugins = {}
    if additional_plugin_modules:
        external_plugins = load_additional_plugin_modules(additional_plugin_modules)

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
