"""Plugin loading mechanism for ASH."""

import importlib
import sys
from typing import Any, Callable, Dict, Iterable, List, Optional

from automated_security_helper.core.exceptions import ASHConfigValidationError
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
#: Not reset per call, because ``importlib`` caches imports and a later call would
#: otherwise report a clean set for a process whose first call lost a group. Each
#: call does ask the package to import its failed groups again
#: (``ash_builtin.retry_failed_plugin_groups``), and drops an entry once its group
#: has loaded, so a group lost only to import order is not reported missing after
#: it has been recovered.
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

            # Before the lists are read: a group lost to the order the process
            # imported ASH's modules in loads now (see retry_failed_plugin_groups).
            retry = getattr(module, "retry_failed_plugin_groups", None)
            if callable(retry):
                retry()
            for recorded in [
                name
                for name in _PLUGIN_LOAD_ERRORS
                if name == module_name or name.startswith(f"{module_name}.")
            ]:
                if recorded not in getattr(module, "ASH_PLUGIN_LOAD_ERRORS", {}):
                    del _PLUGIN_LOAD_ERRORS[recorded]

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
#: Every loader applies the same rule: ``load_additional_plugin_modules``,
#: ``discover_plugins`` (which ``execution_engine`` and ``workspace.execution`` call
#: after it) and ``load_plugins``. A scan refuses a name outside the namespace before
#: any of them runs (``refuse_plugin_modules_outside_namespace``).
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
#:
#: Matched with its separator: the top-level package is ``ash_plugins`` or ends in
#: ``_ash_plugins``, so ``hash_plugins`` or ``flash_plugins`` is not in the namespace.
_ALLOWED_TOP_LEVEL_SUFFIX = "ash_plugins"


def _module_path_refusal(module_path: str) -> Optional[str]:
    """Why *module_path* names no plugin module a scan may import, or None.

    The top-level package is what the namespace rule tests, so
    ``my_ash_plugins.scanners`` is accepted on the strength of ``my_ash_plugins``
    rather than needing its own rule. A name has to be a dotted path of ASCII
    identifiers, the only spelling that imports the module it names, so a stray
    space, an empty segment, a comma or a fullwidth letter is refused. ASH's plugin
    root and the package above it are refused although they are in the namespace:
    the root holds every plugin package ASH ships and names none of them, and naming
    a package does not select the plugins its subpackages define (see
    :func:`scan_plugin_filter`).
    """
    parts = module_path.split(".")
    if not module_path.isascii() or not all(part.isidentifier() for part in parts):
        return "not a dotted path of Python identifiers"
    if _module_within(_OPT_IN_PLUGIN_ROOT, module_path):
        return (
            "ASH's plugin root, which holds every plugin package ASH ships rather "
            "than naming one"
        )
    for prefix in _ALLOWED_MODULE_PREFIXES:
        if prefix.endswith("."):
            if module_path.startswith(prefix):
                return None
        elif module_path == prefix or module_path.startswith(prefix + "."):
            return None

    top_level = parts[0]
    if top_level == _ALLOWED_TOP_LEVEL_SUFFIX or top_level.endswith(
        "_" + _ALLOWED_TOP_LEVEL_SUFFIX
    ):
        return None
    return "outside ASH's plugin namespace"


def _is_allowed_module_path(module_path: str) -> bool:
    """Whether *module_path* names a plugin module a scan may import."""
    return _module_path_refusal(module_path) is None


def _namespace_rule() -> str:
    return (
        "Module paths must be dotted Python identifiers that start with one of: "
        f"{', '.join(_ALLOWED_MODULE_PREFIXES)}, or name a top-level package "
        f"called '{_ALLOWED_TOP_LEVEL_SUFFIX}' or ending in "
        f"'_{_ALLOWED_TOP_LEVEL_SUFFIX}'; ASH's plugin root '{_OPT_IN_PLUGIN_ROOT}' "
        "names no plugin package, so name the package below it."
    )


class PluginModuleError(ASHConfigValidationError):
    """``ash_plugin_modules`` names something that adds no plugin module to a scan.

    An invalid configuration, so a scan maps it to exit code 3 with every other
    ``ASHConfigValidationError``. Its own type lets a command that maps other
    configuration errors differently still give this one exit code 3.
    """


class PluginModuleNamespaceError(PluginModuleError):
    """``ash_plugin_modules`` names a module outside the plugin namespace."""


class PluginModuleImportError(PluginModuleError):
    """A module ``ash_plugin_modules`` names could not be imported."""


def _namespace_package_refusal(module_path: str) -> Optional[str]:
    """Why *module_path* is refused as a namespace package, or None.

    A namespace package (a directory with no ``__init__.py``, whose portions can
    come from several distributions) declares no ``ASH_*`` lists and defines and
    binds no plugin (its portions are bound as modules), so naming it adds no plugin
    to a scan (:func:`scan_plugin_filter`).

    Each level of the name is located without importing its parent packages
    (``config.plugin_module_trust._spec_without_importing``), so the check runs no
    code. A name that cannot be located is left to the import, which refuses it
    (:class:`PluginModuleImportError`).
    """
    from automated_security_helper.config.plugin_module_trust import (
        _spec_without_importing,
    )

    parts = module_path.split(".")
    spec = None
    for depth in range(1, len(parts) + 1):
        try:
            spec = _spec_without_importing(".".join(parts[:depth]), spec)
        except (ImportError, ValueError):
            return None
        if spec is None:
            return None
    if (
        spec is not None
        and spec.submodule_search_locations is not None
        and spec.origin is None
    ):
        return (
            "a namespace package, with no __init__.py: it declares no plugins and a "
            "scan selects none of the packages it holds, so name those packages"
        )
    return None


def refuse_plugin_modules_outside_namespace(plugin_modules: Iterable[str]) -> None:
    """Refuse a scan whose ``ash_plugin_modules`` names something that is not a plugin module.

    Refused: a name outside the plugin namespace or not spelled as a module path
    (:func:`_module_path_refusal`), and a namespace package
    (:func:`_namespace_package_refusal`). Checked before any of them is imported,
    so a refused name runs no code and an accepted name beside it is not imported
    either. Empty entries (a trailing comma) name nothing and are ignored.

    Raises:
        PluginModuleNamespaceError: Naming every refused entry. A scan maps it to
            exit code 3, invalid configuration.
    """
    misnamed: List[str] = []
    namespace_packages: List[str] = []
    for name in dict.fromkeys(plugin_modules):
        if not name:
            continue
        reason = _module_path_refusal(name)
        if reason is not None:
            misnamed.append(f"{name!r} ({reason})")
            continue
        reason = _namespace_package_refusal(name)
        if reason is not None:
            namespace_packages.append(f"{name!r} ({reason})")
    if not misnamed and not namespace_packages:
        return
    rule = f" {_namespace_rule()}" if misnamed else ""
    raise PluginModuleNamespaceError(
        "ash_plugin_modules names "
        + ", ".join(misnamed + namespace_packages)
        + f", which is not a plugin module ASH imports.{rule} Nothing was imported "
        "and nothing was scanned. Rename the package or name the packages inside it, "
        "or remove the entry from the config file, --config-overrides, "
        "--ash-plugin-modules or ASH_PLUGIN_MODULES."
    )


#: ASH's built-in plugin package. Every scan selects its plugins without naming it.
BUILTIN_PLUGIN_PACKAGE = "automated_security_helper.plugin_modules.ash_builtin"

#: Where ASH keeps the plugin packages a scan opts into by naming them in
#: ``ash_plugin_modules`` (``ash_aws_plugins``, ``ash_snyk_plugins``, ...).
_OPT_IN_PLUGIN_ROOT = "automated_security_helper.plugin_modules"


def _module_within(module: str, package: str) -> bool:
    return module == package or module.startswith(package + ".")


def _is_builtin_plugin_module(module: str) -> bool:
    """Whether *module* is in ``ash_builtin``, whose plugins every scan uses.

    Only ``ash_builtin``: the other packages under ``plugin_modules`` ship with ASH
    but take part in a scan only when that scan names them, and no ASH module outside
    ``plugin_modules`` defines a plugin.
    """
    return _module_within(module, BUILTIN_PLUGIN_PACKAGE)


def _bound_in(module_name: str) -> List[Any]:
    """The objects an imported module's namespace binds; imports nothing.

    A package's submodules appear here as module objects, never as the classes
    they define, so what this returns does not depend on which submodules the
    process has imported.
    """
    module = sys.modules.get(module_name)
    if module is None:
        return []
    return list(vars(module).values())


def _declared_by(module_name: str) -> List[Any]:
    """The plugins and event handlers an imported module declares; imports nothing."""
    module = sys.modules.get(module_name)
    declared: List[Any] = []
    if module is None:
        return declared
    for attr in ("ASH_CONVERTERS", "ASH_SCANNERS", "ASH_REPORTERS"):
        value = getattr(module, attr, None)
        if isinstance(value, (list, tuple)):
            declared.extend(value)
    handlers = getattr(module, "ASH_EVENT_HANDLERS", None)
    if isinstance(handlers, dict):
        for callbacks in handlers.values():
            if isinstance(callbacks, (list, tuple)):
                declared.extend(callbacks)
    return declared


def scan_plugin_filter(plugin_modules: Iterable[str]) -> Callable[[Any], bool]:
    """Which registered plugins and event handlers a scan naming *plugin_modules* uses.

    The plugin registry and the event-handler lists are process-wide: a module
    stays registered after the scan that imported it, and ``list_scanners``
    imports the community packages ASH ships so it can describe them. A scan
    therefore selects from them through this filter rather than taking everything
    registered, so it gets ASH's built-in plugins plus, for each module its own
    ``ash_plugin_modules`` names, the classes and handlers that are:

    * defined in that module itself;
    * bound in its namespace, such as a class its ``__init__`` imports;
    * listed in its ``ASH_CONVERTERS``, ``ASH_SCANNERS``, ``ASH_REPORTERS`` or
      ``ASH_EVENT_HANDLERS``.

    A class defined only in a submodule of a named package is not selected through
    the package. A scan naming the package does not import that submodule, so
    whether the class is registered depends on what else the process imported.
    The bound and listed objects are matched by identity, so another class with
    the same name and module is not selected.

    Call it after the modules are imported; it reads their namespaces from
    ``sys.modules`` and imports nothing.
    """
    modules = frozenset(name for name in plugin_modules if name)
    # Keyed by id for identity matching; the values keep each object alive while
    # the filter exists, so no key can be reused by another object.
    selected: Dict[int, Any] = {}
    for name in modules:
        for obj in _bound_in(name) + _declared_by(name):
            selected[id(obj)] = obj

    def admits(plugin: Any) -> bool:
        module = getattr(plugin, "__module__", None) or ""
        if _is_builtin_plugin_module(module):
            return True
        if module in modules:
            return True
        return selected.get(id(plugin)) is plugin

    return admits


def scan_handler_filter(plugin_modules: Iterable[str]) -> Callable[[Any], bool]:
    """Which event handlers a scan naming *plugin_modules* notifies.

    The handlers :func:`scan_plugin_filter` selects, plus every handler defined
    outside ASH's plugin namespace, such as one the program running the scan
    subscribed with ``ash_plugin_manager.subscribe``. That handler belongs to the
    program rather than to a plugin module, so it is notified in each scan the
    program runs. A handler defined in a plugin module (one inside the namespace)
    that the scan does not name is not notified.
    """
    plugins = scan_plugin_filter(plugin_modules)

    def admits(callback: Any) -> bool:
        if plugins(callback):
            return True
        return not _is_allowed_module_path(getattr(callback, "__module__", None) or "")

    return admits


def load_additional_plugin_modules(
    plugin_modules: List[str] | None = None,
    fail_on_import_error: bool = False,
) -> dict:
    """Load additional plugin modules specified in configuration.

    Args:
        plugin_modules: List of module paths to import
        fail_on_import_error: Raise :class:`PluginModuleImportError` naming every
            module that failed to import, after trying them all, rather than
            logging a warning per module. A scan and the commands that read a
            config's ``ash_plugin_modules`` pass True: a module the operator named
            that does not import would otherwise leave a scan that runs without its
            plugins and passes. ASH's own vendored packages are loaded with False.

    Raises:
        PluginModuleImportError: With *fail_on_import_error*, when any named module
            raised while it was imported (ImportError for a missing package or
            dependency, or any other exception its own code raised).
    """
    if plugin_modules is None:
        plugin_modules = []
    discovered = {"converters": [], "scanners": [], "reporters": []}
    failed: List[str] = []

    for module_path in dict.fromkeys(plugin_modules):
        # Validate module path matches expected namespace patterns
        if not _is_allowed_module_path(module_path):
            ASH_LOGGER.warning(
                f"Skipping module with unexpected namespace: {module_path}. "
                f"{_namespace_rule()}"
            )
            continue

        ASH_LOGGER.info(f"Importing additional plugin module: {module_path}")
        try:
            # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
            module = importlib.import_module(module_path)
        except ImportError as e:
            if not fail_on_import_error:
                ASH_LOGGER.warning(f"Failed to import plugin module {module_path}: {e}")
                continue
            failed.append(f"{module_path!r} ({type(e).__name__}: {e})")
            continue
        except Exception as e:
            if not fail_on_import_error:
                raise
            failed.append(f"{module_path!r} ({type(e).__name__}: {e})")
            continue

        # The import itself triggers plugin registration through the plugin
        # decorators. Track what the module declares.
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

    if failed:
        raise PluginModuleImportError(
            "ash_plugin_modules names "
            + ", ".join(failed)
            + ", which could not be imported. Nothing was scanned or installed. "
            "Install the package, or remove the entry from the config file, "
            "--config-overrides, --ash-plugin-modules or ASH_PLUGIN_MODULES."
        )
    return discovered


def load_plugins(plugin_context=None) -> Dict[str, List[Any]]:
    """Load all ASH plugins, both internal and external.

    Args:
        plugin_context: Optional plugin context containing configuration

    Returns:
        Dict[str, List[Any]]: Dictionary containing lists of loaded plugins by type

    Raises:
        PluginModuleNamespaceError: The config names a plugin module outside the
            plugin namespace (see refuse_plugin_modules_outside_namespace).
        PluginModuleImportError: A module the config names could not be imported.
    """
    # Extract additional plugin modules from context if available, split on
    # commas the way a scan reads them
    additional_plugin_modules = []
    if plugin_context and plugin_context.config:
        from automated_security_helper.config.plugin_module_trust import (
            split_plugin_modules,
        )

        additional_plugin_modules = split_plugin_modules(
            getattr(plugin_context.config, "ash_plugin_modules", [])
        )
    # The same refusal as a scan's, before anything is imported
    refuse_plugin_modules_outside_namespace(additional_plugin_modules)

    # Set the context on the plugin manager if provided
    if plugin_context:
        ash_plugin_manager.set_context(plugin_context)

    # Load internal plugins
    internal_plugins = load_internal_plugins()

    # Load any additional plugin modules specified in configuration
    external_plugins = {}
    if additional_plugin_modules:
        external_plugins = load_additional_plugin_modules(
            additional_plugin_modules, fail_on_import_error=True
        )

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
