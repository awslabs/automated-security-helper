"""Plugin loading mechanism for ASH."""

import ast
import collections.abc
import functools
import importlib
import logging
import re
import sys
import types
from dataclasses import dataclass
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Tuple,
)

from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.plugin_manager import (
    callable_module,
    callback_display_name,
    masked_form_identity,
    masked_module_names,
)
from automated_security_helper.utils.log import ASH_LOGGER


#: Plugin modules this process failed to import, mapped to the error text.
#:
#: Superseded as the record of a run's failures by the run-scoped
#: :data:`PluginLoadRecord` below, which is what ``ScanPhase`` reads: a
#: process-wide record poisoned every later run in the same interpreter. Kept
#: because ``load_internal_plugins`` still drops an entry recorded here once
#: its group has loaded (``ash_builtin.retry_failed_plugin_groups``), so a
#: group lost only to import order is not reported missing after it has been
#: recovered.
_PLUGIN_LOAD_ERRORS: Dict[str, str] = {}


@dataclass(frozen=True)
class PluginLoadFailure:
    """One plugin module this run failed to import or to register.

    ``recorded`` is the error as the run's results record it
    (``metadata.plugin_load_errors``). ``kind`` is the error's type name, which
    is all a refusal may say about a module whose name a config read from the
    environment: the error's own text can quote the name. ``stage`` is where
    the loss happened -- "import" for the import itself, "register" for a
    module that imported but whose declarations (the ASH_* lists,
    ASH_EVENT_HANDLERS) could not be read or subscribed -- so the refusal can
    say which truthfully. Defaulted, so a record built before the split reads
    the same.
    """

    recorded: str
    kind: str = ""
    stage: str = "import"


#: One run's import failures, keyed by module path. RUN-SCOPED, NEVER
#: MODULE-GLOBAL: a process-wide record poisoned every later run in the same
#: interpreter (the MCP server above all) -- a rerun after the operator fixed
#: the dependency still refused on the stale record, and a clean config's
#: results carried an earlier run's failure, module name included. The record
#: lives on the run's ``PluginContext`` and is passed explicitly; a caller
#: loading its own fixed list (the vendored inventory) passes none and gets a
#: throwaway. ``ScanPhase`` reads the run's record to write
#: ``metadata.plugin_load_errors`` and a MISSING row per failed scanner-region
#: module, which is what puts the loss in front of the completeness gate
#: instead of in a WARNING nobody reads. ``importlib`` caches successful
#: imports only, so a failed module is re-attempted, and re-recorded, by the
#: next run.
PluginLoadRecord = MutableMapping[str, PluginLoadFailure]


def recorded_load_errors(record: Mapping[str, PluginLoadFailure]) -> Dict[str, str]:
    """``record`` as ``metadata.plugin_load_errors`` holds it: module to error text."""
    return {name: failure.recorded for name, failure in record.items()}


def combined_plugin_load_errors(
    records: Iterable[Optional[Mapping[str, str]]],
) -> Dict[str, str]:
    """Several runs' ``metadata.plugin_load_errors`` as one map.

    For the results that combine runs: ``ash merge`` (each shard's) and a
    workspace (each project's). Every module any run failed to import is kept,
    in the order *records* gives the runs. A module that failed with the same
    error in several runs is listed once; one whose errors differ keeps each
    distinct one, joined with ``"; "`` in that order, so no run's reason is lost.
    """
    errors: Dict[str, List[str]] = {}
    for record in records:
        for module_path, error in (record or {}).items():
            seen = errors.setdefault(module_path, [])
            if error not in seen:
                seen.append(error)
    return {module_path: "; ".join(seen) for module_path, seen in errors.items()}


def load_internal_plugins(record: Optional[PluginLoadRecord] = None):
    """Load all internal ASH plugins.

    ``record`` is the run's :data:`PluginLoadRecord`; with none given the
    failures are logged but recorded nowhere.
    """
    if record is None:
        record = {}
    internal_modules = [INTERNAL_PLUGIN_PACKAGE]

    loaded_plugins = {"converters": [], "scanners": [], "reporters": []}

    for module_name in internal_modules:
        try:
            # Inside the manager's declaring window: a handler the package's
            # decorators subscribe while it imports is recorded as the
            # package's, not as the program's.
            with ash_plugin_manager.declaring_import(module_name):
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
                        # Named never-raising: a handler without __name__ (a
                        # functools.partial) made this line raise AttributeError,
                        # which the ImportError-only arm below did not catch, so
                        # the whole built-in load crashed with the handlers before
                        # it subscribed and those after it not.
                        ASH_LOGGER.debug(
                            "Registering event callback "
                            f"{callback_display_name(callback)} for {event_type}"
                        )
                        ash_plugin_manager.subscribe(
                            event_type, callback, declared_by=module_name
                        )

            # Per-group import failures the package isolated for us.
            #
            # ERROR, not WARNING, and recorded rather than only logged. A plugin
            # group missing from the set is the failure the completeness gate exists
            # to catch, and per-group isolation without this would make it quieter
            # than the startup crash it replaced: the run degrades and reports
            # itself complete. `recorded_load_errors` over the run's record is
            # how ScanPhase turns each one into a MISSING row.
            for failed_module, error in getattr(
                module, "ASH_PLUGIN_LOAD_ERRORS", {}
            ).items():
                record[failed_module] = PluginLoadFailure(recorded=error)
                ASH_LOGGER.error(
                    f"Plugin module {failed_module} failed to import, so the plugins "
                    f"it declares are not registered and will not run: {error}"
                )

        except Exception as e:  # noqa: BLE001 -- one recorded path for every loss
            # Reached when `ash_builtin` itself is unimportable (its own
            # per-group isolation handles a single group failing), and when
            # reading its declarations or subscribing its handlers raises
            # anything else: not only ImportError, because a non-ImportError
            # here crashed the run unrecorded, with the handlers before the
            # failing one subscribed and those after it not. Recorded so the
            # loss reaches the same reader as a partial one; nothing else in the
            # run can distinguish "no plugins configured" from "the plugin
            # package did not load". A BaseException (a Ctrl-C, SystemExit)
            # still propagates.
            record[module_name] = PluginLoadFailure(
                recorded=f"{type(e).__name__}: {e}", kind=type(e).__name__
            )
            ASH_LOGGER.error(
                f"Failed to load internal module {module_name}, so the built-in "
                f"plugins it declares are not registered: {type(e).__name__}: {e}"
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

#: Where ASH keeps the plugin packages a scan opts into by naming them in
#: ``ash_plugin_modules`` (``ash_aws_plugins``, ``ash_snyk_plugins``, ...).
_OPT_IN_PLUGIN_ROOT = "automated_security_helper.plugin_modules"


def _module_within(module: str, package: str) -> bool:
    return module == package or module.startswith(package + ".")


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
        except Exception:  # noqa: BLE001 -- a finder that raises leaves the name to the import
            # Not only ImportError and ValueError: a meta-path or path-entry
            # finder is third-party code and can raise anything, and a name whose
            # lookup raised crashed the refusal step instead of being left to the
            # import, whose own failure names the real problem.
            return None
        if spec is None:
            return None
    # The loop always runs (str.split returns at least one part) and returns on a
    # None spec, so spec is set here; the check says so to the type checker.
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


#: ASH's built-in plugin package. Every scan selects its plugins without naming it.
BUILTIN_PLUGIN_PACKAGE = "automated_security_helper.plugin_modules.ash_builtin"


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


def _listed(value: Any) -> List[Any]:
    """The entries of a declared list, in the shapes the loader accepts.

    ``load_additional_plugin_modules`` takes any iterable that is not a ``str``
    or ``bytes`` for ``ASH_CONVERTERS``, ``ASH_SCANNERS``, ``ASH_REPORTERS`` and
    for each value of ``ASH_EVENT_HANDLERS``: a set, a dict view or a generator
    as well as a list or tuple. The scan filter reads the same shapes, so a
    plugin declared through any of them is selected the way it was loaded. A
    generator is read once by the loader, so one read here finds nothing in
    it; that is the declaring module's shape, not a selection rule.
    """
    if isinstance(value, (str, bytes)) or not isinstance(
        value, collections.abc.Iterable
    ):
        return []
    try:
        return list(value)
    except Exception:  # noqa: BLE001 -- a declaration that cannot be read declares nothing here
        return []


def _declared_by(module_name: str) -> List[Any]:
    """The plugins and event handlers an imported module declares; imports nothing.

    Reads every declaration shape the loader accepts (``_listed``), and any
    mapping for ``ASH_EVENT_HANDLERS``, as the loader iterates its ``items()``.
    """
    module = sys.modules.get(module_name)
    declared: List[Any] = []
    if module is None:
        return declared
    for attr in ("ASH_CONVERTERS", "ASH_SCANNERS", "ASH_REPORTERS"):
        declared.extend(_listed(getattr(module, attr, None)))
    handlers = getattr(module, "ASH_EVENT_HANDLERS", None)
    if isinstance(handlers, collections.abc.Mapping):
        for callbacks in handlers.values():
            declared.extend(_listed(callbacks))
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
    ``sys.modules`` and imports nothing. ``plugin_modules`` takes the entries
    ``load_additional_plugin_modules`` takes, comma lists included, split the
    same way: a caller passing raw config entries (the workspace's report step)
    got a filter that selected nothing for a comma-joined entry.

    A plugin or handler is judged by the module its function or class was
    defined in, read never-raising (``callable_module``): a ``functools.partial``
    is judged by the function it wraps, since the partial itself reports
    ``functools`` as its module, and a callable whose ``__module__`` read raises
    or is not a ``str`` is judged by identity alone. Subscriptions are
    process-wide, so a filter that raised on one odd callback would break every
    scoped notify of its event, in other runs' scans too.
    """
    # Imported here: plugin_module_trust imports config modules that import the
    # plugin packages, which import this module.
    from automated_security_helper.config.plugin_module_trust import (
        split_plugin_modules,
    )

    modules = frozenset(split_plugin_modules(plugin_modules))
    # Keyed by id for identity matching; the values keep each object alive while
    # the filter exists, so no key can be reused by another object.
    selected: Dict[int, Any] = {}
    for name in modules:
        for obj in _bound_in(name) + _declared_by(name):
            selected[id(obj)] = obj

    def admits(plugin: Any) -> bool:
        module = callable_module(plugin) or ""
        if _is_builtin_plugin_module(module):
            return True
        if module in modules:
            return True
        return selected.get(id(plugin)) is plugin

    return admits


def scan_handler_filter(
    plugin_modules: Iterable[str], *, manager: Any = None
) -> Callable[[Any], bool]:
    """Which event handlers a scan naming *plugin_modules* notifies.

    The handlers :func:`scan_plugin_filter` selects, plus every handler defined
    outside ASH's plugin namespace, such as one the program running the scan
    subscribed with ``ash_plugin_manager.subscribe``. That handler belongs to the
    program rather than to a plugin module, so it is notified in each scan the
    program runs. A handler defined in a plugin module (one inside the namespace)
    that the scan does not name is not notified, whoever subscribed it: a
    subscribe with no declarer outside the loader's import window (a plugin
    submodule subscribing when something other than the loader imports it) does
    not make a namespace-defined handler the program's.

    Where a handler was defined is read by ``callable_module``: a
    ``functools.partial`` by the function it wraps (the partial's own module is
    ``functools``, outside the namespace, which admitted every partial a plugin
    module declared into every later scan of the process), and a callable whose
    module cannot be read is left out rather than raising. A handler that a
    plugin module declared through ``ASH_EVENT_HANDLERS`` (``manager``'s
    ``handler_declared_by``, the process-wide manager by default) belongs to
    that module wherever its function was defined, so one defined in a helper
    library outside the namespace is notified only by a scan naming the
    declaring module, never as the program's.

    Handlers, unlike plugin classes, are also admitted from a module BELOW a
    named module: a package whose ``__init__`` imports a submodule that
    subscribes its handlers with the ``event_subscriber`` decorator declares
    nothing and binds nothing by name, and the engine's phases notified such
    handlers through ``plugins_of`` before they took this filter. A class
    defined only in a submodule stays unselected (:func:`scan_plugin_filter`):
    whether it is registered depends on what else the process imported, which
    is not true of a handler the package's own import subscribed.
    """
    from automated_security_helper.config.plugin_module_trust import (
        split_plugin_modules,
    )

    # Split as scan_plugin_filter splits, so a comma-joined config entry names
    # the same modules for the submodule arm below as for the class filter.
    names = frozenset(split_plugin_modules(plugin_modules))
    plugins = scan_plugin_filter(names)
    registry = manager if manager is not None else ash_plugin_manager

    def admits(callback: Any) -> bool:
        if plugins(callback):
            return True
        module = callable_module(callback)
        if module is not None and any(
            module == name or module.startswith(name + ".") for name in names
        ):
            return True
        declarers, program = registry.handler_owners(callback)
        if module is None:
            # Where it was defined cannot be read: left out whoever subscribed
            # it, as before the owners record existed.
            return False
        inside_namespace = _is_allowed_module_path(module)
        if program and not inside_namespace:
            # The program running the scan subscribed it itself (a subscribe
            # with no declarer outside any loader import window) and defined it
            # in its own code: notified in every scan the program runs, whatever
            # plugin modules also list it. A callable defined INSIDE the plugin
            # namespace is that package's whoever subscribed it: a plugin's
            # submodule subscribing at import, outside the loader's window,
            # must not make its handler the program's, so the namespace rule
            # below decides for it.
            return True
        if declarers:
            # Owned by plugin modules only: by the module that listed it or
            # whose import subscribed it, even when the declaration can no
            # longer be re-read (a one-shot iterator the loader consumed), so
            # the record decides, not the re-read. ASH's own package counts as
            # named, as scan_plugin_filter counts it.
            return any(
                owner in names or _is_builtin_plugin_module(owner)
                for owner in declarers
            )
        return not inside_namespace

    return admits


#: The namespace roots the rule above names, which stay readable when a
#: masked module's dotted prefixes and suffixes are hidden below. The
#: rule's own text is public -- ASH prints it on every namespace refusal,
#: and it names the opt-in plugin root too -- so a failure quoting one of
#: these alone ("No module named 'ash_plugins'", a message pointing at
#: automated_security_helper.plugin_modules) gives away nothing the rule
#: did not already say, and hiding it would blank ASH's own messages.
#: Derived from the prefix list and the opt-in root so they cannot drift.
_READABLE_NAMESPACE_ROOTS = frozenset(
    prefix.rstrip(".") for prefix in _ALLOWED_MODULE_PREFIXES
) | {_OPT_IN_PLUGIN_ROOT}

#: Module words ASH's own text prints, which are never suffix needles: the
#: readable roots above, the opt-in root's own leaf, and the plugin kinds
#: (cli/dependencies.PLUGIN_KINDS plus their plural directory spellings and
#: the event-handler kind). A masked value whose suffix equals one of these
#: is quoting a word every ASH message may hold, so hiding it would blank
#: readable text; the value's other forms stay hidden.
_ASH_PUBLIC_MODULE_WORDS = _READABLE_NAMESPACE_ROOTS | {
    _OPT_IN_PLUGIN_ROOT.rsplit(".", 1)[1],
    "converter",
    "scanner",
    "reporter",
    "converters",
    "scanners",
    "reporters",
    "event_handler",
    "event_handlers",
}

#: Words a load's own failure text always prints: ASH's loader frame and the
#: import machinery's frames. A run needle that occurs INSIDE one of these
#: would blank readable text ("security" matched anywhere blanks part of
#: automated_security_helper in every frame), so runs are exempt by
#: containment here, not only by equality against the public words. The cost
#: mirrors the public-word set's: a masked segment spelled like part of these
#: words prints where a text quotes it alone.
_ASH_LOAD_PRINTED_WORDS = (
    "automated_security_helper",
    "importlib",
    "_bootstrap",
)

#: How a text prints the file of a module's last segment after the segment's
#: name: the source file, the byte code, the stub, the Windows extension
#: module, the script spelling and the untagged extension module. Each is its
#: own form, because a form is matched only as a whole component and
#: "leaf.py" does not end where "leaf.pyc" does.
_MODULE_FILE_SUFFIXES = (".py", ".pyc", ".pyd", ".pyi", ".pyw", ".so")

#: The tag a compiled extension module's file name carries after the leaf
#: besides "cpython-": the stable-ABI tag ("leaf.abi3.so") and the Windows tag
#: with the interpreter's version digits and an optional build letter
#: ("leaf.cp312-win_amd64.pyd", "leaf.cp313t-win_amd64.pyd"). The digits cannot
#: be listed, so one pattern bounded as a whole component covers them; the
#: platform text after the tag is left readable, as it is after "cpython".
_EXTENSION_FILE_TAG = r"\.(?:abi3|cp\d+)[a-z]*"

#: Where a compiled extension module's file name ends: after its ".so" or
#: ".pyd" suffix, with no ASCII letter, digit or "_" next, as a form ends at a
#: whole component. The class is ASCII only (``(?-i:...)``): the pattern is
#: compiled case-insensitively, and under that flag a bare class would also
#: match the characters that fold onto an ASCII letter (the Kelvin sign, the
#: long s, the dotless i, the dotted capital I), which do not glue a name.
_EXTENSION_FILE_END = r"(?!(?-i:[A-Za-z0-9_]))"

#: What follows the leaf in the file name of a compiled extension module from
#: any interpreter or build: an optional debug suffix on the leaf ("leaf_d.pyd"
#: on Windows) and then either a version tag (``_EXTENSION_FILE_TAG``), which
#: is hidden with the leaf, or any one other dotted tag before the ".so" or
#: ".pyd" suffix -- PyPy's "leaf.pypy310-pp73-x86_64-linux-gnu.so", GraalPy's
#: "leaf.graalpy311-311-native-x86_64-linux.so" -- which is looked at and left
#: readable, so only the leaf is hidden. The suffix ends the name
#: (``_EXTENSION_FILE_END``). The debug suffix is the Windows ".pyd" spelling;
#: it is taken only when the name ends in ".pyd", since a POSIX debug build
#: puts the "d" in the ABI tag and "leaf_d.so" is another module's file.
_EXTENSION_FILE_AFTER_LEAF = (
    r"(?:_d(?=(?:\.[A-Za-z0-9_-]+)?\.pyd"
    + _EXTENSION_FILE_END
    + r"))?(?:"
    + _EXTENSION_FILE_TAG
    + r"|(?=(?:\.[A-Za-z0-9_-]+)?\.(?:so|pyd)"
    + _EXTENSION_FILE_END
    + r"))"
)

#: What CPython writes before a module's last segment in the name of the entry
#: point it looks for in an extension module: "dynamic module does not define
#: module export function (PyInit_<leaf>)". "_" is part of a component, so the
#: leaf after this prefix is not a whole component and needs a form of its own.
_EXTENSION_ENTRY_PREFIX = "PyInit_"

#: The most blanks a look-behind of ``_AFTER_IMPORT`` counts between the word or
#: the mark before a name and the name. A look-behind has a fixed width, so each
#: count is an alternative of its own.
_MOST_BLANKS = 8

#: The most dots of a relative import ``_AFTER_IMPORT`` counts.
_MOST_DOTS = 4

#: Where a longer name that starts with a masked run names it without a dot.
#: The runs are whole-component forms, which a longer name ("<leaf>_extras")
#: does not match, so these places carry a pattern of their own:
#:
#: - after "import" and one or more blanks (spaces or tabs): ``from <parent>
#:   import <leaf>_extras``;
#: - after "import name '" or "import name \"" and after "attribute '" or
#:   "attribute \"": the errors "cannot import name '<leaf>_extras' from
#:   '<parent>'" and "module '<parent>' has no attribute '<leaf>_extras'";
#: - after a "," or an opening "(" and any blanks, line breaks included: a later
#:   name of an import list and the names of a parenthesized list over several
#:   lines;
#: - after the leading dots of a relative import, one to ``_MOST_DOTS`` of them.
#:
#: All are zero-width look-behinds, so only the run itself is replaced.
_AFTER_IMPORT = (
    "(?:"
    + "|".join(
        [
            *(
                rf"(?<=\bimport[ \t]{{{count}}})"
                for count in range(1, _MOST_BLANKS + 1)
            ),
            r"(?<=\bimport name ')",
            r'(?<=\bimport name ")',
            r"(?<=\battribute ')",
            r'(?<=\battribute ")',
            r"(?<=[,(])",
            *(
                rf"(?<=[,(][ \t\r\n]{{{count}}})"
                for count in range(1, _MOST_BLANKS + 1)
            ),
            *(
                rf"(?<=\.{{{count}}})(?<![\w.]\.{{{count}}})"
                for count in range(1, _MOST_DOTS + 1)
            ),
        ]
    )
    + ")"
)

#: What makes a masked run the start of a longer name: an ASCII letter, digit or
#: "_" next. The class is ASCII only (``(?-i:...)``) for the reason
#: ``_EXTENSION_FILE_END`` gives.
_NAME_CONTINUES = r"(?=(?-i:[A-Za-z0-9_]))"


def _longer_name_after_import(run: str) -> "re.Pattern[str]":
    """*run* where it starts a longer name in an import line (``_AFTER_IMPORT``).

    The run is looked for first, so the look-behinds are tried only where it
    stands.
    """
    body = re.escape(run)
    return re.compile(
        f"(?={body}){_AFTER_IMPORT}{body}{_NAME_CONTINUES}", re.IGNORECASE
    )


def _masked_module_forms(module_path: str) -> Tuple[str, ...]:
    """Every form of a masked *module_path* a failure's text can print.

    The dotted name itself, and -- since a crash's traceback frames and
    ``__file__`` print it as a filesystem path -- the same name with "/" or
    "\\" in place of the dots. A dotted name adds each proper dotted prefix
    in those three spellings too: a missing top-level package quotes the top
    level alone ("No module named 'pkg'"), and a parent package that raises
    puts ".../pkg/__init__.py" in the frame, neither of which the full
    name's forms match. Two bounds keep the prefixes from blanking readable
    text: one shorter than the redaction word band
    (``MIN_REDACTED_LENGTH``) is matched too widely to be a safe needle,
    and one equal to a namespace root the rule names
    (``_READABLE_NAMESPACE_ROOTS``) is public text. The whole name and each
    prefix needle add their PEP 503 distribution spelling (lowercase, every
    run of ".", "_" or "-" to one "-") when it differs: a package body
    asking ``importlib.metadata`` for its own distribution quotes that
    spelling, which no dotted or path form matches.

    Each form is matched only as a whole component: with no ASCII letter,
    digit or "_" beside either end, so a longer module name that merely holds
    a form ("<parent>_extras") keeps its text, while "." "/" "\\" and
    quotes end a component. A load also hides the masked entry's own value
    as a plain value, inside a longer name too
    (:func:`load_additional_plugin_modules`). A dotted parent is a form too,
    unless it is shorter than ``MIN_REDACTED_LENGTH`` or a namespace root, so
    it is hidden wherever a text names it as a component.

    Every contiguous run of segments past the first is a needle too, in the
    same three spellings: a text can quote a segment past the last masked
    boundary alone -- "cannot import name 'leaf' from ...", "has no
    attribute 'leaf'" -- and a from-import of a MIDDLE segment quotes that
    segment alone ("cannot import name 'mid' from '<top>'"), which no
    whole-name, prefix or suffix form matches. A run's bounds are stricter
    than a prefix's: one shorter than the anywhere band
    (``MIN_ANYWHERE_LENGTH``) would match as a whole word in unrelated
    text, and one equal to a word ASH's own messages print
    (``_ASH_PUBLIC_MODULE_WORDS``) is public. A short or public segment
    therefore still prints: that is the accepted cost of not blanking
    readable text, and a run contained INSIDE a word the load's own frames
    print (``_ASH_LOAD_PRINTED_WORDS``) is exempt the same way. Each run
    also carries a pattern for the import line (``_AFTER_IMPORT``): a run
    that a letter, a digit or "_" follows is hidden after "import", after
    "import name '" or "attribute '", after a "," or "(" and after the leading
    dots of a relative import, although a longer name ("<leaf>_extras") is not a
    whole component, so ``from <parent> import <leaf>_extras``, the list forms of
    it and the errors that quote it do not print the leaf beside a hidden
    parent. When any
    suffix is hidden, the LAST segment also adds its ".py" and
    "__pycache__" ".cpython" file spellings ("leaf.py",
    "__pycache__/leaf.cpython-*.pyc" print the segment with an extension no
    dotted form matches); only the last, because a package's frame prints
    "<seg>/__init__.py", which a hidden run's "/" form matches, and a
    middle segment's file spelling can be an ASH file of its own. The
    spellings are ``_MODULE_FILE_SUFFIXES`` (the source file, byte code,
    stub, Windows extension and untagged extension spellings), each its own
    form because a form ends at a component bound. The stable-ABI and
    version-tagged extension names ("leaf.abi3.so", "leaf.cp312-win_amd64.pyd"),
    the names other interpreters give an extension ("leaf.pypy310-pp73-...so")
    and the debug-build names ("leaf_d.pyd") are one needle with a pattern
    (``_EXTENSION_FILE_AFTER_LEAF``). A leaf
    shorter than ``MIN_REDACTED_LENGTH`` is left out on the prefix rule's
    floor. The last segment also adds the entry point CPython names for an
    extension module that does not define it ("PyInit_" and the leaf, in
    ``_EXTENSION_ENTRY_PREFIX``), under the same rule; a path with one
    segment adds it for the name itself.

    Every form is returned as a ``ModuleFormNeedle``: a str that the
    redaction engine exempts inside ASH's and the import machinery's own
    traceback frame lines (a segment named like that vocabulary otherwise
    blanks text that is the same for every failing load), and whose PEP 503
    spelling carries a bounded pattern for the other separator spellings of
    the same distribution name.
    """
    from automated_security_helper.utils.numeric_text import (
        MIN_ANYWHERE_LENGTH,
        MIN_REDACTED_LENGTH,
    )

    # Imported here: config_validator imports config modules that import the
    # plugin packages, which import this module.
    from automated_security_helper.config.config_validator import (
        make_module_form_needle,
        whole_component_regex,
    )

    def pep503(form: str) -> str:
        # The distribution-name spelling (PEP 503 normalization): a package
        # body asking importlib.metadata for its own distribution quotes
        # "No package metadata was found for <top-ash-plugins>", which no
        # dotted or path form matches.
        return re.sub(r"[-_.]+", "-", form.lower())

    forms = [module_path]
    # The variant pattern a form carries, keyed by the form's text and filled
    # beside the form's own append, so a form and its pattern cannot drift
    # apart: the needle loop below looks a form up here, never by matching its
    # text against another form's.
    patterns: Dict[str, "re.Pattern[str]"] = {}

    def add_distribution_spelling(spelling: str) -> None:
        # A PEP 503 spelling long enough for the word band also carries a
        # variant pattern: the normalization treats every run of "-", "_" and
        # "." as one separator, so the canonical literal alone left the other
        # separator spellings readable ("Segtop.Ash_Plugins"). The pattern
        # takes the canonical's own band. At the anywhere band it is bounded
        # as the literal forms are, as a whole component (a dist-info file
        # name runs the spelling into "-1.0", and "-" ends a component). Below
        # it the pattern is bounded on both sides by characters that are not
        # word characters, dots or dashes -- at least as strict as the word
        # band -- so a short variant is matched only whole. Either way a name
        # that does not normalize segment for segment never matches.
        forms.append(spelling)
        if "-" not in spelling or len(spelling) < MIN_REDACTED_LENGTH:
            return
        body = r"[-_.]+".join(re.escape(piece) for piece in spelling.split("-"))
        if len(spelling) >= MIN_ANYWHERE_LENGTH:
            patterns[spelling] = whole_component_regex(body)
        else:
            patterns[spelling] = re.compile(
                r"(?<![\w.\-])" + body + r"(?![\w.\-])", re.IGNORECASE
            )

    if pep503(module_path) != module_path:
        add_distribution_spelling(pep503(module_path))
    if "." not in module_path:
        forms.append(f"{_EXTENSION_ENTRY_PREFIX}{module_path}")
    if "." in module_path:
        forms.append(module_path.replace(".", "/"))
        forms.append(module_path.replace(".", "\\"))
        parts = module_path.split(".")
        for end in range(1, len(parts)):
            prefix = ".".join(parts[:end])
            if len(prefix) < MIN_REDACTED_LENGTH:
                continue
            if prefix in _READABLE_NAMESPACE_ROOTS:
                continue
            forms.append(prefix)
            if pep503(prefix) != prefix:
                add_distribution_spelling(pep503(prefix))
            if "." in prefix:
                forms.append(prefix.replace(".", "/"))
                forms.append(prefix.replace(".", "\\"))
        last_hidden = False
        for start in range(1, len(parts)):
            for end in range(start + 1, len(parts) + 1):
                run = ".".join(parts[start:end])
                if len(run) < MIN_ANYWHERE_LENGTH:
                    continue
                if run in _ASH_PUBLIC_MODULE_WORDS:
                    continue
                if any(run in word for word in _ASH_LOAD_PRINTED_WORDS):
                    continue
                forms.append(run)
                patterns.setdefault(run, _longer_name_after_import(run))
                if "." in run:
                    forms.append(run.replace(".", "/"))
                    forms.append(run.replace(".", "\\"))
            suffix = ".".join(parts[start:])
            if len(suffix) < MIN_ANYWHERE_LENGTH:
                continue
            if suffix in _ASH_PUBLIC_MODULE_WORDS:
                continue
            # The same exemption the run loop applies: a suffix contained in a
            # word the load's own frames print is never a needle, so it must not
            # count as hidden either, or the leaf's file spellings were added for
            # a segment no form hides.
            if any(suffix in word for word in _ASH_LOAD_PRINTED_WORDS):
                continue
            last_hidden = True
        # The ".py" and "__pycache__" ".cpython" file spellings cover the LAST
        # segment only: a package's frame prints "<seg>/__init__.py", which a
        # hidden run's "/" path form already matches, while a middle segment's
        # file spelling can be an ASH file of its own ("loader" would make
        # "loader.py" a needle and blank the loader's frame).
        leaf = parts[-1]
        if (
            last_hidden
            and len(leaf) >= MIN_REDACTED_LENGTH
            and leaf not in _ASH_PUBLIC_MODULE_WORDS
        ):
            forms.extend(f"{leaf}{suffix}" for suffix in _MODULE_FILE_SUFFIXES)
            forms.append(f"{leaf}.cpython")
            forms.append(f"{_EXTENSION_ENTRY_PREFIX}{leaf}")
            # The compiled extension file names: this form's own text covers
            # the stable-ABI name, and its pattern the version-digit tags, the
            # other interpreters' tags and the debug-build names.
            forms.append(f"{leaf}.abi3")
            patterns[f"{leaf}.abi3"] = whole_component_regex(
                re.escape(leaf) + _EXTENSION_FILE_AFTER_LEAF
            )
    # Each form is a ModuleFormNeedle: frame-exempt, so a segment spelled
    # like the load's own frame vocabulary ("import_module") keeps ASH's and
    # importlib's frame lines readable while redacting everywhere else. A form
    # that has a variant pattern carries it (``patterns``).
    return tuple(
        make_module_form_needle(
            form,
            frame_exempt=True,
            pattern=patterns.get(form),
            whole_component=True,
        )
        for form in dict.fromkeys(forms)
    )


def _masked_module_needles(
    names: Iterable[str], shown: Optional[Mapping[str, str]]
) -> List[str]:
    """The :func:`_masked_module_forms` of each of *names* that *shown* labels
    with something other than itself, each form once.

    A form is the same as another by :func:`masked_form_identity`, not by its
    text: the form for an inner segment of one name carries a pattern for a
    longer name after an import, and the form for the parent of another name has
    the same text without it, so both are kept.

    *shown* is the map a run names its modules with
    (``plugin_module_trust.config_module_names``): a name it maps to its own
    text is written literally and is not masked. These are the whole-component
    needles only, without the plain names that hide a masked name inside a
    longer module name; what a load or a registry read hides is
    :func:`masked_module_scope`, which a caller passes to
    ``masked_module_names``.
    """
    labels = shown or {}
    distinct: Dict[Tuple[Any, ...], str] = {}
    for name in names:
        if labels.get(name, name) == name:
            continue
        for form in _masked_module_forms(name):
            distinct.setdefault(masked_form_identity(form), form)
    return list(distinct.values())


def masked_module_scope(shown: Optional[Mapping[str, str]]) -> Tuple[str, ...]:
    """What a run hides of the modules it names by a mask: each masked name of
    *shown* as a plain value, in the spellings a traceback writes it, then the
    :func:`_masked_module_needles` of them all.

    The plain values are the name, and for a dotted name its ``/`` and ``\\``
    path spellings too. Each is hidden wherever it occurs, inside a longer
    module name ("<name>_extras") too, as an environment value is. The needles
    add the spellings a plain value does not match (dotted parents, inner
    segments, file names), each as a whole component. A load redacts a
    failure's text with this set, and the scope of a registry read
    (``plugin_manager.masked_module_names``) is given the same set, so a line
    that prints a registered module's path hides the masked name as a failure's
    text does.
    """
    labels = shown or {}
    names = tuple(name for name, label in labels.items() if label != name)
    spellings = tuple(
        spelling
        for name in names
        for spelling in (name, name.replace(".", "/"), name.replace(".", "\\"))
    )
    return (*dict.fromkeys(spellings), *_masked_module_needles(labels, labels))


class PluginModuleError(ASHConfigValidationError):
    """``ash_plugin_modules`` names something that adds no plugin module to a scan.

    An invalid configuration, so a scan maps it to exit code 3 with every other
    ``ASHConfigValidationError``. Its own type lets a command that maps other
    configuration errors differently still give this one exit code 3.

    ``str`` carries the scan's closing sentences. A command that neither scans
    nor has the scan's options (``ash report``, ``ash dependencies install``,
    ``ash merge``) shows :meth:`shown_with` instead, so its message does not
    tell the operator nothing was scanned or name options it does not have.
    """

    def __init__(self, naming: str, closing: str = "") -> None:
        super().__init__(f"{naming} {closing}" if closing else naming)
        #: The sentence naming each refused entry (and the reason), without the
        #: scan's closing sentences.
        self.naming = naming
        #: The refused entries as configured, raw: a check that knows which
        #: input contributed each entry picks its closing's remedies from
        #: these (an entry only ASH_PLUGIN_MODULES added is not fixed by
        #: editing a config file). The raisers that know their entries set it.
        self.entries: Tuple[str, ...] = ()
        #: The refused entries only ASH_PLUGIN_MODULES contributed, set by the
        #: check that holds both lists (plugin_module_trust.
        #: refuse_plugin_modules_a_scan_refuses). None means the message
        #: builder offers NO environment remedy: it maps None to an empty
        #: set. Every surface that builds its refusal through
        #: plugin_module_refusal_message gets the field from the judge; the
        #: config validator's own check offers the same remedy by its own
        #: subtraction, without this field.
        self.environment_only_entries: Optional[FrozenSet[str]] = None

    def shown_with(self, closing: str) -> str:
        """The refusal with *closing* in place of the scan's closing sentences."""
        return f"{self.naming} {closing}"


class PluginModuleNamespaceError(PluginModuleError):
    """``ash_plugin_modules`` names a module outside the plugin namespace."""


class PluginModuleImportError(PluginModuleError):
    """A module ``ash_plugin_modules`` names failed to import.

    The configuration asked for the module's plugins and the run has none of
    them, which is the fail-open the namespace refusal already closes for a
    misnamed entry: without this, the import failure would be only a WARNING,
    the run would go on without the configured plugins, and completeness would
    read 100%.
    """

    #: Which stage(s) the named modules failed at ("import", "register").
    #: :func:`plugin_module_fix` reads it to pick a command closing's fix
    #: clause; the builders below set it.
    stages: frozenset = frozenset(("import",))


def refuse_plugin_modules_outside_namespace(
    plugin_modules: Iterable[str], shown: Optional[Mapping[str, str]] = None
) -> None:
    """Refuse a scan whose ``ash_plugin_modules`` names something that is not a plugin module.

    Refused: a name outside the plugin namespace or not spelled as a module path
    (:func:`_module_path_refusal`), and a namespace package
    (:func:`_namespace_package_refusal`). Checked before any of them is imported,
    so a refused name runs no code and an accepted name beside it is not imported
    either. Entries are split on commas as every loader splits them
    (``split_plugin_modules``), so a raw config entry naming two modules is two
    names here too and not one misnamed path; empty entries (a trailing comma)
    name nothing and are ignored, and a name repeated across entries is named
    once.

    ``shown`` maps a name to how the message names it, for a name a config read
    from the environment; any other name is named as it is. Callers build it
    with ``plugin_module_trust.config_module_names`` (``shown_module_names``
    underneath) from the resolved config.

    Raises:
        PluginModuleNamespaceError: Naming every refused entry. A scan maps it to
            exit code 3, invalid configuration.
    """
    labels = shown or {}
    misnamed: List[str] = []
    namespace_packages: List[str] = []
    refused_entries: List[str] = []
    # Split on commas as the loaders do (split_plugin_modules), but NOT
    # stripped: a name padded with whitespace is a misspelling this check
    # exists to refuse, and the loaders' strip would have cleaned it into a
    # valid one. A value that is not a list is read as one entry, as there.
    entries: Iterable[object]
    if plugin_modules is None:
        entries = ()
    elif isinstance(plugin_modules, (list, tuple, set, frozenset)):
        entries = plugin_modules
    else:
        entries = (plugin_modules,)
    pieces = [
        piece
        for entry in entries
        for piece in (entry.split(",") if isinstance(entry, str) else (entry,))
    ]
    # Deduplicated after the split, in first-seen order, so a name repeated
    # across entries is named once in the refusal (the dict.fromkeys the loop
    # ran over before the split did this for whole entries).
    for name in dict.fromkeys(pieces):
        if not name:
            continue
        label = labels.get(name, name)
        reason = _module_path_refusal(name)
        if reason is not None:
            misnamed.append(f"{label!r} ({reason})")
            refused_entries.append(name)
            continue
        reason = _namespace_package_refusal(name)
        if reason is not None:
            namespace_packages.append(f"{label!r} ({reason})")
            refused_entries.append(name)
    if not misnamed and not namespace_packages:
        return
    rule = f" {_namespace_rule()}" if misnamed else ""
    refusal = PluginModuleNamespaceError(
        "ash_plugin_modules names "
        + ", ".join(misnamed + namespace_packages)
        + f", which is not a plugin module ASH imports.{rule}",
        "Nothing was imported "
        "and nothing was scanned. Rename the package or name the packages inside it, "
        "or remove the entry from the config file, --config-overrides, "
        "--ash-plugin-modules or ASH_PLUGIN_MODULES.",
    )
    refusal.entries = tuple(refused_entries)
    raise refusal


def load_additional_plugin_modules(
    plugin_modules: List[str] | None = None,
    shown: Optional[Mapping[str, str]] = None,
    record: Optional[PluginLoadRecord] = None,
    values: Iterable[str] = (),
) -> dict:
    """Load additional plugin modules specified in configuration.

    Args:
        plugin_modules: List of module paths to import. An entry may name several,
            separated by commas, as a config file's ``ash_plugin_modules`` entry
            may; they are imported in order, each once.
        shown: How a log line names a module, for a name a config read from the
            environment (``plugin_module_trust.shown_module_names``), as
            :func:`refuse_plugin_modules_outside_namespace` takes it; any other
            name is named as it is.
        record: The run's :data:`PluginLoadRecord` for import failures. With
            none given the failures are logged but recorded nowhere, which is
            the tolerant shape a caller loading its own fixed list (the
            vendored inventory) wants: its failures must not reach any scan.
        values: The values the run's configuration read from the environment
            (``error_text.config_environment_values`` or the workspace's).
            An import error's text can quote any of them, not only the
            module's own name, so they are redacted from the recorded text --
            which feeds the warning line here, the refusal and
            ``metadata.plugin_load_errors`` -- and carried on the error. The
            name of each masked entry of *shown*, whether or not it is among
            *plugin_modules*, is hidden wherever it occurs, inside a longer
            name too, whether or not it is listed here; the spellings derived
            from it (its dotted parents, path and file spellings) are hidden as
            whole components.
    """
    # Imported here: plugin_module_trust imports config modules that import the
    # plugin packages, which import this module.
    from automated_security_helper.config.plugin_module_trust import (
        split_plugin_modules,
    )
    from automated_security_helper.plugins.discovery import shown_import_failure
    from automated_security_helper.utils.redacted_model import value_tuple

    # One string given as values is one value, not its characters, when the
    # path spellings are added to it below.
    values = value_tuple(values)
    if record is None:
        record = {}
    labels = shown or {}
    discovered = {"converters": [], "scanners": [], "reporters": []}

    unique = split_plugin_modules(plugin_modules)
    if unique:
        # A long-lived process (the MCP server) re-attempts these modules after
        # the operator installs what one needs. The import system caches a miss
        # for a sys.path entry it could not read, so a module installed into a
        # directory that did not exist at startup is never found without this.
        importlib.invalidate_caches()

    # A masked module's forms are needles for the WHOLE load, not only for
    # its own failure: a value that splits into several module names (a
    # comma-joined variable) never appears whole in a traceback -- a piece's
    # body importing a sibling piece quotes the SIBLING -- and a literal
    # module can import a masked piece's missing submodule, which puts the
    # piece in a failure whose own name is not masked at all. Needles built
    # per failing module miss both, so every masked module's forms
    # (_masked_module_forms: the name, its path spellings, its dotted
    # prefixes) are computed once here and every failure in the load,
    # literal modules included, redacts with the one set. Widened at the one
    # place both failure arms carry and redact from, so the record, the
    # WARNING line, the exit-3 refusal and the DEBUG traceback all hide
    # every form.
    #
    # The forms come from every masked name the run's map labels, not from the
    # modules of this call. A scan loads its operator modules in one call and
    # every other module in a call of its own, so the call of a failing literal
    # module does not list a masked entry that loads in another call, and an
    # error that quotes that entry's parent package ("cannot import name 'x'
    # from '<parent>'") would print the parent if only this call's modules
    # were masked. The map is the run's, so the answer is the same however the
    # modules are grouped.
    #
    # A value the configuration read from the environment IS the module path
    # for an entry read whole from a variable. It stays a plain value here,
    # hidden wherever it occurs and inside a longer name ("<name>_extras") too,
    # as every other environment value is, and every masked name of the map is
    # added to the values whatever the caller passes in ``values``. The forms
    # add the spellings a plain value does not match (path separators, dotted
    # parents, inner segments, file names); they are matched only as whole
    # components (config_validator.ModuleFormNeedle.whole_component). The
    # registry lines the import writes are given the same set below.
    masked_scope = masked_module_scope(labels)
    shown_values = (*values, *masked_scope)

    # What the whole load imported, for the register arm's eviction: an entry's
    # refused module can have been imported by an EARLIER entry of this load (a
    # sibling that imports it), and an eviction scoped to the entry's own window
    # then left the refused module in sys.modules, so a long-lived process kept
    # re-refusing it from the stale module after the operator fixed the file.
    load_modules_before = set(sys.modules)
    # The modules this load refused, as owners: a later entry that is one of
    # them or a submodule of one would import the evicted package again and
    # re-run its decorators, undoing the refusal within the same load.
    refused_roots: List[str] = []

    for module_path in unique:
        label = labels.get(module_path, module_path)
        # Validate module path matches expected namespace patterns
        if not _is_allowed_module_path(module_path):
            ASH_LOGGER.warning(
                f"Skipping module with unexpected namespace: {label}. "
                f"{_namespace_rule()}"
            )
            continue

        refused_owner = next(
            (root for root in refused_roots if _module_within(module_path, root)),
            None,
        )
        if refused_owner is not None:
            # Recorded under this entry too, so the refusal names every entry
            # the operator wrote, and never imported: the refused package would
            # run again.
            earlier = record.get(refused_owner) or next(
                (
                    failure
                    for recorded_name, failure in record.items()
                    if _module_within(recorded_name, refused_owner)
                ),
                None,
            )
            if earlier is not None:
                record.setdefault(module_path, earlier)
            ASH_LOGGER.warning(
                f"Not importing plugin module {label}: {labels.get(refused_owner, refused_owner)} "
                "was refused earlier in this load, and importing a module inside "
                "it would run the refused package again"
            )
            continue

        # For the two failure arms' cleanup: what this module's import
        # registers (its decorators) and what the loop below subscribes must
        # not outlive its refusal in the process-wide registry, and only
        # modules THIS window imported are this load's to evict -- a module
        # loaded by some earlier import of the process is not.
        registered_before = ash_plugin_manager.registration_snapshot()
        modules_before = set(sys.modules)
        try:
            ASH_LOGGER.info(f"Importing additional plugin module: {label}")
            # The import runs the module's decorators, and the plugin manager
            # prints the module path they register under: those lines hide
            # every masked module of this load while it runs. The declaring
            # window makes a handler a decorator subscribes here this module's,
            # not the program's (the ASH_EVENT_HANDLERS loop below records the
            # same owner for the listed ones).
            with (
                ash_plugin_manager.declaring_import(module_path),
                masked_module_names(masked_scope),
            ):
                # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
                module = importlib.import_module(module_path)
            # The import itself should trigger plugin registration
            # via the AshPlugin metaclass
        except Exception as e:  # noqa: BLE001 -- one path for every import failure
            # Not only ImportError: a configured module whose body raises
            # anything at import is the same loss, so it takes the same
            # recorded, carried, exit-3 path instead of an unrecorded crash.
            from automated_security_helper.utils.error_text import (
                carry_environment_values,
                error_text,
            )

            # The import arm's half of the register arm's cleanup below.
            # Python removes the failed module itself from sys.modules, but a
            # submodule its body imported before raising stays, so a
            # long-lived process (the MCP server) would reload the FIXED file
            # against the stale submodule. Only the module's own subtree, and
            # only what this window imported: a dependency it imported first
            # is shared with the whole process.
            #
            # For a dotted entry, the PARENT package can be what failed:
            # importing "pkg.sub" runs pkg/__init__ first, and when that
            # raises, Python removes "pkg" itself while a sibling it imported
            # and the registrations it made would outlive a cleanup scoped to
            # the entry. The owner is the shortest prefix this window imported
            # that the failure took back out of sys.modules; with every
            # prefix still importable, the entry itself failed and owns.
            owner = module_path
            parts = module_path.split(".")
            for end in range(1, len(parts)):
                prefix = ".".join(parts[:end])
                if prefix not in modules_before and prefix not in sys.modules:
                    owner = prefix
                    break
            # Over a snapshot of the keys: another thread importing while this
            # handler runs resizes sys.modules, and a comprehension iterating
            # the live dict raised "dictionary changed size during iteration"
            # from inside the except handler, skipping the record, the undo and
            # the refusal below.
            for added in [
                key
                for key in list(sys.modules)
                if key not in modules_before
                and (key == owner or key.startswith(owner + "."))
            ]:
                sys.modules.pop(added, None)
            # And a plugin its decorators registered before the body raised
            # must not outlive the refusal either, exactly as on the register
            # arm: with the module gone, the next resolution would re-import
            # and re-run the refused module.
            ash_plugin_manager.undo_registrations_since(registered_before, owner=owner)

            # Recorded, not only logged: the run's record is how ScanPhase and
            # the completeness gate see an import loss, and
            # `refuse_failed_plugin_imports` is how a configured module's loss
            # refuses the run instead of degrading it. Keyed by the module
            # path, one entry per real module: keying by the shown form made
            # every env-read entry share the one '<value>' key. The keys reach
            # no surface (the field is repr=False and excluded from dumps, and
            # a configured failure refuses the run before any metadata is
            # written); the shown label is applied where a key is printed.
            # Recorded redacted: the error's text can quote any env-read
            # value, and this one string reaches every surface.
            carry_environment_values(e, shown_values)
            record[module_path] = PluginLoadFailure(
                recorded=f"{type(e).__name__}: {error_text(e)}",
                kind=type(e).__name__,
            )
            refused_roots.append(owner)
            ASH_LOGGER.warning(
                f"Failed to import plugin module {label}: "
                f"{shown_import_failure(e, module_path, label)}"
            )
            # The refusal withholds a masked module's error text, so the
            # traceback is the one place the cause survives: at DEBUG, with
            # every env-read value redacted (the frames quote the module's
            # path, which for an env-read entry is the variable's value).
            if ASH_LOGGER.isEnabledFor(logging.DEBUG):
                import traceback

                from automated_security_helper.utils.error_text import (
                    text_without_values,
                )

                ASH_LOGGER.debug(
                    "Plugin module import failure traceback (redacted):\n%s",
                    text_without_values(
                        "".join(traceback.format_exception(e)), shown_values
                    ),
                )
            continue

        try:
            # Track what was discovered, per module first: a module refused
            # below must contribute nothing to the returned groups, which the
            # scanner inventory keeps with no record and no refusal. A str is
            # iterable, so a declaration like ASH_CONVERTERS = 'x' would turn
            # its characters into converters (and bytes its ints): those two
            # and non-iterables are refused, and every other iterable -- a
            # set, dict values, a generator -- is accepted, as it was before
            # the check existed.
            found: dict = {"converters": [], "scanners": [], "reporters": []}
            for group, attribute in (
                ("converters", "ASH_CONVERTERS"),
                ("scanners", "ASH_SCANNERS"),
                ("reporters", "ASH_REPORTERS"),
            ):
                if hasattr(module, attribute):
                    declared = getattr(module, attribute)
                    if isinstance(declared, (str, bytes)) or not isinstance(
                        declared, collections.abc.Iterable
                    ):
                        raise TypeError(
                            f"{attribute} must be an iterable of plugins, "
                            f"not {type(declared).__name__}"
                        )
                    # A mapping is iterable too, over its KEYS: a dict of
                    # plugins would hand its string keys to the callers as
                    # plugin classes, which crashes the scanner inventory.
                    if isinstance(declared, collections.abc.Mapping):
                        raise TypeError(
                            f"{attribute} must be an iterable of plugins, not a "
                            f"{type(declared).__name__}, whose iteration yields "
                            "its keys"
                        )
                    items = list(declared)
                    # The container was checked; its entries were not, so a
                    # list of NAMES reached the callers as plugin classes too.
                    # A plugin class is callable; a str or any other
                    # non-callable entry is refused with the mapping.
                    for item in items:
                        if isinstance(item, (str, bytes)) or not callable(item):
                            raise TypeError(
                                f"{attribute} holds an entry that is not a plugin "
                                f"class: {type(item).__name__}"
                            )
                    # An iterator (a generator) is consumed by the read above,
                    # and the module keeps the exhausted object: every later
                    # reader of the cached module (the scan filter, the
                    # inventory, a reload) found no plugins in it. The module's
                    # attribute is rebound to what was read.
                    if isinstance(declared, collections.abc.Iterator):
                        setattr(module, attribute, items)
                    found[group].extend(items)

            # Register event handlers from external modules
            if hasattr(module, "ASH_EVENT_HANDLERS"):
                ASH_LOGGER.debug(
                    f"Found event handlers in {label}: {list(module.ASH_EVENT_HANDLERS.keys())}"
                )
                # The whole mapping is validated before anything subscribes,
                # display names included: the manager is process-wide, so a
                # bad second entry -- or one whose __name__ the debug line
                # below cannot read, a functools.partial say -- must not
                # leave the first entry's callbacks registered past this
                # module's refusal. In a long-lived server they would fire
                # in the next scan.
                subscriptions = []
                for event_type, handlers in module.ASH_EVENT_HANDLERS.items():
                    for callback in handlers:
                        if not callable(callback):
                            raise TypeError(
                                f"ASH_EVENT_HANDLERS[{event_type!r}] holds an "
                                "entry that is not callable"
                            )
                        # Strict: a declared handler the debug line cannot
                        # truthfully name (a metaclass makes even the type
                        # name raise) is refused with the mapping, while
                        # notify()'s display of an already-subscribed
                        # callback never raises.
                        subscriptions.append(
                            (
                                event_type,
                                callback,
                                callback_display_name(callback, strict=True),
                            )
                        )
                for event_type, callback, display in subscriptions:
                    ASH_LOGGER.debug(
                        f"Registering event callback {display} for {event_type}"
                    )
                    # Declared by this module: the scan handler filter admits
                    # it for scans that name this module, wherever its
                    # function was defined, and for no other scan.
                    ash_plugin_manager.subscribe(
                        event_type, callback, declared_by=module_path
                    )
        except Exception as e:  # noqa: BLE001 -- one path for every registration failure
            # The module imported; the loss is in reading or registering what
            # it declares. Recorded apart (stage), so the refusal does not say
            # "failed to import" about a module that imported, with the same
            # carry, redaction and DEBUG traceback as the import arm: the
            # declarations can quote env-read values too.
            from automated_security_helper.utils.error_text import (
                carry_environment_values,
                error_text,
            )

            # The refused module and its own submodules leave sys.modules, so
            # a long-lived process (the MCP server) imports the FIXED file on
            # the next load instead of re-failing from the stale module. Only
            # those, and only what this window imported: a dependency the
            # module imported first is shared with the whole process (popping
            # it would make a later import run its body again and mint new
            # class objects), a module another thread imported in the same
            # window is not this import's to remove, and a module some earlier
            # import loaded stays as it was.
            # The window is the whole LOAD's, not this entry's: an earlier
            # entry of this load (a sibling that imports this module) can be
            # what first imported it, and evicting only this entry's own
            # imports left the refused module in sys.modules.
            for added in [
                key
                for key in list(sys.modules)
                if key not in load_modules_before
                and (key == module_path or key.startswith(module_path + "."))
            ]:
                sys.modules.pop(added, None)
            # And what the refused module itself registered leaves the
            # registry: its decorated plugins and anything the loop above
            # subscribed must not fire in the next scan of a long-lived
            # server, nor make a later resolution re-import the refused
            # module. Only the refused module's own: another thread's plugin
            # loaded in this window, and a plugin module this one
            # first-imported, keep theirs.
            ash_plugin_manager.undo_registrations_since(
                registered_before, owner=module_path
            )
            carry_environment_values(e, shown_values)
            record[module_path] = PluginLoadFailure(
                recorded=f"{type(e).__name__}: {error_text(e)}",
                kind=type(e).__name__,
                stage="register",
            )
            refused_roots.append(module_path)
            ASH_LOGGER.warning(
                f"Failed to register plugin module {label}: "
                f"{shown_import_failure(e, module_path, label)}"
            )
            if ASH_LOGGER.isEnabledFor(logging.DEBUG):
                import traceback

                from automated_security_helper.utils.error_text import (
                    text_without_values,
                )

                ASH_LOGGER.debug(
                    "Plugin module registration failure traceback (redacted):\n%s",
                    text_without_values(
                        "".join(traceback.format_exception(e)), shown_values
                    ),
                )
        else:
            # Only an accepted module's declarations reach the returned
            # groups: the refusal says the module's plugins are not loaded,
            # and a tolerant caller (the scanner inventory) keeps the return.
            for group, items in found.items():
                discovered[group].extend(items)

    return discovered


def refuse_failed_plugin_imports(
    plugin_modules: Iterable[str],
    record: Mapping[str, PluginLoadFailure],
    shown: Optional[Mapping[str, str]] = None,
    environment_only: Iterable[str] = (),
) -> None:
    """Refuse the run when a configured plugin module failed to import.

    The configuration named these modules, so a run without their plugins is
    not the run the operator configured: load_additional_plugin_modules keeps
    going (a vendored-inventory caller wants every importable group), records
    each failure in ``record`` (the run's own, never the process's), and the
    callers that load a CONFIG's modules call this right after it with the same
    record. ``shown`` is the refusal's naming map, as
    :func:`refuse_plugin_modules_outside_namespace` takes it.
    ``environment_only`` names the entries only ``ASH_PLUGIN_MODULES``
    contributed (``plugin_module_trust.environment_only_plugin_modules``): when
    a refused entry is one of them, the refusal's closing also offers the one
    remedy such an entry has, "unset it in ASH_PLUGIN_MODULES", as the check
    surfaces' refusals do.

    Raises:
        PluginModuleImportError: Naming every configured module that failed,
            with its import error. A scan maps it to exit code 3, invalid
            configuration.
    """
    from automated_security_helper.config.plugin_module_trust import (
        split_plugin_modules,
    )
    from automated_security_helper.plugins.discovery import masked_failure_kind

    labels = shown or {}
    failed = []
    unregistered = []
    # The raw entries behind each phrase, so every refusal below carries
    # ``entries`` as the populated sites do and a check that holds the
    # environment-only subtraction can offer "unset it in ASH_PLUGIN_MODULES".
    failed_entries: List[str] = []
    unregistered_entries: List[str] = []
    for name in split_plugin_modules(plugin_modules):
        # The record is keyed by the module path; the shown label is applied
        # only here, where a key is printed, so two env-read entries keep
        # their own records and only the failed one is named.
        if name not in record:
            continue
        failure = record[name]
        label = labels.get(name, name)
        # A masked name's error text is withheld with it: an import error
        # routinely quotes the module's own name ("cannot import name ...
        # from 'the_module'"), which would put the env-read value in the
        # refusal beside the mask.
        said = (
            failure.recorded
            if label == name
            else masked_failure_kind(failure.kind or "an import failure")
        )
        phrase = f"{label!r} ({said})"
        # By the loss's stage, so the refusal's sentence is true for each
        # module: "failed to import" about a module that imported sent the
        # operator debugging the wrong thing.
        if getattr(failure, "stage", "import") == "register":
            unregistered.append(phrase)
            unregistered_entries.append(name)
        else:
            failed.append(phrase)
            failed_entries.append(name)
    if not failed and not unregistered:
        return
    if not unregistered:
        import_only = _import_refusal(failed)
        import_only.entries = tuple(failed_entries)
        raise _with_environment_remedy(import_only, environment_only)
    if not failed:
        registration_only = _registration_refusal(unregistered)
        registration_only.entries = tuple(unregistered_entries)
        raise _with_environment_remedy(registration_only, environment_only)
    imports, registrations = (
        _import_refusal(failed),
        _registration_refusal(unregistered),
    )
    both = PluginModuleImportError(
        f"{imports.naming} {registrations.naming}",
        "Nothing was scanned. Install what the modules need, fix what they "
        "declare, or remove the entries from the config file, "
        "--config-overrides, --ash-plugin-modules or ASH_PLUGIN_MODULES.",
    )
    both.stages = frozenset(("import", "register"))
    both.entries = tuple(failed_entries) + tuple(unregistered_entries)
    raise _with_environment_remedy(both, environment_only)


def _with_environment_remedy(
    refusal: PluginModuleImportError, environment_only: Iterable[str]
) -> PluginModuleImportError:
    """*refusal*, its closing extended by the environment remedy where one applies.

    The scan's callers print ``str(error)``, never
    ``plugin_module_refusal_message``, so the remedy has to be in the message
    itself. It is the check surfaces' own emitter
    (``ConfigValidator.with_environment_remedy``) that appends it, so the
    wording has one source; ``environment_only_entries`` is recorded as the
    judge records it. A refusal with no environment-only entry is returned as
    it is.
    """
    from automated_security_helper.config.config_validator import ConfigValidator

    environment_entries = frozenset(environment_only)
    if not any(entry in environment_entries for entry in refusal.entries):
        return refusal
    refusal.environment_only_entries = environment_entries
    closing = str(refusal)[len(refusal.naming) :].strip()
    remedied = ConfigValidator.with_environment_remedy(
        closing.rstrip("."), refusal, set(environment_entries)
    )
    refusal.args = (f"{refusal.naming} {remedied}",)
    return refusal


def _import_refusal(failed: List[str]) -> PluginModuleImportError:
    """The import refusal, one wording for the scan's loader and the checks."""
    refusal = PluginModuleImportError(
        "ash_plugin_modules names " + ", ".join(failed) + ", which failed to "
        "import, so the plugins it declares are not loaded.",
        "Nothing was scanned. Install what the module needs, or remove the "
        "entry from the config file, --config-overrides, --ash-plugin-modules "
        "or ASH_PLUGIN_MODULES.",
    )
    refusal.stages = frozenset(("import",))
    return refusal


def _registration_refusal(unregistered: List[str]) -> PluginModuleImportError:
    """The refusal for a module that imported but could not be registered.

    Its own words: saying "failed to import" about a module that imported is
    false, and the loss is in what the module declares (the ASH_* lists,
    ASH_EVENT_HANDLERS), which is what the operator has to fix.
    """
    refusal = PluginModuleImportError(
        "ash_plugin_modules names "
        + ", ".join(unregistered)
        + ", which imported, but what it declares could not be registered, so "
        "the plugins it declares are not loaded.",
        "Nothing was scanned. Fix the module's ASH_EVENT_HANDLERS or ASH_* "
        "lists, or remove the entry from the config file, --config-overrides, "
        "--ash-plugin-modules or ASH_PLUGIN_MODULES.",
    )
    refusal.stages = frozenset(("register",))
    return refusal


def plugin_module_fix(error: PluginModuleError) -> str:
    """The fix clause of a command's closing, by the recorded loss's stage.

    ``ash report``, ``ash merge``, ``ash dependencies install`` and ``ash
    plugin list`` each close the refusal in their own words; this is the one
    clause between them that depends on what failed, so a registration loss
    is not answered with "install what the module needs" -- the module
    imported, and its dependencies are not the problem. An error that records
    no stage reads as an import loss (the namespace refusals keep their own
    closings and never reach this)."""
    stages = getattr(error, "stages", None) or frozenset(("import",))
    if stages == {"register"}:
        return "Fix the module's ASH_EVENT_HANDLERS or ASH_* lists"
    if "register" in stages:
        return "Install what the modules need, fix what they declare"
    return "Install what the module needs"


def _unfindable_level(module_path: str) -> Optional[str]:
    """The shortest prefix of ``module_path`` no installed package provides.

    Each level is located without importing anything
    (``config.plugin_module_trust._spec_without_importing``), the way
    :func:`_namespace_package_refusal` walks a name, so the check runs no
    code. None when every level is found, or when a level cannot be judged
    without importing (a parent that fills its ``__path__`` on import, say):
    those are left to the import.
    """
    from automated_security_helper.config.plugin_module_trust import (
        _spec_without_importing,
    )

    parts = module_path.split(".")
    spec = None
    for depth in range(1, len(parts) + 1):
        prefix = ".".join(parts[:depth])
        parent = spec
        try:
            spec = _spec_without_importing(prefix, spec)
        except Exception:  # noqa: BLE001 -- a finder that raises leaves the name to the import
            return None
        if spec is None:
            # find_spec returns None for a missing name; PathFinder for a
            # missing submodule. Either way the scan's import would raise
            # ModuleNotFoundError naming this prefix -- unless the parent
            # fills its __path__ on import, which only the import can judge.
            if _parent_extends_its_path(parts[: depth - 1], parent):
                return None
            return prefix
    return None


def _parent_extends_its_path(parent_parts: List[str], parent: Optional[Any]) -> bool:
    """Whether the missing child's not-yet-imported parent extends its ``__path__``.

    A pkgutil-style namespace package (an ``__init__`` calling
    ``pkgutil.extend_path`` or ``pkg_resources.declare_namespace``) keeps
    portions in other directories that only its import adds to its
    ``__path__``, so a child not found under the one located portion can still
    import. Judged by the parent's source, never by importing it, and only
    for a parent that is not imported: an imported parent's search locations
    are its real, extended ``__path__``, so a miss there is a miss. The
    source comes from the parent spec's loader (``get_source``), so a zipped
    package is read too. The judgment is of calls: an ``ast.Call`` whose
    function is a name or attribute called ``extend_path`` or
    ``declare_namespace``, or a name either was imported as from ``pkgutil``
    or ``pkg_resources``. An identifier that is no call -- an f-string's
    expression, an attribute assignment target, the parent's own ``def`` of
    the name -- extends nothing, and a comment, a string or a longer name
    never did. A PEP 420 namespace parent has no source and its spec lists
    every portion already. A parent that cannot be judged is left to the
    import: no source to get (a sourceless, .pyc-only package included),
    source the parser rejects, or source over the one-MiB bound.

    Named limits, left as they are: a call built without either identifier
    (``getattr(pkgutil, 'extend' + '_path')``) and a manual ``__path__``
    append are refused although the import works. Leaving an unjudgeable
    parent to the import also means the check surfaces miss what only the
    import can see: a PLAIN parent that is sourceless or over the bound has
    its missing child accepted here while the scan refuses it, the trade
    accepted over refusing parents whose calls the check cannot read.
    """
    if not parent_parts or parent is None:
        return False
    parent_name = ".".join(parent_parts)
    if parent_name in sys.modules:
        return False
    loader = getattr(parent, "loader", None)
    get_source = getattr(loader, "get_source", None)
    if get_source is None:
        return False
    try:
        source = get_source(parent_name)
    except Exception:  # noqa: BLE001 -- a source that can't be got can't be judged
        return True
    if source is None:
        # Sourceless (a .pyc-only package): nothing to judge from.
        return True
    if len(source) > 1024 * 1024:
        # Bounded work: a parent this large is left to the import rather than
        # judged from a prefix the parser would reject.
        return True
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        # Source the parser rejects is left to the import, whose own failure
        # names the real problem: a null byte raises ValueError, and a deeply
        # nested expression raises MemoryError ("Parser stack overflowed"),
        # not SyntaxError.
        return True
    names = {"extend_path", "declare_namespace"}
    called_as = set(names)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in (
            "pkgutil",
            "pkg_resources",
        ):
            called_as.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name in names
            )
    for node in ast.walk(tree):
        target = node.func if isinstance(node, ast.Call) else None
        if isinstance(target, ast.Name) and target.id in called_as:
            return True
        if isinstance(target, ast.Attribute) and target.attr in names:
            return True
    return False


def refuse_unfindable_plugin_imports(
    plugin_modules: Iterable[str],
    shown: Optional[Mapping[str, str]] = None,
) -> None:
    """Refuse configured modules no installed package provides, importing nothing.

    The locatable half of :func:`refuse_failed_plugin_imports`'s class, for the
    check surfaces (``config validate``, ``lint``, ``get``,
    ``validate-plugin-dependencies``, the MCP ``validate_config``), which must
    agree with the scan without importing a plugin module. One named
    exception: ``lint`` judges the file as written, so it reads neither
    ``--config-overrides`` nor ``ASH_PLUGIN_MODULES`` and judges only the
    file's own entries -- the same input can lint clean and still refuse a
    scan. A name whose spec is
    not found would give the scan's import exactly ``ModuleNotFoundError: No
    module named '...'``, so the refusal says that, in the import refusal's
    words. The limit: a module that is installed but fails while importing (a
    missing dependency of its own, say) can only be caught by importing it, so
    that half stays with the scan's loader and the checks accept it.

    Raises:
        PluginModuleImportError: Naming every configured module no installed
            package provides. Every caller maps ASHConfigValidationError to
            exit 3, invalid configuration.
    """
    from automated_security_helper.config.plugin_module_trust import (
        split_plugin_modules,
    )
    from automated_security_helper.plugins.discovery import masked_failure_kind

    labels = shown or {}
    names = split_plugin_modules(plugin_modules)
    if not names:
        return
    # The import system caches a miss for a sys.path entry it could not read,
    # as the loader's own invalidation above this says: without the same
    # invalidation a long-lived process (the MCP server) keeps refusing a
    # module installed after its first answer while the scan's loader imports
    # it.
    importlib.invalidate_caches()
    failed = []
    failed_entries: List[str] = []
    for name in names:
        missing = _unfindable_level(name)
        if missing is None:
            continue
        label = labels.get(name, name)
        # The masked arm withholds the error text with the name, as the
        # loader's refusal does: the text quotes the name.
        said = (
            f"ModuleNotFoundError: No module named '{missing}'"
            if label == name
            else masked_failure_kind("ModuleNotFoundError")
        )
        failed.append(f"{label!r} ({said})")
        failed_entries.append(name)
    if failed:
        refusal = _import_refusal(failed)
        refusal.entries = tuple(failed_entries)
        raise refusal


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
    # Imported here: plugin_module_trust imports config modules that import the
    # plugin packages, which import this module.
    from automated_security_helper.config.plugin_module_trust import (
        config_module_names,
        split_plugin_modules,
    )

    # Extract additional plugin modules from context if available
    additional_plugin_modules = []
    shown = None
    if plugin_context and plugin_context.config:
        additional_plugin_modules = split_plugin_modules(
            getattr(plugin_context.config, "ash_plugin_modules", [])
        )
        # An entry the config read from the environment is named by its masked
        # form, never the variable's value.
        shown = config_module_names(plugin_context.config)
    # Before importing any of them: a name outside the plugin namespace refuses
    # the command with exit 3 (every caller maps ASHConfigValidationError so),
    # and nothing is imported.
    refuse_plugin_modules_outside_namespace(additional_plugin_modules, shown=shown)

    # Set the context on the plugin manager if provided
    if plugin_context:
        ash_plugin_manager.set_context(plugin_context)

    # The run's own failure record, never the process's: a stale record from an
    # earlier run in the same interpreter must not refuse or pollute this one.
    record = plugin_context.plugin_load_record if plugin_context is not None else {}

    # Load internal plugins
    internal_plugins = load_internal_plugins(record=record)

    # Load any additional plugin modules specified in configuration
    external_plugins = {}
    if additional_plugin_modules:
        from automated_security_helper.utils.error_text import (
            config_environment_values,
        )

        external_plugins = load_additional_plugin_modules(
            additional_plugin_modules,
            shown=shown,
            record=record,
            values=config_environment_values(
                plugin_context.config if plugin_context else None
            ),
        )
        # A configured module that failed to import refuses the command, as a
        # misnamed one did above: the run has none of the plugins the operator
        # asked for (every caller maps ASHConfigValidationError to exit 3).
        refuse_failed_plugin_imports(additional_plugin_modules, record, shown=shown)

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


#: The plugin package every run loads, whatever its config lists. The same one
#: load_internal_plugins imports.
INTERNAL_PLUGIN_PACKAGE = "automated_security_helper.plugin_modules.ash_builtin"


def plugins_of(plugin_modules: Iterable[object]) -> Callable[[Any], bool]:
    """A filter for one run's plugins: classes, and event handlers too.

    For ``plugin_modules()``'s ``filter_callback`` and ``notify()``'s ``_scope``.

    The registry is process-wide, and a module registers its plugins once, the
    first time anything in the process imports it. In a process that runs more
    than one scan, the MCP server above all, it therefore holds every module any
    earlier scan, session or tool loaded. A run that resolved its plugins from
    the whole registry ran plugins its own configuration never named: an earlier
    session's AWS reporters, with this session's results and the server's
    credentials, or the vendored scanners ``list_scanners`` loads.

    The filter keeps a class or handler defined in ASH's built-in plugin package
    or in one of ``plugin_modules`` (or a module below one of them), one that
    one of them exports by name, for a package that re-exports plugins defined
    elsewhere, and one that one of them lists in its ``ASH_CONVERTERS``,
    ``ASH_SCANNERS``, ``ASH_REPORTERS`` or ``ASH_EVENT_HANDLERS``, for a module
    that declares a handler defined elsewhere without binding it by name.
    ``plugin_modules`` takes the same entries ``load_additional_plugin_modules``
    does, comma lists included.
    """
    from automated_security_helper.config.plugin_module_trust import (
        split_plugin_modules,
    )

    roots = (INTERNAL_PLUGIN_PACKAGE, *split_plugin_modules(plugin_modules))
    # Keyed by id for identity matching; the values keep each object alive
    # while the filter exists, so no key can be reused by another object (the
    # shape scan_plugin_filter uses): a listed entry a custom iterable built
    # could otherwise be freed and its id handed to an unrelated callable. The
    # namespace is read through _bound_in, one list() over the live dict in C,
    # where a comprehension over vars(module).values() raised "dictionary
    # changed size during iteration" when another thread imported a submodule
    # into the package meanwhile.
    exported: Dict[int, Any] = {}
    for root in roots:
        for value in _bound_in(root):
            if isinstance(value, (type, types.FunctionType)):
                exported[id(value)] = value
        for value in _declared_by(root):
            exported[id(value)] = value

    def belongs(plugin: Any) -> bool:
        # The object as listed or exported first, a functools.partial included:
        # a declared partial is the listed object itself, and unwrapping it
        # before the identity check would compare its function instead.
        if exported.get(id(plugin)) is plugin:
            return True
        # A functools.partial reports functools as its module; its function is
        # what was defined somewhere.
        while isinstance(plugin, functools.partial):
            plugin = plugin.func
        if exported.get(id(plugin)) is plugin:
            return True
        # callable_module is never-raising, like callback_display_name: the
        # loader accepts callables whose attribute reads raise or hold odd
        # values, and subscriptions are process-wide, so a filter that raises
        # on one callback breaks every scoped notify of its event -- in other
        # runs' scans too. Such a callback is left out of the scope instead.
        name = callable_module(plugin)
        if name is None:
            return False
        return any(name == root or name.startswith(root + ".") for root in roots)

    return belongs
