# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import threading
from typing import Dict, List, Tuple

from automated_security_helper.plugins.events import AshEventType

_BASE = "automated_security_helper.plugin_modules.ash_builtin"


def _load_module(module_path: str):
    """Import a module by its dotted path and return it."""
    # nosec
    return importlib.import_module(
        module_path
    )  # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import


#: Plugin group name -> module path suffix, in import order.
#:
#: Each group is imported in its own try/except so an ImportError in one (an
#: optional third-party dependency missing from a scanner module, say) cannot cost
#: the groups imported after it. Measured on this tree with `detect_secrets`
#: blocked, before isolation: 2 converters and 4 scanners registered, 0 reporters,
#: neither event handler, and `load_internal_plugins` reported zeros for all three.
#:
#: Only the MODULES are listed here. The classes each one contributes are derived
#: from its ``__all__`` by ``_plugin_classes``, so this table cannot drift from the
#: packages the way a hand-written class list did (``GHASReporter`` and
#: ``GitLabCycloneDXReporter`` were registered but missing from ``ASH_REPORTERS``).
#: It is still the run's record of what it INTENDED to load: a group that fails is
#: reported by module path rather than inferred from the shape of what survived.
_PLUGIN_GROUPS: Tuple[Tuple[str, str], ...] = (
    ("converters", "converters"),
    ("scanners", "scanners"),
    ("reporters", "reporters"),
    ("event_handlers", "event_handlers"),
)

#: Event type -> the exported handler names subscribed to it.
_EVENT_HANDLER_NAMES: Dict[AshEventType, Tuple[str, ...]] = {
    AshEventType.SCAN_COMPLETE: ("handle_scan_completion_logging",),
    AshEventType.EXECUTION_START: ("handle_suppression_expiration_check",),
}


def _plugin_classes(module, base) -> list[type]:
    """Return every ``base`` subclass the module exports, sorted by class name.

    Why this exists rather than a hand-written list per plugin kind: importing a
    plugin package fires its ``@ash_*_plugin`` decorators, so the *registered*
    set is whatever that package exports. Naming the classes a second time in
    ``_load_builtin_plugins`` created a second, independent inventory that
    nothing reconciled against the first, and it drifted -- ``GHASReporter`` and
    ``GitLabCycloneDXReporter`` were registered by their decorators but absent
    from ``ASH_REPORTERS``, which is what ``plugins/discovery.py`` reads. The
    two reporters were therefore invisible to plugin discovery while being live
    in the registry.

    Deriving the list means "exported by the package" and "in ASH_REPORTERS" are
    the same statement, so adding a reporter cannot forget this file.

    ``__all__`` is the enumeration source because it is the package's own
    declaration of what it exports; the ``base`` filter then drops exported
    non-plugin helpers such as ``ReportContentEmitter``, which is a plain class
    and not a ``ReporterPluginBase``.
    """
    found = []
    for name in getattr(module, "__all__", ()):
        obj = getattr(module, name, None)
        if isinstance(obj, type) and issubclass(obj, base) and obj is not base:
            found.append(obj)
    if not found:
        # An empty inventory would silently disable a whole plugin kind, which is
        # indistinguishable from "this package legitimately ships none" at every
        # call site downstream. Builtin packages always ship some.
        raise RuntimeError(
            f"{module.__name__} exported no {base.__name__} subclasses via __all__; "
            f"builtin plugin discovery would silently come up empty."
        )
    return sorted(found, key=lambda cls: cls.__name__)


def _load_builtin_plugins():
    """Import each built-in plugin group in isolation and report what was lost.

    The @ash_scanner_plugin / @ash_converter_plugin / @ash_reporter_plugin
    decorators fire at import time to register each class with the plugin manager,
    so the import itself is sufficient for registration.

    ONE TRY/EXCEPT PER GROUP, not one around the set. A single unguarded optional
    third-party import inside one scanner module used to cost every plugin module
    imported after it -- the 15 reporters and both event handlers have nothing to
    do with a secrets scanner's dependencies, and they went with it because they
    import last. Per-group isolation bounds that to the group that actually broke.

    Isolation on its own would make the loss quieter, not louder: a degraded run
    that reports nothing is worse than a startup crash, because the crash is
    visible and the clean report is not. So the failed group names are returned
    alongside the plugins, `load_internal_plugins` logs them at ERROR, and
    `ScanPhase` records a MISSING row for each one so both completeness gates can
    see it.

    Returns:
        (converters, scanners, reporters, event_handlers, load_errors) where
        load_errors maps a failed module's dotted path to the error text.
    """
    from automated_security_helper.base.converter_plugin import ConverterPluginBase
    from automated_security_helper.base.reporter_plugin import ReporterPluginBase
    from automated_security_helper.base.scanner_plugin import ScannerPluginBase

    plugin_bases = {
        "converters": ConverterPluginBase,
        "scanners": ScannerPluginBase,
        "reporters": ReporterPluginBase,
    }
    plugins: Dict[str, List[type]] = {group: [] for group in plugin_bases}
    handler_exports: Dict[str, object] = {}
    load_errors: Dict[str, str] = {}

    for group, module_suffix in _PLUGIN_GROUPS:
        module_path = f"{_BASE}.{module_suffix}"
        try:
            module = _load_module(module_path)
        except ImportError as exc:
            # ImportError only. A module that raises something else is stating that
            # ASH itself is broken rather than that an optional dependency is
            # absent, and swallowing that would turn a bug into a quietly smaller
            # plugin set. `_plugin_classes` raising RuntimeError on an empty
            # inventory is deliberately outside this handler for the same reason.
            load_errors[module_path] = f"{type(exc).__name__}: {exc}"
            continue

        if group in plugin_bases:
            plugins[group] = _plugin_classes(module, plugin_bases[group])
            continue

        for handler_names in _EVENT_HANDLER_NAMES.values():
            for attribute_name in handler_names:
                try:
                    handler_exports[attribute_name] = getattr(module, attribute_name)
                except AttributeError as exc:
                    # The module imported but does not export a handler this table
                    # names. Recorded rather than raised for the same reason as
                    # above, and per attribute so one renamed export does not read
                    # as the whole group failing.
                    load_errors[f"{module_path}.{attribute_name}"] = (
                        f"{type(exc).__name__}: {exc}"
                    )

    event_handlers = {
        event_type: [
            handler_exports[name] for name in handler_names if name in handler_exports
        ]
        for event_type, handler_names in _EVENT_HANDLER_NAMES.items()
    }

    return (
        plugins["converters"],
        plugins["scanners"],
        plugins["reporters"],
        event_handlers,
        load_errors,
    )


# Lazy-load on first access via load_internal_plugins() in plugins/loader.py.
# The module-level lists below are populated once _load_builtin_plugins runs
# (triggered by `importlib.import_module` in the loader).
_loaded = _load_builtin_plugins()

ASH_CONVERTERS = _loaded[0]
ASH_SCANNERS = _loaded[1]
ASH_REPORTERS = _loaded[2]
ASH_EVENT_HANDLERS = _loaded[3]

#: Modules in this package that failed to import, mapped to the error text.
#:
#: Empty on a healthy install. Read by ``load_internal_plugins``, which raises the
#: finding to ERROR and passes it to its callers, because a plugin group silently
#: missing from the set is the failure the completeness gate exists to catch.
ASH_PLUGIN_LOAD_ERRORS: Dict[str, str] = _loaded[4]


#: Serializes retry_failed_plugin_groups. load_internal_plugins runs once per
#: ScanExecutionEngine, and workspace mode builds those on several threads at once.
_retry_lock = threading.Lock()


def retry_failed_plugin_groups() -> Dict[str, str]:
    """Import each plugin group that failed to import again, and keep what loads now.

    Returns the load errors that remain, which is empty when every group loaded.

    WHY A GROUP CAN FAIL ONLY BECAUSE OF WHAT WAS IMPORTED FIRST. This package is
    loaded as a side effect of importing ``models.asharp_model``: its
    ``_resolve_forward_refs()`` imports ``config.ash_config``, which imports
    built-in plugin modules for their config classes, which runs this package's
    module body. The plugin modules import core modules back -- the reporters import
    ``core.unified_metrics`` and ``core.scanner_statistics_calculator``, the other
    groups ``utils.sarif_utils`` and ``utils.suppression_matcher``. When one of those
    core modules is the first ASH module a process imports, it is still empty when
    its plugins import it, so the group raises ImportError and is recorded above.
    Measured by importing each of the package's 211 modules first in a fresh
    interpreter: seven lost at least one group, ``interactions.run_ash_scan`` (the
    programmatic entry point) lost all 15 reporters, and
    ``utils.suppression_matcher`` lost every group.

    WHY RETRYING IS THE FIX, AND NOT A WORKAROUND FOR ONE ORDER. The cycle exists
    only while that first import is running. ``load_internal_plugins`` runs after
    it has finished, when the same import succeeds, so trying again there recovers
    every order without naming any of them. A group that fails for any other
    reason -- an optional dependency that is absent -- fails again and stays in
    ``ASH_PLUGIN_LOAD_ERRORS``, so nothing a completeness gate should see is
    hidden. ``models.asharp_model`` recovers its own half of the same cycle the same
    way, by resolving its forward reference again on first use.

    Rejected: breaking the cycle where it forms, at ``_resolve_forward_refs()``
    running at import time. Dropping that call would make every ``AshAggregatedResults``
    instance built through ``model_construct`` unserializable in a process that has
    not yet built one any other way (see the comment above ``_resolve_forward_refs``),
    and the core modules on the cycle would still form it again through any other
    import of the config.

    Importing a group again registers nothing twice. Its submodules that imported
    the first time are still in ``sys.modules`` and are not run again; only the
    modules that raised, which Python removed, run again, and none of them got as
    far as a plugin decorator before raising.

    The module attributes are rebound rather than mutated, so a reader that reads
    ``ASH_REPORTERS`` from this module after the call sees the recovered list.
    """
    global ASH_CONVERTERS, ASH_SCANNERS, ASH_REPORTERS, ASH_EVENT_HANDLERS
    global ASH_PLUGIN_LOAD_ERRORS
    if not ASH_PLUGIN_LOAD_ERRORS:
        return {}
    with _retry_lock:
        if ASH_PLUGIN_LOAD_ERRORS:
            loaded = _load_builtin_plugins()
            ASH_CONVERTERS = loaded[0]
            ASH_SCANNERS = loaded[1]
            ASH_REPORTERS = loaded[2]
            ASH_EVENT_HANDLERS = loaded[3]
            ASH_PLUGIN_LOAD_ERRORS = loaded[4]
        return dict(ASH_PLUGIN_LOAD_ERRORS)
