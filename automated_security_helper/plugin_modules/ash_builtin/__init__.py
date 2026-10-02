# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
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
