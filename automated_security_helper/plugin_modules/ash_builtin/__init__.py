# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib

from automated_security_helper.plugins.events import AshEventType


def _load_module(module_path: str):
    """Import a module by its dotted path and return it."""
    # nosec
    return importlib.import_module(
        module_path
    )  # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import


def _plugin_classes(module, base) -> list:
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
    """Load all built-in plugin classes lazily via importlib.

    The @ash_scanner_plugin / @ash_converter_plugin / @ash_reporter_plugin
    decorators fire at import time to register each class with the plugin
    manager, so the import itself is sufficient for registration.
    """
    from automated_security_helper.base.converter_plugin import ConverterPluginBase
    from automated_security_helper.base.reporter_plugin import ReporterPluginBase
    from automated_security_helper.base.scanner_plugin import ScannerPluginBase

    _base = "automated_security_helper.plugin_modules.ash_builtin"

    # -- Converters --
    converters_mod = _load_module(f"{_base}.converters")

    # -- Scanners --
    scanners_mod = _load_module(f"{_base}.scanners")

    # -- Reporters --
    reporters_mod = _load_module(f"{_base}.reporters")

    # -- Event Handlers --
    event_handlers_mod = _load_module(f"{_base}.event_handlers")
    handle_scan_completion_logging = event_handlers_mod.handle_scan_completion_logging
    handle_suppression_expiration_check = (
        event_handlers_mod.handle_suppression_expiration_check
    )

    return (
        _plugin_classes(converters_mod, ConverterPluginBase),
        _plugin_classes(scanners_mod, ScannerPluginBase),
        _plugin_classes(reporters_mod, ReporterPluginBase),
        {
            AshEventType.SCAN_COMPLETE: [handle_scan_completion_logging],
            AshEventType.EXECUTION_START: [handle_suppression_expiration_check],
        },
    )


# Lazy-load on first access via load_internal_plugins() in plugins/loader.py.
# The module-level lists below are populated once _load_builtin_plugins runs
# (triggered by `importlib.import_module` in the loader).
_loaded = _load_builtin_plugins()

ASH_CONVERTERS = _loaded[0]
ASH_SCANNERS = _loaded[1]
ASH_REPORTERS = _loaded[2]
ASH_EVENT_HANDLERS = _loaded[3]
