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


#: Module path suffix -> the attributes that module is expected to export.
#:
#: DECLARATIVE SO THE LOSS IS MEASURABLE, which is the whole reason this replaced
#: a straight-line sequence of `_load_module` calls. Plugin registration is a
#: decorator side effect at class-definition time, so a module that raises
#: part-way through leaves the classes defined before the raise registered and the
#: rest absent -- and the old shape let one ImportError abort the remaining groups
#: too, because they were imported by the same function. Measured on this tree with
#: `detect_secrets` blocked: 2 converters and 4 scanners registered, 0 reporters,
#: neither event handler, and `load_internal_plugins` reported zeros for all three.
#:
#: This table drives the imports, so it cannot drift from them the way a separate
#: manifest would. That matters because it is also the run's record of what it
#: INTENDED to load: a group that fails is reported by name rather than inferred
#: from the shape of what survived.
_PLUGIN_GROUPS: Tuple[Tuple[str, str, Tuple[str, ...]], ...] = (
    (
        "converters",
        "converters",
        ("ArchiveConverter", "JupyterConverter"),
    ),
    (
        "scanners",
        "scanners",
        (
            "BanditScanner",
            "CdkNagScanner",
            "CfnNagScanner",
            "CheckovScanner",
            "DetectSecretsScanner",
            "GrypeScanner",
            "NpmAuditScanner",
            "OpengrepScanner",
            "SemgrepScanner",
            "SyftScanner",
        ),
    ),
    (
        "reporters",
        "reporters",
        (
            "CsvReporter",
            "CycloneDXReporter",
            "FlatJsonReporter",
            "GitLabSASTReporter",
            "HtmlReporter",
            "JunitXmlReporter",
            "MarkdownReporter",
            "OcsfReporter",
            "SarifReporter",
            "SpdxReporter",
            "TextReporter",
            "UnusedSuppressionsReporter",
            "YamlReporter",
        ),
    ),
    (
        "event_handlers",
        "event_handlers",
        (
            "handle_scan_completion_logging",
            "handle_suppression_expiration_check",
        ),
    ),
)

#: Event type -> the exported handler names subscribed to it.
_EVENT_HANDLER_NAMES: Dict[AshEventType, Tuple[str, ...]] = {
    AshEventType.SCAN_COMPLETE: ("handle_scan_completion_logging",),
    AshEventType.EXECUTION_START: ("handle_suppression_expiration_check",),
}


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
    exports: Dict[str, object] = {}
    load_errors: Dict[str, str] = {}

    for group, module_suffix, attribute_names in _PLUGIN_GROUPS:
        module_path = f"{_BASE}.{module_suffix}"
        try:
            module = _load_module(module_path)
        except ImportError as exc:
            # ImportError only. A module that raises something else is stating that
            # ASH itself is broken rather than that an optional dependency is
            # absent, and swallowing that would turn a bug into a quietly smaller
            # plugin set.
            load_errors[module_path] = f"{type(exc).__name__}: {exc}"
            continue

        for attribute_name in attribute_names:
            try:
                exports[attribute_name] = getattr(module, attribute_name)
            except AttributeError as exc:
                # The module imported but does not export what this table says it
                # does. Recorded rather than raised for the same reason as above,
                # and recorded per attribute so one renamed export does not read as
                # the whole group failing.
                load_errors[f"{module_path}.{attribute_name}"] = (
                    f"{type(exc).__name__}: {exc}"
                )

    def _present(group: str) -> List[object]:
        """The classes from *group* that actually made it into ``exports``."""
        for candidate_group, _suffix, attribute_names in _PLUGIN_GROUPS:
            if candidate_group != group:
                continue
            return [exports[name] for name in attribute_names if name in exports]
        return []

    event_handlers = {
        event_type: [exports[name] for name in handler_names if name in exports]
        for event_type, handler_names in _EVENT_HANDLER_NAMES.items()
    }

    return (
        _present("converters"),
        _present("scanners"),
        _present("reporters"),
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
