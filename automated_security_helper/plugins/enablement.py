# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Default enablement of the plugin modules ASH ships, read from the manifests.

Policy, in one sentence: a shipped plugin module whose manifests are
``default_enabled`` loads without being named; every other plugin module -- a
shipped opt-in package and a custom SDK plugin identically -- loads when
``ash_plugin_modules`` (or ``--ash-plugin-modules``) names it or when it is
installed as its own distribution. This module is the one place that turns the
manifest's ``default_enabled`` field into those answers, plus the same read in
the error direction: the "you named a scanner ASH ships whose module this run did
not load; add the module" hint. Everything else iterates the merged plugin
surface and consults nothing (``tests/unit/test_enablement_is_read_in_few_places.py``
enforces that).

There is one source: the manifests (``automated_security_helper.plugin_manifests``).
A plugin's maturity (``tier``) is a separate field of the same record and is not
read here, so promoting an opt-in scanner to ``supported`` changes nothing this
module answers. The module sets are derived from each manifest's
``plugin_module``; no member list is kept beside the manifests.

Reading a manifest imports no plugin, which is what lets the hint name a module
without loading the scanner it reports as not loaded.
"""

from __future__ import annotations

from typing import Dict, Iterable, Mapping, Sequence, Tuple

from automated_security_helper.plugin_manifests import (
    opt_in_module_for,
    scanner_manifests,
)


def modules_loading_unnamed() -> Tuple[str, ...]:
    """Every shipped plugin module a scan loads without naming it, sorted.

    The loader's "internal plugins" set: the ``plugin_module`` of every manifest
    that is ``default_enabled``.
    """
    return tuple(
        sorted({m.plugin_module for m in scanner_manifests() if m.default_enabled})
    )


def modules_needing_naming() -> Tuple[str, ...]:
    """Every shipped plugin module that loads only when named or installed, sorted.

    The ``plugin_module`` of every manifest that is not ``default_enabled``,
    less any module a ``default_enabled`` manifest also names.
    """
    unnamed = set(modules_loading_unnamed())
    return tuple(
        sorted(
            {
                m.plugin_module
                for m in scanner_manifests()
                if not m.default_enabled and m.plugin_module not in unnamed
            }
        )
    )


def loads_unnamed(module: str) -> bool:
    """Whether *module* loads without being named, or is inside a module that does.

    This is the loader's enable-default decision in one place. Everything that
    is not within such a module -- the other shipped packages and custom plugins
    alike -- loads when named or installed, so nothing downstream of the loader
    can tell those two apart by mechanics.
    """
    return any(
        module == root or module.startswith(root + ".")
        for root in modules_loading_unnamed()
    )


def unloaded_opt_in_scanners(
    requested: Iterable[str],
    known_names: Iterable[str],
    scanner_classes: Iterable[type],
) -> Dict[str, str]:
    """``{requested name: plugin module}`` for the names that resolve to nothing
    but name a scanner ASH ships whose module this run did not load.

    The manifests map each opt-in scanner's name (and alias) to its plugin module
    without importing it. "Not loaded" means no class in *scanner_classes* comes
    from the module: a module that did supply this run's scanners, but not the
    requested name, is not reported (the hint would send the operator to add what
    is already there), and ``sys.modules`` is not consulted, because anything in
    the process may have imported a module this run did not list. Names are
    compared lower-cased and stripped, as ScanPhase compares them.
    """
    known = {str(name).lower().strip() for name in known_names}
    loaded = {str(getattr(cls, "__module__", "")) for cls in scanner_classes}
    unloaded: Dict[str, str] = {}
    for name in requested:
        if name.lower().strip() in known:
            continue
        module = opt_in_module_for(name)
        if module and not any(
            loaded_module == module or loaded_module.startswith(module + ".")
            for loaded_module in loaded
        ):
            unloaded[name] = module
    return unloaded


def unloaded_opt_in_hint(unloaded: Mapping[str, str]) -> str:
    """The sentence naming the module(s) to add for *unloaded*, or "" for none."""
    if not unloaded:
        return ""
    modules = sorted(set(unloaded.values()))
    provided = (
        f"is provided by {modules[0]}, which this run did not load."
        if len(unloaded) == 1
        else f"are provided by {', '.join(modules)}, which this run did not load."
    )
    return (
        f"{', '.join(sorted(unloaded))} {provided}"
        " Add "
        f"{', '.join(modules)} to ash_plugin_modules in the ASH config, or pass "
        + " ".join(f"--ash-plugin-modules {module}" for module in modules)
        + "."
    )


def unloaded_opt_in_refusal(
    requested: Sequence[str],
    known_names: Iterable[str],
    scanner_classes: Iterable[type],
) -> str:
    """The refusal text for an allowlist that resolves to nothing and names an
    unloaded shipped scanner, or "" when this refusal does not apply.

    One text for the engine's construction-time check and ScanPhase's backstop,
    so both refuse in the same words: the module to add, and beside it every
    requested name that is neither registered nor a shipped scanner, so the
    operator is not sent to add a module and then refused again for the
    misspelling the first refusal dropped. Not when nothing is registered
    (*scanner_classes* empty): there is nothing to judge the names against, and
    ``refuse_selection_matching_no_scanner`` and ScanPhase skip that case too.
    Not when any requested name resolves: such a run scans what resolved and
    ScanPhase warns about the rest.
    """
    scanner_classes = list(scanner_classes)
    if not requested or not scanner_classes:
        return ""
    known = {str(name).lower().strip() for name in known_names}
    if any(name.lower().strip() in known for name in requested):
        return ""
    unloaded = unloaded_opt_in_scanners(requested, known, scanner_classes)
    if not unloaded:
        return ""
    misspelled = sorted(set(requested) - set(unloaded))
    also = (
        " No registered scanner matches "
        f"{', '.join(misspelled)} either: check the spelling, "
        "names use hyphens, not underscores."
        if misspelled
        else ""
    )
    return unloaded_opt_in_hint(unloaded) + also
