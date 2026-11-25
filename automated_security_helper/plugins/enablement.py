# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The one behavioral meaning registry membership has: default enablement.

Policy, in one sentence: members of
:data:`automated_security_helper.plugins.registries.CORE` load without being
named; every other plugin module -- the other shipped registries' members and
custom SDK plugins identically -- loads when ``ash_plugin_modules`` (or
``--ash-plugin-modules``) names it or when it is installed as its own
distribution. The enablement default is the only thing membership changes, so
this module is the one place that reads membership to apply it, plus the same
read in the error direction: the "you named a scanner ASH ships whose module
this run did not load; add the module" hint. Everything else iterates the
merged plugin surface and consults nothing
(``tests/unit/test_registry_externality_site_count.py`` enforces that).

The scanner-name index here is read from the member packages' source files,
not by importing them: importing one runs its ``@ash_scanner_plugin``
registrations, which would load the scanners this module exists to report as
not loaded. A scanner's selectable name is the ``name: Literal["..."]``
default of its config class, a subclass of ``ScannerPluginConfigBase``. The
packages read are exactly the shipped members that need naming -- membership
comes from the registry declarations, never from a directory glob -- so a
package that is moved between registries changes this index in the same edit.
(When per-plugin manifests land, the name index moves onto them and the source
read retires.)
"""

from __future__ import annotations

import ast
import functools
from pathlib import Path
from typing import Dict, Iterable, Mapping, Optional, Sequence, Tuple

from automated_security_helper.plugins import registries

_PLUGIN_MODULES_PACKAGE = "automated_security_helper.plugin_modules"
_PLUGIN_MODULES_DIR = Path(__file__).resolve().parent.parent / "plugin_modules"

_WARNED_RENAMED_SPELLINGS: set[str] = set()


def warn_renamed_spelling(
    old: str, new: str, dropped_in: str, *, reason: Optional[str] = None
) -> None:
    """Say once per process that the spelling *old* is now *new*.

    The generalization of the community-tier alias warning
    (``core.alpha_scanners.warn_community_alias`` delegates here): one warning
    per old spelling per process, naming the release that stops accepting it.
    """
    if old in _WARNED_RENAMED_SPELLINGS:
        return
    _WARNED_RENAMED_SPELLINGS.add(old)
    # Imported here: the log module is not needed to answer policy queries.
    from automated_security_helper.utils.log import ASH_LOGGER

    because = f"{reason}, so use" if reason else "use"
    ASH_LOGGER.warning(
        f"'{old}' is deprecated: {because} '{new}'. The old spelling is "
        f"accepted until ASH {dropped_in}.",
        extra={"markup": False},
    )


def loads_unnamed(module: str) -> bool:
    """Whether *module* loads without being named: the CORE-membership read.

    This is the loader's enable-default decision in one place. Everything that
    is not within a CORE member -- other shipped registries' members and custom
    plugins alike -- loads when named or installed, so nothing downstream of
    the loader can tell those two apart by mechanics.
    """
    return registries.CORE.holds(module)


def modules_loading_unnamed() -> Tuple[str, ...]:
    """Every shipped plugin module a scan loads without naming it.

    The loader's "internal plugins" set, answered by the same uniform
    iteration as :func:`modules_needing_naming`.
    """
    return tuple(
        member
        for registry in registries.SHIPPED_REGISTRIES
        for member in registry.members
        if loads_unnamed(member)
    )


def modules_needing_naming() -> Tuple[str, ...]:
    """Every shipped plugin module that loads only when named or installed.

    A uniform iteration over all shipped registries, filtered by the one
    policy above; the answer does not say which registry a module came from.
    """
    return tuple(
        member
        for registry in registries.SHIPPED_REGISTRIES
        for member in registry.members
        if not loads_unnamed(member)
    )


def _scanner_config_names(source: str) -> list[str]:
    """``name`` defaults of every ``ScannerPluginConfigBase`` subclass in *source*."""
    names = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.ClassDef):
            continue
        bases = {
            b.id if isinstance(b, ast.Name) else getattr(b, "attr", None)
            for b in node.bases
        }
        if "ScannerPluginConfigBase" not in bases:
            continue
        for stmt in node.body:
            if (
                isinstance(stmt, ast.AnnAssign)
                and isinstance(stmt.target, ast.Name)
                and stmt.target.id == "name"
                and isinstance(stmt.value, ast.Constant)
                and isinstance(stmt.value.value, str)
            ):
                names.append(stmt.value.value)
    return names


@functools.lru_cache(maxsize=4)
def _scanner_names_by_module(members: Tuple[str, ...]) -> Dict[str, str]:
    """``{scanner name, lowercased: dotted module path}`` over *members*.

    Keyed on the member tuple, so a test that points the registries at a
    fixture set gets a fresh index instead of a stale cache.
    """
    mapping: Dict[str, str] = {}
    for member in members:
        if not member.startswith(_PLUGIN_MODULES_PACKAGE + "."):
            # Only in-tree packages have source files at a known place; a
            # shipped member outside the plugin-modules package (none today)
            # contributes no name hints rather than failing the index.
            continue
        relative = member[len(_PLUGIN_MODULES_PACKAGE) + 1 :]
        package_dir = _PLUGIN_MODULES_DIR.joinpath(*relative.split("."))
        if not (package_dir / "__init__.py").is_file():
            continue
        for source in sorted(package_dir.glob("*.py")):
            for name in _scanner_config_names(source.read_text(encoding="utf-8")):
                mapping.setdefault(name.lower(), member)
    return mapping


def shipped_scanner_modules() -> Dict[str, str]:
    """``{scanner name, lowercased: module path}`` for every shipped module
    that needs naming."""
    return dict(_scanner_names_by_module(modules_needing_naming()))


def shipped_module_for(scanner_name: str) -> Optional[str]:
    """The shipped, needs-naming module providing *scanner_name*, or ``None``."""
    return shipped_scanner_modules().get(str(scanner_name).lower().strip())


def unloaded_shipped_scanners(
    requested: Iterable[str],
    known_names: Iterable[str],
    scanner_classes: Iterable[type],
) -> Dict[str, str]:
    """``{requested name: plugin module}`` for the names that resolve to nothing
    but name a scanner ASH ships whose module this run did not load.

    "Not loaded" means no class in *scanner_classes* comes from the module: a
    module that did supply this run's scanners, but not the requested name, is
    not reported (the hint would send the operator to add what is already
    there), and ``sys.modules`` is not consulted, because anything in the
    process may have imported a module this run did not list. Names are
    compared lower-cased and stripped, as ScanPhase compares them.
    """
    known = {str(name).lower().strip() for name in known_names}
    loaded = {str(getattr(cls, "__module__", "")) for cls in scanner_classes}
    unloaded: Dict[str, str] = {}
    for name in requested:
        if name.lower().strip() in known:
            continue
        module = shipped_module_for(name)
        if module and not any(
            loaded_module == module or loaded_module.startswith(module + ".")
            for loaded_module in loaded
        ):
            unloaded[name] = module
    return unloaded


def unloaded_shipped_hint(unloaded: Mapping[str, str]) -> str:
    """The sentence naming the module(s) to add for *unloaded*, or "" for none."""
    if not unloaded:
        return ""
    modules = sorted(set(unloaded.values()))
    provided = (
        f"is provided by {modules[0]}, which this run did not load."
        if len(unloaded) == 1
        else (f"are provided by {', '.join(modules)}, which this run did not load.")
    )
    return (
        f"{', '.join(sorted(unloaded))} {provided}"
        " Add "
        f"{', '.join(modules)} to ash_plugin_modules in the ASH config, or pass "
        + " ".join(f"--ash-plugin-modules {module}" for module in modules)
        + "."
    )


def unloaded_shipped_refusal(
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
    unloaded = unloaded_shipped_scanners(requested, known, scanner_classes)
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
    return unloaded_shipped_hint(unloaded) + also
