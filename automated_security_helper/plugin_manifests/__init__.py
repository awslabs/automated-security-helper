# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The manifests of the plugins ASH ships, readable without loading any plugin.

Each module here is pure data: a ``MANIFESTS`` tuple of
:class:`~automated_security_helper.base.plugin_manifest.ScannerManifest` built
from literals, for one plugin package under ``plugin_modules``. Nothing here
imports a plugin, so reading a manifest never fires a plugin's
``@ash_scanner_plugin`` registration. That is what lets the scan phase say
"``snyk-code`` is provided by this module, which this run did not load" without
loading the scanner it is reporting as not loaded, and it is what replaces the
earlier reader that parsed plugin sources as text to get the same answer. The
manifest is also the one source of which plugin modules load without being named
(``default_enabled``); ``plugins.enablement`` reads it there and nowhere else
re-derives it.

The modules are discovered by walking this package (``pkgutil``), so a new
plugin's manifest needs no edit here. The totality tests
(``tests/unit/plugin_manifests``) walk ``plugin_modules`` the same way and fail,
naming the scanner, for any registered scanner that has no manifest and any
manifest that names no registered scanner.

Registry rules, enforced when the manifests are first read:

- names are unique, and so are aliases across manifests;
- an alias may equal another manifest's NAME only through the retirement shape:
  that manifest is ``deprecated`` and ``superseded_by`` the alias's owner;
- a ``deprecated`` manifest's target exists and lists the deprecated name as an
  alias.
"""

from __future__ import annotations

import functools
import importlib
import pkgutil
from types import MappingProxyType
from typing import Any, Dict, Literal, Mapping, Optional

from automated_security_helper.base.plugin_manifest import (
    ConfigSection,
    ExclusionOption,
    PluginTier,
    ScannerManifest,
)


class ManifestRegistryError(ValueError):
    """The shipped manifests contradict each other, or one of them is malformed.

    The second shape is a fault in a single entry: a name that no table of the
    builtin module knows, a missing description, an options class that cannot
    yield its section class.
    """


def check_table_rows(
    module: str, names: set[str], **tables: Mapping[str, object]
) -> None:
    """Refuse a row of a manifest module's table that names no scanner it declares.

    A manifest module builds each manifest from tables keyed by scanner name and
    reads them with ``.get``, which answers "nothing declared" for a name no
    scanner has. A row left behind by a renamed or removed scanner is then
    dropped without a word, and the scanner ships without the options it was
    meant to carry (a client's exclusion entries, a denied option's default).
    Each module calls this once, after its ``MANIFESTS``, with the tables it reads.
    """
    for table_name, table in tables.items():
        unknown = sorted(set(table) - names)
        if unknown:
            raise ManifestRegistryError(
                f"{module}.{table_name} has rows for scanners the module does "
                f"not declare: {unknown}"
            )


def _load_manifests() -> tuple[ScannerManifest, ...]:
    manifests: list[ScannerManifest] = []
    for info in sorted(pkgutil.iter_modules(__path__), key=lambda m: m.name):
        module = importlib.import_module(f"{__name__}.{info.name}")
        manifests.extend(getattr(module, "MANIFESTS", ()))
    return tuple(sorted(manifests, key=lambda m: m.name))


def _check(manifests: tuple[ScannerManifest, ...]) -> None:
    by_name: Dict[str, ScannerManifest] = {}
    for manifest in manifests:
        if manifest.name in by_name:
            raise ManifestRegistryError(f"two manifests are named {manifest.name!r}")
        by_name[manifest.name] = manifest
    owners: Dict[str, str] = {}
    for manifest in manifests:
        for alias in manifest.aliases:
            if alias in owners:
                raise ManifestRegistryError(
                    f"alias {alias!r} is declared by both {owners[alias]!r} and "
                    f"{manifest.name!r}"
                )
            owners[alias] = manifest.name
            other = by_name.get(alias)
            if other is not None and not (
                other.tier is PluginTier.DEPRECATED
                and other.superseded_by == manifest.name
            ):
                raise ManifestRegistryError(
                    f"{manifest.name!r} declares {alias!r} as an alias, but "
                    f"{alias!r} is a scanner of its own; only a deprecated "
                    f"scanner superseded by {manifest.name!r} may be an alias "
                    "of it"
                )
    for manifest in manifests:
        if manifest.tier is not PluginTier.DEPRECATED:
            continue
        target = by_name.get(manifest.superseded_by or "")
        if target is None:
            raise ManifestRegistryError(
                f"{manifest.name!r} is superseded by {manifest.superseded_by!r}, "
                "which has no manifest"
            )
        if manifest.name not in target.aliases:
            raise ManifestRegistryError(
                f"{manifest.name!r} is superseded by {target.name!r}, which does "
                f"not list {manifest.name!r} among its aliases"
            )


@functools.lru_cache(maxsize=1)
def scanner_manifests() -> tuple[ScannerManifest, ...]:
    """Every shipped scanner manifest, sorted by name; refuses a contradiction."""
    manifests = _load_manifests()
    _check(manifests)
    return manifests


def manifest_for(name: str) -> Optional[ScannerManifest]:
    """The manifest named *name* (case and surrounding space ignored), or None.

    Aliases are not names: ask :func:`dispatch_target` which scanner serves one.
    """
    wanted = str(name).lower().strip()
    return next((m for m in scanner_manifests() if m.name == wanted), None)


def dispatch_target(name: str) -> Optional[str]:
    """The name of the scanner that serves *name*, or None if none does.

    A name with a manifest of its own is served by itself, except a
    ``deprecated`` one, which is served by the scanner it names in
    ``superseded_by``. A name that is only an alias is served by the manifest
    that declares it. This DECLARES the dispatch; nothing in the scan path
    consults it yet, so declaring a retirement changes no run until a separate
    change wires it.
    """
    wanted = str(name).lower().strip()
    own = manifest_for(wanted)
    if own is not None:
        return own.superseded_by or own.name
    return next(
        (m.name for m in scanner_manifests() if wanted in m.aliases),
        None,
    )


def plugin_config_sections(
    kind: Literal["scanners", "reporters", "converters"],
) -> tuple[tuple[str, ConfigSection], ...]:
    """``(plugin name, section)`` for every plugin of *kind* that has a typed config section.

    The order is the order of the config schema: scanners by their Python field
    name, reporters and converters as declared in ``option_sections``. The config
    layer builds its root model's plugin sections from these rows, so it names
    no plugin.
    """
    from automated_security_helper.plugin_manifests import option_sections

    if kind == "reporters":
        return tuple(option_sections.REPORTER_SECTIONS)
    if kind == "converters":
        return tuple(option_sections.CONVERTER_SECTIONS)
    if kind != "scanners":
        # ``Literal`` is not checked at run time: a misspelled kind ("scanner",
        # "Reporters") would otherwise be answered with the scanner rows, and
        # the config root would be built from the wrong sections.
        raise ValueError(
            f"{kind!r} is not a plugin kind with config sections; expected "
            "'scanners', 'reporters' or 'converters'"
        )
    rows = [
        (manifest.name, manifest.config_section)
        for manifest in scanner_manifests()
        if manifest.config_section is not None
    ]
    return tuple(sorted(rows, key=lambda row: row[0].replace("-", "_")))


#: The list defaults of the options of the plugins ASH ships whose section is not a
#: typed field of the configuration (``plugin_config_sections`` lists the typed
#: ones): by config segment, then plugin name, then the option's path under the
#: section, the items of its default as JSON values.
#:
#: ``--config-overrides KEY+=VALUE`` reads it when KEY is such an option that no
#: config file wrote. For a section the configuration does not type, the document
#: the overrides are applied to holds only what a file wrote, so a ``+=`` has no
#: default to add to; the plugin's own options model has it, and cannot be imported
#: there, because importing a plugin package registers its plugins for the whole
#: process and the overrides are applied before any is imported. The defaults are
#: mirrored here as data, as ``alpha._DENIED_OPTION_DEFAULTS`` and
#: ``config.reporter_trust.REPORTER_DESTINATION_OPTIONS`` mirror theirs.
#: ``tests/unit/plugin_manifests/test_config_sections_and_exclusions.py`` walks the
#: shipped plugin packages and holds this table equal to their options models, so a
#: list option added to one of them, or a default changed, fails that test until
#: the table follows.
UNTYPED_LIST_OPTION_DEFAULTS: Mapping[
    str, Mapping[str, Mapping[tuple[str, ...], tuple[Any, ...]]]
] = MappingProxyType(
    {
        "reporters": MappingProxyType(
            {
                "bedrock-summary-reporter": MappingProxyType(
                    {
                        ("options", "compliance_frameworks"): (),
                        ("options", "exclude_scanner_types"): ("SECRET",),
                        ("options", "exclude_sections"): (),
                        ("options", "include_sections"): (
                            "executive_summary",
                            "risk_assessment",
                            "technical_analysis",
                            "remediation_guide",
                            "compliance_impact",
                        ),
                    }
                ),
            }
        ),
        "scanners": MappingProxyType(
            {
                "ferret-scan": MappingProxyType({("options", "exclude_patterns"): ()}),
                "guarddog": MappingProxyType(
                    {
                        ("options", "ecosystems"): (
                            "pypi",
                            "npm",
                            "go",
                            "github_action",
                            "rubygems",
                            "crates",
                        ),
                        ("options", "exclude_rules"): (),
                        ("options", "excluded_paths"): (),
                        ("options", "rules"): (),
                    }
                ),
                "trivy-repo": MappingProxyType(
                    {
                        ("options", "scanners"): (
                            "vuln",
                            "secret",
                            "misconfig",
                            "license",
                        )
                    }
                ),
            }
        ),
    }
)


@functools.lru_cache(maxsize=1)
def exclusion_options() -> tuple[tuple[str, ExclusionOption], ...]:
    """``(scanner name, option)`` for every option a client config may exclude by.

    In manifest order (by scanner name, then as declared).
    """
    return tuple(
        (manifest.name, option)
        for manifest in scanner_manifests()
        for option in manifest.exclusion_options
    )


@functools.lru_cache(maxsize=1)
def opt_in_scanner_modules() -> Dict[str, str]:
    """``{scanner name or alias: dotted plugin module}`` for every scanner that
    ships but is not loaded unless its module is named.

    Keyed on ``default_enabled``, not on ``tier``: the callers (the "add this
    module" hint, ``dependencies install``, the MCP inventory's shipped-module
    list) all ask about loading, and a maintained scanner that stays opt-in is
    ``supported`` and still needs naming. Keys are lower-case.
    """
    mapping: Dict[str, str] = {}
    for manifest in scanner_manifests():
        if manifest.default_enabled:
            continue
        for name in (manifest.name, *manifest.aliases):
            mapping.setdefault(name, manifest.plugin_module)
    return mapping


def opt_in_module_for(scanner_name: str) -> Optional[str]:
    """The module that provides *scanner_name*, or None if no opt-in one does."""
    return opt_in_scanner_modules().get(str(scanner_name).lower().strip())
