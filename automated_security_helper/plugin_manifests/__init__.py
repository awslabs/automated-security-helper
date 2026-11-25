# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The manifests of the plugins ASH ships, readable without loading any plugin.

Each module here is pure data: a ``MANIFESTS`` tuple of
:class:`~automated_security_helper.base.plugin_manifest.ScannerManifest` built
from literals, for one plugin package under ``plugin_modules``. Nothing here
imports a plugin, so reading a manifest never fires a plugin's
``@ash_scanner_plugin`` registration. That is what lets the scan phase say
"``snyk-code`` is an alpha scanner; add this module" without loading the scanner
it is reporting as not loaded, and it is what replaces the earlier reader that
parsed plugin sources as text to get the same answer.

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
from typing import Dict, Optional

from automated_security_helper.base.plugin_manifest import (
    PluginTier,
    ScannerManifest,
)


class ManifestRegistryError(ValueError):
    """The shipped manifests contradict each other."""


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


@functools.lru_cache(maxsize=1)
def alpha_scanner_modules() -> Dict[str, str]:
    """``{scanner name or alias: dotted plugin module}`` for every alpha scanner.

    The manifest tier scan. Keys are lower-case.
    """
    mapping: Dict[str, str] = {}
    for manifest in scanner_manifests():
        if manifest.tier is not PluginTier.ALPHA:
            continue
        for name in (manifest.name, *manifest.aliases):
            mapping.setdefault(name, manifest.plugin_module)
    return mapping


def alpha_module_for(scanner_name: str) -> Optional[str]:
    """The module that provides *scanner_name*, or None if no alpha one does."""
    return alpha_scanner_modules().get(str(scanner_name).lower().strip())
