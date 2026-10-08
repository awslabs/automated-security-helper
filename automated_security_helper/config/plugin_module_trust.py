# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which ``ash_plugin_modules`` entries a config file in the scanned tree may add.

ASH imports every module ``ash_plugin_modules`` names into its own process. When the
config was built from a file inside the scanned tree (``config/sandbox_grants.py``
decides that), the entries it adds beyond the trusted list (the defaults, an
operator config outside the tree, and ``--config-overrides``) are kept only if
they name an installed module: one that ``importlib.util.find_spec`` locates
outside the scanned tree. An entry that is not importable, or whose spec points
into the tree, is dropped with one warning naming ``ash_plugin_modules``.

Packages named this way keep working, which is what ASH's own
``.ash/.ash_community_plugins.yaml`` relies on: its entries live in the installed
``automated_security_helper`` package. A module inside the directory the running
``automated_security_helper`` package was imported from is ASH's own code and is
kept even when that directory is in the tree, as it is for an editable install of
the repository being scanned; that code is already running.

Locating a dotted name imports its parent packages, so each level is checked
before the next is looked up, and a parent that fails the check is never imported.
``--ash-plugin-modules`` and ``ASH_PLUGIN_MODULES`` are the operator's and are not
filtered here.
"""

from __future__ import annotations

import importlib.util
from importlib.machinery import ModuleSpec
from pathlib import Path
from typing import TYPE_CHECKING, Iterable, List, Optional, Sequence

from automated_security_helper.config.config_sources import describe_config_path
from automated_security_helper.config.sandbox_grants import is_within
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig


def split_plugin_modules(entries: Optional[Iterable[object]]) -> List[str]:
    """Entries split on commas and stripped, the way ScanExecutionEngine reads them."""
    names: List[str] = []
    for entry in entries or []:
        if entry is None:
            continue
        for part in str(entry).split(","):
            part = part.strip()
            if part and part not in names:
                names.append(part)
    return names


def _own_package_dir() -> Optional[Path]:
    import automated_security_helper

    origin = getattr(automated_security_helper, "__file__", None)
    return Path(origin).resolve().parent if origin else None


def _spec_locations(spec: ModuleSpec) -> List[Path]:
    locations = [Path(p) for p in (spec.submodule_search_locations or [])]
    if spec.has_location and spec.origin:
        locations.append(Path(spec.origin))
    return locations


def refusal_reason(name: str, scanned_root: Path) -> Optional[str]:
    """Why ``name`` may not be imported for a config in the scanned tree, or None."""
    own = _own_package_dir()
    parts = name.split(".")
    for depth in range(1, len(parts) + 1):
        prefix = ".".join(parts[:depth])
        try:
            spec = importlib.util.find_spec(prefix)
        except (ImportError, ValueError):
            spec = None
        if spec is None:
            return "it is not importable from the installed environment"
        for location in _spec_locations(spec):
            if own is not None and is_within(location, own):
                continue
            if is_within(location, scanned_root):
                return "it resolves inside the scanned tree"
    return None


def confine_plugin_modules(
    config: "AshConfig",
    trusted_config: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    scanned_root: Path,
    in_tree: Sequence[Path],
) -> None:
    """Drop the entries of ``config.ash_plugin_modules`` an in-tree file may not add.

    Args:
        config: The resolved AshConfig, changed in place.
        trusted_config: The trusted base ``resolve_config`` built for the sandbox
            settings: the defaults, or the operator's config outside the tree.
        config_overrides: ``--config-overrides``. Those under
            ``ash_plugin_modules`` are replayed onto ``trusted_config`` to get the
            trusted list, the same way the sandbox overrides are.
        scanned_root: The scanned tree (``sandbox_grants.scanned_tree``).
        in_tree: The config files inside the tree, named in the warning.
    """
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )

    module_overrides = [
        override
        for override in config_overrides or []
        if override.partition("=")[0].removesuffix("+").strip() == "ash_plugin_modules"
    ]
    if module_overrides:
        trusted_config = apply_config_overrides(trusted_config, module_overrides)
    trusted_names = set(split_plugin_modules(trusted_config.ash_plugin_modules))
    kept: List[str] = []
    refused: List[str] = []
    for name in split_plugin_modules(getattr(config, "ash_plugin_modules", [])):
        if name in trusted_names:
            kept.append(name)
            continue
        reason = refusal_reason(name, scanned_root)
        if reason is None:
            kept.append(name)
        else:
            refused.append(f"{name!r} ({reason})")
    if not refused:
        return
    config.ash_plugin_modules = kept
    files = ", ".join(describe_config_path(path) for path in in_tree)
    ASH_LOGGER.warning(
        f"Ignoring ash_plugin_modules entries {', '.join(refused)} from {files}: "
        "the file is inside the scanned tree, so only installed modules outside the "
        "tree are imported from it. Name other modules with --ash-plugin-modules, "
        "--config-overrides or a config file outside the tree."
    )
