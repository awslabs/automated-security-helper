# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import importlib.util
from typing import List
from automated_security_helper.utils.log import ASH_LOGGER


def _find_plugin_package(name: str):
    """Return the spec of top-level regular package *name*, or None.

    This looks the name up directly instead of enumerating ``sys.path`` with
    ``pkgutil.iter_modules()``. That enumeration only ever yields top-level names,
    so the one match it could make was ``name == namespace``; a direct lookup gives
    the same answer without reading every ``sys.path`` entry.

    Reading every entry is what broke. On CPython 3.13 and later,
    ``zipimporter.invalidate_caches()`` drops the archive from
    ``zipimport._zip_directory_cache``, and ``pkgutil``'s zip iterator indexes that
    private dict directly, so after any ``importlib.invalidate_caches()`` a full
    ``iter_modules()`` raises ``KeyError`` for every zip archive on ``sys.path``.
    On Windows a console-script launcher such as ``ash.exe`` or ``pytest.exe`` is a
    zip archive and is ``sys.path[0]``, so plugin discovery crashed there.

    Dotted names are skipped, as the ``sys.path`` walk always skipped them: finding
    them would import their parent package, and ``load_additional_plugin_modules``
    already imports dotted plugin modules after checking them against its
    namespace allowlist.
    """
    if not name or "." in name:
        return None
    try:
        spec = importlib.util.find_spec(name)
    except (ImportError, ValueError):
        return None
    if spec is None:
        return None
    # pkgutil.iter_modules() reported only regular packages (a directory with an
    # __init__) as ispkg; a namespace package has no origin.
    if spec.submodule_search_locations is None or spec.origin is None:
        return None
    return spec


def discover_plugins(plugin_modules: List[str] | None = None):
    """Discover plugins in the given namespace"""
    if plugin_modules is None:
        plugin_modules = ["ash_plugins"]
    discovered = {"converters": [], "scanners": [], "reporters": []}

    # Look for top-level packages named exactly like a requested namespace
    for name in dict.fromkeys(plugin_modules):
        if _find_plugin_package(name) is None:
            continue
        try:
            # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
            module = importlib.import_module(name)
            # The import itself should trigger plugin registration
            # via the AshPlugin metaclass
            ASH_LOGGER.info(f"Discovered plugin package: {name}")

            # Track what was discovered
            if hasattr(module, "ASH_CONVERTERS"):
                discovered["converters"].extend(module.ASH_CONVERTERS)
            if hasattr(module, "ASH_SCANNERS"):
                discovered["scanners"].extend(module.ASH_SCANNERS)
            if hasattr(module, "ASH_REPORTERS"):
                discovered["reporters"].extend(module.ASH_REPORTERS)

        except ImportError as e:
            ASH_LOGGER.warning(f"Failed to import plugin {name}: {e}")

    return discovered
