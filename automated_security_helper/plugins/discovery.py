# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import importlib.util
from typing import List
from automated_security_helper.utils.log import ASH_LOGGER


def _is_top_level_package(name: str) -> bool:
    """Whether ``name`` is an importable top-level regular package.

    This used to be answered by walking ``pkgutil.iter_modules()`` -- every entry on
    sys.path -- and comparing names. That walk can raise on an entry that is not a
    module directory at all. On Windows a console-script launcher such as
    ``.venv\\Scripts\\pytest.exe`` is a zip archive and lands on sys.path, so a
    zipimporter for it sits in sys.path_importer_cache. ``importlib.invalidate_caches()``
    (which ``monkeypatch.syspath_prepend`` calls, among others) evicts that archive
    from ``zipimport._zip_directory_cache``, and pkgutil's zip walker indexes that
    private dict directly, so the next walk raised ``KeyError: '...\\pytest.exe'``
    out of discover_plugins (unit-test windows-latest py3.14, run 37632758015, job
    112839639522). Nothing about the plugin being looked for was involved.

    Asking for the one name instead touches no other sys.path entry, and the
    zipimporter's own find_spec repopulates its cache rather than indexing it.

    Kept to what the walk matched. It yielded top-level names only, so a dotted name
    never matched, and it reported a directory as a package only if it had an
    ``__init__`` -- a namespace package (origin None) was not one. One deliberate
    difference: find_spec also consults meta-path finders, so a plugin package
    installed in editable mode through an import hook is now found where the
    sys.path walk could not see it.
    """
    if not name or "." in name:
        return False
    try:
        spec = importlib.util.find_spec(name)
    except Exception as e:  # a broken finder must not stop discovery
        ASH_LOGGER.warning(f"Could not look up plugin package {name}: {e}")
        return False
    return (
        spec is not None
        and spec.submodule_search_locations is not None
        and spec.origin is not None
    )


def discover_plugins(plugin_modules: List[str] | None = None):
    """Discover plugins in the given namespace"""
    if plugin_modules is None:
        plugin_modules = ["ash_plugins"]
    discovered = {"converters": [], "scanners": [], "reporters": []}

    # Look for top-level packages named by plugin_modules
    for name in dict.fromkeys(plugin_modules):
        if not _is_top_level_package(name):
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
