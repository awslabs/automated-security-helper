# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""discover_plugins must not depend on every sys.path entry being enumerable.

It used to call ``pkgutil.iter_modules()`` over all of ``sys.path``. On CPython
3.13+ that raises ``KeyError`` for a zip archive on ``sys.path`` once
``importlib.invalidate_caches()`` has run: ``zipimporter.invalidate_caches()``
drops the archive from ``zipimport._zip_directory_cache`` and ``pkgutil`` indexes
that dict directly. On Windows the console-script launcher (``ash.exe``,
``pytest.exe``) is a zip archive and is ``sys.path[0]``, and pytest's
``monkeypatch.syspath_prepend`` calls ``importlib.invalidate_caches()``, so
``TestPrewarm`` failed on the Windows py3.13 leg whenever a test that used it ran
earlier in the same xdist worker.

These tests use real packages on disk and a real zip archive, no mocks.
"""

import importlib
import importlib.metadata  # noqa: F401  (imported, as it always is under pytest)
import pkgutil
import sys
import zipfile

import pytest

from automated_security_helper.plugins.discovery import discover_plugins

_PLUGIN = "zipcache_probe_ash_plugins"
_LOOKALIKE = _PLUGIN + "_evil"
_NAMESPACE_ONLY = "zipcache_nsonly_ash_plugins"


@pytest.fixture
def poisoned_sys_path(tmp_path, monkeypatch):
    """sys.path holding a launcher-like zip whose directory cache was invalidated."""
    packages = tmp_path / "site"
    for name in (_PLUGIN, _LOOKALIKE):
        pkg = packages / name
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text(
            f"ASH_SCANNERS = [{name!r}]\n", encoding="utf-8"
        )
    # A directory without __init__: a namespace package, which the old walk
    # never reported as a package either.
    (packages / _NAMESPACE_ONLY).mkdir()

    launcher = tmp_path / "launcher.exe"
    with zipfile.ZipFile(launcher, "w") as zf:
        zf.writestr("__main__.py", "pass\n")

    monkeypatch.syspath_prepend(str(packages))
    monkeypatch.syspath_prepend(str(launcher))
    # Put a zipimporter for the archive into sys.path_importer_cache, as running
    # from the launcher does, then invalidate the way syspath_prepend and other
    # code do.
    assert pkgutil.get_importer(str(launcher)) is not None
    importlib.invalidate_caches()

    yield
    for name in (_PLUGIN, _LOOKALIKE, _NAMESPACE_ONLY):
        sys.modules.pop(name, None)
    sys.path_importer_cache.pop(str(launcher), None)


def test_the_fixture_reproduces_the_hazard(poisoned_sys_path):
    """Negative control: the full sys.path walk the old code did fails here on 3.13+.

    On 3.12 and earlier zipimporter.invalidate_caches() re-read the archive, so the
    walk succeeds; asserting that too keeps this control from being vacuous on
    either side of the change.
    """
    if sys.version_info >= (3, 13):
        with pytest.raises(KeyError):
            list(pkgutil.iter_modules())
    else:
        list(pkgutil.iter_modules())


def test_discovery_finds_the_plugin_despite_the_zip(poisoned_sys_path):
    discovered = discover_plugins([_PLUGIN])

    assert discovered["scanners"] == [_PLUGIN]
    assert _PLUGIN in sys.modules


def test_discovery_does_not_import_a_lookalike(poisoned_sys_path):
    discovered = discover_plugins([_PLUGIN])

    assert _LOOKALIKE not in sys.modules
    assert _LOOKALIKE not in discovered["scanners"]


def test_discovery_skips_namespace_packages_and_missing_names(poisoned_sys_path):
    discovered = discover_plugins([_NAMESPACE_ONLY, "zipcache_absent_ash_plugins"])

    assert discovered == {"converters": [], "scanners": [], "reporters": []}
    assert _NAMESPACE_ONLY not in sys.modules
