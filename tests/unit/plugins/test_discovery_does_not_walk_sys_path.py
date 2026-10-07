# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""discover_plugins looks up the packages it is asked for and walks nothing else.

Regression for TestPrewarm::test_cli_modules_are_included on unit-test
(windows-latest, py3.14), run 37632758015, job 112839639522:
``KeyError: '...\\.venv\\Scripts\\pytest.exe'`` raised from pkgutil inside
discover_plugins. A Windows console-script launcher is a zip archive and sits on
sys.path; once anything calls ``importlib.invalidate_caches()`` (pytest's
``monkeypatch.syspath_prepend`` does), its entry leaves
``zipimport._zip_directory_cache`` and pkgutil's zip walker, which indexes that
private dict directly, raises. These tests rebuild that state on any OS with a zip
on sys.path.
"""

from __future__ import annotations

import importlib
import pkgutil
import sys
import zipfile
import zipimport
from pathlib import Path

import pytest

from automated_security_helper.plugins.discovery import discover_plugins


@pytest.fixture
def evicted_zip_on_sys_path(tmp_path, monkeypatch):
    """A launcher-like zip on sys.path whose zipimport directory cache was evicted."""
    launcher = tmp_path / "launcher.exe"
    with zipfile.ZipFile(launcher, "w") as archive:
        archive.writestr("__main__.py", "print('launcher')\n")
    monkeypatch.syspath_prepend(str(launcher))
    importer = zipimport.zipimporter(str(launcher))
    monkeypatch.setitem(sys.path_importer_cache, str(launcher), importer)
    importer.invalidate_caches()
    _evict(monkeypatch, launcher)
    return launcher


def _evict(monkeypatch, launcher: Path) -> None:
    """Leave ``launcher`` out of zipimport's directory cache, on every Python.

    From 3.13, ``zipimporter.invalidate_caches()`` pops the archive's entry, which is
    the state the Windows leg hit. On 3.12 and earlier it rereads the archive instead,
    so the entry is back after every ``importlib.invalidate_caches()``. Removing it by
    hand gives every version in the matrix the 3.13+ state, and pkgutil's zip walker
    indexes the dict directly on all of them. Call this after the last invalidation
    a test makes.
    """
    monkeypatch.delitem(zipimport._zip_directory_cache, str(launcher), raising=False)
    assert str(launcher) not in zipimport._zip_directory_cache


def _plant_package(root: Path, name: str, *, init: bool = True) -> None:
    package = root / name
    package.mkdir(parents=True)
    if init:
        (package / "__init__.py").write_text(
            "ASH_SCANNERS = ['planted']\n", encoding="utf-8"
        )


@pytest.fixture
def plugin_root(tmp_path, monkeypatch):
    root = tmp_path / "plugins"
    root.mkdir()
    monkeypatch.syspath_prepend(str(root))
    yield root
    for name in list(sys.modules):
        if name.startswith("zz_test_"):
            monkeypatch.delitem(sys.modules, name, raising=False)


def test_the_hazard_is_real_on_this_python(evicted_zip_on_sys_path):
    """Positive control: the old sys.path walk raises in exactly this state."""
    try:
        list(pkgutil.iter_modules())
    except KeyError as e:
        # Compare the key itself: str(KeyError) is the key's repr, which doubles
        # every backslash in a Windows path.
        assert e.args == (str(evicted_zip_on_sys_path),)
    else:
        pytest.skip("this Python's pkgutil no longer indexes the zip cache directly")


def test_discovery_survives_an_evicted_zip_on_sys_path(
    evicted_zip_on_sys_path, plugin_root, monkeypatch
):
    _plant_package(plugin_root, "zz_test_ash_plugins")
    importlib.invalidate_caches()
    _evict(monkeypatch, evicted_zip_on_sys_path)
    found = discover_plugins(plugin_modules=["zz_test_ash_plugins"])
    assert found["scanners"] == ["planted"]


def test_a_regular_top_level_package_is_discovered(plugin_root):
    _plant_package(plugin_root, "zz_test_regular_ash_plugins")
    importlib.invalidate_caches()
    assert discover_plugins(["zz_test_regular_ash_plugins"])["scanners"] == ["planted"]


@pytest.mark.parametrize(
    "name, plant",
    [
        pytest.param("zz_test_missing_ash_plugins", None, id="missing"),
        pytest.param("zz_test_ns_ash_plugins", "namespace", id="namespace-package"),
        pytest.param("zz_test_mod_ash_plugins", "module", id="plain-module"),
        pytest.param("zz_test_dotted.ash_plugins", None, id="dotted-name"),
    ],
)
def test_what_the_old_walk_did_not_match_is_still_not_matched(plugin_root, name, plant):
    """Kept to the old walk's semantics: top-level regular packages only."""
    if plant == "namespace":
        _plant_package(plugin_root, name, init=False)
    elif plant == "module":
        (plugin_root / f"{name}.py").write_text(
            "ASH_SCANNERS = ['x']\n", encoding="utf-8"
        )
    importlib.invalidate_caches()
    assert discover_plugins([name]) == {
        "converters": [],
        "scanners": [],
        "reporters": [],
    }
    assert name not in sys.modules
