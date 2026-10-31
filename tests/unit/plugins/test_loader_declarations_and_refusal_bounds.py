# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The plugin loader's declaration and refusal bounds, as the low findings read them.

What each test pins, and what it read at the base before the fix:

* ``load_internal_plugins`` names a handler never-raising and records any
  failure (a partial without ``__name__`` raised AttributeError past the
  ImportError-only arm, with the handlers before it subscribed);
* a declared ``ASH_EVENT_HANDLERS`` key spelled as a member's name subscribes
  under the member (it was subscribed under the string, which notify never uses);
* an ``ASH_*`` declaration that is a mapping, or holds an entry that is no
  plugin class, is refused at the register stage (a dict's keys and a list of
  names reached the callers as plugin classes), and a generator declaration is
  rebound to what was read (the cached module kept the exhausted generator);
* ``scan_plugin_filter`` and ``refuse_plugin_modules_outside_namespace`` split
  comma-joined entries as every other loader does (a raw entry selected nothing,
  or was refused as a misnamed path);
* a finder that raises anything leaves the name to the import (only ImportError
  and ValueError were caught);
* a module refused at the register stage is not imported again by a later entry
  of the same load, and is evicted although an earlier entry imported it (the
  later entry re-ran the refused package; the sibling-imported module stayed);
* the ``.py`` file spellings of a masked name's leaf are added only when a run
  was hidden (a suffix contained in a word the load's frames print set the flag);
* ``plugins_of`` matches exported objects by identity, not by a bare id.
"""

from __future__ import annotations

import functools
import importlib
import sys
import types
from unittest.mock import patch

import pytest

from automated_security_helper.plugins import loader
from automated_security_helper.plugins.events import AshEventType
from automated_security_helper.plugins.loader import (
    _masked_module_forms,
    _namespace_package_refusal,
    load_additional_plugin_modules,
    load_internal_plugins,
    plugins_of,
    refuse_plugin_modules_outside_namespace,
    scan_plugin_filter,
)
from automated_security_helper.plugins.plugin_manager import (
    AshPluginLibrary,
    AshPluginManager,
)

pytestmark = pytest.mark.unit

_PREFIX = "lowldr"


@pytest.fixture
def planted(tmp_path, monkeypatch):
    """Plant a package on sys.path; its modules are dropped from sys.modules after."""

    def plant(name: str, source: str, **submodules: str) -> str:
        site = tmp_path / "site"
        (site / name).mkdir(parents=True, exist_ok=True)
        (site / name / "__init__.py").write_text(source, encoding="utf-8")
        for sub, body in submodules.items():
            (site / name / f"{sub}.py").write_text(body, encoding="utf-8")
        monkeypatch.syspath_prepend(str(site))
        importlib.invalidate_caches()
        return name

    yield plant
    for name in list(sys.modules):
        if name.startswith(_PREFIX):
            del sys.modules[name]


def _manager() -> AshPluginManager:
    return AshPluginManager(
        plugin_library=AshPluginLibrary(
            converters={}, scanners={}, reporters={}, event_handlers={}
        )
    )


# ---------------------------------------------------------------------------
# load_internal_plugins
# ---------------------------------------------------------------------------


def test_the_internal_load_survives_a_handler_without_a_name(monkeypatch):
    """Red before the fix: callback.__name__ raised AttributeError on a partial,
    which the ImportError-only arm did not catch."""

    def handler(*args, **kwargs):
        return "handled"

    fake = types.ModuleType(loader.INTERNAL_PLUGIN_PACKAGE)
    fake.ASH_SCANNERS = []
    fake.ASH_EVENT_HANDLERS = {
        AshEventType.SCAN_COMPLETE: [functools.partial(handler, 1)]
    }
    monkeypatch.setitem(sys.modules, loader.INTERNAL_PLUGIN_PACKAGE, fake)
    manager = _manager()
    monkeypatch.setattr(loader, "ash_plugin_manager", manager)
    record: dict = {}

    loaded = load_internal_plugins(record=record)

    assert record == {}
    assert loaded["scanners"] == []
    assert manager.notify(AshEventType.SCAN_COMPLETE) == ["handled"]


def test_a_non_import_error_in_the_internal_load_is_recorded(monkeypatch):
    """Red before the fix: a TypeError from the declarations propagated out of
    load_internal_plugins unrecorded."""

    class _Broken:
        # The loader reads keys() for its debug line before items(); both
        # raise the same TypeError so the recorded kind is the declaration's.
        def keys(self):
            raise TypeError("the handlers mapping is broken")

        def items(self):
            raise TypeError("the handlers mapping is broken")

    fake = types.ModuleType(loader.INTERNAL_PLUGIN_PACKAGE)
    fake.ASH_EVENT_HANDLERS = _Broken()
    monkeypatch.setitem(sys.modules, loader.INTERNAL_PLUGIN_PACKAGE, fake)
    monkeypatch.setattr(loader, "ash_plugin_manager", _manager())
    record: dict = {}

    load_internal_plugins(record=record)

    assert record[loader.INTERNAL_PLUGIN_PACKAGE].kind == "TypeError"


# ---------------------------------------------------------------------------
# Declarations
# ---------------------------------------------------------------------------


def test_a_member_named_string_key_subscribes_under_the_member(planted, monkeypatch):
    """Red before the fix: the handler was subscribed under the string
    "SCAN_COMPLETE", which no phase ever notifies."""
    name = planted(
        f"{_PREFIX}keys_ash_plugins",
        "def on_scan(*a, **k):\n    return 'keyed'\n"
        "ASH_EVENT_HANDLERS = {'SCAN_COMPLETE': [on_scan]}\n",
    )
    manager = _manager()
    monkeypatch.setattr(loader, "ash_plugin_manager", manager)
    record: dict = {}

    load_additional_plugin_modules([name], record=record)

    assert record == {}
    assert manager.notify(AshEventType.SCAN_COMPLETE) == ["keyed"]


def test_a_mapping_declaration_is_refused(planted, monkeypatch):
    """Red before the fix: the dict iterated over its string keys, which were
    returned as plugin classes."""
    name = planted(
        f"{_PREFIX}map_ash_plugins",
        "class MapScanner:\n    pass\nASH_SCANNERS = {'a': MapScanner}\n",
    )
    monkeypatch.setattr(loader, "ash_plugin_manager", _manager())
    record: dict = {}

    discovered = load_additional_plugin_modules([name], record=record)

    assert record[name].stage == "register"
    assert record[name].kind == "TypeError"
    assert discovered["scanners"] == []


def test_a_list_of_names_is_refused(planted, monkeypatch):
    """Red before the fix: the strings reached the callers as plugin classes."""
    name = planted(f"{_PREFIX}names_ash_plugins", "ASH_SCANNERS = ['NamesScanner']\n")
    monkeypatch.setattr(loader, "ash_plugin_manager", _manager())
    record: dict = {}

    discovered = load_additional_plugin_modules([name], record=record)

    assert record[name].kind == "TypeError"
    assert discovered["scanners"] == []


def test_a_generator_declaration_is_rebound_to_what_was_read(planted, monkeypatch):
    """Red before the fix: the module kept the exhausted generator, so a second
    read of the cached module's ASH_SCANNERS found nothing."""
    name = planted(
        f"{_PREFIX}gen_ash_plugins",
        "class GenScanner:\n    pass\nASH_SCANNERS = (c for c in (GenScanner,))\n",
    )
    monkeypatch.setattr(loader, "ash_plugin_manager", _manager())
    record: dict = {}

    discovered = load_additional_plugin_modules([name], record=record)

    assert record == {}
    assert [c.__name__ for c in discovered["scanners"]] == ["GenScanner"]
    assert [c.__name__ for c in sys.modules[name].ASH_SCANNERS] == ["GenScanner"]


# ---------------------------------------------------------------------------
# Comma-joined entries
# ---------------------------------------------------------------------------


def test_scan_plugin_filter_splits_a_comma_joined_entry(monkeypatch):
    """Red before the fix: the entry was one module name, so a class defined in
    either module was not admitted."""
    cls = type("Plugin", (), {"__module__": f"{_PREFIX}a_ash_plugins"})

    admits = scan_plugin_filter([f"{_PREFIX}a_ash_plugins, {_PREFIX}b_ash_plugins"])

    assert admits(cls)
    assert not scan_plugin_filter([f"{_PREFIX}b_ash_plugins"])(cls)


def test_the_namespace_refusal_splits_a_comma_joined_entry():
    """Red before the fix: the comma made the entry 'not a dotted path of
    identifiers', so a raw config entry the scan accepts was refused."""
    refuse_plugin_modules_outside_namespace(
        [f"{_PREFIX}a_ash_plugins,{_PREFIX}b_ash_plugins"]
    )  # does not raise

    with pytest.raises(Exception, match="outside ASH's plugin namespace"):
        refuse_plugin_modules_outside_namespace([f"{_PREFIX}a_ash_plugins,evil_pkg"])


def test_a_name_repeated_across_entries_is_refused_once():
    """Red before the fix: the comma split dropped the deduplication the loop
    had over whole entries, so a repeated name was named twice in the refusal."""
    with pytest.raises(Exception) as caught:
        refuse_plugin_modules_outside_namespace(
            ["evil_pkg", f"evil_pkg,{_PREFIX}a_ash_plugins", "evil_pkg"]
        )

    assert str(caught.value).count("'evil_pkg'") == 1


# ---------------------------------------------------------------------------
# A finder that raises
# ---------------------------------------------------------------------------


def test_a_finder_that_raises_leaves_the_name_to_the_import():
    """Red before the fix: only ImportError and ValueError were caught, so the
    refusal step itself crashed."""
    with patch(
        "automated_security_helper.config.plugin_module_trust._spec_without_importing",
        side_effect=RuntimeError("a broken meta-path finder"),
    ):
        assert _namespace_package_refusal(f"{_PREFIX}odd_ash_plugins") is None
        assert loader._unfindable_level(f"{_PREFIX}odd_ash_plugins") is None


# ---------------------------------------------------------------------------
# A refused module stays refused for the whole load
# ---------------------------------------------------------------------------


def test_a_later_entry_inside_a_refused_package_is_not_imported(
    planted, monkeypatch, tmp_path
):
    """Red before the fix: the second entry imported the evicted package again,
    re-running its body (and its decorators) within the same load."""
    counter = tmp_path / "imports.txt"
    name = planted(
        f"{_PREFIX}again_ash_plugins",
        f"open({str(counter)!r}, 'a').write('x\\n')\nASH_EVENT_HANDLERS = 5\n",
        sub="VALUE = 1\n",
    )
    monkeypatch.setattr(loader, "ash_plugin_manager", _manager())
    record: dict = {}

    load_additional_plugin_modules([name, f"{name}.sub"], record=record)

    assert counter.read_text().count("x") == 1
    assert record[name].stage == "register"
    assert f"{name}.sub" in record
    assert name not in sys.modules


def test_a_refused_module_an_earlier_entry_imported_is_evicted(planted, monkeypatch):
    """Red before the fix: the eviction was scoped to the refused entry's own
    import window, and a sibling entry had imported the module first, so the
    stale module stayed in sys.modules."""
    bad = planted(f"{_PREFIX}bad_ash_plugins", "ASH_EVENT_HANDLERS = 5\n")
    good = planted(
        f"{_PREFIX}good_ash_plugins",
        f"import {bad}  # noqa: F401\nASH_SCANNERS = []\n",
    )
    monkeypatch.setattr(loader, "ash_plugin_manager", _manager())
    record: dict = {}

    load_additional_plugin_modules([good, bad], record=record)

    assert good not in record
    assert record[bad].stage == "register"
    assert bad not in sys.modules
    assert good in sys.modules


# ---------------------------------------------------------------------------
# Masked forms
# ---------------------------------------------------------------------------


def test_a_leafs_file_spellings_follow_the_run_loops_exemptions():
    """Red before the fix: the suffix "security" is inside a word the load's own
    frames print, so no run form hid it, yet last_hidden was set and the leaf's
    ".py" spellings were added for a segment nothing hides."""
    forms = [str(form) for form in _masked_module_forms("deep_ash_plugins.security")]

    assert "security.py" not in forms
    assert "security.cpython" not in forms
    # Control: a leaf no exemption covers keeps its file spellings.
    control = [
        str(form) for form in _masked_module_forms("deep_ash_plugins.leafmodule")
    ]
    assert "leafmodule.py" in control


# ---------------------------------------------------------------------------
# plugins_of keeps its exported objects
# ---------------------------------------------------------------------------


def test_plugins_of_matches_an_exported_object_by_identity(monkeypatch):
    """The filter keeps the exported objects beside their ids: an unrelated
    object cannot be admitted through a reused id."""
    exported = type("Exported", (), {"__module__": "elsewhere.impl"})
    package = types.ModuleType(f"{_PREFIX}facade_ash_plugins")
    package.Exported = exported
    monkeypatch.setitem(sys.modules, package.__name__, package)

    belongs = plugins_of([package.__name__])

    assert belongs(exported)
    stranger = type("Stranger", (), {"__module__": "elsewhere.impl"})
    assert not belongs(stranger)
    del package.Exported
    # The filter still admits the object it was built with, whatever the module
    # binds now: it holds the object, not only its id.
    assert belongs(exported)
