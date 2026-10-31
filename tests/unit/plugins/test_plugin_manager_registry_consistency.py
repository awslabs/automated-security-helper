# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The plugin manager's registry reads stay consistent with its writes.

Three shapes in one process-wide manager. ``notify`` tested an event's
membership outside the event lock and indexed the dict inside it, so an undo on
another thread that deleted the key in between raised KeyError. ``register_plugin_module``
wrote a registration under the registry lock and its untrusted attribution after
releasing it, so a concurrent ``plugins_loaded_by`` could read the registration
without its attribution and keep a class the scan should not be offered. And
``plugin_modules`` memoised a resolution in which a registered module failed to
import, keyed by the registrations alone, so the module's classes stayed missing
after it became importable. The first cut of that fix skipped the memo on any
failure, so a module that kept failing was re-imported (its top-level code and
decorators re-run) and re-warned on every read; the memo now carries the failed
paths and is reused until one of them is in ``sys.modules``. The second cut
relied on that signal alone, and a failed import leaves nothing in
``sys.modules``, so in a long-lived server a module whose dependency an operator
installed stayed out of the list; the memo now also expires after
``FAILED_IMPORT_RETRY_SECONDS`` and the retry drops the import system's directory
caches first.

The two races are modelled deterministically: a dict whose membership and index
disagree, and a registry lock that records what the attribution table held the
moment it was released.
"""

from __future__ import annotations

import sys
import threading
import types

import pytest

from automated_security_helper.plugins.events import AshEventType
from automated_security_helper.plugins.plugin_manager import (
    AshPluginLibrary,
    AshPluginManager,
)

pytestmark = pytest.mark.unit


def _manager():
    return AshPluginManager(
        plugin_library=AshPluginLibrary(
            converters={}, scanners={}, reporters={}, event_handlers={}
        )
    )


class _KeyGoneBetweenCheckAndIndex(dict):
    """Membership says the event is there; the index finds it deleted."""

    def __contains__(self, key):
        return True

    def __getitem__(self, key):
        raise KeyError(key)


def test_notify_survives_an_event_key_deleted_between_check_and_index():
    manager = _manager()
    manager.plugin_library.event_handlers = _KeyGoneBetweenCheckAndIndex()

    assert manager.notify(AshEventType.SCAN_COMPLETE) == []


class _ReleaseObservingLock:
    """A registry lock that snapshots the attribution table when released."""

    def __init__(self, manager, seen):
        self._lock = threading.Lock()
        self._manager = manager
        self._seen = seen

    def __enter__(self):
        self._lock.acquire()
        return self

    def __exit__(self, *exc):
        self._seen.append(dict(self._manager._untrusted_registrations))
        self._lock.release()
        return False


def test_an_untrusted_registration_is_attributed_before_the_lock_is_released():
    manager = _manager()
    seen: list = []
    manager._registry_lock = _ReleaseObservingLock(manager, seen)

    with manager.untrusted_import("zz_untrusted_ash_plugins"):
        manager.register_plugin_module(
            "scanner", "ZzScanner", "zz_untrusted_ash_plugins"
        )

    assert seen, "the registry lock was never taken"
    assert ("scanner", "ZzScanner") in seen[-1], (
        "the attribution was written after the registry lock was released"
    )
    assert seen[-1][("scanner", "ZzScanner")][0] == "zz_untrusted_ash_plugins"


def test_a_module_that_becomes_importable_is_resolved_on_the_next_call(monkeypatch):
    manager = _manager()
    name = "zz_later_importable_ash_plugins"
    monkeypatch.delitem(sys.modules, name, raising=False)
    manager.register_plugin_module("scanner", "LaterScanner", name)

    assert manager.plugin_modules("scanner") == []

    module = types.ModuleType(name)
    module.LaterScanner = type(
        "LaterScanner", (), {"__module__": name, "ash_plugin_type": "scanner"}
    )
    monkeypatch.setitem(sys.modules, name, module)

    assert manager.plugin_modules("scanner") == [module.LaterScanner]


class _CountingFinder:
    """A meta path finder that counts the import attempts of one name and finds nothing."""

    def __init__(self, name):
        self.name = name
        self.attempts = 0

    def find_spec(self, fullname, path=None, target=None):
        if fullname == self.name:
            self.attempts += 1
        return None


def test_a_module_that_keeps_failing_is_imported_once_until_something_imports_it(
    monkeypatch,
):
    """Red before the fix: every read re-imported the still-failing module."""
    manager = _manager()
    name = "zz_keeps_failing_ash_plugins"
    monkeypatch.delitem(sys.modules, name, raising=False)
    finder = _CountingFinder(name)
    monkeypatch.setattr(sys, "meta_path", [finder, *sys.meta_path])
    manager.register_plugin_module("scanner", "NeverScanner", name)

    assert manager.plugin_modules("scanner") == []
    assert manager.plugin_modules("scanner") == []
    assert finder.attempts == 1, (
        f"the failing module was imported {finder.attempts} times over two reads"
    )

    module = types.ModuleType(name)
    module.NeverScanner = type(
        "NeverScanner", (), {"__module__": name, "ash_plugin_type": "scanner"}
    )
    monkeypatch.setitem(sys.modules, name, module)

    assert manager.plugin_modules("scanner") == [module.NeverScanner]


def test_a_failed_import_is_retried_after_the_window_without_touching_sys_modules(
    monkeypatch, tmp_path
):
    """Red before the fix: a module file written after the failure was never loaded.

    The module becomes importable the way an operator makes it so: a file
    appears on ``sys.path``. Nothing here touches ``sys.modules``, the memo's
    other signal, and the clock is the module's own ``_monotonic`` stand-in.
    """
    from automated_security_helper.plugins import plugin_manager as pm

    clock = {"now": 1000.0}
    monkeypatch.setattr(pm, "_monotonic", lambda: clock["now"])
    monkeypatch.syspath_prepend(str(tmp_path))
    name = "zz_fixed_later_ash_plugins"
    monkeypatch.delitem(sys.modules, name, raising=False)
    manager = _manager()
    manager.register_plugin_module("scanner", "LateFileScanner", name)
    try:
        assert manager.plugin_modules("scanner") == []

        (tmp_path / f"{name}.py").write_text(
            "class LateFileScanner:\n    ash_plugin_type = 'scanner'\n",
            encoding="utf-8",
        )
        assert name not in sys.modules
        assert manager.plugin_modules("scanner") == [], (
            "control: the memo was dropped inside the retry window"
        )

        clock["now"] += pm.FAILED_IMPORT_RETRY_SECONDS
        assert name not in sys.modules
        resolved = manager.plugin_modules("scanner")

        assert [cls.__name__ for cls in resolved] == ["LateFileScanner"]
        assert resolved[0].__module__ == name
    finally:
        sys.modules.pop(name, None)


def test_a_clean_resolution_is_still_memoised(monkeypatch):
    """Control: with every import succeeding the memo is used."""
    manager = _manager()
    name = "zz_memoised_ash_plugins"
    module = types.ModuleType(name)
    module.MemoScanner = type(
        "MemoScanner", (), {"__module__": name, "ash_plugin_type": "scanner"}
    )
    monkeypatch.setitem(sys.modules, name, module)
    manager.register_plugin_module("scanner", "MemoScanner", name)

    first = manager.plugin_modules("scanner")
    assert first == [module.MemoScanner]
    assert "scanner" in manager._resolved_plugins
