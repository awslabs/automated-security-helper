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
after it became importable.

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
