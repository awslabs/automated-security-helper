# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The plugin manager's event keys, filters and memo, as the low findings read them.

What each test pins, and what it read at the base before the fix:

* ``subscribe`` normalizes a member-named string key to the member and warns on
  a key no ASH event uses (it accepted any key silently, and such a handler
  never fired);
* a handler filter that raises on one subscriber leaves that one out of the
  notification (it aborted the whole notification for every subscriber);
* a plugin decorated with an unknown plugin type is reported, not logged as
  registered (the log said "Registered plugin module" and nothing was stored);
* ``remove_plugin_module_registration`` with a module path removes that
  module's registration (popping by the bare name removed the other module's
  under a name collision);
* the resolution memo is keyed by the registration objects' identity, so a
  module registered again after an eviction is resolved again (the key of name,
  path and flag handed the evicted module's classes back).
"""

from __future__ import annotations

import types
from unittest.mock import patch

import pytest

from automated_security_helper.plugins.events import AshEventType
from automated_security_helper.plugins.plugin_manager import (
    AshPluginLibrary,
    AshPluginManager,
)

pytestmark = pytest.mark.unit

_MODULE = "automated_security_helper.plugins.plugin_manager"


def _manager() -> AshPluginManager:
    return AshPluginManager(
        plugin_library=AshPluginLibrary(
            converters={}, scanners={}, reporters={}, event_handlers={}
        )
    )


def _handler(result, module="embedding_program.hooks"):
    def on_event(*args, **kwargs):
        return result

    on_event.__module__ = module
    return on_event


# ---------------------------------------------------------------------------
# Event keys
# ---------------------------------------------------------------------------


def test_a_member_named_string_subscribes_under_the_member():
    """Red before the fix: the handler sat under the string key, which
    notify(AshEventType.SCAN_COMPLETE) never reached."""
    manager = _manager()

    manager.subscribe("SCAN_COMPLETE", _handler("by name"))

    assert manager.notify(AshEventType.SCAN_COMPLETE) == ["by name"]
    assert AshEventType.SCAN_COMPLETE in manager.plugin_library.event_handlers
    assert "SCAN_COMPLETE" not in manager.plugin_library.event_handlers


def test_a_key_no_event_uses_is_accepted_with_a_warning():
    """Red before the fix: accepted silently."""
    manager = _manager()

    with patch(f"{_MODULE}.ASH_LOGGER") as logger:
        manager.subscribe("NOT_AN_EVENT", _handler("odd"))

    warnings = " ".join(str(c.args[0]) for c in logger.warning.call_args_list)
    assert "NOT_AN_EVENT" in warnings
    assert "not an AshEventType member" in warnings
    # Still subscribed, for a program notifying its own key.
    with patch(f"{_MODULE}.ASH_LOGGER"):
        assert manager.notify("NOT_AN_EVENT") == ["odd"]


# ---------------------------------------------------------------------------
# A raising filter
# ---------------------------------------------------------------------------


def test_a_filter_that_raises_on_one_subscriber_leaves_only_that_one_out():
    """Red before the fix: the filter's exception escaped notify, so no
    subscriber was notified."""
    manager = _manager()
    odd = _handler("odd")
    fine = _handler("fine")
    manager.subscribe(AshEventType.EXECUTION_START, odd)
    manager.subscribe(AshEventType.EXECUTION_START, fine)

    def admits(callback):
        if callback is odd:
            raise RuntimeError("cannot judge this one")
        return True

    with patch(f"{_MODULE}.ASH_LOGGER") as logger:
        fired = manager.notify(AshEventType.EXECUTION_START, handler_filter=admits)

    assert fired == ["fine"]
    warnings = " ".join(str(c.args[0]) for c in logger.warning.call_args_list)
    assert "cannot judge this one" in warnings


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_an_unknown_plugin_type_is_reported_not_registered():
    """Red before the fix: nothing was stored and the log said 'Registered'."""
    manager = _manager()

    class Widget:
        pass

    with patch(f"{_MODULE}.ASH_LOGGER") as logger:
        manager.register_plugin_module("widget", Widget, "some_ash_plugins.widgets")

    warnings = " ".join(str(c.args[0]) for c in logger.warning.call_args_list)
    assert "unknown plugin type" in warnings
    verbose = " ".join(str(c.args[0]) for c in logger.verbose.call_args_list)
    assert "Registered plugin module" not in verbose
    assert manager.plugin_library.scanners == {}


def test_a_colliding_registration_is_removed_by_its_module_path():
    """Red before the fix: popping by the bare name removed the FIRST module's
    registration when asked to remove the second's."""
    manager = _manager()

    class Twin:
        pass

    manager.register_plugin_module("scanner", Twin, "first_ash_plugins.mod")
    manager.register_plugin_module("scanner", Twin, "second_ash_plugins.mod")
    assert set(manager.plugin_library.scanners) == {
        "Twin",
        "second_ash_plugins.mod:Twin",
    }

    removed = manager.remove_plugin_module_registration(
        "scanner", "Twin", plugin_module_path="second_ash_plugins.mod"
    )

    assert removed is True
    assert set(manager.plugin_library.scanners) == {"Twin"}
    assert (
        manager.plugin_library.scanners["Twin"].plugin_module_path
        == "first_ash_plugins.mod"
    )
    # Without a path the bare name is still what goes, as before.
    assert manager.remove_plugin_module_registration("scanner", "Twin") is True
    assert manager.plugin_library.scanners == {}


# ---------------------------------------------------------------------------
# The resolution memo
# ---------------------------------------------------------------------------


def test_a_module_registered_again_after_an_eviction_is_resolved_again(monkeypatch):
    """Red before the fix: the memo's key (name, path, enabled) matched the
    re-registration, so the evicted module's class objects came back."""
    manager = _manager()
    module_name = "memo_ash_plugins.scanners"
    generation = {"n": 0}

    def import_module(path):
        generation["n"] += 1
        module = types.ModuleType(path)
        module.MemoScanner = type(
            "MemoScanner", (), {"ash_plugin_type": "scanner", "__module__": path}
        )
        return module

    monkeypatch.setattr(f"{_MODULE}.importlib.import_module", import_module)

    manager.register_plugin_module("scanner", "MemoScanner", module_name)
    first = manager.plugin_modules("scanner")
    assert manager.plugin_modules("scanner") == first  # memo hit, one import
    assert generation["n"] == 1

    manager.remove_plugin_module_registration("scanner", "MemoScanner")
    manager.register_plugin_module("scanner", "MemoScanner", module_name)
    second = manager.plugin_modules("scanner")

    assert generation["n"] == 2
    assert second[0] is not first[0]


def test_a_resolution_the_registry_changed_under_is_not_memoised(monkeypatch):
    """Red before the fix: the resolution was memoised under the registrations
    copied before the import, which the registry no longer held."""
    manager = _manager()
    module_name = "racy_ash_plugins.scanners"

    def import_module(path):
        # The loader's undo lands while the resolution imports.
        manager.remove_plugin_module_registration("scanner", "RacyScanner")
        module = types.ModuleType(path)
        module.RacyScanner = type(
            "RacyScanner", (), {"ash_plugin_type": "scanner", "__module__": path}
        )
        return module

    monkeypatch.setattr(f"{_MODULE}.importlib.import_module", import_module)
    manager.register_plugin_module("scanner", "RacyScanner", module_name)

    manager.plugin_modules("scanner")

    assert manager._resolved_plugins == {}
