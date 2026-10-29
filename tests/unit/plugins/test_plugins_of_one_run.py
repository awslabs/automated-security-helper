# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``loader.plugins_of``: which registered plugins and handlers belong to one run.

A scan resolves its plugins and notifies its event handlers through this filter,
so a module another scan in the same process loaded stays out of it
(tests/unit/cli/mcp/test_session_plugins_stay_in_their_session.py is the end-to-end
case). These pin the filter's rules and ``notify``'s use of it.
"""

from __future__ import annotations

import functools
import sys
import types

import pytest

from automated_security_helper.plugins.events import AshEventType
from automated_security_helper.plugins.loader import (
    INTERNAL_PLUGIN_PACKAGE,
    plugins_of,
)
from automated_security_helper.plugins.plugin_manager import (
    AshPluginLibrary,
    AshPluginManager,
    callable_module,
)

pytestmark = pytest.mark.unit


def _defined_in(module: str, name: str = "Plugin") -> type:
    return type(name, (), {"__module__": module})


def _handler_in(module: str):
    def handler(*args, **kwargs):
        return module

    handler.__module__ = module
    return handler


def test_built_in_plugins_always_belong():
    belongs = plugins_of([])
    assert belongs(_defined_in(f"{INTERNAL_PLUGIN_PACKAGE}.scanners.x"))
    assert not belongs(_defined_in("other_ash_plugins.scanner"))


def test_a_listed_module_and_the_modules_below_it_belong():
    belongs = plugins_of(["mine_ash_plugins", "pkg.single_module"])
    assert belongs(_defined_in("mine_ash_plugins"))
    assert belongs(_defined_in("mine_ash_plugins.reporters.deep"))
    assert belongs(_defined_in("pkg.single_module"))
    # A sibling that only shares a prefix is someone else's.
    assert not belongs(_defined_in("mine_ash_plugins_extra.scanner"))
    assert not belongs(_defined_in("pkg"))


def test_comma_lists_are_split_like_the_loader_splits_them():
    belongs = plugins_of(["a_ash_plugins, b_ash_plugins", None, ""])
    assert belongs(_defined_in("a_ash_plugins.x"))
    assert belongs(_defined_in("b_ash_plugins.x"))


def test_a_class_a_listed_package_re_exports_belongs(monkeypatch):
    """A package may export plugins its own modules import from elsewhere."""
    elsewhere = _defined_in("vendor_impl.scanner", "Reexported")
    package = types.ModuleType("facade_ash_plugins")
    package.Reexported = elsewhere
    monkeypatch.setitem(sys.modules, "facade_ash_plugins", package)

    assert plugins_of(["facade_ash_plugins"])(elsewhere)
    assert not plugins_of([])(elsewhere)


def test_handlers_are_judged_by_where_they_are_defined():
    belongs = plugins_of(["mine_ash_plugins"])
    assert belongs(_handler_in("mine_ash_plugins.events"))
    assert not belongs(_handler_in("theirs_ash_plugins.events"))
    # A partial has no __module__ of its own; its function's counts.
    assert belongs(functools.partial(_handler_in("mine_ash_plugins.events"), 1))
    assert not belongs(functools.partial(_handler_in("theirs_ash_plugins"), 1))


def _module_hiding_callable(result, value="raise"):
    """A callable whose ``__module__`` read raises, or is not a str."""

    class Odd:
        def __getattribute__(self, attribute):
            if attribute == "__module__":
                if value == "raise":
                    raise RuntimeError("no module today")
                return value
            return object.__getattribute__(self, attribute)

        def __call__(self, *args, **kwargs):
            return result

    return Odd()


@pytest.mark.parametrize("value", ["raise", 5], ids=["raising", "non-string"])
def test_a_callable_hiding_its_module_is_left_out_without_raising(value):
    """The filter reads a callback's ``__module__``, and the loader accepts
    callables whose attributes raise or hold odd values. Subscriptions are
    process-wide, so a filter that raises on one callback breaks every scoped
    notify of that event, in other runs' scans too: such a callback is left
    out of the scope instead."""
    odd = _module_hiding_callable("odd", value)
    belongs = plugins_of(["mine_ash_plugins"])
    assert belongs(odd) is False

    manager = AshPluginManager(
        plugin_library=AshPluginLibrary(
            converters={}, scanners={}, reporters={}, event_handlers={}
        )
    )
    mine = _handler_in("mine_ash_plugins.events")
    manager.subscribe(AshEventType.EXECUTION_START, odd)
    manager.subscribe(AshEventType.EXECUTION_START, mine)

    fired = manager.notify(
        AshEventType.EXECUTION_START, _scope=plugins_of(["mine_ash_plugins"])
    )
    assert fired == ["mine_ash_plugins.events"]


def test_callable_module_reads_where_a_callable_was_defined():
    """The module read the run scope and the undo filter share: a
    ``functools.partial`` chain is unwrapped to its function, and a module that
    cannot be read (the read raises, or the value is no ``str``) is ``None``
    rather than an error."""
    mine = _handler_in("mine_ash_plugins.events")
    nested = functools.partial(functools.partial(mine, 1), 2)
    wrapped_odd = functools.partial(_module_hiding_callable("odd", 5), 1)

    assert callable_module(mine) == "mine_ash_plugins.events"
    assert callable_module(nested) == "mine_ash_plugins.events"
    assert callable_module(_module_hiding_callable("odd", "raise")) is None
    assert callable_module(_module_hiding_callable("odd", 5)) is None
    assert callable_module(wrapped_odd) is None


def test_an_undo_leaves_a_handler_whose_module_cannot_be_read():
    """The undo of a refused module removes the handlers defined under that
    module, a partial of one included, and nothing else: a handler whose
    ``__module__`` cannot be read is not read as the refused module's."""
    manager = AshPluginManager(
        plugin_library=AshPluginLibrary(
            converters={}, scanners={}, reporters={}, event_handlers={}
        )
    )
    snapshot = manager.registration_snapshot()
    odd = _module_hiding_callable("odd", "raise")
    refused = _handler_in("refused_ash_plugins.events")
    wrapped = functools.partial(_handler_in("refused_ash_plugins.deep"), 1)
    unrelated = _handler_in("unrelated_ash_plugins.events")
    for callback in (odd, refused, wrapped, unrelated):
        manager.subscribe(AshEventType.EXECUTION_START, callback)

    manager.undo_registrations_since(snapshot, "refused_ash_plugins")

    kept = manager.plugin_library.event_handlers[AshEventType.EXECUTION_START]
    assert len(kept) == 2
    assert kept[0] is odd
    assert kept[1] is unrelated


def test_a_type_name_raising_callable_is_notified_as_anonymous():
    """notify()'s debug line names each callback, and no callback shape may
    make that raise: a metaclass can make even ``type(callback).__name__``
    raise, and such a callable can reach the handler list through the
    manager's own subscribe (no loader validation on that path). The display
    name ends in a fixed stand-in instead."""
    from automated_security_helper.plugins.plugin_manager import (
        callback_display_name,
    )

    class _Meta(type):
        @property
        def __name__(cls):
            raise RuntimeError("no type name")

    class _Nameless(metaclass=_Meta):
        def __call__(self, *args, **kwargs):
            return "nameless"

    callback = _Nameless()
    assert callback_display_name(callback) == "anonymous"

    manager = AshPluginManager(
        plugin_library=AshPluginLibrary(
            converters={}, scanners={}, reporters={}, event_handlers={}
        )
    )
    manager.subscribe(AshEventType.EXECUTION_START, callback)
    assert manager.notify(AshEventType.EXECUTION_START) == ["nameless"]


def test_notify_reaches_only_the_handlers_its_scope_accepts():
    manager = AshPluginManager(
        plugin_library=AshPluginLibrary(
            converters={}, scanners={}, reporters={}, event_handlers={}
        )
    )
    received = []

    def mine(**kwargs):
        received.append(("mine", sorted(kwargs)))

    def theirs(**kwargs):
        received.append(("theirs", sorted(kwargs)))

    mine.__module__ = "mine_ash_plugins.events"
    theirs.__module__ = "theirs_ash_plugins.events"
    manager.subscribe(AshEventType.EXECUTION_START, mine)
    manager.subscribe(AshEventType.EXECUTION_START, theirs)

    manager.notify(
        AshEventType.EXECUTION_START,
        phase="scan",
        _scope=plugins_of(["mine_ash_plugins"]),
    )
    # The scope is not handed to the handlers as event data.
    assert received == [("mine", ["phase"])]

    received.clear()
    manager.notify(AshEventType.EXECUTION_START, phase="scan")
    assert [name for name, _ in received] == ["mine", "theirs"]
