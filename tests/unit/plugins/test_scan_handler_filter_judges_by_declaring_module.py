# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``scan_handler_filter`` judges a handler by what declared it, never by raising.

Subscriptions are process-wide, so the filter a scan notifies through decides
which earlier scan's handlers fire in this one. Three shapes used to slip
through: a ``functools.partial`` reports ``functools`` as its module, outside the
plugin namespace, so every partial a plugin module declared was notified in
every later scan; a handler a plugin module lists but whose function lives in a
helper library outside the namespace was read as the program's own; and a
callback whose ``__module__`` read raises broke the notify of every subscriber
of its event.

Three more, found by review of the first cut. A handler a plugin package's own
import subscribed from a submodule (the ``event_subscriber`` decorator declares
nothing) was left out of the scan that named the package. A callback the program
subscribed first and a plugin module listed later was taken over by the module and
silenced in scans not naming it. And a declared handler whose declaration could no
longer be re-read was refused even by the scan naming its module.

A fourth round: the first-owner rule that fixed the program-first order broke
the other orders. A plugin's handler that its own import subscribed through the
``event_subscriber`` decorator, before the loader's declared subscribe, read as
the program's and ran in every scan; a program handler a plugin module had
listed first was silenced. The manager now records every owner (the modules, and
whether the program subscribed outside any loader import window), and the filter
admits the program's handlers always and a module's in scans naming the module.

A fifth, measured on that cut: the program flag admitted a handler DEFINED inside
the plugin namespace that nothing declared (a plugin submodule subscribing when
something other than the loader imported it), so an unnamed package's handler ran
in every scan. The flag admits only a handler defined outside the namespace; for
one defined inside it the namespace rule decides, as it did before the record.
"""

from __future__ import annotations

import functools
import importlib
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.plugins.events import AshEventType
from automated_security_helper.plugins.loader import (
    load_additional_plugin_modules,
    plugins_of,
    scan_handler_filter,
    scan_plugin_filter,
)
from automated_security_helper.plugins.plugin_manager import (
    AshPluginLibrary,
    AshPluginManager,
)

pytestmark = pytest.mark.unit


def _handler_in(module: str):
    def on_event(*args, **kwargs):
        return module

    on_event.__module__ = module
    return on_event


def _manager():
    return AshPluginManager(
        plugin_library=AshPluginLibrary(
            converters={}, scanners={}, reporters={}, event_handlers={}
        )
    )


class _ModuleHiding:
    """A callable whose ``__module__`` read raises."""

    def __getattribute__(self, attribute):
        if attribute == "__module__":
            raise RuntimeError("no module today")
        return object.__getattribute__(self, attribute)

    def __call__(self, *args, **kwargs):
        return "odd"


def test_a_partial_is_judged_by_the_function_it_wraps():
    """Three partials, judged by the functions they wrap: another module's
    refused, this scan's admitted, the program's admitted. The scan names the
    module that defines ``mine`` so the test reads the partial rule alone; the
    submodule arm (a handler below a named package) is pinned separately."""
    theirs = functools.partial(_handler_in("zz_their_ash_plugins.events"), 1)
    mine = functools.partial(_handler_in("zz_mine_ash_plugins.events"), 1)
    program = functools.partial(_handler_in("zz_program.hooks"), 1)

    admits = scan_handler_filter(["zz_mine_ash_plugins.events"], manager=_manager())

    assert not admits(theirs), "a partial of another module's handler fired"
    assert admits(mine)
    assert admits(program)


def test_a_callable_hiding_its_module_is_left_out_without_raising():
    odd = _ModuleHiding()

    assert scan_handler_filter([], manager=_manager())(odd) is False
    assert scan_plugin_filter([])(odd) is False


def test_a_declared_handler_from_a_helper_library_belongs_to_its_module(
    monkeypatch,
):
    """Declared by a plugin module, defined outside the namespace."""
    helper = _handler_in("zz_helper_lib.callbacks")
    lister = types.ModuleType("zz_lister_ash_plugins")
    lister.ASH_EVENT_HANDLERS = {AshEventType.SCAN_COMPLETE: [helper]}
    monkeypatch.setitem(sys.modules, "zz_lister_ash_plugins", lister)
    manager = _manager()
    manager.subscribe(
        AshEventType.SCAN_COMPLETE, helper, declared_by="zz_lister_ash_plugins"
    )

    assert manager.handler_declared_by(helper) == "zz_lister_ash_plugins"
    assert not scan_handler_filter([], manager=manager)(helper), (
        "a scan that never named the declaring module was notified"
    )
    assert scan_handler_filter(["zz_lister_ash_plugins"], manager=manager)(helper)


def test_a_handler_the_program_subscribed_itself_is_still_notified():
    program = _handler_in("zz_program.hooks")
    manager = _manager()
    manager.subscribe(AshEventType.SCAN_COMPLETE, program)

    assert manager.handler_declared_by(program) is None
    assert scan_handler_filter([], manager=manager)(program)


def test_a_handler_a_named_package_subscribed_from_a_submodule_is_admitted():
    """Red before the fix: in the namespace, below the named module, declared
    by nothing, so neither the plugin filter nor the program rule admitted it.
    Red again on the owners-record cut: the subscribe, made outside any loader
    window, flagged it the program's and every scan notified it (the control)."""
    below = _handler_in("zz_deep_ash_plugins.events")
    manager = _manager()
    manager.subscribe(AshEventType.SCAN_COMPLETE, below)

    assert scan_handler_filter(["zz_deep_ash_plugins"], manager=manager)(below)
    assert not scan_handler_filter([], manager=manager)(below), (
        "control: a scan not naming the package was notified"
    )
    assert not scan_handler_filter(["zz_deep_ash_plugins_other"], manager=manager)(
        below
    ), "a sibling package with the named one as a prefix admitted it"


def test_the_program_keeps_a_callback_a_plugin_module_lists_later():
    """Red before the fix: the later declared subscribe took the callback over."""
    shared = _handler_in("zz_program.hooks")
    manager = _manager()
    manager.subscribe(AshEventType.SCAN_COMPLETE, shared)
    manager.subscribe(
        AshEventType.SCAN_START, shared, declared_by="zz_claims_ash_plugins"
    )

    assert manager.handler_owners(shared) == (
        frozenset({"zz_claims_ash_plugins"}),
        True,
    )
    assert scan_handler_filter([], manager=manager)(shared)


def test_the_program_keeps_a_callback_a_plugin_module_listed_first():
    """Red before the fix: the first record won, so the program's own
    subscribe of a callable a plugin module had listed was silenced in every
    scan not naming that module."""
    shared = _handler_in("zz_program.hooks")
    manager = _manager()
    manager.subscribe(
        AshEventType.SCAN_START, shared, declared_by="zz_claims_ash_plugins"
    )
    manager.subscribe(AshEventType.SCAN_COMPLETE, shared)

    assert manager.handler_owners(shared) == (
        frozenset({"zz_claims_ash_plugins"}),
        True,
    )
    assert scan_handler_filter([], manager=manager)(shared)


def test_a_decorator_subscribe_during_a_plugin_import_is_the_plugins_not_the_programs():
    """Red before the fix: a subscribe with no declarer was the program's
    wherever it came from, so a plugin's handler that its import subscribed
    before the loader's declared subscribe ran in every scan."""
    helper = _handler_in("zz_helper_lib.callbacks")
    manager = _manager()
    with manager.declaring_import("zz_decl_ash_plugins"):
        manager.subscribe(AshEventType.SCAN_COMPLETE, helper)
    manager.subscribe(
        AshEventType.SCAN_COMPLETE, helper, declared_by="zz_decl_ash_plugins"
    )

    assert manager.handler_owners(helper) == (frozenset({"zz_decl_ash_plugins"}), False)
    assert manager.handler_declared_by(helper) == "zz_decl_ash_plugins"
    assert not scan_handler_filter([], manager=manager)(helper), (
        "a scan not naming the module was notified"
    )
    assert scan_handler_filter(["zz_decl_ash_plugins"], manager=manager)(helper)


def test_the_declaring_window_is_per_thread_and_restored():
    manager = _manager()
    first = _handler_in("zz_helper_lib.one")
    second = _handler_in("zz_helper_lib.two")
    with manager.declaring_import("zz_outer_ash_plugins"):
        with manager.declaring_import("zz_inner_ash_plugins"):
            manager.subscribe(AshEventType.SCAN_COMPLETE, first)
        manager.subscribe(AshEventType.SCAN_COMPLETE, second)
    program = _handler_in("zz_helper_lib.three")
    manager.subscribe(AshEventType.SCAN_COMPLETE, program)

    assert manager.handler_owners(first) == (frozenset({"zz_inner_ash_plugins"}), False)
    assert manager.handler_owners(second) == (
        frozenset({"zz_outer_ash_plugins"}),
        False,
    )
    assert manager.handler_owners(program) == (frozenset(), True)


def test_a_declared_record_admits_the_handler_when_its_module_is_named(
    monkeypatch,
):
    """Red before the fix: the record refused unless the declaration re-read.

    The declaring module is not in ``sys.modules`` (a one-shot iterable the
    loader consumed is the live shape), so only the record says who declared
    the handler.
    """
    monkeypatch.delitem(sys.modules, "zz_gone_ash_plugins", raising=False)
    helper = _handler_in("zz_helper_lib.callbacks")
    manager = _manager()
    manager.subscribe(
        AshEventType.SCAN_COMPLETE, helper, declared_by="zz_gone_ash_plugins"
    )

    assert scan_handler_filter(["zz_gone_ash_plugins"], manager=manager)(helper)
    assert not scan_handler_filter([], manager=manager)(helper), (
        "control: a scan not naming the declaring module was notified"
    )


def test_plugins_of_keeps_a_declared_partial_as_the_listed_object(monkeypatch):
    """Red before the fix: the partial was unwrapped before the identity check,
    and its function, defined elsewhere, matched nothing."""
    listed = functools.partial(_handler_in("zz_elsewhere.hooks"), 1)
    module = types.ModuleType("zz_partial_ash_plugins")
    module.ASH_EVENT_HANDLERS = {AshEventType.SCAN_COMPLETE: [listed]}
    monkeypatch.setitem(sys.modules, "zz_partial_ash_plugins", module)

    assert plugins_of(["zz_partial_ash_plugins"])(listed)
    assert not plugins_of([])(listed), "control: unnamed, unselected"


def test_an_undo_drops_the_declared_record_with_the_handler():
    manager = _manager()
    snapshot = manager.registration_snapshot()
    refused = _handler_in("zz_refused_ash_plugins.events")
    manager.subscribe(
        AshEventType.SCAN_COMPLETE, refused, declared_by="zz_refused_ash_plugins"
    )
    assert manager.handler_declared_by(refused) == "zz_refused_ash_plugins"

    manager.undo_registrations_since(snapshot, "zz_refused_ash_plugins")

    assert manager.handler_declared_by(refused) is None


def test_a_declared_set_and_a_dict_view_select_like_a_list(monkeypatch):
    """The loader accepts any non-text iterable; the scan filter reads the same."""
    scanner = type("SetScanner", (), {"__module__": "zz_elsewhere.impl"})
    handler = _handler_in("zz_elsewhere.hooks")
    module = types.ModuleType("zz_shapes_ash_plugins")
    module.ASH_SCANNERS = {scanner}
    module.ASH_EVENT_HANDLERS = types.MappingProxyType(
        {AshEventType.SCAN_COMPLETE: frozenset({handler})}
    )
    monkeypatch.setitem(sys.modules, "zz_shapes_ash_plugins", module)

    admits = scan_plugin_filter(["zz_shapes_ash_plugins"])

    assert admits(scanner)
    assert admits(handler)
    assert not scan_plugin_filter([])(scanner), "control: unnamed, unselected"


def test_plugins_of_keeps_a_handler_a_named_module_lists_without_binding(
    monkeypatch,
):
    handler = _handler_in("zz_elsewhere.hooks")
    module = types.ModuleType("zz_lists_ash_plugins")
    module.ASH_EVENT_HANDLERS = {AshEventType.SCAN_COMPLETE: [handler]}
    monkeypatch.setitem(sys.modules, "zz_lists_ash_plugins", module)

    assert plugins_of(["zz_lists_ash_plugins"])(handler)
    assert not plugins_of([])(handler), "control: unnamed, unselected"


@pytest.fixture
def site(tmp_path, monkeypatch):
    root = tmp_path / "site"
    root.mkdir()
    monkeypatch.syspath_prepend(str(root))
    before = set(sys.modules)
    yield root
    for name in set(sys.modules) - before:
        del sys.modules[name]
    importlib.invalidate_caches()


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_the_loader_records_which_module_declared_each_handler(site):
    _write(
        site,
        "zzdeclhelper_pkg/__init__.py",
        "def on_event(**kwargs):\n    pass\n",
    )
    _write(
        site,
        "zzdecl_ash_plugins/__init__.py",
        "from zzdeclhelper_pkg import on_event\n"
        "ASH_EVENT_HANDLERS = {'scan_complete': [on_event]}\n",
    )
    importlib.invalidate_caches()
    manager = _manager()

    with patch("automated_security_helper.plugins.loader.ash_plugin_manager", manager):
        load_additional_plugin_modules(["zzdecl_ash_plugins"], record={})

    handler = sys.modules["zzdeclhelper_pkg"].on_event
    assert manager.handler_declared_by(handler) == "zzdecl_ash_plugins"
    assert not scan_handler_filter([], manager=manager)(handler)
    assert scan_handler_filter(["zzdecl_ash_plugins"], manager=manager)(handler)


def test_a_helper_decorated_with_event_subscriber_and_listed_stays_the_plugins(site):
    """The case the filter's docstring promises, end to end through the loader.

    The helper library decorates ``on_event`` with ``event_subscriber``, so the
    plugin module's import subscribes it (no declarer) BEFORE the loader's
    declared subscribe. Red before the fix: the first record won, the handler
    read as the program's, and every scan of the process notified it.
    """
    _write(
        site,
        "zzdecohelper_pkg/__init__.py",
        "from automated_security_helper.plugins.decorators import event_subscriber\n"
        "@event_subscriber('scan_complete')\n"
        "def on_event(**kwargs):\n"
        "    pass\n",
    )
    _write(
        site,
        "zzdeco_ash_plugins/__init__.py",
        "from zzdecohelper_pkg import on_event\n"
        "ASH_EVENT_HANDLERS = {'scan_complete': [on_event]}\n",
    )
    importlib.invalidate_caches()
    manager = _manager()

    with (
        patch("automated_security_helper.plugins.loader.ash_plugin_manager", manager),
        patch(
            "automated_security_helper.plugins.decorators.ash_plugin_manager", manager
        ),
    ):
        load_additional_plugin_modules(["zzdeco_ash_plugins"], record={})

    handler = sys.modules["zzdecohelper_pkg"].on_event
    assert manager.handler_owners(handler) == (frozenset({"zzdeco_ash_plugins"}), False)
    assert not scan_handler_filter([], manager=manager)(handler), (
        "a scan that never named the plugin module was notified"
    )
    assert scan_handler_filter(["zzdeco_ash_plugins"], manager=manager)(handler)
