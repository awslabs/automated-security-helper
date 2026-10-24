# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``AshPluginManager.plugins_loaded_by``: what one scan takes from the shared registry.

Registrations made inside ``untrusted_import`` are attributed to the module being
imported. A scan that loads neither that module nor one the operator named is
not offered the classes only those registrations bring in.
``tests/unit/config/test_plugin_classes_across_scans.py`` runs the same rule
through real scans in one process; these pin its edges on a manager of their
own, with modules made in memory.
"""

from __future__ import annotations

import sys
import threading
import types
from typing import Dict, List

import pytest

from automated_security_helper.plugins.plugin_manager import (
    AshPluginLibrary,
    AshPluginManager,
)


def _plugin(name: str, module: str) -> type:
    cls = type(name, (), {"ash_plugin_type": "scanner"})
    cls.__module__ = module
    return cls


@pytest.fixture
def modules(monkeypatch):
    """Make in-memory modules importable, each holding the given classes."""

    def install(name: str, *classes: type, **attributes: object) -> types.ModuleType:
        module = types.ModuleType(name)
        for cls in classes:
            setattr(module, cls.__name__, cls)
        for attribute, value in attributes.items():
            setattr(module, attribute, value)
        monkeypatch.setitem(sys.modules, name, module)
        return module

    return install


def _manager() -> AshPluginManager:
    return AshPluginManager(plugin_library=AshPluginLibrary())


def _register(manager: AshPluginManager, cls: type) -> None:
    manager.register_plugin_module("scanner", cls, cls.__module__)


def _offered(manager: AshPluginManager, names: List[str]) -> List[str]:
    resolved: Dict[str, List[type]] = {"scanner": manager.plugin_modules("scanner")}
    return [
        cls.__name__ for cls in manager.plugins_loaded_by(resolved, names)["scanner"]
    ]


def test_a_class_an_untrusted_import_registered_needs_its_module(modules):
    carried = _plugin("ProbeCarried", "probe_carry_pkg.scanner")
    modules("probe_carry_pkg.scanner", carried)
    manager = _manager()
    with manager.untrusted_import("probe_carry_pkg"):
        _register(manager, carried)

    assert _offered(manager, []) == []
    assert _offered(manager, ["probe_carry_pkg"]) == ["ProbeCarried"]
    # The module that defines it, named directly: importing it again would
    # register nothing, so the class's own module counts.
    assert _offered(manager, ["probe_carry_pkg.scanner"]) == ["ProbeCarried"]
    assert _offered(manager, ["probe_other_pkg"]) == []


def test_a_module_that_lists_or_has_the_class_counts(modules):
    carried = _plugin("ProbeListed", "probe_list_impl.scanner")
    modules("probe_list_impl.scanner", carried)
    modules("probe_lister_pkg", ASH_SCANNERS=[carried])
    modules("probe_reexporter_pkg", carried)
    manager = _manager()
    with manager.untrusted_import("probe_list_impl"):
        _register(manager, carried)

    assert _offered(manager, ["probe_lister_pkg"]) == ["ProbeListed"]
    assert _offered(manager, ["probe_reexporter_pkg"]) == ["ProbeListed"]


def test_a_module_the_operator_named_keeps_it_for_every_scan(modules):
    carried = _plugin("ProbeOperator", "probe_operator_pkg.scanner")
    modules("probe_operator_pkg.scanner", carried)
    manager = _manager()
    with manager.untrusted_import("probe_operator_pkg"):
        _register(manager, carried)
    assert _offered(manager, []) == []

    manager.trust_plugin_modules(["probe_operator_pkg"])

    assert _offered(manager, []) == ["ProbeOperator"]


def test_a_class_an_untracked_registration_also_brings_in_is_kept(modules):
    """A class the untrusted module imports from an operator-loaded one."""
    builtin = _plugin("ProbeBuiltin", "probe_builtin_pkg.scanner")
    carried = _plugin("ProbeAlongside", "probe_alongside_pkg.scanner")
    modules("probe_builtin_pkg.scanner", builtin)
    modules("probe_alongside_pkg.scanner", carried, builtin)
    manager = _manager()
    _register(manager, builtin)
    with manager.untrusted_import("probe_alongside_pkg"):
        _register(manager, carried)

    assert _offered(manager, []) == ["ProbeBuiltin"]


def test_a_class_only_an_untrusted_registration_brings_in_is_dropped(modules):
    """``plugin_modules`` takes every plugin class in a registered module."""
    carried = _plugin("ProbeRegistered", "probe_unregistered_pkg.scanner")
    beside = _plugin("ProbeUnregistered", "probe_unregistered_pkg.scanner")
    modules("probe_unregistered_pkg.scanner", carried, beside)
    manager = _manager()
    with manager.untrusted_import("probe_unregistered_pkg"):
        _register(manager, carried)

    assert sorted(cls.__name__ for cls in manager.plugin_modules("scanner")) == [
        "ProbeRegistered",
        "ProbeUnregistered",
    ]
    assert _offered(manager, []) == []


def test_a_registration_that_replaced_the_tracked_one_is_not_taken_for_it(modules):
    carried = _plugin("ProbeReplaced", "probe_replaced_pkg.scanner")
    modules("probe_replaced_pkg.scanner", carried)
    manager = _manager()
    with manager.untrusted_import("probe_replaced_pkg"):
        _register(manager, carried)
    del manager.plugin_library.scanners["ProbeReplaced"]
    _register(manager, carried)

    assert _offered(manager, []) == ["ProbeReplaced"]


def test_a_class_registered_outside_any_untrusted_import_is_kept(modules):
    direct = _plugin("ProbeDirect", "probe_direct_host")
    modules("probe_direct_host", direct)
    manager = _manager()
    _register(manager, direct)

    assert _offered(manager, []) == ["ProbeDirect"]


def test_another_thread_registering_meanwhile_is_not_attributed(modules):
    carried = _plugin("ProbeWindow", "probe_window_pkg.scanner")
    other = _plugin("ProbeOtherThread", "probe_other_thread_host")
    modules("probe_window_pkg.scanner", carried)
    modules("probe_other_thread_host", other)
    manager = _manager()

    with manager.untrusted_import("probe_window_pkg"):
        thread = threading.Thread(target=_register, args=(manager, other))
        thread.start()
        thread.join(timeout=30)
        _register(manager, carried)

    assert _offered(manager, []) == ["ProbeOtherThread"]


def test_nothing_tracked_returns_the_classes_unchanged():
    manager = _manager()
    plugins = {"scanner": [_plugin("ProbeUnchanged", "anywhere")]}

    assert manager.plugins_loaded_by(plugins, []) == plugins
