# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A registration hides a masked module name in its own resolution warning.

``plugin_modules`` re-resolves every registration of a kind whenever any
registration of the kind changes, so the "Failed to import plugin module"
warning of one registration is written when the next reader asks, under that
reader's masked-module scope. In a long-lived process (the MCP server) the next
reader can be another session's call, or a read that sets no scope, and the
warning then printed a module path that a run's config read from the
environment in clear.

A registration made while a scope was in force (the loader's import, which runs
the decorators) now records that scope. The warning the registration's import
failure writes hides the recorded names whoever resolves, in addition to the
names the reader's own scope hides.

The registry line that lists the modules a class was imported with ("not
selected") reads the same record: it hides the names the registration was made
under, not only the reader's.

``discover_plugins`` imports a plugin package a second time after the loader has
tried it. A package whose body registers a plugin and then raises is registered
by that second import, so the import runs under the run's masked-module scope
too, or the registration would record no names and every later resolution
warning would print the package in clear.

The loader drops a refused package from ``sys.modules``, so a later resolution
imports it a third time, and its decorators run again. That import runs under
the names its registration recorded as well: the decorator's debug line and the
"already registered" warning it reaches name the package, and a reader that sets
no scope (another session of a long-lived process) would otherwise see them in
clear. Every line the reader writes is checked, not only the failed-import
warning.

Covered: the resolution in ``plugin_modules`` and the import probe in
``_registered_classes``, each read outside any scope; the recorded names added
to a reader's own scope; the "not selected" line read outside the scope its
registration was made in; the registration a discovery import makes; the lines
of a package the loader refused and a reader then imports again, in both
imports; and, as controls, a registration made outside any scope, a package
discovery names literally, the same read under the loader's own scope, and a
scope that does not outlive the resolution.
"""

from __future__ import annotations

import logging
import sys
import types
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.discovery import discover_plugins
from automated_security_helper.plugins.loader import (
    load_additional_plugin_modules,
    masked_module_scope,
)
from automated_security_helper.plugins.plugin_manager import (
    AshPluginLibrary,
    AshPluginManager,
    AshPluginRegistration,
    masked_module_names,
    without_masked_modules,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

MASK = "<value>"


class _Sink(logging.Handler):
    def __init__(self):
        super().__init__(level=1)
        self.messages: List[str] = []

    def emit(self, record):
        self.messages.append(record.getMessage())


@pytest.fixture
def messages():
    """Every ash log record's message, whatever the logger's level was."""
    sink = _Sink()
    level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(sink)
    ASH_LOGGER.setLevel(1)
    yield sink.messages
    ASH_LOGGER.removeHandler(sink)
    ASH_LOGGER.setLevel(level)


def _manager() -> AshPluginManager:
    return AshPluginManager(plugin_library=AshPluginLibrary())


def _hiding(*names: str):
    return masked_module_names(masked_module_scope(dict.fromkeys(names, MASK)))


def test_a_registration_made_in_a_scope_masks_its_warning_when_resolved_outside_it(
    messages,
):
    name = "kqrecord_ash_plugins"
    manager = _manager()
    with _hiding(name):
        manager.register_plugin_module(
            "scanner", "KqRecord", f"{name}_extras.kqmissing"
        )

    manager.plugin_modules("scanner")

    joined = "\n".join(messages)
    assert name not in joined, joined
    assert f"Failed to import plugin module {MASK}_extras.kqmissing" in joined, joined


def test_a_registration_made_in_a_scope_masks_its_import_probe_outside_it(messages):
    name = "kqrecordprobe_ash_plugins"
    manager = _manager()
    with _hiding(name):
        manager.register_plugin_module(
            "scanner", "KqRecordProbe", f"{name}_extras.kqmissing"
        )
    registration = manager.plugin_library.scanners["KqRecordProbe"]

    found = AshPluginManager._registered_classes("scanner", registration)

    assert found == []
    joined = "\n".join(messages)
    assert name not in joined, joined
    assert f"Failed to import plugin module {MASK}_extras.kqmissing" in joined, joined


def test_the_recorded_names_are_added_to_the_readers_own_scope(messages):
    recorded = "kqrecordone_ash_plugins"
    reader = "kqrecordtwo_ash_plugins"
    manager = _manager()
    with _hiding(recorded):
        manager.register_plugin_module(
            "scanner", "KqRecordOne", f"{recorded}.{reader}_missing"
        )

    with _hiding(reader):
        manager.plugin_modules("scanner")

    joined = "\n".join(messages)
    assert recorded not in joined, joined
    assert reader not in joined, joined


def _carried_by(module: str, class_name: str, monkeypatch: pytest.MonkeyPatch) -> type:
    """A scanner class defined in ``<module>.scanner``, an importable module."""
    holder_name = f"{module}.scanner"
    carried = type(class_name, (), {"ash_plugin_type": "scanner"})
    carried.__module__ = holder_name
    holder = types.ModuleType(holder_name)
    setattr(holder, class_name, carried)
    monkeypatch.setitem(sys.modules, holder_name, holder)
    return carried


def test_the_not_selected_line_hides_the_modules_its_registration_was_masked_for(
    messages, monkeypatch
):
    """The registration was made while a scope hid ``name``, inside an untrusted
    import of a module of that name. The line is written by a later reader that
    sets no scope, and it lists the importing module."""
    name = "kqrecordsel_ash_plugins"
    carried = _carried_by(name, "KqRecordCarried", monkeypatch)
    manager = _manager()
    with manager.untrusted_import(name):
        with _hiding(name):
            manager.register_plugin_module("scanner", carried, carried.__module__)
    resolved = {"scanner": manager.plugin_modules("scanner")}

    kept = manager.plugins_loaded_by(resolved, [])

    assert kept["scanner"] == []
    joined = "\n".join(messages)
    assert name not in joined, joined
    assert f"'KqRecordCarried' (imported with {MASK})" in joined, joined


DISCOVERY_BODY = (
    "from automated_security_helper.plugins.decorators import ash_scanner_plugin\n"
    "\n"
    "\n"
    "@ash_scanner_plugin\n"
    "class {cls}:\n"
    "    pass\n"
    "\n"
    "\n"
    "raise ImportError('the body failed after its decorators ran')\n"
)


@pytest.fixture
def plant_package(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A function that plants a top-level package whose body registers one
    scanner and then raises ``ImportError``."""
    planted: List[tuple] = []

    def plant(name: str, class_name: str) -> None:
        root = tmp_path / f"discovery-{name}"
        (root / name).mkdir(parents=True)
        (root / name / "__init__.py").write_text(
            DISCOVERY_BODY.format(cls=class_name), encoding="utf-8"
        )
        monkeypatch.syspath_prepend(str(root))
        planted.append((name, class_name))

    yield plant
    for name, class_name in planted:
        ash_plugin_manager.remove_plugin_module_registration("scanner", class_name)
        sys.modules.pop(name, None)


def _resolution_warnings(messages: List[str]) -> List[str]:
    return [m for m in messages if "Failed to import plugin module" in m]


def test_a_discovery_import_records_the_scope_of_a_masked_package(
    messages, plant_package
):
    """The loader's import is not the only one: discovery imports the package
    again, its decorators register it again, and a later reader that sets no
    scope writes the resolution warning."""
    name = "kqdisc_ash_plugins"
    plant_package(name, "KqDiscRegistered")

    discover_plugins(plugin_modules=[name], shown={name: MASK})
    ash_plugin_manager.plugin_modules("scanner")

    failed = _resolution_warnings(messages)
    assert failed, messages
    assert all(name not in m for m in failed), failed


def test_a_registration_of_a_package_names_the_masks_of_a_class_defined_below_it():
    """``plugin_modules`` lists every plugin class of a registered module,
    including an undecorated subclass imported from a submodule, whose
    ``__module__`` is below the registration's path. The line that names that
    class's module hides the names the registration was made under."""
    name = "kqprefix_ash_plugins"
    manager = _manager()
    with _hiding(name):
        manager.register_plugin_module("scanner", "KqPrefix", name)
    recorded = manager.plugin_library.scanners["KqPrefix"]._masked_forms

    forms = manager.masked_forms_of_module("scanner", f"{name}.extra.scanner")

    assert recorded
    assert forms == recorded, forms
    with masked_module_names(forms):
        assert (
            without_masked_modules(f"{name}.extra.scanner") == f"{MASK}.extra.scanner"
        )


def _refuse_then_discover(name: str, shown: dict) -> None:
    """The sequence a scan runs for a module its config names: the loader refuses
    the package (and takes back what its decorators registered), then discovery
    imports it again, which registers it again before the body raises."""
    record: dict = {}
    masked = tuple(entry for entry, label in shown.items() if label != entry)
    load_additional_plugin_modules([name], shown=shown, record=record, values=masked)
    assert sorted(record) == [name], record
    discover_plugins(plugin_modules=[name], shown=shown)


def test_a_reader_that_imports_a_refused_package_again_hides_its_name_in_every_line(
    messages, plant_package
):
    """Discovery left the package registered, and the loader dropped it from
    ``sys.modules``, so the resolution of the next reader (another session, no
    scope) runs the body and its decorators again. The decorator's debug line and
    the "already registered" warning name the package: those lines are written
    under the reader's scope, so the import has to run under the registration's."""
    name = "kqrefused_ash_plugins"
    plant_package(name, "KqRefusedThird")
    _refuse_then_discover(name, {name: MASK})

    ash_plugin_manager.plugin_modules("scanner")

    joined = "\n".join(messages)
    assert name not in joined, joined
    assert f"from '{MASK}' already registered" in joined, joined


def test_the_import_probe_of_a_refused_package_hides_its_name_in_every_line(
    messages, plant_package
):
    name = "kqrefusedprobe_ash_plugins"
    plant_package(name, "KqRefusedProbe")
    _refuse_then_discover(name, {name: MASK})
    registration = ash_plugin_manager._registrations("scanner")["KqRefusedProbe"]

    found = AshPluginManager._registered_classes("scanner", registration)

    assert found == []
    joined = "\n".join(messages)
    assert name not in joined, joined
    assert f"from '{MASK}' already registered" in joined, joined


# --- controls --------------------------------------------------------------------


def test_a_module_of_the_same_path_still_gets_the_recorded_names():
    name = "kqprefixexact_ash_plugins"
    manager = _manager()
    with _hiding(name):
        manager.register_plugin_module("scanner", "KqPrefixExact", name)
    recorded = manager.plugin_library.scanners["KqPrefixExact"]._masked_forms

    assert recorded
    assert manager.masked_forms_of_module("scanner", name) == recorded


def test_a_module_that_only_starts_with_the_registered_path_gets_no_names():
    """A dotted prefix ends at a dot: ``<name>_other`` is another package."""
    name = "kqprefixname_ash_plugins"
    manager = _manager()
    with _hiding(name):
        manager.register_plugin_module("scanner", "KqPrefixName", name)

    assert manager.masked_forms_of_module("scanner", f"{name}_other.extra") == ()
    assert manager.masked_forms_of_module("scanner", name[:-1]) == ()


def test_a_reader_under_the_loaders_scope_hides_the_name_of_a_refused_package(
    messages, plant_package
):
    """The same read under the scope the loader held hides the name whether or
    not the registration recorded it."""
    name = "kqrefusedscope_ash_plugins"
    plant_package(name, "KqRefusedScope")
    _refuse_then_discover(name, {name: MASK})

    with _hiding(name):
        ash_plugin_manager.plugin_modules("scanner")

    joined = "\n".join(messages)
    assert name not in joined, joined
    assert f"from '{MASK}' already registered" in joined, joined


def test_a_refused_package_the_run_names_literally_prints_as_it_is(
    messages, plant_package
):
    name = "kqrefusedplain_ash_plugins"
    plant_package(name, "KqRefusedPlain")
    _refuse_then_discover(name, {name: name})

    ash_plugin_manager.plugin_modules("scanner")

    joined = "\n".join(messages)
    assert f"from '{name}' already registered" in joined, joined


def test_the_recorded_names_are_not_part_of_the_models_data():
    """What the note on the attribute says: a private attribute is never dumped
    and is not in the schema."""
    name = "kqrecorddump_ash_plugins"
    manager = _manager()
    with _hiding(name):
        manager.register_plugin_module("scanner", "KqRecordDump", f"{name}.kqmissing")
    registration = manager.plugin_library.scanners["KqRecordDump"]

    assert registration._masked_forms
    assert "_masked_forms" not in registration.model_dump()
    assert (
        "_masked_forms" not in AshPluginRegistration.model_json_schema()["properties"]
    )


def test_a_package_discovery_names_literally_prints_as_it_is(messages, plant_package):
    name = "kqdiscplain_ash_plugins"
    plant_package(name, "KqDiscPlain")

    discover_plugins(plugin_modules=[name], shown={})
    ash_plugin_manager.plugin_modules("scanner")

    failed = _resolution_warnings(messages)
    assert any(name in m for m in failed), messages


def test_the_not_selected_line_prints_a_module_as_it_is_when_nothing_masked_it(
    messages, monkeypatch
):
    name = "kqrecordselplain_ash_plugins"
    carried = _carried_by(name, "KqRecordCarriedPlain", monkeypatch)
    manager = _manager()
    with manager.untrusted_import(name):
        manager.register_plugin_module("scanner", carried, carried.__module__)
    resolved = {"scanner": manager.plugin_modules("scanner")}

    manager.plugins_loaded_by(resolved, [])

    joined = "\n".join(messages)
    assert f"'KqRecordCarriedPlain' (imported with {name})" in joined, joined


def test_a_registration_made_outside_any_scope_prints_as_it_is(messages):
    name = "kqrecordplain_ash_plugins"
    manager = _manager()
    manager.register_plugin_module("scanner", "KqRecordPlain", f"{name}.kqmissing")

    manager.plugin_modules("scanner")

    joined = "\n".join(messages)
    assert f"Failed to import plugin module {name}.kqmissing" in joined, joined


def test_the_recorded_names_do_not_outlive_the_resolution(messages):
    name = "kqrecordend_ash_plugins"
    manager = _manager()
    with _hiding(name):
        manager.register_plugin_module("scanner", "KqRecordEnd", f"{name}.kqmissing")
    manager.plugin_modules("scanner")

    assert without_masked_modules(name) == name
