# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``builtin_plugin_registry`` (the ``_builtin_plugins_only`` fixture) loses nothing.

The fixture swaps the plugin registry for a copy holding only ASH's built-ins. A plugin
module imported for the first time inside a snapshot test registers into that copy, and
because the module then stays in ``sys.modules`` its registration code never runs again.
If the copy were simply discarded, every later test in the worker would see a registry
without that plugin, which no real process could produce. These tests drive the context
manager directly, inside the test's own (already swapped) registry, and clean up what
they add so nothing leaks into the rest of the suite.

A module an earlier test imported registered its plugins into the real registry, and
Python does not run that again, so when a snapshot test's run loads the module (a
config's ash_plugin_modules) the fixture puts its real registrations back, as a fresh
process importing it would have them. Finding them by the class names the module
exports missed three shapes a fresh process registers: a plugin registered under a
name that is not its class's, a file imported under two names and loaded by the
second, and a package that imports only the submodule its plugins are in.
"""

from __future__ import annotations

import gc
import importlib
import sys
import types
import weakref
from collections.abc import Iterator
from pathlib import Path

import pytest

from automated_security_helper.plugins import ash_plugin_manager
from tests.snapshot.conftest import builtin_plugin_registry

pytest_plugins = ["pytester"]

_MODULE = "snapshot_registry_probe_plugin"
_REPORTER = "SnapshotRegistryProbeReporter"
_EVENT = "snapshot-registry-probe-event"

_KINDS = ("converters", "scanners", "reporters")


def _is_ash_module(module: str) -> bool:
    return module == "automated_security_helper" or module.startswith(
        "automated_security_helper."
    )


def _handler_name(handler) -> str:
    module = getattr(handler, "__module__", None) or ""
    return f"{module}:{getattr(handler, '__qualname__', type(handler).__name__)}"


#: Strong references to every class a record has seen, keyed by id so each is
#: held once; a held class's id stays taken, so a key never collides (see
#: _registration_state).
_recorded_classes: dict = {}


def _registration_state(registration) -> dict:
    """A registration as registry_state records it: the module it comes from,
    the class that module holds under the registration's name, by the module
    it is defined in as well as its qualified name (None when the module holds
    none), its identity, so a replacement whose names copy the original's is a
    change too, and the registration's own fields."""
    module = registration.plugin_module_path
    held = getattr(sys.modules.get(module), registration.name, None)
    held_class = None
    if held is not None:
        held_class = (
            f"{getattr(held, '__module__', '')}."
            f"{getattr(held, '__qualname__', type(held).__name__)}"
        )
    if held is not None:
        # Hold every recorded class for the life of the process: a freed
        # class's id can be reused by its replacement, and class_id would then
        # read the replacement as unchanged. The pin lives outside the record
        # because the record is written to JSON.
        _recorded_classes[id(held)] = held
    return {
        "module": module,
        "class": held_class,
        # An id() is meaningful only in the process that read it, so the whole
        # record is process-local (see registry_state's docstring).
        "class_id": None if held is None else id(held),
        "fields": registration.model_dump(mode="json"),
    }


def _plugin_classes(modules: set) -> dict:
    """For each loaded module of *modules*, the names it holds whose values are
    plugin classes, so one a test left behind unregistered is a recorded
    difference. As the loader does (plugin_manager's module walk), a value is
    checked for ash_plugin_type only when it is a class: an instance whose
    class carries it, or a MagicMock, which answers any attribute read, is
    nothing the loader would register. Two limits the loader's walk shares: an
    instance whose ``__class__`` is a property runs that property inside
    isinstance, and a metaclass property that raises propagates."""
    # Reading ash_plugin_type can run code (a metaclass property, a lazy
    # import) that adds a name to the module, so each module's names are read
    # from a snapshot.
    return {
        module: sorted(
            attribute_name
            for attribute_name, attribute in list(vars(sys.modules[module]).items())
            if isinstance(attribute, type)
            and getattr(attribute, "ash_plugin_type", None) is not None
        )
        for module in sorted(modules)
        if module in sys.modules
    }


def registry_state() -> dict:
    """The shared plugin registry by name: each registration with the module it
    comes from, the class that module holds under its name, by names and by
    identity, and its fields, and each event's handlers by module and name.
    Not a test.

    The record is comparable only within the process that made it: class_id is
    an id(), which means nothing in another process, so a record written to a
    file and read back elsewhere, or compared across pytest workers, reports
    every registration changed by class_id. The child run that writes one to
    before.json is pinned to one process with -n 0.

    test_snapshot_plugin_registry_leaves_the_registry.py runs this file in a
    pytest process of its own, records this before it, and calls
    registry_changes_since after it, so the registry is read here, in the file
    whose tests change it.
    """
    library = ash_plugin_manager.plugin_library
    state: dict = {
        kind: {
            name: _registration_state(registration)
            for name, registration in getattr(library, kind).items()
        }
        for kind in _KINDS
    }
    state["event_handlers"] = {
        str(event): [_handler_name(handler) for handler in handlers]
        for event, handlers in library.event_handlers.items()
    }
    state["plugin_classes"] = _plugin_classes(
        {
            registration.plugin_module_path
            for kind in _KINDS
            for registration in getattr(library, kind).values()
        }
    )
    return state


def registry_changes_since(before: dict) -> list[str]:
    """What this file's tests left in the shared registry, given the
    registry_state() from before them. Not a test.

    Empty when every registration and handler there before is still there,
    unchanged, and each one added comes from one of ASH's own modules: a module
    a test's run imports for the first time registers its plugins as it would in
    a fresh process, and tests/snapshot/conftest.py merges them back on purpose.
    A plugin a test wrote and left registered is listed.
    """
    after = registry_state()
    left = []
    for kind in _KINDS:
        for name, entry in before[kind].items():
            after_entry = after[kind].get(name)
            if after_entry != entry:
                # The differing fields are named: a class_id-only line in a
                # record compared across processes says the id is the cause
                # (registry_state's record is process-local).
                what = (
                    "is gone"
                    if after_entry is None
                    else "changed: "
                    + ", ".join(
                        sorted(
                            field
                            for field in entry
                            if after_entry.get(field) != entry[field]
                        )
                    )
                )
                left.append(f"{kind}: {name} from {entry['module']} {what}")
        for name, entry in after[kind].items():
            if name not in before[kind] and not _is_ash_module(entry["module"]):
                left.append(
                    f"{kind}: {name} from {entry['module']} is still registered"
                )
    for event, handlers in before["event_handlers"].items():
        for handler in handlers:
            if handler not in after["event_handlers"].get(event, []):
                left.append(f"{event}: handler {handler} is no longer subscribed")
    for event, handlers in after["event_handlers"].items():
        for handler in handlers:
            if handler not in before["event_handlers"].get(
                event, []
            ) and not _is_ash_module(handler.partition(":")[0]):
                left.append(f"{event}: handler {handler} is still subscribed")
    # A module a test removed the last registration of still holds its
    # classes, and the after record reads only the modules a registration
    # names, so comparing with that record alone would list each such class as
    # gone. Read just the missing modules, and keep the after record for the
    # rest: reading ash_plugin_type can run code (see _plugin_classes), so no
    # module is read a second time. Only the before record's modules are
    # compared; a module first named during the run has no baseline to list
    # leftovers against, and what was registered from it is already compared
    # above, registration by registration.
    before_classes = before.get("plugin_classes", {})
    after_classes = dict(after.get("plugin_classes", {}))
    missing = set(before_classes) - set(after_classes)
    if missing:
        after_classes.update(_plugin_classes(missing))
    for module, names in before_classes.items():
        after_names = after_classes.get(module, [])
        for class_name in after_names:
            if class_name not in names:
                left.append(f"{module}: plugin class {class_name} is still defined")
        for class_name in names:
            if class_name not in after_names:
                left.append(f"{module}: plugin class {class_name} is gone")
    return left


def a_scanner_registration():
    """A built-in scanner's name and its registration, as the shared registry
    holds it. Not a test.

    test_snapshot_plugin_registry_leaves_the_registry.py changes it in place, or
    the class its module holds under its name, to check that
    registry_changes_since lists the change, and puts it back.

    The registration is the live one, so a caller changes the registry with no
    registry spelling on its own lines. test_project_isolation.py's
    _REGISTRY_HELPERS lets only this file and its companion
    test_snapshot_plugin_registry_leaves_the_registry.py name this helper.
    """
    from automated_security_helper.plugins.loader import load_internal_plugins

    load_internal_plugins()
    scanners = ash_plugin_manager.plugin_library.scanners
    name = min(scanners)
    return name, scanners[name]


@pytest.mark.unit
def test_a_replacement_at_a_collected_classs_id_is_a_change(monkeypatch):
    """A record holds the class it saw, so the class cannot be collected and a
    replacement can never come back under the freed id reading as unchanged.

    class_id is id()-based. Were a record to hold only the id, dropping the
    class and defining a new one under the same name would let the allocator
    reuse the freed id, and the two states would compare equal. Whether the
    allocator does reuse it is its own business (measured: about 1 run in 200
    it does not), so the cell asserts the mechanism first: after the module
    drops the class, the record's pin must still hold it, which a weak
    reference shows deterministically.
    """

    class _Registration:
        plugin_module_path = "snapshot_registry_id_reuse_probe"
        name = "Probe"

        @staticmethod
        def model_dump(mode: str) -> dict:
            return {"name": "Probe"}

    module = types.ModuleType(_Registration.plugin_module_path)
    monkeypatch.setitem(sys.modules, module.__name__, module)

    module.Probe = type("Probe", (), {})
    recorded = weakref.ref(module.Probe)
    before = _registration_state(_Registration)
    del module.Probe
    gc.collect()
    assert recorded() is not None, (
        "the recorded class was collected, so a replacement may reuse its id"
    )
    module.Probe = type("Probe", (), {})
    after = _registration_state(_Registration)

    assert after != before, (
        "a class defined after the recorded one was collected read as unchanged"
    )


@pytest.mark.unit
def test_a_registration_a_test_removed_is_listed_as_gone(monkeypatch):
    """A registration a test removed and did not put back is listed as gone,
    and nothing else is: its module still holds its class, so the module's
    plugin classes read as they did before. The removed registration is the
    last one naming its module by construction -- the module is a throwaway of
    this cell's own, so a built-in that shares its module with another
    registration cannot break that precondition, which is still asserted
    below."""
    _, registration = a_scanner_registration()
    module = types.ModuleType("snapshot_registry_removed_probe")
    module.RemovedProbe = type("RemovedProbe", (), {"ash_plugin_type": "scanner"})
    monkeypatch.setitem(sys.modules, module.__name__, module)
    probe = registration.model_copy(
        update={"plugin_module_path": module.__name__, "name": "RemovedProbe"}
    )
    monkeypatch.setitem(
        ash_plugin_manager.plugin_library.scanners, "a-removed-probe", probe
    )
    before = registry_state()
    monkeypatch.delitem(ash_plugin_manager.plugin_library.scanners, "a-removed-probe")

    # The docstring's precondition: the removed registration was the last one
    # naming its module, so the after record no longer reads the module. With
    # another registration still naming it, a comparison that never read the
    # missing modules would also produce the one line, and this cell would
    # guard nothing.
    assert module.__name__ not in registry_state()["plugin_classes"]
    # The control that makes the guard visible: the module's class is read
    # from the before record's missing modules, so it is in the before
    # record, and only the registration's own line comes back.
    assert before["plugin_classes"][module.__name__] == ["RemovedProbe"]
    left = registry_changes_since(before)

    assert left == [f"scanners: a-removed-probe from {module.__name__} is gone"], left


@pytest.mark.unit
def test_a_registration_a_test_added_is_listed_as_still_registered(monkeypatch):
    """A registration a test added from a module that is not ASH's own, and did
    not remove, is listed as still registered, and nothing else is. The added
    module is never imported, so no module's classes change."""
    _, registration = a_scanner_registration()
    probe = registration.model_copy(
        update={"plugin_module_path": "a_probe_module_no_test_imports"}
    )
    before = registry_state()
    monkeypatch.setitem(
        ash_plugin_manager.plugin_library.scanners, "a-probe-left-behind", probe
    )

    left = registry_changes_since(before)

    still = (
        "scanners: a-probe-left-behind from a_probe_module_no_test_imports"
        " is still registered"
    )
    assert left == [still], left


@pytest.fixture
def probe_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """An importable module that registers a reporter and an event handler on import."""
    (tmp_path / f"{_MODULE}.py").write_text(
        "from automated_security_helper.plugins import ash_plugin_manager\n"
        f"ash_plugin_manager.register_plugin_module('reporter', {_REPORTER!r}, __name__)\n"
        "def on_event(*args, **kwargs):\n"
        "    return None\n"
        f"ash_plugin_manager.subscribe({_EVENT!r}, on_event)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    yield
    # Undo everything the import did, so the outer fixture's merge finds nothing.
    sys.modules.pop(_MODULE, None)
    library = ash_plugin_manager.plugin_library
    library.reporters.pop(_REPORTER, None)
    handlers = library.event_handlers.get(_EVENT)
    if handlers is not None:
        handlers[:] = [h for h in handlers if h.__module__ != _MODULE]
        if not handlers:
            del library.event_handlers[_EVENT]


def _handler_modules() -> list[str]:
    handlers = ash_plugin_manager.plugin_library.event_handlers.get(_EVENT, [])
    return [h.__module__ for h in handlers]


@pytest.mark.unit
@pytest.mark.usefixtures("probe_module")
def test_a_plugin_first_imported_inside_is_kept_afterwards():
    library = ash_plugin_manager.plugin_library
    assert _REPORTER not in library.reporters
    with pytest.MonkeyPatch.context() as mp:
        with builtin_plugin_registry(mp):
            importlib.import_module(_MODULE)
            assert _REPORTER in library.reporters
            assert _handler_modules() == [_MODULE]
        # monkeypatch has not restored the real dicts yet; the copy is still installed.
    # Now it has. The module is cached, so importing it again would register nothing;
    # the registration must have been carried over.
    assert _MODULE in sys.modules
    assert library.reporters[_REPORTER].plugin_module_path == _MODULE
    assert _handler_modules() == [_MODULE]


@pytest.mark.unit
def test_a_registration_from_an_already_imported_module_is_not_kept():
    """A test that registers a fake by hand gets it undone, as before."""
    library = ash_plugin_manager.plugin_library
    with pytest.MonkeyPatch.context() as mp:
        with builtin_plugin_registry(mp):
            ash_plugin_manager.register_plugin_module(
                "reporter", "SnapshotRegistryHandMade", __name__
            )
            assert "SnapshotRegistryHandMade" in library.reporters
    assert "SnapshotRegistryHandMade" not in library.reporters


@pytest.mark.unit
def test_an_existing_registration_is_not_overwritten(monkeypatch):
    """A key the real registry already holds keeps the real registry's entry."""
    library = ash_plugin_manager.plugin_library
    name, original = next(iter(library.reporters.items()))
    with pytest.MonkeyPatch.context() as mp:
        with builtin_plugin_registry(mp):
            replacement = original.model_copy(
                update={"plugin_module_path": "snapshot_registry_new_module"}
            )
            library.reporters[name] = replacement
            # Pretend the module was imported during the block.
            monkeypatch.setitem(sys.modules, "snapshot_registry_new_module", sys)
    assert library.reporters[name] is original


REGISTERS = (
    "from automated_security_helper.plugins import ash_plugin_manager\n"
    "class {cls}:\n"
    "    pass\n"
    "ash_plugin_manager.register_plugin_module('reporter', {name!r}, __name__)\n"
)


@pytest.fixture
def planted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Write plugin modules under tmp_path; undo their imports and registrations."""
    monkeypatch.syspath_prepend(str(tmp_path))
    modules: list[str] = []
    names: list[str] = []

    def plant(files: dict[str, str], imported: list[str], registered: str) -> None:
        for relative, text in files.items():
            path = tmp_path / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        for name in imported:
            importlib.import_module(name)
            modules.append(name)
        names.append(registered)

    yield plant
    for name in modules:
        for loaded in [m for m in sys.modules if m == name or m.startswith(name + ".")]:
            sys.modules.pop(loaded, None)
    for name in names:
        ash_plugin_manager.plugin_library.reporters.pop(name, None)


def _loaded_inside(module: str) -> set[str]:
    """The reporters a snapshot test's registry holds after its run's loader
    imports ``module``."""
    from automated_security_helper.plugins import loader as plugin_loader

    with pytest.MonkeyPatch.context() as mp:
        with builtin_plugin_registry(mp):
            plugin_loader.importlib.import_module(module)
            return set(ash_plugin_manager.plugin_library.reporters)


@pytest.mark.unit
def test_a_plugin_registered_under_another_name(planted):
    planted(
        {
            "probe_alias_mod.py": REGISTERS.format(
                cls="ProbeAliasClass", name="probe-alias"
            )
        },
        ["probe_alias_mod"],
        "probe-alias",
    )
    present = "probe-alias" in _loaded_inside("probe_alias_mod")
    assert present, "the plugin registered under another name was not put back"


@pytest.mark.unit
def test_a_file_imported_under_two_names_loaded_by_the_second(planted, tmp_path):
    # Imported as probe_two_pkg.mod first, then as mod (its directory on the
    # path too): the second import's registration is skipped as a duplicate.
    sys.path.insert(0, str(tmp_path / "probe_two_pkg"))
    try:
        planted(
            {
                "probe_two_pkg/__init__.py": "",
                "probe_two_pkg/probe_two_mod.py": REGISTERS.format(
                    cls="ProbeTwoNames", name="ProbeTwoNames"
                ),
            },
            ["probe_two_pkg.probe_two_mod", "probe_two_mod"],
            "ProbeTwoNames",
        )
        present = "ProbeTwoNames" in _loaded_inside("probe_two_mod")
    finally:
        sys.path.remove(str(tmp_path / "probe_two_pkg"))
    assert present, "the plugin of a file loaded by its second name was not put back"


@pytest.mark.unit
def test_a_package_that_imports_only_its_submodule(planted):
    planted(
        {
            "probe_sub_pkg/__init__.py": "from . import probe_sub_mod\n",
            "probe_sub_pkg/probe_sub_mod.py": REGISTERS.format(
                cls="ProbeSubReporter", name="ProbeSubReporter"
            ),
        },
        ["probe_sub_pkg"],
        "ProbeSubReporter",
    )
    present = "ProbeSubReporter" in _loaded_inside("probe_sub_pkg")
    assert present, "the plugin of the package's submodule was not put back"


@pytest.mark.unit
def test_a_plugin_of_another_module_is_not_put_back(planted):
    """The control: only the loaded module's plugins come back."""
    planted(
        {
            "probe_other_a.py": REGISTERS.format(cls="ProbeOtherA", name="ProbeOtherA"),
            "probe_other_b.py": REGISTERS.format(cls="ProbeOtherB", name="ProbeOtherB"),
        },
        ["probe_other_a", "probe_other_b"],
        "ProbeOtherA",
    )
    loaded = _loaded_inside("probe_other_a")
    ash_plugin_manager.plugin_library.reporters.pop("ProbeOtherB", None)
    only = "ProbeOtherA" in loaded and "ProbeOtherB" not in loaded
    assert only, "another module's plugin was put back, or the module's own was not"


# Two snapshot tests whose run loads trivy-repo from ash_plugin_modules, in one
# process. The first imports the module, which registers trivy-repo; the second
# finds it in sys.modules, so Python does not run that registration again.
_LOADS_TRIVY = """
from tests.snapshot.conftest import builtin_plugin_registry

MODULE = "automated_security_helper.plugin_modules.ash_trivy_plugins"


def _trivy_repo_is_loaded():
    from automated_security_helper.plugins import ash_plugin_manager
    from automated_security_helper.plugins.loader import load_additional_plugin_modules

    load_additional_plugin_modules([MODULE])
    names = [cls.__name__ for cls in ash_plugin_manager.plugin_modules("scanner")]
    return "TrivyRepoScanner" in names


def test_{first}(monkeypatch):
    with builtin_plugin_registry(monkeypatch):
        assert _trivy_repo_is_loaded()


def test_{second}(monkeypatch):
    with builtin_plugin_registry(monkeypatch):
        assert _trivy_repo_is_loaded()
"""


@pytest.mark.integration
@pytest.mark.parametrize(
    "first, second", [("a", "b"), ("b", "a")], ids=["a then b", "b then a"]
)
def test_a_module_an_earlier_test_imported_loads_again(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch, first, second
):
    """A run that loads a plugin module gets its plugins, whichever test in the
    worker imported the module first, as a fresh ``ash`` process does.

    Run in a new process each time, so the first test there is the first to
    import the module, in both orders.
    """
    repo_root = Path(__file__).resolve().parents[2]
    monkeypatch.setenv("PYTHONPATH", str(repo_root))
    pytester.makepyfile(test_two_runs=_LOADS_TRIVY.format(first=first, second=second))
    result = pytester.runpytest_subprocess("-p", "no:cacheprovider", "-n", "0")
    result.assert_outcomes(passed=2)
