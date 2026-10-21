# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A module that imports but cannot register is refused in words that say so.

The loader's one try used to run from the import through discovery and the
ASH_EVENT_HANDLERS subscribe loop, so a module that imported cleanly with a
bad ASH_EVENT_HANDLERS was recorded and refused as "which failed to import"
-- a false sentence, and the subscribe loop had already registered the good
entries of a half-valid mapping into the process-wide manager, where they
survived into the next scan of a long-lived server. The refusal still carries
exit 3 (a configured module ASH cannot use is an invalid configuration); only
the words and the record's stage tell the two losses apart, and a bad entry
registers nothing.
"""

from __future__ import annotations

import sys

import pytest

from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.loader import (
    PluginModuleImportError,
    load_additional_plugin_modules,
    refuse_failed_plugin_imports,
)

EVENT = "registration-probe-event"


@pytest.fixture
def planted(tmp_path, monkeypatch):
    def plant(name: str, source: str) -> str:
        site = tmp_path / "site"
        (site / name).mkdir(parents=True)
        (site / name / "__init__.py").write_text(source, encoding="utf-8")
        monkeypatch.syspath_prepend(str(site))
        monkeypatch.delitem(sys.modules, name, raising=False)
        return name

    plant.site = tmp_path / "site"
    yield plant
    for name in list(sys.modules):
        if name.startswith("zqreg26"):
            del sys.modules[name]


def _load_and_refuse(name: str) -> tuple:
    record: dict = {}
    load_additional_plugin_modules([name], record=record)
    with pytest.raises(PluginModuleImportError) as caught:
        refuse_failed_plugin_imports([name], record)
    return record, str(caught.value)


def test_a_bad_handlers_shape_is_refused_as_a_registration_failure(planted):
    name = planted("zqreg26bad_ash_plugins", 'ASH_EVENT_HANDLERS = ["not a mapping"]\n')

    record, refusal = _load_and_refuse(name)

    assert "failed to import" not in refusal, refusal
    assert "imported" in refusal, refusal
    assert "register" in refusal, refusal
    assert record[name].stage == "register", record


def test_a_half_valid_mapping_registers_nothing(planted):
    """The good first entry's callback must not stay subscribed in the
    process-wide manager past the refusal: in a long-lived server it would
    fire in the next scan. Read through the manager's own notify(), which
    returns the subscribers' results."""
    name = planted(
        "zqreg26half_ash_plugins",
        "def good_cb(*a, **k):\n"
        "    return 'half-valid-marker'\n"
        f"ASH_EVENT_HANDLERS = {{'{EVENT}-half': [good_cb], 'other': 5}}\n",
    )

    _load_and_refuse(name)

    assert ash_plugin_manager.notify(f"{EVENT}-half") == [], "a callback fired"


def _load_clean(name: str) -> dict:
    record: dict = {}
    load_additional_plugin_modules([name], record=record)
    assert record == {}, record
    refuse_failed_plugin_imports([name], record)
    return record


def test_a_partial_beside_a_named_callback_is_accepted(planted):
    """A functools.partial has no __name__, and the subscribe loop's debug
    line read callback.__name__ eagerly: the partial was refused outright,
    and coming after a good callback it left the good one subscribed past
    the refusal. A partial is a valid handler; both subscribe."""
    name = planted(
        "zqreg26part_ash_plugins",
        "import functools\n"
        "def good_cb(*a, **k):\n"
        "    return 'named'\n"
        "part_cb = functools.partial(good_cb)\n"
        f"ASH_EVENT_HANDLERS = {{'{EVENT}-part': [good_cb, part_cb]}}\n",
    )

    _load_clean(name)

    fired = ash_plugin_manager.notify(f"{EVENT}-part")
    assert len(fired) == 2, fired


def test_a_name_raising_callable_is_accepted_by_its_type_name(planted):
    """callable() passes an instance whose __name__ descriptor raises; the
    display name falls back to the type's, and nothing raises mid-loop.
    (Firing it through notify() is the manager's own eager __name__ read, a
    separate site; this cell pins the loader's acceptance.)"""
    name = planted(
        "zqreg26nameless_ash_plugins",
        "class Shy:\n"
        "    @property\n"
        "    def __name__(self):\n"
        "        raise RuntimeError('no name today')\n"
        "    def __call__(self, *a, **k):\n"
        "        return 'shy'\n"
        f"ASH_EVENT_HANDLERS = {{'{EVENT}-shy': [Shy()]}}\n",
    )

    _load_clean(name)

    assert name in sys.modules, "the accepted module was not left loaded"
    # Firing it is the manager's half of the same contract: notify() names
    # callbacks through the same never-raising helper the loader uses.
    assert ash_plugin_manager.notify(f"{EVENT}-shy") == ["shy"]


def test_a_type_name_raising_callable_in_the_mapping_is_refused(planted):
    """A declared handler whose very type name cannot be read (a metaclass
    property that raises) is refused with the mapping, before anything
    subscribes: the declaration is validated strictly, while notify()'s
    display of an already-subscribed callback never raises."""
    name = planted(
        "zqreg26meta_ash_plugins",
        "class _Meta(type):\n"
        "    @property\n"
        "    def __name__(cls):\n"
        "        raise RuntimeError('no type name')\n"
        "class _Nameless(metaclass=_Meta):\n"
        "    def __call__(self, *a, **k):\n"
        "        return 'nameless'\n"
        f"ASH_EVENT_HANDLERS = {{'{EVENT}-meta': [_Nameless()]}}\n",
    )
    record: dict = {}
    load_additional_plugin_modules([name], record=record)

    assert record[name].stage == "register", record
    assert record[name].kind == "RuntimeError", record
    assert ash_plugin_manager.notify(f"{EVENT}-meta") == [], "a callback fired"


@pytest.mark.parametrize(
    "attribute", ["ASH_CONVERTERS", "ASH_SCANNERS", "ASH_REPORTERS"]
)
def test_a_string_valued_ash_list_is_refused_at_the_register_stage(planted, attribute):
    """A string is iterable, so ASH_CONVERTERS = 'zq' used to turn its
    characters into converters and the scan went on: the three ASH_* lists
    have to be a list or a tuple, refused in the register words."""
    name = planted(
        f"zqreg26str{attribute[4].lower()}_ash_plugins", f"{attribute} = 'zq'\n"
    )
    record: dict = {}
    load_additional_plugin_modules([name], record=record)

    with pytest.raises(PluginModuleImportError) as caught:
        refuse_failed_plugin_imports([name], record)

    assert "failed to import" not in str(caught.value), str(caught.value)
    assert record[name].stage == "register", record


def test_a_fixed_module_loads_after_a_registration_failure(planted, tmp_path):
    """A register-stage failure leaves no stale module behind: in a
    long-lived server the operator fixes the file, and the next load has to
    import the fixed file rather than re-fail from the module left in
    sys.modules."""
    import importlib

    name = planted("zqreg26stale_ash_plugins", "ASH_EVENT_HANDLERS = 5\n")
    record: dict = {}
    load_additional_plugin_modules([name], record=record)
    assert record[name].stage == "register", record
    assert name not in sys.modules, "the failed module was left behind"

    init = tmp_path / "site" / name / "__init__.py"
    init.write_text("ASH_EVENT_HANDLERS = {}\n", encoding="utf-8")
    importlib.invalidate_caches()

    _load_clean(name)


def test_a_dependency_already_imported_stays_after_a_registration_failure(
    planted, tmp_path
):
    """Only what the failed import added leaves sys.modules: a module that
    was already loaded before stays."""
    import importlib

    dep = planted("zqreg26dep_ash_plugins", "VALUE = 1\n")
    importlib.import_module(dep)
    name = planted(
        "zqreg26user_ash_plugins",
        f"import {dep}  # noqa: F401\nASH_EVENT_HANDLERS = 5\n",
    )
    record: dict = {}
    load_additional_plugin_modules([name], record=record)

    assert record[name].stage == "register", record
    assert name not in sys.modules
    assert dep in sys.modules, "an already-loaded module was removed"


def test_a_dependency_first_imported_by_the_refused_module_stays(planted):
    """The cleanup after a registration failure removes the refused module and
    its own submodules, nothing else: a dependency whose first import happened
    inside the refused module's import is shared with the whole process, so
    popping it makes the next import run its body again and mint new class
    objects, breaking isinstance checks everywhere the first ones went."""
    import importlib

    tally = planted("zqreg26tally_ash_plugins", "RUNS = 0\nFIRST = None\n")
    importlib.import_module(tally)
    dep = planted(
        "zqreg26newdep_ash_plugins",
        f"import {tally} as tally\n"
        "tally.RUNS += 1\n"
        "class Kind:\n"
        "    pass\n"
        "if tally.FIRST is None:\n"
        "    tally.FIRST = Kind\n",
    )
    name = planted(
        "zqreg26fresh_ash_plugins",
        f"import {dep}  # noqa: F401\nfrom . import part\nASH_EVENT_HANDLERS = 5\n",
    )
    (planted.site / name / "part.py").write_text("X = 1\n", encoding="utf-8")

    record: dict = {}
    load_additional_plugin_modules([name], record=record)

    assert record[name].stage == "register", record
    # The refused module and its own submodule go; the dependency stays.
    assert name not in sys.modules
    assert f"{name}.part" not in sys.modules
    assert dep in sys.modules, "a dependency the refused module imported was removed"
    again = importlib.import_module(dep)
    counts = sys.modules[tally]
    assert counts.RUNS == 1, "the dependency's body ran again"
    assert again.Kind is counts.FIRST, "the dependency's class identity changed"


def test_a_module_another_thread_imports_in_the_window_stays(planted):
    """The MCP server runs scans as threads of one process, so a module another
    thread imports while this load's import is under way is not this import's
    to remove. The two imports are coordinated with events, never timing."""
    import importlib
    import threading

    gates = planted(
        "zqreg26gates_ash_plugins",
        "import threading\n"
        "IN_WINDOW = threading.Event()\n"
        "OTHER_DONE = threading.Event()\n",
    )
    importlib.import_module(gates)
    other = planted("zqreg26other_ash_plugins", "VALUE = 2\n")
    name = planted(
        "zqreg26window_ash_plugins",
        f"import {gates} as gates\n"
        "gates.IN_WINDOW.set()\n"
        "if not gates.OTHER_DONE.wait(60):\n"
        "    raise RuntimeError('the other thread never imported')\n"
        "ASH_EVENT_HANDLERS = 5\n",
    )
    gate_module = sys.modules[gates]

    def _import_other():
        if gate_module.IN_WINDOW.wait(60):
            importlib.import_module(other)
            gate_module.OTHER_DONE.set()

    thread = threading.Thread(target=_import_other)
    thread.start()
    try:
        record: dict = {}
        load_additional_plugin_modules([name], record=record)
    finally:
        # If the plugin module never ran (an import failure before the gate),
        # release the thread rather than letting it wait out its timeout.
        gate_module.IN_WINDOW.set()
        thread.join(60)

    assert record[name].stage == "register", record
    assert other in sys.modules, "another thread's import was removed"


def test_a_refused_decorated_plugin_is_unregistered_and_not_run_again(planted):
    """A decorated plugin class the refused import registered must not outlive
    the refusal: the registry is process-wide, and with the module gone from
    sys.modules the next plugin resolution -- any run's, in a long-lived server
    -- would import the refused module and run its body again (resolution
    catches only ImportError, so any other error from the body reaches the
    caller mid-resolution)."""
    import importlib

    tally = planted("zqreg26count_ash_plugins", "BODY_RUNS = 0\n")
    importlib.import_module(tally)
    name = planted(
        "zqreg26deco_ash_plugins",
        f"import {tally} as tally\n"
        "tally.BODY_RUNS += 1\n"
        "from automated_security_helper.plugins.decorators import ash_plugin\n"
        "@ash_plugin(plugin_type='converter')\n"
        "class Zqreg26DecoConverter:\n"
        "    pass\n"
        "ASH_SCANNERS = 'zq'\n",
    )
    only_mine = lambda cls: getattr(cls, "__module__", "") == name  # noqa: E731

    record: dict = {}
    try:
        load_additional_plugin_modules([name], record=record)
        assert record[name].stage == "register", record

        resolved = ash_plugin_manager.plugin_modules("converter", only_mine)
        resolved += ash_plugin_manager.plugin_modules("converter", only_mine)

        assert resolved == [], "the refused module's class stayed registered"
        assert sys.modules[tally].BODY_RUNS == 1, (
            "a later resolution ran the refused module's body again"
        )
    finally:
        ash_plugin_manager.remove_plugin_module_registration(
            "converter", "Zqreg26DecoConverter"
        )


def test_a_refused_modules_discoveries_are_not_returned(planted):
    """The scanner inventory keeps this function's RETURN with no record and
    no refusal, so a module refused at the register stage must not leave the
    valid ASH_* entries it declared before the failure in the returned
    groups: the refusal says its plugins are not loaded."""
    name = planted(
        "zqreg26keep_ash_plugins",
        "class Zqreg26KeepScanner:\n"
        "    pass\n"
        "ASH_SCANNERS = [Zqreg26KeepScanner]\n"
        f"ASH_EVENT_HANDLERS = {{'{EVENT}-keep': [5]}}\n",
    )
    record: dict = {}
    discovered = load_additional_plugin_modules([name], record=record)

    assert record[name].stage == "register", record
    assert discovered["scanners"] == [], discovered


def test_an_accepted_modules_discoveries_are_returned(planted):
    """The control for the cell above: an accepted module's declared entries
    are in the returned groups."""
    name = planted(
        "zqreg26give_ash_plugins",
        "class Zqreg26GiveScanner:\n    pass\nASH_SCANNERS = [Zqreg26GiveScanner]\n",
    )
    discovered = load_additional_plugin_modules([name], record={})

    names = [getattr(cls, "__name__", "") for cls in discovered["scanners"]]
    assert names == ["Zqreg26GiveScanner"], discovered


def test_the_scanner_inventory_lists_no_scanner_of_a_refused_package(
    planted, monkeypatch
):
    """The caller the return matters to: the inventory loads the vendored
    package list tolerantly (no record, no refusal) and lists whatever comes
    back, so a package refused at the register stage must contribute no
    scanner class to the listing."""
    import automated_security_helper.core.scanner_inventory as inventory

    name = planted(
        "zqreg26inv_ash_plugins",
        "class Zqreg26InvScanner:\n"
        "    pass\n"
        "ASH_SCANNERS = [Zqreg26InvScanner]\n"
        f"ASH_EVENT_HANDLERS = {{'{EVENT}-inv': [5]}}\n",
    )
    monkeypatch.setattr(
        inventory,
        "_VENDORED_SCANNER_PLUGIN_PACKAGES",
        (name, *inventory._VENDORED_SCANNER_PLUGIN_PACKAGES),
    )

    listed = inventory._loaded_scanner_classes()

    assert all(getattr(cls, "__name__", "") != "Zqreg26InvScanner" for cls in listed), [
        getattr(cls, "__name__", "") for cls in listed
    ]
    assert name not in sys.modules, "the bad package was not refused"


def _converters_of(module: str) -> list:
    from automated_security_helper.plugins.loader import plugins_of

    found = ash_plugin_manager.plugin_modules("converter", plugins_of([module]))
    return sorted(cls.__name__ for cls in found if cls.__name__.startswith("Zqreg26"))


def test_another_threads_plugin_loaded_in_the_window_survives(planted):
    """The undo removes what the REFUSED module registered, not everything the
    window saw: a good plugin module another thread loads while the refused
    module's import is under way (the MCP server runs scans as threads of one
    process) keeps its converter and its handler. Losing them here is a loss
    for the whole process: the cached import never runs the decorator again."""
    import importlib
    import threading

    gates = planted(
        "zqreg26wgates_ash_plugins",
        "import threading\n"
        "IN_WINDOW = threading.Event()\n"
        "OTHER_DONE = threading.Event()\n",
    )
    importlib.import_module(gates)
    good = planted(
        "zqreg26wgood_ash_plugins",
        "from automated_security_helper.plugins.decorators import ash_plugin\n"
        "@ash_plugin(plugin_type='converter')\n"
        "class Zqreg26WGoodConverter:\n"
        "    pass\n"
        "def _handler(*a, **k):\n"
        "    return 'good'\n"
        f"ASH_EVENT_HANDLERS = {{'{EVENT}-wgood': [_handler]}}\n",
    )
    bad = planted(
        "zqreg26wbad_ash_plugins",
        f"import {gates} as gates\n"
        "gates.IN_WINDOW.set()\n"
        "if not gates.OTHER_DONE.wait(60):\n"
        "    raise RuntimeError('the other thread never loaded')\n"
        "ASH_EVENT_HANDLERS = 5\n",
    )
    gate_module = sys.modules[gates]
    record_bad: dict = {}

    def _load_bad():
        load_additional_plugin_modules([bad], record=record_bad)

    thread = threading.Thread(target=_load_bad)
    thread.start()
    try:
        if not gate_module.IN_WINDOW.wait(60):
            raise RuntimeError("control: the refused module never reached its window")
        record_good: dict = {}
        load_additional_plugin_modules([good], record=record_good)
        assert record_good == {}, record_good
    finally:
        gate_module.OTHER_DONE.set()
        thread.join(60)

    try:
        assert record_bad[bad].stage == "register", record_bad
        assert _converters_of(good) == ["Zqreg26WGoodConverter"], (
            "another thread's registration was undone"
        )
        assert ash_plugin_manager.notify(f"{EVENT}-wgood") == ["good"], (
            "another thread's subscription was undone"
        )
    finally:
        ash_plugin_manager.remove_plugin_module_registration(
            "converter", "Zqreg26WGoodConverter"
        )


def test_a_dependency_plugin_modules_registration_survives(planted):
    """A plugin module the refused module first imported stays loaded (the
    dependency rule), so undoing its registration loses it for good: a later
    load of it imports nothing new and never re-runs its decorator."""
    dep = planted(
        "zqreg26wdep_ash_plugins",
        "from automated_security_helper.plugins.decorators import ash_plugin\n"
        "@ash_plugin(plugin_type='converter')\n"
        "class Zqreg26WDepConverter:\n"
        "    pass\n",
    )
    name = planted(
        "zqreg26wuser_ash_plugins",
        f"import {dep}  # noqa: F401\nASH_EVENT_HANDLERS = 5\n",
    )

    record: dict = {}
    try:
        load_additional_plugin_modules([name], record=record)
        assert record[name].stage == "register", record
        assert dep in sys.modules

        assert _converters_of(dep) == ["Zqreg26WDepConverter"], (
            "a kept dependency's registration was undone"
        )
        # And its own configured load afterwards resolves it too.
        record_dep: dict = {}
        load_additional_plugin_modules([dep], record=record_dep)
        assert record_dep == {}, record_dep
        assert _converters_of(dep) == ["Zqreg26WDepConverter"]
    finally:
        ash_plugin_manager.remove_plugin_module_registration(
            "converter", "Zqreg26WDepConverter"
        )


def test_a_helpers_own_class_registered_in_the_window_survives(planted):
    """A shared helper the refused module calls can register a class the
    REFUSED module defines (undone: the registration's module path is the
    refused module's) and one the HELPER defines (kept: it is not the refused
    module's to lose)."""
    import importlib

    helper = planted(
        "zqreg26whelp_ash_plugins",
        "from automated_security_helper.plugins.decorators import ash_plugin\n"
        "def register(cls):\n"
        "    return ash_plugin(cls, plugin_type='converter')\n"
        "class Zqreg26WHelpConverter:\n"
        "    pass\n"
        "def register_own():\n"
        "    return ash_plugin(Zqreg26WHelpConverter, plugin_type='converter')\n",
    )
    importlib.import_module(helper)
    name = planted(
        "zqreg26wmine_ash_plugins",
        f"import {helper} as helper\n"
        "class Zqreg26WMineConverter:\n"
        "    pass\n"
        "helper.register(Zqreg26WMineConverter)\n"
        "helper.register_own()\n"
        "ASH_EVENT_HANDLERS = 5\n",
    )

    record: dict = {}
    try:
        load_additional_plugin_modules([name], record=record)
        assert record[name].stage == "register", record

        # The refused module's own class is undone, through the helper too.
        assert _converters_of(name) == [], "the refused module's class stayed"
        # The helper's own class is not the refused module's to lose.
        assert _converters_of(helper) == ["Zqreg26WHelpConverter"], (
            "a shared helper's own registration was undone"
        )
    finally:
        for cls in ("Zqreg26WMineConverter", "Zqreg26WHelpConverter"):
            ash_plugin_manager.remove_plugin_module_registration("converter", cls)


def test_a_module_loaded_before_the_load_stays_after_its_registration_failure(
    planted,
):
    """The cleanup removes what THIS load's import added: a module some
    earlier import of this process loaded, whose declarations fail here, is
    not this load's to evict."""
    import importlib

    name = planted(
        "zqreg26preload_ash_plugins",
        "ASH_EVENT_HANDLERS = 5\n",
    )
    importlib.import_module(name)

    record: dict = {}
    load_additional_plugin_modules([name], record=record)

    assert record[name].stage == "register", record
    assert name in sys.modules, "a module loaded before this load was evicted"


def test_a_raising_declaration_read_is_a_registration_failure(planted):
    """Reading what the module declares is the register stage's work: a
    module whose attribute access raises (a module __getattr__) imported, so
    its refusal says register, never \"failed to import\"."""
    name = planted(
        "zqreg26getattr_ash_plugins",
        "def __getattr__(attribute):\n"
        "    raise RuntimeError('no declarations today')\n",
    )
    record: dict = {}
    load_additional_plugin_modules([name], record=record)

    with pytest.raises(PluginModuleImportError) as caught:
        refuse_failed_plugin_imports([name], record)

    assert "failed to import" not in str(caught.value), str(caught.value)
    assert record[name].stage == "register", record


def test_a_fixed_module_reloads_fresh_after_an_import_failure(planted, tmp_path):
    """The import arm's half of the cleanup: Python removes the failed module
    itself from sys.modules, but a submodule its body imported before raising
    stays, so after the operator fixes the files a long-lived process reloads
    the package against the STALE submodule. The refused module's own subtree
    goes with it."""
    import importlib

    name = planted(
        "zqreg26impfix_ash_plugins",
        "from . import part\nraise RuntimeError('crash after part')\n",
    )
    # Different lengths on purpose: a rewrite in the same mtime second with
    # the same size would validate the first import's bytecode cache, and the
    # cell would then measure the cache, not the loader's cleanup.
    (planted.site / name / "part.py").write_text("VALUE = 'stale'\n", encoding="utf-8")

    record: dict = {}
    load_additional_plugin_modules([name], record=record)

    assert getattr(record[name], "stage", "import") == "import", record
    assert name not in sys.modules
    assert f"{name}.part" not in sys.modules, "a stale submodule was left behind"

    (planted.site / name / "part.py").write_text(
        "VALUE = 'rewritten'\n", encoding="utf-8"
    )
    (planted.site / name / "__init__.py").write_text(
        "from . import part\nASH_REPORTERS = []\n", encoding="utf-8"
    )
    importlib.invalidate_caches()

    _load_clean(name)
    assert sys.modules[name].part.VALUE == "rewritten", (
        "the fixed file was not reloaded"
    )


def test_a_dependency_first_imported_stays_after_an_import_failure(planted):
    """Only the refused module's own subtree goes on the import arm too: a
    dependency whose first import happened inside the failing body is shared
    with the whole process."""
    name = planted(
        "zqreg26impdep_ash_plugins",
        "import zqreg26sharedep_ash_plugins  # noqa: F401\n"
        "raise RuntimeError('crash after dep')\n",
    )
    dep = planted("zqreg26sharedep_ash_plugins", "VALUE = 1\n")

    record: dict = {}
    load_additional_plugin_modules([name], record=record)

    assert getattr(record[name], "stage", "import") == "import", record
    assert dep in sys.modules, "a dependency the failing module imported was removed"


def test_an_import_failures_registrations_are_undone(planted):
    """A decorated plugin registered before the body raised must not outlive
    the import refusal, exactly as a register-stage failure's must not: the
    registry is process-wide, and the module is gone from sys.modules."""
    name = planted(
        "zqreg26impdeco_ash_plugins",
        "from automated_security_helper.plugins.decorators import ash_plugin\n"
        "@ash_plugin(plugin_type='converter')\n"
        "class Zqreg26ImpDecoConverter:\n"
        "    pass\n"
        "raise RuntimeError('crash after registering')\n",
    )
    only_mine = lambda cls: getattr(cls, "__module__", "") == name  # noqa: E731

    record: dict = {}
    try:
        load_additional_plugin_modules([name], record=record)
        assert getattr(record[name], "stage", "import") == "import", record

        resolved = ash_plugin_manager.plugin_modules("converter", only_mine)
        assert resolved == [], "the refused module's class stayed registered"
    finally:
        ash_plugin_manager.remove_plugin_module_registration(
            "converter", "Zqreg26ImpDecoConverter"
        )


def test_a_dotted_entrys_failed_parent_is_cleaned_up_and_undone(planted):
    """Importing a dotted entry runs the parent package first. When THAT
    raises -- after importing a sibling and registering a decorated plugin --
    Python removes the parent itself from sys.modules, so a cleanup scoped to
    the dotted entry would leave the sibling stale and the parent's
    registration alive, pointing at a module that is no longer imported: the
    two failures the undotted arm refuses, one level up. The owner is the
    shortest prefix this load imported that the failure took back out of
    sys.modules."""
    name = planted(
        "zqreg26dottedparent_ash_plugins",
        "from . import common  # noqa: F401\n"
        "from automated_security_helper.plugins.decorators import ash_plugin\n"
        "@ash_plugin(plugin_type='converter')\n"
        "class Zqreg26DottedParentConverter:\n"
        "    pass\n"
        "raise RuntimeError('crash after registering')\n",
    )
    (planted.site / name / "common.py").write_text("X = 1\n", encoding="utf-8")
    (planted.site / name / "scanners.py").write_text("Y = 1\n", encoding="utf-8")
    entry = f"{name}.scanners"
    only_mine = lambda cls: getattr(cls, "__module__", "") == name  # noqa: E731

    record: dict = {}
    try:
        load_additional_plugin_modules([entry], record=record)
        assert getattr(record[entry], "stage", "import") == "import", record

        assert name not in sys.modules
        assert f"{name}.common" not in sys.modules, (
            "the failed parent's sibling stayed in sys.modules"
        )
        resolved = ash_plugin_manager.plugin_modules("converter", only_mine)
        assert resolved == [], "the failed parent's class stayed registered"
    finally:
        ash_plugin_manager.remove_plugin_module_registration(
            "converter", "Zqreg26DottedParentConverter"
        )


@pytest.mark.parametrize(
    "declaration",
    [
        "ASH_SCANNERS = {Zqreg26ShapeScanner}",
        "ASH_SCANNERS = frozenset({Zqreg26ShapeScanner})",
        "ASH_SCANNERS = {'a': Zqreg26ShapeScanner}.values()",
        "ASH_SCANNERS = (c for c in (Zqreg26ShapeScanner,))",
    ],
    ids=["set", "frozenset", "dict-values", "generator"],
)
def test_any_non_string_iterable_declaration_is_accepted(planted, declaration):
    """The shape check exists to stop a str's characters becoming plugins; any
    other iterable worked before the check and keeps working: refusing a set
    or a generator breaks modules that were valid."""
    name = planted(
        "zqreg26shape_ash_plugins",
        "class Zqreg26ShapeScanner:\n    pass\n" + declaration + "\n",
    )

    record: dict = {}
    discovered = load_additional_plugin_modules([name], record=record)

    assert record == {}, record
    names = [getattr(cls, "__name__", "") for cls in discovered["scanners"]]
    assert names == ["Zqreg26ShapeScanner"], discovered


@pytest.mark.parametrize(
    "declaration",
    ["ASH_SCANNERS = 'zq'", "ASH_SCANNERS = b'zq'", "ASH_SCANNERS = 5"],
    ids=["str", "bytes", "non-iterable"],
)
def test_a_string_bytes_or_non_iterable_declaration_is_refused(planted, declaration):
    """The controls: a str (whose characters would become plugins), bytes
    (whose items are ints) and a non-iterable are the shapes the check is
    for, refused at the register stage."""
    name = planted("zqreg26badshape_ash_plugins", declaration + "\n")

    record: dict = {}
    discovered = load_additional_plugin_modules([name], record=record)

    assert record[name].stage == "register", record
    assert record[name].kind == "TypeError", record
    assert discovered["scanners"] == [], discovered


def test_a_failed_modules_earlier_valid_lists_are_not_returned(planted):
    """A valid ASH_CONVERTERS read before a bad ASH_SCANNERS raises must not
    reach the returned groups: the refused module contributes nothing to the
    tolerant caller, whichever list failed."""
    name = planted(
        "zqreg26mixlists_ash_plugins",
        "class Zqreg26MixConverter:\n"
        "    pass\n"
        "ASH_CONVERTERS = [Zqreg26MixConverter]\n"
        "ASH_SCANNERS = 'zq'\n",
    )

    record: dict = {}
    discovered = load_additional_plugin_modules([name], record=record)

    assert record[name].stage == "register", record
    assert discovered["converters"] == [], discovered


def test_an_import_failure_keeps_its_exact_words(planted):
    """The control: a true import failure's wording is untouched, byte for
    byte, so no agreement cell moves."""
    name = planted("zqreg26imp_ash_plugins", "raise ImportError('cannot start')\n")

    record, refusal = _load_and_refuse(name)

    assert getattr(record[name], "stage", "import") == "import", record
    assert (
        "which failed to import, so the plugins it declares are not loaded." in refusal
    ), refusal


def test_both_kinds_of_failure_are_both_named(planted):
    """Two configured modules, one of each loss: the refusal names both, each
    under its own sentence."""
    broken = planted("zqreg26mixa_ash_plugins", "raise ImportError('cannot start')\n")
    bad = planted("zqreg26mixb_ash_plugins", "ASH_EVENT_HANDLERS = 5\n")
    record: dict = {}
    load_additional_plugin_modules([broken, bad], record=record)

    with pytest.raises(PluginModuleImportError) as caught:
        refuse_failed_plugin_imports([broken, bad], record)

    refusal = str(caught.value)
    assert "zqreg26mixa_ash_plugins" in refusal, refusal
    assert "zqreg26mixb_ash_plugins" in refusal, refusal
    assert "which failed to import" in refusal, refusal
    assert "register" in refusal, refusal
