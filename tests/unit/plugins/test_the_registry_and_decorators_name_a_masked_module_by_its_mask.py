# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The registry's and the decorators' log lines name a masked module by its mask.

A module a config read from the environment is named by its mask in the lines
the loader writes about it. Four lines of the plugin manager and the plugin
decorator print a module path from the class or the registration instead, and
named the module in clear: the decorator's "Auto-registering" line, the
"already registered" warning, the protected-name error, the "Failed to import
plugin module" warning and the "not selected" line. Each now passes what it
prints through the same masking as a failure's text, for the masked modules of
the load or run that is reading the registry (``masked_module_names``). The
scope exists only inside that block on the calling thread, so no run, thread
or test sees another's names.

Cells: one per line; the loader's own import, which sets the scope for the
decorators a masked module runs and hides a masked name inside a longer module
name in the registration line; the failure text of a load, where a masked
name inside a longer name is hidden too; and the controls (no scope, another
name's scope, a scope that has ended, a plain value that is not a module name).
"""

from __future__ import annotations

import logging
import sys
import types
from pathlib import Path
from typing import Dict, List

import pytest

from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.plugins.plugin_manager import (
    AshPluginLibrary,
    AshPluginManager,
    AshPluginRegistration,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

MASK = "<value>"
RAISES_FROM_FILE = (
    "import pathlib\n"
    "raise RuntimeError((pathlib.Path(__file__).parent / 'msg.txt')"
    ".read_text(encoding='utf-8'))\n"
)
DECORATED_BODY = (
    "from automated_security_helper.plugins.decorators import ash_scanner_plugin\n"
    "\n"
    "\n"
    "@ash_scanner_plugin\n"
    "class KqMmLoaded:\n"
    "    pass\n"
)


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


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "kqmm-site"
    root.mkdir()
    monkeypatch.syspath_prepend(str(root))
    yield root
    for name in [m for m in sys.modules if m.startswith("kqmm")]:
        sys.modules.pop(name, None)


def _plant(root: Path, files: Dict[str, str]) -> None:
    for relative, body in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")


def _masked(*names: str):
    """A scope hiding *names*, as a run whose config read them from the
    environment sets it (the engine, the workspace and the loader build it from
    their shown map with ``masked_module_scope``)."""
    from automated_security_helper.plugins.loader import masked_module_scope
    from automated_security_helper.plugins.plugin_manager import masked_module_names

    shown = dict.fromkeys(names, MASK)
    return masked_module_names(masked_module_scope(shown))


def _manager() -> AshPluginManager:
    return AshPluginManager(plugin_library=AshPluginLibrary())


def _decorated(name: str, module: str) -> type:
    plugin = type(name, (), {})
    plugin.__module__ = module
    return plugin


# --- one cell per line ---------------------------------------------------------


def test_the_decorators_line_names_a_masked_module_by_its_mask(messages):
    module = "kqmmdeco_ash_plugins"
    plugin = _decorated("KqMmDecorated", module)
    try:
        with _masked(module):
            ash_scanner_plugin(plugin)
    finally:
        ash_plugin_manager.remove_plugin_module_registration("scanner", "KqMmDecorated")

    joined = "\n".join(messages)
    assert module not in joined, joined
    assert f"Auto-registering scanner plugin KqMmDecorated from {MASK}" in joined, (
        joined
    )


def test_the_already_registered_warning_names_a_masked_module_by_its_mask(messages):
    module = "kqmmreg_ash_plugins"
    manager = _manager()

    with _masked(module):
        manager.register_plugin_module("scanner", "KqMmReg", module)
        manager.register_plugin_module("scanner", "KqMmReg", module)

    joined = "\n".join(messages)
    assert module not in joined, joined
    assert (
        f"Plugin module 'KqMmReg' from '{MASK}' already registered. Skipping." in joined
    ), joined


def test_the_protected_name_error_names_a_masked_module_by_its_mask(messages):
    module = "kqmmprot_ash_plugins"
    manager = _manager()

    with _masked(module):
        manager.register_plugin_module("scanner", "ash-default", module)

    joined = "\n".join(messages)
    assert module not in joined, joined
    assert f"Plugin module at path '{MASK}' should register" in joined, joined


def test_the_resolution_warning_names_a_masked_module_by_its_mask(messages):
    """The registered path is a child of the masked entry, which does not
    import: the path and the import error's own text both name the entry."""
    module = "kqmmres_ash_plugins"
    manager = _manager()
    manager.register_plugin_module("scanner", "KqMmRes", f"{module}.kqmissing_sub")

    with _masked(module):
        manager.plugin_modules("scanner")

    joined = "\n".join(messages)
    assert module not in joined, joined
    assert (
        f"Failed to import plugin module {MASK}.kqmissing_sub: No module named '{MASK}'"
    ) in joined, joined


def test_the_import_probe_warning_names_a_masked_module_by_its_mask(messages):
    module = "kqmmprobe_ash_plugins"
    registration = AshPluginRegistration(
        name="KqMmProbe", plugin_module_path=f"{module}.kqmissing_sub"
    )

    with _masked(module):
        found = AshPluginManager._registered_classes("scanner", registration)

    assert found == []
    joined = "\n".join(messages)
    assert module not in joined, joined
    assert f"Failed to import plugin module {MASK}.kqmissing_sub" in joined, joined


def test_the_not_selected_line_names_a_masked_module_by_its_mask(messages, monkeypatch):
    """The line lists the modules an untrusted import was given, which a config
    in the scanned tree can read from the environment."""
    module = "kqmmsel_ash_plugins"
    holder_name = f"{module}.scanner"
    carried = type("KqMmCarried", (), {"ash_plugin_type": "scanner"})
    carried.__module__ = holder_name
    holder = types.ModuleType(holder_name)
    setattr(holder, "KqMmCarried", carried)
    monkeypatch.setitem(sys.modules, holder_name, holder)
    manager = _manager()
    with manager.untrusted_import(module):
        manager.register_plugin_module("scanner", carried, holder_name)
    resolved = {"scanner": manager.plugin_modules("scanner")}

    with _masked(module):
        kept = manager.plugins_loaded_by(resolved, [])

    assert kept["scanner"] == []
    joined = "\n".join(messages)
    assert module not in joined, joined
    assert f"'KqMmCarried' (imported with {MASK})" in joined, joined


# --- the loader sets the scope for the decorators a masked module runs ---------


def test_a_masked_modules_own_registration_lines_are_masked(site, messages):
    from automated_security_helper.plugins.loader import (
        load_additional_plugin_modules,
    )

    module = "kqmmload_ash_plugins"
    _plant(site, {f"{module}/__init__.py": DECORATED_BODY})
    try:
        for _ in range(2):
            record: Dict = {}
            load_additional_plugin_modules(
                [module], shown={module: MASK}, record=record, values=(module,)
            )
            assert record == {}, record
            # The second import runs the body again, so the decorator finds the
            # first run's registration.
            sys.modules.pop(module, None)
    finally:
        ash_plugin_manager.remove_plugin_module_registration("scanner", "KqMmLoaded")

    joined = "\n".join(messages)
    assert module not in joined, joined
    assert f"Auto-registering scanner plugin KqMmLoaded from {MASK}" in joined, joined
    assert f"Plugin module 'KqMmLoaded' from '{MASK}' already registered" in joined, (
        joined
    )


def test_a_registration_line_hides_a_masked_name_inside_a_longer_module_name(
    site, messages
):
    """A masked package imports a sibling whose name holds the package's name
    (``<name>_extras``) and whose body registers a plugin. The decorator's line
    prints the sibling's path, and the load hides the masked name inside it."""
    from automated_security_helper.plugins.loader import (
        load_additional_plugin_modules,
    )

    module = "kqmmxreg_ash_plugins"
    _plant(
        site,
        {
            f"{module}/__init__.py": f"import {module}_extras\n",
            f"{module}_extras/__init__.py": DECORATED_BODY.replace(
                "KqMmLoaded", "KqMmExtra"
            ),
        },
    )
    try:
        record: Dict = {}
        load_additional_plugin_modules(
            [module], shown={module: MASK}, record=record, values=(module,)
        )
        assert record == {}, record
    finally:
        ash_plugin_manager.remove_plugin_module_registration("scanner", "KqMmExtra")

    joined = "\n".join(messages)
    assert module not in joined, joined
    assert f"Auto-registering scanner plugin KqMmExtra from {MASK}_extras" in joined, (
        joined
    )


# --- a failure's text ------------------------------------------------------------


def test_a_failures_text_hides_the_masked_name_inside_a_longer_name(site):
    """The environment value of a module entry is the module's own path. A
    load hides it as a plain value, inside any longer name too, whether the
    masked module loads in the same call as the failing one or not."""
    from automated_security_helper.plugins.loader import (
        load_additional_plugin_modules,
    )

    masked = "kqmmlong_ash_plugins"
    literal = "kqmmlit_ash_plugins"
    _plant(
        site,
        {
            f"{masked}/__init__.py": "",
            f"{literal}/__init__.py": RAISES_FROM_FILE,
            f"{literal}/msg.txt": f"{masked} beside {masked}_extras",
        },
    )
    record: Dict = {}

    load_additional_plugin_modules(
        [masked, literal], shown={masked: MASK}, record=record, values=(masked,)
    )

    assert sorted(record) == [literal], sorted(record)
    assert f"{MASK} beside {MASK}_extras" in record[literal].recorded, record[
        literal
    ].recorded
    assert masked not in record[literal].recorded, record[literal].recorded


def test_a_plain_environment_value_is_still_hidden_inside_a_longer_word(site):
    """Control: a value that is not a module entry keeps the strict treatment."""
    from automated_security_helper.plugins.loader import (
        load_additional_plugin_modules,
    )

    secret = "kqmmsecret-4417"
    literal = "kqmmplainlit_ash_plugins"
    _plant(
        site,
        {
            f"{literal}/__init__.py": RAISES_FROM_FILE,
            f"{literal}/msg.txt": f"{secret}_tail",
        },
    )
    record: Dict = {}

    load_additional_plugin_modules([literal], shown={}, record=record, values=(secret,))

    assert sorted(record) == [literal], sorted(record)
    assert f"{MASK}_tail" in record[literal].recorded, record[literal].recorded
    assert secret not in record[literal].recorded, record[literal].recorded


# --- controls --------------------------------------------------------------------


def test_without_a_scope_a_module_prints_as_it_is(messages):
    module = "kqmmplain_ash_plugins"
    plugin = _decorated("KqMmPlain", module)
    try:
        ash_scanner_plugin(plugin)
    finally:
        ash_plugin_manager.remove_plugin_module_registration("scanner", "KqMmPlain")

    joined = "\n".join(messages)
    assert f"Auto-registering scanner plugin KqMmPlain from {module}" in joined, joined


def test_a_scope_hides_only_the_names_it_was_given(messages):
    manager = _manager()

    with _masked("kqmmother_ash_plugins"):
        manager.register_plugin_module("scanner", "KqMmOther", "kqmmthis_ash_plugins")
        manager.register_plugin_module("scanner", "KqMmOther", "kqmmthis_ash_plugins")

    joined = "\n".join(messages)
    assert "from 'kqmmthis_ash_plugins'" in joined, joined


def test_a_scope_leaves_nothing_behind_when_it_ends(messages):
    module = "kqmmend_ash_plugins"
    manager = _manager()

    with _masked(module):
        manager.register_plugin_module("scanner", "KqMmEnd", module)
    manager.register_plugin_module("scanner", "KqMmEnd", module)

    joined = "\n".join(messages)
    assert f"from '{module}'" in joined, joined
