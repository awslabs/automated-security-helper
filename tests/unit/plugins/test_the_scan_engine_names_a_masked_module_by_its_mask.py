# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan engine names a masked module by its mask in the registry lines it writes.

``ScanExecutionEngine`` logs the registered plugins its scan does not use, with
the module each was defined in, and it reads the process-wide registry through
``ash_plugin_manager`` to do so. A plugin a masked entry's package defines in
a dotted parent of the entry is registered under that parent's name, which the
masked entry's own name contains. The engine now builds the masked modules of
its run from the same map it names the entries with (``shown``), and reads the
registry inside ``masked_module_names`` for them.

Cells: the left-out line, with a dotted parent of a masked entry; the registry
resolution warning; the three registry calls the engine makes, and the
filter over the registry, each seen to run inside the scope; and the same
calls seen to print a longer module name that holds the masked name hidden.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Dict, List
from unittest.mock import MagicMock

import pytest

from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.plugin_manager import AshPluginManager
from automated_security_helper.utils.log import ASH_LOGGER

MASK = "<value>"
LEFT_OUT_BODY = (
    "from automated_security_helper.plugins.decorators import ash_scanner_plugin\n"
    "\n"
    "\n"
    "@ash_scanner_plugin\n"
    "class KqMmLeftOut:\n"
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
    for name in ("ASH_PLUGIN_MODULES", "ASH_CONFIG", "ASH_SOURCE_DIR"):
        monkeypatch.delenv(name, raising=False)
    root = tmp_path / "kqmm-engine-site"
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


def _config_reading(tmp_path: Path, monkeypatch, value: str):
    """A resolved config whose one plugin module entry reads *value* from the
    environment. The file sits outside the scanned tree (the cwd), so the entry
    is kept as the operator's."""
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.setenv("ASH_KQMM_ENTRY", value)
    source = tmp_path / "src"
    source.mkdir()
    monkeypatch.chdir(source)
    config_file = tmp_path / "cfg" / ".ash.yaml"
    config_file.parent.mkdir()
    config_file.write_text(
        "project_name: probe\nash_plugin_modules:\n  - !ENV ${ASH_KQMM_ENTRY}\n",
        encoding="utf-8",
    )
    return resolve_config(config_path=str(config_file))


def _engine(tmp_path: Path, config) -> None:
    from automated_security_helper.core.execution_engine import ScanExecutionEngine

    context = MagicMock()
    context.config = config
    context.source_dir = tmp_path / "src"
    context.output_dir = tmp_path / "out"
    context.work_dir = tmp_path / "out" / "work"
    ScanExecutionEngine(
        context=context, ash_plugin_modules=[], asharp_model=MagicMock()
    )


def _recording(monkeypatch, method: str, name: str, seen: List[str]) -> None:
    """Wrap ``AshPluginManager.<method>`` to note, at each call, how the scope
    in force would print *name*."""
    from automated_security_helper.plugins.plugin_manager import (
        without_masked_modules,
    )

    original = getattr(AshPluginManager, method)

    def recorder(self, *args, **kwargs):
        seen.append(without_masked_modules(name))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(AshPluginManager, method, recorder)


# --- the left-out line -----------------------------------------------------------


def test_the_left_out_line_names_a_dotted_parent_of_a_masked_entry_by_its_mask(
    tmp_path, monkeypatch, site, messages
):
    """The entry is ``<parent>.<child>``; the plugin the parent package defines
    is registered under the parent's name, and the scan names only the child,
    so the plugin is left out and its module is printed."""
    parent = "kqmmeng_ash_plugins"
    child = "kqmmengchild_ash_plugins"
    _plant(
        site,
        {
            f"{parent}/__init__.py": LEFT_OUT_BODY,
            f"{parent}/{child}/__init__.py": "",
        },
    )
    config = _config_reading(tmp_path, monkeypatch, f"{parent}.{child}")
    try:
        _engine(tmp_path, config)
    finally:
        ash_plugin_manager.remove_plugin_module_registration("scanner", "KqMmLeftOut")

    left_out = [m for m in messages if "Registered plugins not used by this scan" in m]
    assert any("scanner KqMmLeftOut" in m for m in left_out), left_out
    assert all(parent not in m for m in left_out), left_out
    assert any(f"scanner KqMmLeftOut ({MASK})" in m for m in left_out), left_out


# --- the registry resolution -----------------------------------------------------


def test_the_resolution_warning_names_a_masked_modules_child_by_its_mask(
    tmp_path, monkeypatch, site, messages
):
    name = "kqmmengres_ash_plugins"
    _plant(site, {f"{name}/__init__.py": ""})
    ash_plugin_manager.register_plugin_module(
        "scanner", "KqMmEngRes", f"{name}.kqmissing_sub"
    )
    config = _config_reading(tmp_path, monkeypatch, name)
    try:
        _engine(tmp_path, config)
    finally:
        ash_plugin_manager.remove_plugin_module_registration("scanner", "KqMmEngRes")

    failed = [
        m
        for m in messages
        if "Failed to import plugin module" in m and "kqmissing_sub" in m
    ]
    assert failed, messages
    assert all(name not in m for m in failed), failed
    assert any(f"{MASK}.kqmissing_sub" in m for m in failed), failed


# --- the scope around the engine's registry calls ----------------------------------


def test_the_engine_reads_the_registry_inside_the_scope(tmp_path, monkeypatch, site):
    """Six registry reads: the three plugin kinds that select this scan's
    plugins, and the three the left-out list makes."""
    name = "kqmmengscope_ash_plugins"
    _plant(site, {f"{name}/__init__.py": ""})
    seen: List[str] = []
    _recording(monkeypatch, "plugin_modules", name, seen)
    config = _config_reading(tmp_path, monkeypatch, name)

    _engine(tmp_path, config)

    assert seen.count(MASK) >= 6, seen


def test_the_engine_filters_the_registry_inside_the_scope(tmp_path, monkeypatch, site):
    name = "kqmmengfilter_ash_plugins"
    _plant(site, {f"{name}/__init__.py": ""})
    seen: List[str] = []
    _recording(monkeypatch, "plugins_loaded_by", name, seen)
    config = _config_reading(tmp_path, monkeypatch, name)

    _engine(tmp_path, config)

    assert seen == [MASK], seen


def test_the_engine_reads_the_registry_in_a_scope_that_hides_a_longer_name(
    tmp_path, monkeypatch, site
):
    """The scope holds the masked entry's own name as a plain value too, so a
    longer module name that holds it (``<name>_extras``) is hidden inside it."""
    name = "kqmmenglong_ash_plugins"
    _plant(site, {f"{name}/__init__.py": ""})
    seen: List[str] = []
    _recording(monkeypatch, "plugin_modules", f"{name}_extras", seen)
    config = _config_reading(tmp_path, monkeypatch, name)

    _engine(tmp_path, config)

    assert seen.count(f"{MASK}_extras") >= 6, seen


def test_the_engine_filters_the_registry_in_a_scope_that_hides_a_longer_name(
    tmp_path, monkeypatch, site
):
    name = "kqmmenglongfilter_ash_plugins"
    _plant(site, {f"{name}/__init__.py": ""})
    seen: List[str] = []
    _recording(monkeypatch, "plugins_loaded_by", f"{name}_extras", seen)
    config = _config_reading(tmp_path, monkeypatch, name)

    _engine(tmp_path, config)

    assert seen == [f"{MASK}_extras"], seen


def test_a_name_no_entry_masks_prints_as_it_is_inside_the_engines_scope(
    tmp_path, monkeypatch, site
):
    """Control: the scope holds the run's masked entries only."""
    entry = "kqmmengmasked_ash_plugins"
    other = "kqmmengother_ash_plugins"
    _plant(site, {f"{entry}/__init__.py": ""})
    seen: List[str] = []
    _recording(monkeypatch, "plugins_loaded_by", other, seen)
    config = _config_reading(tmp_path, monkeypatch, entry)

    _engine(tmp_path, config)

    assert seen == [other], seen
