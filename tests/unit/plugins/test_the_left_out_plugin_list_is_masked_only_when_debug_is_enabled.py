# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The engine's list of unused plugins is masked only when DEBUG is enabled.

``ScanExecutionEngine`` lists the registered plugins its scan does not use. The
count goes to INFO and the names, each with the module it was defined in, go to
DEBUG. The list used to be built and masked (``without_masked_modules``, a full
redaction pass over the forms of every masked module in scope) for every
registered plugin on every engine build, so a process at INFO paid for the
redaction of text nobody saw. The names are now built and masked only when the
logger is enabled for DEBUG, as the loader's traceback and the decorators' line
are.

A plugin in the list can come from a module that another run's scope masked when
the plugin registered (the registry is the process's). The list hides the names
the plugin's registration was made under, besides the engine's own.

Covered: no masking call at INFO, and the count still logged; at DEBUG the list
is written with the module named by its mask; a plugin registered under another
scope's mask is named by that mask too, and, as a control, one registered under
no mask keeps its module name.
"""

from __future__ import annotations

import importlib
import logging
import sys
from pathlib import Path
from typing import Callable, Dict, List
from unittest.mock import MagicMock

import pytest

from automated_security_helper.core import execution_engine
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.loader import masked_module_scope
from automated_security_helper.plugins.plugin_manager import masked_module_names
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

MASK = "<value>"
PARENT = "kqlft_ash_plugins"
CHILD = "kqlftchild_ash_plugins"
LEFT_OUT_BODY = (
    "from automated_security_helper.plugins.decorators import ash_scanner_plugin\n"
    "\n"
    "\n"
    "@ash_scanner_plugin\n"
    "class KqLftLeftOut:\n"
    "    pass\n"
)


class _Sink(logging.Handler):
    def __init__(self):
        super().__init__(level=1)
        self.messages: List[str] = []

    def emit(self, record):
        self.messages.append(record.getMessage())


@pytest.fixture
def at_level():
    """A function that sets the ash logger's level and returns the messages
    the logger passes to its handlers from then on."""
    sink = _Sink()
    saved = ASH_LOGGER.level
    ASH_LOGGER.addHandler(sink)

    def use(level: int) -> List[str]:
        ASH_LOGGER.setLevel(level)
        return sink.messages

    yield use
    ASH_LOGGER.removeHandler(sink)
    ASH_LOGGER.setLevel(saved)


@pytest.fixture
def masking_calls(monkeypatch: pytest.MonkeyPatch) -> List[str]:
    """The texts the engine passed to ``without_masked_modules``."""
    original: Callable[[str], str] = execution_engine.without_masked_modules
    calls: List[str] = []

    def counting(text: str) -> str:
        calls.append(text)
        return original(text)

    monkeypatch.setattr(execution_engine, "without_masked_modules", counting)
    return calls


@pytest.fixture
def engine_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A resolved config whose one plugin module entry, ``<parent>.<child>``,
    reads from the environment. The parent package defines a scanner the scan
    does not select, so the engine lists it as left out."""
    for name in ("ASH_PLUGIN_MODULES", "ASH_CONFIG", "ASH_SOURCE_DIR"):
        monkeypatch.delenv(name, raising=False)
    site = tmp_path / "left-out-site"
    files: Dict[str, str] = {
        f"{PARENT}/__init__.py": LEFT_OUT_BODY,
        f"{PARENT}/{CHILD}/__init__.py": "",
    }
    for relative, body in files.items():
        path = site / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.setenv("ASH_KQLFT_ENTRY", f"{PARENT}.{CHILD}")
    source = tmp_path / "src"
    source.mkdir()
    monkeypatch.chdir(source)
    config_file = tmp_path / "cfg" / ".ash.yaml"
    config_file.parent.mkdir()
    config_file.write_text(
        "project_name: probe\nash_plugin_modules:\n  - !ENV ${ASH_KQLFT_ENTRY}\n",
        encoding="utf-8",
    )

    from automated_security_helper.config.resolve_config import resolve_config

    yield resolve_config(config_path=str(config_file))
    ash_plugin_manager.remove_plugin_module_registration("scanner", "KqLftLeftOut")
    for name in [m for m in sys.modules if m.startswith("kqlft")]:
        sys.modules.pop(name, None)


@pytest.fixture
def plant(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A function that plants a package holding one scanner class, imports it
    (inside the mask of its own name when asked, as another run's load does) and
    leaves the class registered for the test. The scan never selects it."""
    planted: List[tuple] = []

    def plant_module(module: str, class_name: str, masked: bool) -> None:
        root = tmp_path / f"planted-{module}"
        (root / module).mkdir(parents=True)
        (root / module / "__init__.py").write_text(
            LEFT_OUT_BODY.replace("KqLftLeftOut", class_name), encoding="utf-8"
        )
        monkeypatch.syspath_prepend(str(root))
        scope = masked_module_scope({module: MASK}) if masked else ()
        with masked_module_names(scope):
            importlib.import_module(module)
        planted.append((module, class_name))

    yield plant_module
    for module, class_name in planted:
        ash_plugin_manager.remove_plugin_module_registration("scanner", class_name)
        sys.modules.pop(module, None)


def _build_engine(tmp_path: Path, config) -> None:
    context = MagicMock()
    context.config = config
    context.source_dir = tmp_path / "src"
    context.output_dir = tmp_path / "out"
    context.work_dir = tmp_path / "out" / "work"
    execution_engine.ScanExecutionEngine(
        context=context, ash_plugin_modules=[], asharp_model=MagicMock()
    )


def test_the_left_out_names_are_not_masked_when_debug_is_off(
    tmp_path, at_level, masking_calls, engine_config
):
    messages = at_level(logging.INFO)

    _build_engine(tmp_path, engine_config)

    assert masking_calls == [], masking_calls
    counted = [m for m in messages if "registered plugin(s) not used by this scan" in m]
    assert counted, messages
    assert [m for m in messages if "Registered plugins not used" in m] == [], messages


def test_the_left_out_names_are_masked_when_debug_is_enabled(
    tmp_path, at_level, masking_calls, engine_config
):
    """Control: the list is written, with the module named by its mask."""
    messages = at_level(logging.DEBUG)

    _build_engine(tmp_path, engine_config)

    assert masking_calls, masking_calls
    listed = [m for m in messages if "Registered plugins not used" in m]
    assert any(f"scanner KqLftLeftOut ({MASK})" in m for m in listed), listed
    assert all(PARENT not in m for m in listed), listed


def test_a_plugin_registered_under_another_scopes_mask_is_named_by_that_mask(
    tmp_path, at_level, engine_config, plant
):
    """The engine's scope masks the entry of its own config. The plugin comes
    from a module that a different run's scope masked when it registered, and
    the engine's list names that module by the mask too."""
    other = "kqlftother_ash_plugins"
    plant(other, "KqLftOtherOut", masked=True)
    messages = at_level(logging.DEBUG)

    _build_engine(tmp_path, engine_config)

    listed = [m for m in messages if "Registered plugins not used" in m]
    assert listed, messages
    assert all(other not in m for m in listed), listed
    assert any(f"scanner KqLftOtherOut ({MASK})" in m for m in listed), listed


def test_a_plugin_registered_under_no_mask_keeps_its_module_name(
    tmp_path, at_level, engine_config, plant
):
    """Control: a plugin whose module nothing masked is listed with its module."""
    plain = "kqlftplain_ash_plugins"
    plant(plain, "KqLftPlainOut", masked=False)
    messages = at_level(logging.DEBUG)

    _build_engine(tmp_path, engine_config)

    listed = [m for m in messages if "Registered plugins not used" in m]
    assert any(f"scanner KqLftPlainOut ({plain})" in m for m in listed), listed
