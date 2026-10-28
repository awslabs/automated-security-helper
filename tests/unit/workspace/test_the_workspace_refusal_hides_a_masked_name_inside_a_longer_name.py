# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace's import refusal hides a masked module name, inside a longer name too.

A module name that a project's config read from the environment is hidden
wherever the workspace run prints it, and a longer module name that holds the
masked name (``<name>_extras``) is hidden along with it. That holds for the
refusal the run raises and for the WARNING line the failed import writes, whether
the modules are the operator's own (``--ash-plugin-modules``, loaded in one call)
or are named only by the projects (loaded one at a time).

The registry pre-warm that follows the loads hides it too, in the lines a
resolution of a registered plugin writes.

The cells pin that from the refusal's own text and the log lines: a module that
is not masked fails to import a module named after the masked one plus a suffix,
and neither the shown refusal nor the WARNING line names the masked name or the
part of the longer name that holds it.
"""

from __future__ import annotations

import logging
import sys
from typing import List

import pytest

from automated_security_helper.config.environment_record import (
    ENVIRONMENT_VALUE_SHOWN,
)
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.loader import PluginModuleError
from automated_security_helper.utils.error_text import error_text
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    prewarm_plugin_registry,
)
from automated_security_helper.workspace.resolver import resolve_workspace

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


def _plan(tmp_path, modules, masked):
    """A one-project plan that names *modules*, of which *masked* was read from
    the environment, as resolution records it."""
    (tmp_path / "api").mkdir()
    workspace_file = tmp_path / "dev.code-workspace"
    workspace_file.write_text('{"folders": [{"path": "api"}]}', encoding="utf-8")
    plan = resolve_workspace(workspace_file)
    project = plan.projects[0].model_copy(
        update={
            "ash_plugin_modules": modules,
            "plugin_module_names": {masked: ENVIRONMENT_VALUE_SHOWN},
        }
    )
    return plan.model_copy(update={"projects": [project]})


def _plant(tmp_path, monkeypatch, masked, literal):
    site = tmp_path / "site"
    (site / masked).mkdir(parents=True)
    (site / masked / "__init__.py").write_text("", encoding="utf-8")
    (site / literal).mkdir(parents=True)
    (site / literal / "__init__.py").write_text(
        f"import {masked}_extras\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(site))


def _refusal_and_warning(plan, settings, messages, literal):
    try:
        with pytest.raises(PluginModuleError) as raised:
            prewarm_plugin_registry(plan, settings)
    finally:
        for name in [m for m in sys.modules if m.startswith("kqwsref")]:
            sys.modules.pop(name, None)
    warnings = [
        m for m in messages if "Failed to import plugin module" in m and literal in m
    ]
    assert len(warnings) == 1, warnings
    return error_text(raised.value), warnings[0]


def test_the_workspace_refusal_hides_a_masked_name_inside_a_longer_name(
    tmp_path, monkeypatch, messages
):
    masked = "kqwsref_ash_plugins"
    literal = "kqwsreflit_ash_plugins"
    _plant(tmp_path, monkeypatch, masked, literal)
    plan = _plan(tmp_path, [masked, literal], masked)

    shown, warning = _refusal_and_warning(
        plan, ProjectScanSettings(output_dir=tmp_path / "out"), messages, literal
    )

    assert masked not in shown, shown
    assert f"{MASK}_extras" in shown, shown
    assert masked not in warning, warning
    assert f"{MASK}_extras" in warning, warning


def test_the_refusal_and_warning_hide_a_masked_name_for_operator_modules(
    tmp_path, monkeypatch, messages
):
    """The operator's own modules load in one call, the masked module beside the
    one that fails on the longer name."""
    masked = "kqwsref_ash_plugins"
    literal = "kqwsreflit_ash_plugins"
    _plant(tmp_path, monkeypatch, masked, literal)
    plan = _plan(tmp_path, [], masked)
    settings = ProjectScanSettings(
        output_dir=tmp_path / "out", ash_plugin_modules=(masked, literal)
    )

    shown, warning = _refusal_and_warning(plan, settings, messages, literal)

    assert masked not in shown, shown
    assert f"{MASK}_extras" in shown, shown
    assert masked not in warning, warning
    assert f"{MASK}_extras" in warning, warning


def test_the_prewarm_resolution_hides_a_masked_name_inside_a_longer_module_name(
    tmp_path, monkeypatch, messages
):
    """The registry holds a plugin whose module path is a longer name that holds
    the masked name, and resolving it fails. The resolution writes the path and
    the import error's text, and both hide the masked name."""
    masked = "kqwsreg_ash_plugins"
    site = tmp_path / "site"
    (site / masked).mkdir(parents=True)
    (site / masked / "__init__.py").write_text("", encoding="utf-8")
    monkeypatch.syspath_prepend(str(site))
    plan = _plan(tmp_path, [masked], masked)
    ash_plugin_manager.register_plugin_module(
        "scanner", "KqWsRegExtra", f"{masked}_extras.kqmissing"
    )
    try:
        prewarm_plugin_registry(plan, ProjectScanSettings(output_dir=tmp_path / "out"))
    finally:
        ash_plugin_manager.remove_plugin_module_registration("scanner", "KqWsRegExtra")
        for name in [m for m in sys.modules if m.startswith("kqwsreg")]:
            sys.modules.pop(name, None)

    failed = [
        m
        for m in messages
        if "Failed to import plugin module" in m and "kqmissing" in m
    ]
    assert failed, messages
    assert all(masked not in m for m in failed), failed
    assert any(f"{MASK}_extras" in m for m in failed), failed
