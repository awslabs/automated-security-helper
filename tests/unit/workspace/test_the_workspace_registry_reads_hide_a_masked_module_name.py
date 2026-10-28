# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every registry read of a workspace run hides the run's masked module names.

A resolution of the registry writes a "Failed to import plugin module" warning
for each registration whose module does not import, and it runs whenever a
registration has changed since the last one. The workspace pre-warms the
registry and reads the reporters inside the run's masked-module scope. Two more
reads ran outside it: the reporter list ``execute_workspace`` builds for the
report step, and the scanner list ``refuse_unresolvable_scanner_selection``
checks a ``--scanners`` selection against. In a process that serves several
sessions (the MCP server) another session's registration can land between the
pre-warm and those reads, so the resolution happens in them, and a module path
that a project's config read from the environment printed in clear.

Both reads now run inside the same scope. The reporter list is built in one
entry of it: ``workspace_reporter_classes`` is the same read with its own entry,
for a caller that holds none, and ``execute_workspace`` does not enter the scope
a second time inside its own.

Covered: the default reporter read of ``execute_workspace`` and the scanner read
of the selection check, each resolving a registration made just before the read
by a call that sets no scope; the one entry of the scope for the reporter list;
and, as a control, a registration whose module name no project masked.
"""

from __future__ import annotations

import contextlib
import logging
import sys
from typing import List

import pytest

from automated_security_helper.config.environment_record import (
    ENVIRONMENT_VALUE_SHOWN,
)
from automated_security_helper.core.exceptions import ScannerSelectionError
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.workspace import execution as execution_module
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    execute_workspace,
    refuse_unresolvable_scanner_selection,
)
from automated_security_helper.workspace.resolver import resolve_workspace

MASK = "<value>"
MASKED = "kqwsread_ash_plugins"


class _Sink(logging.Handler):
    def __init__(self):
        super().__init__(level=1)
        self.messages: List[str] = []

    def emit(self, record):
        self.messages.append(record.getMessage())


class _Stop(Exception):
    """Ends ``execute_workspace`` right after the reporter read."""


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
def plan(tmp_path, monkeypatch):
    """A one-project plan that names the masked module, as resolution records an
    entry its config read from the environment."""
    site = tmp_path / "site"
    (site / MASKED).mkdir(parents=True)
    (site / MASKED / "__init__.py").write_text("", encoding="utf-8")
    monkeypatch.syspath_prepend(str(site))
    (tmp_path / "api").mkdir()
    workspace_file = tmp_path / "dev.code-workspace"
    workspace_file.write_text('{"folders": [{"path": "api"}]}', encoding="utf-8")
    resolved = resolve_workspace(workspace_file)
    project = resolved.projects[0].model_copy(
        update={
            "ash_plugin_modules": [MASKED],
            "plugin_module_names": {MASKED: ENVIRONMENT_VALUE_SHOWN},
        }
    )
    yield resolved.model_copy(update={"projects": [project]})
    for name in [m for m in sys.modules if m.startswith("kqwsread")]:
        sys.modules.pop(name, None)


def _failures(messages: List[str]) -> List[str]:
    return [m for m in messages if "Failed to import plugin module" in m]


def test_the_default_reporter_read_hides_a_masked_module_name(
    tmp_path, monkeypatch, messages, plan
):
    """Another session registers a reporter between the pre-warm and the read."""

    def another_sessions_registration(_plan, _settings):
        ash_plugin_manager.register_plugin_module(
            "reporter", "KqWsReadReporter", f"{MASKED}_extras.kqmissing"
        )
        return []

    def stop(_plan, _settings):
        raise _Stop

    monkeypatch.setattr(
        execution_module, "_reporter_classes_of_run", another_sessions_registration
    )
    monkeypatch.setattr(execution_module, "refuse_unresolvable_scanner_selection", stop)
    try:
        with pytest.raises(_Stop):
            execute_workspace(plan, ProjectScanSettings(output_dir=tmp_path / "out"))
    finally:
        ash_plugin_manager.remove_plugin_module_registration(
            "reporter", "KqWsReadReporter"
        )

    failed = _failures(messages)
    assert failed, messages
    assert all(MASKED not in m for m in failed), failed
    assert any(f"{MASK}_extras.kqmissing" in m for m in failed), failed


def test_the_default_reporter_read_enters_the_runs_scope_once(
    tmp_path, monkeypatch, plan
):
    """``workspace_reporter_classes`` reads the registry in the run's scope, and
    so does the list ``execute_workspace`` builds from its result. The two reads
    share one entry of the scope: entering it again inside the first would build
    every form of the run a second time, to be dropped as a repeat."""
    entered: List[object] = []
    original = execution_module._masked_modules_of_run

    def counting(the_plan):
        entered.append(the_plan)
        return original(the_plan)

    def stop(_plan, _settings):
        raise _Stop

    monkeypatch.setattr(execution_module, "_masked_modules_of_run", counting)
    monkeypatch.setattr(
        execution_module, "prewarm_plugin_registry", lambda _plan, _settings: None
    )
    monkeypatch.setattr(execution_module, "refuse_unresolvable_scanner_selection", stop)

    with pytest.raises(_Stop):
        execute_workspace(plan, ProjectScanSettings(output_dir=tmp_path / "out"))

    assert len(entered) == 1, entered


def test_the_scanner_selection_read_hides_a_masked_module_name(
    tmp_path, messages, plan
):
    ash_plugin_manager.register_plugin_module(
        "scanner", "KqWsReadScanner", f"{MASKED}_extras.kqmissing"
    )
    settings = ProjectScanSettings(
        output_dir=tmp_path / "out", enabled_scanners=("kqnosuch-scanner",)
    )
    try:
        with contextlib.suppress(ScannerSelectionError):
            refuse_unresolvable_scanner_selection(plan, settings)
    finally:
        ash_plugin_manager.remove_plugin_module_registration(
            "scanner", "KqWsReadScanner"
        )

    failed = _failures(messages)
    assert failed, messages
    assert all(MASKED not in m for m in failed), failed
    assert any(f"{MASK}_extras.kqmissing" in m for m in failed), failed


def test_a_registration_no_project_masked_prints_as_it_is_in_the_scanner_read(
    tmp_path, messages, plan
):
    other = "kqwsreadother_ash_plugins"
    ash_plugin_manager.register_plugin_module(
        "scanner", "KqWsReadOther", f"{other}.kqmissing"
    )
    settings = ProjectScanSettings(
        output_dir=tmp_path / "out", enabled_scanners=("kqnosuch-scanner",)
    )
    try:
        with contextlib.suppress(ScannerSelectionError):
            refuse_unresolvable_scanner_selection(plan, settings)
    finally:
        ash_plugin_manager.remove_plugin_module_registration("scanner", "KqWsReadOther")

    failed = _failures(messages)
    assert any(f"{other}.kqmissing" in m for m in failed), failed
