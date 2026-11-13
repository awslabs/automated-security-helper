# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pre-scan report-path check is built with the workspace's plugin modules.

``execute_workspace`` checks the workspace report paths before any project is
scanned, so a bad file name, a collision or a link at one refuses the run while
nothing has been written. The two calls beside it (the unsupported-reporter check
and the report step itself) pass the workspace's plugin modules, so they build the
plugin-module reporters too; this one did not, so it built only the built-in
reporters, and a plugin-module reporter's bad name, collision or link was refused
only after every project had been scanned.
"""

from __future__ import annotations

import pytest

from automated_security_helper.workspace import execution
from automated_security_helper.workspace.execution import workspace_plugin_modules
from tests.unit.workspace.test_execution import (
    FakeOrchestrator,
    _make_workspace,
    _settings,
)

pytestmark = pytest.mark.unit


class _Halt(Exception):
    """Raised by the recording pre-check so no project is scanned."""


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    yield
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}


def test_the_pre_check_is_given_the_workspace_plugin_modules(tmp_path, monkeypatch):
    calls = []

    def record(plan, output_dir, **kwargs):
        calls.append(kwargs)
        raise _Halt

    monkeypatch.setattr(execution, "refuse_linked_workspace_report_paths", record)
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    settings = _settings(tmp_path, phases=("scan", "report"))

    with pytest.raises(_Halt):
        execution.execute_workspace(
            plan, settings, orchestrator_factory=FakeOrchestrator.create
        )

    (kwargs,) = calls
    # RED at the base: the call passed no plugin_modules (a KeyError here), so the
    # pre-check built only the built-in reporters.
    assert kwargs["plugin_modules"] == list(workspace_plugin_modules(plan, settings))
    # Control: the check ran before any project was handed to an orchestrator.
    assert FakeOrchestrator.built == []
