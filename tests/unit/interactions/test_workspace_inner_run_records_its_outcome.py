# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace scan run as the inner run of a container scan records how it ended.

It takes the outer process's run ID out of its environment before any project
runs, and stamps its completion marker into the unified results only after the
workspace report step, so a refusal at that step leaves the refusal and no marker
(utils/inner_run_outcome.py). These run the real ``execute_workspace`` with a
stand-in orchestrator, so the order of the steps is the production order.
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock

import pytest

from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _run_workspace_mode,
)
from automated_security_helper.workspace import execution as workspace_execution
from automated_security_helper.workspace.reporting import MANIFEST_FILENAME
from tests.unit.workspace import test_workspace_report_path_links as links
from tests.utils.helpers import builtin_reporter_classes

RUN = "0123456789abcdef0123456789abcdef"


@pytest.fixture
def real_workspace_execution(monkeypatch):
    """``execute_workspace`` as production runs it, around the stand-in orchestrator."""
    real = workspace_execution.execute_workspace
    seen_ids = []

    def execute(plan, settings):
        seen_ids.append(os.environ.get("ASH_OUTER_RUN_ID"))
        return real(
            plan,
            settings,
            orchestrator_factory=links._Orchestrator.create,
            reporter_classes=reporters,
        )

    reporters = builtin_reporter_classes()
    assert len(reporters) >= 15

    monkeypatch.setattr(workspace_execution, "execute_workspace", execute)
    links._Orchestrator.built = []
    links._Orchestrator.during_scan = None
    yield seen_ids
    links._Orchestrator.built = []
    links._Orchestrator.during_scan = None


def _run(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_OUTER_RUN_ID", RUN)
    return _run_workspace_mode(
        ScanOptions(
            source_dir=tmp_path / "ws",
            output_dir=tmp_path / "out",
            workspace_plan=links._plan(tmp_path),
        ),
        MagicMock(),
    )


def _run_records(tmp_path):
    document = json.loads(
        (tmp_path / "out" / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    return [
        (checkpoint["type"], (checkpoint.get("metadata") or {}).get("run_id"))
        for checkpoint in document["validation_checkpoints"]
        if checkpoint.get("type") in ("run_completed", "report_path_refused")
    ]


def test_a_completed_workspace_run_marks_its_completion(
    tmp_path, monkeypatch, real_workspace_execution
):
    _run(tmp_path, monkeypatch)

    assert _run_records(tmp_path) == [("run_completed", RUN)]
    assert not (tmp_path / "out" / "ash_inner_run_outcome.json").exists()


def test_a_report_step_refusal_leaves_the_refusal_and_no_marker(
    tmp_path, monkeypatch, real_workspace_execution
):
    """A link made while the projects run is refused when the report step starts."""
    planted = []

    def plant() -> None:
        if not planted:
            planted.append(links._plant_link(tmp_path, MANIFEST_FILENAME))

    links._Orchestrator.during_scan = plant

    with pytest.raises(SystemExit) as refused:
        _run(tmp_path, monkeypatch)

    assert refused.value.code == 1
    assert planted, "the link was not planted during the scan"
    assert _run_records(tmp_path) == []
    outcome = json.loads(
        (tmp_path / "out" / "ash_inner_run_outcome.json").read_text(encoding="utf-8")
    )
    assert (outcome["type"], outcome["metadata"]["run_id"]) == (
        "report_path_refused",
        RUN,
    )


def test_the_projects_do_not_see_the_run_id(
    tmp_path, monkeypatch, real_workspace_execution
):
    """Taken out of the environment before any project's scan starts."""
    _run(tmp_path, monkeypatch)

    assert real_workspace_execution == [None]
