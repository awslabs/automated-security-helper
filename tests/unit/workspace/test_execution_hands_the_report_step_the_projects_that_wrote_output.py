# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which projects' per-project reports the workspace report step lists as this run's.

``emit_workspace_reports`` takes the keys of the projects whose own output the run
wrote, and falls back to reading the COMPLETED projects out of the unified results
file when it is not given them. The two differ for a project that FAILED after its
output directory was set up: its reports were written by this run, but the file
calls it failed. The reporting half is pinned in
``test_workspace_reporting_manifest_fidelity``; this file pins the caller, which
holds every outcome in memory and has to hand the set over. Driven through the
real ``execute_workspace`` because a call assertion on a stand-in would not notice
the argument being dropped.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    execute_workspace,
)
from automated_security_helper.workspace.reporting import (
    MANIFEST_FILENAME,
    REPORTS_DIR_NAME,
)
from tests.unit.workspace.test_workspace_reporting import (
    FakePerProjectReporter,
    _plan,
    _run,
)

pytestmark = pytest.mark.unit


def _orchestrator(failing_keys):
    """An orchestrator that writes its project's report file, then maybe raises."""

    class _Orchestrator:
        def __init__(self, **kwargs):
            self.key = Path(kwargs["source_dir"]).name
            self.output_dir = Path(kwargs["output_dir"])

        @classmethod
        def create(cls, **kwargs):
            return cls(**kwargs)

        def execute_scan(self, phases=None):
            reports = self.output_dir / REPORTS_DIR_NAME
            reports.mkdir(parents=True, exist_ok=True)
            (reports / "ash.ghas.sarif").write_text("{}", encoding="utf-8")
            if self.key in failing_keys:
                raise RuntimeError("fixture failure after the reports were written")
            model = AshAggregatedResults()
            model.sarif = SarifReport.model_validate(
                {
                    "version": "2.1.0",
                    "runs": [
                        _run(
                            self.key,
                            rule=f"RULE-{self.key.upper()}",
                            uri=f"src/{self.key}.py",
                        )
                    ],
                }
            )
            return model

    return _Orchestrator


def _execute(tmp_path, failing_keys):
    root = tmp_path / "ws"
    for key in ("api", "web"):
        (root / key / "src").mkdir(parents=True, exist_ok=True)
    (root / "fixture.code-workspace").write_text(
        json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}),
        encoding="utf-8",
    )
    result = execute_workspace(
        _plan(root, "api", "web"),
        ProjectScanSettings(
            output_dir=tmp_path / "out",
            phases=("scan", "report"),
            max_parallel_projects=1,
        ),
        orchestrator_factory=_orchestrator(failing_keys).create,
        reporter_classes=[FakePerProjectReporter],
    )
    manifest = json.loads(
        (tmp_path / "out" / REPORTS_DIR_NAME / MANIFEST_FILENAME).read_text(
            encoding="utf-8"
        )
    )
    return result, manifest["reporters"]["fake-per-project"]


def test_a_failed_project_that_wrote_its_reports_is_listed_as_this_runs(tmp_path):
    result, entry = _execute(tmp_path, failing_keys={"web"})

    # Control: web really is recorded as failed in the run, so the listing below
    # is a decision about a failed project and not about a completed one.
    statuses = {p.project: p.status.value for p in result.payload.projects}
    assert statuses == {"api": "completed", "web": "failed"}, statuses

    assert [item["project"] for item in entry["per_project_artifacts"]] == [
        "api",
        "web",
    ]
    assert entry["missing_per_project_artifacts"] == []


def test_a_project_whose_scan_completed_is_still_listed(tmp_path):
    """The other direction: handing the set over must not drop the completed."""
    _, entry = _execute(tmp_path, failing_keys=set())

    assert [item["project"] for item in entry["per_project_artifacts"]] == [
        "api",
        "web",
    ]
    assert entry["missing_per_project_artifacts"] == []
