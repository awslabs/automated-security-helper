"""A workspace scan carries each project's support notices to the unified results file.

Why this exists
---------------
The metadata of the workspace's unified results file is written fresh, so a key a
project's scan records reaches it only if the executor carries it from that project's
results to the aggregator. ``WorkspaceAggregator.write`` records the notices it is given
united by id (tests/unit/workspace/test_workspace_root_unions_support_notices.py pins
that). This file pins the other half: ``execute_workspace`` gives it what each project's
scan recorded, in workspace-file order, so a notice that only the second project met is
not lost.

The control is the same workspace with no notice in any project, which writes no key.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.workspace.execution import execute_workspace
from tests.unit.models._support_notice_helpers import (
    CPU_ID,
    POLYFILL_ID,
    SANDBOX_ID,
    cpu_notice,
    polyfill_notice,
    sandbox_notice,
)
from tests.unit.workspace.test_execution import _make_workspace, _sarif, _settings

pytestmark = pytest.mark.unit


class _Orchestrator:
    """A project scan that ran bandit and recorded the notices its project is given."""

    notices: Dict[str, List[Any]] = {}

    def __init__(self, **kwargs: Any) -> None:
        self.key = Path(kwargs["source_dir"]).name

    @classmethod
    def create(cls, **kwargs: Any) -> "_Orchestrator":
        return cls(**kwargs)

    def execute_scan(self, phases=None):
        model = AshAggregatedResults()
        model.sarif = SarifReport.model_validate(_sarif(count=0))
        model.scanner_results["bandit"] = ScannerTargetStatusInfo(
            status="PASSED", excluded=False, dependencies_satisfied=True
        )
        model.metadata.support_notices = list(self.notices.get(self.key, [])) or None
        return model


def _workspace(tmp_path: Path, notices: Optional[Dict[str, List[Any]]]):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))
    _Orchestrator.notices = notices or {}
    try:
        return execute_workspace(
            plan, _settings(tmp_path), orchestrator_factory=_Orchestrator.create
        )
    finally:
        _Orchestrator.notices = {}


def _ids(result) -> List[str]:
    document = json.loads(result.results_path.read_text("utf-8"))
    return [notice["id"] for notice in document["metadata"]["support_notices"]]


class TestTheWorkspaceResultsCarryEveryProjectsNotices:
    def test_each_projects_notices_are_recorded_in_workspace_file_order(self, tmp_path):
        result = _workspace(
            tmp_path,
            {"api": [cpu_notice()], "web": [sandbox_notice(), polyfill_notice()]},
        )

        assert _ids(result) == [CPU_ID, SANDBOX_ID, POLYFILL_ID]

    def test_a_notice_only_the_second_project_met_is_recorded(self, tmp_path):
        result = _workspace(tmp_path, {"web": [sandbox_notice()]})

        assert _ids(result) == [SANDBOX_ID]

    def test_a_notice_both_projects_met_is_recorded_once(self, tmp_path):
        result = _workspace(
            tmp_path, {"api": [cpu_notice()], "web": [cpu_notice(), sandbox_notice()]}
        )

        assert _ids(result) == [CPU_ID, SANDBOX_ID]

    def test_the_model_reads_the_recorded_notices_back(self, tmp_path):
        result = _workspace(tmp_path, {"api": [cpu_notice()]})

        model = AshAggregatedResults.model_validate_json(
            result.results_path.read_text("utf-8")
        )

        assert model.metadata.support_notices == [cpu_notice()]


class TestAWorkspaceWhoseProjectsRecordNoNoticeWritesNoKey:
    def test_control_no_project_recorded_one(self, tmp_path):
        result = _workspace(tmp_path, None)

        document = json.loads(result.results_path.read_text("utf-8"))

        assert "support_notices" not in document["metadata"]
