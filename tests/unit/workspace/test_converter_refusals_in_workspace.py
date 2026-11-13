# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace project counts incomplete conversion as ``ash --source-dir P`` does.

``_compute_exit_code`` fails a single-directory scan when ``incomplete_converters``
names a converter: one that crashed, one whose tool was absent with inputs to
convert, or the archive converter after refusing an archive over an extraction
limit. The workspace verdict asked only the scanner questions, and the MCP
workspace tools reported ``incomplete_converters: []`` for every project, so the
same project passed inside a workspace and exited 1 on its own.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceExitCode,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_section import (
    workspace_project_rows,
)
from tests.unit.workspace.test_execution import (
    FakeOrchestrator,
    _make_workspace,
    _run,
    _sarif,
)

pytestmark = pytest.mark.unit

OVER_LIMIT_ROW = {
    "converted_paths": [],
    "refused_inputs": [
        {
            "path": "vendor/big.zip",
            "reason": "its members declare more than 1073741824 bytes, the "
            "max_total_bytes extraction limit",
            "limit": "max_total_bytes",
        }
    ],
}
REASON = "refused 1 input over an extraction limit: vendor/big.zip (max_total_bytes)"


@pytest.fixture(autouse=True)
def _fresh_fake_orchestrator():
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    yield
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}


def _project(tmp_path, converter_results):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {
        "sarif": _sarif(count=0),
        "scanner_results": {
            "bandit": {
                "status": "PASSED",
                "excluded": False,
                "dependencies_satisfied": True,
            }
        },
        "converter_results": converter_results,
    }
    return plan


def test_an_archive_over_a_limit_makes_the_project_incomplete(tmp_path):
    outcome = _run(tmp_path, _project(tmp_path, {"archive": OVER_LIMIT_ROW}))
    entry = outcome.payload.projects[0]

    # Control: every scanner completed and nothing was found.
    assert entry.incomplete_scanners == []
    assert entry.exceeds_threshold is False

    assert entry.incomplete_converters == {"archive": REASON}
    assert entry.scan_incomplete is True
    assert outcome.exit_code == WorkspaceExitCode.INTERNAL_ERROR


def test_the_unified_results_and_the_workspace_table_carry_the_converter(tmp_path):
    _run(tmp_path, _project(tmp_path, {"archive": OVER_LIMIT_ROW}))

    unified = json.loads((tmp_path / "out" / "ash_aggregated_results.json").read_text())
    (project,) = unified["workspace"]["projects"]
    assert project["incomplete_converters"] == {"archive": REASON}

    model = AshAggregatedResults()
    model.workspace = WorkspaceResults.model_validate(unified["workspace"])
    (row,) = workspace_project_rows(model)
    assert row["result"] == "FAILED (incomplete)"
    assert "conversion incomplete: archive" in row["detail"]


def test_the_gate_off_still_names_the_converter(tmp_path):
    outcome = _run(
        tmp_path,
        _project(tmp_path, {"archive": OVER_LIMIT_ROW}),
        fail_on_incomplete_scanners=False,
    )
    entry = outcome.payload.projects[0]

    assert entry.scan_incomplete is False
    assert outcome.exit_code == WorkspaceExitCode.SUCCESS
    assert entry.incomplete_converters == {"archive": REASON}


def test_a_member_refusal_alone_leaves_the_project_complete(tmp_path):
    row = {
        "converted_paths": [],
        "refused_inputs": [
            {"path": "outer.zip", "member": "inner.zip", "reason": "nested"}
        ],
    }
    outcome = _run(tmp_path, _project(tmp_path, {"archive": row}))
    entry = outcome.payload.projects[0]

    assert entry.incomplete_converters == {}
    assert entry.scan_incomplete is False
    assert outcome.exit_code == WorkspaceExitCode.SUCCESS


def test_a_missing_converter_tool_with_inputs_makes_the_project_incomplete(tmp_path):
    """The converter rows a single-directory scan already fails on, nbconvert absent."""
    row = {
        "converted_paths": [],
        "dependencies_satisfied": False,
        "candidate_inputs": 2,
    }
    outcome = _run(tmp_path, _project(tmp_path, {"jupyter": row}))
    entry = outcome.payload.projects[0]

    assert list(entry.incomplete_converters) == ["jupyter"]
    assert entry.scan_incomplete is True


class TestMcpWorkspace:
    def test_the_project_coverage_names_the_converter(self, tmp_path):
        from automated_security_helper.cli.mcp.workspace import _project_coverage
        from automated_security_helper.core.resource_management.scan_tracking import (
            coverage_has_gap,
        )

        entry = _run(
            tmp_path, _project(tmp_path, {"archive": OVER_LIMIT_ROW})
        ).payload.projects[0]

        coverage = _project_coverage(entry)

        assert coverage["incomplete_converters"] == [
            {"converter": "archive", "reason": REASON}
        ]
        assert coverage_has_gap(coverage)

    def test_the_project_scan_closes_incomplete(self, tmp_path):
        from automated_security_helper.cli.mcp import workspace as ws

        registry = ScanRegistry()
        scan_id = registry.register_scan(
            directory_path=str(tmp_path), output_directory=str(tmp_path)
        )
        outcome = WorkspaceProjectResult(
            project="app",
            relative_path="app",
            display_label="app",
            status=ProjectRunStatus.COMPLETED,
            output_path=str(Path(tmp_path)),
            scanners={"bandit": "PASSED"},
            incomplete_converters={"archive": REASON},
            scan_incomplete=True,
        )
        payload = WorkspaceResults.model_construct(projects=[outcome])
        with patch.object(ws, "get_scan_registry", return_value=registry):
            ws._close_registrations({"app": scan_id}, payload)
        entry = registry.get_scan(scan_id)

        assert entry.status.value == "incomplete"
        assert entry.coverage["incomplete_converters"] == [
            {"converter": "archive", "reason": REASON}
        ]
