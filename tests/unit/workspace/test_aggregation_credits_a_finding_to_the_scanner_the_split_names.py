# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A finding is credited to the scanner row its actionable count is credited to.

A project's outcome splits its actionable count by scanner, naming a scanner as
``result_scanner_name`` does: a ``scanner_name`` that is not a string names none,
so the finding belongs to the unattributed scanner. The aggregator credited the
same finding to ``str(scanner_name)``, a row of its own, so the rollup held a
finding count under one row and the actionable count under another, and a row
could carry more actionable findings than findings. It now names the scanner the
same way.
"""

from __future__ import annotations

import pytest

from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
)
from automated_security_helper.workspace.aggregation import (
    UNATTRIBUTED_SCANNER,
    WorkspaceAggregator,
)
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

pytestmark = pytest.mark.unit


def _project(tmp_path) -> ProjectPlan:
    return ProjectPlan(
        key="api",
        relative_path="api",
        path=(tmp_path / "ws" / "api").as_posix(),
        label="api",
        display_label="api",
    )


def _aggregator(tmp_path, project: ProjectPlan) -> WorkspaceAggregator:
    plan = WorkspacePlan(
        workspace_file=(tmp_path / "ws.code-workspace").as_posix(),
        workspace_root=(tmp_path / "ws").as_posix(),
        projects=[project],
    )
    return WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")


def _run(scanner_name) -> dict:
    return {
        "tool": {"driver": {"name": "ASH"}},
        "results": [
            {
                "ruleId": "R1",
                "level": "error",
                "message": {"text": "finding"},
                "properties": {"scanner_name": scanner_name, "issue_severity": "HIGH"},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": "src/app.py"}}}
                ],
            }
        ],
    }


def _outcome(split: dict) -> WorkspaceProjectResult:
    outcome = WorkspaceProjectResult(
        project="api",
        relative_path="api",
        display_label="api",
        status=ProjectRunStatus.COMPLETED,
        severity_threshold="MEDIUM",
        finding_count=1,
        actionable_finding_count=1,
        output_path="projects/api",
    )
    outcome.carry_scanner_actionable_counts(split)
    return outcome


@pytest.mark.parametrize("name", [5, ["bandit"], True], ids=["int", "list", "bool"])
def test_a_scanner_name_that_is_not_a_string_is_the_unattributed_row(tmp_path, name):
    project = _project(tmp_path)
    aggregator = _aggregator(tmp_path, project)

    aggregator.add(_outcome({UNATTRIBUTED_SCANNER: 1}), _run(name), project)

    # RED at the base: the finding was counted under str(name) ("5"), and the
    # actionable count under "unattributed", the row the split names.
    assert aggregator._scanner_findings == {UNATTRIBUTED_SCANNER: 1}
    assert aggregator._scanner_actionable == {UNATTRIBUTED_SCANNER: 1}


def test_a_scanner_name_that_is_a_string_keeps_its_row(tmp_path):
    """Control, green on both sides: a named scanner is one row for both counts."""
    project = _project(tmp_path)
    aggregator = _aggregator(tmp_path, project)

    aggregator.add(_outcome({"bandit": 1}), _run("bandit"), project)

    assert aggregator._scanner_findings == {"bandit": 1}
    assert aggregator._scanner_actionable == {"bandit": 1}
