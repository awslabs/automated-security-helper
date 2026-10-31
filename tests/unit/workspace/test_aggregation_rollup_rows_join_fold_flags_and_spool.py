# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Three edges of the workspace scanner rollup.

Why this file exists
--------------------
``WorkspaceAggregator`` rolls every project's scanner rows into the unified file's
``scanner_results`` and spools each project's SARIF run to disk before writing.

The rows were joined on the raw scanner name. ``cli/merge`` documents that one
results file records "Bandit" where another records "bandit", and compares every
name stripped and lowered for that reason; the rollup did not, so one scanner
became two rows the moment two projects' configs spelled it differently.

The row's ``excluded`` and ``dependencies_satisfied`` were derived from the
rolled-up status (``SKIPPED`` and ``!= MISSING``). The project rows carry both
flags themselves, and they disagree with the status in two routine cases: an
operator-excluded scanner whose tool is also absent is a MISSING row with
``excluded`` set, and a scanner that had nothing to scan is a SKIPPED row with
``excluded`` unset.

The spool file was named by the project key alone. Two keys that differ only in
letter case are two projects, and one file name on a case-insensitive output
volume, where the second spool replaced the first project's run.

The contract these cases pin:

- two spellings of one scanner roll up into one row, named as the first project
  spelled it, with the worse status;
- the row's flags come from the carried rows, not from the rolled-up status;
- two projects whose keys differ only in case spool to two distinct file names
  on a case-insensitive filesystem.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional, Tuple

import pytest

from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
)
from automated_security_helper.workspace.aggregation import WorkspaceAggregator
from tests.unit.workspace.test_workspace_reporting import _plan, _run

pytestmark = pytest.mark.unit


def _outcome(
    key: str,
    statuses: Dict[str, str],
    flags: Optional[Dict[str, Tuple[bool, bool]]] = None,
) -> WorkspaceProjectResult:
    outcome = WorkspaceProjectResult(
        project=key,
        relative_path=key,
        display_label=key,
        status=ProjectRunStatus.COMPLETED,
        severity_threshold="MEDIUM",
        output_path=f"projects/{key}",
        scanners=statuses,
    )
    if flags is not None:
        outcome.carry_scanner_flags(flags)
    return outcome


def _rollup(tmp_path: Path, *projects) -> Dict[str, dict]:
    keys = [key for key, _, _ in projects]
    plan = _plan(tmp_path / "ws", *keys)
    aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")
    for plan_project, (key, statuses, flags) in zip(plan.projects, projects):
        aggregator.add(_outcome(key, statuses, flags), None, plan_project)
    path = aggregator.write(exit_code=0, wall_clock_seconds=0.1)
    return json.loads(path.read_text("utf-8"))["scanner_results"]


def test_two_spellings_of_one_scanner_are_one_row(tmp_path):
    rows = _rollup(
        tmp_path,
        ("api", {"Bandit": "PASSED"}, None),
        ("web", {"bandit": "FAILED"}, None),
    )

    assert set(rows) == {"Bandit"}, sorted(rows)
    assert rows["Bandit"]["status"] == "FAILED"


def test_the_rows_flags_come_from_the_carried_rows_not_the_status(tmp_path):
    rows = _rollup(
        tmp_path,
        (
            "api",
            {"grype": "MISSING", "semgrep": "SKIPPED"},
            # grype: excluded by the operator on a host that also lacks its tool.
            # semgrep: nothing to scan, not excluded.
            {"grype": (True, False), "semgrep": (False, True)},
        ),
    )

    assert rows["grype"]["excluded"] is True
    assert rows["grype"]["dependencies_satisfied"] is False
    assert rows["semgrep"]["excluded"] is False
    assert rows["semgrep"]["dependencies_satisfied"] is True


def test_a_row_without_carried_flags_keeps_the_status_derived_answer(tmp_path):
    """Control: an outcome built without flags (a results file read back) is unchanged."""
    rows = _rollup(tmp_path, ("api", {"grype": "MISSING", "semgrep": "SKIPPED"}, None))

    assert rows["grype"]["excluded"] is False
    assert rows["grype"]["dependencies_satisfied"] is False
    assert rows["semgrep"]["excluded"] is True


def test_keys_differing_only_in_case_spool_to_distinct_names(tmp_path):
    plan = _plan(tmp_path / "ws", "Api", "api")
    aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")
    for plan_project in plan.projects:
        key = plan_project.key
        aggregator.add(
            _outcome(key, {"bandit": "PASSED"}),
            _run(key, rule="B101", uri="src/app.py"),
            plan_project,
        )

    spooled = list(aggregator._spooled.values())
    assert len(spooled) == 2
    assert len({path.name.lower() for path in spooled}) == 2, spooled
