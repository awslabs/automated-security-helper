# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The workspace scanner rollup reports each scanner's own exit code, not a constant 0.

Why this file exists
--------------------
``WorkspaceAggregator`` rolls every project's scanners up into the unified file's
``scanner_results``. The entry wrote ``"exit_code": 0`` for every scanner beside a
``status`` that could say ``ERROR``, so a consumer reading the rollup saw a scanner
that failed with a clean exit.

The contract these cells pin:

- a scanner's row carries the code its own run recorded, taken from the same project
  row its ``status`` comes from, never from a second rollup;
- a scanner whose project row recorded no code (it produced no target report, so the
  row's ``exit_code`` stayed unset) reads 125, the incomplete-run member of the
  contract's judged codes, and never a default 0, unless its status is SKIPPED: that
  is a complete, operator-chosen outcome, and it reads the value its own row carries;
- across projects the worse status wins and brings its code; equal statuses keep the
  larger code; the order the projects arrive in does not matter;
- a recorded 0 beside a non-passing status is kept as recorded.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, Optional

import pytest

from automated_security_helper.models.asharp_model import ScannerTargetStatusInfo
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
)
from automated_security_helper.workspace.aggregation import (
    RESULTS_FILENAME,
    WorkspaceAggregator,
)
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    execute_workspace,
)
from tests.unit.workspace.test_execution import FakeOrchestrator, _make_workspace
from tests.unit.workspace.test_workspace_reporting import _plan

pytestmark = pytest.mark.unit

#: The code a scanner reads when its project row recorded none.
NO_CODE = 125


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    yield
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}


def _outcome(
    key: str,
    statuses: Dict[str, str],
    codes: Optional[Dict[str, int]] = None,
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
    outcome.carry_scanner_exit_codes(codes or {})
    return outcome


def _rollup(tmp_path: Path, *projects) -> Dict[str, dict]:
    """The ``scanner_results`` block ``write`` produces for these project rows."""
    keys = [key for key, _, _ in projects]
    plan = _plan(tmp_path / "ws", *keys)
    aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")
    for plan_project, (key, statuses, codes) in zip(plan.projects, projects):
        aggregator.add(_outcome(key, statuses, codes), None, plan_project)
    path = aggregator.write(exit_code=0, wall_clock_seconds=0.1)
    return json.loads(path.read_text("utf-8"))["scanner_results"]


def _result_with(**rows: ScannerTargetStatusInfo):
    return SimpleNamespace(scanner_results=dict(rows))


def _rollup_in_completion_order(
    tmp_path: Path, plan_keys, *completed
) -> Dict[str, dict]:
    """The rollup when projects finish in *completed* order, not plan order."""
    plan = _plan(tmp_path / "ws", *plan_keys)
    by_key = {project.key: project for project in plan.projects}
    aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")
    for key, statuses in completed:
        aggregator.add(_outcome(key, statuses), None, by_key[key])
    path = aggregator.write(exit_code=0, wall_clock_seconds=0.1)
    return json.loads(path.read_text("utf-8"))["scanner_results"]


@pytest.mark.parametrize(
    "completed",
    [
        pytest.param(
            (("web", {"bandit": "PASSED"}), ("api", {"Bandit": "PASSED"})),
            id="web-first",
        ),
        pytest.param(
            (("api", {"Bandit": "PASSED"}), ("web", {"bandit": "PASSED"})),
            id="api-first",
        ),
    ],
)
def test_the_published_row_is_named_by_the_plan_orders_spelling_whatever_finished_first(
    tmp_path, completed
):
    """Red at the base for the web-first order: the row took the spelling of the
    project that finished first, so a parallel run named it ``bandit`` one time
    and ``Bandit`` the next."""
    rolled = _rollup_in_completion_order(tmp_path, ("api", "web"), *completed)

    assert "Bandit" in rolled, sorted(rolled)
    assert "bandit" not in rolled
    assert rolled["Bandit"]["status"] == "PASSED"


@pytest.mark.parametrize(
    ("status", "recorded"),
    [
        pytest.param("PASSED", 0, id="passed-0"),
        pytest.param("FAILED", 1, id="failed-1"),
        pytest.param("FAILED", 2, id="failed-2"),
        pytest.param("ERROR", 127, id="error-127"),
        pytest.param("ERROR", 3, id="error-3"),
    ],
)
def test_a_scanner_rolls_up_the_code_its_run_recorded(tmp_path, status, recorded):
    rolled = _rollup(tmp_path, ("api", {"tool": status}, {"tool": recorded}))

    assert rolled["tool"]["status"] == status
    assert rolled["tool"]["exit_code"] == recorded


@pytest.mark.parametrize("status", ["MISSING", "ERROR", "PASSED"])
def test_a_scanner_whose_row_recorded_no_code_reads_125(tmp_path, status):
    rolled = _rollup(tmp_path, ("api", {"tool": status}, {}))

    assert rolled["tool"]["exit_code"] == NO_CODE


def test_a_skipped_scanner_with_no_code_reads_the_value_its_own_row_carries(tmp_path):
    """SKIPPED is a complete, operator-chosen outcome: not 125, not a made-up 0.

    The rolled-up entry and the scanner's own row are both read from the same dump
    here, so the cell cannot pass by agreeing with a constant.
    """
    from automated_security_helper.workspace.execution import _scanner_exit_codes

    row = ScannerTargetStatusInfo(
        status="SKIPPED", excluded=True, dependencies_satisfied=True
    )
    own = row.model_dump(by_alias=True, exclude_unset=True).get("exit_code")

    rolled = _rollup(
        tmp_path,
        (
            "api",
            {"tool": "SKIPPED"},
            _scanner_exit_codes(_result_with(tool=row)),
        ),
    )

    assert rolled["tool"]["exit_code"] == own
    assert rolled["tool"]["exit_code"] not in (NO_CODE, 0)
    assert rolled["tool"]["excluded"] is True


def test_a_missing_scanner_reads_125_and_is_marked_without_dependencies(tmp_path):
    rolled = _rollup(tmp_path, ("api", {"tool": "MISSING"}, {}))

    assert rolled["tool"]["exit_code"] == NO_CODE
    assert rolled["tool"]["dependencies_satisfied"] is False


def test_a_recorded_zero_beside_a_failing_status_is_kept(tmp_path):
    rolled = _rollup(tmp_path, ("api", {"tool": "FAILED"}, {"tool": 0}))

    assert rolled["tool"]["status"] == "FAILED"
    assert rolled["tool"]["exit_code"] == 0


def test_each_scanner_in_one_project_keeps_its_own_code(tmp_path):
    rolled = _rollup(
        tmp_path,
        (
            "api",
            {"ok": "PASSED", "bad": "FAILED", "broken": "ERROR", "absent": "MISSING"},
            {"ok": 0, "bad": 1, "broken": 127},
        ),
    )

    assert {name: row["exit_code"] for name, row in rolled.items()} == {
        "ok": 0,
        "bad": 1,
        "broken": 127,
        "absent": NO_CODE,
    }


@pytest.mark.parametrize("order", ["passing-first", "failing-first"])
def test_the_worse_status_brings_its_code_in_either_order(tmp_path, order):
    passing = ("api", {"tool": "PASSED"}, {"tool": 0})
    erroring = ("web", {"tool": "ERROR"}, {"tool": 127})
    projects = (passing, erroring) if order == "passing-first" else (erroring, passing)

    rolled = _rollup(tmp_path, *projects)

    assert rolled["tool"]["status"] == "ERROR"
    assert rolled["tool"]["exit_code"] == 127


@pytest.mark.parametrize("order", ["small-first", "large-first"])
def test_equal_statuses_keep_the_larger_code_in_either_order(tmp_path, order):
    small = ("api", {"tool": "FAILED"}, {"tool": 1})
    large = ("web", {"tool": "FAILED"}, {"tool": 2})
    projects = (small, large) if order == "small-first" else (large, small)

    rolled = _rollup(tmp_path, *projects)

    assert rolled["tool"]["status"] == "FAILED"
    assert rolled["tool"]["exit_code"] == 2


def test_the_unrecorded_code_of_a_worse_status_is_not_replaced_by_a_better_one(
    tmp_path,
):
    rolled = _rollup(
        tmp_path,
        ("api", {"tool": "MISSING"}, {}),
        ("web", {"tool": "PASSED"}, {"tool": 0}),
    )

    assert rolled["tool"]["status"] == "MISSING"
    assert rolled["tool"]["exit_code"] == NO_CODE


def test_a_project_row_with_a_recorded_code_gives_that_code():
    from automated_security_helper.workspace.execution import _scanner_exit_codes

    codes = _scanner_exit_codes(
        _result_with(tool=ScannerTargetStatusInfo(status="FAILED", exit_code=2))
    )

    assert codes == {"tool": 2}


def test_a_project_row_whose_code_was_never_set_gives_125():
    from automated_security_helper.workspace.execution import _scanner_exit_codes

    codes = _scanner_exit_codes(
        _result_with(tool=ScannerTargetStatusInfo(status="MISSING"))
    )

    assert codes == {"tool": NO_CODE}


def test_a_project_row_whose_code_is_none_gives_125():
    from automated_security_helper.workspace.execution import _scanner_exit_codes

    codes = _scanner_exit_codes(
        _result_with(tool=ScannerTargetStatusInfo(status="ERROR", exit_code=None))
    )

    assert codes == {"tool": NO_CODE}


def test_a_project_row_set_to_zero_explicitly_gives_zero():
    from automated_security_helper.workspace.execution import _scanner_exit_codes

    codes = _scanner_exit_codes(
        _result_with(tool=ScannerTargetStatusInfo(status="PASSED", exit_code=0))
    )

    assert codes == {"tool": 0}


def test_the_carrier_is_in_no_dump_of_the_project_result(tmp_path):
    """The codes travel in-process only: no second copy in every project block."""
    outcome = _outcome("api", {"tool": "FAILED"}, {"tool": 2})

    assert outcome.carried_scanner_exit_codes == {"tool": 2}
    assert "scanner_exit_codes" not in outcome.model_dump(mode="json")
    assert "scanner_exit_codes" not in outcome.model_dump()
    assert "scanner_exit_codes" not in WorkspaceProjectResult.model_fields


def test_the_schema_of_the_project_result_has_no_exit_code_carrier():
    """Byte-for-byte the schema file is the unit base's: the carrier is not in it."""
    schema = WorkspaceProjectResult.model_json_schema()
    shipped = json.loads(
        (
            Path(__file__).resolve().parents[3]
            / "automated_security_helper"
            / "schemas"
            / "AshAggregatedResults.json"
        ).read_text("utf-8")
    )

    assert "scanner_exit_codes" not in schema["properties"]
    assert "scanner_exit_codes" not in json.dumps(shipped)


def test_passing_the_codes_to_the_constructor_does_not_carry_them():
    outcome = WorkspaceProjectResult(
        project="api",
        relative_path="api",
        display_label="api",
        status=ProjectRunStatus.COMPLETED,
        severity_threshold="MEDIUM",
        output_path="projects/api",
        scanners={"tool": "FAILED"},
        scanner_exit_codes={"tool": 2},
    )

    assert outcome.carried_scanner_exit_codes == {}


def test_a_copied_project_result_still_carries_the_codes(tmp_path):
    outcome = _outcome("api", {"tool": "FAILED"}, {"tool": 2})

    assert outcome.model_copy().carried_scanner_exit_codes == {"tool": 2}
    assert copy.deepcopy(outcome).carried_scanner_exit_codes == {"tool": 2}


def test_the_unified_file_of_a_real_workspace_run_carries_each_scanners_code(tmp_path):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {
        "scanner_results": {
            "bandit": {"status": "FAILED", "exit_code": 1},
            "grype": {"status": "MISSING", "dependencies_satisfied": False},
            "semgrep": {"status": "PASSED", "exit_code": 0},
        }
    }

    result = execute_workspace(
        plan,
        ProjectScanSettings(
            output_dir=tmp_path / "out", phases=("scan",), max_parallel_projects=1
        ),
        orchestrator_factory=FakeOrchestrator.create,
    )

    rolled = json.loads(result.results_path.read_text("utf-8"))["scanner_results"]
    assert result.results_path.name == RESULTS_FILENAME
    assert {name: row["exit_code"] for name, row in rolled.items()} == {
        "bandit": 1,
        "grype": NO_CODE,
        "semgrep": 0,
    }
