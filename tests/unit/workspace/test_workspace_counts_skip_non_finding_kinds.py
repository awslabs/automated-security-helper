# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A project's finding counts leave out a result that states no finding.

The workspace verdict no longer counts a result of kind ``pass``, ``notApplicable``
or ``informational`` (``sarif_utils.NON_FINDING_KINDS``) as actionable. SARIF gives
such a result level ``none``, which ASH grades INFO, and the counts beside the
verdict still took it for one of the project's findings: the project's
``finding_count``, its ``policy_origin_finding_count``, and the per-scanner rollup of
the unified results that sums them. A project of one real finding and one rule that
was not evaluated read as two. A result states no finding when its kind is one of
those and nothing in it reports a problem: its level is ``none`` or not stated, and no
``issue_severity`` it declares is above INFO. One whose level reports a problem is a
finding, and the counts include it.

Every test with a non-finding kind has a control that changes the kind and nothing
else. A result that carries a suppression in effect stays out of the count, as it
always has.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from automated_security_helper.models.workspace import ProjectRunStatus
from automated_security_helper.utils.sarif_utils import NON_FINDING_KINDS
from tests.unit.workspace.test_execution import (
    FakeOrchestrator,
    _make_workspace,
    _run,
)

pytestmark = pytest.mark.unit

# Sorted, so every pytest-xdist worker collects the same ids in the same order.
NON_FINDING = sorted(NON_FINDING_KINDS)
# The kinds that assert a finding. A result that states no kind is a failing one.
FINDING = ["fail", "open", "review"]
ANY_FINDING = [pytest.param(None, id="absent"), *FINDING]


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    yield
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}


def _result(rule: str, kind: str | None, *, level: str, suppressed: bool = False):
    entry: dict[str, Any] = {
        "ruleId": rule,
        "level": level,
        "message": {"text": rule},
        "properties": {"scanner_name": "bandit"},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": "src/app.py"}}},
        ],
    }
    if kind is not None:
        entry["kind"] = kind
    if suppressed:
        entry["suppressions"] = [{"kind": "external"}]
    return entry


def _sarif(note_kind: str | None, *, suppressed: bool = False) -> dict[str, Any]:
    """One real finding of bandit, and a note of bandit's of *note_kind*."""
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "ASH"}},
                "results": [
                    _result("F1", None, level="error"),
                    _result("N1", note_kind, level="none", suppressed=suppressed),
                ],
                "invocations": [],
            }
        ],
    }


def _entry(outcome, key):
    return next(entry for entry in outcome.payload.projects if entry.project == key)


def _rollup(tmp_path) -> dict[str, int]:
    """Each scanner's finding count in the unified results file, as a consumer reads it."""
    written = json.loads(
        (tmp_path / "out" / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    return {
        name: (row or {}).get("finding_count", 0)
        for name, row in (written.get("scanner_results") or {}).items()
    }


# ---------------------------------------------------------------------------
# The project's own counts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_result_that_states_no_finding_is_not_one_of_the_projects_findings(
    tmp_path, kind
):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(kind)}

    entry = _entry(_run(tmp_path, plan), "api")

    assert entry.status is ProjectRunStatus.COMPLETED, entry.error
    assert entry.finding_count == 1


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_the_same_result_that_asserts_a_finding_is_one_of_them(tmp_path, kind):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(kind)}

    entry = _entry(_run(tmp_path, plan), "api")

    assert entry.status is ProjectRunStatus.COMPLETED, entry.error
    assert entry.finding_count == 2


@pytest.mark.parametrize("kind", NON_FINDING)
def test_the_policy_origin_count_leaves_out_a_result_that_states_no_finding(
    tmp_path, kind
):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    project = plan.projects[0]
    project.policy_scanners = ["bandit"]
    project.policy_scanners_gate = False
    FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(kind)}

    entry = _entry(_run(tmp_path, plan), "api")

    assert (entry.finding_count, entry.policy_origin_finding_count) == (1, 1)


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_the_policy_origin_count_keeps_the_same_result_when_it_asserts_a_finding(
    tmp_path, kind
):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    project = plan.projects[0]
    project.policy_scanners = ["bandit"]
    project.policy_scanners_gate = False
    FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(kind)}

    entry = _entry(_run(tmp_path, plan), "api")

    assert (entry.finding_count, entry.policy_origin_finding_count) == (2, 2)


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_suppressed_result_that_states_no_finding_stays_out_of_the_count(
    tmp_path, kind
):
    """Must-not-regress control: a suppression in effect has always left a result out.

    Green at the base too.
    """
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(kind, suppressed=True)}

    entry = _entry(_run(tmp_path, plan), "api")

    assert entry.finding_count == 1


# ---------------------------------------------------------------------------
# The per-scanner rollup of the unified results
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", NON_FINDING)
def test_the_rollup_does_not_credit_a_scanner_with_a_result_that_states_no_finding(
    tmp_path, kind
):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(kind)}

    entry = _entry(_run(tmp_path, plan), "api")

    rollup = _rollup(tmp_path)
    assert rollup["bandit"] == 1
    # The rollup sums what the per-project counts say.
    assert sum(rollup.values()) == entry.finding_count


@pytest.mark.parametrize("kind", ANY_FINDING)
def test_the_rollup_credits_the_scanner_with_the_same_result_when_it_asserts_a_finding(
    tmp_path, kind
):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(kind)}

    entry = _entry(_run(tmp_path, plan), "api")

    rollup = _rollup(tmp_path)
    assert rollup["bandit"] == 2
    assert sum(rollup.values()) == entry.finding_count


def _only_a_note(kind: str) -> dict[str, Any]:
    """The same SARIF with the real finding taken out: bandit's one result is a note."""
    sarif = _sarif(kind)
    sarif["runs"][0]["results"].pop(0)
    return sarif


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_scanner_with_only_such_results_is_credited_with_no_findings(tmp_path, kind):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {"sarif": _only_a_note(kind)}

    _run(tmp_path, plan)

    assert _rollup(tmp_path)["bandit"] == 0


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_scanner_with_only_such_results_still_has_its_row(tmp_path, kind):
    """Must-not-regress control: leaving a result out of a count leaves no scanner out.

    Green at the base too.
    """
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {"sarif": _only_a_note(kind)}

    _run(tmp_path, plan)

    assert "bandit" in _rollup(tmp_path)


# ---------------------------------------------------------------------------
# A result of such a kind whose level reports a problem
# ---------------------------------------------------------------------------


def _only_a_pair(kind: str) -> dict[str, Any]:
    """The same SARIF with the real finding taken out: bandit's one result is of *kind*
    at level warning."""
    sarif = _only_a_note(kind)
    sarif["runs"][0]["results"][0]["level"] = "warning"
    return sarif


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_result_whose_level_reports_a_problem_is_in_the_count(tmp_path, kind):
    """A result of a non-finding kind whose level reports a problem is a finding, so the
    project counts it."""
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {"sarif": _only_a_pair(kind)}

    entry = _entry(_run(tmp_path, plan), "api")

    assert entry.status is ProjectRunStatus.COMPLETED, entry.error
    assert entry.finding_count == 1
