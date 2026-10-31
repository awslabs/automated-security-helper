# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The workspace counts read a suppression's state, as every other reader does.

A SARIF suppression whose ``state`` is ``rejected`` or ``underReview`` has not
taken effect (SARIF 3.35.4). The flat finding's ``is_suppressed``, the OCSF
record's status and the per-scanner counts all read a result's suppressions
through ``sarif_utils.suppressions_in_effect``; the workspace aggregation read
any non-empty list as suppressed, so a finding whose only suppression awaited
review was left out of a project's finding and actionable counts and of the
``--min-severity`` gate while the reports showed it as active.
"""

from __future__ import annotations

import pytest

from automated_security_helper.workspace.aggregation import (
    actionable_results_by_scanner,
    count_actionable_results,
    has_finding_at_min_severity,
    result_is_suppressed,
)
from tests.unit.workspace.test_execution import (
    FakeOrchestrator,
    _make_workspace,
    _run,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    yield
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}


def _finding(state) -> dict:
    suppression = {"kind": "external"}
    if state is not None:
        suppression["state"] = state
    return {
        "ruleId": "R0",
        "level": "error",
        "message": {"text": "fixture"},
        "properties": {"scanner_name": "bandit", "issue_severity": "HIGH"},
        "suppressions": [suppression],
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": "src/app.py"}}}
        ],
    }


@pytest.mark.parametrize("state", ["rejected", "underReview"])
def test_a_suppression_not_in_effect_leaves_the_finding_active(state):
    findings = [_finding(state)]

    # RED at the base: any non-empty suppressions list read as suppressed.
    assert result_is_suppressed(findings[0]) is False
    assert actionable_results_by_scanner(findings, "MEDIUM") == {"bandit": 1}
    assert count_actionable_results(findings, "MEDIUM") == 1
    assert has_finding_at_min_severity(findings, "high") is True


@pytest.mark.parametrize("state", [None, "accepted"])
def test_an_accepted_or_stateless_suppression_hides_the_finding(state):
    """Control: the readings that already agreed stay as they were."""
    findings = [_finding(state)]

    assert result_is_suppressed(findings[0]) is True
    assert actionable_results_by_scanner(findings, "MEDIUM") == {"bandit": 0}
    assert count_actionable_results(findings, "MEDIUM") == 0
    assert has_finding_at_min_severity(findings, "high") is False


def test_a_project_counts_a_finding_whose_suppression_awaits_review(tmp_path):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {
        "sarif": {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "ASH"}},
                    "results": [_finding("underReview")],
                    "invocations": [],
                }
            ],
        }
    }

    outcome = _run(tmp_path, plan)
    entry = outcome.payload.projects[0]

    # RED at the base: finding_count 0 and actionable_finding_count 0, the
    # rollup's bandit row at 0 too, for a finding every report showed as active.
    assert entry.finding_count == 1
    assert entry.actionable_finding_count == 1
    assert entry.exceeds_threshold is True
