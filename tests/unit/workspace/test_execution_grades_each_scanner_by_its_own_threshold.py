# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace project's verdict grades each finding by its own scanner's threshold.

Why this file exists
--------------------
``_compute_exit_code`` resolves the threshold per result: a scanner with its own
``options.severity_threshold`` is judged by it, every other scanner by the global
one. The workspace verdict judged every finding of a project against the one
project-wide threshold, so a project whose config tightened or relaxed one scanner
got a different answer inside a workspace than ``ash --source-dir P`` gave it.
The per-scanner rollup in the unified file re-derived its counts the same way,
and over every finding of the run, so it also counted policy-origin findings the
project's own verdict excludes and exceeded the per-project totals it sums.

The contract these cases pin:

- the counter grades a finding by the threshold its scanner's name resolves to,
  falling back to the project-wide threshold for a scanner that has none;
- a project whose config gives one scanner a stricter threshold is judged by it
  inside a workspace;
- the unified ``scanner_results`` actionable counts sum what the projects'
  verdicts counted: a non-gating policy scanner's findings count zero there.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.models.workspace import WorkspaceExitCode
from automated_security_helper.workspace.aggregation import (
    actionable_results_by_scanner,
    count_actionable_results,
)
from tests.unit.workspace.test_execution import (
    FakeOrchestrator,
    _make_workspace,
    _run,
    _scanner,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    yield
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}


def _finding(scanner: str, severity: str = "HIGH") -> dict:
    return {
        "ruleId": f"{scanner}-rule",
        "level": "error",
        "message": {"text": "fixture"},
        "properties": {"scanner_name": scanner, "issue_severity": severity},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": "src/app.py"}}}
        ],
    }


def _sarif_of(*findings: dict) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "ASH"}},
                "results": list(findings),
                "invocations": [],
            }
        ],
    }


def test_the_counter_grades_each_finding_by_its_scanners_threshold():
    findings = [_finding("bandit"), _finding("semgrep"), _finding("semgrep")]

    def threshold_for(scanner):
        return "CRITICAL" if scanner == "bandit" else None

    by_scanner = actionable_results_by_scanner(
        findings, "MEDIUM", threshold_for=threshold_for
    )

    # bandit's HIGH is below its own CRITICAL gate; semgrep has no setting of its
    # own and is judged by the project's MEDIUM. Every scanner is a key.
    assert by_scanner == {"bandit": 0, "semgrep": 2}
    assert (
        count_actionable_results(findings, "MEDIUM", threshold_for=threshold_for) == 2
    )
    # Control: without a resolver, the project-wide threshold judges them all.
    assert count_actionable_results(findings, "MEDIUM") == 3


def test_a_scanner_with_its_own_stricter_threshold_is_judged_by_it(
    tmp_path, monkeypatch
):
    """`ash --source-dir P` with bandit at CRITICAL exits 0 on a HIGH; so must P here."""

    def threshold_info(_results, scanner_name):
        if scanner_name == "bandit":
            return "CRITICAL", "config"
        return "MEDIUM", "global"

    monkeypatch.setattr(
        ScannerStatisticsCalculator,
        "get_scanner_threshold_info",
        staticmethod(threshold_info),
    )
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {
        "sarif": _sarif_of(_finding("bandit"), _finding("semgrep")),
        "scanner_results": {
            "bandit": _scanner("PASSED"),
            "semgrep": _scanner("PASSED"),
        },
    }

    outcome = _run(tmp_path, plan)
    entry = outcome.payload.projects[0]

    # Only semgrep's HIGH is actionable under the project's MEDIUM; bandit's HIGH
    # is below the CRITICAL its own options set.
    assert entry.finding_count == 2
    assert entry.actionable_finding_count == 1
    assert outcome.exit_code == WorkspaceExitCode.ACTIONABLE_FINDINGS

    rollup = json.loads(outcome.results_path.read_text("utf-8"))["scanner_results"]
    assert rollup["bandit"]["actionable_finding_count"] == 0
    assert rollup["semgrep"]["actionable_finding_count"] == 1


def test_the_rollup_counts_what_the_verdict_counted_not_policy_origin_findings(
    tmp_path,
):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    # semgrep is a scanner only the workspace policy asked for, and the policy
    # does not gate: its findings are reported and decide nothing.
    plan.projects[0] = plan.projects[0].model_copy(
        update={"policy_scanners": ["semgrep"], "policy_scanners_gate": False}
    )
    FakeOrchestrator.behaviour["api"] = {
        "sarif": _sarif_of(_finding("bandit"), _finding("semgrep")),
        "scanner_results": {
            "bandit": _scanner("PASSED"),
            "semgrep": _scanner("PASSED"),
        },
    }

    outcome = _run(tmp_path, plan)
    entry = outcome.payload.projects[0]

    assert entry.finding_count == 2
    assert entry.policy_origin_finding_count == 1
    assert entry.actionable_finding_count == 1

    rollup = json.loads(outcome.results_path.read_text("utf-8"))["scanner_results"]
    # The per-scanner split sums to the project's own total.
    assert rollup["bandit"]["actionable_finding_count"] == 1
    assert rollup["semgrep"]["actionable_finding_count"] == 0
    assert rollup["semgrep"]["finding_count"] == 1
