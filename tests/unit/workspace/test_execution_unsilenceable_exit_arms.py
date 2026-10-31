# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace project fails on the two exit-1 arms no setting silences in a single scan.

Why this file exists
--------------------
``_compute_exit_code`` returns 1 for a rule a scanner could not evaluate and for a
scanner tool ASH could not stop, with the completeness gate on or off: the first
means the scan reports nothing about compliance with that rule, the second means
the tool may still be writing into the output directory after the verdict read
it. The workspace layer read both facts into its ``scan_incompleteness`` object
and then dropped them: ``WorkspaceProjectResult`` had no field for either, and
the ``scan_incomplete`` fold read only the gated arms and the stale-database arm.
So ``ash --source-dir P`` exited 1 where the same P inside a workspace exited 0,
or 2 when it also had findings.

The contract these cases pin:

- an error-level run notification naming a rule puts that rule in
  ``unevaluated_rules`` and fails the project, with the gate off;
- a per-target report recording ``could_not_stop`` puts its scanner and reason in
  ``unstoppable_tools`` and fails the project, with the gate off;
- a clean project with the gate off still passes, so the two arms, and not the
  gate, are what moved the verdict.
"""

from __future__ import annotations

import pytest

from automated_security_helper.models.workspace import WorkspaceExitCode
from tests.unit.workspace.test_execution import (
    FakeOrchestrator,
    _make_workspace,
    _run,
    _sarif,
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


def _sarif_with_an_unevaluated_rule(rule_id: str) -> dict:
    """A clean SARIF whose run says, at run level, that *rule_id* raised."""
    sarif = _sarif(count=0)
    sarif["runs"][0]["invocations"] = [
        {
            "executionSuccessful": True,
            "toolExecutionNotifications": [
                {
                    "level": "error",
                    "message": {"text": f"{rule_id} could not be evaluated"},
                    "associatedRule": {"id": rule_id},
                }
            ],
        }
    ]
    return sarif


def test_an_unevaluated_rule_fails_the_project_with_the_gate_off(tmp_path):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {
        "sarif": _sarif_with_an_unevaluated_rule("AwsSolutions-S1"),
        "scanner_results": {"cdk-nag": _scanner("PASSED")},
    }

    outcome = _run(tmp_path, plan, fail_on_incomplete_scanners=False)
    entry = outcome.payload.projects[0]

    # Control: nothing else can move this verdict. No findings, every scanner
    # ran, and the completeness gate is off.
    assert entry.actionable_finding_count == 0
    assert entry.incomplete_scanners == []
    assert entry.no_scanner_ran is False

    assert entry.unevaluated_rules == ["AwsSolutions-S1"]
    assert entry.scan_incomplete is True
    assert outcome.exit_code == WorkspaceExitCode.INTERNAL_ERROR


def test_a_tool_ash_could_not_stop_fails_the_project_with_the_gate_off(tmp_path):
    reason = "bandit's tool was still running after the stop and was left running"
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {
        "sarif": _sarif(count=0),
        "scanner_results": {"bandit": _scanner("PASSED")},
        "additional_reports": {"bandit": {"source": {"could_not_stop": reason}}},
    }

    outcome = _run(tmp_path, plan, fail_on_incomplete_scanners=False)
    entry = outcome.payload.projects[0]

    assert entry.actionable_finding_count == 0
    assert entry.incomplete_scanners == []

    assert entry.unstoppable_tools == {"bandit": reason}
    assert entry.scan_incomplete is True
    assert outcome.exit_code == WorkspaceExitCode.INTERNAL_ERROR


def test_a_clean_project_with_the_gate_off_still_passes(tmp_path):
    """The two arms are what moved the verdicts above, not the gate setting."""
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {
        "sarif": _sarif(count=0),
        "scanner_results": {"bandit": _scanner("PASSED")},
    }

    outcome = _run(tmp_path, plan, fail_on_incomplete_scanners=False)
    entry = outcome.payload.projects[0]

    assert entry.unevaluated_rules == []
    assert entry.unstoppable_tools == {}
    assert entry.scan_incomplete is False
    assert outcome.exit_code == WorkspaceExitCode.SUCCESS
