# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A project's workspace verdict counts the SARIF report its scan wrote.

Why this file exists
--------------------
``_compute_exit_code`` counts a single scan's actionable findings from the SARIF
report the scan's own SARIF reporter wrote this run, because that reporter
serializes every suppression where the in-memory model's ``result.suppressions``
is not reliably set. The workspace counted from the in-memory model, so a project
whose findings were all suppressed in the written report could be recorded
FAILED with three actionable findings inside a workspace while ``ash --source-dir
P`` exited 0 on the same tree.

The contract these cases pin:

- a project whose scan recorded a SARIF report has its counts read from that
  file, and the run carried into the unified file is that file's results;
- a ``reports/ash.sarif`` the scan did not record (an earlier run's file) is not
  read; nor is one reached through a link;
- the policy-origin exclusion holds when the counts come from the file, because
  the file was written before the model was tagged.
"""

from __future__ import annotations

import json
import os

import pytest

from automated_security_helper.models.workspace import ProjectRunStatus
from tests.unit.workspace.test_execution import (
    FakeOrchestrator,
    _make_workspace,
    _run,
    _sarif,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    yield
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}


def _entry(outcome, key):
    return next(entry for entry in outcome.payload.projects if entry.project == key)


def test_the_counts_come_from_the_written_sarif_when_the_scan_recorded_one(tmp_path):
    """Three findings the model holds unsuppressed, suppressed in the written report."""
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {
        "sarif": _sarif(level="error", count=3),
        "written_sarif": _sarif(level="error", count=3, suppressed=True),
    }

    outcome = _run(tmp_path, plan)

    entry = _entry(outcome, "api")
    assert entry.status is ProjectRunStatus.COMPLETED, entry.error
    assert entry.finding_count == 0, (
        "the verdict counted the model's unsuppressed findings, not the written "
        "report's suppressed ones"
    )
    assert entry.actionable_finding_count == 0
    assert entry.exceeds_threshold is False
    parsed = json.loads(outcome.results_path.read_text(encoding="utf-8"))
    carried = [result for run in parsed["sarif"]["runs"] for result in run["results"]]
    assert len(carried) == 3
    assert all(result.get("suppressions") for result in carried), (
        "the unified file carries the model's results, which disagree with the "
        "counts read from the written report"
    )


def test_a_report_the_scan_did_not_record_is_not_read(tmp_path):
    """Must-not-flag control: an earlier run's file at the same name counts nothing."""
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(level="error", count=3)}
    reports = tmp_path / "out" / "projects" / "api" / "reports"
    reports.mkdir(parents=True)
    (reports / "ash.sarif").write_text(
        json.dumps(_sarif(level="error", count=3, suppressed=True)), encoding="utf-8"
    )

    outcome = _run(tmp_path, plan)

    entry = _entry(outcome, "api")
    assert entry.finding_count == 3
    assert entry.actionable_finding_count == 3
    assert entry.exceeds_threshold is True


@pytest.mark.skipif(
    not hasattr(os, "symlink"), reason="the platform cannot make a symlink"
)
def test_a_report_reached_through_a_link_is_not_read(tmp_path, caplog):
    """A link at the recorded name is refused, and the log names it."""
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    elsewhere = tmp_path / "elsewhere.sarif"
    elsewhere.write_text(
        json.dumps(_sarif(level="error", count=3, suppressed=True)), encoding="utf-8"
    )
    reports = tmp_path / "out" / "projects" / "api" / "reports"
    reports.mkdir(parents=True)
    try:
        os.symlink(elsewhere, reports / "ash.sarif")
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"cannot make a symlink here: {error}")
    # The fake writes through the link (a real reporter refuses; this test is about
    # the read), so the model records the name while the path is a link.
    FakeOrchestrator.behaviour["api"] = {
        "sarif": _sarif(level="error", count=3),
        "written_sarif": _sarif(level="error", count=3, suppressed=True),
    }

    outcome = _run(tmp_path, plan)

    entry = _entry(outcome, "api")
    assert entry.finding_count == 3, entry
    assert entry.actionable_finding_count == 3
    assert "is a symlink" in caplog.text, caplog.text


def test_the_policy_origin_exclusion_holds_for_counts_read_from_the_file(tmp_path):
    """Must-not-regress control for the re-tagging of the file's entries.

    Green at the base too, where the counts come from the already tagged model;
    at the tip the entries are the file's, written before the tag, and must be
    tagged the same way or the gate-off exclusion silently stops excluding.
    """
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    project = plan.projects[0]
    project.policy_scanners = ["bandit"]
    project.policy_scanners_gate = False
    FakeOrchestrator.behaviour["api"] = {
        "sarif": _sarif(level="error", count=3),
        "written_sarif": _sarif(level="error", count=3),
    }

    outcome = _run(tmp_path, plan)

    entry = _entry(outcome, "api")
    assert entry.finding_count == 3
    assert entry.policy_origin_finding_count == 3
    assert entry.actionable_finding_count == 0, (
        "a finding of a scanner only the policy added gated the project with the "
        "gate off"
    )
    assert entry.exceeds_threshold is False
