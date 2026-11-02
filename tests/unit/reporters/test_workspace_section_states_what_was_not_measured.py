# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The workspace project table states what a project did not measure.

* A project's label already holds its key when two projects share a label
  (``svc (apps-a)``), and the table appended the key again.
* A project that was never scanned has no counts. Its zeros read as a clean
  scan, so its Findings and Actionable columns read ``n/a``.
* Partial coverage, a project in which no scanner ran, and the inputs a scanner
  did not scan are named in the row's detail; none of them is in a count.
* The Result column carries the status class the report stylesheet styles, and a
  skip that is an error is styled as the failure the workspace exit code counts.
"""

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.workspace import (
    ProjectInputNotScanned,
    ProjectRunStatus,
    SkippedProjectReason,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_section import (
    html_workspace_section,
    workspace_project_rows,
)

pytestmark = pytest.mark.unit


def _project(key: str, **overrides) -> WorkspaceProjectResult:
    fields = {
        "project": key,
        "relative_path": key,
        "display_label": key,
        "status": ProjectRunStatus.COMPLETED,
        "severity_threshold": "MEDIUM",
        "output_path": f"projects/{key}",
    }
    fields.update(overrides)
    return WorkspaceProjectResult(**fields)


def _model(*projects: WorkspaceProjectResult) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.workspace = WorkspaceResults(
        workspace_file="/w/.ash-workspace.yaml",
        workspace_root="/w",
        exit_code=0,
        projects=list(projects),
    )
    return model


def _row(model: AshAggregatedResults, key: str) -> dict:
    return next(row for row in workspace_project_rows(model) if row["key"] == key)


class TestALabelThatHoldsItsKeyIsNotGivenItTwice:
    def test_a_disambiguated_label_is_shown_as_it_is(self):
        row = _row(_model(_project("apps-a", display_label="svc (apps-a)")), "apps-a")
        assert row["project"] == "svc (apps-a)"

    def test_a_plain_label_gets_its_key(self):
        row = _row(_model(_project("apps-a", display_label="svc")), "apps-a")
        assert row["project"] == "svc (apps-a)"

    def test_a_label_equal_to_the_key_is_shown_once(self):
        row = _row(_model(_project("apps-a")), "apps-a")
        assert row["project"] == "apps-a"


class TestAProjectNeverScannedHasNoCounts:
    @pytest.mark.parametrize(
        "overrides",
        [
            {"status": ProjectRunStatus.FAILED, "error": "scanner crashed"},
            {
                "status": ProjectRunStatus.SKIPPED,
                "skip_reason": SkippedProjectReason.NO_CHANGES,
            },
            {
                "status": ProjectRunStatus.SKIPPED,
                "skip_reason": SkippedProjectReason.ERROR,
                "skip_detail": "no such directory",
            },
        ],
        ids=["failed", "skipped-no-changes", "skipped-error"],
    )
    def test_the_counts_read_not_available(self, overrides):
        row = _row(_model(_project("svc", severity_threshold=None, **overrides)), "svc")
        assert row["findings"] == "n/a", row
        assert row["actionable"] == "n/a", row

    def test_a_scanned_project_keeps_its_counts(self):
        row = _row(
            _model(_project("svc", finding_count=4, actionable_finding_count=2)),
            "svc",
        )
        assert row["findings"] == 4, row
        assert row["actionable"] == 2, row


class TestTheDetailNamesWhatWasNotMeasured:
    def test_partial_coverage_is_named(self):
        row = _row(
            _model(_project("svc", partial_coverage_scanners=["bandit", "semgrep"])),
            "svc",
        )
        assert "partial coverage: bandit, semgrep" in row["detail"], row

    def test_a_project_in_which_no_scanner_ran_says_so(self):
        row = _row(_model(_project("svc", no_scanner_ran=True)), "svc")
        assert "no scanner ran" in row["detail"], row

    def test_inputs_not_scanned_are_named(self):
        row = _row(
            _model(
                _project(
                    "svc",
                    inputs_not_scanned=[
                        ProjectInputNotScanned(
                            scanner="npm-audit",
                            path="svc/package-lock.json",
                            reason="offline",
                        )
                    ],
                )
            ),
            "svc",
        )
        assert (
            "inputs not scanned: npm-audit: 'svc/package-lock.json' (offline)"
            in row["detail"]
        ), row

    def test_a_long_list_of_inputs_is_cut_with_a_count(self):
        inputs = [
            ProjectInputNotScanned(
                scanner="npm-audit", path=f"svc/lock-{index}.json", reason="offline"
            )
            for index in range(30)
        ]
        row = _row(_model(_project("svc", inputs_not_scanned=inputs)), "svc")
        assert " more" in row["detail"], row
        assert "lock-29.json" not in row["detail"], row

    def test_a_clean_project_has_no_detail(self):
        assert _row(_model(_project("svc")), "svc")["detail"] == ""


class TestTheResultColumnIsStyled:
    @pytest.mark.parametrize(
        "overrides, state",
        [
            ({"exceeds_threshold": True}, "failed"),
            ({}, "passed"),
            (
                {
                    "status": ProjectRunStatus.SKIPPED,
                    "skip_reason": SkippedProjectReason.NO_CHANGES,
                },
                "skipped",
            ),
            (
                {
                    "status": ProjectRunStatus.SKIPPED,
                    "skip_reason": SkippedProjectReason.ERROR,
                },
                "failed",
            ),
        ],
        ids=["over-threshold", "clean", "skipped-no-changes", "skipped-error"],
    )
    def test_the_row_and_the_result_carry_the_state(self, overrides, state):
        model = _model(_project("svc", severity_threshold="MEDIUM", **overrides))

        assert _row(model, "svc")["state"] == state
        fragment = html_workspace_section(model)
        assert f'<tr class="{state}">' in fragment, fragment
        assert f'class="status-{state}"' in fragment, fragment
