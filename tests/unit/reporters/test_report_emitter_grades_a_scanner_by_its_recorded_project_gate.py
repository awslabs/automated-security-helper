# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The HTML, Markdown and Text emitter grades a project's scanner by that scanner's gate.

A workspace file records, per project, the gate each scanner was judged by
(``scanner_thresholds``) and the scanners whose own threshold the scan read from
an environment variable and did not publish (``withheld_scanner_thresholds``,
graded at the strictest gate). The merged JUnit report and the actionable view
read that table before the project's gate. The emitter behind the HTML,
Markdown and Text reports read the project's gate alone, so one finding was
actionable in two reports and "Below threshold" in the third.
"""

from __future__ import annotations

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)

pytestmark = pytest.mark.unit


def _model(tmp_path, **project_fields) -> AshAggregatedResults:
    """One project, gated at HIGH, carrying the named scanner gate fields."""
    model = AshAggregatedResults()
    model.ash_config = None
    model.workspace = WorkspaceResults(
        workspace_file=(tmp_path / "fixture.code-workspace").as_posix(),
        workspace_root=tmp_path.as_posix(),
        exit_code=0,
        projects=[
            WorkspaceProjectResult(
                project="api",
                relative_path="api",
                display_label="api",
                status=ProjectRunStatus.COMPLETED,
                severity_threshold="HIGH",
                output_path="projects/api",
                **project_fields,
            )
        ],
    )
    return model


def _finding(scanner: str, severity: str) -> FlatVulnerability:
    return FlatVulnerability(
        id=f"{scanner}-{severity}",
        title="a finding",
        description="",
        severity=severity,
        scanner=scanner,
        scanner_type="SAST",
        workspace_project="api",
    )


class TestAnEmitterGradesAScannerByItsRecordedGate:
    def test_a_withheld_scanner_s_low_finding_is_actionable_under_a_high_gate(
        self, tmp_path
    ):
        """RED at the base: the emitter read the project's HIGH gate alone, so
        the LOW finding the project's own count included read "Below threshold"
        while the actionable view and the merged JUnit report listed it."""
        emitter = ReportContentEmitter(
            _model(tmp_path, withheld_scanner_thresholds=["bandit"])
        )

        assert emitter.is_finding_actionable(_finding("bandit", "LOW"))

    def test_a_scanner_that_withheld_nothing_keeps_the_project_gate(self, tmp_path):
        """Control, green on both sides: a scanner the table does not name is
        graded by the project's HIGH gate."""
        emitter = ReportContentEmitter(
            _model(tmp_path, withheld_scanner_thresholds=["bandit"])
        )

        assert not emitter.is_finding_actionable(_finding("semgrep", "LOW"))
        assert emitter.is_finding_actionable(_finding("semgrep", "HIGH"))

    def test_a_relaxed_recorded_scanner_gate_wins_over_the_project_gate(
        self, tmp_path
    ):
        """RED at the base: bandit was recorded at CRITICAL, so its HIGH finding
        was not part of the project's count, yet the emitter graded it by the
        project's HIGH gate and called it actionable."""
        emitter = ReportContentEmitter(
            _model(tmp_path, scanner_thresholds={"bandit": "CRITICAL"})
        )

        assert not emitter.is_finding_actionable(_finding("bandit", "HIGH"))
        assert emitter.is_finding_actionable(_finding("bandit", "CRITICAL"))

    def test_a_single_directory_finding_is_unchanged(self):
        """Control, green on both sides: with no workspace there is no table."""
        emitter = ReportContentEmitter(AshAggregatedResults())

        assert not emitter.is_finding_actionable(
            FlatVulnerability(
                id="x",
                title="a finding",
                description="",
                severity="INFO",
                scanner="bandit",
                scanner_type="SAST",
            )
        )
