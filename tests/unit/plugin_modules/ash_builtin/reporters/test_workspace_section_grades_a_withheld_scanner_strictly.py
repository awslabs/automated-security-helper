# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The merged reporters grade a scanner with a withheld threshold by the strictest gate.

``withheld_scanner_thresholds`` names the scanners whose own threshold the scan
read from an environment variable and did not publish. The per-scanner gate table
the JUnit reporter reads left them out, so their findings were graded by the
project's gate, which may be looser than the withheld value. They are now listed
at the strictest gate, so the merged report cannot call a finding below threshold
that the project's own count included.
"""

from __future__ import annotations

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_section import (
    workspace_project_scanner_thresholds,
)

pytestmark = pytest.mark.unit


def _model(tmp_path, *projects: WorkspaceProjectResult) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.workspace = WorkspaceResults(
        workspace_file=(tmp_path / "fixture.code-workspace").as_posix(),
        workspace_root=tmp_path.as_posix(),
        exit_code=0,
        projects=list(projects),
    )
    return model


def _project(key: str, **fields) -> WorkspaceProjectResult:
    return WorkspaceProjectResult(
        project=key,
        relative_path=key,
        display_label=key,
        status=ProjectRunStatus.COMPLETED,
        severity_threshold="HIGH",
        output_path=f"projects/{key}",
        **fields,
    )


class TestTheScannerGateTableNamesAWithheldScanner:
    def test_a_withheld_scanner_is_listed_at_the_strictest_gate(self, tmp_path):
        model = _model(
            tmp_path,
            _project("api", withheld_scanner_thresholds=["bandit"]),
            _project("web"),
        )

        # RED at the base: the table was empty, so the reporter fell back to the
        # project's HIGH gate for bandit.
        assert workspace_project_scanner_thresholds(model) == {"api": {"bandit": "ALL"}}

    def test_a_recorded_threshold_and_a_withheld_one_sit_side_by_side(self, tmp_path):
        model = _model(
            tmp_path,
            _project(
                "api",
                scanner_thresholds={"semgrep": "critical"},
                withheld_scanner_thresholds=["bandit"],
            ),
        )

        assert workspace_project_scanner_thresholds(model) == {
            "api": {"semgrep": "CRITICAL", "bandit": "ALL"}
        }

    def test_a_project_that_withheld_nothing_is_unchanged(self, tmp_path):
        """Control, green on both sides."""
        model = _model(
            tmp_path,
            _project("api", scanner_thresholds={"bandit": "CRITICAL"}),
        )

        assert workspace_project_scanner_thresholds(model) == {
            "api": {"bandit": "CRITICAL"}
        }
