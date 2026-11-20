# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The workspace surfaces read coverage the way a single scan's payload does.

* ``no_scanner_ran_for_project`` answers from ``scan_incompleteness``, as the
  workspace outcome does, so an ERROR scanner that audited some targets is not
  "no scanner ran" beside its own "N of M targets unevaluated" row.
* ``_project_coverage`` gives a ``FAILED (MISSING on some files)`` row the reason
  ``missing_dependencies``, the token ``ScanIncompleteness.to_payload`` gives it.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.cli.mcp.workspace import _project_coverage
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.unified_metrics import ScannerMetrics
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
)
from automated_security_helper.workspace.aggregation import (
    no_scanner_ran_for_project,
)

pytestmark = pytest.mark.unit

_MODULE = "automated_security_helper.interactions.run_ash_scan"


def _metric(status: str, *, attempted=None, failed=0) -> ScannerMetrics:
    return ScannerMetrics.model_construct(
        scanner_name="cdk-nag",
        status=status,
        actionable=0,
        targets_attempted=attempted,
        targets_failed=failed,
    )


@pytest.mark.parametrize(
    ("status", "attempted", "failed", "expected"),
    [
        # Evaluated 6 of 10 targets: it ran, so the workspace must not say otherwise.
        (ScannerStatus.ERROR.value, 10, 4, False),
        # Controls: lost every target, no counts, or only an ERROR with no audit.
        (ScannerStatus.ERROR.value, 10, 10, True),
        (ScannerStatus.ERROR.value, None, 0, True),
        (ScannerStatus.MISSING.value, 10, 4, True),
    ],
)
def test_the_project_set_level_answer_is_the_scan_payloads(
    status, attempted, failed, expected
):
    results = AshAggregatedResults()
    metric = _metric(status, attempted=attempted, failed=failed)

    with patch(f"{_MODULE}.get_unified_scanner_metrics", return_value=[metric]):
        single = ras.scan_incompleteness(results, gate=True).no_scanner_ran
        workspace = no_scanner_ran_for_project(results)

    assert single is expected
    assert workspace is single, (
        "the workspace layer and a single scan answered differently for the same "
        "results"
    )


def test_a_missing_tree_row_reads_one_reason_on_both_surfaces():
    row = ("tool-a", "FAILED (MISSING on some files)")
    single = ras.ScanIncompleteness(
        scanners=(row,),
        observed=(("tool-a", "FAILED"),),
        missing_dependencies=("tool-a",),
    ).to_payload()["incomplete_scanners"]
    outcome = WorkspaceProjectResult(
        project="app",
        relative_path="app",
        display_label="app",
        status=ProjectRunStatus.COMPLETED,
        severity_threshold="MEDIUM",
        output_path="projects/app",
        scanners={"tool-a": "FAILED"},
        incomplete_scanners=["tool-a"],
        incomplete_scanner_details={"tool-a": row[1]},
        scan_incomplete=True,
    )

    workspace = _project_coverage(outcome)["incomplete_scanners"]

    assert [r["reason"] for r in single] == ["missing_dependencies"]
    assert [r["reason"] for r in workspace] == [r["reason"] for r in single]


def test_a_partial_loss_row_still_reads_partial_coverage_in_the_workspace():
    # Control: without the MISSING annotation the reason stays partial_coverage.
    outcome = WorkspaceProjectResult(
        project="app",
        relative_path="app",
        display_label="app",
        status=ProjectRunStatus.COMPLETED,
        severity_threshold="MEDIUM",
        output_path="projects/app",
        scanners={"tool-a": "FAILED"},
        incomplete_scanners=["tool-a"],
        incomplete_scanner_details={"tool-a": "FAILED (4 of 10 targets unevaluated)"},
        partial_coverage_scanners=["tool-a"],
        scan_incomplete=True,
    )

    (row,) = _project_coverage(outcome)["incomplete_scanners"]

    assert row["reason"] == "partial_coverage"
