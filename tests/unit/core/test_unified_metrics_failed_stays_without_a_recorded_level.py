# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A recorded FAILED flips to PASSED only when the reports record the graded level.

``get_unified_scanner_metrics`` reads a recorded FAILED row as PASSED when nothing is
actionable, because the row can carry a FAILED from an earlier rebuild whose
findings a later run dropped. The finding counts it reads are re-graded at whatever
threshold the configuration record resolves to now. A results file written before
the executor recorded the graded level on each report (``scanner_severity_threshold``)
gives the read-back nothing to grade with but that record, so a scan that failed at
LOW through an environment-read threshold read as 0 actionable at MEDIUM, its row
flipped PASSED, and ``_populate_scanner_results_from_unified_metrics`` wrote PASSED
over the scan's own graded status.

The flip now also needs the reports to record the level they were graded against.
The controls: a report that records the level keeps the flip, and a recorded LOW
grades the LOW finding actionable, so the row stays FAILED on the counts alone.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.unified_metrics import get_unified_scanner_metrics
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

SCANNER = "shape-tool"


def _report(recorded_level: str | None) -> dict:
    """A dict-result target report with one LOW finding, graded at *recorded_level*
    (None: a report written before the level was recorded)."""
    counts = {
        "suppressed": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 1,
        "info": 0,
    }
    report = {
        "scanner_name": SCANNER,
        "target_type": "source",
        "status": "FAILED",
        "finding_count": 1,
        "severity_counts": counts,
        "raw_results": {"severity_counts": counts},
    }
    if recorded_level is not None:
        report["scanner_severity_threshold"] = recorded_level
    return report


def _model(recorded_level: str | None) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.ash_config.global_settings.severity_threshold = "MEDIUM"
    model.scanner_results = {
        SCANNER: ScannerTargetStatusInfo(status=ScannerStatus.FAILED)
    }
    model.additional_reports = {SCANNER: {"source": _report(recorded_level)}}
    return model


def _status(model: AshAggregatedResults) -> str:
    (metrics,) = [
        m for m in get_unified_scanner_metrics(model) if m.scanner_name == SCANNER
    ]
    return metrics.status


class TestARecordedFailedStaysWithoutARecordedLevel:
    def test_a_report_with_no_recorded_level_keeps_the_rows_failed(self):
        assert _status(_model(recorded_level=None)) == "FAILED"

    def test_control_a_report_that_records_the_level_still_flips(self):
        """The LOW finding is nothing actionable at the recorded MEDIUM, and the
        record says MEDIUM is what graded it, so the row's FAILED is stale."""
        assert _status(_model(recorded_level="MEDIUM")) == "PASSED"

    def test_control_a_recorded_low_grades_the_finding_actionable(self):
        assert _status(_model(recorded_level="LOW")) == "FAILED"
