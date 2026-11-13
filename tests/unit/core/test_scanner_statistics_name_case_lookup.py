# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner's per-target reports are found under either spelling of its name.

``extract_scanner_statistics`` unions scanner names case-insensitively and keeps
the first spelling met, scanner_results' before additional_reports'. Every
per-target read then looked the reports up by that spelling exactly, so with
"Bandit" recorded in scanner_results and the reports filed under "bandit" (a
merged or hand-written results file) the reports were never read: an ERROR
recorded only there, the dict counts, the durations and the target counters were
all lost, together with the row the union had dropped. The reports are now found
under the exact key or, failing that, the one key that folds to the name, and a
report's own ``scanner_name`` is matched the same way.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.core.unified_metrics import (
    get_unified_scanner_metrics,
    target_counts,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


def _model(recorded_as: str, filed_as: str, **fields) -> AshAggregatedResults:
    """A scanner recorded PASSED under *recorded_as* whose one source report, with
    *fields*, is filed under *filed_as* and names itself *filed_as*."""
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.scanner_results[recorded_as] = ScannerTargetStatusInfo(
        status=ScannerStatus.PASSED
    )
    report = {"scanner_name": filed_as, "target_type": "source", "status": "PASSED"}
    report.update(fields)
    model.additional_reports = {filed_as: {"source": report}}
    return model


class TestAReportFiledUnderAnotherCaseIsRead:
    def test_an_error_recorded_only_there_makes_the_row_error(self):
        model = _model("Bandit", "bandit", status="ERROR")

        stats = ScannerStatisticsCalculator.extract_scanner_statistics(model)
        (metrics,) = get_unified_scanner_metrics(model)

        assert list(stats) == ["Bandit"]
        assert stats["Bandit"]["error"] is True
        assert metrics.status == "ERROR"

    def test_the_target_counters_are_read(self):
        model = _model("Bandit", "bandit", targets_attempted=4, targets_failed=1)

        assert target_counts(model, "Bandit") == (4, 1)

    def test_the_duration_is_read(self):
        model = _model("Bandit", "bandit", duration=2.5)

        stats = ScannerStatisticsCalculator.extract_scanner_statistics(model)

        assert stats["Bandit"]["duration"] == 2.5

    def test_the_same_spelling_is_read_as_before(self):
        """Control."""
        model = _model("bandit", "bandit", status="ERROR")

        stats = ScannerStatisticsCalculator.extract_scanner_statistics(model)

        assert list(stats) == ["bandit"]
        assert stats["bandit"]["error"] is True


class TestTheExactKeyWins:
    def test_the_exact_key_is_read_over_a_folded_one(self):
        model = _model("Bandit", "Bandit", status="ERROR")
        model.additional_reports["bandit"] = {
            "source": {
                "scanner_name": "bandit",
                "target_type": "source",
                "status": "PASSED",
            }
        }

        reports = ScannerStatisticsCalculator.reports_for(model, "Bandit")

        assert reports is model.additional_reports["Bandit"]

    def test_a_name_with_no_report_under_any_case_reads_none(self):
        model = _model("Bandit", "bandit")

        assert ScannerStatisticsCalculator.reports_for(model, "semgrep") is None


class TestEveryReadFollowsTheFoldedKey:
    """The module docstring says the dict counts were lost under a folded key too,
    and ``reports_for`` lists MISSING among what it serves; neither was pinned
    under a folded key, nor was the graded level the FAILED-to-PASSED flip reads."""

    def test_dict_counts_under_a_folded_key_feed_the_row(self):
        model = _model(
            "Bandit",
            "bandit",
            raw_results={"findings": []},
            severity_counts={"high": 1},
        )

        stats = ScannerStatisticsCalculator.extract_scanner_statistics(model)
        (metrics,) = get_unified_scanner_metrics(model)

        assert stats["Bandit"]["high"] == 1
        assert metrics.high == 1
        assert metrics.status == "FAILED"

    def test_a_missing_report_under_a_folded_key_marks_the_dependencies(self):
        model = _model("Bandit", "bandit", status="MISSING")

        stats = ScannerStatisticsCalculator.extract_scanner_statistics(model)

        assert stats["Bandit"]["dependencies_missing"] is True

    def test_a_graded_level_under_a_folded_key_is_the_scanners(self):
        """The recorded level is read under the folded key, and grades the
        threshold when the record holds it as an environment reference (a literal
        threshold in the record is graded as written)."""
        model = _model("Bandit", "bandit", scanner_severity_threshold="HIGH")

        assert ScannerStatisticsCalculator.graded_level_recorded(model, "Bandit")
        with patch.object(
            type(model.ash_config),
            "get_plugin_config",
            return_value={"options": {"severity_threshold": "${ASH_U18_LEVEL}"}},
        ):
            threshold, _source = ScannerStatisticsCalculator.get_scanner_threshold_info(
                model, "Bandit"
            )
        assert threshold == "HIGH"
