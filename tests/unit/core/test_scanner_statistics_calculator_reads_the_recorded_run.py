# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ScannerStatisticsCalculator reads what the run recorded, and only that.

- A scanner that recorded no duration has none (None, rendered N/A), not 0.0,
  whether or not it ran: a never-started ERROR row, an excluded one, and a run
  whose report holds a null or a non-number all read None.
- The legacy two-target row's durations are read off dicts and objects alike,
  and a None duration is not float()ed.
- The scanner name falls back to ``scanner_details.tool_name`` when the details
  are the dict attach_scanner_details stores.
- A suppression a reviewer rejected, or one under review, does not hide a result.
- A recorded ERROR row is not explained away by one tree's partial loss when
  another tree's run raised.
- The per-target walks read only this scanner's own reports: one naming another
  scanner is not read; one naming no scanner is read for the key it is filed
  under (its duration, counters and ERROR), but gives no status.
- get_scanner_status grades unusable counters ERROR, as the unified metrics do.
- The scanner-level report is found under the Python None key too.
- A scanner recorded only under a converted-tree report reads that report.
"""

from __future__ import annotations

import math
from types import SimpleNamespace

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.core.unified_metrics import (
    format_duration,
    get_unified_scanner_metrics,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Suppression,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


def _model(additional_reports=None, with_config=True) -> AshAggregatedResults:
    model = AshAggregatedResults()
    if with_config:
        model.ash_config = get_default_config()
    if additional_reports is not None:
        model.additional_reports = additional_reports
    return model


def _report(scanner_name: str, target: str = "source", **fields) -> dict:
    report = {"scanner_name": scanner_name, "target_type": target, "status": "PASSED"}
    report.update(fields)
    return report


def _result(scanner_name=None, suppressions=None, scanner_details=None) -> Result:
    properties = {}
    if scanner_name is not None:
        properties["scanner_name"] = scanner_name
    if scanner_details is not None:
        properties["scanner_details"] = scanner_details
    return Result(
        ruleId="R1",
        level="error",
        message=Message(text="x"),
        properties=PropertyBag(**properties),
        suppressions=suppressions,
    )


def _sarif(*results: Result) -> SarifReport:
    return SarifReport(
        runs=[Run(tool=Tool(driver=ToolComponent(name="tool")), results=list(results))]
    )


class TestDuration:
    def test_a_scanner_that_did_not_run_has_no_duration(self):
        model = _model({"grype": {"None": _report("grype", None, status="MISSING")}})
        model.scanner_results["grype"] = ScannerTargetStatusInfo(
            status=ScannerStatus.MISSING, dependencies_satisfied=False
        )

        stats = ScannerStatisticsCalculator.extract_scanner_statistics(model)

        assert stats["grype"]["duration"] is None
        (metrics,) = get_unified_scanner_metrics(model)
        assert format_duration(metrics.duration) == "N/A"

    def test_a_recorded_duration_is_summed_over_the_targets(self):
        model = _model(
            {
                "bandit": {
                    "source": _report("bandit", duration=1.5),
                    "converted": _report("bandit", "converted", duration=0.5),
                }
            }
        )

        stats = ScannerStatisticsCalculator.extract_scanner_statistics(model)

        assert stats["bandit"]["duration"] == 2.0

    def test_a_row_that_recorded_a_duration_keeps_it(self):
        model = _model()
        model.scanner_results["bandit"] = ScannerTargetStatusInfo(
            status=ScannerStatus.PASSED, duration=0.0
        )

        stats = ScannerStatisticsCalculator.extract_scanner_statistics(model)

        assert stats["bandit"]["duration"] == 0.0

    def test_the_legacy_two_target_row_is_read_as_dicts_and_with_a_none_duration(
        self,
    ):
        model = _model()
        model.scanner_results["old"] = SimpleNamespace(
            status="PASSED",
            source={"duration": 2.5},
            converted=SimpleNamespace(duration=None),
        )

        stats = ScannerStatisticsCalculator.extract_scanner_statistics(model)

        assert stats["old"]["duration"] == 2.5

    def test_a_scanner_that_recorded_no_number_reads_none(self):
        """A row holding text, or a report with a null duration, recorded no
        duration: it reads None, which every reader formats as "N/A" (as an
        excluded scanner's already did). Coerced to 0.0 it read "<1ms", a run
        time the scanner never had: a scanner that never started (failed to
        construct, or its module failed to import) carries exactly this shape."""
        model = _model({"nulled": {"source": _report("nulled", duration=None)}})
        model.scanner_results["odd"] = SimpleNamespace(status="PASSED", duration="fast")

        stats = ScannerStatisticsCalculator.extract_scanner_statistics(model)

        assert stats["odd"]["duration"] is None
        assert stats["nulled"]["duration"] is None

    def test_a_scanner_that_never_started_reads_none_not_zero(self):
        """An ERROR row for a scanner that never ran (it failed to construct, was
        refused as a duplicate, or its module failed to import) carries no
        duration. The none/zero rule keys on whether a number was recorded, not on
        the row being excluded or missing, so it reads None and not 0.0, which
        would render as "<1ms"."""
        model = _model()
        model.scanner_results["broken"] = SimpleNamespace(status="ERROR", duration=None)

        stats = ScannerStatisticsCalculator.extract_scanner_statistics(model)

        assert stats["broken"]["error"] is True
        assert stats["broken"]["duration"] is None

    @pytest.mark.parametrize("value", [math.nan, math.inf])
    def test_a_non_finite_duration_renders_as_not_available(self, value):
        assert format_duration(value) == "N/A"

    def test_just_under_a_minute_is_a_minute(self):
        assert format_duration(59.96) == "1m 0s"
        assert format_duration(59.9) == "59.9s"


class TestNamesAndSuppressions:
    def test_scanner_details_tool_name_names_the_scanner(self):
        result = _result(scanner_details={"tool_name": "bandit"})

        assert ScannerStatisticsCalculator._get_scanner_name_from_result(result) == (
            "bandit"
        )

    def test_a_rejected_suppression_does_not_hide_the_finding(self):
        model = _model()
        model.sarif = _sarif(
            _result(
                "bandit", suppressions=[Suppression(kind="external", state="rejected")]
            ),
            _result(
                "bandit", suppressions=[Suppression(kind="external", state="accepted")]
            ),
            _result("bandit", suppressions=[Suppression(kind="external")]),
            _result(
                "bandit",
                suppressions=[Suppression(kind="external", state="underReview")],
            ),
        )

        suppressed, critical, high, medium, low, info = (
            ScannerStatisticsCalculator.extract_sarif_counts_for_scanner(
                model, "bandit"
            )
        )

        # Accepted and state-less suppressions hide a result; rejected and under
        # review do not, so two of the four results are counted.
        assert suppressed == 2, (suppressed, critical)
        assert critical == 2


class TestTheRecordedRun:
    def test_a_partial_loss_does_not_explain_an_error_row_beside_a_crashed_tree(self):
        partial = _report(
            "cdk-nag",
            status="ERROR",
            targets_attempted=3,
            targets_failed=1,
            severity_counts={
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
        )
        crashed = _report(
            "cdk-nag",
            "converted",
            status="FAILED",
            raw_results={"status": "failed", "errors": ["the run raised"]},
            exception="RuntimeError: the run raised",
        )
        model = _model({"cdk-nag": {"source": partial, "converted": crashed}})
        model.scanner_results["cdk-nag"] = ScannerTargetStatusInfo(
            status=ScannerStatus.ERROR
        )

        _, _, error = ScannerStatisticsCalculator.get_scanner_status_info(
            model, "cdk-nag"
        )

        assert error is True

    def test_a_report_that_names_another_scanner_is_not_this_scanners(self):
        foreign = _report("semgrep", status="ERROR", targets_attempted=0)
        model = _model({"bandit": {"source": foreign}})

        assert ScannerStatisticsCalculator.any_target_errored(model, "bandit") is False
        assert ScannerStatisticsCalculator.scanner_evaluated_nothing(
            model, "bandit"
        ) is (False)

    def test_get_scanner_status_grades_unusable_counters_error(self):
        model = _model(
            {"cdk-nag": {"source": _report("cdk-nag", targets_attempted="3")}}
        )

        status = ScannerStatisticsCalculator.get_scanner_status(model, "cdk-nag")

        assert status == "ERROR"
        (metrics,) = get_unified_scanner_metrics(model)
        assert metrics.status == "ERROR"

    def test_the_scanner_level_report_is_found_under_the_python_none_key(self):
        model = _model(
            {
                "grype": {
                    None: _report(
                        "grype", None, status="MISSING", dependencies_satisfied=False
                    )
                }
            }
        )

        excluded, dependencies_missing, error = (
            ScannerStatisticsCalculator.get_scanner_status_info(model, "grype")
        )

        assert (excluded, dependencies_missing, error) == (False, True, False)

    def test_a_scanner_recorded_only_under_the_converted_tree_reads_that_report(self):
        model = _model({"semgrep": {"converted": _report("semgrep", "converted")}})

        excluded, dependencies_missing, error = (
            ScannerStatisticsCalculator.get_scanner_status_info(model, "semgrep")
        )

        assert (excluded, dependencies_missing, error) == (False, False, False)
        assert ScannerStatisticsCalculator.get_scanner_status(model, "semgrep") == (
            "PASSED"
        )

    def test_a_report_that_names_no_scanner_gives_no_status(self):
        """A status filed under the wrong key would flip a row, so a report that
        names no scanner gives none, under the source key or under any other tree's
        (the fallback that reads a converted-only report): the scanner has no
        recorded status and reads as errored, as one with nothing recorded always
        has."""
        source_only = _model({"bandit": {"source": {"status": "PASSED"}}})
        converted_only = _model({"bandit": {"converted": {"status": "PASSED"}}})

        for model in (source_only, converted_only):
            assert ScannerStatisticsCalculator.get_scanner_status_info(
                model, "bandit"
            ) == (False, False, True)

    def test_a_name_less_reports_duration_and_counters_are_read_for_their_key(self):
        """A report that names no scanner (a results file written before the field
        existed, or built by hand) is still the scanner's for everything but its
        status: its duration is summed, and its ERROR and counters are read, for the
        key it is filed under, as the metrics' own_target_reports read them."""
        model = _model(
            {
                "bandit": {
                    "source": {
                        "status": "ERROR",
                        "duration": 1.5,
                        "targets_attempted": 3,
                        "targets_failed": 3,
                        "raw_results": {"status": "ok", "findings": []},
                        "severity_counts": {"high": 2},
                    }
                }
            }
        )

        stats = ScannerStatisticsCalculator.extract_scanner_statistics(model)

        assert stats["bandit"]["duration"] == 1.5
        assert ScannerStatisticsCalculator.any_target_errored(model, "bandit") is True
        assert (
            ScannerStatisticsCalculator._dict_result_counts(model, "bandit").high == 2
        )


class TestTheRecordedLevelsAreDefinedOnce:
    def test_the_level_the_executor_writes_is_the_level_the_calculator_reads(self):
        """The executor writes ``scanner_severity_threshold`` only for a value in its
        set and the calculator accepts only a value in its own. Two copies of the
        ladder could drift, and the read-back would quietly fall back to the
        record's own read; both are the severity ladder's levels."""
        from automated_security_helper.core import scanner_statistics_calculator
        from automated_security_helper.core.phases import scanner_executor
        from automated_security_helper.utils.severity_ladder import (
            SEVERITY_THRESHOLDS,
        )

        ladder = frozenset(SEVERITY_THRESHOLDS)

        assert scanner_executor._GRADED_LEVELS == ladder
        assert scanner_statistics_calculator._RECORDED_LEVELS == ladder
