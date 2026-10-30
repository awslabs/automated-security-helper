"""Three readings of the unified metrics over a scanner's recorded rows.

- ``target_counts`` reads a failure count above the attempt count (3 attempted, 5
  failed; 0 attempted, 2 failed) as a usable claim, and the coverage line printed
  a negative evaluated count. Such counters are unusable, like a negative one.
- ``get_unified_scanner_metrics`` inherited a recorded FAILED when nothing else
  decided the status, so a scanner whose findings a later run dropped or
  suppressed stayed FAILED with 0 actionable while the exit code passed. With
  nothing actionable the gate passes, so the row reads PASSED.
- the scanner_results rebuild dropped the ``missing_reason`` the metrics compute
  for a FAILED scanner whose dependencies were missing on one tree, so the row
  said FAILED and nothing said which tree went unscanned.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.unified_metrics import (
    coverage_shortfalls,
    get_unified_scanner_metrics,
    populate_metrics_from_unified_source,
    target_counts,
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
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

SCANNER = "cdk-nag"


def _model(reports: dict) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.additional_reports = {SCANNER: reports}
    return model


def _report(target: str, **fields) -> dict:
    report = {"scanner_name": SCANNER, "target_type": target, "status": "PASSED"}
    report.update(fields)
    return report


class TestMoreFailuresThanAttemptsIsUnusable:
    @pytest.mark.parametrize("attempted, failed", [(3, 5), (0, 2)])
    def test_the_counters_are_unusable(self, attempted, failed):
        model = _model(
            {
                "source": _report(
                    "source", targets_attempted=attempted, targets_failed=failed
                )
            }
        )

        assert target_counts(model, SCANNER) == (-1, -1)
        assert coverage_shortfalls(model) == [(SCANNER, None, None)]

    def test_a_partial_loss_is_read_as_before(self):
        """Control."""
        model = _model(
            {"source": _report("source", targets_attempted=3, targets_failed=1)}
        )

        assert target_counts(model, SCANNER) == (3, 1)
        assert coverage_shortfalls(model) == [(SCANNER, 3, 1)]


class TestARecordedFailedWithNothingActionableReadsPassed:
    """The flip also needs the report to record the level it was graded against
    (``scanner_severity_threshold``); a report from before that was recorded keeps
    the row's FAILED, see test_unified_metrics_failed_stays_without_a_recorded_level."""

    def test_the_row_is_passed(self):
        model = _model(
            {
                "source": _report(
                    "source", status="FAILED", scanner_severity_threshold="MEDIUM"
                )
            }
        )
        model.scanner_results[SCANNER] = ScannerTargetStatusInfo(
            status=ScannerStatus.FAILED
        )

        (metrics,) = get_unified_scanner_metrics(model)

        assert metrics.actionable == 0
        assert metrics.status == "PASSED"

    def test_another_recorded_status_is_kept(self):
        """Control: the row's SKIPPED (a shard's record) is still inherited."""
        model = _model({"source": _report("source", status="SKIPPED")})
        model.scanner_results[SCANNER] = ScannerTargetStatusInfo(
            status=ScannerStatus.SKIPPED
        )

        (metrics,) = get_unified_scanner_metrics(model)

        assert metrics.status == "SKIPPED"

    def test_a_dict_result_whose_counts_were_never_recorded_stays_failed(self):
        """A results file written by a dict-result scanner before its counts were
        assigned carries the findings in raw_results and no severity_counts, so
        the rebuilt row's FAILED is the only evidence the gate failed; re-rendering
        it must not say PASSED. The override runs only when the counts it rests on
        were recorded."""
        model = _model(
            {
                "source": _report(
                    "source",
                    status="FAILED",
                    raw_results={"findings": [{"severity": "high"}]},
                )
            }
        )
        model.scanner_results[SCANNER] = ScannerTargetStatusInfo(
            status=ScannerStatus.FAILED
        )

        (metrics,) = get_unified_scanner_metrics(model)

        assert metrics.actionable == 0
        assert metrics.status == "FAILED"

    def test_a_dict_result_with_recorded_zero_counts_reads_passed(self):
        """Control: the same shape with its counts recorded (all zero, a scan that
        found nothing) is overridden."""
        model = _model(
            {
                "source": _report(
                    "source",
                    status="FAILED",
                    scanner_severity_threshold="MEDIUM",
                    raw_results={"findings": []},
                    severity_counts={
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "info": 0,
                        "suppressed": 0,
                    },
                )
            }
        )
        model.scanner_results[SCANNER] = ScannerTargetStatusInfo(
            status=ScannerStatus.FAILED
        )

        (metrics,) = get_unified_scanner_metrics(model)

        assert metrics.status == "PASSED"


class TestAnErrorFiledUnderAnotherTargetIsTheScannersError:
    """The calculator's per-target walk reads every key, so an ERROR report under
    "converted" beside a PASSED source report and a PASSED recorded row grades
    the scanner ERROR. This tests the walk (``any_target_errored``) over a report
    built by hand under "converted", not the refiling that puts a
    results-processing failure there; that refiling is the executor's and is
    tested with it (``test_scanner_executor_processes_each_target``)."""

    def test_the_row_is_error(self):
        model = _model(
            {
                "source": _report("source"),
                "converted": _report("converted", status="ERROR"),
            }
        )
        model.scanner_results[SCANNER] = ScannerTargetStatusInfo(
            status=ScannerStatus.PASSED
        )

        (metrics,) = get_unified_scanner_metrics(model)

        assert metrics.status == "ERROR"

    def test_two_passed_targets_read_passed(self):
        """Control."""
        model = _model({"source": _report("source"), "converted": _report("converted")})
        model.scanner_results[SCANNER] = ScannerTargetStatusInfo(
            status=ScannerStatus.PASSED
        )

        (metrics,) = get_unified_scanner_metrics(model)

        assert metrics.status == "PASSED"


class TestAFailedRowKeepsTheMissingTreesReason:
    def test_the_rebuilt_row_says_which_tree(self):
        model = _model(
            {
                "source": _report("source", status="FAILED"),
                "converted": _report(
                    "converted",
                    status="MISSING",
                    dependencies_satisfied=False,
                    missing_reason="the tool is not installed",
                ),
            }
        )
        model.sarif = SarifReport(
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name=SCANNER)),
                    results=[
                        Result(
                            ruleId="R1",
                            level="error",
                            message=Message(text="x"),
                            properties=PropertyBag(scanner_name=SCANNER),
                        )
                    ],
                )
            ]
        )

        rebuilt = populate_metrics_from_unified_source(model)
        row = rebuilt.scanner_results[SCANNER]

        assert row.status == ScannerStatus.FAILED
        assert isinstance(row.missing_reason, str)
        assert "the tool is not installed" in row.missing_reason
        assert "converted" in row.missing_reason
