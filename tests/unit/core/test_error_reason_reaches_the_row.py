"""A scanner that ended in ERROR says why, on its container, its row and its metrics.

A SKIPPED or MISSING scanner's row carries the reason (``skipped_reason``,
``missing_reason``); an ERROR scanner's row carried none, so its cause was in the
``errors`` of its per-target reports and in ash.log only. The container now takes a
reason (``record_error_reason``), the ``scanner_results`` row has ``error_reason``
and ``error_reason_code`` beside the other two, and the unified metrics fill them
for an ERROR scanner from the row, then the per-target reports, else from the counts
and statuses the scanner was graded ERROR from.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core import unified_metrics
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.exceptions import DEFAULT_SENTENCES, ReasonCode
from automated_security_helper.core.unified_metrics import (
    ScannerMetrics,
    get_unified_scanner_metrics,
    populate_metrics_from_unified_source,
    recorded_error_reason,
)
from automated_security_helper.models import scanner_validation
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)
from automated_security_helper.models.scanner_validation import (
    ScannerValidationManager,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

TIMED_OUT = ("timed_out", "it timed out after 300 s and was killed")
NO_RESULT = ("no_result", "it returned no result")

#: What the scan phase records for a scan() that raised, as the failure handler
#: writes it: its prefix, then the scanner's own text, asides and all.
RAISED = (
    "Failed to execute example-tool scanner on source: ExampleScanner scan failed: "
    "its output is not JSON (decoder said: Expecting value). Stderr not read: see "
    "the log for details"
)
#: The first sentence of RAISED, which is what the reports show for it.
RAISED_SENTENCE = "its output is not JSON"


def _report(status, reason=None, **extra) -> dict:
    """One per-target report, as ``ScanResultProcessor`` dumps a container."""
    report = {"scanner_name": "example-tool", "status": status, "duration": 1.0}
    if reason is not None:
        report["error_reason_code"], report["error_reason"] = reason
    report.update(extra)
    return report


def _raised_report(
    home: str = "raw_results", error: str = RAISED, reason=None, **extra
) -> dict:
    """The report of a scan() that raised, with whatever counts it kept first.

    The executor writes the failure into ``raw_results`` (its ``errors`` lead with
    the scan phase's own message, and the report's own ``errors`` stay unset);
    ``home="errors"`` puts the message in the report's own, where the scan phase
    writes the error of a scanner that could not be built.
    """
    if home == "raw_results":
        extra["raw_results"] = {
            "status": "failed",
            "errors": [error],
            "exception": "the scan raised",
        }
    else:
        extra["errors"] = [error]
    return _report(ScannerStatus.ERROR, reason, **extra)


def _model(reports: dict, row: ScannerTargetStatusInfo | dict | None = None):
    results = AshAggregatedResults()
    results.additional_reports = {"example-tool": reports}
    if row is not None:
        results.scanner_results["example-tool"] = row
    return results


def _metrics(results: AshAggregatedResults) -> ScannerMetrics:
    (found,) = [
        metrics
        for metrics in get_unified_scanner_metrics(results)
        if metrics.scanner_name == "example-tool"
    ]
    return found


def _row(results: AshAggregatedResults) -> ScannerTargetStatusInfo:
    return populate_metrics_from_unified_source(results).scanner_results["example-tool"]


class TestTheContainerKeepsTheFirstReason:
    def test_a_recorded_reason_is_on_the_container(self):
        container = ScanResultsContainer(scanner_name="example-tool")

        container.record_error_reason(*TIMED_OUT)

        assert container.error_reason_code == "timed_out"
        assert container.error_reason == TIMED_OUT[1]

    def test_the_first_reason_is_kept(self):
        container = ScanResultsContainer(scanner_name="example-tool")

        container.record_error_reason(*TIMED_OUT)
        container.record_error_reason(*NO_RESULT)

        assert (container.error_reason_code, container.error_reason) == TIMED_OUT

    def test_the_dump_that_leaves_out_unset_fields_keeps_both(self):
        """That dump is the per-target report the metrics read the reason from."""
        container = ScanResultsContainer(scanner_name="example-tool")
        container.record_error_reason(*TIMED_OUT)

        dumped = container.model_dump(exclude_unset=True, exclude_none=True)

        assert dumped["error_reason_code"] == "timed_out"
        assert dumped["error_reason"] == TIMED_OUT[1]

    def test_a_container_that_recorded_none_dumps_neither(self):
        container = ScanResultsContainer(scanner_name="example-tool")
        container.add_error("something failed")

        dumped = container.model_dump(exclude_unset=True, exclude_none=True)

        assert "error_reason" not in dumped
        assert "error_reason_code" not in dumped
        assert container.error_reason is None
        assert container.error_reason_code is None

    @pytest.mark.parametrize(
        "code, sentence",
        [("", "x"), ("x", ""), (None, "x"), ("x", None), (7, "x"), ("x", 7)],
    )
    def test_two_strings_are_needed_to_record_one(self, code, sentence):
        container = ScanResultsContainer(scanner_name="example-tool")

        container.record_error_reason(code, sentence)  # type: ignore[arg-type]

        assert container.error_reason is None
        assert container.error_reason_code is None
        container.record_error_reason(*NO_RESULT)
        assert container.error_reason_code == "no_result"


class TestTheRowHasTheFieldsBesideTheOtherTwoReasons:
    def test_a_row_from_a_results_file_without_them_reads_none(self):
        row = ScannerTargetStatusInfo.model_validate({"status": "ERROR"})

        assert row.error_reason is None
        assert row.error_reason_code is None

    def test_a_row_keeps_what_a_results_file_recorded(self):
        row = ScannerTargetStatusInfo.model_validate(
            {
                "status": "ERROR",
                "error_reason_code": "timed_out",
                "error_reason": TIMED_OUT[1],
            }
        )

        assert (row.error_reason_code, row.error_reason) == TIMED_OUT

    def test_the_schema_describes_both(self):
        properties = ScannerTargetStatusInfo.model_json_schema()["properties"]

        for name in ("error_reason", "error_reason_code"):
            assert properties[name]["description"], name
        assert "ERROR" in properties["error_reason"]["description"]


class TestTheMetricsOfAnErrorScanner:
    def test_the_reason_its_report_recorded_is_the_scanners(self):
        results = _model({"source": _report(ScannerStatus.ERROR, TIMED_OUT)})

        metrics = _metrics(results)

        assert metrics.status == "ERROR"
        assert (metrics.error_reason_code, metrics.error_reason) == TIMED_OUT

    def test_a_report_read_back_from_json_carries_it_too(self):
        results = _model({"source": _report("ERROR", TIMED_OUT)})

        assert _metrics(results).error_reason == TIMED_OUT[1]

    @pytest.mark.parametrize("status", ["PASSED", "MISSING"])
    def test_a_scanner_that_is_not_in_error_has_none(self, status):
        """Its report may hold one from a target that failed; its status says more."""
        results = _model({"source": _report(status, TIMED_OUT)})

        metrics = _metrics(results)

        assert metrics.status == status
        assert metrics.error_reason is None
        assert metrics.error_reason_code is None

    def test_the_row_is_read_before_the_reports(self):
        row = ScannerTargetStatusInfo(
            status=ScannerStatus.ERROR,
            error_reason_code=NO_RESULT[0],
            error_reason=NO_RESULT[1],
        )
        results = _model({"source": _report(ScannerStatus.ERROR, TIMED_OUT)}, row)

        assert (_metrics(results).error_reason_code) == "no_result"

    def test_the_reports_are_read_in_the_order_a_reason_is_looked_up_in(self):
        results = _model(
            {
                "converted": _report(ScannerStatus.ERROR, NO_RESULT),
                "source": _report(ScannerStatus.ERROR, TIMED_OUT),
            }
        )

        assert _metrics(results).error_reason_code == "timed_out"

    def test_the_code_and_the_sentence_come_from_one_report(self):
        """A code in one report and a sentence in another is neither's reason."""
        source = _report(ScannerStatus.ERROR, error_reason_code="timed_out")
        converted = _report(ScannerStatus.ERROR, NO_RESULT)
        results = _model({"source": source, "converted": converted})

        metrics = _metrics(results)

        assert (metrics.error_reason_code, metrics.error_reason) == NO_RESULT

    def test_a_sentence_with_no_code_is_not_a_reason(self):
        source = _report(ScannerStatus.ERROR, error_reason=TIMED_OUT[1])
        results = _model({"source": source})

        assert recorded_error_reason(results, "example-tool") is None
        assert _metrics(results).error_reason is None

    def test_an_error_with_nothing_recorded_has_none(self):
        results = _model(
            {"source": _report(ScannerStatus.ERROR, errors=["Failed to execute"])}
        )

        metrics = _metrics(results)

        assert metrics.status == "ERROR"
        assert metrics.error_reason is None
        assert metrics.error_reason_code is None


class TestTheErrorsOnlyTheStatisticsDecide:
    def test_counters_that_cannot_be_read(self):
        report = _report(ScannerStatus.PASSED, targets_attempted="3", targets_failed=0)

        metrics = _metrics(_model({"source": report}))

        assert metrics.status == "ERROR"
        assert metrics.error_reason_code == ReasonCode.COUNTERS_UNUSABLE
        assert metrics.error_reason == DEFAULT_SENTENCES[ReasonCode.COUNTERS_UNUSABLE]

    def test_a_scanner_nothing_gives_a_status(self):
        report = {"scanner_name": "example-tool", "errors": ["something"]}

        metrics = _metrics(_model({"source": report}))

        assert metrics.status == "ERROR"
        assert metrics.error_reason_code == ReasonCode.NO_STATUS
        assert metrics.error_reason == DEFAULT_SENTENCES[ReasonCode.NO_STATUS]

    def test_a_scanner_that_failed_on_its_targets_says_how_many(self):
        report = _report(ScannerStatus.ERROR, targets_attempted=3, targets_failed=2)

        metrics = _metrics(_model({"source": report}))

        assert metrics.error_reason_code == ReasonCode.TARGETS_FAILED
        assert metrics.error_reason == "it failed on 2 of its 3 target(s)"

    def test_a_recorded_reason_is_not_replaced_by_the_counts(self):
        report = _report(
            ScannerStatus.ERROR, TIMED_OUT, targets_attempted=3, targets_failed=3
        )

        assert _metrics(_model({"source": report})).error_reason_code == "timed_out"

    def test_the_counts_name_no_target(self):
        report = _report(
            ScannerStatus.ERROR,
            targets_attempted=2,
            targets_failed=2,
            errors=["templates/secret-name.yaml: could not be read"],
        )

        metrics = _metrics(_model({"source": report}))

        assert metrics.error_reason == "it failed on 2 of its 2 target(s)"
        assert "secret-name" not in metrics.error_reason
        assert "/" not in metrics.error_reason


class TestASentenceThatSaysWhyOutranksTheCounts:
    """What failed the targets is the row's cause; how many failed is not.

    A scan() that raised after it counted a failed target leaves counts that read
    as a partial loss, and an error that says what went wrong. The reports list the
    error's first sentence for an ERROR nobody gave a reason, and the row must not
    record a sentence made from the counts in its place, or the row and the report
    would disagree and the cause would be hidden. The counts stay the reason of an
    ERROR the statistics alone decide, and of one whose errors say nothing a report
    can show.
    """

    @pytest.mark.parametrize("home", ["raw_results", "errors"])
    def test_the_counts_do_not_take_the_place_of_the_errors_sentence(self, home):
        results = _model(
            {"source": _raised_report(home, targets_attempted=3, targets_failed=1)}
        )

        metrics = _metrics(results)

        assert metrics.status == "ERROR"
        assert (metrics.error_reason_code, metrics.error_reason) == (None, None)
        sentence = unified_metrics.recorded_error_sentence(results, "example-tool")
        assert sentence == RAISED_SENTENCE

    @pytest.mark.parametrize(
        "report",
        [
            pytest.param(
                lambda: _raised_report(targets_attempted=3, targets_failed=1),
                id="it failed on some of its targets",
            ),
            pytest.param(
                lambda: _raised_report(targets_attempted="3", targets_failed=0),
                id="its counters cannot be read",
            ),
            pytest.param(
                lambda: {"scanner_name": "example-tool", "errors": [RAISED]},
                id="nothing gives it a status",
            ),
        ],
    )
    def test_no_reason_made_from_counts_or_statuses_is_recorded_beside_it(self, report):
        results = _model({"source": report()})

        metrics = _metrics(results)

        assert metrics.status == "ERROR"
        assert (metrics.error_reason_code, metrics.error_reason) == (None, None)

    def test_the_rebuilt_row_records_none_and_says_so_twice(self):
        report = _raised_report(targets_attempted=3, targets_failed=1)
        results = _model({"source": report})

        first = _row(results)
        first_dump = first.model_dump(exclude_unset=True)
        second_dump = _row(results).model_dump(exclude_unset=True)

        assert first.status == ScannerStatus.ERROR
        assert (first.error_reason_code, first.error_reason) == (None, None)
        assert "error_reason" not in first_dump
        assert "error_reason_code" not in first_dump
        assert second_dump == first_dump

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(
                "templates/x.yaml: could not be read", id="not the scan phase's text"
            ),
            pytest.param(
                "Failed to execute example-tool scanner on source: could not read "
                "/home/someone/x.yaml",
                id="a sentence that names a path",
            ),
            pytest.param(
                "Failed to execute example-tool scanner on source: " + "y" * 201,
                id="a sentence over the limit",
            ),
        ],
    )
    def test_a_failure_report_with_no_sentence_to_show_is_a_failed_run_not_a_partial_loss(
        self, error
    ):
        """A scan that raised is not an ERROR the counts decide: what it counted
        before it raised says nothing of why it failed, and "it failed on 1 of its 3
        target(s)" would read as a partial loss. With no sentence to show, the
        reason is the code's own, ``run_failed``."""
        results = _model(
            {
                "source": _raised_report(
                    error=error, targets_attempted=3, targets_failed=1
                )
            }
        )

        metrics = _metrics(results)

        assert metrics.error_reason_code == ReasonCode.RUN_FAILED
        assert metrics.error_reason == DEFAULT_SENTENCES[ReasonCode.RUN_FAILED]
        assert unified_metrics.recorded_error_sentence(results, "example-tool") is None

    def test_a_failure_report_with_unreadable_counters_is_a_failed_run_too(self):
        """Unreadable counters are another reason made from counts, so a crash gets
        ``run_failed`` for them too. (A report whose error sits in its own ``errors``
        carries no failure mark and keeps ``counters_unusable``.)"""
        results = _model(
            {
                "source": _raised_report(
                    "raw_results",
                    error="templates/x.yaml: could not be read",
                    targets_attempted="3",
                    targets_failed=0,
                )
            }
        )

        metrics = _metrics(results)

        assert metrics.error_reason_code == ReasonCode.RUN_FAILED, (
            metrics.error_reason_code,
            metrics.error_reason,
        )

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param("templates/x.yaml: could not be read", id="no prefix"),
            pytest.param(
                "Failed to execute example-tool scanner on source: could not read "
                "/home/someone/x.yaml",
                id="a sentence that names a path",
            ),
        ],
    )
    def test_control_an_error_only_the_counts_decide_keeps_them(self, error):
        """The counts stay the reason of an ERROR that is no failure report: the
        scanner returned, with some targets failed and an error nobody can show."""
        results = _model(
            {
                "source": _report(
                    ScannerStatus.ERROR,
                    errors=[error],
                    targets_attempted=3,
                    targets_failed=1,
                )
            }
        )

        metrics = _metrics(results)

        assert metrics.error_reason_code == ReasonCode.TARGETS_FAILED
        assert metrics.error_reason == "it failed on 1 of its 3 target(s)"
        assert unified_metrics.recorded_error_sentence(results, "example-tool") is None

    def test_a_recorded_reason_outranks_the_sentence(self):
        report = _raised_report(reason=TIMED_OUT, targets_attempted=3, targets_failed=1)

        metrics = _metrics(_model({"source": report}))

        assert (metrics.error_reason_code, metrics.error_reason) == TIMED_OUT

    def test_the_sentence_is_read_in_the_order_a_reason_is_looked_up_in(self):
        second = RAISED.replace(RAISED_SENTENCE, "its report is empty")
        results = _model(
            {
                "converted": _raised_report(error=second),
                "source": _raised_report(),
            }
        )

        sentence = unified_metrics.recorded_error_sentence(results, "example-tool")
        assert sentence == RAISED_SENTENCE

    def test_a_report_another_scanner_filed_under_it_is_not_read(self):
        foreign = _raised_report()
        foreign["scanner_name"] = "another-tool"

        results = _model({"source": foreign})

        assert unified_metrics.recorded_error_sentence(results, "example-tool") is None

    def test_control_without_the_sentence_the_counts_are_the_reason(self, monkeypatch):
        """The row cases above rest on the sentence: take it away and the counts speak."""
        monkeypatch.setattr(
            unified_metrics, "recorded_error_sentence", lambda *args, **kwargs: None
        )
        report = _report(
            ScannerStatus.ERROR, errors=[RAISED], targets_attempted=3, targets_failed=1
        )

        metrics = _metrics(_model({"source": report}))

        assert metrics.error_reason_code == ReasonCode.TARGETS_FAILED


class TestTheRebuiltRow:
    def test_an_error_row_carries_the_reason(self):
        results = _model({"source": _report(ScannerStatus.ERROR, TIMED_OUT)})

        row = _row(results)

        assert row.status == ScannerStatus.ERROR
        assert (row.error_reason_code, row.error_reason) == TIMED_OUT

    def test_it_is_among_the_fields_a_dump_that_leaves_unset_ones_out_keeps(self):
        row = _row(_model({"source": _report(ScannerStatus.ERROR, TIMED_OUT)}))

        dumped = row.model_dump(exclude_unset=True)

        assert dumped["error_reason_code"] == "timed_out"
        assert dumped["error_reason"] == TIMED_OUT[1]

    def test_a_passed_row_carries_none_and_keeps_its_shape(self):
        row = _row(_model({"source": _report(ScannerStatus.PASSED)}))

        assert row.error_reason is None
        assert row.error_reason_code is None
        dumped = row.model_dump(exclude_unset=True)
        assert "error_reason" not in dumped
        assert "error_reason_code" not in dumped

    def test_a_reason_a_row_kept_beyond_its_error_is_dropped(self):
        stale = ScannerTargetStatusInfo(
            status=ScannerStatus.PASSED,
            error_reason_code=TIMED_OUT[0],
            error_reason=TIMED_OUT[1],
        )
        results = _model({"source": _report(ScannerStatus.PASSED)}, stale)

        row = _row(results)

        assert row.status == ScannerStatus.PASSED
        assert row.error_reason is None
        assert row.error_reason_code is None

    def test_a_rebuild_run_twice_gives_one_answer(self):
        results = _model({"source": _report(ScannerStatus.ERROR, TIMED_OUT)})

        first = populate_metrics_from_unified_source(results).scanner_results[
            "example-tool"
        ]
        first_dump = first.model_dump(exclude_unset=True)
        second = populate_metrics_from_unified_source(results).scanner_results[
            "example-tool"
        ]

        assert second.model_dump(exclude_unset=True) == first_dump

    def test_a_derived_reason_gives_one_answer_twice_too(self):
        report = _report(ScannerStatus.ERROR, targets_attempted=3, targets_failed=1)
        results = _model({"source": report})

        first = _row(results).model_dump(exclude_unset=True)
        second = _row(results).model_dump(exclude_unset=True)

        assert second == first
        assert first["error_reason_code"] == ReasonCode.TARGETS_FAILED

    def test_a_status_the_rebuild_cannot_read_is_its_own_reason(self):
        results = AshAggregatedResults()
        metrics = ScannerMetrics(scanner_name="example-tool", status="NOT-A-STATUS")

        rebuilt = unified_metrics._populate_scanner_results_from_unified_metrics(
            results, [metrics]
        )

        row = rebuilt.scanner_results["example-tool"]
        assert row.status == ScannerStatus.ERROR
        assert row.error_reason_code == ReasonCode.STATUS_UNKNOWN
        assert row.error_reason == DEFAULT_SENTENCES[ReasonCode.STATUS_UNKNOWN]

    def test_the_row_of_a_processed_container_has_the_reason(self, tmp_path):
        """From the executor's container through the processor's dump to the row."""
        from automated_security_helper.base.plugin_context import PluginContext
        from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
        from automated_security_helper.core.phases.scan_result_processor import (
            ScanResultProcessor,
        )

        output = tmp_path / "output"
        context = PluginContext(
            source_dir=tmp_path,
            output_dir=output,
            work_dir=output / ASH_WORK_DIR_NAME,
            config=AshConfig(project_name="error-reasons"),
        )
        container = ScanResultsContainer(
            scanner_name="example-tool", target_type="source", raw_results=None
        )
        container.status = ScannerStatus.ERROR
        container.record_error_reason(*TIMED_OUT)
        results = ScanResultProcessor(plugin_context=context).process_container(
            container, AshAggregatedResults()
        )

        row = populate_metrics_from_unified_source(results).scanner_results[
            "example-tool"
        ]

        assert (row.error_reason_code, row.error_reason) == TIMED_OUT

    def test_control_without_the_rebuild_copy_the_row_has_none(self, monkeypatch):
        """The row cases above can fail: skip the copy and the row says nothing."""
        results = _model({"source": _report(ScannerStatus.ERROR, TIMED_OUT)})
        real = unified_metrics._populate_scanner_results_from_unified_metrics

        def without_the_reason(aggregated, metrics_list):
            return real(
                aggregated,
                [
                    metrics.model_copy(
                        update={"error_reason": None, "error_reason_code": None}
                    )
                    for metrics in metrics_list
                ],
            )

        monkeypatch.setattr(
            unified_metrics,
            "_populate_scanner_results_from_unified_metrics",
            without_the_reason,
        )

        row = populate_metrics_from_unified_source(results).scanner_results[
            "example-tool"
        ]

        assert row.status == ScannerStatus.ERROR
        assert row.error_reason is None
        assert row.error_reason_code is None


class TestTheBackfilledRow:
    @pytest.fixture
    def manager(self):
        from unittest.mock import MagicMock

        context = MagicMock()
        context.config = MagicMock()
        return ScannerValidationManager(context)

    def test_a_queued_scanner_that_never_completed_has_a_reason(self, manager):
        manager.update_scanner_state(
            "bandit",
            registration_status="registered",
            queued_for_execution=True,
            execution_completed=False,
        )

        results = AshAggregatedResults()
        manager.ensure_complete_results(results)

        row = results.scanner_results["bandit"]
        assert row.status == ScannerStatus.ERROR
        assert row.error_reason_code == ReasonCode.QUEUED_NOT_COMPLETED
        assert row.error_reason == DEFAULT_SENTENCES[ReasonCode.QUEUED_NOT_COMPLETED]

    def test_a_failure_recorded_by_someone_else_is_not_restated(self, manager):
        """Its text can hold a path; the row says nothing rather than guess."""
        manager.update_scanner_state(
            "bandit",
            registration_status="registered",
            queued_for_execution=False,
            execution_completed=False,
            failure_reason="construction raised at /home/someone/tree",
        )

        results = AshAggregatedResults()
        manager.ensure_complete_results(results)

        row = results.scanner_results["bandit"]
        assert row.status == ScannerStatus.ERROR
        assert row.error_reason is None
        assert row.error_reason_code is None

    def test_the_models_package_and_the_vocabulary_agree(self):
        """``models`` does not import ``core.exceptions``, so it writes the two out."""
        assert (
            scanner_validation.QUEUED_NOT_COMPLETED_CODE
            == ReasonCode.QUEUED_NOT_COMPLETED
        )
        assert (
            scanner_validation.QUEUED_NOT_COMPLETED_SENTENCE
            == DEFAULT_SENTENCES[ReasonCode.QUEUED_NOT_COMPLETED]
        )
