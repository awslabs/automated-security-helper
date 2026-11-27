"""A cause the executor recorded is not replaced by the completeness pass's guess.

A scanner whose run ended in an ERROR container (a timeout, a refused exit
code, a result that could not be graded) is queued by the scan phase and never
appended to the completed scanners, so the phase's completeness pass finds no
row for it and files one. That backfilled row says the scanner "was queued for
execution but did not complete". For a scanner that did run and was graded
ERROR the sentence is false, and it must not stand in front of the cause the
executor recorded on the per-target report.

The row tests elsewhere go from the processor to the rebuild without the pass,
and the scan-phase fixture replaces the validation manager with a mock, so no
test composed the three. This one does, with the real manager: the container the
executor returns, the processor that dumps it, the real completeness pass, and
the row rebuild the engine runs.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.exceptions import DEFAULT_SENTENCES, ReasonCode
from automated_security_helper.core.phases.scan_result_processor import (
    ScanResultProcessor,
)
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
    recorded_error_reason,
)
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

CAUSES = [
    (ReasonCode.TIMED_OUT, "it timed out after 300 s and was killed"),
    (ReasonCode.COULD_NOT_START, "its tool could not be started"),
    (
        ReasonCode.EXIT_CODE_REJECTED,
        (
            "its tool exited with code 3, which this scanner does not accept as a "
            "completed run, so its results file is not graded"
        ),
    ),
    (ReasonCode.RESULT_UNGRADABLE, "its result could not be graded"),
    (ReasonCode.NOT_EVALUATED, "no rule was evaluated against 1 of its targets"),
]


def _context(tmp_path) -> PluginContext:
    output = tmp_path / "output"
    return PluginContext(
        source_dir=tmp_path,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(project_name="completeness-pass"),
    )


def _manager() -> ScannerValidationManager:
    context = MagicMock()
    context.config = MagicMock()
    return ScannerValidationManager(context)


def _queue_without_completion(manager: ScannerValidationManager, name: str) -> None:
    """What the scan phase leaves for a scanner whose run returned an ERROR container."""
    manager.update_scanner_state(
        name,
        registration_status="registered",
        queued_for_execution=True,
        execution_completed=False,
    )


def _error_container(name: str, target: str, reason) -> ScanResultsContainer:
    container = ScanResultsContainer(
        scanner_name=name, target_type=target, raw_results=None
    )
    container.status = ScannerStatus.ERROR
    container.record_error_reason(*reason)
    return container


def _scan(tmp_path, containers, queued) -> AshAggregatedResults:
    """The scan phase's order: process each container, run the pass, rebuild the rows."""
    results = AshAggregatedResults()
    processor = ScanResultProcessor(plugin_context=_context(tmp_path))
    for container in containers:
        results = processor.process_container(container, results)
    manager = _manager()
    for name in queued:
        _queue_without_completion(manager, name)
    manager.ensure_complete_results(results)
    return populate_metrics_from_unified_source(results)


class TestARecordedCauseSurvivesThePass:
    @pytest.mark.parametrize(("code", "sentence"), CAUSES)
    def test_the_row_keeps_the_cause_the_executor_recorded(
        self, tmp_path, code, sentence
    ):
        results = _scan(
            tmp_path,
            [_error_container("bandit", "source", (code, sentence))],
            ["bandit"],
        )

        row = results.scanner_results["bandit"]
        assert row.status == ScannerStatus.ERROR
        assert (row.error_reason_code, row.error_reason) == (code, sentence)

    def test_the_recorded_cause_is_read_back_from_the_rebuilt_model(self, tmp_path):
        recorded = CAUSES[0]
        results = _scan(
            tmp_path,
            [_error_container("bandit", "source", recorded)],
            ["bandit"],
        )

        assert recorded_error_reason(results, "bandit") == recorded

    def test_a_results_file_written_with_the_guess_in_front_of_a_cause_reads_the_cause(
        self, tmp_path
    ):
        """What ``ash report`` reads back from a file an earlier run wrote."""
        recorded = CAUSES[0]
        results = AshAggregatedResults()
        results = ScanResultProcessor(
            plugin_context=_context(tmp_path)
        ).process_container(_error_container("bandit", "source", recorded), results)
        results.scanner_results = {
            "bandit": ScannerTargetStatusInfo(
                status=ScannerStatus.ERROR,
                dependencies_satisfied=True,
                excluded=False,
                error_reason_code=ReasonCode.QUEUED_NOT_COMPLETED,
                error_reason=DEFAULT_SENTENCES[ReasonCode.QUEUED_NOT_COMPLETED],
            )
        }

        assert recorded_error_reason(results, "bandit") == recorded

    def test_the_cause_of_one_target_is_kept_when_the_other_target_has_none(
        self, tmp_path
    ):
        recorded = CAUSES[0]
        clean = ScanResultsContainer(
            scanner_name="bandit", target_type="converted", raw_results=None
        )
        clean.status = ScannerStatus.PASSED
        results = _scan(
            tmp_path,
            [_error_container("bandit", "source", recorded), clean],
            ["bandit"],
        )

        row = results.scanner_results["bandit"]
        assert (row.error_reason_code, row.error_reason) == recorded

    def test_one_scanner_cause_is_not_given_to_another(self, tmp_path):
        recorded = CAUSES[0]
        results = _scan(
            tmp_path,
            [_error_container("bandit", "source", recorded)],
            ["bandit", "checkov"],
        )

        assert results.scanner_results["bandit"].error_reason_code == recorded[0]
        assert (
            results.scanner_results["checkov"].error_reason_code
            == ReasonCode.QUEUED_NOT_COMPLETED
        )

    def test_a_pair_the_report_wrote_stays_when_the_row_has_none(self, tmp_path):
        """The row rebuild reads a row's own pair first when it is not the pass's guess."""
        recorded = CAUSES[2]
        results = _scan(
            tmp_path,
            [_error_container("bandit", "source", recorded)],
            [],
        )

        row = results.scanner_results["bandit"]
        assert (row.error_reason_code, row.error_reason) == recorded


class TestAScannerThatNeverCompletedStillSaysSo:
    def test_a_queued_scanner_with_no_report_gets_the_queued_sentence(self, tmp_path):
        results = _scan(tmp_path, [], ["bandit"])

        row = results.scanner_results["bandit"]
        assert row.status == ScannerStatus.ERROR
        assert row.error_reason_code == ReasonCode.QUEUED_NOT_COMPLETED
        assert row.error_reason == DEFAULT_SENTENCES[ReasonCode.QUEUED_NOT_COMPLETED]

    def test_a_report_with_no_recorded_reason_does_not_hide_the_queued_sentence(
        self, tmp_path
    ):
        container = ScanResultsContainer(
            scanner_name="bandit", target_type="source", raw_results=None
        )
        container.status = ScannerStatus.ERROR
        results = _scan(tmp_path, [container], ["bandit"])

        row = results.scanner_results["bandit"]
        assert row.status == ScannerStatus.ERROR
        assert row.error_reason_code == ReasonCode.QUEUED_NOT_COMPLETED
