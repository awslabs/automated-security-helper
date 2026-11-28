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

The cause is not always a reason the executor filed. A scan() that raised with
nothing to say why files no reason: its report holds the error and no pair, and
the first sentence of that error is what the reports list. A scanner whose whole
run crashed holds a failure report with no sentence to show, and its reason is
``run_failed``. The pass's guess only says that nothing completed, so it is the
answer when nothing else says why, and no earlier. The last but one class runs
both crashes through the executor's own run loop, the processor, the pass and the
rebuild, and reads the row and the report line. The last class reads a saved
results file whose row holds the guess.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.exceptions import DEFAULT_SENTENCES, ReasonCode
from automated_security_helper.core.phases.scan_result_processor import (
    ScanResultProcessor,
)
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.core.unified_metrics import (
    get_unified_scanner_metrics,
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
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

NAME = "example-tool"
#: What a scan() that raised says, and so the sentence the reports list for it.
CRASH = "the tool's JSON output has no results array"
#: What the executor's failure handler records for that crash on a target, with the
#: scan phase's prefix: the first sentence of it is CRASH.
RAISED = f"Failed to execute {NAME} scanner on source: {CRASH}"
#: What the executor records when the scanner's whole run raised: text with no
#: failure prefix, so there is no first sentence to list.
RUN_CRASHED = f"Unexpected error in scanner {NAME}: {CRASH}"

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


class _ScannerConfig(ScannerPluginConfigBase):
    name: str = NAME


class _CrashingScanner(ScannerPluginBase):
    """A real scanner plugin whose scan() raises and records nothing about why."""

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("scan() is overridden directly")

    def scan(
        self,
        target,
        target_type=None,
        global_ignore_paths=None,
        config=None,
        *args,
        **kwargs,
    ):
        raise RuntimeError(CRASH)


def _live_context(tmp_path) -> PluginContext:
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("print('x')\n", encoding="utf-8")
    output_dir = tmp_path / "output"
    (output_dir / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=output_dir / ASH_WORK_DIR_NAME,
        config=AshConfig(project_name="completeness-pass"),
    )


def _live_scan(tmp_path, *, whole_run_crashes: bool = False) -> AshAggregatedResults:
    """A crashing scanner through the scan phase's own order of work.

    The executor's run loop runs it and builds the container: the per-target
    handler's when scan() raised, the failure container of a run that raised as a
    whole when ``whole_run_crashes``. The processor files each container, the
    execution check names what completed, the real completeness pass backfills the
    rest, and the rebuild the engine runs writes the rows.
    """
    context = _live_context(tmp_path)
    manager = _manager()
    _queue_without_completion(manager, NAME)
    processor = ScanResultProcessor(plugin_context=context, validation_manager=manager)
    config = _ScannerConfig()
    config.options.severity_threshold = "MEDIUM"
    scanner = _CrashingScanner(config=config, context=context)
    scanner.exit_code = 0
    targets = [{"path": context.source_dir, "type": "source"}]
    executor = ScannerExecutor(
        plugin_context=context,
        progress_display=MagicMock(),
        scanner_tasks=[(NAME, scanner, targets)],
        process_results_fn=processor.process_container,
    )
    if whole_run_crashes:

        def _crash(*args):
            raise RuntimeError(CRASH)

        executor._execute_scanner = _crash  # type: ignore[method-assign]
    aggregated = AshAggregatedResults(ash_config=get_default_config())
    results = executor.run_sequential(aggregated)

    # What the cases rest on: the scanner did not complete, so the pass files its
    # guess for it, and the rebuild starts from that row.
    assert executor.completed_scanners == []
    manager.validate_execution_completion([])
    manager.ensure_complete_results(results)
    guessed = results.scanner_results[NAME]
    assert guessed.error_reason_code == ReasonCode.QUEUED_NOT_COMPLETED
    return populate_metrics_from_unified_source(results)


def _guessed(report: dict) -> AshAggregatedResults:
    """A results file whose row holds the pass's guess beside one per-target report."""
    results = AshAggregatedResults(ash_config=get_default_config())
    results.additional_reports = {NAME: {"source": report}}
    results.scanner_results = {
        NAME: ScannerTargetStatusInfo(
            status=ScannerStatus.ERROR,
            dependencies_satisfied=True,
            excluded=False,
            error_reason_code=ReasonCode.QUEUED_NOT_COMPLETED,
            error_reason=DEFAULT_SENTENCES[ReasonCode.QUEUED_NOT_COMPLETED],
        )
    }
    return results


def _report(**extra) -> dict:
    """One per-target report of an ERROR, as the processor dumps a container."""
    return {
        "scanner_name": NAME,
        "status": ScannerStatus.ERROR,
        "duration": 1.0,
        **extra,
    }


def _failure_dict(*errors: str) -> dict:
    """A scan's failure record, as the executor writes it into ``raw_results``."""
    return {"status": "failed", "errors": list(errors), "exception": CRASH}


def _metrics_of(results: AshAggregatedResults):
    (found,) = [
        metrics
        for metrics in get_unified_scanner_metrics(results)
        if metrics.scanner_name == NAME
    ]
    return found


def _report_lines(results: AshAggregatedResults) -> dict:
    """The reports' "Scanners that did not run" lines: name -> (status, reason)."""
    return {
        name: (entry["status"], entry["reason"])
        for entry in ReportContentEmitter(results).get_scanners_not_run()
        for name in entry["scanners"]
    }


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
        """With no row from the pass, the row is rebuilt from the report's own pair."""
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


class TestACrashNothingCanNameIsReadFromItsReport:
    """A crash that recorded no reason is not the pass's "did not complete".

    The executor files a reason where it knows the cause: a timeout, a tool that
    never started, an exit code the scanner refuses. A scan() that raised with none
    of those leaves an ERROR report that holds the error and no pair, and the
    reports list the first sentence of that error; the row records no reason, as
    the output reference says. A scanner whose whole run crashed holds a failure
    report whose text has no first sentence to list, and its reason is
    ``run_failed``.
    """

    def test_a_scan_that_raised_is_listed_by_its_first_sentence(self, tmp_path):
        results = _live_scan(tmp_path)

        row = results.scanner_results[NAME]
        assert row.status == ScannerStatus.ERROR
        assert (row.error_reason_code, row.error_reason) == (None, None)
        assert _report_lines(results) == {NAME: ("ERROR", CRASH)}

    def test_its_flat_row_records_no_reason(self, tmp_path):
        results = _live_scan(tmp_path)

        (flat,) = ReportContentEmitter(results).get_scanner_results()

        assert flat["status"] == "ERROR"
        assert (flat["error_reason_code"], flat["error_reason"]) == (None, None)

    def test_a_scanner_whose_whole_run_crashed_reads_run_failed(self, tmp_path):
        results = _live_scan(tmp_path, whole_run_crashes=True)
        failed = (ReasonCode.RUN_FAILED, DEFAULT_SENTENCES[ReasonCode.RUN_FAILED])

        row = results.scanner_results[NAME]
        assert row.status == ScannerStatus.ERROR
        assert (row.error_reason_code, row.error_reason) == failed
        assert _report_lines(results) == {NAME: ("ERROR", failed[1])}
        (flat,) = ReportContentEmitter(results).get_scanner_results()
        assert (flat["error_reason_code"], flat["error_reason"]) == failed

    @pytest.mark.parametrize(
        "whole_run_crashes", [False, True], ids=["one target", "whole run"]
    )
    def test_a_second_rebuild_gives_the_row_it_already_holds(
        self, tmp_path, whole_run_crashes
    ):
        results = _live_scan(tmp_path, whole_run_crashes=whole_run_crashes)
        first = results.scanner_results[NAME].model_dump(exclude_unset=True)

        again = populate_metrics_from_unified_source(results)

        assert again.scanner_results[NAME].model_dump(exclude_unset=True) == first


class TestThePassesGuessIsTheLastThingARowSays:
    """A row that holds the guess still reads what its reports say first.

    A results file written before this was read this way has the guess in front of
    everything the reports recorded, and ``ash report`` and ``ash merge`` rebuild
    its rows. The reports are read first: a sentence they list, a crash with no
    sentence to show and the counts of the targets that failed each outrank the
    guess, which is the answer only when nothing else says why.
    """

    def test_a_sentence_the_reports_list_ranks_above_it(self):
        results = _guessed(_report(raw_results=_failure_dict(RAISED)))

        metrics = _metrics_of(results)

        assert metrics.status == ScannerStatus.ERROR
        assert (metrics.error_reason_code, metrics.error_reason) == (None, None)
        assert _report_lines(results) == {NAME: ("ERROR", CRASH)}

    def test_the_rebuilt_row_of_such_a_file_drops_it(self):
        results = _guessed(_report(raw_results=_failure_dict(RAISED)))

        row = populate_metrics_from_unified_source(results).scanner_results[NAME]

        assert row.status == ScannerStatus.ERROR
        assert (row.error_reason_code, row.error_reason) == (None, None)

    def test_a_crash_with_no_sentence_to_show_ranks_above_it(self):
        results = _guessed(_report(raw_results=_failure_dict(RUN_CRASHED)))

        metrics = _metrics_of(results)

        assert (metrics.error_reason_code, metrics.error_reason) == (
            ReasonCode.RUN_FAILED,
            DEFAULT_SENTENCES[ReasonCode.RUN_FAILED],
        )

    def test_the_counts_of_the_targets_that_failed_rank_above_it(self):
        results = _guessed(_report(targets_attempted=2, targets_failed=2))

        metrics = _metrics_of(results)

        assert (metrics.error_reason_code, metrics.error_reason) == (
            ReasonCode.TARGETS_FAILED,
            "it failed on 2 of its 2 target(s)",
        )

    def test_control_a_report_that_says_nothing_leaves_it_the_answer(self):
        metrics = _metrics_of(_guessed(_report()))

        assert (metrics.error_reason_code, metrics.error_reason) == (
            ReasonCode.QUEUED_NOT_COMPLETED,
            DEFAULT_SENTENCES[ReasonCode.QUEUED_NOT_COMPLETED],
        )
