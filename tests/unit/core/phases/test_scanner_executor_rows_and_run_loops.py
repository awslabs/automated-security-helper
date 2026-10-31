# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ScannerExecutor: what one target's row records, and how the run loops report.

Per target:

- the heartbeat counts from the scan's start and is stopped when entering the
  scopes raises;
- a disabled scanner is left unscanned (SKIPPED, excluded), not graded ERROR;
- a sandbox refusal's text is redacted; a run's recorded cause is not re-led by the
  record failure; an interrupt is not logged as "returned no result";
- the TRACE record of the raw result is formatted only at TRACE;
- False alone is MISSING; an empty dict or list is refused as ungradable;
- a target scan() never ran on records no times, counters or unscanned inputs;
- a failed dict with no errors gets a reason, and the refusal of any other
  status names the plugin's status redacted;
- a negative counter is warned about once; unevaluated targets and a recorded
  timeout reach a row that is already ERROR; a skipped reason writes the home
  directory as a tilde; the row is named as the task is.

The run loops:

- a scanner with no row is not recorded as completed;
- a failed scanner is not shown "Completed scan" in green; a run that did not
  succeed is shown "Scan failed" in red;
- SCAN_COMPLETE subscribers get a copy of the remaining list, in both modes;
- the parallel loop emits SCAN_START, keys tasks by position, records the future's
  own plugin and sets the scan's cancel event on a cancel; a scanner whose
  bookkeeping raised leaves the remaining list and is announced with a
  SCAN_COMPLETE whose ``succeeded`` is False (every finished turn is announced;
  ``completed_scanners`` still names the recorded ones alone), with the
  processor error redacted.
"""

from __future__ import annotations

import logging
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.cancellation import ScanCancelled, cancel_scope
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases import scanner_executor
from automated_security_helper.core.phases.scanner_executor import (
    ScannerExecutor,
    _ScannerHeartbeat,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sandbox.scope import SandboxUnavailable

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

CANARY = "ENVCANARY-executor-rows-quoted-value"


class _ScannerConfig(ScannerPluginConfigBase):
    name: str = "scripted"


class _ScriptedScanner(ScannerPluginBase):
    """A real ScannerPluginBase whose scan() replays a scripted outcome, then
    runs an optional hook that can record state on the plugin as a tool run
    would (a timeout, unevaluated targets)."""

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
        self.scan_calls.append(target_type)
        hook = getattr(self, "after_scan", None)
        if callable(hook):
            hook(self)
        outcome = self.scripted_result
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def _context(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir(exist_ok=True)
    (source_dir / "app.py").write_text("print('x')\n", encoding="utf-8")
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    work_dir = tmp_path / "work"
    work_dir.mkdir(exist_ok=True)
    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )


def _scanner(context, scripted_result=None, enabled=True, after_scan=None):
    config = _ScannerConfig(enabled=enabled)
    config.options.severity_threshold = "MEDIUM"
    scanner = _ScriptedScanner(config=config, context=context)
    scanner.scan_calls = []
    scanner.scripted_result = scripted_result
    scanner.after_scan = after_scan
    scanner.start_time = datetime(2026, 1, 1, 10, 0, 0)
    scanner.end_time = datetime(2026, 1, 1, 10, 0, 7)
    scanner.exit_code = 0
    return scanner


def _executor(context, tasks=None, **kwargs):
    return ScannerExecutor(
        plugin_context=context,
        progress_display=MagicMock(),
        scanner_tasks=tasks or [],
        **kwargs,
    )


def _targets(context):
    return [{"path": context.source_dir, "type": "source"}]


def _sarif() -> SarifReport:
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "tool"}}, "results": []}],
        }
    )


def _one_row(context, scanner, name="scripted"):
    (row,) = _executor(context)._execute_scanner(name, scanner, _targets(context))
    return row


def _record_log(monkeypatch, level_name):
    lines = []
    monkeypatch.setattr(
        scanner_executor.ASH_LOGGER,
        level_name,
        lambda message, *args, **kwargs: lines.append(str(message)),
    )
    return lines


def _plugin_values(monkeypatch, *values):
    monkeypatch.setattr(
        _ScriptedScanner, "_environment_values", lambda self: tuple(values)
    )


def _refuse_sandbox(monkeypatch, reason, grades_missing):
    """Make the sandbox resolution refuse every scanner with *reason*."""

    def _refuse(*args, **kwargs):
        raise SandboxUnavailable(reason)

    monkeypatch.setattr(scanner_executor, "scanner_sandbox_scope", _refuse)
    monkeypatch.setattr(
        scanner_executor,
        "sandbox_refusal_grades_missing",
        lambda refusal: grades_missing,
    )


class TestTheHeartbeat:
    def test_elapsed_time_counts_from_start_not_from_construction(self, monkeypatch):
        clock = iter([10.0, 50.0])
        monkeypatch.setattr(scanner_executor.time, "monotonic", lambda: next(clock))

        heartbeat = _ScannerHeartbeat("tool", "source", interval=0)
        heartbeat.start()

        assert heartbeat._started == 50.0

    def test_the_heartbeat_is_stopped_when_entering_the_scopes_raises(
        self, tmp_path, monkeypatch
    ):
        """Started before the with-statement whose finally stops it, a raise while
        entering the scopes left the daemon thread announcing the scanner."""
        made = []

        class _Recording:
            def __init__(self, *args, **kwargs):
                self.started = False
                self.stopped = False
                made.append(self)

            def start(self):
                self.started = True
                return self

            def stop(self):
                self.stopped = True

        @contextmanager
        def _refusing_scope(_context):
            raise RuntimeError("the tool config directory could not be made")
            yield  # pragma: no cover

        monkeypatch.setattr(scanner_executor, "_ScannerHeartbeat", _Recording)
        monkeypatch.setattr(scanner_executor, "tool_config_scope", _refusing_scope)
        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, scripted_result=_sarif()))

        assert row.status == ScannerStatus.ERROR, row.errors
        assert made, "no heartbeat was made"
        for heartbeat in made:
            assert heartbeat.stopped or not heartbeat.started, vars(heartbeat)


class TestOneTargetsRow:
    def test_a_disabled_scanner_is_left_unscanned_not_graded_error(
        self, tmp_path, monkeypatch
    ):
        errors = _record_log(monkeypatch, "error")
        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, _sarif(), enabled=False))

        assert row.status == ScannerStatus.SKIPPED, (row.status, row.errors)
        assert row.excluded is True
        assert "disabled" in (row.skipped_reason or ""), row.skipped_reason
        assert not any("returned no result" in line for line in errors), errors

    @pytest.mark.parametrize("grades_missing", [False, True], ids=["error", "missing"])
    def test_a_sandbox_refusals_text_is_redacted_on_the_row(
        self, tmp_path, monkeypatch, grades_missing
    ):
        _plugin_values(monkeypatch, CANARY)
        _refuse_sandbox(monkeypatch, f"backend refused: {CANARY}", grades_missing)
        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, _sarif()))

        recorded = [*row.errors, row.missing_reason or ""]
        assert any("backend refused" in text for text in recorded), recorded
        assert not any(CANARY in text for text in recorded), recorded

    def test_a_kept_flags_cause_is_not_re_led_by_the_record_failure(self, tmp_path):
        """A run that was cancelled and then failed its record step: the row's
        reason leads with the cancel, as the gate order says."""

        def _kept(plugin):
            plugin._scan_kept_flag = ("cancelled", "the stop was sent")
            plugin._scan_post_run_error = "the output file could not be written"

        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, _sarif(), after_scan=_kept))

        assert row.status == ScannerStatus.ERROR
        assert row.errors, row
        assert "was cancelled on source" in row.errors[0], row.errors
        assert not row.errors[0].startswith(
            "scripted ran on source, but ASH could not record"
        ), row.errors

    def test_an_interrupt_is_not_logged_as_a_scanner_returning_no_result(
        self, tmp_path, monkeypatch
    ):
        errors = _record_log(monkeypatch, "error")
        context = _context(tmp_path)
        scanner = _scanner(context, ScanCancelled("the scan was cancelled"))

        with pytest.raises(ScanCancelled):
            _executor(context)._execute_scanner("scripted", scanner, _targets(context))

        assert not any("returned no result" in line for line in errors), errors

    def test_the_raw_result_is_formatted_only_at_trace(self, tmp_path, monkeypatch):
        class _Counted:
            shown = 0

            def __repr__(self):
                type(self).shown += 1
                return "<counted>"

        previous = scanner_executor.ASH_LOGGER.level
        scanner_executor.ASH_LOGGER.setLevel(logging.INFO)
        try:
            context = _context(tmp_path)
            row = _one_row(context, _scanner(context, _Counted()))
        finally:
            scanner_executor.ASH_LOGGER.setLevel(previous)

        assert row.status == ScannerStatus.ERROR, row.errors
        assert _Counted.shown == 0

    @pytest.mark.parametrize("empty", [{}, []], ids=["dict", "list"])
    def test_an_empty_result_is_refused_not_read_as_missing_dependencies(
        self, tmp_path, empty
    ):
        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, empty))

        assert row.status == ScannerStatus.ERROR, (row.status, row.errors)
        assert any("could not be graded" in error for error in row.errors), row.errors
        assert row.dependencies_satisfied is True
        assert row.missing_reason is None

    def test_false_alone_is_still_missing(self, tmp_path):
        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, False))

        assert row.status == ScannerStatus.MISSING
        assert row.dependencies_satisfied is False

    def test_a_target_never_scanned_records_no_times_or_counters(
        self, tmp_path, monkeypatch
    ):
        """The plugin's times and counters are the last scan's; a refused
        target copied them and inflated the coverage sums."""
        _refuse_sandbox(monkeypatch, "backend refused", grades_missing=False)
        context = _context(tmp_path)
        scanner = _scanner(context, _sarif())
        scanner.targets_attempted = 3
        scanner.targets_failed = 1
        scanner.inputs_not_scanned = [{"path": "a.lock", "reason": "offline"}]

        row = _one_row(context, scanner)

        assert row.status == ScannerStatus.ERROR
        assert row.start_time is None and row.end_time is None, row
        assert row.duration is None
        assert row.targets_attempted is None
        assert row.targets_failed == 0
        assert row.inputs_not_scanned == []

    def test_a_failed_dict_with_no_errors_gets_a_reason(self, tmp_path):
        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, {"status": "failed"}))

        assert row.status == ScannerStatus.ERROR
        assert any("failed without saying why" in e for e in row.errors), row.errors

    def test_the_refusal_names_the_plugins_status_redacted(self, tmp_path, monkeypatch):
        _plugin_values(monkeypatch, CANARY)
        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, {"status": f"odd {CANARY}"}))

        assert row.status == ScannerStatus.ERROR
        assert any("does not say its tool completed" in e for e in row.errors), (
            row.errors
        )
        assert not any(CANARY in e for e in row.errors), row.errors

    def test_a_negative_target_counter_is_warned_about_once(
        self, tmp_path, monkeypatch
    ):
        warnings = _record_log(monkeypatch, "warning")
        context = _context(tmp_path)
        scanner = _scanner(context, _sarif())
        scanner.targets_attempted = -1

        _one_row(context, scanner)

        negative = [line for line in warnings if "cannot be negative" in line]
        assert len(negative) == 1, warnings

    def test_unevaluated_targets_and_a_timeout_reach_a_row_already_error(
        self, tmp_path
    ):
        """A result the executor grades ERROR on its own (a failed dict) still
        names the targets the tool never evaluated and the recorded timeout."""

        def _tool_records(plugin):
            plugin.record_unevaluated_target("second.yaml")
            plugin._scan_timed_out_after = 7.0

        context = _context(tmp_path)
        scanner = _scanner(
            context,
            {"status": "failed", "errors": ["tool said no"]},
            after_scan=_tool_records,
        )

        row = _one_row(context, scanner)

        assert row.status == ScannerStatus.ERROR
        assert any(
            "no rule was evaluated against second.yaml" in e for e in row.errors
        ), row.errors
        assert any("timed out after" in e for e in row.errors), row.errors

    def test_a_skipped_reason_writes_the_home_directory_as_a_tilde(
        self, tmp_path, monkeypatch
    ):
        home = str(Path.home())
        monkeypatch.setattr(
            _ScriptedScanner,
            "nothing_scanned_reason",
            f"no lockfile under {home}/project",
            raising=False,
        )
        context = _context(tmp_path)
        scanner = _scanner(context, _sarif())
        scanner.targets_attempted = 0

        row = _one_row(context, scanner)

        assert row.status == ScannerStatus.SKIPPED, (row.status, row.errors)
        assert home not in (row.skipped_reason or ""), row.skipped_reason
        assert "~/project" in (row.skipped_reason or ""), row.skipped_reason

    def test_the_row_is_named_as_the_task_is(self, tmp_path):
        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, _sarif()), name="display-name")

        assert row.scanner_name == "display-name"


class TestTheRunLoops:
    def test_a_scanner_with_no_row_is_not_recorded_as_completed(self, tmp_path):
        context = _context(tmp_path)
        scanner = _scanner(context, _sarif())
        missing = [{"path": tmp_path / "nowhere", "type": "source"}]
        executor = _executor(context, [("scripted", scanner, missing)])

        executor.run_sequential(AshAggregatedResults())

        assert executor.completed_scanners == []

    def test_a_failed_scanner_is_not_shown_completed_in_green(self, tmp_path):
        """A scan() that raised and a dict that said "failed" each grade their
        target ERROR inside the per-target handler, so the scanner's turn is a
        recorded one with an ERROR row: shown with errors, never green."""
        context = _context(tmp_path)
        raising = _scanner(context, RuntimeError("the tool exploded"))
        errored = _scanner(context, {"status": "failed", "errors": ["tool said no"]})
        clean = _scanner(context, _sarif())
        executor = _executor(
            context,
            [
                ("raising", raising, _targets(context)),
                ("errored", errored, _targets(context)),
                ("clean", clean, _targets(context)),
            ],
        )

        executor.run_sequential(AshAggregatedResults())

        descriptions = [
            call.kwargs.get("description", "")
            for call in executor.progress_display.update_task.call_args_list
        ]
        assert "[green](clean) Completed scan" in descriptions, descriptions
        assert not any(
            d.startswith(("[green](raising)", "[green](errored)")) for d in descriptions
        ), descriptions
        assert any("(raising)" in d and "with errors" in d for d in descriptions)
        assert any("(errored)" in d and "with errors" in d for d in descriptions)

    def test_a_run_that_did_not_succeed_is_shown_failed_in_red(
        self, tmp_path, monkeypatch
    ):
        """The run itself failed (the executor's own wrapper says so): red."""
        context = _context(tmp_path)
        executor = _executor(
            context, [("broken", _scanner(context, _sarif()), _targets(context))]
        )
        monkeypatch.setattr(
            executor, "_safe_execute_scanner", lambda name, plugin, targets: ([], False)
        )

        executor.run_sequential(AshAggregatedResults())

        descriptions = [
            call.kwargs.get("description", "")
            for call in executor.progress_display.update_task.call_args_list
        ]
        assert "[red](broken) Scan failed" in descriptions, descriptions
        assert executor.completed_scanners == []

    def test_sequential_scan_complete_passes_a_copy_of_the_remaining_list(
        self, tmp_path
    ):
        seen = []

        def _notify(event_type, **kwargs):
            if "remaining_scanners" in kwargs:
                seen.append(kwargs["remaining_scanners"])

        context = _context(tmp_path)
        executor = _executor(
            context,
            [
                ("first", _scanner(context, _sarif()), _targets(context)),
                ("second", _scanner(context, _sarif()), _targets(context)),
            ],
            notify_fn=_notify,
        )

        executor.run_sequential(AshAggregatedResults())

        assert len(seen) == 2, seen
        assert seen[0] == ["second"], seen
        assert seen[1] == [], seen

    @pytest.mark.parametrize("mode", ["run_sequential", "run_parallel"])
    def test_a_scanner_that_returned_none_is_announced_and_leaves_the_list(
        self, tmp_path, monkeypatch, mode
    ):
        """Red at the base: the None branch filed the failure row and went on, so
        the scanner stayed on the remaining list, no SCAN_COMPLETE named it, and
        the last one never read remaining_count 0."""
        seen = []

        def _notify(event_type, **kwargs):
            if "remaining_scanners" in kwargs:
                seen.append(
                    (
                        kwargs["scanner"],
                        kwargs["remaining_scanners"],
                        kwargs["succeeded"],
                        kwargs["remaining_count"],
                    )
                )

        context = _context(tmp_path)
        executor = _executor(
            context,
            [("lost", _scanner(context, _sarif()), _targets(context))],
            notify_fn=_notify,
        )
        monkeypatch.setattr(
            executor,
            "_safe_execute_scanner",
            lambda name, plugin, targets: (None, False),
        )

        getattr(executor, mode)(AshAggregatedResults())

        assert seen == [("lost", [], False, 0)], seen

    def test_a_scan_that_scanned_nothing_is_not_shown_as_clean(self):
        """A scanner with no container (every target was missing) or only
        MISSING ones scanned nothing: shown with errors, not in green."""
        from automated_security_helper.models.scan_results_container import (
            ScanResultsContainer,
        )

        outcome = ScannerExecutor._completion_outcome
        passed = ScanResultsContainer(scanner_name="x", status=ScannerStatus.PASSED)
        missing = ScanResultsContainer(scanner_name="x", status=ScannerStatus.MISSING)

        assert outcome(True, [passed]) == "clean"
        # Red at the base: "clean" for both.
        assert outcome(True, []) == "errors"
        assert outcome(True, [missing]) == "errors"
        assert outcome(True, [passed, missing]) == "errors"
        assert outcome(False, [passed]) == "failed"

    def test_parallel_mode_emits_scan_start_for_every_scanner(self, tmp_path):
        from automated_security_helper.plugins.events import AshEventType

        events = []
        context = _context(tmp_path)
        executor = _executor(
            context,
            [
                ("first", _scanner(context, _sarif()), _targets(context)),
                ("second", _scanner(context, _sarif()), _targets(context)),
            ],
            max_workers=2,
            notify_fn=lambda event_type, **kwargs: events.append(
                (event_type, kwargs.get("scanner"))
            ),
        )

        executor.run_parallel(AshAggregatedResults())

        starts = sorted(
            name for kind, name in events if kind == AshEventType.SCAN_START
        )
        assert starts == ["first", "second"], events

    def test_parallel_mode_records_each_futures_own_plugin(self, tmp_path):
        """Two tasks with one display name: the completed plugin was looked up
        by name, so the first was recorded twice and the second never."""
        context = _context(tmp_path)
        first = _scanner(context, _sarif())
        second = _scanner(context, _sarif())
        executor = _executor(
            context,
            [("dup", first, _targets(context)), ("dup", second, _targets(context))],
            max_workers=2,
        )

        executor.run_parallel(AshAggregatedResults())

        recorded = [id(plugin) for plugin in executor.completed_scanners]
        assert sorted(recorded) == sorted([id(first), id(second)]), recorded

    def test_a_cancel_from_one_scanner_sets_the_scans_event(self, tmp_path):
        """Set, the running siblings' tools stop; unset, the drain waited for
        each of them to run to its end."""
        event = threading.Event()
        waited = {}

        def _wait_for_the_event(plugin):
            started = time.monotonic()
            waited["set"] = event.wait(5)
            waited["seconds"] = time.monotonic() - started

        context = _context(tmp_path)
        # The sibling is in its scan, waiting, before the cancel lands: a
        # cancel seen before it started would refuse its start instead.
        cancelling = _scanner(
            context,
            ScanCancelled("cancelled by a scanner"),
            after_scan=lambda plugin: time.sleep(0.3),
        )
        sibling = _scanner(context, _sarif(), after_scan=_wait_for_the_event)
        executor = _executor(
            context,
            [
                ("cancelling", cancelling, _targets(context)),
                ("sibling", sibling, _targets(context)),
            ],
            max_workers=2,
        )

        with cancel_scope(event):
            with pytest.raises(ScanCancelled):
                executor.run_parallel(AshAggregatedResults())

        assert event.is_set()
        assert waited.get("set") is True, waited
        assert waited["seconds"] < 4, waited

    def test_a_scanner_whose_bookkeeping_raised_is_announced_as_a_failed_turn(
        self, tmp_path, monkeypatch
    ):
        """The progress update raising sends the first scanner down the except
        path: it is taken off the remaining list, so the next scanner's
        SCAN_COMPLETE no longer names it as running; its own SCAN_COMPLETE is
        sent with succeeded False (every finished turn is announced, so a
        failed last scanner still ends the completion logger's count), and the
        processor error of its failure container is logged redacted."""
        from automated_security_helper.plugins.events import AshEventType

        _plugin_values(monkeypatch, CANARY)
        errors = _record_log(monkeypatch, "error")
        completions = []

        def _notify(event_type, **kwargs):
            if event_type == AshEventType.SCAN_COMPLETE:
                completions.append(
                    (
                        kwargs["scanner"],
                        kwargs["remaining_scanners"],
                        kwargs["succeeded"],
                    )
                )

        def _process(container, aggregated):
            if container.target_type is None:
                raise ValueError(f"cannot file the failure: {CANARY}")
            return aggregated

        context = _context(tmp_path)
        executor = _executor(
            context,
            [
                ("first", _scanner(context, _sarif()), _targets(context)),
                ("second", _scanner(context, _sarif()), _targets(context)),
            ],
            notify_fn=_notify,
            process_results_fn=_process,
        )
        raised = []

        def _update_task(**kwargs):
            # Once: the first scanner's completion update, inside the try. The
            # except path's own update must go through, or the raise would
            # escape it.
            if kwargs.get("completed") == 100 and not raised:
                raised.append(True)
                raise RuntimeError("the display is gone")

        executor.progress_display.update_task.side_effect = _update_task

        executor.run_sequential(AshAggregatedResults())

        assert completions == [
            ("first", ["second"], False),
            ("second", [], True),
        ], completions
        assert any("Failed to process error results" in line for line in errors), errors
        assert not any(CANARY in line for line in errors), errors
