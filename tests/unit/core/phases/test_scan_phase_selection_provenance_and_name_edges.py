# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Edges of ``ScanPhase`` in how it selects, names and reports scanners.

Each test is red on the tree that carried the defect:

* A plugin whose config access raised ended the phase in the name helper.
* A phase built without a progress display failed at its first ``add_task``.
* A second run kept the first run's shard provenance and validation record, and a
  sharded run that built no scanner recorded no provenance at all.
* Two scanner classes with one name were both queued and one row replaced the other.
* A self-cancelling selection passed straight to the phase ran zero scanners, a
  misspelled exclusion said nothing, and ``--python-only`` could leave nothing of
  an allowlist to run with no word.
* A refusal for an unloaded community scanner dropped the misspelled names beside it.
* A platform reason was not redacted, a nothing-to-scan reason carried the home
  directory, and an in-tree refusal replaced the scanner's own words.
* One scanner's failed results write ended the phase from the reconciliation loop.
* The completion check derived names by a second rule and was skipped on a nameless
  config, and the completeness log called scanners it only listed "added".
* The cached file list named a nested work directory's files twice, and a result
  processor was built on every ``_process_results`` call.
"""

from __future__ import annotations

import contextlib
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.exceptions import ScannerSelectionError
from automated_security_helper.core.phases import scan_phase as scan_phase_module
from automated_security_helper.core.phases.scan_phase import (
    ScanPhase,
    _declared_scanner_roster,
    _scanner_display_name,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.models.scanner_validation import (
    ScannerValidationManager,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

ENV_VALUE = "env-read-canary-5c1d2-value"


@pytest.fixture
def ctx(tmp_path):
    context = MagicMock()
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("print('hello')")
    (tmp_path / "work").mkdir()
    (tmp_path / "output").mkdir()
    context.source_dir = source_dir
    context.work_dir = tmp_path / "work"
    context.output_dir = tmp_path / "output"
    context.config = MagicMock()
    context.config.get_plugin_config.return_value = None
    context.config.global_settings.ignore_paths = []
    context.config._environment_values = []
    context.ignore_suppressions = False
    context.cached_source_files = []
    context.plugin_load_record = {}
    return context


@pytest.fixture
def logger(monkeypatch):
    """The phase's logger, replaced so every level is read the same way."""
    recorder = MagicMock()
    monkeypatch.setattr(scan_phase_module, "ASH_LOGGER", recorder)
    return recorder


def _lines(recorder, level):
    return [str(call.args[0]) for call in getattr(recorder, level).call_args_list]


def _scanner_class(name, *, enabled=True, python_only=True, deps=True):
    """A scanner class double named ``<Name>Scanner`` with config name *name*."""
    class_name = name.replace("-", "").replace("_", "").capitalize() + "Scanner"
    plugin_cls = MagicMock()
    plugin_cls.__name__ = class_name
    instance = MagicMock()
    instance.__class__ = plugin_cls
    instance.__class__.__name__ = class_name
    config = MagicMock()
    config.name = name
    config.enabled = enabled
    config.options.severity_threshold = "HIGH"
    instance.config = config
    instance.validate_plugin_dependencies.return_value = deps
    instance.dependencies_satisfied = deps
    instance.is_python_only.return_value = python_only
    instance.unsupported_platform_reason.return_value = None
    instance.nothing_to_scan_reason.return_value = None
    instance.missing_dependency_reason.return_value = None
    instance.errors = []
    instance.output = []
    instance.exit_code = 0
    instance.start_time = datetime(2024, 1, 1, 10, 0, 0)
    instance.end_time = datetime(2024, 1, 1, 10, 0, 5)
    instance.context = None
    plugin_cls.return_value = instance
    return plugin_cls


def _checkpoint(missing=()):
    checkpoint = MagicMock()
    checkpoint.get_missing_scanners.return_value = list(missing)
    checkpoint.get_unexpected_scanners.return_value = []
    checkpoint.has_issues.return_value = False
    checkpoint.checkpoint_name = "test"
    checkpoint.timestamp = datetime(2024, 1, 1)
    checkpoint.expected_scanners = []
    checkpoint.actual_scanners = []
    checkpoint.discrepancies = []
    checkpoint.errors = []
    checkpoint.metadata = {}
    return checkpoint


def _manager():
    manager = MagicMock(spec=ScannerValidationManager)
    manager.validate_registered_scanners.return_value = None
    manager.validate_scanner_enablement.return_value = None
    checkpoint = _checkpoint()
    manager.validate_task_queue.return_value = checkpoint
    manager.validate_execution_completion.return_value = checkpoint
    manager.ensure_complete_results.return_value = checkpoint
    manager.report_execution_discrepancies.return_value = {}
    manager.report_result_completeness.return_value = {}
    return manager


def _phase(ctx, plugins=(), progress="default"):
    kwargs = {}
    if progress == "default":
        kwargs["progress_display"] = MagicMock(add_task=MagicMock(return_value=1))
    elif progress is not None:
        kwargs["progress_display"] = progress
    with patch.object(scan_phase_module, "ScannerValidationManager") as manager_class:
        manager_class.return_value = _manager()
        phase = ScanPhase(plugin_context=ctx, plugins=list(plugins), **kwargs)
    phase.validation_manager = _manager()
    return phase


def _run(phase, **kwargs):
    return phase._execute_phase(
        aggregated_results=AshAggregatedResults(), parallel=False, **kwargs
    )


class TestTheExpectedRoster:
    class _Segment:
        model_fields: dict = {}

        def __init__(self, extra):
            self.model_extra = extra

    def test_a_disabled_extras_section_is_still_listed(self):
        segment = self._Segment(
            {
                "kept": {"enabled": True},
                "off-dict": {"enabled": False},
                "off-model": SimpleNamespace(enabled=False),
                "on-model": SimpleNamespace(enabled=True),
                "bare": {},
            }
        )

        roster = _declared_scanner_roster(SimpleNamespace(scanners=segment))

        # The roster is what the configuration declares, not what is switched
        # on: a scanner that is left off is still listed.
        assert roster == ["kept", "off-dict", "off-model", "on-model", "bare"]


class TestTheDisplayName:
    def test_a_config_access_that_raises_falls_back_to_the_class(self):
        class Exploding:
            @property
            def config(self):
                raise RuntimeError("config is not ready")

        # Red at the base: the RuntimeError escaped.
        assert _scanner_display_name(Exploding()) == "exploding"

    def test_a_configured_name_still_wins(self):
        plugin = SimpleNamespace(config=SimpleNamespace(name="detect-secrets"))
        assert _scanner_display_name(plugin) == "detect-secrets"


class TestAPhaseWithoutAProgressDisplay:
    def test_it_runs(self, ctx):
        phase = _phase(ctx, progress=None)

        # Red at the base: 'NoneType' object has no attribute 'add_task'.
        results = _run(phase)

        assert isinstance(results, AshAggregatedResults)


class TestShardProvenance:
    def test_a_second_run_does_not_keep_the_first_runs_split(self, ctx):
        phase = _phase(ctx, [_scanner_class(n) for n in ("bandit", "semgrep")])
        _run(phase, shard_index=0, shard_count=2)
        assert phase._shard_assignment is not None

        _run(phase)

        # Red at the base: still the first run's assignment.
        assert phase._shard_assignment is None

    def test_a_sharded_run_that_built_no_scanner_still_records_its_shard(self, ctx):
        phase = _phase(ctx, [])

        _run(phase, shard_index=1, shard_count=3)

        # Red at the base: None, so the results read as an unsharded scan.
        assignment = phase._shard_assignment
        assert assignment is not None
        assert (assignment.shard_index, assignment.shard_count) == (1, 3)
        assert assignment.assigned_scanners == []

    def test_a_later_run_gets_a_fresh_validation_record(self, ctx, monkeypatch):
        class RealLooking:
            """Exactly this class, as the phase builds, answering as the double."""

            def __init__(self, plugin_context):
                self._inner = _manager()

            def __getattr__(self, name):
                return getattr(self._inner, name)

        monkeypatch.setattr(scan_phase_module, "ScannerValidationManager", RealLooking)
        phase = ScanPhase(
            plugin_context=ctx,
            plugins=[],
            progress_display=MagicMock(add_task=MagicMock(return_value=1)),
        )
        first = phase.validation_manager
        assert type(first) is RealLooking

        _run(phase)
        assert phase.validation_manager is first

        _run(phase)
        # Red at the base: the first run's tracker, backfilling its scanners.
        assert phase.validation_manager is not first
        assert type(phase.validation_manager) is RealLooking


class TestTwoScannersWithOneName:
    def test_the_second_is_recorded_not_run(self, ctx, logger):
        first = _scanner_class("twin")
        second = _scanner_class("twin")
        second.__name__ = "OtherTwinScanner"
        phase = _phase(ctx, [first, second])

        with patch.object(scan_phase_module, "ScannerExecutor") as executor_class:
            executor_class.return_value.completed_scanners = []
            results = _run(phase)

        queued = [task[0] for task in executor_class.call_args.kwargs["scanner_tasks"]]
        # Red at the base: ['twin', 'twin'], both queued and one row over the other.
        assert queued == ["twin"]
        duplicate_rows = [key for key in results.scanner_results if "OtherTwin" in key]
        assert len(duplicate_rows) == 1
        row = results.scanner_results[duplicate_rows[0]]
        assert row.status == ScannerStatus.ERROR
        assert any(
            "is already carried by" in line for line in _lines(logger, "error")
        ), _lines(logger, "error")

    def test_the_control_distinct_names_both_run(self, ctx):
        phase = _phase(ctx, [_scanner_class("one"), _scanner_class("two")])

        with patch.object(scan_phase_module, "ScannerExecutor") as executor_class:
            executor_class.return_value.completed_scanners = []
            _run(phase)

        queued = [task[0] for task in executor_class.call_args.kwargs["scanner_tasks"]]
        assert sorted(queued) == ["one", "two"]

    def test_a_later_carrier_the_operator_excluded_is_skipped_not_error(self, ctx):
        """Selection before diagnosis, as for every scanner that does not run.
        Red at the base: the duplicate was recorded ERROR before any selection
        step, so `--exclude-scanners twin` failed the completeness gate on a run
        that ran everything it selected."""
        first = _scanner_class("twin")
        second = _scanner_class("twin")
        second.__name__ = "OtherTwinScanner"
        phase = _phase(ctx, [first, second])

        with patch.object(scan_phase_module, "ScannerExecutor") as executor_class:
            executor_class.return_value.completed_scanners = []
            results = _run(phase, excluded_scanners=["twin"])

        queued = [task[0] for task in executor_class.call_args.kwargs["scanner_tasks"]]
        assert queued == []
        # Both carriers are recorded SKIPPED, excluded: the first under its name,
        # the later one under a row of its own, named by its class (it is not a
        # failure, but a row keyed by the shared name would be the first's).
        row = results.scanner_results["twin"]
        assert row.status == ScannerStatus.SKIPPED
        assert row.excluded is True
        later_rows = [key for key in results.scanner_results if "OtherTwin" in key]
        assert len(later_rows) == 1
        assert results.scanner_results[later_rows[0]].status == ScannerStatus.SKIPPED
        assert results.scanner_results[later_rows[0]].excluded is True

    def test_a_later_holder_that_is_not_selected_leaves_the_first_holders_row_alone(
        self, ctx
    ):
        """The first holder runs; the later one is left out by a Python-only run.
        Red at the base: the later holder's SKIPPED row was written under the
        shared name, so it was the first holder's row, and the name went on the
        excluded list the enablement validation reads although the first holder
        was queued. Now the later holder's row is keyed by its class and the
        shared name stays out of the excluded list."""
        first = _scanner_class("twin", python_only=True)
        second = _scanner_class("twin", python_only=False)
        second.__name__ = "OtherTwinScanner"
        phase = _phase(ctx, [first, second])

        with patch.object(scan_phase_module, "ScannerExecutor") as executor_class:
            executor_class.return_value.completed_scanners = []
            results = _run(phase, python_based_plugins_only=True)

        queued = [task[0] for task in executor_class.call_args.kwargs["scanner_tasks"]]
        assert queued == ["twin"]
        # The phase writes no row for a scanner it queues (the executor files it),
        # so a "twin" row here would be the later holder's. Red at the base: a
        # SKIPPED, excluded row.
        assert "twin" not in results.scanner_results
        later_rows = [key for key in results.scanner_results if "OtherTwin" in key]
        assert len(later_rows) == 1
        assert later_rows[0].startswith("twin (")
        later = results.scanner_results[later_rows[0]]
        assert later.status == ScannerStatus.SKIPPED
        assert later.excluded is True
        enablement = phase.validation_manager.validate_scanner_enablement
        excluded = enablement.call_args.kwargs["excluded_scanners"]
        assert "twin" not in excluded
        assert later_rows[0] in excluded

    def test_a_third_holder_that_is_not_selected_gets_its_own_row(self, ctx):
        """Two later holders of one name left out by a Python-only run get two
        rows: the second row name is taken, so the third holder's is numbered."""
        first = _scanner_class("twin", python_only=True)
        second = _scanner_class("twin", python_only=False)
        second.__name__ = "OtherTwinScanner"
        third = _scanner_class("twin", python_only=False)
        third.__name__ = "OtherTwinScanner"
        phase = _phase(ctx, [first, second, third])

        with patch.object(scan_phase_module, "ScannerExecutor") as executor_class:
            executor_class.return_value.completed_scanners = []
            results = _run(phase, python_based_plugins_only=True)

        later_rows = sorted(
            key for key in results.scanner_results if "OtherTwin" in key
        )
        assert len(later_rows) == 2, later_rows
        assert any("#2" in key for key in later_rows), later_rows
        assert "twin" not in results.scanner_results

    def test_a_selected_later_holder_runs_when_the_first_holder_is_left_out(self, ctx):
        """Selection is decided for every holder of a name before one is chosen.
        Red at the base: the first holder was chosen in discovery order, so the
        selected later holder was recorded as a duplicate, the first was recorded
        under the name as left out, and nothing ran under the name."""
        first = _scanner_class("twin", python_only=False)
        second = _scanner_class("twin", python_only=True)
        second.__name__ = "OtherTwinScanner"
        phase = _phase(ctx, [first, second])

        with patch.object(scan_phase_module, "ScannerExecutor") as executor_class:
            executor_class.return_value.completed_scanners = []
            results = _run(phase, python_based_plugins_only=True)

        tasks = executor_class.call_args.kwargs["scanner_tasks"]
        assert [task[0] for task in tasks] == ["twin"]
        assert tasks[0][1] is second.return_value
        assert "twin" not in results.scanner_results
        left_out = [key for key in results.scanner_results if key.startswith("twin (")]
        assert len(left_out) == 1, left_out
        assert results.scanner_results[left_out[0]].status == ScannerStatus.SKIPPED
        assert results.scanner_results[left_out[0]].excluded is True
        assert not any(
            row.status == ScannerStatus.ERROR
            for row in results.scanner_results.values()
        )

    def test_the_control_no_holder_selected_keeps_the_first_as_the_name(self, ctx):
        first = _scanner_class("twin", python_only=False)
        second = _scanner_class("twin", python_only=False)
        second.__name__ = "OtherTwinScanner"
        phase = _phase(ctx, [first, second])

        with patch.object(scan_phase_module, "ScannerExecutor") as executor_class:
            executor_class.return_value.completed_scanners = []
            results = _run(phase, python_based_plugins_only=True)

        assert executor_class.call_args.kwargs["scanner_tasks"] == []
        assert results.scanner_results["twin"].status == ScannerStatus.SKIPPED
        later_rows = [key for key in results.scanner_results if "OtherTwin" in key]
        assert len(later_rows) == 1
        assert results.scanner_results[later_rows[0]].status == ScannerStatus.SKIPPED

    def test_a_later_carrier_of_a_refused_name_is_told_the_first_does_not_run(
        self, ctx, logger
    ):
        """The first holder's name was refused by the tracker, so the later
        holder's row must not say the first runs. Red at the base: the first
        was entered as the name's holder before the tracker saw it, and the
        text said "which runs"."""
        first = _scanner_class("twin")
        second = _scanner_class("twin")
        second.__name__ = "OtherTwinScanner"
        phase = _phase(ctx, [first, second])

        def refuse_twin(scanner_name, **_state):
            if scanner_name == "twin":
                raise ValueError("refused by the test")

        phase.validation_manager.update_scanner_state.side_effect = refuse_twin

        with patch.object(scan_phase_module, "ScannerExecutor") as executor_class:
            executor_class.return_value.completed_scanners = []
            results = _run(phase)

        queued = [task[0] for task in executor_class.call_args.kwargs["scanner_tasks"]]
        assert queued == []
        assert results.scanner_results["twin"].status == ScannerStatus.ERROR
        duplicate_rows = [key for key in results.scanner_results if "OtherTwin" in key]
        assert len(duplicate_rows) == 1
        assert results.scanner_results[duplicate_rows[0]].status == ScannerStatus.ERROR
        errors = _lines(logger, "error")
        assert any("so neither runs" in line for line in errors), errors
        assert not any("which runs" in line for line in errors), errors


class TestARecordedRowStandsWhenItsResultsFileCannotBeWritten:
    def test_a_duplicate_rows_failed_write_does_not_end_the_phase(self, ctx, logger):
        """The recorders for a scanner that does not run write a results container
        for the row, and one failed write used to end the whole phase before any
        scanner ran. Red at the base: the raise escaped `_execute_phase`."""
        first = _scanner_class("twin")
        second = _scanner_class("twin")
        second.__name__ = "OtherTwinScanner"
        phase = _phase(ctx, [first, second])
        real_process = phase._process_results

        def process_or_refuse(*, results, aggregated_results):
            if "OtherTwin" in results.scanner_name:
                raise OSError(13, "Permission denied", "scanners/twin (OtherTwin)")
            return real_process(results=results, aggregated_results=aggregated_results)

        phase._process_results = process_or_refuse

        with patch.object(scan_phase_module, "ScannerExecutor") as executor_class:
            executor_class.return_value.completed_scanners = []
            results = _run(phase)

        queued = [task[0] for task in executor_class.call_args.kwargs["scanner_tasks"]]
        assert queued == ["twin"]
        duplicate_rows = [key for key in results.scanner_results if "OtherTwin" in key]
        assert len(duplicate_rows) == 1
        assert results.scanner_results[duplicate_rows[0]].status == ScannerStatus.ERROR
        assert any(
            "Could not write the results of scanner" in line
            for line in _lines(logger, "error")
        ), _lines(logger, "error")

    def test_a_not_selected_rows_failed_write_does_not_end_the_phase(self, ctx, logger):
        phase = _phase(ctx, [_scanner_class("one"), _scanner_class("two")])
        real_process = phase._process_results

        def process_or_refuse(*, results, aggregated_results):
            if results.scanner_name == "two":
                raise OSError(13, "Permission denied", "scanners/two")
            return real_process(results=results, aggregated_results=aggregated_results)

        phase._process_results = process_or_refuse

        with patch.object(scan_phase_module, "ScannerExecutor") as executor_class:
            executor_class.return_value.completed_scanners = []
            results = _run(phase, excluded_scanners=["two"])

        queued = [task[0] for task in executor_class.call_args.kwargs["scanner_tasks"]]
        assert queued == ["one"]
        assert results.scanner_results["two"].status == ScannerStatus.SKIPPED
        assert results.scanner_results["two"].excluded is True


class TestEveryRecorderOfAScannerThatDidNotRunGuardsItsWrite:
    """The rows written before a scanner runs keep their own status when the
    file of the row cannot be written. Each test is red at the base for the
    recorder it names: the raise reached a wider handler."""

    @staticmethod
    def _refuse_writes(phase, matches):
        real_process = phase._process_results

        def process_or_refuse(*, results, aggregated_results):
            if matches(results):
                raise OSError(13, "Permission denied", "scanners/refused")
            return real_process(results=results, aggregated_results=aggregated_results)

        phase._process_results = process_or_refuse

    def test_a_construction_failure_row_survives_a_failed_write(self, ctx, logger):
        """Red at the base: the write sat in the handler of the constructor's
        failure, so the raise ended the phase before any scanner ran."""
        broken = _scanner_class("broken")
        broken.side_effect = RuntimeError("constructor failed")
        phase = _phase(ctx, [broken, _scanner_class("fine")])
        self._refuse_writes(phase, lambda row: row.status == ScannerStatus.ERROR)

        with patch.object(scan_phase_module, "ScannerExecutor") as executor_class:
            executor_class.return_value.completed_scanners = []
            results = _run(phase)

        queued = [task[0] for task in executor_class.call_args.kwargs["scanner_tasks"]]
        assert queued == ["fine"]
        error_rows = [
            row
            for row in results.scanner_results.values()
            if row.status == ScannerStatus.ERROR
        ]
        assert len(error_rows) == 1
        assert any(
            "Could not write the results of scanner" in line
            for line in _lines(logger, "error")
        ), _lines(logger, "error")

    def test_a_nothing_to_scan_row_stays_skipped_when_the_write_fails(self, ctx):
        """Red at the base: the raise reached the handler of the scanner's
        filtering and the reconciliation recorded the scanner MISSING."""
        scanner = _scanner_class("idle", deps=False)
        scanner.return_value.nothing_to_scan_reason.return_value = "no files to scan"
        phase = _phase(ctx, [scanner])
        self._refuse_writes(phase, lambda row: row.scanner_name == "idle")

        results = _run(phase)

        row = results.scanner_results["idle"]
        assert row.status == ScannerStatus.SKIPPED
        assert row.skipped_reason == "no files to scan"

    def test_a_missing_dependency_row_keeps_its_reason_when_the_write_fails(self, ctx):
        """Red at the base: the reconciliation recorded the scanner MISSING with
        its dependencies marked satisfied, and the reason was the unclassified
        one, so the report lost what is actually absent."""
        scanner = _scanner_class("tooled", deps=False)
        scanner.return_value.missing_dependency_reason.return_value = "tool is absent"
        phase = _phase(ctx, [scanner])
        self._refuse_writes(phase, lambda row: row.scanner_name == "tooled")

        results = _run(phase)

        row = results.scanner_results["tooled"]
        assert row.status == ScannerStatus.MISSING
        assert row.dependencies_satisfied is False
        assert row.missing_reason == "tool is absent"


class TestSelectionRefusals:
    def test_a_self_cancelling_selection_is_refused_by_the_phase(self, ctx):
        phase = _phase(ctx, [_scanner_class("bandit"), _scanner_class("semgrep")])

        # Red at the base: zero scanners ran and the run read clean.
        with pytest.raises(ScannerSelectionError, match="cancels itself"):
            _run(phase, enabled_scanners=["bandit"], excluded_scanners=["Bandit"])

    def test_the_control_an_engine_subtracted_allowlist_is_unchanged(self, ctx):
        phase = _phase(ctx, [_scanner_class("bandit"), _scanner_class("semgrep")])

        results = _run(
            phase, enabled_scanners=["semgrep"], excluded_scanners=["bandit"]
        )

        assert results.scanner_results["bandit"].excluded is True

    def test_a_misspelled_exclusion_is_said(self, ctx, logger):
        phase = _phase(
            ctx, [_scanner_class("detect-secrets"), _scanner_class("bandit")]
        )

        _run(phase, excluded_scanners=["detect_secrets", "bandit"])

        warnings = " ".join(_lines(logger, "warning"))
        # Red at the base: nothing was said.
        assert "No registered scanner matches the --exclude-scanners name" in warnings
        assert "detect_secrets" in warnings
        assert "bandit," not in warnings

    def test_python_only_that_leaves_the_allowlist_nothing_is_refused(self, ctx):
        phase = _phase(ctx, [_scanner_class("grype", python_only=False)])

        # Red at the base: zero scanners ran and the run read clean.
        with pytest.raises(ScannerSelectionError, match="Python-only"):
            _run(phase, enabled_scanners=["grype"], python_based_plugins_only=True)

    def test_the_control_a_python_only_scanner_in_the_allowlist_runs(self, ctx):
        phase = _phase(
            ctx,
            [
                _scanner_class("grype", python_only=False),
                _scanner_class("bandit", python_only=True),
            ],
        )

        results = _run(
            phase,
            enabled_scanners=["grype", "bandit"],
            python_based_plugins_only=True,
        )

        assert isinstance(results, AshAggregatedResults)

    def test_the_community_refusal_keeps_the_misspelled_names(self, ctx):
        phase = _phase(ctx, [_scanner_class("bandit")])

        def module_for(name):
            return "ash_community.fake_module" if name == "comm-scanner" else None

        with patch(
            "automated_security_helper.core.community_scanners.community_module_for",
            module_for,
        ):
            with pytest.raises(ScannerSelectionError) as raised:
                _run(phase, enabled_scanners=["comm-scanner", "bandti"])

        message = str(raised.value)
        assert "ash_community.fake_module" in message
        # Red at the base: only the hint, the misspelling dropped.
        assert "bandti" in message


class TestReasonsAreRedactedAndKeptApart:
    def test_a_platform_reason_carries_no_environment_value(self, ctx):
        ctx.config._environment_values = [ENV_VALUE]
        scanner = _scanner_class("platformed")
        scanner.return_value.unsupported_platform_reason.return_value = (
            f"needs a build under {ENV_VALUE}"
        )
        phase = _phase(ctx, [scanner])

        results = _run(phase)

        reason = results.scanner_results["platformed"].skipped_reason
        # Red at the base: the value was recorded as written.
        assert "needs a build under" in reason
        assert ENV_VALUE not in reason

    def test_a_nothing_to_scan_reason_is_written_with_a_tilde(self, ctx):
        home = Path.home().as_posix()
        scanner = _scanner_class("idle", deps=False)
        scanner.return_value.nothing_to_scan_reason.return_value = (
            f"{home}/project has nothing to scan"
        )
        phase = _phase(ctx, [scanner])

        results = _run(phase)

        row = results.scanner_results["idle"]
        assert row.status == ScannerStatus.SKIPPED
        # Red at the base: the absolute home directory.
        assert row.skipped_reason == "~/project has nothing to scan"

    def test_an_in_tree_refusal_keeps_the_scanners_own_words(self, ctx, monkeypatch):
        @contextlib.contextmanager
        def refusals():
            yield ["refused the in-tree copy ./bin/tool"]

        monkeypatch.setattr(scan_phase_module, "recording_in_tree_refusals", refusals)
        monkeypatch.setattr(
            scan_phase_module, "plugin_explains_its_own_refusal", lambda *_: True
        )
        scanner = _scanner_class("toolish", deps=False)
        scanner.return_value.missing_dependency_reason.return_value = "tool is v1.2"
        phase = _phase(ctx, [scanner])

        results = _run(phase)

        reason = results.scanner_results["toolish"].missing_reason
        assert "refused the in-tree copy ./bin/tool" in reason
        # Red at the base: the in-tree text alone.
        assert "tool is v1.2" in reason

    def test_the_generic_hook_answer_is_not_added_beside_a_refusal(
        self, ctx, monkeypatch
    ):
        @contextlib.contextmanager
        def refusals():
            yield ["refused the in-tree copy ./bin/tool"]

        monkeypatch.setattr(scan_phase_module, "recording_in_tree_refusals", refusals)
        monkeypatch.setattr(
            scan_phase_module, "plugin_explains_its_own_refusal", lambda *_: False
        )
        scanner = _scanner_class("toolish", deps=False)
        scanner.return_value.missing_dependency_reason.return_value = (
            "tool not found on PATH"
        )
        phase = _phase(ctx, [scanner])

        results = _run(phase)

        reason = results.scanner_results["toolish"].missing_reason
        assert reason == "refused the in-tree copy ./bin/tool"


class TestOneScannersFailedWriteDoesNotEndThePhase:
    def test_the_reconciliation_records_the_row_anyway(self, ctx, monkeypatch):
        broken = _scanner_class("broken")
        broken.return_value.unsupported_platform_reason.side_effect = RuntimeError(
            "hook broke"
        )
        phase = _phase(ctx, [broken, _scanner_class("fine")])
        original = ScanPhase._process_results

        def refusing(self, results, aggregated_results):
            if getattr(results, "scanner_name", None) == "broken":
                raise OSError("cannot create the results directory")
            return original(self, results, aggregated_results)

        monkeypatch.setattr(ScanPhase, "_process_results", refusing)

        # Red at the base: the OSError escaped the reconciliation loop.
        results = _run(phase)

        row = results.scanner_results["broken"]
        assert row.status == ScannerStatus.MISSING


class TestTheCompletionChecks:
    def test_a_nameless_config_does_not_skip_the_execution_check(self, ctx, logger):
        named = _scanner_class("named").return_value
        nameless = _scanner_class("nameless").return_value
        nameless.config.name = None
        phase = _phase(ctx)
        phase._completed_scanners = [named, nameless]

        phase._validate_execution_completion(AshAggregatedResults())

        # Red at the base: sorted(['named', None]) raised and the check was skipped.
        assert not any(
            "Error during execution completion validation" in line
            for line in _lines(logger, "error")
        )
        asked = phase.validation_manager.validate_execution_completion.call_args.args[0]
        assert asked == ["named", "nameless" + "scanner"]

    def test_only_what_was_added_is_called_added(self, ctx, logger):
        phase = _phase(ctx)
        checkpoint = _checkpoint(missing=["added-one", "excluded-one"])

        def ensure(aggregated_results):
            aggregated_results.scanner_results["added-one"] = ScannerTargetStatusInfo(
                status=ScannerStatus.MISSING
            )
            return checkpoint

        phase.validation_manager.ensure_complete_results.side_effect = ensure

        phase._validate_result_completeness(AshAggregatedResults())

        info = _lines(logger, "info")
        added = [line for line in info if line.startswith("Added missing scanners")]
        # Red at the base: "(2): added-one, excluded-one".
        assert added == ["Added missing scanners (1): added-one"]


class TestSmallThings:
    def test_a_work_directory_inside_the_source_tree_is_listed_once(self, ctx):
        nested = ctx.source_dir / ".ash-work"
        nested.mkdir()
        (nested / "converted.py").write_text("x = 1\n")
        ctx.work_dir = nested
        phase = _phase(ctx)

        _run(phase)

        listed = [p for p in ctx.cached_source_files if p.endswith("converted.py")]
        # Red at the base: twice.
        assert listed == [str(nested / "converted.py")]

    def test_a_missing_work_directory_is_not_warned_about(self, ctx, logger):
        ctx.work_dir = ctx.source_dir.parent / "no-such-work-directory"
        phase = _phase(ctx)

        _run(phase)

        # Red at the base: "Could not list <dir>, so nothing under it is scanned"
        # on every run that converted nothing.
        assert not any("Could not list" in line for line in _lines(logger, "warning"))
        assert phase._include_work_dir is False

    def test_a_result_processor_is_not_built_per_call(self, ctx):
        phase = _phase(ctx)
        phase._result_processor = MagicMock()

        with patch.object(scan_phase_module, "ScanResultProcessor") as constructor:
            phase._process_results(MagicMock(), AshAggregatedResults())
            phase._process_results(MagicMock(), AshAggregatedResults())

        # Red at the base: two throwaway processors.
        constructor.assert_not_called()
        assert phase._result_processor.process_container.call_count == 2
