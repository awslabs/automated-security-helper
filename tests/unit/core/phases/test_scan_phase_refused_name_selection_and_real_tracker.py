# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner whose name the tracker refuses is selected first, and the fixes hold
against the real tracker and the real loader.

A review of ``test_scan_phase_converted_tree_and_unconstructed_scanners`` found
that the refused-name path recorded ERROR before any selection step and left the
name out of the allowlist check, and that its tests ran against a mocked tracker
and a hand-built load-record key. Each test here is red on the tree that carried
the defect it names:

* an excluded, disabled or not-allowlisted scanner whose name the tracker
  refuses is recorded SKIPPED, excluded, as an unconstructed one is;
* a ``--scanners`` list naming only the refused scanner is not refused as a
  misspelling, because the scanner exists and has a row;
* with the REAL ``ScannerValidationManager``, a refused scanner beside one that
  executes is recorded ERROR and the other runs, and the later passes do not
  raise on the refused name again;
* the key the REAL loader records for a lost built-in package is the one the
  scan phase reads as "every built-in scanner is lost";
* the record the orchestrator reads for "the scan phase ran to its end" is
  written after the completeness pass has returned, so a pass that raised
  (and was swallowed) still leaves it.

The fixtures mirror the sibling module's.
"""

from __future__ import annotations

import importlib
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import (
    _BUILTIN_PLUGIN_MODULE_PREFIX,
    SCAN_PHASE_COMPLETION_CHECKPOINT,
    ScanPhase,
    _loses_builtin_scanners,
    scan_phase_completed,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scanner_validation import (
    ScannerValidationManager,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


@pytest.fixture
def mock_plugin_context(tmp_path):
    ctx = MagicMock()
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("print('hello')")
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    ctx.source_dir = source_dir
    ctx.work_dir = work_dir
    ctx.output_dir = output_dir
    ctx.config = MagicMock()
    ctx.config.get_plugin_config.return_value = None
    ctx.config.global_settings.ignore_paths = []
    ctx.ignore_suppressions = False
    ctx.cached_source_files = []
    ctx.plugin_load_record = {}
    return ctx


@pytest.fixture
def mock_progress_display():
    display = MagicMock()
    display.add_task.return_value = 1
    return display


def _make_scanner_class(name: str, enabled: bool = True):
    plugin_cls = MagicMock()
    plugin_cls.__name__ = name

    plugin_instance = MagicMock()
    plugin_instance.__class__ = plugin_cls
    plugin_instance.__class__.__name__ = name
    config = MagicMock()
    config.name = name
    config.enabled = enabled
    config.options.severity_threshold = "HIGH"
    plugin_instance.config = config
    plugin_instance.validate_plugin_dependencies.return_value = True
    plugin_instance.dependencies_satisfied = True
    plugin_instance.is_python_only.return_value = True
    plugin_instance.errors = []
    plugin_instance.output = []
    plugin_instance.exit_code = 0
    plugin_instance.start_time = datetime(2024, 1, 1, 10, 0, 0)
    plugin_instance.end_time = datetime(2024, 1, 1, 10, 0, 5)
    plugin_instance.context = None
    plugin_instance.scan.return_value = {"status": "success"}

    plugin_cls.return_value = plugin_instance
    return plugin_cls


@pytest.fixture
def scan_phase(mock_plugin_context, mock_progress_display):
    """The phase over a MOCKED tracker that refuses the class-shaped name."""
    with patch(
        "automated_security_helper.core.phases.scan_phase.ScannerValidationManager"
    ) as MockValMgr:
        mock_val_mgr = MagicMock(spec=ScannerValidationManager)
        mock_val_mgr.validate_registered_scanners.return_value = None
        mock_val_mgr.validate_scanner_enablement.return_value = None

        checkpoint = MagicMock()
        checkpoint.get_missing_scanners.return_value = []
        checkpoint.get_unexpected_scanners.return_value = []
        checkpoint.has_issues.return_value = False
        checkpoint.checkpoint_name = "test"
        checkpoint.timestamp = datetime(2024, 1, 1)
        checkpoint.expected_scanners = []
        checkpoint.actual_scanners = []
        checkpoint.discrepancies = []
        checkpoint.errors = []
        checkpoint.metadata = {}
        mock_val_mgr.validate_task_queue.return_value = checkpoint
        mock_val_mgr.validate_execution_completion.return_value = checkpoint
        mock_val_mgr.ensure_complete_results.return_value = checkpoint
        mock_val_mgr.report_execution_discrepancies.return_value = {}
        mock_val_mgr.report_result_completeness.return_value = {}
        MockValMgr.return_value = mock_val_mgr

        phase = ScanPhase(
            plugin_context=mock_plugin_context,
            plugins=[],
            progress_display=mock_progress_display,
        )
        phase.validation_manager = mock_val_mgr

        def refuse_class_shaped_names(scanner_name, **_state):
            if scanner_name.endswith("Scanner"):
                raise ValueError(
                    f"Scanner name looks like a class name: {scanner_name!r}"
                )

        mock_val_mgr.update_scanner_state.side_effect = refuse_class_shaped_names
        return phase


class TestARefusedNameIsSelectedBeforeItIsDiagnosed:
    def test_an_excluded_scanner_with_a_refused_name_is_skipped(self, scan_phase):
        scan_phase.plugins = [_make_scanner_class("FooScanner")]

        results = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(),
            excluded_scanners=["FooScanner"],
            parallel=False,
        )

        row = results.scanner_results["FooScanner"]
        # Red at the base: ERROR, excluded False, and the completeness gate
        # failed a run that ran everything it selected.
        assert row.status == ScannerStatus.SKIPPED
        assert row.excluded is True

    def test_a_disabled_scanner_with_a_refused_name_is_skipped(self, scan_phase):
        scan_phase.plugins = [_make_scanner_class("FooScanner", enabled=False)]

        results = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        row = results.scanner_results["FooScanner"]
        assert row.status == ScannerStatus.SKIPPED
        assert row.excluded is True

    def test_a_scanner_left_off_the_allowlist_with_a_refused_name_is_skipped(
        self, scan_phase
    ):
        scan_phase.plugins = [
            _make_scanner_class("FooScanner"),
            _make_scanner_class("bandit"),
        ]

        results = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(),
            enabled_scanners=["bandit"],
            parallel=False,
        )

        row = results.scanner_results["FooScanner"]
        assert row.status == ScannerStatus.SKIPPED
        assert row.excluded is True

    def test_a_selected_scanner_with_a_refused_name_is_still_an_error(self, scan_phase):
        """The control: selected and refused is the failure the gate has to see."""
        scan_phase.plugins = [_make_scanner_class("FooScanner")]

        results = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        row = results.scanner_results["FooScanner"]
        assert row.status == ScannerStatus.ERROR
        assert row.excluded is False


class TestARefusedNameIsAKnownNameForTheAllowlist:
    def test_naming_only_the_refused_scanner_is_not_a_misspelling(self, scan_phase):
        scan_phase.plugins = [_make_scanner_class("FooScanner")]

        # Red at the base: the refused instance was dropped before the known
        # names were built, so a list naming only it matched nothing and the run
        # was refused as a misspelled selection, with an ERROR row for it.
        results = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(),
            enabled_scanners=["FooScanner"],
            parallel=False,
        )

        assert results.scanner_results["FooScanner"].status == ScannerStatus.ERROR


class TestTheFixesHoldAgainstTheRealTracker:
    def test_a_refused_scanner_beside_one_that_runs(
        self, mock_plugin_context, mock_progress_display
    ):
        foo = _make_scanner_class("FooScanner")
        bandit = _make_scanner_class("bandit")
        phase = ScanPhase(
            plugin_context=mock_plugin_context,
            plugins=[foo, bandit],
            progress_display=mock_progress_display,
        )
        assert isinstance(phase.validation_manager, ScannerValidationManager)

        # The real tracker refuses the class-shaped name at registration; the
        # later passes (enablement, task queue, completion, completeness) then
        # read the results that carry the refused row, and raise nowhere.
        results = phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        refused = results.scanner_results["FooScanner"]
        assert refused.status == ScannerStatus.ERROR
        assert refused.excluded is False
        # The other scanner ran: its scan() was called and the real tracker holds
        # its state. The refused name was never registered, so the completeness
        # pass expects bandit alone and, reading a completed tracked state as
        # present (the phase writes no row for an executed scanner on this
        # path, by design), counts bandit alone. Whether such a scanner gets a
        # row before the metrics rebuild is the phase's design, not asserted.
        bandit.return_value.scan.assert_called()
        assert "bandit" in phase.validation_manager.scanner_states
        assert "FooScanner" not in phase.validation_manager.scanner_states
        completeness = [
            checkpoint
            for checkpoint in results.validation_checkpoints
            if isinstance(checkpoint, dict)
            and checkpoint.get("checkpoint_name") == "result_completeness"
        ]
        assert completeness and completeness[-1]["expected_scanners"] == ["bandit"]
        assert completeness[-1]["actual_scanners"] == ["bandit"]

    def test_an_excluded_refused_scanner_is_skipped_with_the_real_tracker(
        self, mock_plugin_context, mock_progress_display
    ):
        phase = ScanPhase(
            plugin_context=mock_plugin_context,
            plugins=[_make_scanner_class("FooScanner")],
            progress_display=mock_progress_display,
        )

        results = phase._execute_phase(
            aggregated_results=AshAggregatedResults(),
            excluded_scanners=["FooScanner"],
            parallel=False,
        )

        row = results.scanner_results["FooScanner"]
        assert row.status == ScannerStatus.SKIPPED
        assert row.excluded is True


class TestTheLoaderRecordsTheKeyTheScanPhaseReads:
    def test_a_lost_builtin_package_is_recorded_under_the_prefix(self, monkeypatch):
        # Imported here: the loader's own imports resolve forward references
        # this test's modules are part of, so a top-level import would make
        # collection fail on them (the scan phase imports it lazily too).
        from automated_security_helper.plugins import loader

        original_import = importlib.import_module

        def import_module_losing_the_builtins(name, package=None):
            if name == loader.INTERNAL_PLUGIN_PACKAGE:
                raise ImportError(f"No module named {name!r} (forced by the test)")
            return original_import(name, package)

        monkeypatch.setattr(
            loader.importlib, "import_module", import_module_losing_the_builtins
        )
        record = {}

        loader.load_internal_plugins(record)

        # The key the loader writes is the one _loses_builtin_scanners reads, so
        # a run that lost its built-in package gets its roster and its row.
        assert list(record) == [loader.INTERNAL_PLUGIN_PACKAGE]
        (key,) = record
        assert _loses_builtin_scanners(key)
        assert key == _BUILTIN_PLUGIN_MODULE_PREFIX
        assert "ImportError" in record[key].recorded


class TheCompletenessPassRaised(RuntimeError):
    pass


class TestACompletedPhaseIsRecordedWhenItsCompletenessPassRaises:
    def test_the_marker_is_written_after_a_raising_completeness_pass(
        self, mock_plugin_context, mock_progress_display
    ):
        """The orchestrator's record of a finished scan does not ride the diagnostic.

        The completeness pass catches its own errors and lets the phase return
        normally ("scan will continue"), and the record the orchestrator read
        used to be the checkpoint that pass appends inside its try. A pass that
        raised then left a completed phase with no record of it, and a later
        phase's failure wrote no results file. Red at the base: no checkpoint
        at all was appended by the raising pass, so ``scan_phase_completed``
        read False on a phase that returned its results.
        """
        phase = ScanPhase(
            plugin_context=mock_plugin_context,
            plugins=[_make_scanner_class("bandit")],
            progress_display=mock_progress_display,
        )
        assert isinstance(phase.validation_manager, ScannerValidationManager)

        def ensure_complete_results_raises(aggregated_results):
            raise TheCompletenessPassRaised("forced by the test")

        phase.validation_manager.ensure_complete_results = (
            ensure_complete_results_raises
        )

        results = phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        names = [
            checkpoint.get("checkpoint_name")
            for checkpoint in results.validation_checkpoints
            if isinstance(checkpoint, dict)
        ]
        # The pass raised before its checkpoint, so the diagnostic is absent...
        assert "result_completeness" not in names
        # ...and the phase's own marker, written after the pass returned, is
        # the one the orchestrator reads.
        assert names[-1] == SCAN_PHASE_COMPLETION_CHECKPOINT
        assert scan_phase_completed(results) is True

    def test_the_marker_is_the_last_checkpoint_of_a_phase_whose_pass_ran(
        self, mock_plugin_context, mock_progress_display
    ):
        """The control: with the pass intact, both records are there, marker last."""
        phase = ScanPhase(
            plugin_context=mock_plugin_context,
            plugins=[_make_scanner_class("bandit")],
            progress_display=mock_progress_display,
        )

        results = phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        names = [
            checkpoint.get("checkpoint_name")
            for checkpoint in results.validation_checkpoints
            if isinstance(checkpoint, dict)
        ]
        assert "result_completeness" in names
        assert names[-1] == SCAN_PHASE_COMPLETION_CHECKPOINT
        assert scan_phase_completed(results) is True
