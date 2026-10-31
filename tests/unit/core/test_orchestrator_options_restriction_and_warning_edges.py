"""Orchestrator edges that each dropped something the caller asked for.

* ``simple_mode`` and ``offline`` were declared, documented and read by nothing:
  the engine was never told about the first, and no scanner saw the second.
* A severity restriction rewrote the thresholds of the config the caller handed
  over as ``resolved_config``, skipped the config a report over saved results
  gates on, accepted a word that is not on the ladder, and printed a threshold
  that a configuration read from the environment.
* A config passed to the constructor was replaced without a word, a
  ``config_base_gate`` beside ``resolved_config`` was dropped, and a copy of an
  orchestrator shared the original's run id.
* A results file that vanished after the path was given let the scan start,
  config warnings reached the returned model after the reports were written and
  were doubled over saved results, a failure while applying metadata left the
  previous results set aside, and a cancel that arrived during the last phase
  was acted on after the results file was written.
"""

import copy
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.cancellation import (
    CancelEvent,
    ScanCancelled,
    cancel_scope,
)
from automated_security_helper.core.exceptions import ASHValidationError
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.models.asharp_model import AshAggregatedResults
from tests.utils.helpers import results_of_a_scan

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

_ORCHESTRATOR = "automated_security_helper.core.orchestrator"


def _dirs(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "proj"
    source.mkdir()
    return source, tmp_path / "out"


class _Engine:
    """Stands in for the engine: records what it saw when the phases ran."""

    def __init__(self, model=None, on_run=None):
        self._asharp_model = model
        self._on_run = on_run
        self.runs = 0

    def execute_phases(self, phases=None):
        self.runs += 1
        if self._on_run is not None:
            self._on_run()
        return self._asharp_model


def _initialize(orchestrator, engine=None, config=None):
    """initialize() with resolution and engine construction stubbed.

    Returns the patched engine class, so a test can read what it was given.
    """
    cfg = config if config is not None else AshConfig(project_name="test")
    with (
        patch(f"{_ORCHESTRATOR}.resolve_config", return_value=cfg),
        patch(
            f"{_ORCHESTRATOR}.ScanExecutionEngine",
            return_value=engine if engine is not None else MagicMock(),
        ) as engine_class,
    ):
        orchestrator.initialize()
    return engine_class


class TestTheOptionsTheCallerSet:
    def test_simple_mode_reaches_the_engine(self, tmp_path):
        source, output = _dirs(tmp_path)
        orchestrator = ASHScanOrchestrator(
            source_dir=source, output_dir=output, simple_mode=True
        )

        engine_class = _initialize(orchestrator)

        # Red at the base: the engine was built with its default, False.
        assert engine_class.call_args.kwargs["simple_mode"] is True

    def test_the_default_stays_off(self, tmp_path):
        """The control: a run that did not ask for it does not get it."""
        source, output = _dirs(tmp_path)
        orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output)

        engine_class = _initialize(orchestrator)

        assert engine_class.call_args.kwargs["simple_mode"] is False

    def test_offline_is_held_while_the_engine_is_built(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        source, output = _dirs(tmp_path)
        orchestrator = ASHScanOrchestrator(
            source_dir=source, output_dir=output, offline=True
        )
        seen = []

        def build(**kwargs):
            seen.append(os.environ.get("ASH_OFFLINE"))
            return MagicMock()

        with (
            patch(
                f"{_ORCHESTRATOR}.resolve_config",
                return_value=AshConfig(project_name="test"),
            ),
            patch(f"{_ORCHESTRATOR}.ScanExecutionEngine", side_effect=build),
        ):
            orchestrator.initialize()

        # Red at the base: nothing set the variable, so every scanner ran online.
        assert seen == ["YES"]
        assert "ASH_OFFLINE" not in os.environ

    def test_an_online_run_leaves_the_variable_alone(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        source, output = _dirs(tmp_path)
        orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output)
        seen = []

        def build(**kwargs):
            seen.append(os.environ.get("ASH_OFFLINE"))
            return MagicMock()

        with (
            patch(
                f"{_ORCHESTRATOR}.resolve_config",
                return_value=AshConfig(project_name="test"),
            ),
            patch(f"{_ORCHESTRATOR}.ScanExecutionEngine", side_effect=build),
        ):
            orchestrator.initialize()

        assert seen == [None]

    def test_offline_is_held_while_the_phases_run(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        source, output = _dirs(tmp_path)
        orchestrator = ASHScanOrchestrator(
            source_dir=source, output_dir=output, offline=True
        )
        seen = []
        engine = _Engine(
            model=AshAggregatedResults(),
            on_run=lambda: seen.append(os.environ.get("ASH_OFFLINE")),
        )
        _initialize(orchestrator, engine=engine)

        orchestrator.execute_scan(phases=["report"])

        assert seen == ["YES"]
        assert "ASH_OFFLINE" not in os.environ

    def test_the_hold_nests_with_the_callers_own(self, tmp_path, monkeypatch):
        """The CLI and the workspace hold the same value around the whole run; the
        orchestrator's hold neither fails beside it nor releases it early."""
        from automated_security_helper.utils.process_env import (
            hold_environ,
            release_environ,
        )

        monkeypatch.setenv("ASH_OFFLINE", "no")
        source, output = _dirs(tmp_path)
        orchestrator = ASHScanOrchestrator(
            source_dir=source, output_dir=output, offline=True
        )

        hold_environ("ASH_OFFLINE", "YES")
        try:
            with orchestrator._offline_scope():
                assert os.environ["ASH_OFFLINE"] == "YES"
            assert os.environ["ASH_OFFLINE"] == "YES"
        finally:
            release_environ("ASH_OFFLINE")

        assert os.environ["ASH_OFFLINE"] == "no"


class TestTheConfigInputs:
    def test_a_config_given_to_the_constructor_is_said_to_be_unused(self, tmp_path):
        source, output = _dirs(tmp_path)

        with patch(f"{_ORCHESTRATOR}.ASH_LOGGER") as logger:
            ASHScanOrchestrator(
                source_dir=source,
                output_dir=output,
                config=AshConfig(project_name="given"),
            )

        warned = [str(call.args[0]) for call in logger.warning.call_args_list]
        # Red at the base: initialize() replaced the field and nothing said so.
        assert any("not used" in line for line in warned), warned

    def test_no_config_no_warning(self, tmp_path):
        """The control."""
        source, output = _dirs(tmp_path)

        with patch(f"{_ORCHESTRATOR}.ASH_LOGGER") as logger:
            ASHScanOrchestrator(source_dir=source, output_dir=output)

        assert logger.warning.call_count == 0

    def test_a_base_gate_beside_a_resolved_config_is_refused(self, tmp_path):
        source, output = _dirs(tmp_path)

        # Red at the base: the gate was accepted and never consulted.
        with pytest.raises(ValueError, match="config_base_gate"):
            ASHScanOrchestrator(
                source_dir=source,
                output_dir=output,
                resolved_config=AshConfig(project_name="resolved"),
                config_base_gate=lambda path: True,
            )

    @pytest.mark.parametrize("how", ["copy", "deepcopy", "model_copy"])
    def test_a_copy_that_was_not_initialized_has_its_own_run_id(self, tmp_path, how):
        source, output = _dirs(tmp_path)
        template = ASHScanOrchestrator(source_dir=source, output_dir=output)

        copied = {
            "copy": lambda: copy.copy(template),
            "deepcopy": lambda: copy.deepcopy(template),
            "model_copy": lambda: template.model_copy(),
        }[how]()

        # Red at the base: the private attribute was copied with the rest.
        assert copied._run_id != template._run_id

    def test_a_copy_of_an_initialized_one_keeps_the_id_its_engine_was_built_under(
        self, tmp_path
    ):
        source, output = _dirs(tmp_path)
        template = ASHScanOrchestrator(source_dir=source, output_dir=output)
        _initialize(template)

        assert copy.copy(template)._run_id == template._run_id


class TestTheSeverityRestriction:
    """A restriction can only tighten, and LOW is stricter than HIGH.

    The threshold names the least severe finding that still fails a scan, so
    the lower the word the more findings gate. Each test below starts from the
    looser word (HIGH) and restricts to the stricter one (LOW).
    """

    def test_the_callers_resolved_config_is_not_rewritten(self, tmp_path):
        source, output = _dirs(tmp_path)
        shared = AshConfig(project_name="shared")
        shared.global_settings.severity_threshold = "HIGH"
        orchestrator = ASHScanOrchestrator(
            source_dir=source,
            output_dir=output,
            resolved_config=shared,
            severity_threshold_restriction="LOW",
        )

        _initialize(orchestrator)

        assert orchestrator.config.global_settings.severity_threshold == "LOW"
        # Red at the base: the caller's object was the one rewritten, and a
        # workspace hands the same one to every scan.
        assert shared.global_settings.severity_threshold == "HIGH"
        assert orchestrator.config is not shared

    def test_without_a_restriction_the_config_is_adopted_as_given(self, tmp_path):
        """The control: no copy is made when nothing will be rewritten."""
        source, output = _dirs(tmp_path)
        shared = AshConfig(project_name="shared")
        orchestrator = ASHScanOrchestrator(
            source_dir=source, output_dir=output, resolved_config=shared
        )

        _initialize(orchestrator)

        assert orchestrator.config is shared

    def test_the_recorded_config_of_saved_results_is_restricted_too(self, tmp_path):
        source, output = _dirs(tmp_path)
        loaded = results_of_a_scan()
        loaded.ash_config = AshConfig(project_name="recorded")
        loaded.ash_config.global_settings.severity_threshold = "HIGH"
        orchestrator = ASHScanOrchestrator(
            source_dir=source,
            output_dir=output,
            severity_threshold_restriction="LOW",
        )

        orchestrator._adopt_this_runs_values(loaded, AshConfig(project_name="now"))

        # Red at the base: only the run's own config was restricted, and the
        # report over saved results gates on the recorded one.
        assert loaded.ash_config.global_settings.severity_threshold == "LOW"

    def test_a_word_off_the_ladder_is_refused_and_nothing_is_written(self, tmp_path):
        source, output = _dirs(tmp_path)
        config = AshConfig(project_name="p")
        config.global_settings.severity_threshold = "MEDIUM"
        orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output)

        # Red at the base: stricter_of ranks an unknown word after CRITICAL, so it
        # won and became the configuration's threshold.
        with pytest.raises(ASHValidationError, match="SEVERE"):
            orchestrator._restrict_severity_threshold(config, "SEVERE")

        assert config.global_settings.severity_threshold == "MEDIUM"

    def test_lower_case_is_the_same_word_and_blank_is_none(self, tmp_path):
        source, output = _dirs(tmp_path)
        config = AshConfig(project_name="p")
        config.global_settings.severity_threshold = "HIGH"
        orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output)

        orchestrator._restrict_severity_threshold(config, "  ")
        assert config.global_settings.severity_threshold == "HIGH"

        orchestrator._restrict_severity_threshold(config, "low")
        assert config.global_settings.severity_threshold == "LOW"

    def test_the_scanners_of_the_config_it_is_given_are_the_ones_tightened(
        self, tmp_path
    ):
        source, output = _dirs(tmp_path)
        target = AshConfig(
            scanners={"custom-scanner": {"options": {"severity_threshold": "HIGH"}}}
        )
        other = AshConfig(
            scanners={"custom-scanner": {"options": {"severity_threshold": "HIGH"}}}
        )
        orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output)
        orchestrator.config = other

        orchestrator._restrict_severity_threshold(target, "LOW")

        tightened = (target.scanners.model_extra or {})["custom-scanner"]["options"]
        untouched = (other.scanners.model_extra or {})["custom-scanner"]["options"]
        # Red at the base: the scanners were read from self.config.
        assert tightened["severity_threshold"] == "LOW"
        assert untouched["severity_threshold"] == "HIGH"

    def test_a_threshold_read_from_the_environment_is_not_printed(self, tmp_path):
        source, output = _dirs(tmp_path)
        held = "environment-held-threshold-value"
        config = AshConfig(
            scanners={"custom-scanner": {"options": {"severity_threshold": held}}}
        )
        config._environment_values = [held]
        orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output)

        with patch(f"{_ORCHESTRATOR}.ASH_LOGGER") as logger:
            orchestrator._restrict_severity_threshold(config, "HIGH")

        said = [str(call.args[0]) for call in logger.info.call_args_list]
        assert said, "the tightening should be logged"
        # Red at the base: the value was in the line.
        assert not any(held in line for line in said), said

    def test_the_ladder_words_are_printed_as_they_are(self, tmp_path):
        """The control: redaction does not mask the words the line is about."""
        source, output = _dirs(tmp_path)
        config = AshConfig(project_name="p")
        config.global_settings.severity_threshold = "LOW"
        config._environment_values = ["LOW"]
        orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output)

        with patch(f"{_ORCHESTRATOR}.ASH_LOGGER") as logger:
            orchestrator._restrict_severity_threshold(config, "HIGH")

        said = [str(call.args[0]) for call in logger.info.call_args_list]
        assert any("HIGH" in line and "LOW" in line for line in said), said


class TestSavedResultsAndTheScanSet:
    def test_a_results_file_that_is_gone_when_the_engine_is_built_is_a_load_failure(
        self, tmp_path
    ):
        source, output = _dirs(tmp_path)
        gone = tmp_path / "gone.json"
        orchestrator = ASHScanOrchestrator(
            source_dir=source, output_dir=output, existing_results_path=gone
        )

        # Red at the base: a bare FileNotFoundError, which no entry point reads as
        # a refusal.
        with pytest.raises(ASHValidationError, match="Failed to load existing results"):
            _initialize(orchestrator)

    def test_a_results_file_that_vanishes_before_the_scan_is_not_a_scan(self, tmp_path):
        source, output = _dirs(tmp_path)
        existing = tmp_path / "existing.json"
        existing.write_text(results_of_a_scan().model_dump_json())
        engine = _Engine(model=AshAggregatedResults())
        orchestrator = ASHScanOrchestrator(
            source_dir=source, output_dir=output, existing_results_path=existing
        )
        _initialize(orchestrator, engine=engine)
        existing.unlink()

        # Red at the base: the file was judged by whether it was there, so the
        # run went on to the phases with the model the engine already held.
        with pytest.raises(ASHValidationError, match="Failed to load existing results"):
            orchestrator.execute_scan(phases=["report"])

        assert engine.runs == 0

    def test_a_given_results_path_creates_only_the_reports_directory(self, tmp_path):
        source, output = _dirs(tmp_path)
        orchestrator = ASHScanOrchestrator(
            source_dir=source,
            output_dir=output,
            existing_results_path=tmp_path / "gone.json",
        )

        orchestrator.ensure_directories()

        assert (output / "reports").is_dir()
        # Red at the base: a missing file sent the call down the scan branch.
        assert not (output / "scanners").exists()

    def test_a_scan_with_no_engine_does_not_walk_the_tree_first(self, tmp_path):
        source, output = _dirs(tmp_path)
        orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output)
        orchestrator.config = AshConfig(project_name="p")

        with patch(f"{_ORCHESTRATOR}.scan_set") as walk:
            with pytest.raises(ASHValidationError, match="never initialized"):
                orchestrator.execute_scan(phases=["scan"])

        # Red at the base: the walk ran, and wrote the scan set, first.
        walk.assert_not_called()


class TestConfigWarnings:
    def _config(self, *warnings):
        config = AshConfig(project_name="p")
        config._resolution_warnings = list(warnings)
        return config

    @staticmethod
    def _warnings_in(model):
        return [
            c["message"]
            for c in model.validation_checkpoints
            if c.get("type") == "config_warning"
        ]

    def test_the_report_phase_sees_them_and_each_is_recorded_once(self, tmp_path):
        source, output = _dirs(tmp_path)
        model = AshAggregatedResults()
        seen = []
        engine = _Engine(
            model=model, on_run=lambda: seen.append(self._warnings_in(model))
        )
        orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output)
        _initialize(orchestrator, engine=engine, config=self._config("w1", "w1", "w2"))

        returned = orchestrator.execute_scan(phases=["report"])

        # Red at the base: none when the phases ran, three at the end.
        assert seen == [["w1", "w2"]]
        assert self._warnings_in(returned) == ["w1", "w2"]

    def test_saved_results_do_not_get_a_warning_they_already_hold(self, tmp_path):
        source, output = _dirs(tmp_path)
        model = AshAggregatedResults()
        model.validation_checkpoints.append(
            {"type": "config_warning", "severity": "warning", "message": "w1"}
        )
        engine = _Engine(model=model)
        orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output)
        _initialize(orchestrator, engine=engine, config=self._config("w1", "w2"))

        returned = orchestrator.execute_scan(phases=["report"])

        assert self._warnings_in(returned) == ["w1", "w2"]


class TestACancelBeforeTheResultsWrite:
    def test_no_results_file_is_left_behind(self, tmp_path):
        source, output = _dirs(tmp_path)
        event = CancelEvent()
        engine = _Engine(model=AshAggregatedResults(), on_run=event.set)
        orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output)
        _initialize(orchestrator, engine=engine)

        with patch(f"{_ORCHESTRATOR}.scan_set", return_value=[]):
            with cancel_scope(event):
                with pytest.raises(ScanCancelled):
                    orchestrator.execute_scan(phases=["scan"])

        # Red at the base: the file was written, and the cancel was acted on after.
        assert not (output / "ash_aggregated_results.json").exists()

    def test_without_a_cancel_the_file_is_written(self, tmp_path):
        """The control."""
        source, output = _dirs(tmp_path)
        engine = _Engine(model=AshAggregatedResults())
        orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output)
        _initialize(orchestrator, engine=engine)

        with patch(f"{_ORCHESTRATOR}.scan_set", return_value=[]):
            orchestrator.execute_scan(phases=["scan"])

        assert (output / "ash_aggregated_results.json").is_file()


class TestAFailureWhileApplyingMetadata:
    def test_the_previous_results_are_put_back(self, tmp_path):
        source, output = _dirs(tmp_path)
        orchestrator = ASHScanOrchestrator(
            source_dir=source, output_dir=output, keep_previous_results=True
        )

        with (
            patch.object(
                ASHScanOrchestrator, "_apply_metadata", side_effect=RuntimeError("boom")
            ),
            patch.object(ASHScanOrchestrator, "settle_previous_results") as settle,
        ):
            with pytest.raises(RuntimeError, match="boom"):
                _initialize(orchestrator)

        # Red at the base: the metadata step sat outside the guard, so the results
        # set aside stayed aside and the scan never reached the call that settles
        # them.
        settle.assert_called_once_with(restore=True)
