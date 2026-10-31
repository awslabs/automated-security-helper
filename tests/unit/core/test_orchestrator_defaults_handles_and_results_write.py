# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The orchestrator's defaults, handles, cleanup and results write.

Eight defects of ``ASHScanOrchestrator``, each pinned by a test red on the tree
that carried it:

* source_dir and output_dir defaults were computed when the module was
  imported, so the source-derived output default never applied.
* When set_aside raised, the PreviousResults handle was dropped, so a held set
  a killed earlier scan left was never discarded after this scan succeeded.
* The existing results file was read with the locale encoding.
* A caller-supplied work_dir was never given to the plugin context, yet the
  end-of-scan cleanup deleted it.
* A failed rmtree of the work directory after every phase turned a completed
  scan into a failure.
* In a workspace, _apply_metadata overwrote the recorded project_name with a
  value the project's config read from the environment.
* severity_threshold_restriction skipped a scanner whose own threshold was the
  empty string, which the executor reads as a threshold with no gate.
* The results file was written by the scan phase at its own end, before the
  engine's later passes, so a direct orchestrator caller kept that early file.

No engine runs here: the engine is a stub, and the scan-set walk is patched.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core import orchestrator as orchestrator_module
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.core.previous_results import (
    HELD_DIR_NAME,
    RESTORED_MARKER_NAME,
    PreviousResults,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit


def _dirs(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "proj"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    return source, output


class TestDefaultsAreComputedPerInstance:
    def test_output_dir_derives_from_the_source_dir_given(self, tmp_path):
        source = tmp_path / "proj"
        source.mkdir()

        orchestrator = ASHScanOrchestrator(source_dir=source)

        # Red at the base: the import-time default, under the importing
        # process's directory, stood in for the source-derived one.
        assert orchestrator.output_dir == source / ".ash" / "ash_output"

    def test_a_bare_orchestrator_scans_the_working_directory(
        self, tmp_path, monkeypatch
    ):
        # Under a directory of this test's own: the result is then the same
        # wherever pytest is run from, and whatever the constructor derives
        # from the working directory lands here, never in the checkout.
        monkeypatch.chdir(tmp_path)
        orchestrator = ASHScanOrchestrator()
        assert Path.cwd().resolve() == tmp_path.resolve()
        assert orchestrator.source_dir == Path.cwd()
        assert orchestrator.output_dir == Path.cwd() / ".ash" / "ash_output"


class TestAStaleHeldSetIsDiscardedWhenSetAsideFailed:
    def test_the_held_set_goes_once_the_scan_has_its_results(
        self, tmp_path, monkeypatch
    ):
        source, output = _dirs(tmp_path)
        held = output / HELD_DIR_NAME
        held.mkdir()
        (held / "ash_aggregated_results.json").write_text("stale", encoding="utf-8")

        def refuse(self):
            raise PermissionError(13, "Permission denied", str(self.output_dir))

        monkeypatch.setattr(PreviousResults, "set_aside", refuse)
        orchestrator = ASHScanOrchestrator(
            source_dir=source, output_dir=output, keep_previous_results=True
        )
        orchestrator._set_previous_results_aside()
        orchestrator.settle_previous_results(restore=False)

        # Red at the base: the handle was dropped, so nothing discarded the set.
        assert not held.exists()

    def test_nothing_is_put_back_when_nothing_of_this_scans_was_set_aside(
        self, tmp_path, monkeypatch
    ):
        """The control: a restore after a failed set aside moves nothing."""
        source, output = _dirs(tmp_path)
        held = output / HELD_DIR_NAME
        held.mkdir()
        (held / "ash_aggregated_results.json").write_text("stale", encoding="utf-8")
        own = output / "ash_aggregated_results.json"
        own.write_text("this scan", encoding="utf-8")

        def refuse(self):
            raise PermissionError(13, "Permission denied", str(self.output_dir))

        monkeypatch.setattr(PreviousResults, "set_aside", refuse)
        orchestrator = ASHScanOrchestrator(
            source_dir=source, output_dir=output, keep_previous_results=True
        )
        orchestrator._set_previous_results_aside()
        orchestrator.settle_previous_results(restore=True)

        assert own.read_text(encoding="utf-8") == "this scan"
        assert held.exists()

    def test_the_stale_top_level_results_go_when_set_aside_failed(
        self, tmp_path, monkeypatch
    ):
        """A set aside that failed leaves the previous results at the top level,
        and this scan replaces them: they go when the output directory is
        prepared, as for a scan that keeps nothing, so the previous results
        file does not pass for this run's until its own write (the MCP progress
        tracker reads the file's existence as a complete scan). The marker a
        restore left beside them goes too: with it, holds_restored_results
        read this scan's own output as put-back results."""
        source, output = _dirs(tmp_path)
        stale = output / "ash_aggregated_results.json"
        stale.write_text("stale", encoding="utf-8")
        marker = output / RESTORED_MARKER_NAME
        marker.write_text("restored\n", encoding="utf-8")

        def refuse(self):
            raise PermissionError(13, "Permission denied", str(self.output_dir))

        monkeypatch.setattr(PreviousResults, "set_aside", refuse)
        orchestrator = ASHScanOrchestrator(
            source_dir=source, output_dir=output, keep_previous_results=True
        )
        orchestrator._set_previous_results_aside()
        orchestrator._prepare_output_dir()

        # Red at the previous tip: the cleanup was gated on the handle being
        # None, and the handle stays after a failed set aside, so the stale
        # file and the marker stayed for the whole scan.
        assert not stale.exists()
        assert not marker.exists()

    def test_a_completed_set_aside_keeps_the_cleanup_off(self, tmp_path):
        """The control: once the previous results ARE set aside there is nothing
        at the top level to remove, and the held set is left alone."""
        source, output = _dirs(tmp_path)
        (output / "ash_aggregated_results.json").write_text("prev", encoding="utf-8")

        orchestrator = ASHScanOrchestrator(
            source_dir=source, output_dir=output, keep_previous_results=True
        )
        orchestrator._set_previous_results_aside()
        orchestrator._prepare_output_dir()

        held = output / HELD_DIR_NAME
        assert (held / "ash_aggregated_results.json").read_text(
            encoding="utf-8"
        ) == "prev"
        assert not (output / "ash_aggregated_results.json").exists()


class _CapturingEngine:
    captured: dict = {}

    def __init__(self, **kwargs):
        type(self).captured = dict(kwargs)
        self._asharp_model = kwargs.get("asharp_model") or AshAggregatedResults()


def _build_with_stub_engine(monkeypatch, **kwargs) -> ASHScanOrchestrator:
    monkeypatch.setattr(orchestrator_module, "ScanExecutionEngine", _CapturingEngine)
    # Class-level state shared by every test of this module: emptied here, so a
    # build that stopped constructing the engine would fail its own test on an
    # empty record instead of passing on the previous test's kwargs.
    _CapturingEngine.captured = {}
    orchestrator = ASHScanOrchestrator(**kwargs)
    config = AshConfig()
    orchestrator.config = config
    orchestrator._build_engine(config)
    return orchestrator


class TestTheEngineIsBuiltFromWhatTheCallerGave:
    def test_existing_results_are_read_as_utf8(self, tmp_path, monkeypatch):
        source, output = _dirs(tmp_path)
        existing = tmp_path / "existing.json"
        existing.write_text(AshAggregatedResults().model_dump_json(), encoding="utf-8")
        reads = []
        real_read_text = Path.read_text

        def recording_read_text(self, *args, **kwargs):
            reads.append((self, kwargs.get("encoding")))
            return real_read_text(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", recording_read_text)

        _build_with_stub_engine(
            monkeypatch,
            source_dir=source,
            output_dir=output,
            existing_results_path=existing,
        )

        # Red at the base: read with no encoding, the locale's. The read that is
        # checked is the results file's own, not any read on the way.
        assert (existing, "utf-8") in reads
        assert all(encoding == "utf-8" for path, encoding in reads if path == existing)

    def test_a_callers_work_dir_reaches_the_plugin_context(self, tmp_path, monkeypatch):
        source, output = _dirs(tmp_path)
        work = tmp_path / "my-work"

        _build_with_stub_engine(
            monkeypatch, source_dir=source, output_dir=output, work_dir=work
        )

        # Red at the base: the context always got output_dir/converted.
        assert _CapturingEngine.captured["context"].work_dir == work

    def test_without_a_work_dir_the_context_converts_under_the_output_dir(
        self, tmp_path, monkeypatch
    ):
        """The control: the default is unchanged."""
        source, output = _dirs(tmp_path)

        _build_with_stub_engine(monkeypatch, source_dir=source, output_dir=output)

        assert (
            _CapturingEngine.captured["context"].work_dir == output / ASH_WORK_DIR_NAME
        )


def _with_stub_phases(tmp_path, monkeypatch, **kwargs) -> ASHScanOrchestrator:
    source, output = _dirs(tmp_path)
    orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output, **kwargs)
    orchestrator.config = AshConfig()
    engine = MagicMock()
    engine.execute_phases.return_value = AshAggregatedResults()
    orchestrator.execution_engine = engine
    monkeypatch.setattr(orchestrator_module, "scan_set", lambda **_kw: [])
    return orchestrator


class TestTheEndOfAScan:
    def test_a_failed_work_dir_removal_does_not_fail_the_scan(
        self, tmp_path, monkeypatch
    ):
        work = tmp_path / "w"
        work.mkdir()
        orchestrator = _with_stub_phases(tmp_path, monkeypatch, work_dir=work)

        attempted = []
        real_rmtree = orchestrator_module.shutil.rmtree

        def refuse(path, *args, **kwargs):
            # Only the work directory is refused; any other removal in the
            # process (a fixture's, a library's) runs as it would.
            if Path(path) != work:
                return real_rmtree(path, *args, **kwargs)
            attempted.append(Path(path))
            raise PermissionError(13, "Permission denied", str(path))

        monkeypatch.setattr(orchestrator_module.shutil, "rmtree", refuse)

        # Red at the base: the OSError was wrapped as a failed scan.
        results = orchestrator._execute_scan(phases=["report"])

        assert isinstance(results, AshAggregatedResults)
        # The removal was tried, so the pass above is the failure being absorbed
        # and not a cleanup branch that did not run.
        assert attempted == [work]

    def test_the_results_file_is_written_once_every_phase_has_run(
        self, tmp_path, monkeypatch
    ):
        orchestrator = _with_stub_phases(tmp_path, monkeypatch)

        # execute_scan, not _execute_scan: the write follows the phases, outside
        # the arm that puts the previous results back on a failure or a cancel.
        orchestrator.execute_scan(phases=["scan"])

        # Red at the base: the scan phase wrote it, and the stub phase here
        # does not, so nothing wrote it.
        assert (orchestrator.output_dir / "ash_aggregated_results.json").is_file()

    def test_the_default_phases_write_the_results_file(self, tmp_path, monkeypatch):
        """execute_scan() with no phases runs every phase and writes the file.

        The phases are resolved once, in execute_scan, before the phase runner
        and the write read them; resolved only in the runner, the write read
        None as no scan phase and the default call wrote no results file.
        """
        orchestrator = _with_stub_phases(tmp_path, monkeypatch)

        orchestrator.execute_scan()

        engine = orchestrator.execution_engine
        engine.execute_phases.assert_called_once_with(
            phases=["convert", "scan", "report"]
        )
        assert (orchestrator.output_dir / "ash_aggregated_results.json").is_file()

    def test_a_scan_with_no_existing_results_returns_the_engines_model(
        self, tmp_path, monkeypatch
    ):
        """The model class is read after the phases (the held model before
        them, the returned model at the write), by the module-level import.
        A function-local import of the same name inside the existing-results
        branch made the name local to the whole function, so a scan that did
        not take that branch, which is every ordinary scan, raised
        UnboundLocalError at those reads, right after the phases had run."""
        orchestrator = _with_stub_phases(tmp_path, monkeypatch)
        assert orchestrator.existing_results_path is None
        engine_model = orchestrator.execution_engine.execute_phases.return_value

        results = orchestrator._execute_scan(phases=["scan"])

        assert results is engine_model
        # The mechanism, pinned: no local binding of the name in the function.
        code = ASHScanOrchestrator._execute_scan.__code__
        assert "AshAggregatedResults" not in code.co_varnames


class TestMetadataAndThresholds:
    def test_a_project_name_read_from_the_environment_is_not_applied(self, tmp_path):
        source, output = _dirs(tmp_path)
        orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output)
        config = AshConfig()
        config._environment_values = ["from-the-environment"]
        orchestrator.config = config
        engine = MagicMock()
        engine._asharp_model.metadata.project_name = "recorded"
        orchestrator.execution_engine = engine
        orchestrator.metadata = {"project_name": "from-the-environment"}

        orchestrator._apply_metadata()

        # Red at the base: the raw label replaced the recorded name.
        assert engine._asharp_model.metadata.project_name == "recorded"

    def test_a_plain_project_name_is_applied(self, tmp_path):
        """The control: the workspace's label still names the project."""
        source, output = _dirs(tmp_path)
        orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output)
        orchestrator.config = AshConfig()
        engine = MagicMock()
        engine._asharp_model.metadata.project_name = "recorded"
        orchestrator.execution_engine = engine
        orchestrator.metadata = {"project_name": "api"}

        orchestrator._apply_metadata()

        assert engine._asharp_model.metadata.project_name == "api"

    @pytest.mark.parametrize(
        ("requested", "effective"), [("LOW", "LOW"), ("HIGH", "MEDIUM")]
    )
    def test_a_blank_scanner_threshold_takes_the_restricted_global(
        self, tmp_path, requested, effective
    ):
        source, output = _dirs(tmp_path)
        config = AshConfig(
            scanners={"custom-scanner": {"options": {"severity_threshold": ""}}}
        )
        orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output)

        # LOW gates more findings than the default global MEDIUM, so it is the
        # stricter one and becomes the run's effective threshold; a request of
        # HIGH would be looser and leave the configured MEDIUM standing. The two
        # cases tell the effective global from the requested one: only HIGH over
        # MEDIUM gives a different value for each.
        orchestrator._restrict_severity_threshold(config, requested)

        options = (config.scanners.model_extra or {})["custom-scanner"]["options"]
        # Red at the base: the empty string was skipped as unset and stayed.
        assert options["severity_threshold"] == effective
