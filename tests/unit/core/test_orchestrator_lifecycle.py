"""Tests for ASHScanOrchestrator lifecycle paths outside the happy construction path.

Covers model_post_init's path coercion, initialize()'s stale-output cleanup and
existing-results branches, ensure_directories' cleanup and error wrapping, and
execute_scan end to end.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ASHValidationError
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.models.asharp_model import AshAggregatedResults

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


class _EngineStub:
    """Stand-in for ScanExecutionEngine.

    Written out rather than mocked because the orchestrator only touches two
    members, and a typo in either name should fail the test instead of being
    fabricated on demand -- which is exactly what a bare Mock() would do.
    """

    def __init__(self, asharp_model=None, phases_result=None, raises=None):
        self._asharp_model = asharp_model
        self._phases_result = phases_result
        self._raises = raises
        self.execute_phases_calls = []

    def execute_phases(self, phases=None):
        self.execute_phases_calls.append(phases)
        if self._raises is not None:
            raise self._raises
        return self._phases_result


def _bare(source_dir, output_dir=None, **overrides):
    """Construct without initialize(); the constructor performs no filesystem I/O."""
    params = {
        "source_dir": source_dir,
        "config_path": None,
        "config_overrides": None,
        "no_cleanup": False,
        "metadata": None,
        "ash_plugin_modules": [],
    }
    if output_dir is not None:
        params["output_dir"] = output_dir
    params.update(overrides)
    return ASHScanOrchestrator(**params)


def _initialized(source_dir, output_dir, engine, config=None, **overrides):
    """Construct and initialize with resolution and engine construction stubbed."""
    cfg = config if config is not None else AshConfig(project_name="test")
    orch = _bare(source_dir, output_dir, **overrides)
    with (
        patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=cfg,
        ),
        patch(
            "automated_security_helper.core.orchestrator.ScanExecutionEngine",
            return_value=engine,
        ),
    ):
        orch.initialize()
    return orch


class TestModelPostInitPathCoercion:
    """model_post_init normalizes source_dir/output_dir to Path.

    pydantic already rejects None and already coerces str for these fields, so
    these defensive branches are unreachable through the constructor. They stay
    reachable by mutating the model afterwards, which callers can do because
    validate_assignment is off -- so driving model_post_init directly is the
    honest way to exercise them.
    """

    def test_cleared_source_dir_falls_back_to_cwd(self, tmp_path):
        orch = _bare(tmp_path / "src")
        orch.source_dir = None
        orch.model_post_init(None)
        assert orch.source_dir == Path.cwd()

    def test_string_source_dir_is_coerced_to_path(self, tmp_path):
        src = tmp_path / "src"
        orch = _bare(src)
        orch.source_dir = str(src)
        orch.model_post_init(None)
        assert isinstance(orch.source_dir, Path)
        assert orch.source_dir == src

    def test_cleared_output_dir_is_derived_from_source_dir(self, tmp_path):
        src = tmp_path / "src"
        orch = _bare(src)
        orch.output_dir = None
        orch.model_post_init(None)
        assert orch.output_dir == src.joinpath(".ash", "ash_output")

    def test_string_output_dir_is_coerced_to_path(self, tmp_path):
        src = tmp_path / "src"
        out = tmp_path / "out"
        orch = _bare(src, out)
        orch.output_dir = str(out)
        orch.model_post_init(None)
        assert isinstance(orch.output_dir, Path)
        assert orch.output_dir == out


class TestInitialize:
    """initialize() resolves config, cleans stale output, and builds the engine."""

    def test_resolution_warnings_are_logged(self, tmp_path):
        """Each warning on the resolved config is surfaced through the logger."""
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        cfg = AshConfig(project_name="test")
        cfg._resolution_warnings = ["suppressions file missing", "unknown key foo"]

        with patch(
            "automated_security_helper.core.orchestrator.ASH_LOGGER"
        ) as mock_logger:
            _initialized(src, out, _EngineStub(), config=cfg)

        warned = [str(c.args[0]) for c in mock_logger.warning.call_args_list]
        assert any("suppressions file missing" in m for m in warned)
        assert any("unknown key foo" in m for m in warned)

    def test_stale_result_files_are_removed(self, tmp_path):
        """Known stale artifacts in output_dir are unlinked; others survive."""
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        stale = out / "ash_aggregated_results.json"
        stale.write_text("{}")
        ignore_report = out / "ash-ignore-report.txt"
        ignore_report.write_text("x")
        keeper = out / "some-other-file.txt"
        keeper.write_text("keep me")

        _initialized(src, out, _EngineStub())

        assert not stale.exists()
        assert not ignore_report.exists()
        assert keeper.exists()

    def test_permission_error_on_unlink_is_swallowed(self, tmp_path):
        """A stale file we cannot delete does not abort initialization."""
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        stale = out / "ash_aggregated_results.json"
        stale.write_text("{}")

        with patch.object(Path, "unlink", side_effect=PermissionError("locked")):
            orch = _initialized(src, out, _EngineStub())

        assert orch._initialized is True
        assert stale.exists()

    def test_existing_results_path_is_loaded_into_engine_params(self, tmp_path):
        """With existing_results_path set, the model is parsed and no files are deleted."""
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        stale = out / "ash_aggregated_results.json"
        existing = tmp_path / "existing.json"
        existing.write_text(AshAggregatedResults().model_dump_json())
        stale.write_text("{}")

        captured = {}

        def _capture(**kwargs):
            captured.update(kwargs)
            return _EngineStub()

        orch = _bare(src, out, existing_results_path=existing)
        with (
            patch(
                "automated_security_helper.core.orchestrator.resolve_config",
                return_value=AshConfig(project_name="test"),
            ),
            patch(
                "automated_security_helper.core.orchestrator.ScanExecutionEngine",
                side_effect=_capture,
            ),
        ):
            orch.initialize()

        assert isinstance(captured["asharp_model"], AshAggregatedResults)
        assert stale.exists(), "existing-results runs must not delete prior output"

    def test_initialize_is_idempotent(self, tmp_path):
        """A second initialize() call is a no-op and does not rebuild the engine."""
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        engine = _EngineStub()
        orch = _initialized(src, out, engine)

        with patch(
            "automated_security_helper.core.orchestrator.ScanExecutionEngine"
        ) as mock_engine_cls:
            orch.initialize()

        mock_engine_cls.assert_not_called()
        assert orch.execution_engine is engine


class TestEnsureDirectories:
    """ensure_directories() creates the working tree and wraps failures."""

    def test_existing_results_only_creates_reports_dir(self, tmp_path):
        """With usable existing results, analysis/scanners/converted are left alone."""
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        existing = tmp_path / "existing.json"
        existing.write_text("{}")

        orch = _bare(src, out, existing_results_path=existing)
        orch.ensure_directories()

        assert (out / "reports").is_dir()
        assert not (out / "analysis").exists()
        assert not (out / "scanners").exists()

    def test_previous_working_dirs_are_removed(self, tmp_path):
        """A working directory left over from a prior run is deleted, not merged."""
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        leftover = out / "analysis"
        leftover.mkdir(parents=True)
        stale_artifact = leftover / "previous_run.json"
        stale_artifact.write_text("old")

        orch = _bare(src, out)
        orch.ensure_directories()

        assert leftover.is_dir()
        assert not stale_artifact.exists()

    def test_mkdir_failure_is_wrapped_in_validation_error(self, tmp_path):
        """An OS failure becomes ASHValidationError rather than propagating raw."""
        orch = _bare(tmp_path / "src", tmp_path / "out")

        with patch.object(Path, "mkdir", side_effect=OSError("read-only fs")):
            with pytest.raises(
                ASHValidationError, match="Failed to ensure directories"
            ):
                orch.ensure_directories()


class TestExecuteScan:
    """execute_scan() drives the engine and post-processes its results."""

    def test_default_phases_are_convert_scan_report(self, tmp_path):
        """Calling with no phases runs the three default phases."""
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        results = AshAggregatedResults()
        engine = _EngineStub(phases_result=results)
        orch = _initialized(src, out, engine)

        with patch(
            "automated_security_helper.core.orchestrator.scan_set",
            return_value=["a.py", "b.py"],
        ):
            returned = orch.execute_scan()

        assert engine.execute_phases_calls == [["convert", "scan", "report"]]
        assert returned is results
        assert orch.source_scan_set == ["a.py", "b.py"]

    def test_report_only_phases_skip_scan_set_identification(self, tmp_path):
        """Without convert or scan in phases, the source scan set is never built."""
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        engine = _EngineStub(phases_result=AshAggregatedResults())
        orch = _initialized(src, out, engine)

        with patch(
            "automated_security_helper.core.orchestrator.scan_set"
        ) as mock_scan_set:
            orch.execute_scan(phases=["report"])

        mock_scan_set.assert_not_called()

    def test_existing_results_narrow_phases_to_report(self, tmp_path):
        """An existing results file replaces the engine model and forces report-only."""
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        existing = tmp_path / "existing.json"
        existing.write_text(AshAggregatedResults().model_dump_json())

        engine = _EngineStub(phases_result=AshAggregatedResults())
        orch = _initialized(src, out, engine, existing_results_path=existing)

        orch.execute_scan(phases=["convert", "scan", "report"])

        assert engine.execute_phases_calls == [["report"]]
        assert isinstance(engine._asharp_model, AshAggregatedResults)
        assert (out / "reports").is_dir()

    def test_existing_results_keeps_inspect_phase(self, tmp_path):
        """inspect survives the report-only narrowing; convert and scan do not."""
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        existing = tmp_path / "existing.json"
        existing.write_text(AshAggregatedResults().model_dump_json())

        engine = _EngineStub(phases_result=AshAggregatedResults())
        orch = _initialized(src, out, engine, existing_results_path=existing)

        orch.execute_scan(phases=["convert", "scan", "report", "inspect"])

        assert engine.execute_phases_calls == [["report", "inspect"]]

    def test_unreadable_existing_results_raises_validation_error(self, tmp_path):
        """Malformed existing results fail loudly as ASHValidationError."""
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        existing = tmp_path / "existing.json"
        existing.write_text(AshAggregatedResults().model_dump_json())

        engine = _EngineStub(phases_result=AshAggregatedResults())
        orch = _initialized(src, out, engine, existing_results_path=existing)

        # Corrupt it only after initialize() has parsed the good copy, so the
        # failure lands in execute_scan rather than in initialize.
        existing.write_text("{ not json")

        with pytest.raises(ASHValidationError, match="Failed to load existing results"):
            orch.execute_scan(phases=["report"])

    def test_config_warnings_become_validation_checkpoints(self, tmp_path):
        """Resolution warnings are appended to the results as checkpoint entries."""
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        cfg = AshConfig(project_name="test")
        cfg._resolution_warnings = ["config file ignored"]

        results = AshAggregatedResults()
        engine = _EngineStub(phases_result=results)
        orch = _initialized(src, out, engine, config=cfg)

        with patch(
            "automated_security_helper.core.orchestrator.scan_set", return_value=[]
        ):
            returned = orch.execute_scan(phases=["scan"])

        checkpoints = [
            c
            for c in returned.validation_checkpoints
            if c.get("type") == "config_warning"
        ]
        assert len(checkpoints) == 1
        assert checkpoints[0]["message"] == "config file ignored"
        assert checkpoints[0]["severity"] == "warning"
        assert checkpoints[0]["metadata"]["source"] == "config_resolution"

    def test_work_dir_is_removed_when_cleanup_enabled(self, tmp_path):
        """With no_cleanup False, an existing work_dir is deleted after the scan."""
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        work = tmp_path / "work"
        work.mkdir()
        (work / "scratch.txt").write_text("temp")

        engine = _EngineStub(phases_result=AshAggregatedResults())
        orch = _initialized(src, out, engine, work_dir=work, no_cleanup=False)

        orch.execute_scan(phases=["report"])

        assert not work.exists()

    def test_work_dir_is_kept_when_cleanup_disabled(self, tmp_path):
        """no_cleanup=True preserves the work directory."""
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        work = tmp_path / "work"
        work.mkdir()

        engine = _EngineStub(phases_result=AshAggregatedResults())
        orch = _initialized(src, out, engine, work_dir=work, no_cleanup=True)

        orch.execute_scan(phases=["report"])

        assert work.exists()

    def test_engine_failure_is_wrapped_in_validation_error(self, tmp_path):
        """An arbitrary engine exception surfaces as ASHValidationError."""
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        engine = _EngineStub(raises=RuntimeError("scanner blew up"))
        orch = _initialized(src, out, engine)

        with pytest.raises(ASHValidationError, match="Scan execution failed"):
            orch.execute_scan(phases=["report"])

    def test_validation_error_from_engine_is_not_rewrapped(self, tmp_path):
        """An ASHValidationError passes through with its original message."""
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        engine = _EngineStub(raises=ASHValidationError("inner cause"))
        orch = _initialized(src, out, engine)

        with pytest.raises(ASHValidationError) as excinfo:
            orch.execute_scan(phases=["report"])

        assert "inner cause" in str(excinfo.value)
        assert "Scan execution failed" not in str(excinfo.value)
