"""Tests for ASHScanOrchestrator lifecycle paths outside the happy construction path.

Covers model_post_init's path coercion, initialize()'s stale-output cleanup and
existing-results branches, ensure_directories' cleanup and error wrapping, and
execute_scan end to end.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    ASHValidationError,
)
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


def _initialize_from_file(source_dir, output_dir, engine, config_path):
    """Construct and initialize with the real config resolution; only the engine is stubbed.

    Returns the orchestrator and the engine-class patch, so a test can tell whether
    initialize() got as far as building the engine.
    """
    orch = _bare(source_dir, output_dir, config_path=str(config_path))
    with patch(
        "automated_security_helper.core.orchestrator.ScanExecutionEngine",
        return_value=engine,
    ) as engine_cls:
        orch.initialize()
    return orch, engine_cls


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

    def test_unparseable_config_file_refuses_initialize(self, tmp_path):
        """A config file that does not parse stops initialize() with a config error.

        It used to be replaced by the defaults, with a logged warning, and the scan
        went ahead with the file's suppressions and settings switched off.
        """
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        config = tmp_path / "ash.yaml"
        config.write_text(
            "global_settings:\n  suppressions: [unclosed\n", encoding="utf-8"
        )

        with (
            patch(
                "automated_security_helper.core.orchestrator.ASH_LOGGER"
            ) as mock_logger,
            pytest.raises(ASHConfigValidationError, match="ash.yaml"),
        ):
            _initialize_from_file(src, out, _EngineStub(), config)

        warned = [str(c.args[0]) for c in mock_logger.warning.call_args_list]
        assert not any("CONFIG WARNING" in m for m in warned)

    def test_loadable_config_file_is_resolved_by_initialize(self, tmp_path):
        """Control for the test above: the same path with a file that parses."""
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        config = tmp_path / "ash.yaml"
        config.write_text(
            "global_settings:\n  suppressions:\n"
            "    - rule_id: B101\n      path: '**'\n      reason: fixture\n",
            encoding="utf-8",
        )

        orch, engine_cls = _initialize_from_file(src, out, _EngineStub(), config)

        engine_cls.assert_called_once()
        assert [s.rule_id for s in orch.config.global_settings.suppressions] == ["B101"]

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

    def test_missing_config_file_never_reaches_the_engine(self, tmp_path):
        """A named config file that does not exist refuses the scan before any phase.

        It used to resolve to the defaults, so the scan ran every phase and recorded
        "config file ignored" as a warning checkpoint in otherwise normal results.
        """
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        engine = _EngineStub(phases_result=AshAggregatedResults())

        with pytest.raises(ASHConfigValidationError, match="absent.yaml"):
            orch, _ = _initialize_from_file(src, out, engine, tmp_path / "absent.yaml")
            with patch(
                "automated_security_helper.core.orchestrator.scan_set",
                return_value=[],
            ):
                orch.execute_scan(phases=["scan"])

        assert engine.execute_phases_calls == []

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


class TestIgnoredConfigSources:
    """A config source discovery found and did not use is reported with the scan.

    The settings in it are not applied, so resolve_config records discovery's
    warning as a resolution warning; initialize() logs it and execute_scan() adds
    it to the results as a ``config_warning`` validation checkpoint, which the
    end-of-scan summary prints. Covered both ways a scan gets its config: the
    orchestrator discovering it, and ``ash scan`` passing the file it discovered.
    """

    @staticmethod
    def _two_sources(src: Path) -> Path:
        (src / ".ash").mkdir(parents=True)
        used = src / ".ash" / ".ash.yaml"
        used.write_text("project_name: used\n", encoding="utf-8")
        (src / ".ashrc.toml").write_text('project_name = "ignored"\n', encoding="utf-8")
        return used

    @pytest.mark.parametrize(
        "named", [pytest.param(False, id="discovered"), pytest.param(True, id="named")]
    )
    def test_the_ignored_source_becomes_a_checkpoint(
        self, tmp_path, monkeypatch, named
    ):
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        src = tmp_path / "src"
        used = self._two_sources(src)
        engine = _EngineStub(phases_result=AshAggregatedResults())
        orch = _bare(
            src, tmp_path / "out", config_path=used.as_posix() if named else None
        )

        with (
            patch(
                "automated_security_helper.core.orchestrator.ScanExecutionEngine",
                return_value=engine,
            ),
            patch(
                "automated_security_helper.core.orchestrator.ASH_LOGGER"
            ) as mock_logger,
        ):
            orch.initialize()
        with patch(
            "automated_security_helper.core.orchestrator.scan_set", return_value=[]
        ):
            returned = orch.execute_scan(phases=["scan"])

        assert orch.config.project_name == "used"
        warned = [str(c.args[0]) for c in mock_logger.warning.call_args_list]
        # Named: nothing logged it before the orchestrator. Discovered: resolution
        # logged it, so the orchestrator does not log it again.
        assert (
            any("CONFIG WARNING" in m and ".ashrc.toml" in m for m in warned) is named
        )
        checkpoints = [
            c
            for c in returned.validation_checkpoints
            if c.get("type") == "config_warning"
        ]
        assert len(checkpoints) == 1, checkpoints
        assert ".ashrc.toml" in checkpoints[0]["message"]
        assert "takes precedence" in checkpoints[0]["message"]
        assert checkpoints[0]["metadata"]["source"] == "config_resolution"

    @pytest.mark.parametrize(
        "named", [pytest.param(False, id="discovered"), pytest.param(True, id="named")]
    )
    def test_the_ignored_source_is_logged_once(
        self, tmp_path, monkeypatch, caplog, named
    ):
        """Discovery's warning is logged once in a scan, then shown in the summary.

        Named is how ``ash scan`` runs: run_ash_scan discovers the file and passes
        its path, and the orchestrator resolves it.
        """
        import logging

        from automated_security_helper.interactions.run_ash_scan import (
            _discovered_config_path,
        )

        monkeypatch.delenv("ASH_CONFIG", raising=False)
        src = tmp_path / "src"
        used = self._two_sources(src)
        engine = _EngineStub(phases_result=AshAggregatedResults())

        with caplog.at_level(logging.WARNING):
            if named:
                assert _discovered_config_path(src, log_selection=True) == (
                    used.as_posix()
                )
            orch = _bare(
                src, tmp_path / "out", config_path=used.as_posix() if named else None
            )
            with patch(
                "automated_security_helper.core.orchestrator.ScanExecutionEngine",
                return_value=engine,
            ):
                orch.initialize()

        logged = [
            r.getMessage() for r in caplog.records if ".ashrc.toml" in r.getMessage()
        ]
        assert len(logged) == 1, logged

    def test_the_checkpoint_says_the_settings_are_not_applied(
        self, tmp_path, monkeypatch
    ):
        """Not "suppressions may not be active", which reads as a broken config."""
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        src = tmp_path / "src"
        self._two_sources(src)
        engine = _EngineStub(phases_result=AshAggregatedResults())
        orch = _bare(src, tmp_path / "out")
        with patch(
            "automated_security_helper.core.orchestrator.ScanExecutionEngine",
            return_value=engine,
        ):
            orch.initialize()
        with patch(
            "automated_security_helper.core.orchestrator.scan_set", return_value=[]
        ):
            returned = orch.execute_scan(phases=["scan"])

        (checkpoint,) = [
            c
            for c in returned.validation_checkpoints
            if c.get("type") == "config_warning"
        ]
        assert "may not be active" not in checkpoint["metadata"]["impact"]
        assert "not applied" in checkpoint["metadata"]["impact"]

    def test_control_a_single_source_adds_no_checkpoint(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        src = tmp_path / "src"
        (src / ".ash").mkdir(parents=True)
        (src / ".ash" / ".ash.yaml").write_text(
            "project_name: only\n", encoding="utf-8"
        )
        engine = _EngineStub(phases_result=AshAggregatedResults())
        orch = _bare(src, tmp_path / "out")

        with patch(
            "automated_security_helper.core.orchestrator.ScanExecutionEngine",
            return_value=engine,
        ):
            orch.initialize()
        with patch(
            "automated_security_helper.core.orchestrator.scan_set", return_value=[]
        ):
            returned = orch.execute_scan(phases=["scan"])

        assert [
            c
            for c in returned.validation_checkpoints
            if c.get("type") == "config_warning"
        ] == []
