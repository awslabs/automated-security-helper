"""Tests for ScanExecutionEngine construction, scanner lookup, and phase dispatch.

Covers the constructor's plugin-module loading and config-override paths,
get_scanner, ensure_initialized's validation, and execute_phases' per-phase
dispatch, error handling and duration formatting.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.execution_engine import ScanExecutionEngine
from automated_security_helper.models.asharp_model import AshAggregatedResults

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

_ENGINE_MODULE = "automated_security_helper.core.execution_engine"


class _FlaggedConfig(AshConfig):
    """An AshConfig carrying debug/verbose flags.

    The constructor gates its config override on ``hasattr(config, "debug")``.
    Plain AshConfig declares neither flag and ignores extras, so the override is
    only reachable for a config that really has the fields -- which is what this
    subclass supplies, rather than a mock that would answer hasattr for anything.
    """

    debug: bool = False
    verbose: bool = False


def _make_context(tmp_path, config=None):
    source_dir = tmp_path / "source"
    source_dir.mkdir(exist_ok=True)
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    work_dir = tmp_path / "work"
    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=config if config is not None else AshConfig(project_name="test"),
    )


def _build_engine(tmp_path, config=None, context=None, **kwargs):
    """Build an engine with internal plugin loading stubbed for speed."""
    ctx = context if context is not None else _make_context(tmp_path, config)
    with patch("automated_security_helper.plugins.loader.load_internal_plugins"):
        return ScanExecutionEngine(context=ctx, show_progress=False, **kwargs)


class _StubPhase:
    """Records construction kwargs and returns a fixed result from execute()."""

    instances: list = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.execute_kwargs = None
        self._completed_scanners = ["stub_scanner"]
        type(self).instances.append(self)

    def execute(self, **kwargs):
        self.execute_kwargs = kwargs
        return kwargs.get("aggregated_results")


def _phase_stub_factory():
    """Return a fresh _StubPhase subclass with its own instance list."""

    class _Phase(_StubPhase):
        instances: list = []

    return _Phase


class TestEngineConstruction:
    """__init__ validates its context and applies plugin/config settings."""

    def test_missing_context_is_rejected(self):
        with pytest.raises(ValueError, match="Context must be provided"):
            ScanExecutionEngine(context=None)

    def test_plugin_modules_from_cli_and_config_are_loaded(self, tmp_path):
        """CLI and config module lists are merged, comma-split, and discovered."""
        config = AshConfig(project_name="test")
        config.ash_plugin_modules = ["cfg_mod_a, cfg_mod_b"]
        ctx = _make_context(tmp_path, config)

        with (
            patch("automated_security_helper.plugins.loader.load_internal_plugins"),
            patch(
                "automated_security_helper.plugins.loader.load_additional_plugin_modules"
            ) as mock_load,
            patch(f"{_ENGINE_MODULE}.discover_plugins") as mock_discover,
        ):
            ScanExecutionEngine(
                context=ctx,
                show_progress=False,
                ash_plugin_modules=["cli_mod"],
            )

        mock_load.assert_called_once()
        loaded = set(mock_load.call_args.args[0])
        assert loaded == {"cli_mod", "cfg_mod_a", "cfg_mod_b"}
        assert set(mock_discover.call_args.kwargs["plugin_modules"]) == loaded

    def test_no_plugin_modules_skips_discovery(self, tmp_path):
        """With no modules configured, the loader is never invoked."""
        with (
            patch("automated_security_helper.plugins.loader.load_internal_plugins"),
            patch(
                "automated_security_helper.plugins.loader.load_additional_plugin_modules"
            ) as mock_load,
            patch(f"{_ENGINE_MODULE}.discover_plugins") as mock_discover,
        ):
            ScanExecutionEngine(context=_make_context(tmp_path), show_progress=False)

        mock_load.assert_not_called()
        mock_discover.assert_not_called()

    def test_config_debug_and_verbose_override_environment(self, tmp_path, monkeypatch):
        """Config flags win over ASH_DEBUG/ASH_VERBOSE when the config carries them."""
        monkeypatch.setenv("ASH_DEBUG", "false")
        monkeypatch.setenv("ASH_VERBOSE", "false")
        config = _FlaggedConfig(project_name="test", debug=True, verbose=True)

        captured = {}

        def _capture_display(**kwargs):
            captured.update(kwargs)
            return MagicMock()

        with (
            patch("automated_security_helper.plugins.loader.load_internal_plugins"),
            patch(
                f"{_ENGINE_MODULE}.LiveProgressDisplay", side_effect=_capture_display
            ),
        ):
            ScanExecutionEngine(
                context=_make_context(tmp_path, config),
                show_progress=False,
                debug=False,
                verbose=False,
            )

        assert captured["debug"] is True
        assert captured["verbose"] is True

    def test_directory_logging_failure_propagates(self, tmp_path):
        """A failure while logging the resolved directories is re-raised, not hidden."""
        ctx = _make_context(tmp_path)

        def _explode_on_source_dir_log(msg, *args, **kwargs):
            if isinstance(msg, str) and msg.startswith("Source directory:"):
                raise RuntimeError("logging backend unavailable")

        with (
            patch("automated_security_helper.plugins.loader.load_internal_plugins"),
            patch(f"{_ENGINE_MODULE}.ASH_LOGGER") as mock_logger,
        ):
            mock_logger.debug.side_effect = _explode_on_source_dir_log
            with pytest.raises(RuntimeError, match="logging backend unavailable"):
                ScanExecutionEngine(context=ctx, show_progress=False)

        assert mock_logger.error.called


class TestGetScanner:
    """get_scanner resolves a scanner class by name and instantiates it."""

    def test_empty_name_is_rejected(self, tmp_path):
        engine = _build_engine(tmp_path)
        with pytest.raises(ValueError, match="Scanner name cannot be empty"):
            engine.get_scanner("   ")

    def test_unknown_name_is_rejected(self, tmp_path):
        engine = _build_engine(tmp_path)
        engine.plugins["scanner"] = []
        with pytest.raises(ValueError, match="Scanner nosuchscanner not found"):
            engine.get_scanner("NoSuchScanner")

    def test_matching_scanner_is_instantiated_with_engine_context(self, tmp_path):
        """The found class is constructed with the engine context and its plugin config."""
        engine = _build_engine(tmp_path)
        sentinel_config = object()
        engine._context.config = MagicMock(spec=AshConfig)
        engine._context.config.get_plugin_config.return_value = sentinel_config

        built = {}

        class FakeScanner:
            def __init__(self, context, config):
                built["context"] = context
                built["config"] = config

        engine.plugins["scanner"] = [FakeScanner]

        scanner = engine.get_scanner("fakescanner")

        assert isinstance(scanner, FakeScanner)
        assert built["context"] is engine._context
        assert built["config"] is sentinel_config
        engine._context.config.get_plugin_config.assert_called_once_with(
            plugin_type="scanner", plugin_name="fakescanner"
        )

    def test_lookup_is_case_and_whitespace_insensitive(self, tmp_path):
        engine = _build_engine(tmp_path)
        engine._context.config = None

        class MyScanner:
            def __init__(self, context, config):
                self.config = config

        engine.plugins["scanner"] = [MyScanner]

        scanner = engine.get_scanner("  MYSCANNER  ")

        assert isinstance(scanner, MyScanner)
        assert scanner.config is None


class TestEnsureInitialized:
    """ensure_initialized fills in a default config and rejects bad ones."""

    def test_missing_config_gets_a_default(self, tmp_path):
        """A context with no config is given a default AshConfig, not left empty."""
        ctx = _make_context(tmp_path)
        ctx.config = None
        engine = _build_engine(tmp_path, context=ctx)

        assert isinstance(engine._context.config, AshConfig)
        assert engine._context.config.project_name == "ASH Default Project Config"

    def test_non_ash_config_is_rejected(self, tmp_path):
        engine = _build_engine(tmp_path)
        engine._initialized = False

        with pytest.raises(
            ValueError, match="Configuration must be an AshConfig instance"
        ):
            engine.ensure_initialized(config="not-a-config")

    def test_excluded_scanners_are_removed_from_enabled_list(self, tmp_path):
        """Exclusion takes precedence over the enabled list, case-insensitively."""
        engine = _build_engine(
            tmp_path,
            enabled_scanners=["bandit,Semgrep", "checkov"],
            excluded_scanners=["SEMGREP"],
        )

        assert engine._init_enabled_scanners == ["bandit", "checkov"]
        assert engine._init_excluded_scanners == ["SEMGREP"]

    def test_exclusion_without_enabled_list_leaves_it_empty(self, tmp_path):
        engine = _build_engine(tmp_path, excluded_scanners=["semgrep"])
        assert engine._init_enabled_scanners == []


class TestExecutePhases:
    """execute_phases orders phases, dispatches them, and reports duration."""

    @pytest.fixture
    def engine(self, tmp_path):
        eng = _build_engine(tmp_path)
        eng.progress_display = MagicMock()
        eng.progress_display.live = None
        return eng

    def _run(self, engine, phases, phase_stubs=None, **extra_patches):
        """Execute phases with every phase class and metrics helper stubbed."""
        stubs = phase_stubs if phase_stubs is not None else {}
        patches = {
            "ConvertPhase": stubs.get("convert", _phase_stub_factory()),
            "ScanPhase": stubs.get("scan", _phase_stub_factory()),
            "ReportPhase": stubs.get("report", _phase_stub_factory()),
            "InspectPhase": stubs.get("inspect", _phase_stub_factory()),
        }
        with (
            patch(f"{_ENGINE_MODULE}.ConvertPhase", patches["ConvertPhase"]),
            patch(f"{_ENGINE_MODULE}.ScanPhase", patches["ScanPhase"]),
            patch(f"{_ENGINE_MODULE}.ReportPhase", patches["ReportPhase"]),
            patch(f"{_ENGINE_MODULE}.InspectPhase", patches["InspectPhase"]),
            patch(
                f"{_ENGINE_MODULE}.populate_metrics_from_unified_source",
                side_effect=lambda aggregated_results: aggregated_results,
            ),
            patch(f"{_ENGINE_MODULE}.display_metrics_table") as mock_table,
        ):
            result = (
                engine.execute_phases(phases=phases)
                if phases is not None
                else engine.execute_phases()
            )
        return result, patches, mock_table

    def test_default_phases_run_convert_scan_report(self, engine):
        """With no phases argument, convert, scan and report all execute once."""
        result, patches, _ = self._run(engine, None)

        assert len(patches["ConvertPhase"].instances) == 1
        assert len(patches["ScanPhase"].instances) == 1
        assert len(patches["ReportPhase"].instances) == 1
        assert patches["InspectPhase"].instances == []
        assert isinstance(result, AshAggregatedResults)

    def test_phases_execute_in_canonical_order_regardless_of_input(self, engine):
        """Reversed input still runs convert before scan before report before inspect."""
        order = []

        def _tracking_stub(name):
            cls = _phase_stub_factory()
            original_execute = cls.execute

            def execute(self, **kwargs):
                order.append(name)
                return original_execute(self, **kwargs)

            cls.execute = execute
            return cls

        stubs = {n: _tracking_stub(n) for n in ("inspect", "report", "scan", "convert")}
        self._run(engine, ["inspect", "report", "scan", "convert"], phase_stubs=stubs)

        assert order == ["convert", "scan", "report", "inspect"]

    def test_scan_phase_completed_scanners_are_captured(self, engine):
        """The scan phase's completed scanner list is copied onto the engine."""
        self._run(engine, ["scan"])
        assert engine._completed_scanners == ["stub_scanner"]

    def test_non_report_only_run_creates_work_dir(self, engine):
        """A run including convert creates the work directory; report-only does not."""
        work_dir = engine._context.work_dir
        assert not work_dir.exists()

        self._run(engine, ["convert", "report"])

        assert work_dir.is_dir()

    def test_report_only_run_skips_work_dir_creation(self, engine):
        work_dir = engine._context.work_dir
        self._run(engine, ["report"])
        assert not work_dir.exists()

    def test_reports_dir_is_always_created(self, engine):
        self._run(engine, ["report"])
        assert engine._context.output_dir.joinpath("reports").is_dir()

    def test_execution_start_notification_failure_does_not_abort(self, engine):
        """A broken EXECUTION_START subscriber is logged and the run continues."""
        with patch(
            "automated_security_helper.plugins.ash_plugin_manager.notify",
            side_effect=RuntimeError("subscriber exploded"),
        ):
            result, patches, _ = self._run(engine, ["report"])

        assert len(patches["ReportPhase"].instances) == 1
        assert isinstance(result, AshAggregatedResults)

    def test_phase_failure_is_reraised_after_error_notification(self, engine):
        """A phase exception propagates and an ERROR event is emitted."""
        failing = _phase_stub_factory()

        def execute(self, **kwargs):
            raise RuntimeError("scan phase exploded")

        failing.execute = execute

        notified = []

        def _record(event_type, **kwargs):
            notified.append((event_type, kwargs))

        with patch(
            "automated_security_helper.plugins.ash_plugin_manager.notify",
            side_effect=_record,
        ), pytest.raises(RuntimeError, match="scan phase exploded"):
            self._run(engine, ["scan"], phase_stubs={"scan": failing})

        from automated_security_helper.plugins.events import AshEventType

        error_events = [kw for et, kw in notified if et is AshEventType.ERROR]
        assert len(error_events) == 1
        assert error_events[0]["phase"] == "execution"
        assert "scan phase exploded" in error_events[0]["error"]

    def test_error_notification_failure_still_reraises_original(self, engine):
        """If the ERROR subscriber also fails, the phase exception still surfaces."""
        failing = _phase_stub_factory()

        def execute(self, **kwargs):
            raise RuntimeError("original failure")

        failing.execute = execute

        with patch(
            "automated_security_helper.plugins.ash_plugin_manager.notify",
            side_effect=RuntimeError("notify is broken too"),
        ), pytest.raises(RuntimeError, match="original failure"):
            self._run(engine, ["scan"], phase_stubs={"scan": failing})

    def test_completion_notification_failure_does_not_abort(self, engine):
        """A broken EXECUTION_COMPLETE subscriber does not fail the run."""
        from automated_security_helper.plugins.events import AshEventType

        def _selective(event_type, **kwargs):
            if event_type is AshEventType.EXECUTION_COMPLETE:
                raise RuntimeError("complete subscriber exploded")

        with patch(
            "automated_security_helper.plugins.ash_plugin_manager.notify",
            side_effect=_selective,
        ):
            result, _, mock_table = self._run(engine, ["report"])

        assert isinstance(result, AshAggregatedResults)
        assert mock_table.called, (
            "metrics table must still render after a failed notify"
        )

    def test_live_progress_display_is_stopped(self, engine):
        """A running live display is stopped in the finally block."""
        engine.progress_display.live = object()
        self._run(engine, ["report"])
        engine.progress_display.stop.assert_called_once()

    def test_summary_can_be_suppressed(self, engine):
        engine.show_summary = False
        _, _, mock_table = self._run(engine, ["report"])
        mock_table.assert_not_called()


class TestExecutePhasesDuration:
    """Duration formatting is driven by the module clock, not by wall time."""

    @pytest.fixture
    def engine(self, tmp_path):
        eng = _build_engine(tmp_path)
        eng.progress_display = MagicMock()
        eng.progress_display.live = None
        return eng

    def _run_with_clock(self, engine, elapsed_seconds):
        """Run a report-only phase with now() pinned to a fixed elapsed interval."""
        start = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        end = start + timedelta(seconds=elapsed_seconds)
        clock = MagicMock()
        clock.now.side_effect = [start, end]

        stub = _phase_stub_factory()
        with (
            patch(f"{_ENGINE_MODULE}.ConvertPhase", _phase_stub_factory()),
            patch(f"{_ENGINE_MODULE}.ScanPhase", _phase_stub_factory()),
            patch(f"{_ENGINE_MODULE}.ReportPhase", stub),
            patch(f"{_ENGINE_MODULE}.InspectPhase", _phase_stub_factory()),
            patch(
                f"{_ENGINE_MODULE}.populate_metrics_from_unified_source",
                side_effect=lambda aggregated_results: aggregated_results,
            ),
            patch(f"{_ENGINE_MODULE}.display_metrics_table"),
            patch(f"{_ENGINE_MODULE}.datetime", clock),
            patch(f"{_ENGINE_MODULE}.ASH_LOGGER") as mock_logger,
        ):
            result = engine.execute_phases(phases=["report"])

        completion = [
            str(c.args[0])
            for c in mock_logger.info.call_args_list
            if "Scan Completed in" in str(c.args[0])
        ]
        assert len(completion) == 1, completion
        return result, completion[0]

    def test_seconds_only_duration(self, engine):
        result, message = self._run_with_clock(engine, 42)
        assert "Completed in 42s" in message
        assert result.metadata.summary_stats.duration == 42

    def test_minutes_and_seconds_duration(self, engine):
        _, message = self._run_with_clock(engine, 125)
        assert "Completed in 2m 5s" in message

    def test_hours_minutes_and_seconds_duration(self, engine):
        _, message = self._run_with_clock(engine, 3725)
        assert "Completed in 1h 2m 5s" in message

    def test_start_and_end_times_come_from_the_clock(self, engine):
        result, _ = self._run_with_clock(engine, 60)
        assert result.metadata.summary_stats.start == datetime(
            2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc
        )
        assert result.metadata.summary_stats.end == datetime(
            2026, 1, 1, 12, 1, 0, tzinfo=timezone.utc
        )
