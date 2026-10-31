"""A scanner that raises SystemExit is that scanner's failure, not the end of the scan.

A scanner's in-process code can call ``sys.exit`` (a tool run as a library, a
plugin's own guard). SystemExit is not an Exception, so neither the per-target
handler nor ``_safe_execute_scanner`` caught it: it escaped every handler, no
scanner was recorded, and in parallel mode the pool ran every queued scanner to
completion before the process exited with the plugin's code.

Both handlers now catch SystemExit beside Exception. The control: a keyboard
interrupt is still not caught and still ends the scan.

Two more facts. The row's reason names the exit: ``str(SystemExit(3))`` is ``3``
and ``str(SystemExit())`` is empty, so the reason read "...: 3" or ended in nothing
and never said the plugin called ``sys.exit``. And a SystemExit raised while a
shutdown signal has asked the scans to stop (an embedder's SIGTERM handler, chained
before ASH's own, calling ``sys.exit`` on the main thread) is the process's
shutdown, not the scanner's: both handlers let it through, so the scan ends with
the process instead of recording one scanner's ERROR and moving on to the next.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, Literal
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import (
    OfflineStrategy,
    ScannerStatus,
    ScannerToolType,
)
from automated_security_helper.core.phases import scanner_executor
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


class _Config(ScannerPluginConfigBase):
    name: Literal["shape-tool"] = "shape-tool"


class ExitingScanner(ScannerPluginBase):
    """``scan()`` raises what ``raises`` holds."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    def model_post_init(self, context):
        self.command = "shape-tool"
        self.tool_type = ScannerToolType.SAST
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("scan() is overridden directly")

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        self._pre_scan(target=target, target_type=target_type, config=config)
        self._post_scan(target=target, target_type=target_type)
        raise self.raises


@pytest.fixture
def plugin_context(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(project_name="exits"),
    )


def _scanner(plugin_context, raises: BaseException):
    scanner = ExitingScanner(config=_Config(), context=plugin_context)
    scanner.raises = raises
    return scanner


def _executor(plugin_context):
    return ScannerExecutor(
        plugin_context=plugin_context, progress_display=MagicMock(), scanner_tasks=[]
    )


def _targets(plugin_context):
    return [{"path": Path(plugin_context.source_dir), "type": "source"}]


def test_a_system_exit_from_scan_is_the_rows_error(plugin_context):
    (row,) = _executor(plugin_context)._execute_scanner(
        "shape-tool", _scanner(plugin_context, SystemExit(3)), _targets(plugin_context)
    )

    assert row.status == ScannerStatus.ERROR
    assert row.raw_results["status"] == "failed"
    assert any("Failed to execute shape-tool" in str(e) for e in row.errors), row.errors


def test_a_system_exit_outside_the_per_target_handler_is_a_failure_container(
    plugin_context, monkeypatch
):
    executor = _executor(plugin_context)

    def exits(*args, **kwargs):
        raise SystemExit(4)

    monkeypatch.setattr(executor, "_execute_scanner", exits)

    results, succeeded = executor._safe_execute_scanner(
        "shape-tool", _scanner(plugin_context, SystemExit(4)), _targets(plugin_context)
    )

    assert succeeded is False
    (container,) = results
    assert container.raw_results["status"] == "failed"


def test_a_keyboard_interrupt_still_ends_the_scan(plugin_context):
    """Control: an interrupt is not a scanner's failure."""
    with pytest.raises(KeyboardInterrupt):
        _executor(plugin_context)._execute_scanner(
            "shape-tool",
            _scanner(plugin_context, KeyboardInterrupt()),
            _targets(plugin_context),
        )


def test_a_keyboard_interrupt_still_ends_the_scan_at_the_scanner_handler(
    plugin_context, monkeypatch
):
    """Control for the outer handler: it catches ``(Exception, SystemExit)`` and
    is the handler most likely to be widened, so the interrupt is pinned here
    as well as at the per-target one."""
    executor = _executor(plugin_context)

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(executor, "_execute_scanner", interrupted)

    with pytest.raises(KeyboardInterrupt):
        executor._safe_execute_scanner(
            "shape-tool",
            _scanner(plugin_context, KeyboardInterrupt()),
            _targets(plugin_context),
        )


def _reasons(row) -> str:
    return " ".join(str(error) for error in row.errors)


@pytest.mark.parametrize("code", [3, 0, None, "no rules were loaded"])
def test_the_rows_reason_names_the_exit_and_its_code(plugin_context, code):
    (row,) = _executor(plugin_context)._execute_scanner(
        "shape-tool",
        _scanner(plugin_context, SystemExit(code)),
        _targets(plugin_context),
    )

    assert row.status == ScannerStatus.ERROR
    assert f"the scanner called sys.exit({code!r})" in _reasons(row), row.errors
    assert not _reasons(row).rstrip().endswith("source:"), row.errors


ENV_CANARY = "env-read-canary-u18x-value"


def test_an_exit_message_quoting_an_environment_value_is_redacted(
    plugin_context, caplog
):
    """The named exit is built from the plugin's exit code, which can be a message
    quoting a value the configuration read from the environment. Written from
    the raw code it reached the row's errors, the failure dict, the ERROR log
    record and the ERROR event in clear, beside a description error_text had
    redacted. Red at the base: the value was in the row's reasons and in the
    log."""
    plugin_context.config._environment_values = [ENV_CANARY]
    (row,) = _executor(plugin_context)._execute_scanner(
        "shape-tool",
        _scanner(plugin_context, SystemExit(f"token {ENV_CANARY} refused")),
        _targets(plugin_context),
    )

    assert row.status == ScannerStatus.ERROR
    reasons = _reasons(row)
    assert "the scanner called sys.exit(" in reasons, row.errors
    assert ENV_CANARY not in reasons, row.errors
    assert ENV_CANARY not in str(row.raw_results), row.raw_results
    # The same text is what the per-target handler logs at ERROR (its ``err_str``).
    assert "Failed to execute shape-tool scanner" in caplog.text
    assert ENV_CANARY not in caplog.text
    # The control: the plain code reads as before beside the planted value.
    (plain,) = _executor(plugin_context)._execute_scanner(
        "shape-tool", _scanner(plugin_context, SystemExit(3)), _targets(plugin_context)
    )
    assert "the scanner called sys.exit(3)" in _reasons(plain), plain.errors


def test_the_scanner_handler_redacts_an_environment_value_from_the_exit(
    plugin_context, monkeypatch, caplog
):
    """The outer handler writes the exit into its own reason, its failure dict and
    its ERROR log line. A value the configuration read from the environment, quoted
    in the exit's message, must be redacted from all three there as well."""
    plugin_context.config._environment_values = [ENV_CANARY]
    executor = _executor(plugin_context)
    monkeypatch.setattr(
        executor,
        "_execute_scanner",
        lambda *a, **k: (_ for _ in ()).throw(
            SystemExit(f"token {ENV_CANARY} refused")
        ),
    )

    (container,), succeeded = executor._safe_execute_scanner(
        "shape-tool",
        _scanner(plugin_context, SystemExit(0)),
        _targets(plugin_context),
    )

    assert succeeded is False
    reasons = _reasons(container)
    assert "the scanner called sys.exit(" in reasons, container.errors
    assert ENV_CANARY not in reasons, container.errors
    assert ENV_CANARY not in str(container.raw_results), container.raw_results
    assert "Unexpected error in scanner shape-tool" in caplog.text
    assert ENV_CANARY not in caplog.text


def test_a_failure_containers_reason_names_the_exit_too(plugin_context, monkeypatch):
    executor = _executor(plugin_context)
    monkeypatch.setattr(
        executor,
        "_execute_scanner",
        lambda *a, **k: (_ for _ in ()).throw(SystemExit(4)),
    )

    (container,), succeeded = executor._safe_execute_scanner(
        "shape-tool", _scanner(plugin_context, SystemExit(4)), _targets(plugin_context)
    )

    assert succeeded is False
    assert "the scanner called sys.exit(4)" in _reasons(container), container.errors


class TestAShutdownsExitStillEndsTheScan:
    """A SystemExit raised while shutdown_requested() is True is the process's
    shutdown (an embedder's SIGTERM handler calling sys.exit on the main thread),
    not the scanner's own exit: both handlers let it through."""

    def test_the_per_target_handler_lets_it_through(self, plugin_context, monkeypatch):
        monkeypatch.setattr(scanner_executor, "shutdown_requested", lambda: True)

        with pytest.raises(SystemExit):
            _executor(plugin_context)._execute_scanner(
                "shape-tool",
                _scanner(plugin_context, SystemExit(0)),
                _targets(plugin_context),
            )

    def test_the_scanner_in_flight_is_not_logged_as_returning_no_result(
        self, plugin_context, monkeypatch, caplog
    ):
        """Red at the base: the exit left the handler before the interrupted record
        was set, so the finally block logged "returned no result" at ERROR, the
        line the interrupted branch exists to keep out of the log."""
        monkeypatch.setattr(scanner_executor, "shutdown_requested", lambda: True)

        with pytest.raises(SystemExit):
            _executor(plugin_context)._execute_scanner(
                "shape-tool",
                _scanner(plugin_context, SystemExit(0)),
                _targets(plugin_context),
            )

        assert "returned no result" not in caplog.text, caplog.text

    def test_the_scanner_handler_lets_it_through(self, plugin_context, monkeypatch):
        monkeypatch.setattr(scanner_executor, "shutdown_requested", lambda: True)
        executor = _executor(plugin_context)
        monkeypatch.setattr(
            executor,
            "_execute_scanner",
            lambda *a, **k: (_ for _ in ()).throw(SystemExit(0)),
        )

        with pytest.raises(SystemExit):
            executor._safe_execute_scanner(
                "shape-tool",
                _scanner(plugin_context, SystemExit(0)),
                _targets(plugin_context),
            )

    def test_control_a_plugins_exit_is_still_caught_with_no_shutdown(
        self, plugin_context, monkeypatch
    ):
        monkeypatch.setattr(scanner_executor, "shutdown_requested", lambda: False)

        (row,) = _executor(plugin_context)._execute_scanner(
            "shape-tool",
            _scanner(plugin_context, SystemExit(0)),
            _targets(plugin_context),
        )

        assert row.status == ScannerStatus.ERROR


def test_a_parallel_run_records_the_exiting_scanner_and_the_clean_one(
    plugin_context,
):
    """The parallel symptom: an escaping SystemExit made the pool run every queued
    scanner and then exit the process with the plugin's code, recording none."""
    exiting = _scanner(plugin_context, SystemExit(3))
    clean = _scanner(plugin_context, SystemExit(0))
    clean.scan = lambda *a, **k: {"findings": []}  # type: ignore[method-assign]
    executor = ScannerExecutor(
        plugin_context=plugin_context,
        progress_display=MagicMock(),
        scanner_tasks=[
            ("exiting", exiting, _targets(plugin_context)),
            ("clean", clean, _targets(plugin_context)),
        ],
        max_workers=2,
    )

    results = executor.run_parallel(AshAggregatedResults())

    assert results is not None
    # completed_scanners holds the plugin instances, not the task names.
    assert executor.completed_scanners == [clean]
    # The test is named for recording the exiting scanner: its row must be filed
    # under the task's name, read as an error, and say it called sys.exit. A
    # dropped row would leave the scanner out of the results with no other check
    # noticing.
    assert "exiting" in results.additional_reports, sorted(results.additional_reports)
    exiting_reports = results.additional_reports["exiting"]
    assert exiting_reports, results.additional_reports
    for exiting_report in exiting_reports.values():
        _excluded, _deps_missing, read_as_error = (
            ScannerStatisticsCalculator._status_info_from_report(exiting_report)
        )
        assert read_as_error is True, exiting_report
        assert "sys.exit(3)" in " ".join(str(e) for e in exiting_report["errors"]), (
            exiting_report
        )
    assert "clean" in results.additional_reports, sorted(results.additional_reports)
