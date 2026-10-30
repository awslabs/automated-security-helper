# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The phases' plugin-failure lines carry no value the config read from the environment.

A plugin's own hooks (``missing_dependency_reason``, ``nothing_to_scan_reason``,
a reporter's constructor or ``report``) can raise an exception naming a
configured value, and the phases log those failures to ash.log. The helper
functions are module functions with no config in scope, so the values to
redact arrive as a parameter, the way ``error_text`` takes them.
"""

import logging
from unittest.mock import MagicMock

import pytest

from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.phases.scan_phase import (
    ScanPhase,
    _missing_dependency_reason,
    _nothing_to_scan_reason,
)
from automated_security_helper.core.phases.scanner_executor import (
    _missing_reason_after_scan,
    _skipped_reason_after_scan,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scanner_validation import (
    ScannerValidationManager,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()

CANARY = "/nonexistent/ENVCANARY-ph77/settings.yaml"


@pytest.fixture
def logged():
    lines = []

    class _Collect(logging.Handler):
        def emit(self, record):
            lines.append(logging.Formatter("%(message)s").format(record))

    handler = _Collect(level=logging.DEBUG)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.DEBUG)
    ASH_LOGGER.addHandler(handler)
    try:
        yield lines
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


class _RaisingHooks:
    """A plugin double whose explanation hooks raise with a configured value."""

    def missing_dependency_reason(self):
        raise RuntimeError(f"no tool at {CANARY}")

    def nothing_to_scan_reason(self):
        raise RuntimeError(f"no files under {CANARY}")


def test_missing_dependency_reason_logs_no_environment_value(logged):
    reason = _missing_dependency_reason(_RaisingHooks(), values=[CANARY])

    assert "dependency check failed" in reason, reason
    line = next(line for line in logged if "recording the generic reason" in line)
    assert "ENVCANARY-ph77" not in line, line


def test_nothing_to_scan_reason_logs_no_environment_value(logged):
    reason = _nothing_to_scan_reason(_RaisingHooks(), values=[CANARY])

    assert reason is None
    line = next(line for line in logged if "judged on its dependencies alone" in line)
    assert "ENVCANARY-ph77" not in line, line


def test_skipped_reason_after_scan_logs_no_environment_value(logged):
    reason = _skipped_reason_after_scan(
        _RaisingHooks(), "stub", "source", values=[CANARY]
    )

    assert reason, reason
    line = next(line for line in logged if "recording the generic reason" in line)
    assert "ENVCANARY-ph77" not in line, line


def test_missing_reason_after_scan_logs_no_environment_value(logged):
    reason = _missing_reason_after_scan(
        _RaisingHooks(), "stub", "source", values=[CANARY]
    )

    assert reason, reason
    lines = [line for line in logged if "recording the generic reason" in line]
    assert lines, logged
    for line in lines:
        assert "ENVCANARY-ph77" not in line, line


def _context(tmp_path):
    ctx = MagicMock()
    source_dir = tmp_path / "source"
    source_dir.mkdir(exist_ok=True)
    (source_dir / "app.py").write_text("x = 1")
    work_dir = tmp_path / "work"
    work_dir.mkdir(exist_ok=True)
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    ctx.source_dir = source_dir
    ctx.work_dir = work_dir
    ctx.output_dir = output_dir
    ctx.config = MagicMock()
    ctx.config._environment_values = [CANARY]
    ctx.config.get_plugin_config.return_value = MagicMock(enabled=True, name="mock")
    ctx.config.output_formats = []
    ctx.ignore_suppressions = False
    ctx.cached_source_files = []
    return ctx


def _plugin_class(name="CanaryPlugin"):
    cls = MagicMock(name=name)
    cls.__name__ = name
    instance = MagicMock()
    instance.__class__ = cls
    instance.__class__.__name__ = name
    cfg = MagicMock()
    cfg.enabled = True
    cfg.name = name.lower()
    cfg.extension = "txt"
    instance.config = cfg
    instance.is_python_only.return_value = True
    instance.validate_plugin_dependencies.return_value = True
    instance.report.return_value = None
    # A reporter without companion files answers none. Left unset, the
    # MagicMock answer is os.PathLike (it configures __fspath__) and would be
    # read as a file named after the mock, which the report-file-name check
    # refuses for its separators.
    instance.companion_file_names.return_value = ()
    instance.dependencies_satisfied = True
    cls.return_value = instance
    return cls


def test_scanner_check_failure_logs_no_environment_value(tmp_path, logged):
    """The per-scanner checking handler logs the exception and its stack trace."""
    plugin_cls = _plugin_class("CanaryScanner")
    phase = ScanPhase(
        plugin_context=_context(tmp_path),
        plugins=[plugin_cls],
        progress_display=MagicMock(),
        asharp_model=AshAggregatedResults(),
    )
    manager = MagicMock(spec=ScannerValidationManager)

    # Raised only at the queued-for-execution update, the one inside the
    # per-scanner checking handler; the earlier registration updates pass.
    def _raise_on_queued(*_args, **kwargs):
        if kwargs.get("queued_for_execution") is True and (
            kwargs.get("enablement_status") == "enabled"
        ):
            raise RuntimeError(f"could not read {CANARY}")
        return None

    manager.update_scanner_state.side_effect = _raise_on_queued
    phase.validation_manager = manager

    phase._execute_phase(aggregated_results=AshAggregatedResults())

    line = next(line for line in logged if "Error checking scanner" in line)
    assert "ENVCANARY-ph77" not in line, line
    for trace in (line for line in logged if "Stack trace:" in line):
        assert "ENVCANARY-ph77" not in trace, trace


def test_a_phase_failure_logs_no_environment_value(tmp_path, logged):
    """The phase's own catch-all logs the exception before re-raising."""
    phase = ScanPhase(
        plugin_context=_context(tmp_path),
        plugins=[_plugin_class("CanaryScanner")],
        progress_display=MagicMock(),
        asharp_model=AshAggregatedResults(),
    )
    manager = MagicMock(spec=ScannerValidationManager)
    manager.update_scanner_state.side_effect = RuntimeError(f"could not read {CANARY}")
    phase.validation_manager = manager

    with pytest.raises(RuntimeError):
        phase._execute_phase(aggregated_results=AshAggregatedResults())

    line = next(line for line in logged if "Execution failed" in line)
    assert "ENVCANARY-ph77" not in line, line


def test_reporter_creation_failure_logs_no_environment_value(tmp_path, logged):
    plugin_cls = _plugin_class("CanaryReporter")
    plugin_cls.side_effect = RuntimeError(f"could not open {CANARY}")
    ctx = _context(tmp_path)
    phase = ReportPhase(
        plugin_context=ctx,
        plugins=[plugin_cls],
        progress_display=MagicMock(),
    )

    phase._execute_phase(
        aggregated_results=AshAggregatedResults(), report_dir=ctx.output_dir
    )

    line = next(line for line in logged if "Error creating reporter" in line)
    assert "could not open" in line, line
    assert "ENVCANARY-ph77" not in line, line


def test_reporter_failure_logs_no_environment_value(tmp_path, logged):
    plugin_cls = _plugin_class("CanaryReporter")
    plugin_cls.return_value.report.side_effect = RuntimeError(
        f"could not open {CANARY}"
    )
    ctx = _context(tmp_path)
    phase = ReportPhase(
        plugin_context=ctx,
        plugins=[plugin_cls],
        progress_display=MagicMock(),
    )

    phase._execute_phase(
        aggregated_results=AshAggregatedResults(), report_dir=ctx.output_dir
    )

    line = next(line for line in logged if "Error in reporter" in line)
    assert "could not open" in line, line
    assert "ENVCANARY-ph77" not in line, line
    for trace in (line for line in logged if "Reporter exception traceback" in line):
        assert "ENVCANARY-ph77" not in trace, trace


def test_a_reporter_failure_progress_text_names_no_environment_value(tmp_path):
    """The reporter's task description, which the progress display shows."""
    plugin_cls = _plugin_class("CanaryReporter")
    plugin_cls.return_value.report.side_effect = RuntimeError(
        f"could not open {CANARY}"
    )
    ctx = _context(tmp_path)
    progress = MagicMock()
    phase = ReportPhase(
        plugin_context=ctx, plugins=[plugin_cls], progress_display=progress
    )

    phase._execute_phase(
        aggregated_results=AshAggregatedResults(), report_dir=ctx.output_dir
    )

    described = [
        call.kwargs.get("description") or ""
        for call in progress.update_task.call_args_list
    ]
    failed = [text for text in described if "Failed:" in text]
    assert failed, described
    for text in failed:
        assert "could not open" in text, text
        assert "ENVCANARY-ph77" not in text, text


def test_a_phase_failure_summary_row_names_no_environment_value(tmp_path):
    """The scan phase's "Failed" summary row, which the progress display shows."""
    progress = MagicMock()
    phase = ScanPhase(
        plugin_context=_context(tmp_path),
        plugins=[_plugin_class("CanaryScanner")],
        progress_display=progress,
        asharp_model=AshAggregatedResults(),
    )
    manager = MagicMock(spec=ScannerValidationManager)
    manager.update_scanner_state.side_effect = RuntimeError(f"could not read {CANARY}")
    phase.validation_manager = manager

    with pytest.raises(RuntimeError):
        phase._execute_phase(aggregated_results=AshAggregatedResults())

    rows = [call.args for call in progress.add_summary_row.call_args_list]
    failed = [args for args in rows if len(args) >= 3 and args[1] == "Failed"]
    assert failed, rows
    for args in failed:
        assert "could not read" in args[2], args
        assert "ENVCANARY-ph77" not in args[2], args


def test_a_nothing_to_scan_reason_names_no_environment_value(tmp_path, logged):
    """The reason a scanner without its tool gives for having nothing to scan.

    ScanPhase logs it at INFO and stores it as the scanner's enablement reason
    and as its row's skipped_reason, so each copy is redacted, as the
    executor's twin is.
    """
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
    from automated_security_helper.core.enums import ScannerStatus
    from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
        NpmAuditScanner,
    )

    class _NothingHere(NpmAuditScanner):
        def validate_plugin_dependencies(self) -> bool:
            return False

        def nothing_to_scan_reason(self):
            return f"no files under {CANARY}"

    _NothingHere.__name__ = NpmAuditScanner.__name__
    _NothingHere.__module__ = NpmAuditScanner.__module__
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    config = AshConfig(project_name="n15")
    config._environment_values = [CANARY]
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / ASH_WORK_DIR_NAME,
            config=config,
        ),
        plugins=[_NothingHere],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    # The enablement reason as it is written: a later enablement check
    # replaces it, so the end state does not show it.
    reasons = []
    update = phase.validation_manager.update_scanner_state

    def _recording(*args, **kwargs):
        if "enablement_reason" in kwargs:
            reasons.append(kwargs["enablement_reason"])
        return update(*args, **kwargs)

    phase.validation_manager.update_scanner_state = _recording

    results = phase._execute_phase(aggregated_results=aggregated, parallel=False)

    row = results.scanner_results["npm-audit"]
    # The control: the plugin's reason made it SKIPPED and is what was recorded.
    assert row.status == ScannerStatus.SKIPPED, row
    assert "no files under" in (row.skipped_reason or ""), row
    line = next(line for line in logged if "has nothing to scan" in line)
    assert "ENVCANARY-ph77" not in line, line
    written = [reason for reason in reasons if reason.startswith("Nothing to scan")]
    assert written, reasons
    for reason in written:
        assert "ENVCANARY-ph77" not in reason, reason
    stored = results.model_dump_json()
    assert "ENVCANARY-ph77" not in stored, row.skipped_reason


#: A value only the plugin's own ``_environment_values()`` gives: none of the
#: run's configuration's.
OWN_CANARY = "/etc/ENVCANARY-own-ph88/keys"


@pytest.mark.parametrize("when", ["checked", "ran"])
def test_a_missing_reason_is_redacted_with_the_plugin_s_own_values(
    tmp_path, logged, when
):
    """A MISSING scanner's reason, quoted on its row and in ash.log, is
    redacted with the run's values and the plugin's own, as ``ash
    dependencies install`` redacts its line. Checked: the dependency check
    before the scan refused (ScanPhase's row). Ran: the scan found its
    dependencies unavailable (the executor's row)."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
    from automated_security_helper.core.enums import ScannerStatus
    from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
        NpmAuditScanner,
    )

    class _OwnValues(NpmAuditScanner):
        def validate_plugin_dependencies(self) -> bool:
            return when == "ran"

        def nothing_to_scan_reason(self):
            return None

        def missing_dependency_reason(self):
            return f"needs a key file under {OWN_CANARY}"

        def _environment_values(self):
            return (*super()._environment_values(), OWN_CANARY)

        def scan(self, *args, **kwargs):
            return False

    _OwnValues.__name__ = NpmAuditScanner.__name__
    _OwnValues.__module__ = NpmAuditScanner.__module__
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    config = AshConfig(project_name="n1")
    config._environment_values = [CANARY]
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / ASH_WORK_DIR_NAME,
            config=config,
        ),
        plugins=[_OwnValues],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )

    from automated_security_helper.core.unified_metrics import (
        populate_metrics_from_unified_source,
    )

    # The rows as the execution engine leaves them after the scan phase: the
    # executor's MISSING reaches its row there.
    results = populate_metrics_from_unified_source(
        aggregated_results=phase._execute_phase(
            aggregated_results=aggregated, parallel=False
        )
    )

    row = results.scanner_results["npm-audit"]
    stored = results.model_dump_json()
    # The controls: the scanner is MISSING, and its own reason is what the row
    # and the WARNING quote.
    assert row.status == ScannerStatus.MISSING, row
    assert "needs a key file under" in stored, stored
    missing = [line for line in logged if "marking as MISSING" in line]
    assert any("needs a key file under" in line for line in missing), logged
    assert "ENVCANARY-own-ph88" not in stored, stored
    for line in missing:
        assert "ENVCANARY-own-ph88" not in line, line
