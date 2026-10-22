# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scanner executor's log lines show a tool's or an exception's text as given.

Why this file exists
--------------------
A log call that includes text a tool, a remote or an exception supplied has to
either escape Rich markup once or log with markup off, decided at the call. The
scanner executor logged such text with neither. That was safe only
because ASH's default console handler is built with markup off: under a handler
that renders markup, a "[/x]" in the text raised MarkupError and the line was
dropped, and a "[bold]" was obeyed instead of shown.

Each cell drives one call site and reads that record's own output through two
console handlers, one built with markup on and the default one with markup off.
In both the text shows as given: not dropped, not styled, and not escaped twice
(an escape the handler never consumes shows as a backslash). Nothing is reported
as a logging error.

Out of scope: lines that put in only ASH's own names and counts (a scanner's
configured name, a target type, a sandbox backend, counts), and the progress
display's descriptions, which escape the error already.
"""

from __future__ import annotations

import io
import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable, List, Tuple
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.phases import scanner_executor
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.console import ash_console
from automated_security_helper.utils.log import (
    ASH_LOGGER,
    TRACE_LEVEL,
    ConsoleHandler,
)
from automated_security_helper.utils.sandbox.scope import (
    SandboxBackendUnavailable,
    SandboxUnavailable,
)

PluginContext.model_rebuild()
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

#: Text a tool or an exception can hold: a closing tag that raises when parsed,
#: and a link and a style that would render instead of showing.
_GIVEN = "bad [/x] then [link=file:///tmp/x]here[/link] and [bold]B[/bold]"


class _RenderedPerRecord(ConsoleHandler):
    """ASH's console handler, keeping what it printed for each record."""

    def __init__(self, markup: bool) -> None:
        self.buffer = io.StringIO()
        super().__init__(
            console=ash_console(file=self.buffer, width=400, color_system=None),
            markup=markup,
            show_time=False,
            show_path=False,
        )
        self.setFormatter(logging.Formatter("%(message)s"))
        self.rendered: List[Tuple[logging.LogRecord, str]] = []

    def emit(self, record: logging.LogRecord) -> None:
        start = len(self.buffer.getvalue())
        super().emit(record)
        self.rendered.append((record, self.buffer.getvalue()[start:]))


@pytest.fixture
def consoles():
    """ASH_LOGGER at TRACE through a markup console and the default one."""
    handlers = [_RenderedPerRecord(markup=True), _RenderedPerRecord(markup=False)]
    saved_handlers, saved_level = list(ASH_LOGGER.handlers), ASH_LOGGER.level
    ASH_LOGGER.handlers = list(handlers)
    ASH_LOGGER.setLevel(TRACE_LEVEL)
    try:
        yield handlers
    finally:
        ASH_LOGGER.handlers = saved_handlers
        ASH_LOGGER.setLevel(saved_level)


def _shown_as_given(consoles, capsys, says: str) -> List[logging.LogRecord]:
    """Every record saying ``says`` reached both consoles with the text as given."""
    records: List[logging.LogRecord] = []
    for handler in consoles:
        saying = [(r, out) for r, out in handler.rendered if says in r.getMessage()]
        assert saying, f"no line says {says!r}, so the call was never reached"
        for record, out in saying:
            assert "[/x]" in record.getMessage(), (
                "the text never reached this line, so the cell shows nothing"
            )
            assert _GIVEN in out, (
                f"not shown as given (markup={handler.markup}):\n{out}"
            )
            assert "\\[" not in out, f"escaped twice (markup={handler.markup}):\n{out}"
            records.append(record)
    reported = capsys.readouterr().err
    assert "Logging error" not in reported, reported
    return records


# -- the scanners the cells run ------------------------------------------------------


class _Config(ScannerPluginConfigBase):
    name: str = "stub"


class _ConfigWithPatterns(_Config):
    """A config holding file patterns, which the executor logs with the config."""

    exclude: List[str] = [_GIVEN]


class _Moment(datetime):
    """A time that cannot be subtracted, so the duration's own handler logs."""

    def __sub__(self, other: Any) -> Any:
        raise RuntimeError(_GIVEN)


class _Stub(ScannerPluginBase):
    """A scanner whose scan() does what ``behavior`` names, and whose reasons raise."""

    behavior: str = "clean"

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("scan() is overridden directly")

    def scan(
        self, target, target_type=None, global_ignore_paths=None, config=None, *a, **k
    ):
        if self.behavior == "raises":
            raise RuntimeError(_GIVEN)
        if self.behavior == "missing":
            return False
        if self.behavior == "raw":
            return {"severity_counts": {}, "note": _GIVEN}
        if self.behavior == "nothing-scanned":
            self.targets_attempted = 0
        if self.behavior == "bad-times":
            self.start_time = _Moment(2026, 1, 1, tzinfo=timezone.utc)
            self.end_time = _Moment(2026, 1, 2, tzinfo=timezone.utc)
        return {"severity_counts": {}}

    def missing_dependency_reason(self) -> str:
        raise RuntimeError(_GIVEN)

    def nothing_to_scan_reason(self) -> str | None:
        raise RuntimeError(_GIVEN)


class _ConfigRaises:
    """A plugin whose config cannot be read: the executor's outer handler logs."""

    @property
    def config(self) -> Any:
        raise RuntimeError(_GIVEN)


def _raising(*args: Any, **kwargs: Any) -> Any:
    raise RuntimeError(_GIVEN)


def _context(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('x')\n")
    output = tmp_path / "output"
    output.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=tmp_path / "work",
        config=AshConfig(project_name="test"),
    )


def _targets(context) -> List[dict]:
    return [{"path": context.source_dir, "type": "source"}]


def _stub(context, behavior: str = "clean", name: str = "stub") -> _Stub:
    return _Stub(config=_Config(name=name), context=context, behavior=behavior)


def _executor(context, tasks=(), **kwargs) -> ScannerExecutor:
    return ScannerExecutor(
        plugin_context=context,
        progress_display=MagicMock(),
        scanner_tasks=list(tasks),
        **kwargs,
    )


# -- how each call site is reached -----------------------------------------------------


def _scan_one(behavior: str) -> Callable[..., None]:
    def drive(tmp_path, monkeypatch) -> None:
        context = _context(tmp_path)
        _executor(context)._execute_scanner(
            "stub", _stub(context, behavior), _targets(context)
        )

    return drive


def _the_config_holds_file_patterns(tmp_path, monkeypatch) -> None:
    context = _context(tmp_path)
    scanner = _Stub(config=_ConfigWithPatterns(), context=context)
    _executor(context)._execute_scanner("stub", scanner, _targets(context))


def _a_target_that_does_not_exist(tmp_path, monkeypatch) -> None:
    context = _context(tmp_path)
    gone = f"{tmp_path}/{_GIVEN}"
    _executor(context)._execute_scanner(
        "stub", _stub(context), [{"path": gone, "type": "source"}]
    )


def _the_sandbox_is_unavailable(tmp_path, monkeypatch) -> None:
    def refuses(*args: Any, **kwargs: Any) -> Any:
        raise SandboxBackendUnavailable(_GIVEN, "auto")

    monkeypatch.setattr(scanner_executor, "scanner_sandbox_scope", refuses)
    _scan_one("clean")(tmp_path, monkeypatch)


def _the_named_backend_is_unavailable(tmp_path, monkeypatch) -> None:
    def refuses(*args: Any, **kwargs: Any) -> Any:
        raise SandboxBackendUnavailable(_GIVEN, "bwrap")

    monkeypatch.setattr(scanner_executor, "scanner_sandbox_scope", refuses)
    _scan_one("clean")(tmp_path, monkeypatch)


def _the_sandbox_is_refused(tmp_path, monkeypatch) -> None:
    def refuses(*args: Any, **kwargs: Any) -> Any:
        raise SandboxUnavailable(_GIVEN)

    monkeypatch.setattr(scanner_executor, "scanner_sandbox_scope", refuses)
    _scan_one("clean")(tmp_path, monkeypatch)


def _the_error_notification_cannot_be_issued(tmp_path, monkeypatch) -> None:
    context = _context(tmp_path)
    executor = _executor(context)
    monkeypatch.setattr(executor, "_notify", _raising)
    executor._execute_scanner("stub", _stub(context, "raises"), _targets(context))


def _the_config_cannot_be_read(tmp_path, monkeypatch) -> None:
    context = _context(tmp_path)
    with pytest.raises(RuntimeError):
        _executor(context)._execute_scanner("stub", _ConfigRaises(), _targets(context))


def _the_scanner_raises_unexpectedly(tmp_path, monkeypatch) -> None:
    context = _context(tmp_path)
    _executor(context)._safe_execute_scanner("stub", _ConfigRaises(), _targets(context))


def _that_error_notification_cannot_be_issued(tmp_path, monkeypatch) -> None:
    context = _context(tmp_path)
    executor = _executor(context)
    monkeypatch.setattr(executor, "_notify", _raising)
    executor._safe_execute_scanner("stub", _ConfigRaises(), _targets(context))


def _a_subscriber_raises(tmp_path, monkeypatch) -> None:
    context = _context(tmp_path)
    tasks = [("stub", _stub(context), _targets(context))]
    _executor(context, tasks, notify_fn=_raising).run_sequential(MagicMock())


def _notifications_cannot_be_issued(parallel: bool) -> Callable[..., None]:
    def drive(tmp_path, monkeypatch) -> None:
        context = _context(tmp_path)
        names = ["stub-a", "stub-b"] if parallel else ["stub"]
        tasks = [(n, _stub(context, name=n), _targets(context)) for n in names]
        executor = _executor(context, tasks)
        monkeypatch.setattr(executor, "_notify", _raising)
        if parallel:
            executor.run_parallel(MagicMock())
        else:
            executor.run_sequential(MagicMock())

    return drive


def _results_cannot_be_processed(parallel: bool) -> Callable[..., None]:
    def drive(tmp_path, monkeypatch) -> None:
        context = _context(tmp_path)
        names = ["stub-a", "stub-b"] if parallel else ["stub"]
        tasks = [(n, _stub(context, name=n), _targets(context)) for n in names]
        executor = _executor(context, tasks, process_results_fn=_raising)
        if parallel:
            executor.run_parallel(MagicMock())
        else:
            executor.run_sequential(MagicMock())

    return drive


#: (what the line says, how the cell reaches it). Each id names the call by what
#: it logs; scanner_executor.py has each of them once.
CALLS = [
    pytest.param(
        "missing_dependency_reason() raised",
        _scan_one("missing"),
        id="missing-dependency-reason-raised",
    ),
    pytest.param(
        "nothing_to_scan_reason() raised",
        _scan_one("nothing-scanned"),
        id="nothing-to-scan-reason-raised",
    ),
    pytest.param(
        "Failed to notify event", _a_subscriber_raises, id="a-subscriber-raised"
    ),
    pytest.param(
        "scanner_plugin.config:",
        _the_config_holds_file_patterns,
        id="the-config-with-its-file-patterns",
    ),
    pytest.param(
        "does not exist", _a_target_that_does_not_exist, id="a-missing-target-skipped"
    ),
    pytest.param(
        "not run: scanner sandbox unavailable",
        _the_sandbox_is_unavailable,
        id="the-sandbox-is-unavailable",
    ),
    pytest.param(
        "could not start its tool",
        _the_named_backend_is_unavailable,
        id="the-named-backend-is-unavailable",
    ),
    pytest.param(
        "scanner sandbox was refused",
        _the_sandbox_is_refused,
        id="the-sandbox-is-refused",
    ),
    pytest.param(
        "Stack trace for scanner stub failure:",
        _scan_one("raises"),
        id="the-scans-stack-trace",
    ),
    pytest.param(
        "ERROR notification for stub could not be",
        _the_error_notification_cannot_be_issued,
        id="the-scans-error-notification-failed",
    ),
    pytest.param(
        "raw_results for source", _scan_one("raw"), id="the-raw-results-trace"
    ),
    pytest.param(
        "Error calculating duration for scanner",
        _scan_one("bad-times"),
        id="the-duration-failed",
    ),
    pytest.param(
        "Failed to execute _ConfigRaises scanner",
        _the_config_cannot_be_read,
        id="the-scanners-outer-handler",
    ),
    pytest.param(
        "Unexpected error in scanner stub",
        _the_scanner_raises_unexpectedly,
        id="an-unexpected-error",
    ),
    pytest.param(
        "Stack trace for scanner stub failure:",
        _the_scanner_raises_unexpectedly,
        id="an-unexpected-errors-stack-trace",
    ),
    pytest.param(
        "ERROR notification for stub could not be",
        _that_error_notification_cannot_be_issued,
        id="an-unexpected-errors-notification-failed",
    ),
    pytest.param(
        "SCAN_START notification for stub could not be",
        _notifications_cannot_be_issued(parallel=False),
        id="the-start-notification-failed",
    ),
    pytest.param(
        "SCAN_COMPLETE notification for stub could",
        _notifications_cannot_be_issued(parallel=False),
        id="the-complete-notification-failed",
    ),
    pytest.param(
        "Stack trace for scanner stub failure:",
        _results_cannot_be_processed(parallel=False),
        id="a-sequential-failures-stack-trace",
    ),
    pytest.param(
        "Scanner failed: stub",
        _results_cannot_be_processed(parallel=False),
        id="a-sequential-failure",
    ),
    pytest.param(
        "Failed to process error results for stub",
        _results_cannot_be_processed(parallel=False),
        id="a-sequential-failures-results-failed",
    ),
    pytest.param(
        "SCAN_COMPLETE notification for stub-",
        _notifications_cannot_be_issued(parallel=True),
        id="a-parallel-complete-notification-failed",
    ),
    pytest.param(
        "thread failure:",
        _results_cannot_be_processed(parallel=True),
        id="a-thread-failures-stack-trace",
    ),
    pytest.param(
        "Scanner execution failed in thread pool",
        _results_cannot_be_processed(parallel=True),
        id="a-thread-failure",
    ),
    pytest.param(
        "Failed to process error results for stub-",
        _results_cannot_be_processed(parallel=True),
        id="a-thread-failures-results-failed",
    ),
]


@pytest.mark.parametrize("says, drive", CALLS)
def test_the_executor_logs_tool_text_as_given(
    tmp_path, monkeypatch, consoles, capsys, says, drive
):
    drive(tmp_path, monkeypatch)

    _shown_as_given(consoles, capsys, says)


# -- an npm audit failure, through a scanner run ---------------------------------------


def test_an_npm_audit_failure_logs_its_reason_as_given(
    tmp_path, monkeypatch, consoles, capsys
):
    """The reason npm gave is the scanner's error, and the executor logs it with
    markup off, so the line shows it as npm wrote it."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        npm_audit_scanner,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
        NpmAuditScanner,
        NpmAuditScannerConfig,
    )

    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True)
    (context.source_dir / "package.json").write_text(
        json.dumps({"name": "placeholder-app", "version": "1.0.0"}), encoding="utf-8"
    )
    (context.source_dir / "package-lock.json").write_text(
        json.dumps({"name": "placeholder-app", "lockfileVersion": 3}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        npm_audit_scanner, "find_executable", lambda name: str(tmp_path / name)
    )
    failed = {
        "stdout": json.dumps(
            {"message": _GIVEN, "error": {"summary": "", "detail": ""}}
        ),
        "stderr": "",
        "returncode": 1,
    }

    def respond(self, command, **kwargs):
        if "--version" in command:
            return {"stdout": "10.9.4", "stderr": "", "returncode": 0}
        self._process_command_response(failed)
        return dict(failed)

    scanner = NpmAuditScanner(context=context, config=NpmAuditScannerConfig())
    with patch.object(
        NpmAuditScanner, "_run_subprocess", autospec=True, side_effect=respond
    ):
        (container,) = _executor(context)._execute_scanner(
            "npm-audit", scanner, _targets(context)
        )

    assert _GIVEN in container.raw_results["errors"][0], container.raw_results
    records = _shown_as_given(
        consoles, capsys, "Failed to execute npm-audit scanner on source"
    )
    assert all(getattr(r, "markup", None) is False for r in records), [
        getattr(r, "markup", None) for r in records
    ]
