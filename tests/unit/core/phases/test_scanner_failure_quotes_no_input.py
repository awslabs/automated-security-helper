# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner's failure is recorded without the input a pydantic error refused.

The scan phase records a failing scanner's exception and stack trace in its
results container, which the results file and the reports keep, and logs it.
A pydantic error's own text quotes the refused input, which can be a secret.
The error here comes from a model that does not hide its inputs, as a
plugin's own model might.
"""

import logging
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel, ValidationError

from automated_security_helper.utils.error_text import error_text, traceback_text
from automated_security_helper.utils.log import ASH_LOGGER
from tests.unit.core.phases.test_scanner_executor_lifecycle import (
    _EXEC_MODULE,
    _make_context,
    _make_executor,
    _make_scanner,
    _targets,
)

pytestmark = pytest.mark.unit

CANARY = "ash-canary-7f3e"


class _Unhidden(BaseModel):
    flag: bool


def _refused() -> ValidationError:
    try:
        _Unhidden.model_validate({"flag": CANARY})
    except ValidationError as error:
        assert CANARY in str(error), "the control: this model quotes its input"
        return error
    raise AssertionError("the canary was accepted")


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


def _no_canary(container, logged):
    recorded = repr(container.raw_results) + repr(getattr(container, "errors", ""))
    assert CANARY not in recorded, recorded
    text = "\n".join(logged)
    assert CANARY not in text, text


def test_a_scan_that_raises(tmp_path, logged):
    ctx = _make_context(tmp_path)
    scanner = _make_scanner(ctx, scripted_result=_refused())
    executor = _make_executor(ctx)

    (container,) = executor._execute_scanner("scripted", scanner, _targets(ctx))

    assert "flag" in container.raw_results["exception"]
    assert "ValidationError" in container.raw_results["stack_trace"]
    _no_canary(container, logged)


def test_an_unhandled_failure(tmp_path, logged):
    ctx = _make_context(tmp_path)
    executor = _make_executor(ctx)

    with patch.object(executor, "_execute_scanner", side_effect=_refused()):
        results, succeeded = executor._safe_execute_scanner("s", MagicMock(), [])

    assert succeeded is False
    _no_canary(results[0], logged)


def test_traceback_text_keeps_the_frames():
    try:
        raise _refused()
    except ValidationError as error:
        text = traceback_text()
        assert text == traceback_text(error)
    assert "Traceback (most recent call last)" in text
    assert "test_traceback_text_keeps_the_frames" in text
    assert CANARY not in text, text
    assert "Invalid value at 'flag'" in text


def test_error_text_of_an_unrelated_error_is_its_text():
    assert error_text(OSError("disk full")) == "disk full"


# ---------------------------------------------------------------------------
# Nor a value the config read from the environment
# ---------------------------------------------------------------------------
#
# A config option can come from the environment (``${VAR}``), and an exception
# that names the option's value carries it. The per-target handler redacts the
# config's environment values from what it records; each catch-all behind it
# records the same exception, so each redacts the same values: in the error
# message, the exception and stack trace fields, and what it logs.

ENV_CANARY = "/nonexistent/ENVCANARY-9c1d/settings.toml"

#: An under-HOME value too: once a handler writes it as ~, the absolute
#: spelling the redaction matches is gone, so redaction has to run first.
HOME_CANARY_TAIL = "ENVCANARY-home-11aa/settings.toml"


def _home_canary() -> str:
    from pathlib import Path

    return (Path.home() / HOME_CANARY_TAIL).as_posix()


def _context_reading_the_environment(tmp_path):
    ctx = _make_context(tmp_path)
    ctx.config._environment_values = [ENV_CANARY, _home_canary()]
    return ctx


def _raises_with_the_value(*_args, **_kwargs):
    raise RuntimeError(f"could not open {ENV_CANARY} or {_home_canary()}")


def _no_environment_value(containers, logged):
    recorded = "\n".join(
        repr(container.raw_results)
        + repr(container.errors)
        + repr(container.exception)
        + repr(container.stack_trace)
        for container in containers
    )
    assert "could not open" in recorded, "the control: the failure was recorded"
    assert "ENVCANARY-9c1d" not in recorded, recorded
    assert "ENVCANARY-home-11aa" not in recorded, recorded
    text = "\n".join(logged)
    assert "could not open" in text, "the control: the failure was logged"
    assert "ENVCANARY-9c1d" not in text, text
    assert "ENVCANARY-home-11aa" not in text, text


def test_an_unhandled_failure_records_no_environment_value(tmp_path, logged):
    executor = _make_executor(_context_reading_the_environment(tmp_path))

    with patch.object(executor, "_execute_scanner", side_effect=_raises_with_the_value):
        results, succeeded = executor._safe_execute_scanner("s", MagicMock(), [])

    assert succeeded is False
    _no_environment_value(results, logged)


def test_a_failure_outside_the_targets_records_no_environment_value(tmp_path, logged):
    """Raised inside _execute_scanner but before any target's own handler.

    _execute_scanner logs it and re-raises, and _safe_execute_scanner records it.
    """
    ctx = _context_reading_the_environment(tmp_path)
    scanner = _make_scanner(ctx, scripted_result={"status": "ok"})
    executor = _make_executor(ctx)

    with patch(f"{_EXEC_MODULE}._ScannerHeartbeat", side_effect=_raises_with_the_value):
        results, succeeded = executor._safe_execute_scanner(
            "scripted", scanner, _targets(ctx)
        )

    assert succeeded is False
    _no_environment_value(results, logged)


@pytest.mark.parametrize("run", ["run_sequential", "run_parallel"])
def test_a_run_whose_scanner_raised_records_no_environment_value(tmp_path, logged, run):
    ctx = _context_reading_the_environment(tmp_path)
    executor = _make_executor(
        ctx,
        [
            ("first", _make_scanner(ctx), _targets(ctx)),
            ("second", _make_scanner(ctx), _targets(ctx)),
        ],
        max_workers=2,
    )
    processed = []

    def _process(container, aggregated):
        processed.append(container)
        return aggregated

    executor._process_fn = _process
    with patch.object(
        executor, "_safe_execute_scanner", side_effect=_raises_with_the_value
    ):
        getattr(executor, run)(MagicMock())

    assert len(processed) == 2, processed
    _no_environment_value(processed, logged)


def test_a_timed_out_scanner_line_carries_no_environment_value(tmp_path, logged):
    """The lead-with-the-timeout line prints the configured limit.

    A limit is a short number, which redacts only where the message quotes it
    whole, so it has to be printed as its own quoted token.
    """
    ctx = _make_context(tmp_path)
    ctx.config._environment_values = ["67"]
    scanner = _make_scanner(ctx)
    executor = _make_executor(ctx)

    # Recorded inside scan(): the executor clears the recorded timeout before
    # each scan, so a value set beforehand would be wiped.
    def _timed_out_scan(self, *_args, **_kwargs):
        self._record_timeout({"timed_out": True}, 67)
        raise RuntimeError("tool crashed")

    with patch.object(type(scanner), "scan", _timed_out_scan):
        (container,) = executor._execute_scanner("scripted", scanner, _targets(ctx))

    lines = [line for line in logged if "timed out after" in line]
    assert any("and was killed" in line for line in lines), logged
    for line in lines:
        assert "67" not in line, line
    recorded = next(
        error for error in container.raw_results["errors"] if "timed out after" in error
    )
    assert "67" not in recorded, recorded


def test_an_unfinished_run_reason_carries_no_environment_value(tmp_path, logged):
    """A run that kept its timed_out flag names the limit in its reason.

    The reason goes through ScannerError into the recorded error, so the limit
    has to be the quoted token the downstream redaction can find.
    """
    ctx = _make_context(tmp_path)
    ctx.config._environment_values = ["67"]
    scanner = _make_scanner(ctx)
    executor = _make_executor(ctx)

    # Recorded inside scan(), after the executor's pre-scan clears.
    def _kept_flag_scan(self, *_args, **_kwargs):
        self._record_timeout({"timed_out": True}, 67)
        self._record_kept_flag({"timed_out": True, "error": "the tool was stopped"})
        return {"status": "ok"}

    with patch.object(type(scanner), "scan", _kept_flag_scan):
        (container,) = executor._execute_scanner("scripted", scanner, _targets(ctx))

    recorded = next(
        error for error in container.raw_results["errors"] if "timed out" in error
    )
    assert "the tool was stopped" in recorded, recorded
    assert "67" not in recorded, recorded
    line = next(line for line in logged if "timed out" in line)
    assert "67" not in line, line


def test_a_swallowed_timeout_still_fails_a_normally_returning_scan(tmp_path, logged):
    """The timeout flag CAN be set on the normal-return path: a tool killed at
    the limit leaves a timed_out response, and a scan() override that reads
    the missing output as "no findings" returns normally. The production
    recorder (_record_response, the entry _run_subprocess drives) sets the
    kept flag from the SAME response that sets the timeout -- on the raise
    path the handler's direct state steps backstop both -- so the executor's
    unfinished-run re-check reports the timeout without reading the timeout
    attribute again on this path. This cell drives the full recorder, not
    hand-set flags, so it also holds that coupling."""
    ctx = _make_context(tmp_path)
    scanner = _make_scanner(ctx)
    executor = _make_executor(ctx)

    def _swallowing_scan(self, *_args, **_kwargs):
        self._record_response(
            {"timed_out": True, "error": "the tool was stopped", "returncode": -1},
            67,
            set(),
        )
        return {"status": "ok"}

    with patch.object(type(scanner), "scan", _swallowing_scan):
        (container,) = executor._execute_scanner("scripted", scanner, _targets(ctx))

    # The coupling the production recorder guarantees: a set timeout never
    # travels without the kept flag the executor re-checks.
    assert scanner.scan_timed_out_after == 67
    assert scanner.scan_kept_flag is not None, "timeout recorded without the kept flag"
    recorded = next(
        error for error in container.raw_results["errors"] if "timed out" in error
    )
    assert "the tool was stopped" in recorded, recorded
    assert container.raw_results.get("status") == "failed", container.raw_results


def _timeout_lines(container, logged):
    recorded = [
        error for error in container.raw_results["errors"] if "timed out" in error
    ]
    return recorded, [line for line in logged if "timed out" in line]


def _without_embedded_paths(text: str, tmp_path) -> str:
    """Logged lines carry absolute paths and traceback locations -- the
    package's own files in stack traces, the interpreter under the venv,
    the tmp dir, "line N" -- and a short canary can appear inside any of
    them (a worktree or venv dir name, a line number), so value-absence
    checks run with those spans masked. A value echoed on its own is
    outside every masked span and still fails the check."""
    import re
    import sys
    from pathlib import Path

    import automated_security_helper as _ash

    for spelling in (
        str(tmp_path),
        tmp_path.as_posix(),
        sys.executable,
        sys.prefix,
        str(Path(_ash.__file__).parent),
    ):
        if spelling:
            text = text.replace(spelling, "<path>")
    return re.sub(r"line \d+", "line <n>", text)


def test_an_unfinished_run_reason_names_the_option_for_an_env_typed_limit(
    tmp_path, logged
):
    """An environment value the model typed to the limit ("067" loads as 67)
    would print as '67', which no needle matches: the reason names the option
    instead, through the token every timeout message shares."""
    ctx = _make_context(tmp_path)
    ctx.config._environment_values = ["067"]
    scanner = _make_scanner(ctx)
    executor = _make_executor(ctx)

    def _kept_flag_scan(self, *_args, **_kwargs):
        self._record_timeout({"timed_out": True}, 67)
        self._record_kept_flag({"timed_out": True, "error": "the tool was stopped"})
        return {"status": "ok"}

    with patch.object(type(scanner), "scan", _kept_flag_scan):
        (container,) = executor._execute_scanner("scripted", scanner, _targets(ctx))

    recorded, lines = _timeout_lines(container, logged)
    reason = next(error for error in recorded if "the tool was stopped" in error)
    assert "the configured scan_timeout" in reason, reason
    assert all(
        "67" not in _without_embedded_paths(text, tmp_path) for text in recorded + lines
    ), recorded + lines


def test_a_timed_out_scan_that_raised_names_the_option_for_an_env_typed_limit(
    tmp_path, logged
):
    """The other executor timeout line: a scan that recorded its timeout and
    then raised for another reason is reported as timed out, with the same
    token for the limit."""
    ctx = _make_context(tmp_path)
    ctx.config._environment_values = ["067"]
    scanner = _make_scanner(ctx)
    executor = _make_executor(ctx)

    def _timed_out_then_raised(self, *_args, **_kwargs):
        self._record_timeout({"timed_out": True}, 67)
        raise RuntimeError("tool crashed")

    with patch.object(type(scanner), "scan", _timed_out_then_raised):
        (container,) = executor._execute_scanner("scripted", scanner, _targets(ctx))

    recorded, lines = _timeout_lines(container, logged)
    killed = next(error for error in recorded if "was killed: " in error)
    assert "timed out after the configured scan_timeout" in killed, killed
    assert all(
        "67" not in _without_embedded_paths(text, tmp_path) for text in recorded + lines
    ), recorded + lines


def test_a_spawn_failure_line_carries_no_environment_value(tmp_path, logged):
    """The could-not-start line repeats the plugin's recorded spawn failure,
    which carries the tool's stderr and can name a configured value."""
    ctx = _context_reading_the_environment(tmp_path)
    scanner = _make_scanner(ctx)
    executor = _make_executor(ctx)

    def _spawn_failed_scan(self, *_args, **_kwargs):
        self._record_spawn_failure(
            {
                "spawn_failed": True,
                "stderr": f"Could not start tool --configfile {ENV_CANARY}",
            }
        )
        raise RuntimeError("tool crashed")

    with patch.object(type(scanner), "scan", _spawn_failed_scan):
        (container,) = executor._execute_scanner("scripted", scanner, _targets(ctx))

    line = next(line for line in logged if "could not start its tool on" in line)
    assert "ENVCANARY-9c1d" not in line, line
    recorded = next(
        error
        for error in container.raw_results["errors"]
        if "could not start its tool on" in error
    )
    assert "ENVCANARY-9c1d" not in recorded, recorded


def test_a_post_run_error_line_carries_no_environment_value(tmp_path, logged):
    """The could-not-record line repeats the plugin's recorded post-run error,
    which an overriding scanner can have filled with a configured value."""
    ctx = _context_reading_the_environment(tmp_path)
    scanner = _make_scanner(ctx)
    executor = _make_executor(ctx)

    # Recorded inside scan(), after the executor's pre-scan clears.
    def _post_run_error_scan(self, *_args, **_kwargs):
        self._record_post_run_error(
            {"post_run_error": True, "error": f"could not read {ENV_CANARY}"}
        )
        raise RuntimeError("tool crashed")

    with patch.object(type(scanner), "scan", _post_run_error_scan):
        (container,) = executor._execute_scanner("scripted", scanner, _targets(ctx))

    line = next(
        line for line in logged if "could not record the scanner's output" in line
    )
    assert "ENVCANARY-9c1d" not in line, line
    recorded = next(
        error
        for error in container.raw_results["errors"]
        if "could not record the scanner's output" in error
    )
    assert "ENVCANARY-9c1d" not in recorded, recorded
