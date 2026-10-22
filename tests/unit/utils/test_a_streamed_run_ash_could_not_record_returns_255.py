# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A streamed run that ASH failed to record returns one fixed code, never the tool's.

Why this file exists
--------------------
``run_command_stream_output`` returns a bare exit code, so it has no flag to say
that ASH, not the tool, failed. A failure after the child started (relaying its
output, waiting on it, or the later kill or wait) answers
UNRECORDED_RUN_RETURNCODE. Most scanners accept 1 as "ran and found issues" and
read 0 as a clean run, so a run ASH failed to record answers a code that is
neither.

The answers are fixed:

- a failure before the child started is 127, as for every runner;
- once it started, any failure on ASH's side is UNRECORDED_RUN_RETURNCODE (255),
  one documented constant: never the tool's own code, never 0 or 127. Even when
  only the later kill or wait raised, the run fails closed;
- each such failure is logged on one line, its controls escaped, naming the error,
  and Rich markup in it shows as text;
- the docstring states the limit and points callers that need flags at
  run_command_with_output_handling.

A clean run keeps the tool's code.
"""

from __future__ import annotations

import inspect
import io
import logging
import subprocess
import sys
from typing import Any, List

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import (
    SPAWN_FAILURE_RETURNCODE,
    run_command_stream_output,
)

#: The documented value; the constant itself is pinned by its own cell below.
UNRECORDED = 255

#: Marks the tool's child, so the stand-ins below touch no other process.
_MARK = "ASH-STREAM-TOOL"

#: The error ASH meets: Rich markup that raises if parsed, a newline and an ESC.
_ERROR_TEXT = "ASH's side failed [/x]\nsecond line\x1b[31m"


def _tool(exit_code: int, prints: bool = True) -> List[str]:
    line = "sys.stdout.write('a line\\n'); sys.stdout.flush(); " if prints else ""
    return [sys.executable, "-c", f"import sys; {line}sys.exit({exit_code})", _MARK]


def _is_the_tool(process: Any) -> bool:
    return _MARK in [str(part) for part in (process.args or [])]


@pytest.fixture
def markup_console():
    """ASH_LOGGER through a console handler that renders markup unless the record
    says otherwise, so a line logged without markup off shows the difference."""
    from automated_security_helper.utils.console import ash_console
    from automated_security_helper.utils.log import ASH_LOGGER, ConsoleHandler

    buffer = io.StringIO()
    handler = ConsoleHandler(
        console=ash_console(file=buffer, width=400, color_system=None),
        markup=True,
        show_time=False,
        show_path=False,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    saved_handlers, saved_level = list(ASH_LOGGER.handlers), ASH_LOGGER.level
    ASH_LOGGER.handlers = [handler]
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield buffer
    finally:
        ASH_LOGGER.handlers = saved_handlers
        ASH_LOGGER.setLevel(saved_level)


def _relaying_fails(monkeypatch) -> List[str]:
    """The print that relays each line raises."""
    relayed: List[str] = []

    def failing_print(*args, **kwargs):
        relayed.append(" ".join(map(str, args)))
        raise RuntimeError(_ERROR_TEXT)

    monkeypatch.setattr(subprocess_utils, "print", failing_print, raising=False)
    return relayed


def _waiting_fails(monkeypatch) -> List[Any]:
    """The tool's first wait() raises; any later one is the real one."""
    real_wait = subprocess.Popen.wait
    failed: List[Any] = []

    def wait(self, *args, **kwargs):
        if _is_the_tool(self) and not any(p is self for p in failed):
            failed.append(self)
            raise RuntimeError(_ERROR_TEXT)
        return real_wait(self, *args, **kwargs)

    monkeypatch.setattr(subprocess.Popen, "wait", wait)
    return failed


def _cleanup_fails_after_the_tool_exited(monkeypatch) -> List[Any]:
    """The tool ran and exited, and was waited on. The cleanup after it still
    finds it running (poll() answers None) and its kill raises."""
    real_poll = subprocess.Popen.poll
    real_kill = subprocess.Popen.kill
    killed: List[Any] = []

    def poll(self, *args, **kwargs):
        if _is_the_tool(self) and self.returncode is not None:
            return None
        return real_poll(self, *args, **kwargs)

    def kill(self, *args, **kwargs):
        if _is_the_tool(self):
            killed.append(self)
            raise OSError(_ERROR_TEXT)
        return real_kill(self, *args, **kwargs)

    monkeypatch.setattr(subprocess.Popen, "poll", poll)
    monkeypatch.setattr(subprocess.Popen, "kill", kill)
    return killed


# -- 1-4: after the start, any failure on ASH's side is 255 ----------------------


def test_relaying_the_output_raises(monkeypatch):
    relayed = _relaying_fails(monkeypatch)

    code = run_command_stream_output(_tool(0))

    assert relayed, "nothing was relayed, so the cell shows nothing"
    assert code == UNRECORDED, code


def test_waiting_on_the_tool_raises(monkeypatch):
    failed = _waiting_fails(monkeypatch)

    code = run_command_stream_output(_tool(0, prints=False))

    assert failed, "wait() never ran, so the cell shows nothing"
    assert code == UNRECORDED, code


@pytest.mark.parametrize(
    "exit_code",
    [pytest.param(0, id="tool-exited-0"), pytest.param(3, id="tool-exited-3")],
)
def test_the_later_kill_raising_after_the_tool_exited_fails_closed(
    monkeypatch, exit_code
):
    """Not the tool's 0, which reads as a clean run, and not its 3 either."""
    killed = _cleanup_fails_after_the_tool_exited(monkeypatch)

    code = run_command_stream_output(_tool(exit_code))

    assert killed, "the cleanup never ran, so the cell shows nothing"
    assert code == UNRECORDED, code
    assert code not in (exit_code, 0, SPAWN_FAILURE_RETURNCODE), code


# -- 5-6: the pins ------------------------------------------------------------------


def test_control_a_tool_that_cannot_start_is_127(tmp_path):
    code = run_command_stream_output([str(tmp_path / "no-such-tool"), _MARK])

    assert code == SPAWN_FAILURE_RETURNCODE, code


@pytest.mark.parametrize("exit_code", [0, 3])
def test_control_a_clean_run_keeps_the_tools_code(exit_code):
    assert run_command_stream_output(_tool(exit_code)) == exit_code


class _CloseRaisesAValueError:
    """The tool's output pipe; closing it closes it, then raises a ValueError."""

    def __init__(self, stream: Any) -> None:
        self._stream = stream
        self.closed_by_ash = False

    def __iter__(self) -> Any:
        return iter(self._stream)

    def close(self) -> None:
        self._stream.close()
        self.closed_by_ash = True
        raise ValueError(_ERROR_TEXT)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


def _closing_raises_a_value_error(monkeypatch) -> List[Any]:
    pipes: List[Any] = []

    class _Popen(subprocess.Popen):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            if _is_the_tool(self) and self.stdout is not None:
                pipe = _CloseRaisesAValueError(self.stdout)
                pipes.append(pipe)
                setattr(self, "stdout", pipe)

    monkeypatch.setattr(subprocess, "Popen", _Popen)
    return pipes


@pytest.mark.parametrize("exit_code", [0, 3])
def test_a_close_that_raises_something_other_than_oserror_keeps_the_tools_code(
    monkeypatch, caplog, exit_code
):
    """The run was fully recorded: ASH has the code, relayed every line, and only
    closing the pipe failed, with a ValueError rather than an OSError. That is pure
    resource release, so the tool's code is kept, the failure is logged on one
    escaped line, and nothing escapes the call."""
    pipes = _closing_raises_a_value_error(monkeypatch)

    with caplog.at_level(logging.ERROR, logger="ash"):
        code = run_command_stream_output(_tool(exit_code))

    assert pipes and pipes[0].closed_by_ash, "the pipe was never closed"
    assert code == exit_code, code
    naming = [r.getMessage() for r in caplog.records if "side failed" in r.getMessage()]
    assert len(naming) == 1, naming
    assert "\n" not in naming[0] and "\x1b" not in naming[0], naming


# -- 7: one escaped line names the error, its markup shown as text -----------------


FAILURES = [
    pytest.param(_relaying_fails, _tool(0), id="relaying-raises"),
    pytest.param(_waiting_fails, _tool(0, prints=False), id="wait-raises"),
    pytest.param(
        _cleanup_fails_after_the_tool_exited, _tool(0), id="later-kill-raises-after-0"
    ),
    pytest.param(
        _cleanup_fails_after_the_tool_exited, _tool(3), id="later-kill-raises-after-3"
    ),
]


@pytest.mark.parametrize("arrange, tool", FAILURES)
def test_each_failure_is_logged_once_on_one_escaped_line(
    monkeypatch, caplog, arrange, tool
):
    arrange(monkeypatch)

    with caplog.at_level(logging.ERROR, logger="ash"):
        code = run_command_stream_output(tool)

    assert code == UNRECORDED, code
    naming = [
        r.getMessage() for r in caplog.records if "ASH's side failed" in r.getMessage()
    ]
    assert len(naming) == 1, naming
    assert "\n" not in naming[0] and "\x1b" not in naming[0], naming


@pytest.mark.parametrize("arrange, tool", FAILURES)
def test_each_failure_shows_markup_in_the_error_as_text(
    monkeypatch, markup_console, arrange, tool
):
    arrange(monkeypatch)

    code = run_command_stream_output(tool)

    assert code == UNRECORDED, code
    lines = [
        line
        for line in markup_console.getvalue().splitlines()
        if "ASH's side failed" in line
    ]
    assert len(lines) == 1, markup_console.getvalue()
    assert "ASH's side failed [/x]" in lines[0], lines[0]


# -- 8: the constant and the documented limit ---------------------------------------


def test_the_code_for_a_run_ash_could_not_record_is_one_documented_constant():
    assert subprocess_utils.UNRECORDED_RUN_RETURNCODE == 255

    source = inspect.getsource(subprocess_utils).splitlines()
    (at,) = [
        n
        for n, line in enumerate(source)
        if line.startswith("UNRECORDED_RUN_RETURNCODE")
    ]
    assert source[at - 1].startswith("#:"), "the constant has no doc comment"


def test_the_docstring_states_the_limit_and_points_at_the_flagged_runner():
    doc = run_command_stream_output.__doc__ or ""

    assert "UNRECORDED_RUN_RETURNCODE" in doc, doc
    assert "run_command_with_output_handling" in doc, doc
