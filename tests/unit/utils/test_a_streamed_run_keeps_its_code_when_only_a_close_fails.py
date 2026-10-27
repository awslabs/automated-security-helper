# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What a streamed run returns depends on whether ASH recorded all of it.

``run_command_stream_output`` returns UNRECORDED_RUN_RETURNCODE (255) when anything
about the run went unrecorded or is unknown, and keeps the tool's own code when ASH
holds that code, relayed every line and then only failed to release a resource, such
as closing the pipe it read the output from. That close failure is logged on one
escaped line.

tests/unit/utils/test_a_streamed_run_ash_could_not_record_returns_255.py holds the
255 cases for a relay that raises, a wait that raises, and a cleanup kill that
raises while the process reads as still running. The cleanup kill and wait run
only when ``poll()`` says the tool has not exited, so ASH has no final exit code
there, and a failure in them is unrecorded by the rule. This file adds the kill
that raises after the relay failed, and the close.

The function writes no log file of its own: its relay is the console, covered by
the relay cell in that file.
"""

from __future__ import annotations

import contextlib
import logging
import subprocess
import sys
from typing import IO, Any, Iterator, List, cast

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import (
    UNRECORDED_RUN_RETURNCODE,
    run_command_stream_output,
)

#: Marks the tool's child, so the stand-ins below touch no other process.
_MARK = "ASH-STREAM-CLOSE-TOOL"

#: The error ASH meets: Rich markup that raises if parsed, a newline and an ESC.
_ERROR_TEXT = "closing the pipe failed [/x]\nsecond line\x1b[31m"


def _tool(exit_code: int) -> List[str]:
    return [
        sys.executable,
        "-c",
        f"import sys; print('a line', flush=True); sys.exit({exit_code})",
        _MARK,
    ]


def _tool_that_lingers() -> List[str]:
    """Prints its line and then sleeps, so only the cleanup kill ends it.

    The kill cell's precondition is a child still running at the cleanup's
    poll. A tool that exits by itself races that poll: on a busy host its exit
    can land first, the poll then answers the tool's code, and the kill never
    runs -- the cell fails claiming the kill path was never reached. Measured
    deterministically by holding the parent's path to the poll until the child
    had exited: 5 of 5 runs lost the kill, with the returned code 255 either
    way. A child that cannot exit on its own removes the ordering."""
    return [
        sys.executable,
        "-c",
        "import sys, time; print('a line', flush=True); time.sleep(60)",
        _MARK,
    ]


def _is_the_tool(process: Any) -> bool:
    return _MARK in [str(part) for part in (process.args or [])]


class _CloseRaises:
    """The tool's output pipe, whose close closes it and then raises."""

    def __init__(self, stream: IO[str], closed: List[Any]) -> None:
        self._stream = stream
        self._closed = closed

    def __iter__(self) -> Iterator[str]:
        return iter(self._stream)

    def close(self) -> None:
        self._stream.close()
        self._closed.append(self)
        raise OSError(_ERROR_TEXT)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


def _closing_the_pipe_fails(monkeypatch: pytest.MonkeyPatch) -> List[Any]:
    closed: List[Any] = []

    # The streamed run opens its pipe in text mode.
    class _Popen(subprocess.Popen[str]):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            if _is_the_tool(self) and self.stdout is not None:
                self.stdout = cast(IO[str], _CloseRaises(self.stdout, closed))

    monkeypatch.setattr(subprocess, "Popen", _Popen)
    return closed


def _relay_and_then_kill_fail(monkeypatch: pytest.MonkeyPatch) -> List[Any]:
    """The relay raises, so the tool's code is never waited for, and the cleanup
    kill then raises too."""
    killed: List[Any] = []
    real_kill = subprocess.Popen.kill

    def failing_print(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("relaying failed")

    def kill(self: "subprocess.Popen[str]") -> None:
        if _is_the_tool(self):
            killed.append(self)
            real_kill(self)
            raise OSError(_ERROR_TEXT)
        real_kill(self)

    monkeypatch.setattr(subprocess_utils, "print", failing_print, raising=False)
    monkeypatch.setattr(subprocess.Popen, "kill", kill)
    return killed


def _lines_naming(caplog: pytest.LogCaptureFixture, text: str) -> List[str]:
    return [r.getMessage() for r in caplog.records if text in r.getMessage()]


@pytest.mark.parametrize("exit_code", [0, 3])
def test_a_close_that_raises_after_all_was_recorded_keeps_the_tools_code(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, exit_code: int
) -> None:
    closed = _closing_the_pipe_fails(monkeypatch)

    with caplog.at_level(logging.ERROR, logger="ash"):
        code = run_command_stream_output(_tool(exit_code))

    assert closed, "the pipe was never closed, so the cell shows nothing"
    assert code == exit_code, code
    naming = _lines_naming(caplog, "closing the pipe failed")
    assert len(naming) == 1, naming
    assert "\n" not in naming[0] and "\x1b" not in naming[0], naming


def test_a_kill_that_raises_before_the_code_is_unrecorded(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    killed = _relay_and_then_kill_fail(monkeypatch)

    try:
        with caplog.at_level(logging.ERROR, logger="ash"):
            code = run_command_stream_output(_tool_that_lingers())

        assert killed, "the cleanup kill never ran, so the cell shows nothing"
        assert code == UNRECORDED_RUN_RETURNCODE, code
        naming = _lines_naming(caplog, "closing the pipe failed")
        assert len(naming) == 1, naming
        assert "\n" not in naming[0] and "\x1b" not in naming[0], naming
        # The kill was delivered before its raise, so the child is dead. A run
        # that returns without having reaped it leaves a zombie, reported as
        # "subprocess still running" at collection, where no caller can act on
        # it: by the time the run has returned, the child must be reaped.
        for child in killed:
            assert child.returncode is not None, (
                "the raised kill left the child unreaped when the run returned"
            )
    finally:
        # The test never leaves the zombie behind itself, whatever the run did.
        for child in killed:
            with contextlib.suppress(Exception):
                child.wait(timeout=10)
