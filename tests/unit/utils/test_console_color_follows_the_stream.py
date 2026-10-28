# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Styling on rich's global console follows whether the stream is a terminal now.

Why this exists
---------------
Rich decides a console's color system once, when the console is built, by asking
its file whether it is a terminal, and then writes escape sequences around every
styled span of every print for as long as the console lives. utils/console.py
builds rich's global console when it is imported, so a stream that answered
"terminal" then (a worker's null device can) and is a captured, plain stream by the
time a refusal is printed still got ``\\x1b[1;31m`` around each highlighted span, and
a test that looked for the refusal's words in the captured text found them split by
escapes. utils/log.py had already been cured of the same symptom with Rich's
"auto".

The global console now builds itself again when its stream's answer changes. These
tests print through ASH's own ``print`` to streams that answer True and False, in
turn, and read the bytes each one received.

The control is Rich's own console built the old way: built while stdout is a
terminal, it writes escapes into a stream that is not one (Rich's ``_render_buffer``
styles every segment whenever its ``_color_system`` is set, whatever the file is at
write time). If a later Rich decides at write time itself, the control fails and
this fix is no longer needed.
"""

from __future__ import annotations

import io
import sys

import pytest
import rich
from rich.console import Console

import automated_security_helper.utils.console as ash_console_module
from automated_security_helper.utils.command_safe_stream import CommandSafeStream
from automated_security_helper.utils.console import print as ash_print

_ESCAPE = "\x1b"
_MESSAGE = "[bold red]refused[/bold red]"


class _Stream(io.StringIO):
    """A text stream that answers the terminal question as it was told to."""

    def __init__(self, *, terminal: bool) -> None:
        super().__init__()
        self._terminal = terminal

    def isatty(self) -> bool:
        return self._terminal


@pytest.fixture
def global_console(monkeypatch):
    """The console utils/console.py set up, with an environment in which Rich styles
    a terminal, put back as it was afterwards."""
    console = ash_console_module._configured_console
    assert console is not None
    saved = dict(console.__dict__)
    for name in ("FORCE_COLOR", "NO_COLOR", "TTY_COMPATIBLE", "COLORTERM"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setattr(rich.console, "detect_legacy_windows", lambda: False)
    monkeypatch.setattr(rich, "_console", console)
    monkeypatch.setattr(ash_console_module, "_configured_for_tty", None)
    yield console
    console.__dict__.clear()
    console.__dict__.update(saved)


def _printed_to(monkeypatch, stream: _Stream) -> str:
    monkeypatch.setattr(sys, "stdout", stream)
    ash_print(_MESSAGE)
    return stream.getvalue()


def test_a_stream_that_is_not_a_terminal_gets_no_escape(global_console, monkeypatch):
    monkeypatch.setattr(sys, "stdout", _Stream(terminal=False))
    ash_console_module._set_up_global_console()

    written = _printed_to(monkeypatch, _Stream(terminal=False))

    assert "refused" in written, written
    assert _ESCAPE not in written, written


def test_a_stream_that_is_a_terminal_is_styled(global_console, monkeypatch):
    monkeypatch.setattr(sys, "stdout", _Stream(terminal=True))
    ash_console_module._set_up_global_console()

    written = _printed_to(monkeypatch, _Stream(terminal=True))

    assert "refused" in written, written
    assert _ESCAPE in written, written


def test_a_console_built_under_a_terminal_writes_plainly_to_a_stream_that_is_not_one(
    global_console, monkeypatch
):
    """The symptom: the console was built while stdout answered "terminal", and the
    stream a print then writes to does not."""
    monkeypatch.setattr(sys, "stdout", _Stream(terminal=True))
    ash_console_module._set_up_global_console()

    written = _printed_to(monkeypatch, _Stream(terminal=False))

    assert "refused" in written, written
    assert _ESCAPE not in written, written


def test_each_print_follows_the_stream_as_its_answer_changes(
    global_console, monkeypatch
):
    """Not a terminal, a terminal, then not one again: each print is read right."""
    monkeypatch.setattr(sys, "stdout", _Stream(terminal=False))
    ash_console_module._set_up_global_console()

    first = _printed_to(monkeypatch, _Stream(terminal=False))
    second = _printed_to(monkeypatch, _Stream(terminal=True))
    third = _printed_to(monkeypatch, _Stream(terminal=False))

    assert _ESCAPE not in first, first
    assert _ESCAPE in second, second
    assert _ESCAPE not in third, third
    assert all("refused" in text for text in (first, second, third))


def test_the_console_keeps_its_object_and_its_stream_check_across_a_change(
    global_console, monkeypatch
):
    monkeypatch.setattr(sys, "stdout", _Stream(terminal=False))
    ash_console_module._set_up_global_console()

    _printed_to(monkeypatch, _Stream(terminal=True))

    assert rich.get_console() is global_console
    assert type(global_console).__name__ == "_AshConsole"
    assert isinstance(global_console.file, CommandSafeStream)


def test_a_console_other_code_pointed_rich_at_is_left_alone(
    global_console, monkeypatch
):
    """A test that makes rich's global console a recording one of its own keeps it:
    a change in the stream's answer rebuilds only the console this module set up."""
    monkeypatch.setattr(sys, "stdout", _Stream(terminal=False))
    ash_console_module._set_up_global_console()
    recording_stream = io.StringIO()
    recording = Console(file=recording_stream, color_system=None, width=40)
    monkeypatch.setattr(rich, "_console", recording)

    _printed_to(monkeypatch, _Stream(terminal=True))
    ash_console_module._follow_the_stream(global_console)

    assert rich.get_console() is recording
    assert recording.file is recording_stream


def test_a_console_built_the_old_way_styles_a_stream_that_is_not_a_terminal(
    monkeypatch,
):
    """The control. Rich's own console, built while stdout is a terminal and given a
    stream that is not one, writes escapes anyway; the global console, which follows
    the stream, does not (the tests above)."""
    for name in ("FORCE_COLOR", "NO_COLOR", "TTY_COMPATIBLE", "COLORTERM"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setattr(rich.console, "detect_legacy_windows", lambda: False)
    current = [_Stream(terminal=True)]
    console = Console(file=CommandSafeStream(lambda: current[0]))

    current[0] = _Stream(terminal=False)
    console.print(_MESSAGE)

    written = current[0].getvalue()
    assert "refused" in written, written
    assert _ESCAPE in written, written
