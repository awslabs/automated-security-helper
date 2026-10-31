# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two readings of the console factory follow what was asked of it.

Off a terminal ``_AshConsole`` soft-wraps printed text, so no line is split at the
width. Under a soft wrap Rich divides no line, so a Text that set its own
``overflow`` ("fold") was cropped at the width instead of folded; such a Text (or
one with its own ``no_wrap``) is now laid out as Rich lays it out. And
``typer_console`` read TERMINAL_WIDTH with ``str.isdigit`` before ``int()``, which
left a value typer's ``int()`` accepts (``" 100"``) unused and raised on a digit
``isdigit`` admits and ``int()`` refuses (a superscript); it now reads the variable
as typer does.
"""

from __future__ import annotations

from io import StringIO

import pytest
from rich.text import Text

from automated_security_helper.utils.console import (
    _AshConsole,
    _typer_terminal_width,
    typer_console,
)

pytestmark = pytest.mark.unit


def _lines(console_file: StringIO) -> list[str]:
    return [line.rstrip() for line in console_file.getvalue().splitlines()]


def _console(file: StringIO) -> _AshConsole:
    return _AshConsole(file=file, width=10, force_terminal=False, color_system=None)


def test_a_text_that_asks_to_be_folded_is_folded_off_a_terminal():
    out = StringIO()
    _console(out).print(Text("a" * 25, overflow="fold"))
    assert _lines(out) == ["a" * 10, "a" * 10, "a" * 5]


def test_a_plain_text_is_still_not_wrapped_off_a_terminal():
    out = StringIO()
    _console(out).print("a" * 25)
    assert _lines(out) == ["a" * 25]
    out = StringIO()
    _console(out).print(Text("a" * 25))
    assert _lines(out) == ["a" * 25]


@pytest.mark.parametrize(
    ("value", "width"),
    [
        ("100", 100),
        (" 100", 100),
        ("100 ", 100),
        ("+100", 100),
        ("", None),
        ("0", None),
        ("-5", None),
        ("abc", None),
        ("²", None),  # a superscript two: isdigit True, int() refuses
        ("②", None),  # a circled digit two
    ],
)
def test_terminal_width_is_read_as_typer_reads_it(value, width):
    assert _typer_terminal_width(value) == width


def test_typer_console_takes_a_padded_width_and_survives_a_superscript(monkeypatch):
    monkeypatch.setenv("TERMINAL_WIDTH", " 100")
    assert typer_console().width == 100
    monkeypatch.setenv("TERMINAL_WIDTH", "²")
    typer_console()  # neither raises nor takes the superscript as a width
