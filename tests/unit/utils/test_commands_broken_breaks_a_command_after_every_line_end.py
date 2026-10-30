# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""commands_broken breaks a line-start "::" after every character that ends a line.

Why this exists
---------------
A runner reads a line that starts with "::" as a workflow command. commands_broken
found a line start only at the text's start and after a newline, but the stream in
utils/command_safe_stream.py also ends a line at a lone carriage return, and
``str.splitlines`` ends one at vertical tab, form feed, the three information
separators, NEL and the Unicode line and paragraph separators. A caller that hands
commands_broken raw text (the CSV report writes each field so) kept a command it
meant to break: a field of ``x`` and a carriage return and ``::add-mask::...``
printed as a line of its own.

A line start is now the text's start and the position after any of them, with a
carriage return and newline together as one break.
"""

from __future__ import annotations

import time

import pytest

from automated_security_helper.utils.terminal_text import commands_broken

pytestmark = pytest.mark.unit

BACKSLASH = chr(0x5C)

#: The first colon of a broken "::", written as terminal_text writes it.
BROKEN = BACKSLASH + "x3a"

LINE_ENDS = {
    "newline": "\n",
    "carriage return": "\r",
    "vertical tab": chr(0x0B),
    "form feed": chr(0x0C),
    "file separator": chr(0x1C),
    "group separator": chr(0x1D),
    "record separator": chr(0x1E),
    "next line": chr(0x85),
    "line separator": chr(0x2028),
    "paragraph separator": chr(0x2029),
}


@pytest.mark.parametrize("end", list(LINE_ENDS.values()), ids=list(LINE_ENDS))
def test_a_command_after_a_line_end_is_broken(end):
    assert commands_broken("x" + end + "::add-mask::v") == (
        "x" + end + BROKEN + ":add-mask::v"
    )


@pytest.mark.parametrize("end", list(LINE_ENDS.values()), ids=list(LINE_ENDS))
def test_an_indented_command_after_a_line_end_is_broken(end):
    assert commands_broken("x" + end + "  ::add-mask::v") == (
        "x" + end + "  " + BROKEN + ":add-mask::v"
    )


def test_a_command_at_the_start_of_the_text_is_broken():
    assert commands_broken("::add-mask::v") == BROKEN + ":add-mask::v"


def test_a_carriage_return_and_newline_are_one_break_and_break_one_command():
    broken = commands_broken("x\r\n::add-mask::v")

    assert broken == "x\r\n" + BROKEN + ":add-mask::v"
    assert broken.count(BROKEN) == 1


def test_each_line_of_several_is_broken_once():
    text = "::a\r::b" + chr(0x2028) + "::c\n::d"

    broken = commands_broken(text)

    assert broken == (
        BROKEN + ":a\r" + BROKEN + ":b" + chr(0x2028) + BROKEN + ":c\n" + BROKEN + ":d"
    )


@pytest.mark.parametrize(
    "text",
    [
        "a::b",
        "x\r:b",
        "x\r a::b",
        "x" + chr(0x1F) + "::b",
        "x" + chr(0x1C) + "x::b",
    ],
    ids=[
        "mid-line",
        "one colon",
        "mid-line after a break",
        "unit separator is no break",
        "text after a break",
    ],
)
def test_text_that_is_no_line_start_command_is_left_as_it_was(text):
    assert commands_broken(text) == text


def _least_time(text: str) -> float:
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        commands_broken(text)
        best = min(best, time.perf_counter() - started)
    return best


@pytest.mark.parametrize("body", ["\r", "\r ", chr(0x2028) + "\t"])
def test_a_run_of_line_ends_costs_time_linear_in_its_length(body):
    """A run sixteen times longer costs about sixteen times more, not 256 times.

    A line end is both a line start and whitespace that a command may follow; the
    whitespace skipped leaves them out, so each position is tried once.
    """
    short = body * 500 + "x"
    long = body * 8000 + "x"

    ratio = _least_time(long) / max(_least_time(short), 1e-6)

    assert ratio < 64, ratio
