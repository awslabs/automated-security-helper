# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""error_text strips escape codes to their fixed point in one pass.

The stripper removed complete sequences pass by pass until a pass changed
nothing: an inner sequence's removal can join the bytes around it into a new
one. Each pass re-read the whole text, so "ESC [" repeated k times before "m"
repeated k times took k passes over about 3k characters, time quadratic in the
text, on tool stderr and exception text a scanned repository can shape. The
stripper now reads the text once, keeping each ESC that could still begin a
sequence open until it completes or meets a character no sequence admits, and
gives the same fixed point.
"""

from __future__ import annotations

import random
import time

import pytest

from automated_security_helper.utils.error_text import (
    ESCAPE_CODES,
    _without_escape_codes,
    shown_tool_stderr,
)

pytestmark = pytest.mark.unit

ESC = chr(0x1B)
BEL = chr(0x07)
ST = chr(0x9C)

#: The characters the fuzzed texts are drawn from: the openers, the finals and
#: the terminators of both sequence forms, a break, and plain text.
ALPHABET = [ESC, "[", "]", "m", "K", "2", ";", "8", BEL, ST, "\\", "a", " ", "\n"]


def _fixed_point_by_passes(text: str) -> str:
    """The reference: remove complete sequences until a pass changes nothing."""
    while True:
        stripped = ESCAPE_CODES.sub("", text)
        if stripped == text:
            return text
        text = stripped


CASES = {
    "plain": "no codes here",
    "one csi": "a" + ESC + "[31mb",
    "nested csi": "a" + ESC + "[" + ESC + "[2K" + "mb",
    "twice nested": "a" + ESC + "[" + ESC + "[" + ESC + "[2K" + "m" + "mb",
    "osc bel": "a" + ESC + "]8;;https://example.invalid" + BEL + "b",
    "osc esc backslash": "a" + ESC + "]8;;x" + ESC + "\\" + "b",
    "osc st": "a" + ESC + "]0;title" + ST + "b",
    "csi inside osc": "a" + ESC + "]0;ti" + ESC + "[2K" + "tle" + BEL + "b",
    "osc inside csi": "a" + ESC + "[" + ESC + "]0;t" + BEL + "mb",
    "unterminated osc": "a" + ESC + "]0;no end",
    "osc broken by a line": "a" + ESC + "]0;li\nne" + BEL + "b",
    "lone esc": "a" + ESC + "xb",
    "esc then esc": "a" + ESC + ESC + "[2K" + "[mb",
    "esc esc backslash": "a" + ESC + ESC + "\\" + "b",
    "osc ended past a doubled esc": "a" + ESC + "]x" + ESC + ESC + "\\" + "b",
    "csi dead on a param after an intermediate": "a" + ESC + "[ 0mb",
    "csi dead then outer": "a" + ESC + "[" + ESC + "[ 0m" + "mb",
    "private mode": "a" + ESC + "[?25lb",
    "colon sgr": "a" + ESC + "[38:5:196mb",
    "trailing backslash": "a" + ESC + "[m\\",
    "only an esc": ESC,
    "empty": "",
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_one_pass_gives_the_fixed_point_of_passes(name):
    text = CASES[name]

    assert _without_escape_codes(text) == _fixed_point_by_passes(text), repr(text)


def test_one_pass_gives_the_fixed_point_on_fuzzed_texts():
    """Seeded, so a difference is reproducible from the text printed."""
    draw = random.Random("strips codes in one pass")

    for _ in range(3000):
        text = "".join(draw.choice(ALPHABET) for _ in range(draw.randint(0, 12)))

        assert _without_escape_codes(text) == _fixed_point_by_passes(text), repr(text)


def test_the_result_holds_no_complete_sequence():
    text = "x" + ESC + "[" + ESC + "[2K" + "m" + ESC + "]0;t" + ESC + "\\" + "y"

    stripped = shown_tool_stderr(text, ())

    assert ESCAPE_CODES.search(stripped) is None, repr(stripped)
    assert stripped == "xy"


def _least_time(text: str) -> float:
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        _without_escape_codes(text)
        best = min(best, time.perf_counter() - started)
    return best


def test_nested_openers_cost_time_linear_in_their_count():
    """Sixteen times the openers cost about sixteen times more, not 256 times.

    The least of three timings of each, so a busy host's noise lands on neither
    side; the bound sits well above a linear ratio and well below a quadratic one.
    """
    short = (ESC + "[") * 500 + "m" * 500
    long = (ESC + "[") * 8000 + "m" * 8000

    ratio = _least_time(long) / max(_least_time(short), 1e-6)

    assert ratio < 64, ratio
    assert _without_escape_codes(long) == ""
