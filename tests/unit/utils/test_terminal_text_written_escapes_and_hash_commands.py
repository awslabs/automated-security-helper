# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""controls_shown's ``lookalikes="written"`` reads every escape text it writes, and
commands_broken takes time linear in a backslash run.

``ash report`` on a terminal doubles a backslash run only before the text of an
escape terminal_text itself writes. Two readings of that text went wrong: a
backslash followed by ``U`` and eight hex digits whose value does not fit a C
int made chr() raise OverflowError on some Python versions, which only
ValueError was caught for, so the report failed; and the text of an eight-digit escape was lowercased
before it was compared with escape_for's ``U``, so a run before ``\\U000e0001``
was never doubled and read back as the character.

NAMED_HASH_COMMAND had no anchor on its backslash run, so a run not followed by
"#" was retried from each of its positions: every log line, console echo and
MCP error went through time that grew with the square of the run's length.
"""

from __future__ import annotations

import time

import pytest

from automated_security_helper.utils.terminal_text import (
    as_written,
    commands_broken,
    controls_shown,
    escape_for,
    shown_not_obeyed,
)

pytestmark = pytest.mark.unit

BACKSLASH = chr(0x5C)

#: A format character (Cf) beyond U+FFFF, written as an eight-digit escape.
LANGUAGE_TAG = chr(0xE0001)


#: Eight hex digits (assembled, so the source holds no long hex run): the
#: smallest value that does not fit a C int, the largest, and one just below.
EIGHT_DIGITS = ["8" + "0" * 7, "f" * 8, "7" + "f" * 7]


@pytest.mark.parametrize("digits", EIGHT_DIGITS)
def test_an_escape_text_beyond_any_code_point_is_left_as_text(digits):
    text = "C:" + BACKSLASH + "U" + digits

    shown = controls_shown(text, lookalikes="written")

    assert shown == text
    assert as_written(shown_not_obeyed(text)) == text


def test_a_run_before_the_text_of_an_eight_digit_escape_is_doubled():
    escape_text = escape_for(LANGUAGE_TAG)
    assert escape_text == BACKSLASH + "U000e" + "0001"
    text = "a" + escape_text + "b"

    shown = controls_shown(text, lookalikes="written")

    # One to one: the text of the escape reads as text, not as the character.
    assert shown == "a" + BACKSLASH + escape_text + "b"
    assert controls_shown(text) == shown


def test_a_four_digit_escape_text_is_still_doubled_and_a_path_is_not():
    soft_hyphen = escape_for(chr(0xAD))
    assert controls_shown("x" + soft_hyphen, lookalikes="written") == (
        "x" + BACKSLASH + soft_hyphen
    )
    path = "C:" + BACKSLASH + "Python" + BACKSLASH + "x64"
    assert controls_shown(path, lookalikes="written") == path


def _least_time(text: str) -> float:
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        commands_broken(text)
        best = min(best, time.perf_counter() - started)
    return best


def test_a_backslash_run_costs_time_linear_in_its_length():
    """A run sixteen times longer costs about sixteen times more, not 256 times.

    The least of three timings of each, so a busy host's noise lands on neither
    side; the bound sits well above a linear ratio and well below a quadratic one.

    The run ends in "##x", a "#" that is no command: a check for "#" in the text
    would let a text of backslashes alone skip the pattern, and the unanchored
    pattern would pass unnoticed. With the "#" the pattern has to run, and fail
    at the end of the run from every start it is tried at.
    """
    short = BACKSLASH * 500 + "##x"
    long = BACKSLASH * 8000 + "##x"

    ratio = _least_time(long) / max(_least_time(short), 1e-6)

    assert ratio < 64, ratio
    assert commands_broken(long) == long


def test_a_run_before_a_named_hash_command_is_still_doubled():
    text = "x" + BACKSLASH * 3 + "##vso[task.setvariable variable=a]b"

    broken = commands_broken(text)

    assert (
        broken
        == "x" + BACKSLASH * 6 + BACKSLASH + "x23#vso[task.setvariable variable=a]b"
    )
    assert commands_broken("## Scan Metadata") == "## Scan Metadata"
