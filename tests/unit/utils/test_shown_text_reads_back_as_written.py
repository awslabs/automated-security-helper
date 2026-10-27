# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ShownText reads back as the text it was made from.

Why this exists
---------------
Stored text stays as written, and a sink shows it once. A part a call site showed
already, a ShownText, has to be stored as written too, or every sink that shows
the stored text shows it a second time. A ShownText cannot carry the text it was
made from (it holds no attribute: test_shown_text_is_shown_once.py), so
``terminal_text.as_written`` reads it back. The escapers write a control as its
escape and double a backslash run before text that reads as an escape, so an odd
run ends in an escape and an even run is the backslashes it stood for.
``shown_in_ascii``'s replacements are not reversible, and stay as they are.
"""

from __future__ import annotations

import random

import pytest

from automated_security_helper.utils import terminal_text

#: The characters that interact: backslashes, the letters and digits of an
#: escape's text in both cases, the command forms' characters, the layout
#: characters, a C0 and a C1 control, a separator and a zero-width space.
_ALPHABET = ["\\", "x", "u", "U", "0", "9", "a", "B", "f", ":", "#", "[", "v", " "]
_ALPHABET += ["\n", "\r", "\t", "\x1b", "\x85", "\u2028", "\u200b", "\xe9"]

EDGE_CASES = [
    "",
    "plain",
    "a\x1bb",
    "\\x1b",
    "\\\\x1b",
    "\\\x1b",
    "C:\\x64\\Users\\x",
    "C:\\temp\\",
    "trailing\\",
    "::add-mask::x",
    "  ::warning::x",
    "x\n::error::y",
    "##vso[task.setvariable variable=x]1",
    "\\##[warning]x",
    "\\\\##teamcity[x]",
    "\\X41 \\x4G \\u12 \\U1234567",
    "\\x1B and \\u00E9",
    "secr\udce9t.py",
]


@pytest.mark.parametrize("text", EDGE_CASES)
@pytest.mark.parametrize("maker", ["shown_not_obeyed", "shown_on_one_line"])
def test_an_edge_case_reads_back(maker, text):
    shown = getattr(terminal_text, maker)(text)

    assert terminal_text.as_written(shown) == text, shown


@pytest.mark.parametrize("maker", ["shown_not_obeyed", "shown_on_one_line"])
def test_any_text_reads_back(maker):
    make = getattr(terminal_text, maker)
    chooser = random.Random(20261013)
    for _ in range(20000):
        text = "".join(chooser.choice(_ALPHABET) for _ in range(chooser.randint(0, 16)))
        assert terminal_text.as_written(make(text)) == text, (text, make(text))


def test_text_shown_in_ascii_reads_back_but_its_replacements():
    chooser = random.Random(20261014)
    for _ in range(5000):
        text = "".join(chooser.choice(_ALPHABET) for _ in range(chooser.randint(0, 16)))
        shown = terminal_text.shown_not_obeyed(text)
        # No replacement: each character outside ASCII is written as its escape.
        assert terminal_text.as_written(terminal_text.shown_in_ascii(shown, {})) == text

    replaced = terminal_text.shown_in_ascii(
        terminal_text.shown_not_obeyed("done \u2705 a\x1bb"), {"\u2705": "[OK]"}
    )
    assert terminal_text.as_written(replaced) == "done [OK] a\x1bb"


def test_text_that_is_not_shown_is_as_written_already():
    for text in ("a\\x1bb", "C:\\x64", "::x"):
        assert terminal_text.as_written(text) is text
