# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A line of many markers inside strings is read once, not once per marker.

Why this file exists
--------------------
Every inline pattern ends in ``(.*)?$``, so one match attempt reads to the end
of the line. ``_search_comment`` tried the whole pattern at each marker it met,
and a marker inside a string was rejected only after that attempt had read the
rest of the line: ``k`` markers in strings on a line of ``n`` characters cost
about ``k * n`` (a minified file is one long line, and the scanned tree's author
decides what it holds). Markers are now found with the marker alone, and the
full pattern is tried only at one that lies outside every string.
"""

import time
from pathlib import Path

import pytest

from automated_security_helper.utils.suppression_matcher import (
    InlineSuppression,
    find_inline_suppressions,
)

pytestmark = pytest.mark.unit


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "sample.py"
    path.write_text(text, encoding="utf-8", newline="")
    return path


def test_a_line_of_many_markers_inside_strings_is_scanned_once(tmp_path):
    """Red at the base: each of the markers inside a string ran a match attempt
    to the end of the line, so this one line (about 2.7 million characters)
    took time quadratic in its length, far past the bound asserted. The
    directive after the strings is still found, and none inside them is."""
    strings = '"# ash-ignore: A", ' * 150_000
    source = _write(tmp_path, f"x = [{strings}]  # ash-ignore: R1 why\n")

    started = time.perf_counter()
    found = find_inline_suppressions(source)
    elapsed = time.perf_counter() - started

    assert found == [InlineSuppression(line_number=1, rule_id="R1", reason="why")]
    assert elapsed < 10, elapsed


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        pytest.param("x = 1  # ash-ignore:\n", [], id="marker-without-a-rule-id"),
        pytest.param(
            'x = "# ash-ignore: A"  # ash-ignore: R2 ok\n',
            [InlineSuppression(line_number=1, rule_id="R2", reason="ok")],
            id="string-then-directive",
        ),
        pytest.param(
            "x = 1  # ash-ignore:\ny = 2  # ash-ignore: R3 fine\n",
            [InlineSuppression(line_number=2, rule_id="R3", reason="fine")],
            id="bare-marker-line-then-directive-line",
        ),
        pytest.param(
            "x = 1  // ash-ignore: R4 slash\n",
            [InlineSuppression(line_number=1, rule_id="R4", reason="slash")],
            id="slash-marker",
        ),
    ],
)
def test_the_answers_for_ordinary_lines_are_unchanged(tmp_path, line, expected):
    """The positive controls: what the pass found before it finds now."""
    assert find_inline_suppressions(_write(tmp_path, line)) == expected


@pytest.mark.parametrize(
    ("line", "rule"),
    [
        pytest.param(
            "x = 'a'if y else 1  # ash-ignore: R5 see 'notes'\n",
            "R5",
            id="single-quote-then-if",
        ),
        pytest.param(
            'if "dbg"in env:  # ash-ignore: R6 about "that"\n',
            "R6",
            id="double-quote-then-in",
        ),
        pytest.param(
            "x = 'a'or 'b'  # ash-ignore: R7 see 'notes'\n",
            "R7",
            id="single-quote-then-or",
        ),
        pytest.param(
            'y = "abc"_s  # ash-ignore: R8 see "it"\n',
            "R8",
            id="user-defined-literal-suffix",
        ),
        pytest.param(
            "Description: Bob's bucket  # ash-ignore: R9 logging isn't needed\n",
            "R9",
            id="apostrophes-in-prose-still-close-nothing",
        ),
    ],
)
def test_a_string_closed_before_a_keyword_does_not_hide_a_directive(
    tmp_path, line, rule
):
    """Red at the base for the first four: the closing quote of the string, glued
    to the keyword or suffix after it, was read as an apostrophe, so the string
    stayed open until a quote in the directive's reason and the marker fell
    inside it; the directive was not honored. The last line is the positive
    control: an apostrophe in prose is still not a closer."""
    found = find_inline_suppressions(_write(tmp_path, line))

    assert [(item.line_number, item.rule_id) for item in found] == [(1, rule)]
