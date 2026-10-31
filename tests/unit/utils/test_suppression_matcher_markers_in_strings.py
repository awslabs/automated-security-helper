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


def _best_scan_seconds(tmp_path, count):
    """The least of three timed scans of a line of ``count`` markers inside
    strings, each checked to find the one directive after them and no other."""
    strings = '"# ash-ignore: A", ' * count
    source = _write(tmp_path, f"x = [{strings}]  # ash-ignore: R1 why\n")
    best = None
    for _ in range(3):
        started = time.perf_counter()
        found = find_inline_suppressions(source)
        elapsed = time.perf_counter() - started
        assert found == [InlineSuppression(line_number=1, rule_id="R1", reason="why")]
        best = elapsed if best is None else min(best, elapsed)
    return best


def test_a_line_of_many_markers_inside_strings_is_scanned_once(tmp_path):
    """Red at the base: each of the markers inside a string ran a match attempt
    to the end of the line, so the time grew with the square of the line's
    length. A line four times as long is scanned in about four times the time
    when the scan reads each character once, and sixteen times when it does not;
    the bound sits between them at nine. A ratio, not a number of seconds: an
    absolute bound fails on a loaded runner or under coverage with no
    regression. The directive after the strings is found, and none inside them
    is (each scan is checked for that)."""
    small = _best_scan_seconds(tmp_path, 20_000)
    large = _best_scan_seconds(tmp_path, 80_000)

    assert large < 9 * small, (small, large)


@pytest.mark.parametrize(
    "line",
    [
        pytest.param(
            "x = 'a'if c else '# ash-ignore: X'\n", id="single-quote-then-if-else"
        ),
        pytest.param('x = "s"and "# ash-ignore: X"\n', id="double-quote-then-and"),
        pytest.param('y = "abc"_s + "# ash-ignore: X"\n', id="literal-suffix"),
    ],
)
def test_a_marker_in_a_string_after_a_keyword_glued_closer_is_not_a_directive(
    tmp_path, line
):
    """The inverse of the directive that was swallowed: when the first string was
    left open by a closing quote glued to a keyword, it ran to the opening quote
    of the second literal and the marker inside that literal read as a
    directive, which applied a suppression."""
    assert find_inline_suppressions(_write(tmp_path, line)) == []


def test_a_closing_quote_glued_to_a_keyword_ends_its_string():
    from automated_security_helper.utils.suppression_matcher import _quoted_spans

    assert _quoted_spans("'a'if c else 'b'") == [(0, 3), (13, 16)]
    assert _quoted_spans('"x"in env') == [(0, 3)]


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


@pytest.mark.parametrize(
    ("line", "rule"),
    [
        pytest.param(
            "x = 'x'OR 1=1  # ash-ignore: R10 see 'notes'\n",
            "R10",
            id="sql-upper-case-or",
        ),
        pytest.param(
            'y = "a"And b  # ash-ignore: R11 see "that"\n',
            "R11",
            id="vb-mixed-case-and",
        ),
        pytest.param(
            "z = 'a'then b  # ash-ignore: R12 see 'notes'\n",
            "R12",
            id="then",
        ),
        pytest.param(
            'w = "b"as c  # ash-ignore: R13 see "that"\n',
            "R13",
            id="as",
        ),
        pytest.param(
            "v = 'c'unless d  # ash-ignore: R14 see 'notes'\n",
            "R14",
            id="unless",
        ),
        pytest.param(
            'u = "d"do  # ash-ignore: R15 see "that"\n',
            "R15",
            id="do-at-the-end-of-the-code",
        ),
    ],
)
def test_a_closing_quote_glued_to_a_keyword_in_any_case_does_not_hide_a_directive(
    tmp_path, line, rule
):
    """Red at the base: the keywords were compared in lower case and the list
    lacked ``as``, ``then``, ``unless`` and ``do``, so the closing quote was read
    as an apostrophe, the string stayed open until a quote in the directive's
    reason, and the directive after it went unseen with no warning."""
    found = find_inline_suppressions(_write(tmp_path, line))

    assert [(item.line_number, item.rule_id) for item in found] == [(1, rule)]


def test_a_keyword_in_any_case_ends_its_string():
    from automated_security_helper.utils.suppression_matcher import _quoted_spans

    assert _quoted_spans("'x'OR 1=1") == [(0, 3)]
    assert _quoted_spans('"a"And b') == [(0, 3)]


def test_a_name_that_only_starts_with_a_keyword_is_still_prose():
    """The positive control: ``O'Dowd`` and ``l'asile`` continue past the
    letters of ``do`` and ``as``, so neither quote closes anything."""
    from automated_security_helper.utils.suppression_matcher import _quoted_spans

    assert _quoted_spans("O'Dowd said 'hi'") == [(12, 16)]
    assert _quoted_spans("l'asile and 'it'") == [(12, 16)]
