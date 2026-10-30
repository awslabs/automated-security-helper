# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Inline suppressions are numbered as the scanners number lines, and one
unreadable path does not end the pass.

Why this file exists
--------------------
``find_inline_suppressions`` numbered directives with ``str.splitlines``, which
also breaks a line at a form feed, a vertical tab, NEL, LINE SEPARATOR,
PARAGRAPH SEPARATOR and the ``\\x1c``-``\\x1e`` separators. A scanner's SARIF
``startLine`` counts line feeds only, so after any such character every
directive was attached to a line the results never name and silently stopped
suppressing.

The same function caught ``OSError`` and ``UnicodeDecodeError`` around the
read. A path with an embedded NUL is refused by the OS layer with a
``ValueError`` before the file is opened, and that one path aborted the whole
SARIF suppression pass.

Two later findings on the same function. A directive's reason group ran past a
lone carriage return to the end of the line, so on a CR-only file the rest of
the file (secrets included) was copied into the SARIF justification; the reason
now stops at the first CR. And the quoted-string scan that keeps a marker inside
a string literal from counting as a directive was a regular expression tried at
every quote, quadratic on a line of escaped quotes; it is one linear pass now,
with the same answer on every line.

A third: that scan took every quote for a string delimiter, so two apostrophes
in prose (``Bob's bucket  # ash-ignore: X logging isn't needed``, a YAML plain
scalar with its comment) opened and closed a "string" that held the marker, and
an existing suppression stopped working with no warning. A quote glued to the
word before it opens nothing now, unless that word is a string prefix
(``f"..."``, ``rb'...'``), so a marker inside a prefixed string stays hidden.
"""

import re
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


@pytest.mark.parametrize(
    "separator",
    [
        pytest.param("\x0c", id="form-feed"),
        pytest.param("\x0b", id="vertical-tab"),
        pytest.param(chr(0x85), id="nel"),
        pytest.param(chr(0x2028), id="line-separator"),
        pytest.param(chr(0x2029), id="paragraph-separator"),
        pytest.param("\x1c", id="file-separator"),
    ],
)
def test_a_non_line_feed_separator_does_not_shift_the_line_number(tmp_path, separator):
    """Red at the base: splitlines counted the separator as a line break, so
    the directive on line 2 was numbered 3."""
    source = _write(tmp_path, f"text = 'a{separator}b'\nx = 1  # ash-ignore: R1 why\n")

    found = find_inline_suppressions(source)

    assert found == [InlineSuppression(line_number=2, rule_id="R1", reason="why")]


@pytest.mark.parametrize("line_break", ["\r\n", "\n"], ids=["crlf", "lf"])
@pytest.mark.parametrize("with_scan_root", [False, True], ids=["plain", "scan-root"])
def test_lf_and_crlf_count_once_on_both_read_paths(
    tmp_path, line_break, with_scan_root
):
    """CRLF ends a line as LF does (a scanner's startLine counts the line feed;
    the carriage return belongs to the line before it), the reason carries no
    CR, and the bytes path given a scan root numbers the same as the plain
    path."""
    source = _write(
        tmp_path,
        f"x = 1{line_break}# ash-ignore-next-line: R2 known{line_break}y = 2{line_break}",
    )

    found = find_inline_suppressions(source, tmp_path if with_scan_root else None)

    assert found == [InlineSuppression(line_number=3, rule_id="R2", reason="known")]


@pytest.mark.parametrize("with_scan_root", [False, True], ids=["plain", "scan-root"])
def test_a_lone_cr_is_not_a_line_break(tmp_path, with_scan_root):
    """Both read paths count by line feed: a lone CR inside line 1 does not
    start a new line, so the directive on line 2 targets line 3, as a scanner
    counting line feeds numbers it."""
    source = _write(tmp_path, "x = 1\ry = 1\n# ash-ignore-next-line: R2 known\nz = 2\n")

    found = find_inline_suppressions(source, tmp_path if with_scan_root else None)

    assert found == [InlineSuppression(line_number=3, rule_id="R2", reason="known")]


@pytest.mark.parametrize("with_scan_root", [False, True], ids=["plain", "scan-root"])
def test_a_cr_only_file_is_one_line_with_at_most_one_directive(
    tmp_path, with_scan_root
):
    """The contract the docstring states: a file with no line feed (classic Mac
    CR-only endings) is one line to the line-feed count, so of its two
    directives only the first on the line is found and it names line 1. Its
    reason stops at the CR: it once ran to the end of the file (the rest of
    that one line), and the reason is copied into the SARIF justification of
    every finding the directive suppresses, so the source after the directive
    landed in the results."""
    source = _write(
        tmp_path,
        "x = 1\r# ash-ignore: R1 first\ry = 2\r# ash-ignore: R2 second\rz = 3\r",
    )

    found = find_inline_suppressions(source, tmp_path if with_scan_root else None)

    assert found == [InlineSuppression(line_number=1, rule_id="R1", reason="first")]


@pytest.mark.parametrize(
    "directive",
    ["# ash-ignore: R1 why", "# ash-ignore-next-line: R1 why"],
    ids=["inline", "next-line"],
)
def test_a_lone_cr_ends_the_reason(tmp_path, directive):
    """Red at the base: the reason group matched the CR and everything after it
    on the line, here a secret, which then reached the SARIF justification."""
    source = _write(tmp_path, f"x = 1  {directive}\rtoken = 'hunter2'\ny = 2\n")

    found = find_inline_suppressions(source)

    assert len(found) == 1
    assert found[0].rule_id == "R1"
    assert found[0].reason == "why"


def test_a_cr_alone_after_the_rule_id_leaves_the_default_reason(tmp_path):
    """Cut at the CR, an empty reason is the default one, as for a bare
    directive. Red with ``\\s*`` after the rule id: ``\\s`` matches the CR, so
    the reason group began after it and read ``rest``."""
    source = _write(tmp_path, "x = 1  # ash-ignore: R1\rrest\n")

    found = find_inline_suppressions(source)

    assert found == [
        InlineSuppression(line_number=1, rule_id="R1", reason="Inline suppression")
    ]


@pytest.mark.parametrize(
    "directive",
    ["# ash-ignore:", "# ash-ignore-next-line:"],
    ids=["inline", "next-line"],
)
def test_a_cr_right_after_the_marker_is_no_directive(tmp_path, directive):
    """Red at the base: ``\\s*`` after the marker consumed the CR and the next
    CR-line's first word, ``R1``, was taken as the rule id. The marker has no
    rule id on its own line, so there is no directive."""
    source = _write(tmp_path, f"x = 1  {directive}\rR1 why\ny = 2\n")

    found = find_inline_suppressions(source)

    assert found == []


@pytest.mark.parametrize("marker", ["#", "//"], ids=["hash", "slash"])
def test_a_cr_between_the_comment_marker_and_the_word_is_no_directive(tmp_path, marker):
    """Red at the base: ``\\s*`` between the marker and ``ash-ignore`` matched
    the CR, so a bare comment marker ending one CR-line and a directive-shaped
    text on the next were read as one directive."""
    source = _write(tmp_path, f"x = 1  {marker}\rash-ignore: R1 why\ny = 2\n")

    found = find_inline_suppressions(source)

    assert found == []


# --- the quoted-string scan is linear in the line ---

# The expression the scan replaced, kept here as the reference for what a
# quoted string is: the same spans on every line it finishes on. A quote opens
# a string only at a word boundary, or after a one- or two-letter string prefix
# that is itself at a word start (``f"``, ``rb'``); an apostrophe glued to a
# word opens nothing.
_OPENER = r"(?:(?<!\w)|(?<=\b[rRbBfFuU])|(?<=\b[rRbBfFuU]{2}))"
_REFERENCE_QUOTED_STRING = re.compile(
    _OPENER
    + r"\"(?:\\.|[^\"\\])*\"|"
    + _OPENER
    + r"'(?:\\.|[^'\\])*'|"
    + _OPENER
    + r"`(?:\\.|[^`\\])*`"
)


@pytest.mark.parametrize(
    "line",
    [
        "",
        "x = 1",
        'x = "# ash-ignore: B101"',
        "it's # ash-ignore: X",
        "'it\\'s' # ash-ignore: X",
        '\\"abc" # ash-ignore: X',
        "s = \"oops  'a # ash-ignore: X b'",
        "a = 'x\\\\' # ash-ignore: X 'y'",
        "`t ${x}` + '\"' + \"'\" # ash-ignore: X",
        'ends with a backslash "abc\\',
        "\"\" '' `` # ash-ignore: X",
        '"a\\\\\\"b" # ash-ignore: X',
        "`a 'b` c' # ash-ignore: X",
        "Description: Bob's bucket  # ash-ignore: X logging isn't needed",
        "# it's ok # ash-ignore: X it's fixture-only",
        'f"# ash-ignore: X"',
        "rb'# ash-ignore: X'",
        'Rf"x" # ash-ignore: X "y"',
        "a_'b' # ash-ignore: X",
        'abc"# ash-ignore: X"',
        "x = 1 ;f'# ash-ignore: X'",
        "1'# ash-ignore: X'",
    ],
)
def test_the_quoted_spans_are_the_reference_expressions(line):
    """The one-pass scan and the expression it replaced agree, escape rules and
    the quote-that-never-closes rule included."""
    # Imported here, not at the top: a module without the scan then fails this
    # test alone and still collects the others.
    from automated_security_helper.utils.suppression_matcher import _quoted_spans

    expected = [found.span() for found in _REFERENCE_QUOTED_STRING.finditer(line)]

    assert _quoted_spans(line) == expected


@pytest.mark.parametrize(
    "line",
    [
        pytest.param(
            "  Description: Bob's bucket  # ash-ignore: CKV_AWS_18 logging isn't needed",
            id="yaml-plain-scalar",
        ),
        pytest.param(
            "x = 1  # it's ok # ash-ignore: CKV_AWS_18 it's fixture-only",
            id="apostrophes-in-the-comment",
        ),
    ],
)
def test_an_apostrophe_in_prose_does_not_hide_the_directive(tmp_path, line):
    """Red at the base: the two apostrophes were read as a string that held the
    marker, so the directive the plain search had always found went unseen and
    an existing suppression stopped working with no warning."""
    source = _write(tmp_path, f"{line}\n")

    found = find_inline_suppressions(source)

    assert [(f.line_number, f.rule_id) for f in found] == [(1, "CKV_AWS_18")]


@pytest.mark.parametrize(
    "literal",
    [
        pytest.param("'# ash-ignore: X'", id="plain"),
        pytest.param('f"# ash-ignore: X"', id="f-prefix"),
        pytest.param("rb'# ash-ignore: X'", id="rb-prefix"),
        pytest.param('U"# ash-ignore: X"', id="upper-u-prefix"),
    ],
)
def test_a_marker_inside_a_string_literal_stays_hidden(tmp_path, literal):
    """The control for the apostrophe rule: a real string, plain or with a
    Python string prefix, still hides a marker written inside it."""
    source = _write(tmp_path, f"x = {literal}\n")

    found = find_inline_suppressions(source)

    assert found == []


def test_a_line_of_escaped_quotes_is_scanned_once(tmp_path):
    """Red at the base: each escaped quote started an attempt that ran to the end
    of the line, so this one line took time quadratic in its length (hours for
    the length here, where a pass that reads each character once takes well
    under the bound asserted). The directive after the quotes is still found,
    and nothing in the line is taken for a string."""
    tail = '\\"' * 200_000
    source = _write(tmp_path, f"x = {tail}  # ash-ignore: R1 why\n")

    started = time.perf_counter()
    found = find_inline_suppressions(source)
    elapsed = time.perf_counter() - started

    assert found == [InlineSuppression(line_number=1, rule_id="R1", reason="why")]
    assert elapsed < 10, elapsed


def test_a_path_the_os_layer_refuses_yields_no_suppressions_and_no_error(tmp_path):
    """Red at the base: ``ValueError: embedded null byte`` escaped."""
    found = find_inline_suppressions(tmp_path / "with\x00nul.py")

    assert found == []
