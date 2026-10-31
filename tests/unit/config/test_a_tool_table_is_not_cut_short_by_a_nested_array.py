# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The line-level ``[tool]`` reading ends the table at a HEADER, not at any ``[``.

``_tool_ash_declared`` reads an unparsable pyproject by its lines: an ``ash``
key counts between a bare ``[tool]`` header and the next table header. The
"next header" was any line starting with ``[``, so a row of a multi-line array
value (``  ["a", "b"],``, ``[3]``) ended the table early, the ``ash`` key written
after it was missed, and the pyproject was skipped as holding no ASH settings:
the scan ran with the defaults while its configuration sat unread, the outcome
this reading was written to prevent. A header is now a dotted key path between
one pair of brackets or two (never one of each), with a comment after it at
most. A one-element row such as ``[3]``, ``[1.5]`` or ``[true]`` has a header's
shape too, so a line is tested as a header only outside a multi-line value: the
brackets a value leaves open are tracked, and a bracket in a quoted string or
after a ``#`` is not counted.

Known limit: an array left unclosed in a table that did not parse hides every
header after it, so an ``ash`` key in a later table counts as the ``[tool]``
table's. The failure side is the loud error, not a silent skip.

Red at the base: the nested-array text, the one-element rows, the unpaired
brackets and the header-shaped line inside a string were read as ending the
table, so the ``ash`` key after them was missed. The tests that expect a real
header to end the table, and the strings and comments that hold a bracket, are
controls that hold at both ends.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.config_sources import _tool_ash_declared

pytestmark = pytest.mark.unit

NESTED_ARRAY_THEN_ASH = (
    "[tool]\n"
    "list = [\n"
    '  ["a", "b"],\n'
    '  ["c", "d"]\n'
    "]\n"
    'ash = { severity_threshold = "HIGH"\n'
)


def test_an_ash_key_after_a_nested_array_is_read() -> None:
    offset = _tool_ash_declared(NESTED_ARRAY_THEN_ASH)

    assert offset is not None
    assert NESTED_ARRAY_THEN_ASH[offset:].startswith("ash = {")


@pytest.mark.parametrize(
    "header",
    ["[other]", "[[other]]", '["quoted.name"]', "[ a . b ]  # comment", "[tool.x]\r"],
    ids=["bare", "array", "quoted", "spaced-commented", "crlf"],
)
def test_a_real_header_still_ends_the_table(header: str) -> None:
    """The control: the ``ash`` key under the next header is not tool's."""
    text = f"[tool]\nx = 1\n{header}\nash = 1\n"

    assert _tool_ash_declared(text) is None


@pytest.mark.parametrize(
    "row",
    ['["a"]', "[3]", "[1.5]", "[-1]", "[true]", '[["a"]]', "[a]", "[3],"],
    ids=["string", "int", "float", "negative", "bool", "nested", "bare", "comma"],
)
def test_a_header_shaped_row_inside_an_array_is_not_a_header(row: str) -> None:
    """A row of a multi-line array that has a header's shape (a one-element array
    of a string, a number or a bool) is told by where it sits: inside the value,
    so it does not end the table. The pyproject is skipped otherwise, and the
    scan runs with the defaults while the ``ash`` key after the array sat unread."""
    text = f"[tool]\nmatrix = [\n  [1, 2],\n  {row}\n]\nash = 1\n"

    offset = _tool_ash_declared(text)

    assert offset is not None
    assert text[offset:].startswith("ash = 1")


def test_a_real_header_after_the_array_closes_still_ends_the_table() -> None:
    """The control: once the array is closed, a header ends the table."""
    text = "[tool]\nmatrix = [\n  [3]\n]\n[other]\nash = 1\n"

    assert _tool_ash_declared(text) is None


@pytest.mark.parametrize("stray", ["[a]]", "[[a]"], ids=["closes twice", "opens twice"])
def test_a_line_with_unpaired_brackets_is_no_header(stray: str) -> None:
    """``[a]]`` and ``[[a]`` are not TOML headers: they do not end the table."""
    text = f"[tool]\nx = 1\n{stray}\nash = 1\n"

    offset = _tool_ash_declared(text)

    assert offset is not None
    assert text[offset:].startswith("ash = 1")


@pytest.mark.parametrize(
    "value",
    ['title = "a [b"', "title = 'c ['", "x = 1 # ["],
    ids=["basic string", "literal string", "comment"],
)
def test_a_bracket_in_a_string_or_comment_opens_no_array(value: str) -> None:
    """The control: a bracket inside a quoted string or after a ``#`` is not an
    open array, so the header after it still ends the table."""
    text = f"[tool]\n{value}\n[other]\nash = 1\n"

    assert _tool_ash_declared(text) is None


def test_a_header_shaped_line_inside_a_multi_line_string_is_no_header() -> None:
    text = '[tool]\ntext = """\n[other]\n"""\nash = 1\n'

    offset = _tool_ash_declared(text)

    assert offset is not None
    assert text[offset:].startswith("ash = 1")
