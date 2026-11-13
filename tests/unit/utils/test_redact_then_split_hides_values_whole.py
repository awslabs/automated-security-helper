# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""redact_then_split hides a value before any line of the text is cut.

The order is the contract. A value can hold a line break (a PEM, a
multi-line token), so a site that splits first cuts the value in two, and a
per-line redaction matches neither half: both halves print. These cells pin
that the redaction sees the whole text, with the value's own separators,
before the split -- a helper rewritten as split-then-redact fails the
spanning cells and passes the single-line control, which is exactly the
leak's shape.
"""

from __future__ import annotations

import pytest

from automated_security_helper.utils.error_text import (
    redact_then_split,
    text_without_values,
)

pytestmark = pytest.mark.unit

#: Each fragment is distinctive on its own, so an assert that it is absent
#: can only pass by redaction, never by luck; the whole value holds the
#: separator, which is what a split-first site cuts.
_HEAD = "Zq7Kx9LmHead"
_TAIL = "Pw4Nv2RtTail"


def test_a_value_spanning_lines_is_hidden_from_every_line():
    value = f"{_HEAD}\n{_TAIL}"
    lines = redact_then_split(f"error: refused {value} by policy\nnext", (value,))
    assert lines, lines
    for line in lines:
        assert _HEAD not in line, lines
        assert _TAIL not in line, lines


def test_a_crlf_value_is_matched_in_its_own_spelling():
    # splitlines treats CRLF as one break; a split-first site would hand the
    # redaction "<head>\r" and "<tail>", and neither matches the value.
    value = f"{_HEAD}\r\n{_TAIL}"
    lines = redact_then_split(f"left {value} right", (value,))
    for line in lines:
        assert _HEAD not in line, lines
        assert _TAIL not in line, lines


def test_a_single_line_value_is_hidden_in_its_line():
    # The control: redaction itself, with no split in the way.
    value = f"{_HEAD}{_TAIL}"
    lines = redact_then_split(f"first\nsays {value} here\nlast", (value,))
    assert lines[0] == "first", lines
    assert lines[-1] == "last", lines
    assert all(value not in line for line in lines), lines


def test_a_bare_string_value_is_one_value_not_its_characters():
    # The values arrive through the same normalizer as every sink
    # (environment_strings): one string on its own is ONE value.
    value = f"{_HEAD}{_TAIL}"
    lines = redact_then_split(f"a {value} b", value)
    assert lines == [text_without_values(f"a {value} b", (value,))], lines
    assert all(value not in line for line in lines), lines


def test_no_values_returns_the_texts_own_lines():
    assert redact_then_split("a\nb\r\nc", ()) == ["a", "b", "c"]
