# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""head_and_tail keeps a failed tool's last words; see utils/output_excerpt.py."""

import pytest

from automated_security_helper.utils.output_excerpt import (
    head_and_tail,
    tool_output_excerpt,
)


def test_text_within_the_limit_is_unchanged():
    assert head_and_tail("short", 10) == "short"
    assert head_and_tail("x" * 10, 10) == "x" * 10


def test_a_long_text_keeps_its_start_and_its_end():
    text = "START" + "-" * 5000 + "THE ERROR"
    excerpt = head_and_tail(text, 400)
    assert excerpt.startswith("START")
    assert excerpt.endswith("THE ERROR")
    assert "[4614 characters omitted]" in excerpt


@pytest.mark.parametrize("limit", [4, 100, 2000])
def test_the_kept_text_is_exactly_the_limit(limit):
    text = "abcdefghij" * 1000
    excerpt = head_and_tail(text, limit)
    head, _, rest = excerpt.partition(" ...[")
    _, _, tail = rest.partition("]... ")
    assert len(head) + len(tail) == limit
    assert text.startswith(head) and text.endswith(tail)


def test_a_non_positive_limit_keeps_nothing():
    assert head_and_tail("anything", 0) == ""


def test_a_tool_excerpt_drops_escape_sequences_and_names_control_characters():
    text = "\x1b[31merror\x1b[0m: \x1b]0;title\x07bad\x00 byte\x07\rline\nnext\ttab"
    assert tool_output_excerpt(text, 500) == (
        "error: bad\\x00 byte\\x07\\x0dline\nnext\ttab"
    )


def test_a_tool_excerpt_is_cut_after_cleaning():
    text = "x" * 300 + "\x1b[2J" + "y" * 300
    excerpt = tool_output_excerpt(text, 100)
    assert "\x1b" not in excerpt
    assert excerpt.startswith("x" * 25) and excerpt.endswith("y" * 75)
    assert "characters omitted" in excerpt
