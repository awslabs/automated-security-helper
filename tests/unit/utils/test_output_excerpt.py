# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""head_and_tail keeps a failed tool's last words; see utils/output_excerpt.py."""

import pytest

from automated_security_helper.utils.output_excerpt import (
    head_and_tail,
    tool_output_excerpt,
)

pytestmark = pytest.mark.unit


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


#: A configured value a tool echoed back in its stderr; a placeholder, never a
#: credential.
CONFIGURED = "placeholder-configured-value-7"


def test_a_tool_excerpt_hides_the_callers_values_before_the_cut():
    """The excerpt lands in an error message that results and logs keep, so a
    configured value the tool echoed is hidden as error_text hides it, and on the
    whole text before the cut: a value the cut's marker would split is still
    matched."""
    text = "loading " + CONFIGURED + "\n" + "-" * 400 + "\nfailed: token " + CONFIGURED

    excerpt = tool_output_excerpt(text, 500, values=[CONFIGURED])

    assert CONFIGURED not in excerpt
    assert "loading" in excerpt and "failed: token" in excerpt


def test_a_value_the_cut_would_split_is_still_hidden():
    # The cut's head (a quarter of the limit, 25 characters) ends inside the value:
    # without redaction before the cut, the value's halves would sit on either
    # side of the marker.
    text = "a" * 18 + " " + CONFIGURED + " " + "b" * 400

    excerpt = tool_output_excerpt(text, 100, values=[CONFIGURED])

    assert CONFIGURED not in excerpt
    assert CONFIGURED[:5] not in excerpt and CONFIGURED[-5:] not in excerpt


def test_a_tool_excerpt_without_values_is_cleaned_and_cut_as_before():
    text = "x" * 300 + "y" * 300
    assert tool_output_excerpt(text, 100) == tool_output_excerpt(text, 100, values=())
    assert tool_output_excerpt("plain", 100, values=["other"]) == "plain"
