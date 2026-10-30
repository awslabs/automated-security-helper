# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""tool_output_excerpt and head_and_tail (utils/output_excerpt.py), four readings.

An OSC sequence ends at BEL, at either spelling of ST, or at its line's end, so
one a tool left unterminated no longer swallows the lines after it. The format
characters (a bidirectional override, a zero-width space, the line and paragraph
separators) are written as escapes, as the controls are. A CI command form left
standing at a line's start by a removed color sequence, or formed by the join on
both sides of one, is broken. And head_and_tail does not cut inside an escape's
text or a backslash run.
"""

from __future__ import annotations

import pytest

from automated_security_helper.utils.output_excerpt import (
    head_and_tail,
    tool_output_excerpt,
)

pytestmark = pytest.mark.unit


def test_an_osc_ended_by_the_c1_string_terminator_ends_there():
    text = "a\x1b]0;title\x9cthe reason\x07b"
    assert tool_output_excerpt(text, 500) == "athe reason\\x07b"


def test_an_unterminated_osc_ends_with_its_line():
    text = "a\x1b]0;title\nerror: the reason\n"
    excerpt = tool_output_excerpt(text, 500)
    assert "error: the reason" in excerpt, excerpt
    assert "\x1b" not in excerpt and "\\x1b" in excerpt, excerpt


@pytest.mark.parametrize(
    ("character", "shown"),
    [
        ("\N{RIGHT-TO-LEFT OVERRIDE}", "\\u202e"),
        ("\N{ZERO WIDTH SPACE}", "\\u200b"),
        ("\N{LINE SEPARATOR}", "\\u2028"),
        ("\N{PARAGRAPH SEPARATOR}", "\\u2029"),
        ("\x9b", "\\x9b"),
    ],
)
def test_a_format_character_is_written_as_its_escape(character, shown):
    assert tool_output_excerpt(f"a{character}b", 500) == f"a{shown}b"


def test_a_command_uncovered_by_a_removed_color_sequence_is_broken():
    text = "\x1b[31m::error title=x::pwned\x1b[0m\nnext"
    excerpt = tool_output_excerpt(text, 500)
    assert not excerpt.startswith("::"), excerpt
    assert excerpt.startswith("\\x3a:error title=x::pwned"), excerpt


def test_a_command_formed_by_the_join_around_a_sequence_is_broken():
    text = "see #\x1b[0m#[add-mask]pwned"
    excerpt = tool_output_excerpt(text, 500)
    assert "##[" not in excerpt, excerpt
    assert "\\x23#[add-mask]pwned" in excerpt, excerpt


def test_the_tail_does_not_start_inside_an_escape():
    # limit 100: the head is 25 characters and the tail starts at index 225; the
    # escape "\x41" is written over indices 223-226, so the cut would land inside.
    text = "a" * 223 + "\\x41" + "b" * 73
    assert len(text) == 300
    excerpt = head_and_tail(text, 100)
    _, _, tail = excerpt.partition("]... ")
    assert tail.startswith("\\x41"), tail
    assert "x41" not in excerpt.partition(" ...[")[0]


def test_the_head_does_not_end_inside_an_escape():
    # The head would end at index 25, inside the escape text written over 23-28.
    text = "a" * 23 + "\\u202e" + "b" * 271
    excerpt = head_and_tail(text, 100)
    head, _, _ = excerpt.partition(" ...[")
    assert head == "a" * 23, head


def test_the_tail_does_not_start_inside_a_backslash_run():
    text = "a" * 221 + "\\\\\\\\" + "x41" + "b" * 72
    assert len(text) == 300
    excerpt = head_and_tail(text, 100)
    _, _, tail = excerpt.partition("]... ")
    assert tail.startswith("\\\\\\\\x41"), tail


def test_the_head_does_not_end_inside_a_long_backslash_run():
    # limit 80: the head would end at index 20, inside a run of 40 backslashes
    # written over 1-40. The window the cut looks at opens 11 back, inside the run;
    # the cut must move to the run's start, index 1, not to where the window opened.
    text = "x" + "\\" * 40 + "y" * 100
    excerpt = head_and_tail(text, 80)
    head, _, _ = excerpt.partition(" ...[")
    assert head == "x", head


def test_the_tail_does_not_start_inside_a_long_backslash_run():
    # limit 60: the tail would start at index 95, inside a run of 40 backslashes
    # written over 80-119; it must start with the whole run.
    text = "y" * 80 + "\\" * 40 + "z" * 20
    assert len(text) == 140
    excerpt = head_and_tail(text, 60)
    _, _, tail = excerpt.partition("]... ")
    assert tail == "\\" * 40 + "z" * 20, tail


def test_a_cut_between_plain_characters_is_where_it_was():
    text = "abcdefghij" * 30
    excerpt = head_and_tail(text, 100)
    head, _, rest = excerpt.partition(" ...[")
    _, _, tail = rest.partition("]... ")
    assert len(head) == 25 and len(tail) == 75
