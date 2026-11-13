# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""How a model answer is written when it escapes a character or holds a closed
fence.

Two defects of ``_markdown_as_written``, each pinned by a test that failed at
the base: a "<" or "&" the answer had escaped with a backslash was rewritten
to a backslash and an entity, which CommonMark renders as the entity's own
text; and a closed fence whose content held the fence-closing marker was taken
for an open one, so fence lines were appended and one was left open over the
rest of the report.
"""

import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    _fences_closed,
    _html_as_text,
    _markdown_as_written,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# A backslash-escaped character is text already
# ---------------------------------------------------------------------------


def test_an_escaped_angle_bracket_is_left_as_written():
    r"""``\<`` renders as "<"; ``\&lt;`` would render as the text "&lt;"."""
    assert _markdown_as_written("a \\< b") == "a \\< b"


def test_an_escaped_ampersand_is_left_as_written():
    assert _markdown_as_written("AT\\&T") == "AT\\&T"


def test_an_unescaped_angle_bracket_is_still_written_as_text():
    """The control."""
    assert _markdown_as_written("a < b") == "a &lt; b"


def test_an_escaped_backslash_before_a_tag_does_not_escape_the_tag():
    r"""``\\<i>`` is a literal backslash and then a tag: the tag is HTML and is
    written as text, the backslashes stay."""
    assert _html_as_text("\\\\<i>x</i>") == "\\\\&lt;i>x&lt;/i>"
    assert _markdown_as_written("\\\\<i>x</i>") == "\\\\&lt;i>x&lt;/i>"


# ---------------------------------------------------------------------------
# A closed fence is not an open one
# ---------------------------------------------------------------------------

MARKER = "ash-report-continues"


def test_a_closed_fence_holding_the_marker_text_is_left_alone():
    """The fence is closed, so the report text after the answer renders as the
    report; nothing is appended."""
    answer = f"```\n{MARKER}\n```"

    assert _fences_closed(answer) == answer
    assert _markdown_as_written(answer) == answer


def test_an_open_fence_is_still_closed():
    """The control."""
    assert _fences_closed("```\ncode") == "```\ncode\n```"


def test_a_closed_fence_before_an_open_one_closes_only_the_open_one():
    answer = f"```\n{MARKER}\n```\n\n````\nmore"

    assert _fences_closed(answer) == answer + "\n````"
