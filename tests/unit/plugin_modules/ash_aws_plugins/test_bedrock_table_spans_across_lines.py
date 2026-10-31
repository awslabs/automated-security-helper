# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A code span that touches a GitHub table row is rewritten, wherever it starts.

A GitHub viewer splits each table row into columns before it reads code spans, so
a span that crosses a line break into or within a table is cut at the end of the
row, and the HTML it holds is outside any span. ``_markdown_as_written`` used to
decide by the line a span started on and by a pipe inside it, so a span that
started on a row with no pipe, or on the prose line above the header, kept its
HTML as written. The rewrite now covers a span that holds a line break and
touches a table row on any line, and the table shapes a viewer reads as tables
(a header straight after a prose line, alignment colons, no outer pipes) are
pinned.

The controls pin what is left as written: a span on one row with no pipe, a span
after the blank line that ends a table, and a span across a line break away from
any table.
"""

import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    _markdown_as_written,
)

pytestmark = pytest.mark.unit


def test_a_span_that_starts_on_a_row_and_ends_on_the_next_is_rewritten():
    """No pipe in the span: the viewer cuts it at the end of its row, so the tag
    after the backtick is raw HTML there."""
    table = "| a | b |\n|---|---|\n| `<img src=x onerror=1>\ny` | z |"

    written = _markdown_as_written(table)

    assert "<img" not in written, written
    assert "&lt;img src=x onerror=1>\ny`" in written, written


def test_a_span_that_starts_on_the_prose_line_above_the_header_is_rewritten():
    table = "`<img src=x onerror=1>\n| a | b |\n|---|---|\n| c` | d |"

    written = _markdown_as_written(table)

    assert "<img" not in written, written
    assert "&lt;img src=x onerror=1>" in written, written


@pytest.mark.parametrize(
    "table",
    [
        "Intro line.\n| a | b |\n|---|---|\n| `<i>|x` | y |",
        "| a | b |\n|:--|--:|\n| `<i>|x` | y |",
        "a | b\n--|--\n`<i>|x` | y",
    ],
    ids=["header-after-prose", "alignment-colons", "no-outer-pipes"],
)
def test_the_table_shapes_a_viewer_reads_have_their_pipe_spans_rewritten(table):
    written = _markdown_as_written(table)

    assert "&lt;i>\\|x" in written, written
    assert "<i>" not in written, written


def test_a_span_on_one_row_with_no_pipe_stays_as_written():
    """The control: nothing splits it, so it is code to every viewer."""
    table = "| a | b |\n|---|---|\n| `<b>` | y |"

    assert _markdown_as_written(table) == table


def test_a_span_after_the_blank_line_that_ends_a_table_is_prose():
    """The control: the paragraph after the blank line is not a table row."""
    text = "| a | b |\n|---|---|\n| c | d |\n\nUse `<i>|x` here."

    assert _markdown_as_written(text) == text


def test_a_span_across_a_line_break_away_from_any_table_stays_as_written():
    text = "Use `a<b\ny|c` here."

    assert _markdown_as_written(text) == text
