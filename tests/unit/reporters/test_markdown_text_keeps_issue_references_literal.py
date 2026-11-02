# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Scanner text that reads as an issue reference is put in a code span.

Where the Markdown summary is posted as a pull request comment, GitHub turns
``#123``, ``GH-123`` and ``owner/repo#123`` into links and adds a "mentioned"
event to the issue they name. A scanner message such as "fixed in #1234" would
therefore write into an issue of the project. An ``@name`` and a bare URL were
already put in a code span for the same reason; an issue reference joins them.
"""

import pytest

from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    _html_literal,
    _reference_text,
    _text,
)

pytestmark = pytest.mark.unit


class TestAnIssueReferenceIsPutInACodeSpan:
    def test_a_bare_issue_number(self):
        assert _text("fixed in #1234") == "fixed in `#1234`"

    def test_a_gh_number_in_either_case(self):
        assert _text("see GH-99") == "see `GH-99`"
        assert _text("see gh-99") == "see `gh-99`"

    def test_an_owner_repo_issue_number(self):
        assert _text("tracked in octo-org/some.repo#7") == (
            "tracked in `octo-org/some.repo#7`"
        )

    def test_a_reference_in_brackets_or_at_the_end_of_a_sentence(self):
        assert _text("(#12)") == "(`#12`)"
        assert _text("fixed in #12.") == "fixed in `#12`."

    def test_the_html_summary_line_puts_it_in_code_too(self):
        assert _html_literal("fixed in #1234") == "fixed in <code>#1234</code>"

    def test_the_project_line_puts_it_in_code_beside_a_written_reference(self):
        assert _reference_text("#5 ${ZZ_NAME}") == "`#5` `${ZZ_NAME}`"


class TestTextThatIsNotAReferenceIsLeftAlone:
    """The controls: a ``#`` that GitHub does not link keeps its escape."""

    @pytest.mark.parametrize(
        "text, expected",
        [
            ("item #abc", "item \\#abc"),
            ("5#6", "5\\#6"),
            ("C# and F#", "C\\# and F\\#"),
            ("#123abc", "\\#123abc"),
            ("xGH-1", "xGH-1"),
        ],
    )
    def test_it_is_escaped_as_before(self, text, expected):
        assert _text(text) == expected

    def test_a_url_fragment_stays_inside_the_url_span(self):
        assert _text("see https://example.com/page#12") == (
            "see `https://example.com/page#12`"
        )
