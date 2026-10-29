# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The Bedrock summary report escapes its Markdown text once.

The report writes finding text into Markdown paragraphs, headings and tables
through the Markdown reporter's escapers. With ``html.escape``'s default quote
handling an apostrophe became the numeric entity ``&#x27;``, and the Markdown
pass that followed turned that entity's ``#`` into ``\\#``, which Markdown does
not read as an entity: a reader saw the characters ``&#x27;root&#x27;`` where
the text said ``'root'``. These tests pin that the report's escapers leave a
quote as written and still escape angle brackets, ampersands and each Markdown
syntax character.
"""

import pytest

import automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter as bsr_module

pytestmark = pytest.mark.unit

#: Each character the escaper backslash-escapes: Markdown reads every one as syntax.
MARKDOWN_SYNTAX = "\\`*_[]{}#|~"


@pytest.mark.parametrize("escaper", [bsr_module._text, bsr_module._cell])
@pytest.mark.parametrize("quote", ["'", '"'])
def test_a_quote_stays_a_quote(escaper, quote):
    written = f"the user is {quote}root{quote}."

    assert escaper(written) == written


@pytest.mark.parametrize("escaper", [bsr_module._text, bsr_module._cell])
def test_no_numeric_entity_or_escaped_hash_is_written_for_an_apostrophe(escaper):
    # pragma: allowlist nextline secret
    shown = escaper("Possible hardcoded password: 'hunter2'")

    assert "&#" not in shown, shown
    assert "\\#" not in shown, shown
    # pragma: allowlist nextline secret
    assert shown == "Possible hardcoded password: 'hunter2'"


@pytest.mark.parametrize("escaper", [bsr_module._text, bsr_module._cell])
def test_angle_brackets_and_ampersands_are_still_escaped(escaper):
    assert escaper("a<b>&c") == "a&lt;b&gt;&amp;c"


@pytest.mark.parametrize("character", list(MARKDOWN_SYNTAX))
def test_each_markdown_syntax_character_is_still_escaped(character):
    assert bsr_module._text(f"a{character}b") == f"a\\{character}b"


def test_a_cell_still_turns_line_breaks_into_breaks():
    assert bsr_module._cell("it's\r\nhere") == "it's<br>here"
