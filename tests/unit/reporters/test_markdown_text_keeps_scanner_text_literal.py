# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Markdown report keeps scanner-controlled text literal.

``markdown_reporter._text`` writes a project's or a scanner's text into GitHub
Markdown: it escapes HTML first, then backslash-escapes each character Markdown
would read as syntax. A finding's title is that kind of text (a rule id, here),
and the detailed findings heading prints it through ``_text``. These cells pin
both halves: each character Markdown reads as syntax, one cell apiece, and a
title holding all of them and an angle bracket, directly and through the
rendered report.
"""

import pytest

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters import (
    markdown_reporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
)
from automated_security_helper.schemas.sarif_schema_model import Result

#: Each character ``_text`` backslash-escapes: Markdown reads every one as syntax.
MARKDOWN_SYNTAX = "\\`*_[]{}#|~"

RAW_TITLE = "x*y|z<w`v_u#t[s]r{q}p~o\\m"
ESCAPED_TITLE = "x\\*y\\|z&lt;w\\`v\\_u\\#t\\[s\\]r\\{q\\}p\\~o\\\\m"


@pytest.mark.parametrize("character", list(MARKDOWN_SYNTAX))
def test_each_markdown_syntax_character_is_escaped(character):
    assert markdown_reporter._text(f"a{character}b") == f"a\\{character}b"


def test_text_escapes_html_then_markdown_syntax():
    # Read through the module, as the reporter reads it, so this cell checks
    # the same function the report prints with.
    assert markdown_reporter._text(RAW_TITLE) == ESCAPED_TITLE


def test_a_finding_title_is_printed_literal_in_the_detailed_heading(
    test_plugin_context,
):
    model = AshAggregatedResults(ash_config=get_default_config())
    model.sarif.runs[0].results = [
        Result.model_validate(
            {
                "ruleId": RAW_TITLE,
                "level": "error",
                "message": {"text": "fixture"},
                "properties": {"scanner_name": "bandit"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/app.py"},
                            "region": {"startLine": 3},
                        }
                    }
                ],
            }
        )
    ]
    model._flat_cache = None

    document = MarkdownReporter(context=test_plugin_context).report(model)
    headings = [
        line for line in document.splitlines() if line.startswith("### Finding 1:")
    ]

    assert headings == [f"### Finding 1: {ESCAPED_TITLE}"], headings
