# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Markdown report escapes a quote once, for Markdown.

``markdown_reporter._text`` escapes HTML first and then backslash-escapes
Markdown syntax. ``html.escape`` with its default quote handling writes an
apostrophe as the numeric entity ``&#x27;``, and the second pass turns that
entity's ``#`` into ``\\#``. Markdown does not read the result as an entity, so
a reader saw the characters ``&#x27;`` where a finding said ``'root'``. These
tests pin the fix: a quote stays as written, through the escaper directly and
through the rendered report, while ``<``, ``>``, ``&`` and each Markdown syntax
character are still escaped.
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

pytestmark = pytest.mark.unit

RULE_ID = "the-user-is-'root'-and-\"x\""


@pytest.mark.parametrize("escaper", [markdown_reporter._text, markdown_reporter._cell])
@pytest.mark.parametrize("quote", ["'", '"'])
def test_a_quote_stays_a_quote(escaper, quote):
    written = f"the user is {quote}root{quote}."

    assert escaper(written) == written


@pytest.mark.parametrize("escaper", [markdown_reporter._text, markdown_reporter._cell])
def test_an_apostrophe_writes_no_numeric_entity_or_escaped_hash(escaper):
    # pragma: allowlist nextline secret
    shown = escaper("Possible hardcoded password: 'hunter2'")

    assert "&#" not in shown, shown
    assert "\\#" not in shown, shown


@pytest.mark.parametrize("escaper", [markdown_reporter._text, markdown_reporter._cell])
def test_angle_brackets_and_ampersands_are_still_escaped(escaper):
    assert escaper("a<b>&c") == "a&lt;b&gt;&amp;c"


def test_a_quote_in_a_finding_title_is_printed_as_written(test_plugin_context):
    model = AshAggregatedResults(ash_config=get_default_config())
    model.sarif.runs[0].results = [
        Result.model_validate(
            {
                "ruleId": RULE_ID,
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

    assert headings == [f"### Finding 1: {RULE_ID}"], headings
