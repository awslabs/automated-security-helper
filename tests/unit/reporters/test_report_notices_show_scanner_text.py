# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The human reports show scanner text in their coverage notices and snippets.

A converter's failure reason and the id of a rule that reached no verdict come
from the tools a scan ran, and a finding's code snippet comes from the scanned
repository. The text, Markdown and HTML reports print the first two in their
coverage notices, and the HTML report prints the snippet. Text printed there is
shown, not obeyed: a control character is written as a visible escape, and a
CI command form at a line start is broken, as ``shown_on_one_line`` and
``shown_not_obeyed`` write them.
"""

import html
import re

import pytest

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
)
from automated_security_helper.schemas.sarif_schema_model import Invocation, Result

pytestmark = pytest.mark.unit

#: The marker each probe text carries, so only its own lines are inspected.
MARKER = "probe-mark"


def _probe(tag):
    """Scanner text with ESC, BEL, a line feed and a CI command form after it."""
    return f"{tag}-\x1b[31m-\x07-\n::warning::{MARKER}"


def _model(gap):
    model = AshAggregatedResults(ash_config=get_default_config())
    model.sarif.runs[0].results = []
    model.additional_reports["bandit"] = {
        "source": {"scanner_name": "bandit", "status": "PASSED", "duration": 1.0}
    }
    if gap == "converter":
        model.converter_results["jupyter"] = ConverterStatusInfo(
            converted_paths=[], failure=_probe("conv")
        )
    else:
        model.sarif.runs[0].invocations = [
            Invocation.model_validate(
                {
                    "executionSuccessful": True,
                    "toolExecutionNotifications": [
                        {
                            "level": "error",
                            "associatedRule": {"id": _probe("rule")},
                            "message": {"text": "no verdict"},
                        }
                    ],
                }
            )
        ]
    model._flat_cache = None
    return model


def _commands_at_line_start(document):
    return [
        line
        for line in document.splitlines()
        if line.lstrip().startswith("::") and MARKER in line
    ]


@pytest.mark.parametrize("gap", ["converter", "rule"])
@pytest.mark.parametrize("reporter_cls", [TextReporter, MarkdownReporter, HtmlReporter])
def test_a_coverage_notice_shows_scanner_text(gap, reporter_cls, test_plugin_context):
    document = reporter_cls(context=test_plugin_context).report(_model(gap))

    # The control: the notice is there, with the text in it.
    assert MARKER in document, document
    assert "\x1b" not in document
    assert "\x07" not in document
    assert _commands_at_line_start(document) == []
    # Shown, not dropped: the escape is written out.
    assert "x1b" in document


def test_the_html_snippet_shows_scanner_text_and_keeps_its_layout(test_plugin_context):
    model = AshAggregatedResults(ash_config=get_default_config())
    model.sarif.runs[0].results = [
        Result.model_validate(
            {
                "ruleId": "R1",
                "level": "error",
                "message": {"text": "fixture"},
                "properties": {"scanner_name": "bandit"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/app.py"},
                            "region": {
                                "startLine": 3,
                                "snippet": {"text": "first line\n" + _probe("snip")},
                            },
                        }
                    }
                ],
            }
        )
    ]
    model._flat_cache = None

    document = HtmlReporter(context=test_plugin_context).report(model)
    snippets = [
        html.unescape(text)
        for text in re.findall(
            r"<pre [^>]*><code>(.*?)</code></pre>", document, re.DOTALL
        )
    ]

    assert len(snippets) == 1, snippets
    snippet = snippets[0]
    assert MARKER in snippet, snippet
    assert "\x1b" not in snippet and "\x07" not in snippet, repr(snippet)
    assert _commands_at_line_start(snippet) == [], repr(snippet)
    # A snippet's own layout stays: its lines are still lines.
    assert snippet.startswith("first line\n"), repr(snippet)
