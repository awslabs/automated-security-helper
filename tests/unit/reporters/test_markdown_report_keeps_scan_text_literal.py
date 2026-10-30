# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Markdown report keeps scan text literal and keeps coverage in view.

The report is posted as a CI summary and a GitHub comment, so text that came
from a scan must not act there.

* A name such as ``@someone`` notifies a user, and a bare URL becomes a link,
  without any Markdown syntax. Both are put in a code span, in the headings,
  the lists and the collapsible ``<summary>`` line.
* Each line of a multi-line description began a block of its own: four blanks
  made a code block, ``-`` or ``1.`` a list, ``---`` or ``===`` a rule or a
  heading. They are kept as text.
* The ``<summary>`` line is one line, severity included, so a blank line in the
  value cannot end the HTML block.
* The inputs no scanner or converter read stay in the report when the summary
  is turned off, as the coverage notices do.
* A negative limit is refused when the option is read; it used to slice the
  findings from the end.
"""

import pytest
from pydantic import ValidationError

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
    MarkdownReporterConfig,
    MarkdownReporterConfigOptions,
    _block_text,
    _html_literal,
    _text,
)
from automated_security_helper.schemas.sarif_schema_model import Result

pytestmark = pytest.mark.unit


def _model(**overrides) -> AshAggregatedResults:
    body = {
        "ruleId": "R1",
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
    body.update(overrides)
    model = AshAggregatedResults(ash_config=get_default_config())
    model.sarif.runs[0].results = [Result.model_validate(body)]
    model._flat_cache = None
    return model


def _report(test_plugin_context, model, **options) -> str:
    return MarkdownReporter(
        context=test_plugin_context,
        config=MarkdownReporterConfig(options=MarkdownReporterConfigOptions(**options)),
    ).report(model)


class TestAMentionOrAUrlIsNotActedOn:
    def test_text_puts_each_in_a_code_span(self):
        assert _text("ping @octocat now") == "ping `@octocat` now"
        assert _text("see https://example.com/a?b=1 here") == (
            "see `https://example.com/a?b=1` here"
        )
        assert _text("see www.example.com") == "see `www.example.com`"

    def test_a_url_does_not_take_the_punctuation_that_closes_around_it(self):
        assert _text("(see https://example.com/a.)") == "(see `https://example.com/a`.)"
        assert _text("x](https://example.com/b) y") == "x\\](`https://example.com/b`) y"

    def test_an_address_and_ordinary_text_are_left_alone(self):
        # The control: not everything with an "@" or a dot is a mention.
        assert _text("mail me@example.com") == "mail me@example.com"
        assert _text("a_b *c*") == "a\\_b \\*c\\*"

    def test_html_literal_puts_each_in_a_code_element(self):
        assert _html_literal("x @octocat <y>") == "x <code>@octocat</code> &lt;y&gt;"
        assert _html_literal("https://example.com/a") == (
            "<code>https://example.com/a</code>"
        )

    def test_the_report_holds_a_mention_in_the_heading_and_the_summary(
        self, test_plugin_context
    ):
        document = _report(
            test_plugin_context,
            _model(
                ruleId="rule @octocat",
                locations=[
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "https://example.com/x.py"},
                            "region": {"startLine": 3},
                        }
                    }
                ],
            ),
        )

        assert "<code>@octocat</code>" in document
        assert "<code>https://example.com/x.py" in document
        assert "`@octocat`" in document
        # No bare mention reaches the document outside a code form.
        assert " @octocat" not in document.replace("`@octocat`", "").replace(
            "<code>@octocat</code>", ""
        )


class TestAMultiLineDescriptionStaysText:
    def test_block_text_keeps_indentation_and_markers_literal(self):
        text = "intro\n    indented\n- item\n1. step\n---\n==="
        assert _block_text(text) == (
            "intro\n&nbsp;&nbsp;&nbsp;&nbsp;indented\n\\- item\n1\\. step\n\\---\n\\==="
        )

    def test_a_line_that_starts_with_a_word_is_unchanged(self):
        assert _block_text("plain\nsecond line") == "plain\nsecond line"

    def test_the_report_does_not_start_blocks_from_a_description(
        self, test_plugin_context
    ):
        document = _report(
            test_plugin_context,
            _model(message={"text": "intro\n    indented\n- item\n---"}),
        )

        lines = document.split("\n")
        assert "\\- item" in lines
        assert "\\---" in lines
        assert "&nbsp;&nbsp;&nbsp;&nbsp;indented" in lines
        assert "- item" not in lines
        assert "---" not in lines


class TestTheSummaryLineIsOneLine:
    def test_a_blank_line_in_a_severity_cannot_end_the_html_block(
        self, test_plugin_context
    ):
        """An additional report's severity is read as the gate reads it.

        Text that is not a severity name is graded as a result with no level, so
        none of it reaches the summary line.
        """
        model = _model()
        model.sarif.runs[0].results = []
        model.additional_reports["custom-plugin"] = [
            {
                "title": "Odd severity",
                "description": "d",
                "severity": "HIGH\n\n## Injected heading",
                "file_path": "app.py",
                "line_start": 3,
            }
        ]
        model._flat_cache = None

        document = _report(test_plugin_context, model)

        # The report holds other collapsible sections; this finding's summary is
        # the one that names its location (the line holds the severity, the rule
        # ID and the location, not the title).
        summary = [
            line
            for line in document.split("\n")
            if "<summary>" in line and "app.py:3" in line
        ]
        # The control: the finding is in the report, with its summary line.
        assert len(summary) == 1, summary
        assert summary[0].endswith("</summary>"), summary[0]
        assert "\n## Injected" not in document


class TestCoverageStaysWhenTheSummaryIsOff:
    @staticmethod
    def _with_unscanned_input() -> AshAggregatedResults:
        model = _model()
        model.additional_reports["bandit"] = {
            "source": {
                "scanner_name": "bandit",
                "status": "PASSED",
                "duration": 1.0,
                "inputs_not_scanned": [
                    {"path": "vendor/big.py", "reason": "file too large"}
                ],
            }
        }
        return model

    @pytest.mark.parametrize("include_summary", [True, False])
    def test_the_inputs_not_scanned_section_is_present(
        self, include_summary, test_plugin_context
    ):
        document = _report(
            test_plugin_context,
            self._with_unscanned_input(),
            include_summary=include_summary,
        )

        assert "### Inputs not scanned" in document
        assert "vendor/big.py" in document
        assert "file too large" in document


class TestANegativeLimitIsRefused:
    @pytest.mark.parametrize("option", ["max_detailed_findings", "top_hotspots_limit"])
    def test_a_negative_value_is_refused(self, option):
        with pytest.raises(ValidationError):
            MarkdownReporterConfigOptions(**{option: -1})

    @pytest.mark.parametrize("option", ["max_detailed_findings", "top_hotspots_limit"])
    def test_zero_and_a_positive_value_are_accepted(self, option):
        assert getattr(MarkdownReporterConfigOptions(**{option: 0}), option) == 0
        assert getattr(MarkdownReporterConfigOptions(**{option: 5}), option) == 5
