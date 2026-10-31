# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Markdown report prints a project name's written reference as written.

The configuration records a project name read from the environment as the
reference it was written as, ``${NAME}``, and every report is meant to show that
reference rather than the value. The Markdown report escapes ``{``, ``}`` and
``_`` along with the other Markdown syntax characters, so the project line read
``$\\{MY\\_NAME\\}``, which is not what the file says. Only a ``${NAME}`` reference
in the project line is written as it is, in a code span, because bare it read as
emphasis (``${_X_}``) or as math (``${ORG}/${REPO}``); every other character in
the line, and every other line, is still escaped.
"""

import pytest

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
    MarkdownReporterConfig,
    MarkdownReporterConfigOptions,
    _reference_text,
    _text,
)
from automated_security_helper.schemas.sarif_schema_model import Result

pytestmark = pytest.mark.unit

REFERENCE = "${ZZ_PROJECT_REFERENCE}"
ESCAPED = "\\$\\{ZZ\\_PROJECT\\_REFERENCE\\}"


def _model(project_name: str) -> AshAggregatedResults:
    model = AshAggregatedResults(ash_config=get_default_config())
    model.metadata.project_name = project_name
    model.sarif.runs[0].results = [
        Result.model_validate(
            {
                "ruleId": "R1",
                "level": "error",
                "message": {"text": "fixture"},
                "properties": {"scanner_name": "bandit"},
            }
        )
    ]
    model._flat_cache = None
    return model


def _report(test_plugin_context, model, **options) -> str:
    return MarkdownReporter(
        context=test_plugin_context,
        config=MarkdownReporterConfig(options=MarkdownReporterConfigOptions(**options)),
    ).report(model)


class TestTheReferenceHelper:
    def test_a_written_reference_keeps_its_braces(self):
        assert _reference_text(REFERENCE) == f"`{REFERENCE}`"

    def test_a_reference_is_not_read_as_emphasis_or_math(self):
        """Bare, ``${_X_}`` read as emphasis, and ``${ORG}/${REPO}`` as a
        formula between its two dollar signs."""
        assert _reference_text("${_X_}") == "`${_X_}`"
        assert _reference_text("${ORG}/${REPO}") == "`${ORG}`/`${REPO}`"

    def test_a_reference_beside_another_dollar_sign_is_still_one_code_span(self):
        """A bare ``$`` outside a reference is escaped, as in any other text."""
        assert _reference_text("${ORG}-$HOME") == "`${ORG}`-\\$HOME"
        assert _reference_text("$HOME-${ORG}") == "\\$HOME-`${ORG}`"

    def test_every_other_character_is_still_escaped(self):
        assert _reference_text("a_b *c* ${X}") == "a\\_b \\*c\\* `${X}`"
        assert _reference_text("<x> & [y]") == "&lt;x&gt; &amp; \\[y\\]"

    def test_a_mention_and_a_url_are_still_put_in_a_code_span(self):
        assert _reference_text("@octocat ${X}") == "`@octocat` `${X}`"
        assert _reference_text("https://example.com/a ${X}") == (
            "`https://example.com/a` `${X}`"
        )

    def test_references_that_touch_are_one_code_span(self):
        """Two spans back to back end and open with a run of backticks, which
        Markdown reads as part of one longer span, so the reader saw them."""
        assert _reference_text("${A}${B}") == "`${A}${B}`"
        assert _reference_text("${A}${B}${C}") == "`${A}${B}${C}`"
        assert _reference_text("@octocat${X}") == "`@octocat${X}`"
        assert _reference_text("https://example.com/${X}") == (
            "`https://example.com/${X}`"
        )

    def test_pieces_with_text_between_them_stay_apart(self):
        # The control: only pieces that touch share a span.
        assert _reference_text("${A} ${B}") == "`${A}` `${B}`"
        assert "``" not in _reference_text("${A}/${B} ${C}${D}")

    def test_a_dollar_sign_outside_a_reference_is_escaped(self):
        """GitHub reads a pair of dollar signs as a formula, so any ``$`` that is
        not part of a written reference gets a backslash, and a reference is
        still one unescaped code span."""
        assert _text("cost $5 and $6") == "cost \\$5 and \\$6"
        assert _reference_text("cost $5 and $6 ${X}") == "cost \\$5 and \\$6 `${X}`"

    def test_braces_stay_escaped_for_every_other_line(self):
        # The control: only the project line is a reference.
        assert _text(REFERENCE) == ESCAPED
        assert _text("{a}") == "\\{a\\}"


class TestTheReportPrintsTheReference:
    def test_the_summary_report_prints_the_reference_as_written(
        self, test_plugin_context
    ):
        document = _report(test_plugin_context, _model(REFERENCE))

        assert f"`{REFERENCE}`" in document
        assert ESCAPED not in document

    def test_the_report_without_a_summary_never_prints_the_escaped_form(
        self, test_plugin_context
    ):
        document = _report(
            test_plugin_context, _model(REFERENCE), include_summary=False
        )

        assert ESCAPED not in document

    def test_two_touching_references_print_as_one_code_span(self, test_plugin_context):
        document = _report(test_plugin_context, _model("${ZZ_ORG}${ZZ_REPO}"))

        assert "`${ZZ_ORG}${ZZ_REPO}`" in document
        assert "`${ZZ_ORG}``${ZZ_REPO}`" not in document

    def test_a_name_with_markdown_characters_is_still_escaped(
        self, test_plugin_context
    ):
        document = _report(test_plugin_context, _model("a_b ${ZZ_NAME}"))

        assert "a\\_b `${ZZ_NAME}`" in document
