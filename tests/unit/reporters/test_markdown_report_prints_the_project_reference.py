# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Markdown report prints a project name's written reference as written.

The configuration records a project name read from the environment as the
reference it was written as, ``${NAME}``, and every report is meant to show that
reference rather than the value. The Markdown report escapes ``{`` and ``}``
along with the Markdown syntax characters, so the project line read
``$\\{NAME\\}``, which is not what the file says. Only the project line keeps the
braces; every other line still escapes them.
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
ESCAPED = "$\\{ZZ_PROJECT_REFERENCE\\}"


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
        assert _reference_text(REFERENCE) == REFERENCE

    def test_every_other_character_is_still_escaped(self):
        assert _reference_text("a_b *c* ${X}") == "a\\_b \\*c\\* ${X}"
        assert _reference_text("<x> & [y]") == "&lt;x&gt; &amp; \\[y\\]"

    def test_a_mention_and_a_url_are_still_put_in_a_code_span(self):
        assert _reference_text("@octocat ${X}") == "`@octocat` ${X}"
        assert _reference_text("https://example.com/a ${X}") == (
            "`https://example.com/a` ${X}"
        )

    def test_braces_stay_escaped_for_every_other_line(self):
        # The control: only the project line is a reference.
        assert _text(REFERENCE) == ESCAPED
        assert _text("{a}") == "\\{a\\}"


class TestTheReportPrintsTheReference:
    def test_the_summary_report_prints_the_reference_as_written(
        self, test_plugin_context
    ):
        document = _report(test_plugin_context, _model(REFERENCE))

        assert REFERENCE in document
        assert ESCAPED not in document

    def test_the_report_without_a_summary_never_prints_the_escaped_form(
        self, test_plugin_context
    ):
        document = _report(
            test_plugin_context, _model(REFERENCE), include_summary=False
        )

        assert ESCAPED not in document

    def test_a_name_with_markdown_characters_is_still_escaped(
        self, test_plugin_context
    ):
        document = _report(test_plugin_context, _model("a_b ${ZZ_NAME}"))

        assert "a\\_b ${ZZ_NAME}" in document
