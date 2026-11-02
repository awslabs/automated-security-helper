# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The reports' key to the scanner Result column says what SKIPPED means.

A scanner is SKIPPED when it did not run: it was disabled, or it found nothing to
scan. The key in the HTML, Markdown and text reports said "disabled" only, which
reads a scanner with nothing to scan as one somebody turned off.
"""

import pytest

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
)
from automated_security_helper.schemas.sarif_schema_model import Result

pytestmark = pytest.mark.unit

MEANING = "did not run (disabled, or nothing to scan)"


def _model() -> AshAggregatedResults:
    model = AshAggregatedResults(ash_config=get_default_config())
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
    model.additional_reports["bandit"] = {
        "source": {"scanner_name": "bandit", "status": "FAILED", "duration": 1.0}
    }
    model._flat_cache = None
    return model


@pytest.mark.parametrize(
    "reporter", [HtmlReporter, MarkdownReporter, TextReporter], ids=lambda r: r.__name__
)
def test_the_key_says_what_skipped_means(reporter, test_plugin_context):
    document = reporter(context=test_plugin_context).report(_model())

    assert MEANING in document
    assert "SKIPPED is disabled" not in document
    assert "SKIPPED = disabled" not in document
    assert "</strong> is disabled" not in document
