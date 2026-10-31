# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A coverage shortfall of unknown size renders, in every human report.

``coverage_shortfalls`` yields ``(scanner, None, None)`` for a scanner whose
stored target counters could not be read: the scanner made a coverage claim
nobody can read, so dropping it would complete the scan on its behalf. The
HTML, Markdown and text reporters each wrote the row as
``attempted - failed`` inline, so that one entry raised TypeError and the whole
document was lost, for the scanner whose coverage most needed stating.

Each report now writes the row through one renderer, which says the coverage
is unknown. The control row, with real counts, keeps its numbers.
"""

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    coverage_shortfall_text,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
)

pytestmark = pytest.mark.unit

REPORTERS = {
    "html": HtmlReporter,
    "markdown": MarkdownReporter,
    "text": TextReporter,
}


def _report(status: str, **counters) -> dict:
    return {"scanner_name": "cdk-nag", "status": status, "duration": 1.0, **counters}


def _model(reports: dict) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.additional_reports = reports
    return model


#: A failure count beside no attempt count: a claim the reader cannot trust, so
#: the counters are unusable and the shortfall has no size.
UNUSABLE = {"cdk-nag": {"source": _report("PASSED", targets_failed=2)}}

#: Two of three targets lost: the ordinary shortfall, with its numbers.
PARTIAL = {
    "cdk-nag": {"source": _report("PASSED", targets_attempted=3, targets_failed=2)}
}


class TestTheSharedRenderer:
    def test_unknown_counters_say_so(self):
        text = coverage_shortfall_text(None, None)
        assert "coverage unknown" in text
        assert "None" not in text

    def test_real_counters_keep_their_numbers(self):
        assert coverage_shortfall_text(3, 2) == (
            "evaluated 1 of 3 target(s); 2 could not be evaluated"
        )


@pytest.mark.parametrize("name", sorted(REPORTERS))
def test_a_shortfall_of_unknown_size_does_not_lose_the_report(
    name, test_plugin_context
):
    """At the base each reporter raised TypeError on ``None - None`` here."""
    document = REPORTERS[name](context=test_plugin_context).report(_model(UNUSABLE))

    assert "cdk-nag" in document
    assert "coverage unknown" in document
    # Around every place the phrase is written, not after the first mention of
    # the scanner: that is its row in the scanner table, which comes before the
    # shortfall, so a window there would miss a "None" printed lower down.
    start = 0
    while (index := document.find("coverage unknown", start)) != -1:
        around = document[max(index - 60, 0) : index + 60]
        assert "None" not in around, around
        start = index + 1


@pytest.mark.parametrize("name", sorted(REPORTERS))
def test_a_sized_shortfall_still_states_its_counts(name, test_plugin_context):
    """The control: the renderer did not replace every row with 'unknown'."""
    document = REPORTERS[name](context=test_plugin_context).report(_model(PARTIAL))

    assert "evaluated 1 of 3 target(s); 2 could not be evaluated" in document
    assert "coverage unknown" not in document
