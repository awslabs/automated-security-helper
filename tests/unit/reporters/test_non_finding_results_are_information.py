# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A result that states no finding is listed as information and counted nowhere.

A SARIF result whose ``kind`` is ``pass``, ``notApplicable`` or ``informational``
states no finding (SARIF 3.27.9). The note ASH writes when nothing scanned a
container image is one. The reports listed it and graded it like a finding: at the
``ALL`` threshold it was an actionable card, a row of the findings overview, a line
of the detailed findings and a count in the headline.

The CSV and flat JSON reports now keep its row and name its kind in ``result_kind``.
The HTML, Markdown and text reports list it under Information: never as a card,
never in the findings overview, never in a total.

The model is one bandit result and the note, graded at ``ALL``, the threshold at
which the note reaches the gate; at the default threshold it is below it either way.
"""

import csv
import io
import json

import pytest

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
    CsvReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
    FlatJSONReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
    MarkdownReporterConfig,
    MarkdownReporterConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
    TextReporterConfig,
    TextReporterConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from tests.utils.scanner_thresholds import without_scanner_thresholds

pytestmark = pytest.mark.unit

NOTE = "ASH-container-image-not-scanned"


def _model(
    *, scanner_rows: bool = True, with_note: bool = True
) -> AshAggregatedResults:
    """One bandit result, and the note ASH writes when nothing scanned an image.

    With *scanner_rows* the model has a bandit row, as a scan has; without it the
    model has no scanner rows, as imported SARIF has.
    """
    bandit = {
        "ruleId": "B602",
        "level": "error",
        "message": {"text": "subprocess call with shell=True"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py"},
                    "region": {"startLine": 3},
                }
            }
        ],
    }
    if scanner_rows:
        bandit["properties"] = {"scanner_name": "bandit"}
    results = [bandit]
    if with_note:
        results.append(
            {
                "ruleId": NOTE,
                "kind": "informational",
                "level": "none",
                "message": {"text": "container image example:1 was not scanned"},
            }
        )
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    without_scanner_thresholds(model)
    model.ash_config.global_settings.severity_threshold = "ALL"
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "bandit"}}, "results": results}],
        }
    )
    if scanner_rows:
        model.additional_reports["bandit"] = {
            "source": {"scanner_name": "bandit", "status": "PASSED", "duration": 1.0}
        }
    return model


def _emitter(**options) -> ReportContentEmitter:
    return ReportContentEmitter(_model(**options), human_presentation=True)


def _by_rule(emitter: ReportContentEmitter) -> dict:
    return {vuln.rule_id: vuln for vuln in emitter.flat_vulns}


# --- CSV and flat JSON ----------------------------------------------------------


def test_the_csv_report_keeps_the_row_and_names_its_kind(test_plugin_context):
    text = CsvReporter(context=test_plugin_context).report(_model())

    rows = list(csv.DictReader(io.StringIO(text)))

    assert [(row["rule_id"], row.get("result_kind")) for row in rows] == [
        ("B602", "fail"),
        (NOTE, "informational"),
    ]


def test_the_csv_column_follows_every_older_column(test_plugin_context):
    text = CsvReporter(context=test_plugin_context).report(_model())

    header = next(csv.reader(io.StringIO(text)))

    assert header[-2:] == ["correlation_id", "result_kind"]


def test_the_csv_header_of_a_report_with_no_findings_ends_the_same_way(
    test_plugin_context,
):
    text = CsvReporter(context=test_plugin_context).report(AshAggregatedResults())

    header = next(csv.reader(io.StringIO(text)))

    assert header[-2:] == ["correlation_id", "result_kind"]


def test_the_flat_json_report_keeps_both_findings_and_names_the_kind(
    test_plugin_context,
):
    text = FlatJSONReporter(context=test_plugin_context).report(_model())

    findings = json.loads(text)["findings"]

    assert [(row["rule_id"], row.get("result_kind")) for row in findings] == [
        ("B602", "fail"),
        (NOTE, "informational"),
    ]


# --- the emitter ----------------------------------------------------------------


def test_the_note_has_a_disposition_of_its_own():
    emitter = _emitter()
    rows = _by_rule(emitter)

    assert emitter.disposition(rows["B602"]).value == "actionable"
    assert emitter.disposition(rows[NOTE]).value == "information"


def test_the_note_is_not_actionable_even_where_everything_else_is():
    emitter = _emitter()
    rows = _by_rule(emitter)

    assert emitter.is_finding_actionable(rows["B602"])
    assert not emitter.is_finding_actionable(rows[NOTE])


def test_the_findings_overview_leaves_the_note_out():
    overview = _emitter().get_findings_overview()

    assert [row["rule_id"] for row in overview] == ["B602"]


def test_the_information_overview_lists_the_note_alone():
    overview = _emitter().get_information_overview()

    assert [row["rule_id"] for row in overview] == [NOTE]


def test_the_detailed_findings_and_their_count_leave_the_note_out():
    emitter = _emitter()

    assert [row["rule_id"] for row in emitter.get_detailed_findings()] == ["B602"]
    assert emitter.actionable_finding_count() == 1


def test_a_summary_with_no_scanner_rows_counts_the_note_nowhere():
    summary = _emitter(scanner_rows=False).get_scan_summary()

    assert summary["actionable"] == 1
    assert summary["counts"]["info"] == 0


# --- HTML -----------------------------------------------------------------------


def test_the_html_report_has_one_card_for_the_one_finding(test_plugin_context):
    document = HtmlReporter(context=test_plugin_context).report(_model())

    assert document.count('<article class="finding-card"') == 1
    assert 'data-status="information"' not in document


def test_the_html_report_lists_the_note_in_a_section_of_its_own(test_plugin_context):
    document = HtmlReporter(context=test_plugin_context).report(_model())

    assert 'id="information"' in document
    assert document.index('id="findings"') < document.index('id="information"')
    section = document.split('id="information"', 1)[1].split("</section>", 1)[0]
    assert NOTE in section
    assert "B602" not in section


def test_the_html_finding_count_is_the_cards_it_holds():
    emitter = _emitter()

    assert HtmlReporter._shown_finding_count(emitter) == 1


def test_a_report_with_no_such_result_has_no_information_section(test_plugin_context):
    """Control, green before and after: the page is the one it always was."""
    document = HtmlReporter(context=test_plugin_context).report(_model(with_note=False))

    assert 'id="information"' not in document
    assert document.count('<article class="finding-card"') == 1


# --- Markdown and text ----------------------------------------------------------


def _markdown(context, model) -> str:
    options = MarkdownReporterConfigOptions(
        include_findings_table=True, include_detailed_findings=True
    )
    reporter = MarkdownReporter(
        context=context, config=MarkdownReporterConfig(options=options)
    )
    return reporter.report(model)


def _text(context, model) -> str:
    options = TextReporterConfigOptions(
        include_findings_table=True, include_detailed_findings=True
    )
    return TextReporter(
        context=context, config=TextReporterConfig(options=options)
    ).report(model)


def test_the_markdown_report_lists_the_note_after_the_overview_and_not_in_it(
    test_plugin_context,
):
    text = _markdown(test_plugin_context, _model())

    assert "## Information" in text
    overview_at = text.index("## Findings overview")
    information_at = text.index("## Information")
    assert overview_at < information_at
    overview = text[overview_at:information_at]
    assert "B602" in overview
    assert NOTE not in overview
    assert NOTE in text[information_at:]


def test_the_markdown_report_counts_the_note_in_no_total(test_plugin_context):
    text = _markdown(test_plugin_context, _model())

    assert "Showing 1 of 1 actionable findings" in text


def test_the_text_report_lists_the_note_after_the_overview_and_not_in_it(
    test_plugin_context,
):
    text = _text(test_plugin_context, _model())

    heading = "\nINFORMATION\n-----------\n"
    assert heading in text
    overview_at = text.index("FINDINGS OVERVIEW")
    information_at = text.index(heading)
    assert overview_at < information_at
    # The text table cuts a rule id to the 15 characters of its column.
    cut = NOTE[:15]
    overview = text[overview_at:information_at]
    assert "B602" in overview
    assert cut not in overview
    assert cut in text[information_at:]


# --- a result that contradicts its kind ----------------------------------------


def _single_model(
    kind: str, level: str, *, threshold: str, scanner: str | None = None
) -> AshAggregatedResults:
    """One result of *kind* at *level*, under *threshold*, and nothing else."""
    result = {
        "ruleId": "R-ONE",
        "kind": kind,
        "level": level,
        "message": {"text": "the one result"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py"},
                    "region": {"startLine": 3},
                }
            }
        ],
    }
    if scanner:
        result["properties"] = {"scanner_name": scanner}
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    without_scanner_thresholds(model)
    model.ash_config.global_settings.severity_threshold = threshold
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "bandit"}}, "results": [result]}],
        }
    )
    if scanner:
        model.additional_reports[scanner] = {
            "source": {"scanner_name": scanner, "status": "PASSED", "duration": 1.0}
        }
    return model


@pytest.mark.parametrize("kind", ["pass", "notApplicable", "informational"])
def test_a_result_whose_level_reports_a_problem_is_a_card_and_not_information(
    test_plugin_context, kind
):
    """A result that contradicts its kind is a finding: at MEDIUM the page holds a
    card for it, the information rows leave it out and the actionable count is 1."""
    model = _single_model(kind, "warning", threshold="MEDIUM")
    emitter = ReportContentEmitter(model, human_presentation=True)

    document = HtmlReporter(context=test_plugin_context).report(model)

    assert document.count('<article class="finding-card"') == 1
    assert emitter.get_information_overview() == []
    assert emitter.actionable_finding_count() == 1


@pytest.mark.parametrize("kind", ["pass", "notApplicable", "informational"])
def test_a_scanner_named_note_is_counted_in_no_scanner_row_total(kind):
    """Guard: a result that states no finding and names its scanner is in no
    figure of that scanner's row, so the summary's info and actionable figures
    stay 0 at ALL."""
    model = _single_model(kind, "none", threshold="ALL", scanner="bandit")

    summary = ReportContentEmitter(model, human_presentation=True).get_scan_summary()

    assert summary["actionable"] == 0
    assert summary["counts"]["info"] == 0
