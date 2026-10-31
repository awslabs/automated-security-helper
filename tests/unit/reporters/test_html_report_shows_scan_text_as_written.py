# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The HTML report prints scan text as written, and shows what a viewer would act on.

* Source text that holds nothing a viewer acts on is printed as written. A
  snippet or description with a code sample's ``\\x41`` in it used to print
  ``\\\\x41``, a character the source does not hold.
* The hotspot table shows a path on one line with the backslash of text that
  reads as an escape doubled, so a name the record writes as an escape cannot be
  taken for the escape itself. The finding card's code element and copy
  attribute keep the path as recorded.
* An additional report's severity is the results file's text, so the pill shows
  it as one line.
* A finding with a line number and no file is located nowhere; it does not read
  ``N/A:12``.
* No scanner's filter value is empty, because the "All scanners" entry is the
  empty value: an unnamed scanner is listed as ``unknown``.
* The masthead's unavailable figure is the summary's own count.
"""

import re

import pytest

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)
from automated_security_helper.schemas.sarif_schema_model import Result

pytestmark = pytest.mark.unit

WINDOWS_PATH = "C:\\build\\x64\\app.py"


def _result(**overrides) -> Result:
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
    return Result.model_validate(body)


def _render(test_plugin_context, results, additional_reports=None) -> str:
    model = AshAggregatedResults(ash_config=get_default_config())
    model.sarif.runs[0].results = results
    if additional_reports:
        model.additional_reports = additional_reports
    model._flat_cache = None
    return HtmlReporter(context=test_plugin_context).report(model)


def test_source_text_holding_an_escape_reading_is_printed_as_written(
    test_plugin_context,
):
    document = _render(
        test_plugin_context,
        [
            _result(
                message={"text": "Use '\\x41' not '\\x42' here"},
                locations=[
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/app.py"},
                            "region": {
                                "startLine": 3,
                                "snippet": {"text": 'path = "C:\\x64\\app"'},
                            },
                        }
                    }
                ],
            )
        ],
    )

    assert "Use &#x27;\\x41&#x27; not &#x27;\\x42&#x27; here" in document
    assert "path = &quot;C:\\x64\\app&quot;" in document
    assert "\\\\x41" not in document
    assert "\\\\x64" not in document


def test_snippet_text_with_a_control_is_still_shown_not_obeyed(test_plugin_context):
    document = _render(
        test_plugin_context,
        [
            _result(
                locations=[
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/app.py"},
                            "region": {
                                "startLine": 3,
                                "snippet": {"text": "ok\x1b[2Jgone"},
                            },
                        }
                    }
                ],
            )
        ],
    )

    assert "\x1b" not in document
    assert "ok\\x1b[2Jgone" in document


def test_a_hotspot_shows_a_windows_path_on_one_line_and_the_card_keeps_it(
    test_plugin_context,
):
    document = _render(
        test_plugin_context,
        [
            _result(
                locations=[
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": WINDOWS_PATH},
                            "region": {"startLine": 3},
                        }
                    }
                ],
            )
        ],
    )

    # Read the hotspot table alone: the scanner table above it also holds
    # numeric cells in a row, which the row pattern would take for locations.
    section = re.search(r'<div class="hotspots">.*?</table>', document, re.DOTALL)
    # The control: the hotspot table is there at all.
    assert section, "no hotspot table was rendered"
    hotspot_locations = re.findall(r"<td>\d+</td>\s*<td>(.*?)</td>", section.group())
    assert hotspot_locations, "no hotspot row was rendered"
    # The table doubles the backslash that starts an escape-like segment (the
    # "\x64" of "x64"); the copy attribute keeps the path as recorded.
    assert len(hotspot_locations) == 1, hotspot_locations
    assert "\\\\x64" in hotspot_locations[0], hotspot_locations
    assert f'data-copy-location="{WINDOWS_PATH}:3"' in document


def test_a_line_number_without_a_file_is_not_a_location(test_plugin_context):
    document = _render(
        test_plugin_context,
        [],
        additional_reports={
            "custom-plugin": [
                {
                    "title": "No file",
                    "description": "A finding with a line and no file.",
                    "severity": "HIGH",
                    "line_start": 12,
                }
            ]
        },
    )

    assert "N/A:12" not in document
    assert "N/A" in document


def test_an_additional_reports_severity_is_one_shown_line(test_plugin_context):
    document = _render(
        test_plugin_context,
        [],
        additional_reports={
            "custom-plugin": [
                {
                    "title": "Odd severity",
                    "description": "d",
                    "severity": "HIGH\x1b[31m\nINJECTED",
                    "file_path": "app.py",
                    "line_start": 3,
                }
            ]
        },
    )

    pills = re.findall(r'<span class="pill severity-[^"]*">(.*?)</span>', document)
    assert pills, "no severity pill was rendered"
    for pill in pills:
        assert "\x1b" not in pill, repr(pill)
        assert "\n" not in pill, repr(pill)


def test_an_unnamed_scanner_is_listed_as_unknown_not_as_the_empty_value(
    test_plugin_context,
):
    document = _render(
        test_plugin_context,
        [_result(properties={"scanner_name": ""})],
    )

    values = re.findall(r'<option value="([^"]*)">', document)
    # "All scanners" is the one entry with the empty value (the control).
    assert values.count("") == 1, values
    assert "unknown" in values, values


def test_the_masthead_unavailable_figure_is_the_summarys_count(
    test_plugin_context, monkeypatch
):
    original = ReportContentEmitter.get_scan_summary

    def with_a_count(self, *args, **kwargs):
        summary = original(self, *args, **kwargs)
        summary["unavailable"] = []
        summary["unavailable_count"] = 7
        return summary

    monkeypatch.setattr(ReportContentEmitter, "get_scan_summary", with_a_count)

    document = _render(test_plugin_context, [_result()])

    assert "7 unavailable" in document


def _snippet_result(text: str) -> Result:
    return _result(
        locations=[
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py"},
                    "region": {"startLine": 3, "snippet": {"text": text}},
                }
            }
        ]
    )


def test_a_block_printed_as_written_carries_no_note(test_plugin_context):
    document = _render(test_plugin_context, [_snippet_result('path = "C:\\x64\\app"')])

    assert 'class="shown-note"' not in document


def test_a_block_that_is_shown_says_so(test_plugin_context):
    """A block with a control in it is shown, not printed as written: its
    backslashes are doubled throughout, so the reader is told, once, beside it.

    RED at the base: nothing in the page said so.
    """
    document = _render(
        test_plugin_context, [_snippet_result('a = "\\x41"\nb = 1\x1b[31m')]
    )

    assert document.count('class="shown-note"') == 1, document.count("shown-note")
    assert "Shown, not as written" in document


def _shown_notes(document: str) -> list:
    return re.findall(r'<p class="shown-note"><small>(.*?)</small></p>', document)


def test_the_note_names_a_broken_command_form_and_not_control_characters(
    test_plugin_context,
):
    """RED at the base: the one fixed note said control characters were written
    as escapes, for a block whose only change is a broken CI command form."""
    document = _render(test_plugin_context, [_snippet_result("::error::injected")])

    (note,) = _shown_notes(document)
    assert "CI command forms are broken" in note, note
    assert "control characters" not in note, note
    assert "backslash" not in note, note


def test_the_note_names_control_characters_when_the_block_holds_them(
    test_plugin_context,
):
    document = _render(test_plugin_context, [_snippet_result("b = 1\x1b[31m")])

    (note,) = _shown_notes(document)
    assert "control characters are written as escapes" in note, note
    assert "CI command forms" not in note, note
    assert "backslash" not in note, note


def test_the_note_names_each_change_a_block_holds(test_plugin_context):
    document = _render(
        test_plugin_context,
        [_snippet_result('::error::x\na = "\\x41"\nb = 1\x1b[31m')],
    )

    (note,) = _shown_notes(document)
    assert "control characters are written as escapes" in note, note
    assert "CI command forms are broken" in note, note
    assert "a backslash before text that reads as an escape is doubled" in note, note


def test_the_note_does_not_say_a_backslash_before_plain_text_is_doubled(
    test_plugin_context,
):
    """A backslash that comes before no escape is shown as it is, so the note
    does not claim it was doubled.

    RED at the base: the note added the doubling clause for any backslash in a
    shown block, so a Windows path beside a command form was said to be doubled
    when nothing in it was.
    """
    document = _render(
        test_plugin_context,
        [_snippet_result("::warning::C:\\Program Files")],
    )

    (note,) = _shown_notes(document)
    assert "CI command forms are broken" in note, note
    assert "backslash" not in note, note
    assert "C:\\Program Files" in document


def test_the_note_for_a_control_does_not_call_a_plain_backslash_doubled(
    test_plugin_context,
):
    """The same, for a block shown because of a control character."""
    document = _render(
        test_plugin_context,
        [_snippet_result("C:\\Program Files\x1b[31m")],
    )

    (note,) = _shown_notes(document)
    assert "control characters are written as escapes" in note, note
    assert "backslash" not in note, note


def test_the_note_for_a_command_form_before_crlf_names_only_the_command_form(
    test_plugin_context,
):
    """A carriage return before a line feed is layout, shown as it is, so a
    block whose one change is a broken command form is not said to hold
    control characters (a pin: the note reads the same at the base).
    """
    document = _render(test_plugin_context, [_snippet_result("::error::x\r\n")])

    (note,) = _shown_notes(document)
    assert "CI command forms are broken" in note, note
    assert "control characters" not in note, note
    assert "backslash" not in note, note


def test_the_note_names_a_doubled_backslash_before_a_written_control(
    test_plugin_context,
):
    """A backslash run before a control is doubled with the control written as
    an escape, so the reader is told (green at the base and at the tip)."""
    document = _render(test_plugin_context, [_snippet_result("a \\\x1b[31m")])

    (note,) = _shown_notes(document)
    assert "control characters are written as escapes" in note, note
    assert "a backslash before text that reads as an escape is doubled" in note, note


def test_one_predicate_takes_the_allowed_layout_as_a_parameter():
    from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
        _is_plain,
    )

    assert _is_plain("one line")
    assert not _is_plain("a\tb")
    assert _is_plain("a\tb", "\t")
    assert _is_plain("a\r\nb", "\n")
    assert not _is_plain("a\rb", "\n")
    assert not _is_plain("::error::x")
