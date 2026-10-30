# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The HTML report prints scan text as written, and shows what a viewer would act on.

* Source text that holds nothing a viewer acts on is printed as written. A
  snippet or description with a code sample's ``\\x41`` in it used to print
  ``\\\\x41``, a character the source does not hold.
* The hotspot table prints a path as the finding card does, so a Windows path
  with a ``\\x64`` segment is the same text in both.
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


def test_a_hotspot_prints_a_windows_path_as_the_card_does(test_plugin_context):
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

    hotspot_locations = re.findall(r"<td>\d+</td>\s*<td>(.*?)</td>", document)
    # The control: the hotspot table is there at all.
    assert hotspot_locations, "no hotspot row was rendered"
    assert hotspot_locations == [WINDOWS_PATH], hotspot_locations
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
