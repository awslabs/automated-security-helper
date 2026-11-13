# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The JQ query for a result's own field, and for a key named like a log array.

``properties`` is a key of the SARIF document and of a result, so a result-relative
path that starts with it (``properties.issue_confidence``, the form the validation
reports) became a query on the document's properties and found nothing. A bare
``runs`` or ``results`` key was read as an array at any depth, so
``properties.results.total`` became ``any(.properties.results[]; ...)``, which
jq refuses when ``properties.results`` is an object.
"""

import html as html_module

import pytest

from automated_security_helper.utils.meta_analysis.reporting import (
    generate_html_report,
    generate_jq_query,
)

pytestmark = pytest.mark.unit


def test_a_path_the_caller_says_is_a_results_own_is_read_under_the_results():
    assert generate_jq_query("properties.issue_confidence", result_relative=True) == (
        ".runs[].results[] | select(.properties.issue_confidence != null)"
    )
    assert generate_jq_query("message.text", result_relative=True) == (
        ".runs[].results[] | select(.message.text != null)"
    )
    # Arrays below the result are still tested with any().
    assert generate_jq_query("locations[0].physicalLocation", result_relative=True) == (
        ".runs[].results[] | select(any(.locations[]; .physicalLocation != null))"
    )


def test_without_the_flag_a_leading_properties_is_still_the_documents():
    """The default is unchanged: the caller has to say a path is a result's."""
    assert generate_jq_query("properties.issue_confidence") == (
        '. | select(has("properties")) | select(.properties.issue_confidence != null)'
    )


@pytest.mark.parametrize(
    "path, expected",
    [
        (
            "runs[0].results[0].properties.results.total",
            ".runs[].results[] | select(.properties.results.total != null)",
        ),
        (
            "runs[].results[].properties.runs.name",
            ".runs[].results[] | select(.properties.runs.name != null)",
        ),
        (
            "runs[].results[].message.results.x",
            ".runs[].results[] | select(.message.results.x != null)",
        ),
    ],
)
def test_a_key_named_runs_or_results_deeper_down_is_not_an_array(path, expected):
    assert generate_jq_query(path) == expected


@pytest.mark.parametrize(
    "path, expected",
    [
        ("runs.tool.driver.name", ".runs[] | select(.tool.driver.name != null)"),
        ("runs.results.ruleId", ".runs[].results[] | select(.ruleId != null)"),
        ("runs[0].results.ruleId", ".runs[].results[] | select(.ruleId != null)"),
        ("runs.results[0].ruleId", ".runs[].results[] | select(.ruleId != null)"),
    ],
)
def test_a_bare_runs_or_results_key_in_the_log_is_still_its_array(path, expected):
    assert generate_jq_query(path) == expected


def test_the_html_report_reads_a_validation_path_as_a_results_own(tmp_path):
    validation = {
        "missing_fields": {
            "bandit": {
                "critical": [],
                "important": [],
                "informational": [
                    {
                        "path": "properties.issue_confidence",
                        "original_value": "HIGH",
                        "importance": "informational",
                    }
                ],
            }
        },
        "match_statistics": {},
        "summary": {
            "total_findings": 1,
            "matched_findings": 1,
            "critical_missing_fields": 0,
            "important_missing_fields": 0,
            "informational_missing_fields": 1,
        },
    }

    report = tmp_path / "report.html"
    generate_html_report(validation, str(report), {})
    page = html_module.unescape(report.read_text(encoding="utf-8"))

    assert ".runs[].results[] | select(.properties.issue_confidence != null)" in page
    assert 'select(has("properties"))' not in page
