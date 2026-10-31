# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner with no matched result has no field preservation rate, not a rate of 0.

``field_preservation_rate`` is the share of the compared fields of the matched
results that the aggregate preserved. For a scanner none of whose results matched,
no field was compared; the key stayed at its initial 0, which reads as "every
field was lost" where the aggregate was never compared with anything. It is None
there, and the HTML report shows ``n/a`` for a rate it cannot give.
"""

import html as html_module

import pytest

from automated_security_helper.utils.meta_analysis.reporting import (
    generate_html_report,
)
from automated_security_helper.utils.meta_analysis.sarif_analysis import (
    validate_sarif_aggregation,
)

pytestmark = pytest.mark.unit


def _result(line):
    return {
        "ruleId": "B101",
        "message": {"text": "finding"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "a.py"},
                    "region": {"startLine": line, "endLine": line},
                }
            }
        ],
    }


def _report(*results):
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "t"}}, "results": list(results)}],
    }


def test_a_scanner_with_no_matched_result_has_no_preservation_rate():
    stats = validate_sarif_aggregation({"bandit": _report(_result(3))}, _report())[
        "match_statistics"
    ]["bandit"]

    assert stats["matched_results"] == 0
    assert stats["match_rate"] == 0.0
    assert stats["fields_compared"] == 0
    assert stats["field_preservation_rate"] is None


def test_a_scanner_with_a_matched_result_has_a_rate():
    """The control: with fields compared the rate is a number, as before."""
    stats = validate_sarif_aggregation(
        {"bandit": _report(_result(3))}, _report(_result(3))
    )["match_statistics"]["bandit"]

    assert stats["field_preservation_rate"] == 1.0


def _page(tmp_path, stats):
    results = {
        "missing_fields": {
            "bandit": {"critical": [], "important": [], "informational": []}
        },
        "match_statistics": {"bandit": stats},
        "summary": {
            "total_findings": 1,
            "matched_findings": 0,
            "critical_missing_fields": 0,
            "important_missing_fields": 0,
            "informational_missing_fields": 0,
        },
    }
    report = tmp_path / "report.html"
    generate_html_report(results, str(report), {})
    return html_module.unescape(report.read_text(encoding="utf-8"))


def test_the_html_report_shows_n_a_for_a_rate_it_cannot_give(tmp_path):
    page = _page(
        tmp_path,
        {
            "matched_results": 0,
            "total_results": 1,
            "field_preservation_rate": None,
        },
    )

    # The scanner header and the results table both.
    assert "Match Rate: 0/1 (n/a)" in page
    assert "<td>n/a</td>" in page
    assert "None" not in page.split("<h2>Scanner Results</h2>")[-1].split("</table>")[0]


def test_the_html_report_shows_a_given_rate(tmp_path):
    page = _page(
        tmp_path,
        {"matched_results": 1, "total_results": 4, "match_rate": 0.25},
    )

    assert "Match Rate: 1/4 (25.00%)" in page
    assert "<td>25.00%</td>" in page
