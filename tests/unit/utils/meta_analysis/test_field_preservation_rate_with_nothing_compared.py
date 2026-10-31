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


def _rendered(tmp_path, original_reports, aggregated):
    """The page ``generate_html_report`` writes for what
    ``validate_sarif_aggregation`` returns, not for statistics written by hand."""
    results = validate_sarif_aggregation(original_reports, aggregated)
    report = tmp_path / "report.html"
    generate_html_report(results, str(report), {})
    return html_module.unescape(report.read_text(encoding="utf-8"))


def _scanner_table(page):
    return page.split("<h2>Scanner Results</h2>")[-1].split("</table>")[0]


def test_the_page_for_a_scanner_with_no_matched_result_shows_its_known_zero(tmp_path):
    """Real output always carries ``match_rate``, so a scanner none of whose
    results matched has a known 0%: the page says so and never ``n/a``."""
    page = _rendered(tmp_path, {"bandit": _report(_result(3))}, _report())

    table = _scanner_table(page)
    assert "Match Rate: 0/1 (0.00%)" in page
    assert "<td>0/1</td>" in table
    assert "<td>0.00%</td>" in table
    assert "n/a" not in table
    assert "None" not in table


def test_the_page_for_a_scanner_with_nothing_to_match_shows_zero_of_zero(tmp_path):
    """A scanner whose report holds no result at all. Its statistics are the
    initial ones: ``match_rate`` 0 with 0 of 0 matched, and no preservation rate.
    The page prints what real output holds (0.00%), so a change to ``n/a`` for
    this case is a decision made on purpose and not a drift."""
    stats = validate_sarif_aggregation({"bandit": _report()}, _report(_result(3)))[
        "match_statistics"
    ]["bandit"]
    assert stats["total_results"] == 0
    assert stats["match_rate"] == 0
    assert stats["field_preservation_rate"] is None

    page = _rendered(tmp_path, {"bandit": _report()}, _report(_result(3)))

    table = _scanner_table(page)
    assert "Match Rate: 0/0 (0.00%)" in page
    assert "<td>0/0</td>" in table
    assert "n/a" not in table
    assert "None" not in table


def test_the_page_for_a_scanner_whose_every_result_matched_shows_all_of_them(tmp_path):
    page = _rendered(tmp_path, {"bandit": _report(_result(3))}, _report(_result(3)))

    assert "Match Rate: 1/1 (100.00%)" in page
    assert "<td>100.00%</td>" in _scanner_table(page)


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
    """Statistics written by hand, as an older caller wrote them: without a
    ``match_rate`` the report falls back to ``field_preservation_rate`` and shows
    ``n/a`` when that is None. Real output never omits ``match_rate`` (see the
    tests above), so this is the contract for a caller that does."""
    page = _page(
        tmp_path,
        {
            "matched_results": 0,
            "total_results": 1,
            "field_preservation_rate": None,
        },
    )

    # The scanner header and the results table both.
    # "0/1 (n/a)" still said that none of one matched, where nothing was compared;
    # the counts stay in the table beside it.
    assert "Match Rate: n/a<" in page
    assert "Match Rate: 0/1" not in page
    assert "<td>0/1</td>" in page
    assert "<td>n/a</td>" in page
    assert "None" not in page.split("<h2>Scanner Results</h2>")[-1].split("</table>")[0]


def test_the_html_report_shows_a_given_rate(tmp_path):
    page = _page(
        tmp_path,
        {"matched_results": 1, "total_results": 4, "match_rate": 0.25},
    )

    assert "Match Rate: 1/4 (25.00%)" in page
    assert "<td>25.00%</td>" in page
