"""Unit tests for generate_field_mapping_html_report.py."""

import pytest

from automated_security_helper.utils.meta_analysis.reporting import (
    generate_html_report,
)

pytestmark = pytest.mark.unit


def test_generate_html_report(tmp_path):
    """Test generate_html_report function."""
    # Create test data with the expected structure
    data = {
        "missing_fields": {
            "test_scanner": {
                "critical": [
                    {
                        "path": "test_field",
                        "importance": "critical",
                        "paths": ["path1", "path2"],
                        "original_value": "test_value",
                    }
                ],
                "important": [],
                "informational": [],
            }
        },
        "match_statistics": {
            "test_scanner": {
                "total_matches": 10,
                "exact_matches": 5,
                "partial_matches": 3,
                "no_matches": 2,
                "matched_results": 8,
                "total_results": 10,
                "field_preservation_rate": 0.8,
                "critical_fields_missing": 1,
                "important_fields_missing": 0,
                "informational_fields_missing": 0,
            }
        },
        "summary": {
            "total_findings": 10,
            "matched_findings": 8,
            "critical_missing_fields": 1,
            "important_missing_fields": 0,
            "informational_missing_fields": 0,
        },
        "fields": [
            {
                "name": "test_field",
                "importance": "critical",
                "paths": ["path1", "path2"],
            }
        ],
    }

    report = tmp_path / "test_report.html"

    result = generate_html_report(data, str(report))

    # Should return None (writes to file)
    assert result is None

    # The report is written there, as HTML naming the scanner
    html = report.read_text(encoding="utf-8")
    assert html.rstrip().endswith("</html>")
    assert "test_scanner" in html


def _results_for(scanner: str, path: str, value) -> dict:
    return {
        "missing_fields": {
            scanner: {
                "critical": [
                    {"path": path, "importance": "critical", "original_value": value}
                ],
                "important": [],
                "informational": [],
            }
        },
        "match_statistics": {
            scanner: {
                "matched_results": 1,
                "total_results": 1,
                "field_preservation_rate": 1.0,
                "critical_fields_missing": 1,
                "important_fields_missing": 0,
                "informational_fields_missing": 0,
            }
        },
        "summary": {
            "total_findings": 1,
            "matched_findings": 1,
            "critical_missing_fields": 1,
            "important_missing_fields": 0,
            "informational_missing_fields": 0,
        },
    }


def test_markup_in_scanner_names_paths_and_values_is_escaped(tmp_path):
    """A scanner directory name or a SARIF key is data the report shows, not
    markup it executes."""
    scanner = "bad<script>alert(1)</script>"
    path = "runs[].results[].a<b"
    report = tmp_path / "report.html"

    generate_html_report(
        _results_for(scanner, path, "<img src=x>"),
        str(report),
        {path: {"type": ["str"], "scanners": [scanner], "in_aggregate": False}},
    )

    html = report.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=x>" not in html
    assert "a&lt;b" in html
    # The raw key is not in the page anywhere: not in the row, not in the JQ
    # command built from it.
    assert "a<b" not in html


def test_a_quote_in_a_key_reaches_the_page_escaped_everywhere(tmp_path):
    """The JQ command quotes the key and the shell quotes the command, so a key
    holding a quote and a bracket puts both into the command; the command sits in
    a ``<code>`` element whose text must still be data."""
    scanner = "s"
    path = 'runs[].results[].a"b<c'
    report = tmp_path / "report.html"

    generate_html_report(
        _results_for(scanner, path, 1),
        str(report),
        {path: {"type": ["int"], "scanners": [scanner], "in_aggregate": True}},
    )

    html = report.read_text(encoding="utf-8")
    # Not in the row, and not in the JQ command whatever quoting the command
    # wraps around the key: the raw characters never reach the page.
    assert 'a"b<c' not in html
    assert '"b<c' not in html
    assert "a&quot;b&lt;c" in html


def test_an_intentionally_excluded_field_is_not_rendered_as_missing(tmp_path):
    """field_presence carries intentionally_excluded; the table entry dropped it,
    so every excluded field rendered as "No" in the missing (red) style."""
    path = "runs[].results[].ruleIndex"
    report = tmp_path / "report.html"

    generate_html_report(
        {
            "missing_fields": {},
            "match_statistics": {},
            "summary": {
                "total_findings": 0,
                "matched_findings": 0,
                "critical_missing_fields": 0,
                "important_missing_fields": 0,
                "informational_missing_fields": 0,
            },
        },
        str(report),
        {
            path: {
                "type": ["unknown"],
                "scanners": ["bandit"],
                "in_aggregate": False,
                "intentionally_excluded": True,
            }
        },
    )

    html = report.read_text(encoding="utf-8")
    assert "<td class='informational'>No (Intentionally Excluded)</td>" in html
    assert "<td class='missing'>No</td>" not in html


def test_the_jq_command_quotes_the_query_and_the_scanner_directory(tmp_path):
    """The copyable command is pasted into a shell: a quote in a field key or a
    space in a scanner name must stay inside one argument."""
    scanner = "my scanner"
    path = "runs[].results[].it's"
    report = tmp_path / "report.html"

    generate_html_report(
        _results_for(scanner, path, 1),
        str(report),
        {path: {"type": ["int"], "scanners": [scanner], "in_aggregate": True}},
    )

    import html as html_module

    # The command is HTML-escaped in the page; read it back as the shell would see
    # it once copied. shlex.quote closes and reopens the quotes around the
    # apostrophe, and the scanner directory is quoted while the glob stays bare.
    raw = report.read_text(encoding="utf-8")
    page = html_module.unescape(raw)
    assert "it'\"'\"'s" in page
    assert ".ash/ash_output/scanners/'my scanner'/**/*.sarif" in page
    # In the page itself the quotes are escaped: the shell text above is what a
    # reader copies, not what the HTML carries.
    assert "it'\"'\"'s" not in raw
    assert "it&#x27;" in raw
