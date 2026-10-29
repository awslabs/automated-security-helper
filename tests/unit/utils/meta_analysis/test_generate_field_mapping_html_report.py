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
    page = html_module.unescape(report.read_text(encoding="utf-8"))
    assert "it'\"'\"'s" in page
    assert ".ash/ash_output/scanners/'my scanner'/**/*.sarif" in page
