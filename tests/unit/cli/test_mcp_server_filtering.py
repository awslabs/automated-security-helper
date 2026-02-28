#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for MCP server content filtering.

This module tests the scanner and severity filtering functionality
in the MCP server's get_scan_results tool.
"""

from automated_security_helper.cli.mcp_server import _apply_content_filters


def test_scanner_filtering():
    """Test that scanner filtering works correctly."""
    # Create mock results with multiple scanners
    results = {
        "scan_id": "test-scan",
        "status": "completed",
        "scanner_reports": {
            "bandit": {"findings": 5},
            "semgrep": {"findings": 3},
            "opengrep": {"findings": 2},
            "grype": {"findings": 10},
        },
        "raw_results": {
            "scanner_results": {
                "bandit": {"status": "PASSED", "severity_counts": {"high": 2}},
                "semgrep": {"status": "PASSED", "severity_counts": {"medium": 1}},
                "opengrep": {"status": "PASSED", "severity_counts": {"low": 1}},
                "grype": {"status": "PASSED", "severity_counts": {"critical": 5}},
            },
            "additional_reports": {
                "bandit": {"report": "data"},
                "semgrep": {"report": "data"},
                "opengrep": {"report": "data"},
                "grype": {"report": "data"},
            },
        },
    }

    # Filter for only opengrep and semgrep
    filtered = _apply_content_filters(results, scanners="opengrep,semgrep")

    # Verify scanner_reports only contains requested scanners
    assert "opengrep" in filtered["scanner_reports"]
    assert "semgrep" in filtered["scanner_reports"]
    assert "bandit" not in filtered["scanner_reports"]
    assert "grype" not in filtered["scanner_reports"]
    assert len(filtered["scanner_reports"]) == 2

    # Verify raw_results.scanner_results only contains requested scanners
    assert "opengrep" in filtered["raw_results"]["scanner_results"]
    assert "semgrep" in filtered["raw_results"]["scanner_results"]
    assert "bandit" not in filtered["raw_results"]["scanner_results"]
    assert "grype" not in filtered["raw_results"]["scanner_results"]
    assert len(filtered["raw_results"]["scanner_results"]) == 2

    # Verify raw_results.additional_reports only contains requested scanners
    assert "opengrep" in filtered["raw_results"]["additional_reports"]
    assert "semgrep" in filtered["raw_results"]["additional_reports"]
    assert "bandit" not in filtered["raw_results"]["additional_reports"]
    assert "grype" not in filtered["raw_results"]["additional_reports"]
    assert len(filtered["raw_results"]["additional_reports"]) == 2

    # Verify filter metadata is added
    assert "_content_filters" in filtered
    assert "opengrep" in filtered["_content_filters"]["scanners"]
    assert "semgrep" in filtered["_content_filters"]["scanners"]


def test_severity_filtering():
    """Test that severity filtering works correctly."""
    results = {
        "scan_id": "test-scan",
        "status": "completed",
        "summary_stats": {
            "critical": 5,
            "high": 10,
            "medium": 15,
            "low": 20,
            "info": 5,
            "total": 55,
        },
        "raw_results": {
            "scanner_results": {
                "bandit": {
                    "status": "PASSED",
                    "severity_counts": {
                        "critical": 2,
                        "high": 5,
                        "medium": 8,
                        "low": 10,
                    },
                },
            },
        },
    }

    # Filter for only critical and high severities
    filtered = _apply_content_filters(results, severities="critical,high")

    # Verify summary_stats only contains requested severities (plus non-severity fields)
    assert filtered["summary_stats"]["critical"] == 5
    assert filtered["summary_stats"]["high"] == 10
    assert filtered["summary_stats"]["medium"] == 0
    assert filtered["summary_stats"]["low"] == 0
    assert filtered["summary_stats"]["info"] == 0
    assert filtered["summary_stats"]["total"] == 55  # Non-severity field preserved

    # Verify scanner severity_counts only contains requested severities
    scanner_counts = filtered["raw_results"]["scanner_results"]["bandit"][
        "severity_counts"
    ]
    assert scanner_counts["critical"] == 2
    assert scanner_counts["high"] == 5
    assert "medium" not in scanner_counts
    assert "low" not in scanner_counts


def test_combined_scanner_and_severity_filtering():
    """Test that combined scanner and severity filtering works correctly."""
    results = {
        "scan_id": "test-scan",
        "status": "completed",
        "scanner_reports": {
            "bandit": {"findings": 5},
            "semgrep": {"findings": 3},
        },
        "summary_stats": {
            "critical": 5,
            "high": 10,
            "medium": 15,
            "total": 30,
        },
        "raw_results": {
            "scanner_results": {
                "bandit": {
                    "status": "PASSED",
                    "severity_counts": {
                        "critical": 2,
                        "high": 3,
                        "medium": 5,
                    },
                },
                "semgrep": {
                    "status": "PASSED",
                    "severity_counts": {
                        "critical": 3,
                        "high": 7,
                        "medium": 10,
                    },
                },
            },
            "additional_reports": {
                "bandit": {"report": "data"},
                "semgrep": {"report": "data"},
            },
        },
    }

    # Filter for only semgrep with critical severity
    filtered = _apply_content_filters(
        results, scanners="semgrep", severities="critical"
    )

    # Verify only semgrep is present
    assert "semgrep" in filtered["scanner_reports"]
    assert "bandit" not in filtered["scanner_reports"]
    assert len(filtered["scanner_reports"]) == 1

    # Verify only critical severity is present
    assert filtered["summary_stats"]["critical"] == 5
    assert filtered["summary_stats"]["high"] == 0
    assert filtered["summary_stats"]["medium"] == 0

    # Verify semgrep severity_counts only contains critical
    scanner_counts = filtered["raw_results"]["scanner_results"]["semgrep"][
        "severity_counts"
    ]
    assert scanner_counts["critical"] == 3
    assert "high" not in scanner_counts
    assert "medium" not in scanner_counts


def test_no_modification_of_original():
    """Test that filtering doesn't modify the original results object."""
    original_results = {
        "scan_id": "test-scan",
        "scanner_reports": {
            "bandit": {"findings": 5},
            "semgrep": {"findings": 3},
        },
        "raw_results": {
            "scanner_results": {
                "bandit": {"status": "PASSED"},
                "semgrep": {"status": "PASSED"},
            },
        },
    }

    # Create a copy to compare later
    import copy

    original_copy = copy.deepcopy(original_results)

    # Apply filter
    _apply_content_filters(original_results, scanners="semgrep")

    # Verify original wasn't modified
    assert original_results == original_copy
    assert "bandit" in original_results["scanner_reports"]
    assert "semgrep" in original_results["scanner_reports"]
