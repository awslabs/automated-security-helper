# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A suppression suggested for a one-line finding covers that one line.

A finding with ``line_start`` and no ``line_end`` is a one-line finding. The
suggestion copied both fields as they were, and a suppression with
``line_start`` and no ``line_end`` is open-ended on purpose
(``utils/suppression_matcher.py``): it matches every finding of that rule from
that line to the end of the file. The suggestion now closes the range at the
finding's own line.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

from automated_security_helper.cli.mcp_tools import mcp_suggest_suppression
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability

pytestmark = pytest.mark.unit


def _finding(line_start: Optional[int], line_end: Optional[int]) -> FlatVulnerability:
    return FlatVulnerability(
        id="bandit-B101-oneline",
        title="Use of assert detected",
        description="Use of assert statement detected",
        severity="MEDIUM",
        scanner="bandit",
        scanner_type="SAST",
        rule_id="B101",
        file_path="src/app.py",
        line_start=line_start,
        line_end=line_end,
    )


def _results_file(tmp_path: Path, finding: FlatVulnerability) -> Path:
    document: Dict[str, Any] = {
        "metadata": {
            "scan_id": "test-scan",
            "scan_timestamp": "2026-01-01T00:00:00+00:00",
            "summary_stats": {
                "critical": 0,
                "high": 0,
                "medium": 1,
                "low": 0,
                "info": 0,
                "suppressed": 0,
            },
        },
        "sarif": {"version": "2.1.0", "runs": []},
        "additional_reports": {
            "bandit": [
                {
                    "id": finding.id.removeprefix("bandit-"),
                    "title": finding.title,
                    "description": finding.description,
                    "severity": finding.severity,
                    "type": finding.scanner_type,
                    "rule_id": finding.rule_id,
                    "file_path": finding.file_path,
                    "line_start": finding.line_start,
                    "line_end": finding.line_end,
                }
            ]
        },
        "scanner_results": {},
    }
    path = tmp_path / "ash_aggregated_results.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_a_finding_with_no_line_end_gets_a_closed_range(tmp_path) -> None:
    finding = _finding(line_start=10, line_end=None)
    results = _results_file(tmp_path, finding)

    result = mcp_suggest_suppression(finding.id, results_path=str(results))

    assert result["success"] is True, result
    assert result["json"]["line_start"] == 10
    assert result["json"]["line_end"] == 10, result["json"]
    suppression = AshSuppression.model_validate(result["json"])
    later = _finding(line_start=40, line_end=40)
    assert not suppression.matches(later), "the suggestion still reaches a later line"
    assert suppression.matches(finding)


def test_a_finding_with_both_lines_keeps_them(tmp_path) -> None:
    finding = _finding(line_start=10, line_end=15)
    results = _results_file(tmp_path, finding)

    result = mcp_suggest_suppression(finding.id, results_path=str(results))

    assert result["success"] is True, result
    assert result["json"]["line_start"] == 10
    assert result["json"]["line_end"] == 15


def test_a_finding_with_no_lines_stays_file_wide(tmp_path) -> None:
    finding = _finding(line_start=None, line_end=None)
    results = _results_file(tmp_path, finding)

    result = mcp_suggest_suppression(finding.id, results_path=str(results))

    assert result["success"] is True, result
    assert "line_start" not in result["json"]
    assert "line_end" not in result["json"]
