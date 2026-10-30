# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``suggest_suppression`` refuses a suggestion that would not name the finding.

A suppression names a finding by its file and its rule. For a finding with no
file path the tool built one with an empty path, which matches nothing, and
answered success; for one with no rule id it built one with no rule, which the
matcher reads as every rule in the file, and answered success too. A client's
``expiration`` went straight into the model, whose validator raised a pydantic
``ValidationError`` out of the tool, logged as an unexpected server error. Each
is now a refusal the client can read: ``suppression_not_specific`` for the
first two, ``invalid_expiration`` for the date.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

pytestmark = pytest.mark.unit

SCANNER = "bandit"


def _results_file(
    tmp_path: Path,
    *,
    file_path: Optional[str] = "src/app.py",
    rule_id: Optional[str] = "B101",
    line_start: Optional[int] = 42,
    line_end: Optional[int] = 42,
) -> Path:
    """An aggregated results file with one finding, id ``bandit-finding-one``."""
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
            SCANNER: [
                {
                    "id": "finding-one",
                    "title": "Use of assert detected",
                    "description": "Use of assert statement detected",
                    "severity": "MEDIUM",
                    "type": "SAST",
                    "rule_id": rule_id,
                    "file_path": file_path,
                    "line_start": line_start,
                    "line_end": line_end,
                }
            ]
        },
        "scanner_results": {},
    }
    results = tmp_path / "ash_aggregated_results.json"
    results.write_text(json.dumps(document), encoding="utf-8")
    return results


FINDING = f"{SCANNER}-finding-one"


def _suggest(results: Path, **kwargs: Any) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp_tools import mcp_suggest_suppression

    return mcp_suggest_suppression(
        finding_id=FINDING, results_path=str(results), **kwargs
    )


def test_a_finding_with_no_file_path_is_refused(tmp_path) -> None:
    results = _results_file(tmp_path, file_path=None)

    response = _suggest(results)

    assert response["success"] is False, response
    assert response["error_type"] == "suppression_not_specific", response
    assert "no file path" in response["error"], response
    assert "yaml" not in response, response


def test_a_finding_with_no_rule_id_is_refused(tmp_path) -> None:
    results = _results_file(tmp_path, rule_id=None, line_start=None, line_end=None)

    response = _suggest(results)

    assert response["success"] is False, response
    assert response["error_type"] == "suppression_not_specific", response
    assert "no rule id" in response["error"], response


@pytest.mark.parametrize("expiration", ["31/12/2030", "2030-13-01", "", "soon"])
def test_an_expiration_that_is_not_a_date_is_refused(tmp_path, expiration) -> None:
    from automated_security_helper.models.core import EXPIRATION_RULE

    results = _results_file(tmp_path)

    response = _suggest(results, expiration=expiration)

    assert response["success"] is False, response
    assert response["error_type"] == "invalid_expiration", response
    assert EXPIRATION_RULE in response["error"], response
    # The value is the client's own text: the rule is quoted, the value is not.
    if expiration:
        assert expiration not in response["error"], response


def test_a_finding_that_names_its_file_and_rule_is_still_suggested(tmp_path) -> None:
    results = _results_file(tmp_path)

    response = _suggest(results, expiration="2030-12-31")

    assert response["success"] is True, response
    assert response["json"]["path"] == "src/app.py", response
    assert response["json"]["rule_id"] == "B101", response
    assert response["json"]["expiration"] == "2030-12-31", response
