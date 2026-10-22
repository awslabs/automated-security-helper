# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``get_scan_results(actionable_only=True)`` returns the actionable findings.

Why this file exists
--------------------
With ``actionable_only=True`` the tool adds a flat ``findings`` list, built by
``result_filters.add_findings_list`` from ``raw_results["sarif"]`` after
``filter_actionable_only`` removed the suppressed entries from it. The producer
underneath, ``scan_tracking.get_scan_results``, dumps the results model with
``sarif`` excluded, so the tool reads the SARIF itself and ``findings`` and
``findings_count`` match the scan's actionable findings.

``tests/unit/core/resource_management/test_result_filters.py`` tests the filters
with a payload that carries ``sarif``, which is why they pass. Here the real
producer reads a results file from disk, so the seam between the two is what is
measured.

The same list ignored ``scanners`` and ``severities``: ``apply_content_filters``
narrowed the per-scanner counts and never the findings, so
``actionable_only=True, severities="critical"`` (an example in the filtering
guide) would list findings of every severity once the list had any.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.cli.mcp_server import get_scan_results

FINDINGS = [
    {
        "scanner": "bandit",
        "rule": "B602",
        "level": "error",
        "severity": "HIGH",
        "path": "src/app.py",
        "line": 12,
        "suppressed": False,
    },
    {
        "scanner": "bandit",
        "rule": "B101",
        "level": "note",
        "severity": "LOW",
        "path": "tests/test_app.py",
        "line": 4,
        "suppressed": True,
    },
    {
        "scanner": "detect-secrets",
        "rule": "SECRET-AWS-ACCESS-KEY",
        "level": "error",
        "severity": "CRITICAL",
        "path": "config/settings.ini",
        "line": 3,
        "suppressed": False,
    },
]


def _sarif_result(finding: Dict[str, Any]) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "ruleId": finding["rule"],
        "level": finding["level"],
        "kind": "fail",
        "message": {"text": f"{finding['rule']} finding"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding["path"]},
                    "region": {"startLine": finding["line"]},
                }
            }
        ],
        "properties": {
            "scanner_name": finding["scanner"],
            "issue_severity": finding["severity"],
        },
    }
    if finding["suppressed"]:
        result["suppressions"] = [{"kind": "external", "justification": "test"}]
    return result


def _write_results(output_dir: Path, findings: List[Dict[str, Any]]) -> None:
    """An ash_aggregated_results.json as ASH writes it, with SARIF findings."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    document = json.loads(AshAggregatedResults().model_dump_json(by_alias=True))
    document["sarif"]["runs"][0]["results"] = [_sarif_result(f) for f in findings]
    document["metadata"]["summary_stats"]["actionable"] = sum(
        1 for f in findings if not f["suppressed"]
    )
    document["metadata"]["summary_stats"]["total"] = len(findings)
    document["scanner_results"] = {
        "bandit": {"status": "FAILED", "finding_count": 2},
        "detect-secrets": {"status": "FAILED", "finding_count": 1},
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "ash_aggregated_results.json").write_text(
        json.dumps(document), encoding="utf-8"
    )


@pytest.fixture
def output_dir(tmp_path, monkeypatch) -> Path:
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    path = tmp_path / "project" / ".ash" / "ash_output"
    _write_results(path, FINDINGS)
    return path


async def _results(output_dir: Path, **filters) -> Dict[str, Any]:
    ctx = MagicMock(spec=Context)
    ctx.headers = {}
    result = await get_scan_results(ctx, output_dir=str(output_dir), **filters)
    assert "error" not in result, result
    return result


def _rule_ids(result: Dict[str, Any]) -> List[str]:
    return sorted(finding["rule_id"] for finding in result["findings"])


@pytest.mark.asyncio
class TestActionableOnlyListsTheFindings:
    async def test_every_unsuppressed_finding_is_listed(self, output_dir):
        result = await _results(output_dir, actionable_only=True)

        assert result["findings_count"] == 2, result.get("findings")
        assert _rule_ids(result) == ["B602", "SECRET-AWS-ACCESS-KEY"]

    async def test_each_finding_carries_its_location_and_severity(self, output_dir):
        result = await _results(output_dir, actionable_only=True)

        by_rule = {finding["rule_id"]: finding for finding in result["findings"]}
        assert by_rule["B602"] == {
            "rule_id": "B602",
            "severity": "HIGH",
            "message": "B602 finding",
            "scanner": "bandit",
            "file_path": "src/app.py",
            "line_start": 12,
        }

    async def test_severities_narrow_the_list(self, output_dir):
        result = await _results(output_dir, actionable_only=True, severities="critical")

        assert _rule_ids(result) == ["SECRET-AWS-ACCESS-KEY"]
        assert result["findings_count"] == 1

    async def test_scanners_narrow_the_list(self, output_dir):
        result = await _results(output_dir, actionable_only=True, scanners="bandit")

        assert _rule_ids(result) == ["B602"]

    async def test_the_response_does_not_also_carry_the_sarif(self, output_dir):
        """The list is the view of the findings; the whole SARIF stays on disk.

        The producer leaves the SARIF out of ``raw_results`` to keep responses
        small, and a fix that put it back for every caller would return it twice.
        """
        result = await _results(output_dir, actionable_only=True)

        assert "sarif" not in result["raw_results"]


@pytest.mark.asyncio
async def test_without_actionable_only_there_is_no_findings_list(output_dir):
    """Unchanged: the list is part of the actionable_only view only."""
    result = await _results(output_dir)

    assert "findings" not in result
    assert "sarif" not in result["raw_results"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "filter_level,loads_sarif",
    [("full", True), ("summary", False), ("minimal", False), ("verbose", True)],
)
async def test_the_sarif_is_read_only_for_a_level_that_returns_the_list(
    output_dir, monkeypatch, filter_level, loads_sarif
):
    """The SARIF is read to build the findings list, which summary and minimal drop.

    It was read for every actionable_only call: a scan's whole SARIF, parsed and
    held for a response that left the list out. An unknown filter_level returns
    the full results, list included, so it still reads it.
    """
    from automated_security_helper.cli import mcp_server

    real = mcp_server.mcp_get_scan_results
    asked: List[bool] = []

    async def recording(*args, include_sarif: bool = False, **kwargs):
        asked.append(include_sarif)
        return await real(*args, include_sarif=include_sarif, **kwargs)

    monkeypatch.setattr(mcp_server, "mcp_get_scan_results", recording)

    result = await _results(output_dir, actionable_only=True, filter_level=filter_level)

    assert asked == [loads_sarif], asked
    if loads_sarif:
        assert result["findings_count"] == 2, result.get("findings")
