# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Flat report IDs select the intended saved occurrence through real MCP loaders."""

import json

import pytest

from automated_security_helper.cli.mcp_tools import (
    mcp_explain_finding,
    mcp_suggest_suppression,
)
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
    FlatJSONReporter,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport


def test_flat_report_ids_select_formerly_colliding_saved_findings(
    tmp_path, monkeypatch, test_plugin_context
):
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    results = [
        {
            "ruleId": "B602",
            "message": {"text": "synthetic shared finding"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": path},
                        "region": {"startLine": line, "endLine": line},
                    }
                }
            ],
        }
        for path, line in [("src/one.py", 10), ("src/two.py", 20)]
    ]
    model = AshAggregatedResults(
        sarif=SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [{"tool": {"driver": {"name": "bandit"}}, "results": results}],
            }
        )
    )
    results_file = tmp_path / "ash_aggregated_results.json"
    results_file.write_text(model.model_dump_json())
    saved = AshAggregatedResults.from_json(results_file.read_text())
    findings = json.loads(FlatJSONReporter(context=test_plugin_context).report(saved))[
        "findings"
    ]
    assert len({finding["id"] for finding in findings}) == 2
    for finding in findings:
        explanation = mcp_explain_finding(finding["id"], results_path=str(tmp_path))
        assert explanation["success"] is True
        physical = explanation["finding"]["scanner_metadata"]["locations"][0][
            "physicalLocation"
        ]
        assert physical["artifactLocation"]["uri"] == finding["file_path"]
        assert physical["region"]["startLine"] == finding["line_start"]
        suggestion = mcp_suggest_suppression(
            finding["id"],
            results_path=str(results_file),
            expiration="2030-01-01",
            justification="synthetic regression",
        )
        assert suggestion["success"] is True
        assert suggestion["json"]["path"] == finding["file_path"]
        assert suggestion["json"]["line_start"] == finding["line_start"]
        assert suggestion["json"]["rule_id"] == "B602"


@pytest.mark.parametrize("kind", ["context", "string-lines", "float-lines"])
def test_line_twenty_id_selects_line_twenty_from_saved_reports(
    kind, tmp_path, monkeypatch, test_plugin_context
):
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    if kind == "context":
        results = [
            {
                "ruleId": "B602",
                "message": {"text": "synthetic shared finding"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/app.py"},
                            "contextRegion": {"startLine": line, "endLine": line},
                        }
                    }
                ],
            }
            for line in (10, 20)
        ]
        model = AshAggregatedResults(
            sarif=SarifReport.model_validate(
                {
                    "version": "2.1.0",
                    "runs": [
                        {"tool": {"driver": {"name": "bandit"}}, "results": results}
                    ],
                }
            )
        )
    else:
        convert = str if kind == "string-lines" else float
        model = AshAggregatedResults(
            additional_reports={
                "bandit": [
                    {
                        "rule_id": "B602",
                        "description": "synthetic shared finding",
                        "file_path": "src/app.py",
                        "line_start": convert(line),
                        "line_end": convert(line),
                    }
                    for line in (10, 20)
                ]
            }
        )
    results_file = tmp_path / "ash_aggregated_results.json"
    results_file.write_text(model.model_dump_json())
    saved = AshAggregatedResults.from_json(results_file.read_text())
    findings = json.loads(FlatJSONReporter(context=test_plugin_context).report(saved))[
        "findings"
    ]
    assert [finding["line_start"] for finding in findings] == [10, 20]
    # Ask for the second ID even if it collided; this exposes first-match lookup.
    finding = findings[1]
    explanation = mcp_explain_finding(finding["id"], results_path=str(tmp_path))
    assert explanation["success"] is True
    raw = explanation["finding"]["scanner_metadata"]
    if kind == "context":
        assert (
            raw["locations"][0]["physicalLocation"]["contextRegion"]["startLine"] == 20
        )
    else:
        assert raw["line_start"] == convert(20)
    suggestion = mcp_suggest_suppression(
        finding["id"],
        results_path=str(results_file),
        expiration="2030-01-01",
        justification="synthetic regression",
    )
    assert suggestion["success"] is True
    assert suggestion["json"]["line_start"] == suggestion["json"]["line_end"] == 20
    assert len({item["id"] for item in findings}) == 2
