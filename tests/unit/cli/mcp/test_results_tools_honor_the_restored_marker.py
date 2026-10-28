# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No MCP results tool presents put-back results as the last scan's.

When an MCP scan ends without results, ASH puts the previous scan's results back
in its output directory and leaves a marker beside them
(core/previous_results.py). get_scan_progress, which knows the scan, reads
nothing from them. Every tool that takes an output directory or a results file
instead of a scan id reads the marker, so none of them answers the earlier
scan's findings as `completed` results for a directory whose last scan failed.
Before the previous results were
kept, the directory was empty after such a scan and these tools answered "not
complete".

They answer that again, with the reason: every tool that reads results from a
directory or a file in one (get_scan_results, get_scan_summary,
get_scan_result_paths, explain_finding, diff_scan_results, suggest_suppression)
refuses a directory that carries the marker, with error_category
scan_incomplete and output_holds_previous_results in the context.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli import mcp_server
from automated_security_helper.core.previous_results import RESTORED_MARKER_NAME


def _results_document() -> str:
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.schemas.sarif_schema_model import SarifReport

    model = AshAggregatedResults(ash_config=AshConfig())
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "bandit"}},
                    "results": [
                        {
                            "ruleId": "B101",
                            "level": "error",
                            "message": {"text": "assert used"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app.py"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )
    return model.model_dump_json(by_alias=True)


@pytest.fixture
def output(tmp_path, monkeypatch) -> Path:
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    out = tmp_path / "project" / ".ash" / "ash_output"
    (out / "reports").mkdir(parents=True)
    (out / "ash_aggregated_results.json").write_text(
        _results_document(), encoding="utf-8"
    )
    (out / "reports" / "ash.sarif").write_text(
        json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8"
    )
    return out


def _mark(output: Path) -> None:
    (output / RESTORED_MARKER_NAME).write_text("restored\n", encoding="utf-8")


@pytest.fixture
def ctx() -> MagicMock:
    context = MagicMock(spec=Context)
    context.headers = {}
    for level in ("info", "warning", "error", "debug"):
        setattr(context, level, AsyncMock())
    return context


def _first_finding_id(output: Path) -> str:
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    model = AshAggregatedResults.from_json(
        (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    return model.to_flat_vulnerabilities()[0].id


def _assert_refused(response) -> None:
    assert response.get("success") is False, response
    assert response.get("error_category") == "scan_incomplete", response
    assert "not complete" in response["error"], response
    assert response["context"]["output_holds_previous_results"] is True, response


async def _all_readers(ctx, output: Path, finding_id: str):
    results_file = str(output / "ash_aggregated_results.json")
    return {
        "get_scan_results": await mcp_server.get_scan_results(
            ctx, output_dir=str(output)
        ),
        "get_scan_summary": await mcp_server.get_scan_summary(
            ctx, output_dir=str(output)
        ),
        "get_scan_result_paths": await mcp_server.get_scan_result_paths(
            ctx, output_dir=str(output)
        ),
        "explain_finding": await mcp_server.explain_finding(
            ctx, finding_id=finding_id, results_path=str(output)
        ),
        "diff_scan_results": await mcp_server.diff_scan_results(
            ctx, before_path=results_file, after_path=results_file
        ),
        "suggest_suppression": await mcp_server.suggest_suppression(
            ctx, finding_id=finding_id, results_path=results_file, justification="test"
        ),
    }


@pytest.mark.asyncio
async def test_every_reader_refuses_a_directory_with_the_marker(ctx, output):
    finding_id = _first_finding_id(output)
    _mark(output)

    responses = await _all_readers(ctx, output, finding_id)

    for tool, response in responses.items():
        try:
            _assert_refused(response)
        except AssertionError as failure:
            raise AssertionError(f"{tool}: {failure}") from None


@pytest.mark.asyncio
async def test_without_the_marker_every_reader_reads_them(ctx, output):
    """The control: the same files, unmarked, are read by every tool."""
    finding_id = _first_finding_id(output)

    responses = await _all_readers(ctx, output, finding_id)

    for tool, response in responses.items():
        assert response.get("success") is not False, (tool, response)
        assert response.get("error_category") != "scan_incomplete", (tool, response)
