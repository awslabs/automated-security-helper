# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_scan_results accepts null filters and carries coverage at every level.

The ``scanners`` and ``severities`` arguments were annotated ``str`` with a
default of None, so the argument model refused a client that sent an explicit
null for "no filter" while accepting the same call with the argument left out.
The summary and minimal levels were built from a fixed key set that left out
``coverage_complete`` and the gap lists the tool's docstring promises at every
level, so a summary read as complete for a scan whose results named a scanner
that never ran.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli import mcp_server
from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_session_state,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    clear_profile_registry()
    clear_session_state(None)
    yield
    clear_profile_registry()
    clear_session_state(None)


def _tool():
    tool = mcp_server.mcp._tool_manager.get_tool("get_scan_results")
    assert tool is not None
    return tool


def test_explicit_null_filters_validate() -> None:
    # Red before the fix: "Input should be a valid string" for each null.
    _tool().fn_metadata.arg_model.model_validate({"scanners": None, "severities": None})


@pytest.mark.parametrize("argument", ["scanners", "severities"])
def test_the_schema_admits_null_for_each_filter(argument: str) -> None:
    schema = _tool().parameters["properties"][argument]

    assert {"type": "null"} in schema.get("anyOf", []), schema


def _ctx() -> MagicMock:
    ctx = MagicMock(spec=Context)
    ctx.headers = {}
    for name in ("info", "debug", "warning", "error", "report_progress"):
        setattr(ctx, name, AsyncMock())
    return ctx


def _document() -> Dict[str, Any]:
    return {
        "scan_id": "scan-1",
        "status": "incomplete",
        "is_complete": True,
        "completion_time": None,
        "coverage_complete": False,
        "incomplete_scanners": [
            {"scanner": "bandit", "status": "MISSING", "reason": "missing_dependencies"}
        ],
        "no_scanner_ran": False,
        "summary_stats": {"total": 0, "actionable": 0, "severity_counts": {}},
        "raw_results": {"metadata": {}, "scanner_results": {}},
    }


@pytest.mark.parametrize("filter_level", ["summary", "minimal"])
def test_a_filtered_level_carries_the_coverage_keys(
    tmp_path: Path, monkeypatch, filter_level: str
) -> None:
    monkeypatch.setattr(
        mcp_server, "mcp_get_scan_results", AsyncMock(return_value=_document())
    )

    result = asyncio.run(
        mcp_server.get_scan_results(
            _ctx(), output_dir=str(tmp_path), filter_level=filter_level
        )
    )

    assert result["_filter"] == filter_level, result
    # Red before the fix: the filtered response had no coverage_complete key.
    assert result["coverage_complete"] is False, result
    assert result["incomplete_scanners"][0]["scanner"] == "bandit", result
    assert result["no_scanner_ran"] is False, result


def test_a_key_the_document_lacks_is_not_invented(tmp_path: Path, monkeypatch) -> None:
    """Control: only the gap keys the document carries are copied."""
    document = _document()
    del document["no_scanner_ran"]
    monkeypatch.setattr(
        mcp_server, "mcp_get_scan_results", AsyncMock(return_value=document)
    )

    result = asyncio.run(
        mcp_server.get_scan_results(
            _ctx(), output_dir=str(tmp_path), filter_level="summary"
        )
    )

    assert "no_scanner_ran" not in result, result
    assert result["coverage_complete"] is False, result
