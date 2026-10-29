# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_scan_progress keeps the producer's counts and scanners, and reads only its own tree.

The tool replaced the producer's ``severity_counts``, which carries a catch-all
bucket for a finding whose severity is off the ladder, with a six-bucket sum of
whatever per-target files it found, and replaced the producer's ``scanners`` map
with a glob over those files, so a finding under another key and a scanner that
wrote no file both disappeared. The walk also followed a scanner directory that
was a link elsewhere and returned the JSON it found there as this scan's, which
every other results reader refuses. The producer's view is now kept, the files'
content is added under it, and a directory is read only when it resolves inside
the output directory.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli.mcp.profile_registry import DEFAULT_SESSION_ID
from automated_security_helper.core.resource_management.scan_registry import (
    get_scan_registry,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _server(monkeypatch):
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)


def _ctx() -> MagicMock:
    ctx = MagicMock(spec=Context)
    ctx.headers = {}
    for name in ("info", "debug", "warning", "error", "report_progress"):
        setattr(ctx, name, AsyncMock())
    return ctx


def _write(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _producer(scan_id: str) -> Dict[str, Any]:
    return {
        "scan_id": scan_id,
        "status": "running",
        "is_complete": False,
        "severity_counts": {
            "critical": 0,
            "high": 1,
            "medium": 0,
            "low": 0,
            "info": 0,
            "suppressed": 0,
            "unknown": 2,
        },
        "scanners": {
            "bandit": {"source": {"status": "running", "finding_count": 1}},
            "semgrep": {"source": {"status": "pending", "finding_count": 0}},
        },
    }


def _call(tmp_path: Path, monkeypatch) -> Dict[str, Any]:
    from automated_security_helper.cli import mcp_server

    output = tmp_path / "project" / ".ash" / "ash_output"
    output.mkdir(parents=True)
    scan_id = get_scan_registry().register_scan(
        str(tmp_path / "project"), str(output), session_id=DEFAULT_SESSION_ID
    )
    bandit = {"severity_counts": {"high": 1, "off-ladder": 3}, "status": "PASSED"}
    _write(output / "scanners" / "bandit" / "source" / "ASH.ScanResults.json", bandit)
    elsewhere = tmp_path / "elsewhere"
    _write(
        elsewhere / "source" / "ASH.ScanResults.json",
        {"severity_counts": {"critical": 9}, "status": "FAILED"},
    )
    os.symlink(elsewhere, output / "scanners" / "linked", target_is_directory=True)

    monkeypatch.setattr(
        mcp_server,
        "mcp_get_scan_progress",
        AsyncMock(return_value=_producer(scan_id)),
    )
    monkeypatch.setattr(
        mcp_server,
        "summarize_scanner_statuses",
        lambda output_dir: {"scanner_statuses": {}, "skipped_scanners": []},
    )
    result = asyncio.run(mcp_server.get_scan_progress(_ctx(), scan_id))
    assert "error" not in result, result
    result["_bandit_file"] = bandit
    return result


@pytest.mark.skipif(
    sys.platform == "win32", reason="directory links need a privilege on Windows"
)
def test_the_producers_counts_and_scanners_are_kept(tmp_path, monkeypatch) -> None:
    result = _call(tmp_path, monkeypatch)

    assert result["severity_counts"]["unknown"] == 2, result["severity_counts"]
    assert result["severity_counts"]["high"] == 1
    assert "semgrep" in result["scanners"], "a scanner with no file disappeared"
    assert result["scanners"]["bandit"]["source"] == result["_bandit_file"]


@pytest.mark.skipif(
    sys.platform == "win32", reason="directory links need a privilege on Windows"
)
def test_a_scanner_directory_linked_elsewhere_is_not_read(tmp_path, monkeypatch):
    result = _call(tmp_path, monkeypatch)

    assert "linked" not in result["scanners"], "a linked directory was read"
    assert result["severity_counts"]["critical"] == 0
