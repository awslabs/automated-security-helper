# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_scan_progress tells the progress read whether the caller may see process ids.

A scan's entry records the tools a cancel could not end, with their process ids,
in its warnings and in the stored coverage. The progress read can leave those ids
out (``check_scan_progress(..., name_process_ids=False)``), and only the tool
knows the caller: it passes the request-scoped answer of ``caller_is_remote``,
the same predicate the scan's own response uses. Before, the tool passed no word,
so a remote client's progress read handed back every id as recorded.

The read is replaced by a stand-in that records the options it was given, so
the test measures the tool's side of the hand-off alone.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import sandbox
from automated_security_helper.cli.mcp.profile_registry import DEFAULT_SESSION_ID
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)

pytestmark = pytest.mark.unit


def _poll(tmp_path: Path, monkeypatch, *, remote: bool):
    source = tmp_path / "proj"
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(source),
        output_directory=str(output),
        session_id=DEFAULT_SESSION_ID,
    )
    given: Dict[str, Any] = {}

    async def a_progress_read(scan_id, session_id=None, **options):
        given.update(options)
        return {"scan_id": scan_id, "status": "running"}

    monkeypatch.setattr(mcp_tools, "get_scan_registry", lambda: registry)
    monkeypatch.setattr(mcp_tools, "check_scan_progress", a_progress_read)
    monkeypatch.setattr(sandbox, "caller_is_remote", lambda session_id: remote)
    answer = asyncio.run(mcp_tools.mcp_get_scan_progress(scan_id))
    assert "error" not in answer, answer
    return given


def test_a_remote_callers_progress_read_is_told_to_withhold_process_ids(
    tmp_path, monkeypatch
) -> None:
    given = _poll(tmp_path, monkeypatch, remote=True)

    assert given == {"name_process_ids": False}, given


def test_a_local_callers_progress_read_keeps_the_process_ids(
    tmp_path, monkeypatch
) -> None:
    given = _poll(tmp_path, monkeypatch, remote=False)

    assert given == {"name_process_ids": True}, given
