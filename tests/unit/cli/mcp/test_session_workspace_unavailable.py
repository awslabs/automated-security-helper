# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A session workspace that cannot be created is a documented error, not a class name.

Every source delivery creates the session's workspace first
(``source_delivery._ensure_dir``). When that fails (no space, no permission, a
file where the directory should be), an OSError escaping the delivery function
would have the MCP tool answer with ``error_type`` set to the exception's class
name, "FileExistsError" or "PermissionError", outside the error_type
vocabulary the tools document, so a client could not branch on it.

The failure is ``session_workspace_unavailable`` from set_source_git,
set_source_zip_chunk and set_source_zip_finalize, with the path and the OS error
in ``error``. The workspace here is blocked by a regular file at the session's
directory, so mkdir fails before anything else runs.
"""

from __future__ import annotations

import base64
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli import mcp_server, mcp_tools

SESSION = "session-a"
URL = "https://git.example.com/team/repo.git"


@pytest.fixture
def blocked(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "workspaces"
    root.mkdir()
    blocker = root / SESSION
    blocker.write_text("not a directory\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    # The clone host is checked before the workspace is made
    # (mcp_tools.mcp_set_source_git refuses a host the operator did not list
    # with clone_host_not_permitted), so the host is allowed here and the
    # workspace is what refuses.
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.com")
    return blocker


def _assert_unavailable(result, blocker: Path) -> None:
    assert result["success"] is False, result
    assert result.get("error_type") == "session_workspace_unavailable", result
    assert str(blocker) in result["error"], result


def test_set_source_git(blocked):
    _assert_unavailable(
        mcp_tools.mcp_set_source_git(url=URL, session_id=SESSION), blocked
    )


def test_set_source_zip_chunk(blocked):
    result = mcp_tools.mcp_set_source_zip_chunk(
        upload_id="u1",
        sequence=0,
        data_b64=base64.b64encode(b"PK").decode(),
        last=True,
        session_id=SESSION,
    )
    _assert_unavailable(result, blocked)


def test_set_source_zip_finalize(blocked):
    result = mcp_tools.mcp_set_source_zip_finalize(
        upload_id="u1", expected_sha256="0" * 64, session_id=SESSION
    )
    _assert_unavailable(result, blocked)


@pytest.mark.asyncio
async def test_the_tool_answers_with_the_documented_type(tmp_path, monkeypatch):
    """Through the MCP tool, for the stdio session, as a client would see it."""
    root = tmp_path / "workspaces"
    root.mkdir()
    blocker = root / "__default__"
    blocker.write_text("not a directory\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.com")
    ctx = MagicMock(spec=Context)
    ctx.headers = {}

    result = await mcp_server.set_source_git(ctx, url=URL)

    _assert_unavailable(result, blocker)
