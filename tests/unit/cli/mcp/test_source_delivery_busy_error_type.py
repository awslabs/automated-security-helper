# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A delivery refused because a scan of the session runs has one ``error_type``.

``set_source_git`` and ``set_source_zip_finalize`` both refuse to replace a
session's source while one of its scans runs (``source_delivery._no_scan_running``).
``set_source_zip_finalize`` reported the refusal with an ``error_type``, while
``set_source_git`` caught the same exception as a clone failure and returned no
``error_type`` at all, so a client could not tell "try again after the scan" from
a bad URL without reading the message. These tests call both tools as a client
does, with the session's scan lock held, and check that each names the refusal
the same way: ``source_delivery_busy`` (``source_delivery.SOURCE_DELIVERY_BUSY``).
The clone host is one the operator allows, so the refusal is not the host
allowlist's.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import subprocess
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_session_state,
)

SESSION = "busy-session"
BUSY_MESSAGE = (
    "a scan of this session is running, or its source is being written; "
    "change the delivered source after it finishes"
)
BUSY_ERROR_TYPE = "source_delivery_busy"


@pytest.fixture
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "example.com")
    clear_profile_registry()
    clear_session_state()
    yield tmp_path
    clear_profile_registry()
    clear_session_state()


def _ctx() -> Any:
    ctx = MagicMock()
    ctx.headers = {"mcp-session-id": SESSION}

    async def anoop(*args: Any, **kwargs: Any) -> None:
        return None

    for name in ("info", "error", "debug", "warning", "report_progress"):
        setattr(ctx, name, MagicMock(side_effect=anoop))
    return ctx


def _scan_lock() -> Any:
    from automated_security_helper.cli.mcp.sessions import get_default_registry

    return get_default_registry().get_or_create(SESSION).lock


def _no_git(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError(f"git ran while a scan held the session lock: {args}")


def test_set_source_git_names_the_refusal(_server) -> None:
    from automated_security_helper.cli import mcp_server
    from automated_security_helper.cli.mcp import source_delivery

    with _scan_lock(), patch.object(source_delivery.subprocess, "run", _no_git):
        result = asyncio.run(
            mcp_server.set_source_git(_ctx(), url="https://example.com/repo.git")
        )

    assert result["success"] is False, result
    assert result["error_type"] == BUSY_ERROR_TYPE, result
    assert result["error"] == BUSY_MESSAGE, result
    assert result["session_id"] == SESSION, result


def test_both_delivery_tools_give_the_same_error_type(_server) -> None:
    from automated_security_helper.cli import mcp_server

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("main.py", "x = 1\n")
    data = buffer.getvalue()
    chunk = asyncio.run(
        mcp_server.set_source_zip_chunk(
            _ctx(),
            upload_id="u1",
            sequence=0,
            data_b64=base64.b64encode(data).decode("ascii"),
            last=True,
        )
    )
    assert chunk["success"] is True, chunk

    with _scan_lock(), patch.object(subprocess, "run", _no_git):
        finalized = asyncio.run(
            mcp_server.set_source_zip_finalize(
                _ctx(),
                upload_id="u1",
                expected_sha256=hashlib.sha256(data).hexdigest(),
            )
        )
        cloned = asyncio.run(
            mcp_server.set_source_git(_ctx(), url="https://example.com/repo.git")
        )

    assert finalized["success"] is False, finalized
    assert cloned["success"] is False, cloned
    assert finalized["error_type"] == cloned["error_type"] == BUSY_ERROR_TYPE


def test_a_clone_failure_still_has_no_busy_error_type(_server) -> None:
    """The busy refusal is named for itself, not every failure of the tool."""
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.cli.mcp import source_delivery

    with patch.object(
        source_delivery, "set_source_git", side_effect=RuntimeError("clone failed")
    ):
        result = mcp_tools.mcp_set_source_git(
            url="https://example.com/repo.git", session_id=SESSION
        )

    assert result["success"] is False, result
    assert "error_type" not in result, result
    assert "clone failed" in result["error"], result
