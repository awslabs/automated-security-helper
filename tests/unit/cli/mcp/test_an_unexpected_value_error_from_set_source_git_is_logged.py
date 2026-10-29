# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ValueError nothing expected is logged as unexpected, not renamed a failed clone.

``mcp_set_source_git`` answers each failure it expects with the type that names it:
a refused url, ref, depth or host, a busy session, a timeout, a workspace that cannot
be prepared, git failing, and ``InvalidSessionIdError`` (a ``ValueError``) for the
session id. A last ``except ValueError`` also answered every other ``ValueError`` as
``git_clone_failed``, without a log line. That is the label for git having failed,
and an error from a bug in a later change is not that: the client was told git
failed, and the operator had nothing to read.

Without that arm the error reaches the tool's own handler in ``mcp_server``, which
logs it as unexpected (``log_unexpected_error``, with its traceback and the context
``Error in set_source_git``) and answers ``error_type`` with the exception's class
name. The tests drive the tool, with a substitute for ``set_source_git`` that raises.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli import mcp_server
from automated_security_helper.cli.mcp import source_delivery as sd

URL = "https://git.example.invalid/team/repo.git"


class PlantedValueError(ValueError):
    """A ValueError subclass of this test's own, so its class name is unmistakable."""


@pytest.fixture
def logged(monkeypatch) -> List[Tuple[str, Any]]:
    """What ``log_unexpected_error`` was asked to log: the class name and context."""
    calls: List[Tuple[str, Any]] = []

    def record(logger, error, context=None, values=()) -> None:
        calls.append((type(error).__name__, context))

    monkeypatch.setattr(mcp_server, "log_unexpected_error", record)
    return calls


@pytest.fixture(autouse=True)
def _a_listed_host(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.invalid")
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setattr(sd, "_SESSION_SOURCE_DIRS", {})


def _ctx() -> MagicMock:
    ctx = MagicMock(spec=Context)
    ctx.headers = {}
    return ctx


def _raising(error: BaseException):
    def raiser(**_arguments: Any) -> Any:
        raise error

    return raiser


@pytest.mark.asyncio
async def test_a_value_error_from_the_delivery_is_logged_and_keeps_its_class_name(
    monkeypatch, logged
) -> None:
    monkeypatch.setattr(sd, "set_source_git", _raising(PlantedValueError("a bug")))

    result: Dict[str, Any] = await mcp_server.set_source_git(_ctx(), url=URL)

    assert logged == [("PlantedValueError", "Error in set_source_git")]
    assert result["success"] is False, result
    assert result["error_type"] == "PlantedValueError", result
    assert "a bug" in result["error"], result


@pytest.mark.asyncio
async def test_the_session_id_refusal_is_still_invalid_session_id_and_is_not_logged(
    monkeypatch, logged
) -> None:
    """Control: ``InvalidSessionIdError`` is a ``ValueError`` the wrapper expects."""
    monkeypatch.setattr(
        sd, "set_source_git", _raising(sd.InvalidSessionIdError("not a session"))
    )

    result = await mcp_server.set_source_git(_ctx(), url=URL)

    assert result["error_type"] == "invalid_session_id", result
    assert logged == []


@pytest.mark.asyncio
async def test_a_git_failure_is_still_git_clone_failed_and_is_not_logged(
    monkeypatch, logged
) -> None:
    """Control: what the wrapper expects from git keeps its type and logs nothing as
    unexpected."""
    monkeypatch.setattr(
        sd,
        "set_source_git",
        _raising(sd.GitCommandError("git clone failed", "git_clone_failed")),
    )

    result = await mcp_server.set_source_git(_ctx(), url=URL)

    assert result["error_type"] == "git_clone_failed", result
    assert logged == []
