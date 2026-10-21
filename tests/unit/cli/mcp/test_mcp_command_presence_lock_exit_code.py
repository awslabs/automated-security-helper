# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``PresenceLockError`` reaches the operator as its own message, exit 3.

The error's text carries the fix (set ``ASH_MCP_WORKSPACE_ROOT`` to a
filesystem that supports file locks). The catch-all handler used to bury it
under a traceback, "Unexpected error starting MCP server" and "check system
resources", exit 1. The command runs in-process with a stand-in server that
raises the error; no MCP server is started and nothing listens on a socket.
"""

from __future__ import annotations

import io

import pytest
import typer
from rich.console import Console

from automated_security_helper.cli.mcp import mcp_command
from automated_security_helper.cli.mcp.sessions import PresenceLockError

_MESSAGE = (
    "could not take the lock on this server's presence entry /ws/.stdio-servers/1-x: "
    "the filesystem refused it. Set ASH_MCP_WORKSPACE_ROOT to a directory on a "
    "filesystem that supports file locks."
)


class _Ctx:
    resilient_parsing = False


@pytest.fixture
def stderr(monkeypatch) -> io.StringIO:
    buffer = io.StringIO()
    monkeypatch.setattr(
        "automated_security_helper.cli.mcp._stderr",
        Console(file=buffer, width=400, color_system=None),
    )
    return buffer


def test_a_presence_lock_refusal_prints_its_own_message_and_exits_3(
    monkeypatch, stderr
) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)

    def stand_in_server() -> None:
        raise PresenceLockError(_MESSAGE)

    monkeypatch.setattr(
        "automated_security_helper.cli.mcp_server.run_mcp_server", stand_in_server
    )

    with pytest.raises(typer.Exit) as excinfo:
        mcp_command(ctx=_Ctx(), transport="stdio", host="127.0.0.1", quiet=False)

    assert excinfo.value.exit_code == 3
    message = " ".join(stderr.getvalue().split())
    assert "ASH_MCP_WORKSPACE_ROOT" in message, message
    assert "supports file locks" in message, message
    assert "Unexpected error starting MCP server" not in message, message
    assert "check system resources" not in message, message
