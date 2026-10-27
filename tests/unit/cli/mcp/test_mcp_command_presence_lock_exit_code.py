# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``PresenceLockError`` reaches the operator as its own message, exit 3.

The error's text names the entry, the error that refused its lock and the
option that moves the root (``ASH_MCP_WORKSPACE_ROOT``). The catch-all handler
would bury it under "MCP server failed" and "check system resources", exit 1.
The command prints it alone and exits 3. It runs in-process with a stand-in
server that raises the error; no MCP server is started and nothing listens on a
socket. The message is printed with ``--quiet`` as well, which hides log output
and not the reason the process stopped.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import typer

from automated_security_helper.cli.mcp import mcp_command
from automated_security_helper.cli.mcp.sessions import PresenceLockError

_RUN = "automated_security_helper.cli.mcp_server.run_mcp_server"
_DEPS = "automated_security_helper.cli.mcp.validate_mcp_dependencies"

_MESSAGE = (
    "could not take the lock on this server's presence entry /ws/.stdio-servers/1-x: "
    "the filesystem refused it (errno 28 ENOSPC: No space left on device). The lock "
    "on the registry's guard file under the same workspace root was granted, so the "
    "filesystem does lock files there; the error says what refused this one. Set "
    "ASH_MCP_WORKSPACE_ROOT to another directory to start on a different root."
)


@pytest.mark.parametrize("quiet", [False, True], ids=["default", "quiet"])
def test_a_presence_lock_refusal_prints_its_own_message_and_exits_3(
    quiet, capsys, monkeypatch
) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    ctx = MagicMock(spec=typer.Context)
    ctx.resilient_parsing = False

    with (
        patch(_DEPS, return_value=True),
        patch(_RUN, side_effect=PresenceLockError(_MESSAGE)),
    ):
        with pytest.raises(typer.Exit) as excinfo:
            mcp_command(ctx, transport="stdio", quiet=quiet)

    assert excinfo.value.exit_code == 3
    message = " ".join(capsys.readouterr().err.split())
    assert "ASH_MCP_WORKSPACE_ROOT" in message, message
    assert "errno 28 ENOSPC" in message, message
    assert "a filesystem that supports file locks" not in message, message
    assert "MCP server failed" not in message, message
    assert "check system resources" not in message, message
