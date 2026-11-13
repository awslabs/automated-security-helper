# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""check_installation withholds the server's ``ash`` path from a network caller
that names no session.

Why this file exists
--------------------
``ash_command_output`` is a path in the server's filesystem, so only the client
that launched the server may read it. Whether a call is that client's is decided
by ``sandbox.caller_is_remote(session_id)`` from the session id alone: ``ash
mcp`` deliberately does not record its transport, so ``ASH_MCP_TRANSPORT`` is
unset unless an operator sets it.

The tool once took that id from the request headers (``resolve_session_id``),
which answers ``DEFAULT_SESSION_ID`` -- the local client's id -- for a request
with no ``Mcp-Session-Id`` header. A caller of a stateless streamable-HTTP
server sends none, so it was read as the local client and handed the path, and
a header spelling ``DEFAULT_SESSION_ID`` did the same. The transport decides
instead (``resolve_caller_session_id``): a network call with no session the
server issued is ``UNIDENTIFIED_SESSION_ID``, which is remote.

Each case below is a context the MCP SDK built (a subclass of its ``Context``),
as a tool call over the network or stdio is, with the request a transport
would put behind it. The cases that pass before and after the change are the
controls: the local client keeps the path, and a session the server issued is
remote.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, Callable, Dict, Optional
from unittest.mock import patch

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli import mcp_server, mcp_tools
from automated_security_helper.cli.mcp.http_sessions import (
    CALLER_SCOPE_KEY,
    STREAMABLE_HTTP,
    HttpCaller,
)
from automated_security_helper.cli.mcp.profile_registry import DEFAULT_SESSION_ID
from automated_security_helper.cli.mcp.session_identity import serving_local_client

pytestmark = pytest.mark.unit

#: Where the server's ash executable is, which a remote client must not learn.
HIDDEN_ASH = "/opt/operator-only/bin/ash"

#: What a remote client is told instead: that there is one, not where.
REMOTE_ANSWER = "an ash executable is on the server's PATH"


class _SdkContext(Context):
    """A Context of the SDK's class, with no peer for the tool's log messages."""

    async def info(self, data: Any, *, logger_name: Optional[str] = None) -> None:
        return None

    async def error(self, data: Any, *, logger_name: Optional[str] = None) -> None:
        return None


def _context(request: Optional[SimpleNamespace]) -> _SdkContext:
    return _SdkContext(request_context=SimpleNamespace(request=request))


def _request(headers: Dict[str, str], caller: Optional[HttpCaller]) -> SimpleNamespace:
    """The request a transport puts behind a tool call, stamped as ASH stamps one."""
    scope: Dict[str, Any] = {}
    if caller is not None:
        scope[CALLER_SCOPE_KEY] = caller
    return SimpleNamespace(headers=headers, scope=scope)


#: Callers that reach the tool over the network, or from outside the local
#: client, with no session the server issued.
NO_SESSION_CALLERS: Dict[str, Callable[[], _SdkContext]] = {
    "stateless-server-no-header": lambda: _context(
        _request({"host": "ash.example"}, HttpCaller(STREAMABLE_HTTP, None))
    ),
    "http-app-ash-did-not-build-no-header": lambda: _context(
        _request({"host": "ash.example"}, None)
    ),
    "stateless-server-header-spells-the-local-clients-id": lambda: _context(
        _request(
            {"mcp-session-id": DEFAULT_SESSION_ID}, HttpCaller(STREAMABLE_HTTP, None)
        )
    ),
    "no-request-outside-the-local-client": lambda: _context(None),
}


def _entry() -> Dict[str, Any]:
    return {
        "name": "bandit",
        "enabled": True,
        "dependencies_satisfied": True,
        "version": "1.0",
        "offline_strategy": "bundled",
        "installs_on_first_scan": False,
    }


@pytest.fixture
def ash_is_installed(monkeypatch):
    """The scanners answer, and ``ash`` is on the server's PATH at HIDDEN_ASH."""
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    with (
        patch.object(mcp_tools, "list_scanner_inventory", return_value=[_entry()]),
        patch("shutil.which", return_value=HIDDEN_ASH),
    ):
        yield


@pytest.mark.asyncio
@pytest.mark.parametrize("make", NO_SESSION_CALLERS.values(), ids=NO_SESSION_CALLERS)
async def test_a_network_caller_with_no_session_is_not_told_where_ash_is(
    make, ash_is_installed
):
    result = await mcp_server.check_installation(make())

    assert result["success"] is True, result
    assert result["ash_command_available"] is True, result
    assert result["ash_command_output"] == REMOTE_ANSWER, result
    assert HIDDEN_ASH not in json.dumps(result), result


@pytest.mark.asyncio
async def test_a_session_the_server_issued_is_not_told_where_ash_is(ash_is_installed):
    request = _request(
        {"mcp-session-id": "issued-session-1"},
        HttpCaller(STREAMABLE_HTTP, "issued-session-1"),
    )

    result = await mcp_server.check_installation(_context(request))

    assert result["ash_command_output"] == REMOTE_ANSWER, result
    assert HIDDEN_ASH not in json.dumps(result), result


@pytest.mark.asyncio
async def test_the_local_client_is_still_told_where_ash_is(ash_is_installed):
    """The control: stdio's client, which launched the server, keeps the path."""
    with serving_local_client():
        result = await mcp_server.check_installation(_context(None))

    assert result["success"] is True, result
    assert result["ash_command_output"] == HIDDEN_ASH, result
