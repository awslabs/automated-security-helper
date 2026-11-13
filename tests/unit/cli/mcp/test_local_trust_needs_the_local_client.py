# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""stdio's local trust goes only to a caller ASH knows is the local client.

``run_mcp_server`` (stdio) serves inside ``serving_local_client()``, and so does
an in-process client its embedder drives. Inside it, an MCP SDK Context with no
HTTP request behind it is ``__default__``, stdio's session with local trust.
Anywhere else such a Context is ``__unidentified__``: remote, with no sandbox.
A real stdio server keeping local trust is covered by
``test_stdio_servers_share_the_default_workspace.py``, which delivers a tree
through ``ash mcp`` and finds it in ``__default__``.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli.mcp.profile_registry import DEFAULT_SESSION_ID
from automated_security_helper.cli.mcp.session_identity import (
    SESSION_IDENTITY_REQUIRED,
    UNIDENTIFIED_SESSION_ID,
    resolve_caller_session_id,
)

pytestmark = pytest.mark.unit


def _request_is_none() -> Context:
    return Context(request_context=SimpleNamespace(request=None))


CONTEXTS = pytest.mark.parametrize(
    "make", [Context, _request_is_none], ids=["outside-a-request", "request-is-none"]
)


@CONTEXTS
def test_a_context_without_a_request_is_unidentified(make) -> None:
    assert resolve_caller_session_id(make()) == UNIDENTIFIED_SESSION_ID


@CONTEXTS
def test_the_local_client_keeps_local_trust(make) -> None:
    from automated_security_helper.cli.mcp.session_identity import (
        serving_local_client,
    )

    with serving_local_client():
        assert resolve_caller_session_id(make()) == DEFAULT_SESSION_ID
    assert resolve_caller_session_id(make()) == UNIDENTIFIED_SESSION_ID


def test_an_in_memory_client_not_marked_local_has_no_session() -> None:
    from mcp import Client

    from automated_security_helper.cli.mcp_server import mcp

    async def main():
        async with Client(mcp, raise_exceptions=True) as client:
            return await client.call_tool("clear_source", {})

    result = asyncio.run(main())

    payload = result.structured_content["result"]
    assert payload.get("success") is False, payload
    assert payload.get("error_type") == SESSION_IDENTITY_REQUIRED, payload
