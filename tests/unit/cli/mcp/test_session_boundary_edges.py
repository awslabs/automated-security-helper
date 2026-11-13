# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The edges of ``SessionBoundary`` and ``caller_of`` that no transport test reaches.

* The constructor refuses a mode it does not know, a time to live that is not
  positive, and a stateful boundary with no endpoint path.
* When the SDK's protocol-version list cannot be imported, no request counts as
  being on the SDK's session path, so a 404 never ends a session.
* An sse session id is taken only if it is a UUID spelling and the server issued
  it: a query value that matches the endpoint pattern but is no UUID, and a
  well-formed UUID nobody issued, both carry no identity.
* A websocket scope passes through untouched: no stamp, no sweep.
* ``caller_of`` returns only a real stamp, and a stamp whose id is only
  whitespace names no session.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any, Dict, List

import anyio
import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp.http_sessions import (
    CALLER_SCOPE_KEY,
    MODE_SSE,
    MODE_STATEFUL,
    MODE_STATELESS,
    SSE,
    STREAMABLE_HTTP,
    HttpCaller,
    SessionBoundary,
    _canonical_sse_session,
    _on_the_sdk_session_path,
    caller_of,
)
from automated_security_helper.cli.mcp.session_identity import (
    UNIDENTIFIED_SESSION_ID,
    resolve_caller_session_id,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _workspace_root(tmp_path, monkeypatch) -> None:
    """Keep the sweep a request starts away from any real workspace root."""
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "ws"))
    sessions.reset_default_registry_for_tests()
    yield
    sessions.reset_default_registry_for_tests()


async def _noop_app(scope, receive, send) -> None:
    return None


async def _receive() -> Dict[str, Any]:
    return {"type": "http.request", "body": b"", "more_body": False}


# -- constructor guards ---------------------------------------------------------


@pytest.mark.parametrize(
    "mode", ["", "bogus", "STATEFUL"], ids=["empty", "bogus", "uppercase"]
)
def test_an_unknown_mode_is_refused(mode) -> None:
    with pytest.raises(ValueError, match="unknown session boundary mode"):
        SessionBoundary(_noop_app, mode=mode)


@pytest.mark.parametrize("ttl", [0, -1, -0.5], ids=["zero", "minus-one", "minus-half"])
def test_a_time_to_live_that_is_not_positive_is_refused(ttl) -> None:
    with pytest.raises(ValueError, match="positive number"):
        SessionBoundary(_noop_app, mode=MODE_STATELESS, session_workspace_ttl=ttl)


@pytest.mark.parametrize("endpoint_path", [None, ""], ids=["none", "empty"])
def test_a_stateful_boundary_needs_its_endpoint_path(endpoint_path) -> None:
    with pytest.raises(ValueError, match="needs the endpoint path"):
        SessionBoundary(_noop_app, mode=MODE_STATEFUL, endpoint_path=endpoint_path)


def test_the_guards_do_not_refuse_valid_arguments() -> None:
    SessionBoundary(_noop_app, mode=MODE_STATEFUL, endpoint_path="/mcp")
    SessionBoundary(_noop_app, mode=MODE_STATELESS)
    SessionBoundary(_noop_app, mode=MODE_SSE, session_workspace_ttl=0.5)


# -- the SDK session path needs the path and the hoisted version check ------------
# The version list itself is read when the app is built (see
# test_stateful_issued_sessions.test_the_app_build_itself_fails_without_the_sdks_version_list);
# this function only combines the route match with that hoisted check's answer.


def test_the_sdk_session_path_needs_the_path_and_the_version_check() -> None:
    scope = {"path": "/mcp", "root_path": "", "headers": []}
    assert _on_the_sdk_session_path(scope, "/mcp", True) is True
    assert _on_the_sdk_session_path(scope, "/mcp", False) is False
    assert _on_the_sdk_session_path(scope, "/other", True) is False


# -- sse session ids ------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    ["-" * 32, "0" * 31 + "-", "-" * 36],
    ids=["dashes-32", "zeros-31-and-dash", "dashes-36"],
)
def test_a_pattern_valid_value_that_is_no_uuid_names_no_session(raw) -> None:
    assert _canonical_sse_session(raw) is None


def test_every_uuid_spelling_reads_as_the_hex_form() -> None:
    issued = uuid.uuid4()
    assert _canonical_sse_session(issued.hex) == issued.hex
    assert _canonical_sse_session(str(issued)) == issued.hex
    assert _canonical_sse_session(str(issued).upper()) == issued.hex


def test_a_non_uuid_id_in_the_endpoint_event_is_not_issued(monkeypatch) -> None:
    ended: List[str] = []
    monkeypatch.setattr(sessions, "end_session", lambda sid: ended.append(sid))
    body = b"event: endpoint\ndata: /messages/?session_id=" + b"-" * 32 + b"\n\n"

    async def app(scope, receive, send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": body})

    boundary = SessionBoundary(app, mode=MODE_SSE)
    sent: List[Dict[str, Any]] = []

    async def send(message: Dict[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/sse",
        "root_path": "",
        "headers": [],
        "query_string": b"",
    }

    async def main() -> None:
        await boundary(scope, _receive, send)

    anyio.run(main)

    assert [m["type"] for m in sent] == ["http.response.start", "http.response.body"]
    assert boundary._issued == set()
    # No session was recognized, so the finished stream ends none.
    assert ended == []


def _sse_scope(session_id: str) -> Dict[str, Any]:
    return {
        "type": "http",
        "method": "POST",
        "path": "/messages/",
        "root_path": "",
        "headers": [(b"mcp-session-id", b"header-is-ignored")],
        "query_string": f"session_id={session_id}".encode(),
    }


def test_a_well_formed_session_id_nobody_issued_carries_no_identity() -> None:
    boundary = SessionBoundary(_noop_app, mode=MODE_SSE)
    issued = uuid.uuid4().hex
    forged = uuid.uuid4().hex
    boundary._issued.add(issued)

    assert boundary._identify(_sse_scope(issued), True) == HttpCaller(
        SSE, issued, server_mode=MODE_SSE
    )
    assert boundary._identify(_sse_scope(forged), True) == HttpCaller(
        SSE, None, server_mode=MODE_SSE
    )
    assert boundary._identify(_sse_scope("-" * 32), True) == HttpCaller(
        SSE, None, server_mode=MODE_SSE
    )


# -- other scope types ----------------------------------------------------------


def test_a_websocket_scope_passes_through_unchanged(monkeypatch) -> None:
    swept: List[float] = []
    monkeypatch.setattr(
        sessions,
        "sweep_stale_workspaces",
        lambda ttl, now=None, in_use=None: swept.append(ttl),
    )
    seen: Dict[str, Any] = {}

    async def app(scope, receive, send) -> None:
        seen["scope"], seen["receive"], seen["send"] = scope, receive, send

    boundary = SessionBoundary(app, mode=MODE_STATELESS)
    scope = {"type": "websocket", "path": "/ws", "headers": []}

    async def send(message: Dict[str, Any]) -> None:
        return None

    async def main() -> None:
        await boundary(scope, _receive, send)

    anyio.run(main)

    assert seen["scope"] is scope
    assert seen["send"] is send
    assert CALLER_SCOPE_KEY not in scope
    assert swept == []


# -- caller_of and a stamp's whitespace id ----------------------------------------


@pytest.mark.parametrize(
    "scope",
    [None, "scope", 5, ["ash.mcp.caller"], b""],
    ids=["none", "string", "int", "list", "bytes"],
)
def test_caller_of_a_non_dict_is_none(scope) -> None:
    assert caller_of(scope) is None


def test_caller_of_an_unstamped_or_misstamped_scope_is_none() -> None:
    assert caller_of({}) is None
    assert caller_of({"path": "/mcp"}) is None
    assert caller_of({CALLER_SCOPE_KEY: None}) is None
    assert caller_of({CALLER_SCOPE_KEY: "streamable-http"}) is None
    # Looks like a stamp and is not one.
    lookalike = SimpleNamespace(transport=STREAMABLE_HTTP, session_id="real-id")
    assert caller_of({CALLER_SCOPE_KEY: lookalike}) is None


def test_caller_of_a_real_stamp_is_that_stamp() -> None:
    stamp = HttpCaller(STREAMABLE_HTTP, "sess-1")
    assert caller_of({CALLER_SCOPE_KEY: stamp}) is stamp


def _context(scope: Any) -> Context:
    return Context(
        request_context=SimpleNamespace(request=SimpleNamespace(scope=scope))
    )


@pytest.mark.parametrize(
    "session_id",
    ["", " ", "   ", "\t", " \n "],
    ids=["empty", "space", "spaces", "tab", "space-newline"],
)
def test_a_stamp_whose_id_is_only_whitespace_names_no_session(session_id) -> None:
    ctx = _context({CALLER_SCOPE_KEY: HttpCaller(STREAMABLE_HTTP, session_id)})

    assert resolve_caller_session_id(ctx) == UNIDENTIFIED_SESSION_ID


def test_a_stamp_with_a_real_id_names_that_session() -> None:
    ctx = _context({CALLER_SCOPE_KEY: HttpCaller(STREAMABLE_HTTP, " sess-1 ")})

    assert resolve_caller_session_id(ctx) == "sess-1"


@pytest.mark.parametrize("header", [b"   ", b"\t", b""], ids=["spaces", "tab", "empty"])
def test_a_trusted_upstream_header_of_whitespace_carries_no_identity(header) -> None:
    boundary = SessionBoundary(
        _noop_app, mode=MODE_STATELESS, trust_upstream_session_id=True
    )
    scope = {"type": "http", "headers": [(b"mcp-session-id", header)]}

    assert boundary._identify(scope, True) == HttpCaller(
        STREAMABLE_HTTP, None, server_mode=MODE_STATELESS
    )


def test_a_trusted_upstream_header_is_taken_without_its_padding() -> None:
    boundary = SessionBoundary(
        _noop_app, mode=MODE_STATELESS, trust_upstream_session_id=True
    )
    scope = {"type": "http", "headers": [(b"mcp-session-id", b"  plat-1 ")]}

    assert boundary._identify(scope, True) == HttpCaller(
        STREAMABLE_HTTP, "plat-1", server_mode=MODE_STATELESS
    )
