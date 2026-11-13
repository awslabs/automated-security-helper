# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An sse stream's session is read from its endpoint event and from nothing else.

``SessionBoundary`` reads the session the server issued for an sse stream from
the ``session_id`` of the endpoint URL the SDK writes as the stream's first
event. When that event carries no ``session_id``, the stream carries no
identity, and a later message on the stream, whose body is content the server
relays (a tool result that quotes a URL, say), must not make the boundary adopt
an id as one this app issued, nor end that id's session when the stream
finishes. A ping comment before the endpoint event carries no field and is
passed over; a message after it changes nothing.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Tuple

import anyio
import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp.http_sessions import MODE_SSE, SessionBoundary

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _workspace_root(tmp_path, monkeypatch) -> None:
    """Keep the registry a stream touches away from any real workspace root."""
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "ws"))
    sessions.reset_default_registry_for_tests()
    yield
    sessions.reset_default_registry_for_tests()


def _endpoint_event(session_id: str = "") -> bytes:
    query = f"?session_id={session_id}" if session_id else ""
    return f"event: endpoint\r\ndata: /messages/{query}\r\n\r\n".encode("ascii")


def _message_event(text: str) -> bytes:
    return f'event: message\r\ndata: {{"text": "{text}"}}\r\n\r\n'.encode("ascii")


async def _receive() -> Dict[str, Any]:
    return {"type": "http.request", "body": b"", "more_body": False}


def _serve_stream(
    chunks: List[bytes], monkeypatch
) -> Tuple[SessionBoundary, List[str], List[Dict[str, Any]]]:
    """Serve one GET stream whose body is ``chunks``; return what the boundary did."""
    ended: List[str] = []
    monkeypatch.setattr(sessions, "end_session", lambda sid: ended.append(sid))
    monkeypatch.setattr(
        sessions, "sweep_stale_workspaces", lambda ttl, now=None, in_use=None: []
    )

    async def app(scope, receive, send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        for chunk in chunks:
            await send({"type": "http.response.body", "body": chunk, "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

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
    return boundary, ended, sent


def test_an_endpoint_event_without_a_session_id_leaves_later_messages_unread(
    monkeypatch,
) -> None:
    """A relayed message naming a session-shaped id issues nothing and ends nothing."""
    planted = uuid.uuid4().hex
    chunks = [_endpoint_event(), _message_event(f"see /messages/?session_id={planted}")]

    boundary, ended, sent = _serve_stream(chunks, monkeypatch)

    assert boundary._issued == set()
    assert ended == []
    # The stream itself passes through unchanged.
    bodies = [m["body"] for m in sent if m["type"] == "http.response.body"]
    assert bodies == [*chunks, b""]


def test_the_endpoint_events_session_id_is_issued_and_ended_with_the_stream(
    monkeypatch,
) -> None:
    issued = uuid.uuid4().hex

    boundary, ended, _sent = _serve_stream([_endpoint_event(issued)], monkeypatch)

    assert ended == [issued]
    assert boundary._issued == set()


def test_a_ping_comment_before_the_endpoint_event_is_passed_over(monkeypatch) -> None:
    issued = uuid.uuid4().hex
    chunks = [b": ping\r\n\r\n", _endpoint_event(issued)]

    _boundary, ended, _sent = _serve_stream(chunks, monkeypatch)

    assert ended == [issued]


def test_a_message_after_the_endpoint_event_does_not_change_the_session(
    monkeypatch,
) -> None:
    issued = uuid.uuid4().hex
    other = uuid.uuid4().hex
    chunks = [
        _endpoint_event(issued),
        _message_event(f"see /messages/?session_id={other}"),
    ]

    _boundary, ended, _sent = _serve_stream(chunks, monkeypatch)

    assert ended == [issued]
