# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A stateful app counts as issued only the sessions the SDK actually opened.

The SDK puts an ``Mcp-Session-Id`` on the response to a refused opening request
too, and then discards that session. ASH records an id only from a successful
response. When the SDK answers 404 on its own session path for an id ASH
recorded (the SDK discarded it, for example after its idle timeout), ASH ends
that session too. A 404 from the newer protocol's path, which can mean an
unknown method, ends nothing.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import sys
import zipfile
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from automated_security_helper.cli.mcp import build_streamable_http_app
from automated_security_helper.cli.mcp.http_sessions import (
    MODE_STATEFUL,
    MODE_STATELESS,
    SessionBoundary,
    caller_of,
)
from tests.utils.mcp_transport_harness import (
    LOOPBACK_BASE_URL,
    LOOPBACK_PORT,
    STREAMABLE_HEADERS,
    StreamableHttpClient,
    boundary_of,
)


@pytest.fixture(autouse=True)
def workspace(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "ws"
    root.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    return root


def _deliver(http: StreamableHttpClient, headers) -> Path:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("app.py", "print('hello')\n")
    data = buffer.getvalue()
    http.call_tool(
        "set_source_zip_chunk",
        {
            "upload_id": "u1",
            "sequence": 0,
            "data_b64": base64.b64encode(data).decode(),
            "last": True,
        },
        headers,
    )
    final = http.call_tool(
        "set_source_zip_finalize",
        {"upload_id": "u1", "expected_sha256": hashlib.sha256(data).hexdigest()},
        headers,
    )
    assert final.get("success") is True, final
    return Path(final["source_dir"]).parent


def test_refused_opening_requests_record_no_session() -> None:
    app = build_streamable_http_app(
        mount_path="/mcp", host="127.0.0.1", port=LOOPBACK_PORT
    )
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        statuses = {
            client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": n, "method": "tools/list"},
                headers=STREAMABLE_HEADERS,
            ).status_code
            for n in range(20)
        }
        issued = set(boundary_of(app)._issued)

    assert statuses and all(status >= 400 for status in statuses), statuses
    assert issued == set(), f"{len(issued)} refused requests were recorded as sessions"


def test_a_session_the_sdk_discarded_is_ended(workspace) -> None:
    from automated_security_helper.cli.mcp_server import mcp

    app = build_streamable_http_app(
        mount_path="/mcp", host="127.0.0.1", port=LOOPBACK_PORT
    )
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        http = StreamableHttpClient(client)
        session_id, headers = http.open_session()
        sandbox = _deliver(http, headers)
        # What the SDK does when the session idles out: it forgets the session.
        # Private SDK state, used here only to produce that end without a
        # 30-minute wait.
        mcp.session_manager._server_instances.pop(session_id)

        status, _message = http.rpc("tools/list", None, headers)
        remembered = session_id in boundary_of(app)._issued
        # Read before the client closes: shutdown ends every remembered session.
        still_on_disk = sandbox.exists()

    assert status == 404
    assert not remembered
    assert not still_on_disk, "the discarded session's workspace is still on disk"


@pytest.mark.parametrize(
    "path",
    ["/.well-known/oauth-protected-resource", "/health", "/mcp/x", "/"],
)
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_a_404_from_a_path_the_app_has_no_route_for_ends_nothing(
    workspace, path, method
) -> None:
    """A client that sends its session header to every path of the origin."""
    app = build_streamable_http_app(
        mount_path="/mcp", host="127.0.0.1", port=LOOPBACK_PORT
    )
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        http = StreamableHttpClient(client)
        session_id, headers = http.open_session()
        sandbox = _deliver(http, headers)
        response = client.request(
            method, path, headers={**STREAMABLE_HEADERS, **headers}
        )
        remembered = session_id in boundary_of(app)._issued
        still_on_disk = sandbox.is_dir()
        status, _message = http.rpc("tools/list", None, headers)

    assert response.status_code == 404, response.text[:200]
    assert remembered, "a 404 from no route ended the session"
    assert still_on_disk, "a 404 from no route removed the session's tree"
    assert status == 200


def test_a_404_on_the_endpoint_under_another_mount_path_still_ends_it(
    workspace,
) -> None:
    """The endpoint path is the one the app was built with, not always /mcp."""
    from automated_security_helper.cli.mcp_server import mcp

    app = build_streamable_http_app(
        mount_path="/ash/mcp", host="127.0.0.1", port=LOOPBACK_PORT
    )
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        http = StreamableHttpClient(client, mount_path="/ash/mcp")
        session_id, headers = http.open_session()
        sandbox = _deliver(http, headers)
        unrouted = client.get("/mcp", headers={**STREAMABLE_HEADERS, **headers})
        kept = sandbox.is_dir()
        mcp.session_manager._server_instances.pop(session_id)

        status, _message = http.rpc("tools/list", None, headers)
        remembered = session_id in boundary_of(app)._issued
        still_on_disk = sandbox.exists()

    assert unrouted.status_code == 404 and kept
    assert status == 404
    assert not remembered
    assert not still_on_disk


def test_a_404_on_the_newer_protocol_path_ends_nothing(workspace) -> None:
    app = build_streamable_http_app(
        mount_path="/mcp", host="127.0.0.1", port=LOOPBACK_PORT
    )
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        http = StreamableHttpClient(client)
        session_id, headers = http.open_session()
        sandbox = _deliver(http, headers)
        response = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 7,
                "method": "no/such-method",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities": {},
                    }
                },
            },
            headers={
                **STREAMABLE_HEADERS,
                "Mcp-Protocol-Version": "2026-07-28",
                "Mcp-Session-Id": session_id,
                "Mcp-Method": "no/such-method",
            },
        )
        remembered = session_id in boundary_of(app)._issued
        still_on_disk = sandbox.is_dir()

    assert response.status_code == 404, response.text[:200]
    assert remembered
    assert still_on_disk


def _stateful_boundary(response_headers=(), status: int = 200):
    """A stateful boundary over an app that answers ``status`` with these headers.

    Returns the boundary and the list of scopes the inner app was called with,
    so a test decides what the boundary sees without running the SDK.
    """
    seen: list = []

    async def inner(scope, receive, send) -> None:
        seen.append(scope)
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": list(response_headers),
            }
        )
        await send({"type": "http.response.body", "body": b""})

    boundary = SessionBoundary(inner, mode=MODE_STATEFUL, endpoint_path="/mcp")
    # No workspace sweep: these drive the boundary alone.
    boundary._next_sweep = float("inf")
    return boundary, seen


def _call(boundary: SessionBoundary, method: str = "POST", headers=()) -> None:
    """One request to the boundary's endpoint path."""

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message) -> None:
        return None

    scope = {
        "type": "http",
        "method": method,
        "path": "/mcp",
        "root_path": "",
        "query_string": b"",
        "headers": list(headers),
    }
    asyncio.run(boundary(scope, receive, send))


def _drive(response_headers, request_headers) -> SessionBoundary:
    """One POST through a stateful boundary whose app answers 200."""
    boundary, _seen = _stateful_boundary(response_headers=response_headers)
    _call(boundary, headers=request_headers)
    return boundary


class TestStatefulBoundaryRecordsOnlyIssuedIds:
    def test_a_2xx_echoing_a_client_chosen_header_is_not_recorded(self) -> None:
        boundary = _drive(
            [(b"mcp-session-id", b"client-chosen")],
            [(b"mcp-session-id", b"client-chosen")],
        )

        assert boundary._issued == set()

    def test_an_id_on_a_response_to_a_request_without_one_is_recorded(self) -> None:
        boundary = _drive([(b"mcp-session-id", b"server-issued")], [])

        assert boundary._issued == {"server-issued"}

    def test_a_2xx_carrying_another_id_than_the_request_names_is_not_recorded(
        self,
    ) -> None:
        boundary = _drive([(b"mcp-session-id", b"B")], [(b"mcp-session-id", b"A")])

        assert boundary._issued == set()

    def test_an_id_on_the_newer_protocols_sessionless_path_is_not_recorded(
        self,
    ) -> None:
        boundary = _drive(
            [(b"mcp-session-id", b"fresh")],
            [(b"mcp-protocol-version", b"2026-07-28")],
        )

        assert boundary._issued == set()

    def test_the_session_path_is_decided_once_per_request(self, monkeypatch) -> None:
        from automated_security_helper.cli.mcp import http_sessions

        real = http_sessions._through_the_sdk_session_check
        calls: list = []

        def counting(scope, handshake_versions):
            calls.append(scope.get("method"))
            return real(scope, handshake_versions)

        monkeypatch.setattr(http_sessions, "_through_the_sdk_session_check", counting)

        _drive([(b"mcp-session-id", b"server-issued")], [])

        assert len(calls) == 1


def test_a_stateful_boundary_cannot_be_built_without_the_sdks_version_list(
    monkeypatch,
) -> None:
    monkeypatch.setitem(sys.modules, "mcp_types.version", None)

    with pytest.raises(RuntimeError, match="mcp_types.version"):
        _stateful_boundary()


def test_a_stateless_boundary_does_not_need_the_sdks_version_list(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "mcp_types.version", None)

    async def app(scope, receive, send):  # pragma: no cover - never called
        raise AssertionError("called")

    assert SessionBoundary(app, mode=MODE_STATELESS).mode == MODE_STATELESS


def test_the_version_list_is_read_once_and_not_on_each_request(monkeypatch) -> None:
    boundary, seen = _stateful_boundary()
    boundary._issued.add("issued-id")
    # An import that fails after the boundary was built changes nothing.
    monkeypatch.setitem(sys.modules, "mcp_types.version", None)

    _call(boundary, headers=[(b"mcp-session-id", b"issued-id")])

    caller = caller_of(seen[-1])
    assert caller is not None and caller.session_id == "issued-id"


@pytest.mark.parametrize(
    ("protocol_header", "ends_the_session"),
    [
        pytest.param([], True, id="no-protocol-header"),
        pytest.param([(b"mcp-protocol-version", b"2025-06-18")], True, id="handshake"),
        pytest.param([(b"mcp-protocol-version", b"2026-07-28")], False, id="newer"),
    ],
)
def test_a_delete_ends_the_session_only_on_a_handshake_protocol_version(
    monkeypatch, protocol_header, ends_the_session
) -> None:
    ended: list = []
    monkeypatch.setattr(
        "automated_security_helper.cli.mcp.sessions.end_session", ended.append
    )
    boundary, _seen = _stateful_boundary()
    boundary._issued.add("issued-id")

    _call(
        boundary,
        method="DELETE",
        headers=[(b"mcp-session-id", b"issued-id"), *protocol_header],
    )

    assert ended == (["issued-id"] if ends_the_session else [])
    assert ("issued-id" in boundary._issued) is (not ends_the_session)


def test_a_newer_protocol_delete_leaves_the_session_workspace(workspace) -> None:
    app = build_streamable_http_app(
        mount_path="/mcp", host="127.0.0.1", port=LOOPBACK_PORT
    )
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        http = StreamableHttpClient(client)
        session_id, headers = http.open_session()
        sandbox = _deliver(http, headers)
        status = http.end_session({**headers, "Mcp-Protocol-Version": "2026-07-28"})
        remembered = session_id in boundary_of(app)._issued
        still_on_disk = sandbox.exists()

    assert remembered, f"the session was forgotten (DELETE answered {status})"
    assert still_on_disk, f"the workspace was removed (DELETE answered {status})"


def test_a_stateful_boundary_needs_the_endpoint_path() -> None:
    from automated_security_helper.cli.mcp.http_sessions import MODE_STATEFUL

    async def app(scope, receive, send):  # pragma: no cover - never called
        raise AssertionError("called")

    with pytest.raises(ValueError, match="endpoint path"):
        SessionBoundary(app, mode=MODE_STATEFUL)
