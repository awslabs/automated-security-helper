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

import base64
import hashlib
import io
import zipfile
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from automated_security_helper.cli.mcp import build_streamable_http_app
from automated_security_helper.cli.mcp.http_sessions import SessionBoundary
from tests.utils.mcp_transport_harness import (
    LOOPBACK_BASE_URL,
    LOOPBACK_PORT,
    STREAMABLE_HEADERS,
    StreamableHttpClient,
)


@pytest.fixture(autouse=True)
def workspace(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "ws"
    root.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    return root


def _boundary(app: Any) -> SessionBoundary:
    """The SessionBoundary instance in a built app's middleware stack."""
    layer = app.middleware_stack
    while layer is not None and not isinstance(layer, SessionBoundary):
        layer = getattr(layer, "app", None)
    assert isinstance(layer, SessionBoundary), "no SessionBoundary in the stack"
    return layer


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
        issued = set(_boundary(app)._issued)

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
        remembered = session_id in _boundary(app)._issued
        # Read before the client closes: shutdown ends every remembered session.
        still_on_disk = sandbox.exists()

    assert status == 404
    assert not remembered
    assert not still_on_disk, "the discarded session's workspace is still on disk"


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
        remembered = session_id in _boundary(app)._issued
        still_on_disk = sandbox.is_dir()

    assert response.status_code == 404, response.text[:200]
    assert remembered
    assert still_on_disk
