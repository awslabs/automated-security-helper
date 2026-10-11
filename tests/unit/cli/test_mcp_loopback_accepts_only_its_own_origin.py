# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A loopback server accepts only its own origin.

On a loopback bind the MCP SDK's own check accepts Host ``127.0.0.1:*``,
``localhost:*`` and ``[::1]:*`` and the matching ``http://`` origins on any
port. So a page served by any other local web server -- a dev server on another
port, say -- passes the Origin check and can drive the MCP server from the
user's browser. ASH now accepts only the port the server is bound to: Host
``127.0.0.1:PORT``, ``localhost:PORT`` or ``[::1]:PORT``, and those as
``http://`` origins. A request without an Origin (every non-browser client)
is unaffected.
"""

from __future__ import annotations

from typing import Dict, Optional

import pytest
from starlette.testclient import TestClient

from automated_security_helper.cli.mcp import build_sse_app, build_streamable_http_app

PORT = 8765

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "ash-test", "version": "0"},
    },
}
STREAMABLE_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


def _headers(host: str, origin: Optional[str], base: Dict[str, str]) -> Dict[str, str]:
    # Host is set explicitly: TestClient cannot parse a bracketed IPv6 base URL.
    headers = {**base, "Host": host}
    if origin:
        headers["Origin"] = origin
    return headers


def _streamable_status(host: str, origin: Optional[str]) -> int:
    app = build_streamable_http_app(mount_path="/mcp", host="127.0.0.1", port=PORT)
    with TestClient(app, base_url=f"http://127.0.0.1:{PORT}") as client:
        return client.post(
            "/mcp", json=INITIALIZE, headers=_headers(host, origin, STREAMABLE_HEADERS)
        ).status_code


def _sse_status(host: str, origin: Optional[str]) -> int:
    """POST to the message endpoint; past the Host/Origin check the SDK answers 400."""
    app = build_sse_app(mount_path="/sse", host="127.0.0.1", port=PORT)
    with TestClient(app, base_url=f"http://127.0.0.1:{PORT}") as client:
        return client.post(
            "/messages/",
            json=INITIALIZE,
            headers=_headers(host, origin, {"Content-Type": "application/json"}),
        ).status_code


OWN_HOST = f"127.0.0.1:{PORT}"
OWN = f"http://{OWN_HOST}"


@pytest.mark.parametrize("status", [_streamable_status, _sse_status])
@pytest.mark.parametrize(
    "origin",
    [
        "http://localhost:3000",
        "http://127.0.0.1:9999",
        "http://[::1]:5173",
        f"https://127.0.0.1:{PORT}",
        "http://evil.example",
    ],
)
def test_another_origin_is_refused(status, origin) -> None:
    assert status(OWN_HOST, origin) == 403


@pytest.mark.parametrize("status", [_streamable_status, _sse_status])
@pytest.mark.parametrize(
    "host", ["127.0.0.1:9999", "localhost:3000", "[::1]:5173", "127.0.0.1"]
)
def test_another_port_in_the_host_is_refused(status, host) -> None:
    assert status(host, None) == 421


@pytest.mark.parametrize(
    "host, origin",
    [
        (OWN_HOST, None),
        (OWN_HOST, OWN),
        (f"localhost:{PORT}", f"http://localhost:{PORT}"),
        (f"[::1]:{PORT}", f"http://[::1]:{PORT}"),
    ],
)
def test_the_servers_own_origin_is_served(host, origin) -> None:
    assert _streamable_status(host, origin) == 200
    assert _sse_status(host, origin) == 400


def test_mcp_command_builds_for_the_port_it_binds(monkeypatch) -> None:
    from automated_security_helper.cli.mcp import mcp_command

    seen = {}

    def _build(**kwargs):
        seen.update(kwargs)
        return object()

    class _Ctx:
        resilient_parsing = False

    monkeypatch.setattr(
        "automated_security_helper.cli.mcp.build_streamable_http_app", _build
    )
    monkeypatch.setattr(
        "automated_security_helper.cli.mcp._run_uvicorn",
        lambda app, host, port, log_level: seen.update(bound_port=port),
    )

    mcp_command(
        ctx=_Ctx(), transport="streamable-http", host="127.0.0.1", port=PORT, quiet=True
    )

    assert seen.get("port") == seen.get("bound_port") == PORT
