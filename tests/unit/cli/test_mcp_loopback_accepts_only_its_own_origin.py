# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A loopback server accepts only its own origin.

The MCP SDK's own loopback check accepts Host ``127.0.0.1:*``, ``localhost:*``
and ``[::1]:*`` and the matching ``http://`` origins on any port. ASH accepts
only the port the server is bound to: Host ``127.0.0.1:PORT``,
``localhost:PORT`` or ``[::1]:PORT``, and those as ``http://`` origins. A
request without an Origin (every non-browser client) needs only the right Host.
"""

from __future__ import annotations

from typing import Dict, Optional

import pytest
import typer
from starlette.testclient import TestClient

from automated_security_helper.cli.mcp import (
    build_sse_app,
    build_streamable_http_app,
    mcp_command,
)
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.core.exceptions import ASHValidationError

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


def _post_streamable(app, port: int, host: str, origin: Optional[str]) -> int:
    with TestClient(app, base_url=f"http://127.0.0.1:{port}") as client:
        return client.post(
            "/mcp", json=INITIALIZE, headers=_headers(host, origin, STREAMABLE_HEADERS)
        ).status_code


def _post_sse(app, port: int, host: str, origin: Optional[str]) -> int:
    """POST to the message endpoint; past the Host/Origin check the SDK answers 400."""
    with TestClient(app, base_url=f"http://127.0.0.1:{port}") as client:
        return client.post(
            "/messages/",
            json=INITIALIZE,
            headers=_headers(host, origin, {"Content-Type": "application/json"}),
        ).status_code


def _streamable_status(host: str, origin: Optional[str], port: int = PORT) -> int:
    app = build_streamable_http_app(mount_path="/mcp", host="127.0.0.1", port=port)
    return _post_streamable(app, port, host, origin)


def _sse_status(host: str, origin: Optional[str], port: int = PORT) -> int:
    app = build_sse_app(mount_path="/sse", host="127.0.0.1", port=port)
    return _post_sse(app, port, host, origin)


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
        "http://other.example",
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
    seen = {}

    def _build(**kwargs):
        seen.update(kwargs)
        return object()

    monkeypatch.setattr(
        "automated_security_helper.cli.mcp.build_streamable_http_app", _build
    )
    monkeypatch.setattr(
        "automated_security_helper.cli.mcp._run_uvicorn",
        lambda app, host, port, log_level, listen_socket=None: seen.update(
            bound_port=port
        ),
    )

    mcp_command(
        ctx=_Ctx(), transport="streamable-http", host="127.0.0.1", port=PORT, quiet=True
    )

    assert seen.get("port") == seen.get("bound_port") == PORT


class _Ctx:
    resilient_parsing = False


@pytest.mark.parametrize(
    "host, origin",
    [
        ("127.0.0.1", None),
        ("localhost", "http://localhost"),
        ("[::1]", "http://[::1]"),
        ("127.0.0.1:80", "http://127.0.0.1"),
    ],
)
def test_port_80_serves_its_own_address_written_without_the_port(host, origin) -> None:
    """Clients and browsers leave out the default port."""
    assert _streamable_status(host, origin, port=80) == 200
    assert _sse_status(host, origin, port=80) == 400


def test_port_80_still_refuses_another_port() -> None:
    assert _streamable_status("127.0.0.1:8080", None, port=80) == 421
    assert _streamable_status("127.0.0.1", "http://127.0.0.1:8080", port=80) == 403


@pytest.mark.parametrize(
    "transport, post, served_status",
    [("streamable-http", _post_streamable, 200), ("sse", _post_sse, 400)],
)
def test_port_0_serves_the_port_the_system_chose(
    monkeypatch, transport, post, served_status
) -> None:
    served = {}

    def _serve(app, host, port, log_level, listen_socket=None):
        served.update(port=port, listen_socket=listen_socket)
        if listen_socket is not None:
            served["bound_port"] = listen_socket.getsockname()[1]
        served["status"] = post(app, port, f"127.0.0.1:{port}", None)

    monkeypatch.setattr("automated_security_helper.cli.mcp._run_uvicorn", _serve)

    mcp_command(ctx=_Ctx(), transport=transport, host="127.0.0.1", port=0, quiet=True)

    assert served.get("port") not in (None, 0), served
    assert served.get("bound_port") == served["port"], served
    assert served.get("status") == served_status, served
    assert served["listen_socket"].fileno() == -1, "the socket was left open"


def test_a_refused_bind_with_port_0_binds_nothing(monkeypatch) -> None:
    import socket

    monkeypatch.setattr(
        socket.socket, "bind", lambda self, address: pytest.fail("a socket was bound")
    )
    monkeypatch.setattr(
        "automated_security_helper.cli.mcp._run_uvicorn",
        lambda *a, **k: pytest.fail("the server started"),
    )

    with pytest.raises(typer.Exit) as excinfo:
        mcp_command(
            ctx=_Ctx(), transport="streamable-http", host="0.0.0.0", port=0, quiet=True
        )

    assert excinfo.value.exit_code == ASH_EXIT_USAGE_ERROR


@pytest.mark.parametrize("build", [build_streamable_http_app, build_sse_app])
@pytest.mark.parametrize("port", [None, 0])
def test_a_loopback_app_is_refused_without_the_port_it_listens_on(build, port) -> None:
    """Built for the wrong port, the app would answer 421 to every request."""
    arguments = {} if port is None else {"port": port}

    with pytest.raises(ASHValidationError, match="port"):
        build(mount_path="/x", host="127.0.0.1", **arguments)


@pytest.mark.parametrize("build", [build_streamable_http_app, build_sse_app])
def test_an_app_that_does_not_check_the_port_needs_none(build) -> None:
    build(mount_path="/x", host="0.0.0.0", allowed_hosts=["ash.example"])
    build(mount_path="/x", host="0.0.0.0", trust_upstream_host_check=True)
