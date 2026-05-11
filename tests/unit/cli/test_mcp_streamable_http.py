# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Smoke tests for the streamable-HTTP transport of the ASH MCP server.

Track 10.1 / Task #62. The transport flag in ``mcp_command`` selects between:
- ``stdio`` (default; legacy behavior)
- ``streamable-http`` (FastMCP streamable HTTP served by uvicorn)
- ``sse`` (legacy FastMCP SSE)

These tests stand up a real uvicorn server in a background thread bound to an
ephemeral port, then exercise the auth-header gate and the JSON-RPC handshake
through the official MCP streamable-HTTP client.
"""

from __future__ import annotations

import socket
import threading
import time
from contextlib import closing
from typing import Any, Dict

import httpx
import pytest

from automated_security_helper.cli.mcp import build_streamable_http_app, mcp_command


def _free_port() -> int:
    """Reserve an ephemeral TCP port and return it.

    The socket is closed before returning, so the port is briefly free for
    uvicorn to bind. SO_REUSEADDR keeps races to a minimum.
    """
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(host: str, port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with closing(socket.create_connection((host, port), timeout=0.5)):
                return
        except OSError as e:
            last_err = e
            time.sleep(0.05)
    raise RuntimeError(f"Server never accepted on {host}:{port}: {last_err}")


@pytest.fixture(scope="module")
def streamable_server():
    """Start the MCP server in streamable-http mode in a background thread.

    Yields a dict with host, port, mount_path, header_name, header_value.
    """
    host = "127.0.0.1"
    port = _free_port()
    mount_path = "/mcp"
    header_name = "X-ASH-Auth"
    header_value = "test-token-do-not-share"

    started = threading.Event()
    errors: list[BaseException] = []

    def _run() -> None:
        try:
            started.set()
            mcp_command(
                ctx=_ResilientFalseCtx(),
                transport="streamable-http",
                host=host,
                port=port,
                mount_path=mount_path,
                auth_header_name=header_name,
                auth_header_value=header_value,
                quiet=True,
            )
        except SystemExit:
            # uvicorn signal handler raises SystemExit on shutdown; ignore.
            pass
        except BaseException as exc:  # pragma: no cover - surfaced via errors
            errors.append(exc)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    started.wait(timeout=2.0)
    _wait_for_port(host, port)

    yield {
        "host": host,
        "port": port,
        "mount_path": mount_path,
        "header_name": header_name,
        "header_value": header_value,
        "errors": errors,
    }

    # Best-effort shutdown: kill the uvicorn loop. The thread is a daemon, so
    # leaving it running won't block test teardown — but trigger graceful exit
    # by sending SIGINT-equivalent via stopping the server if we tracked it.
    # The simplest portable signal here is to let the daemon thread die with
    # the test process. We just record any errors that happened.
    assert not errors, f"Server thread raised: {errors!r}"


class _ResilientFalseCtx:
    """Stand-in typer.Context with ``resilient_parsing == False``."""

    resilient_parsing = False


def test_build_streamable_http_app_rejects_missing_header() -> None:
    """The auth middleware returns 401 when the configured header is absent."""
    app = build_streamable_http_app(
        auth_header_name="X-ASH-Auth",
        auth_header_value="secret",
    )
    # Use Starlette TestClient via httpx so we don't need a live server.
    from starlette.testclient import TestClient

    client = TestClient(app)
    # Any request to the mounted MCP path without the header must be 401.
    resp = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert resp.status_code == 401


def test_build_streamable_http_app_rejects_wrong_value() -> None:
    """Wrong header value also gets 401."""
    app = build_streamable_http_app(
        auth_header_name="X-ASH-Auth",
        auth_header_value="secret",
    )
    from starlette.testclient import TestClient

    client = TestClient(app)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        headers={"X-ASH-Auth": "wrong"},
    )
    assert resp.status_code == 401


def test_build_streamable_http_app_no_auth_when_not_configured() -> None:
    """If no header is configured, the auth middleware is not installed."""
    app = build_streamable_http_app(
        auth_header_name=None,
        auth_header_value=None,
    )
    middleware_names = {m.cls.__name__ for m in app.user_middleware}
    assert "_StaticHeaderAuth" not in middleware_names


def test_build_streamable_http_app_installs_auth_middleware() -> None:
    """When both auth options are set, the middleware is on the app."""
    app = build_streamable_http_app(
        auth_header_name="X-ASH-Auth",
        auth_header_value="secret",
    )
    middleware_names = {m.cls.__name__ for m in app.user_middleware}
    assert "_StaticHeaderAuth" in middleware_names


def test_streamable_http_rejects_unauthenticated_request(streamable_server) -> None:
    """A live server returns 401 when the auth header is missing."""
    url = f"http://{streamable_server['host']}:{streamable_server['port']}{streamable_server['mount_path']}"
    with httpx.Client(timeout=5.0) as client:
        resp = client.post(url, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert resp.status_code == 401


def test_streamable_http_check_installation_via_client(streamable_server) -> None:
    """A full MCP handshake over streamable-HTTP returns a non-empty response.

    Uses the official MCP streamable-http client and ClientSession to call
    ``check_installation`` (the tool registered by ``mcp_server.py``).
    """
    import anyio
    import httpx
    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    url = f"http://{streamable_server['host']}:{streamable_server['port']}{streamable_server['mount_path']}"
    headers = {streamable_server["header_name"]: streamable_server["header_value"]}

    result_holder: Dict[str, Any] = {}

    async def _run() -> None:
        async with httpx.AsyncClient(headers=headers, timeout=10.0) as http_client:
            async with streamable_http_client(url, http_client=http_client) as (
                read_stream,
                write_stream,
                _get_session_id,
            ):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    tool_names = {t.name for t in tools.tools}
                    assert "check_installation" in tool_names, (
                        f"Expected 'check_installation' tool, got {tool_names}"
                    )
                    call_result = await session.call_tool("check_installation", {})
                    result_holder["result"] = call_result

    anyio.run(_run)

    assert "result" in result_holder, "Tool call did not complete"
    call_result = result_holder["result"]
    assert call_result is not None
    # Tool result content is a list of content blocks; assert non-empty.
    assert call_result.content, "check_installation returned no content"
