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

import os
import re
import socket
import threading
import time
from contextlib import closing
from typing import Any, Dict

import httpx
import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app as ash_app
from automated_security_helper.cli.mcp import build_streamable_http_app, mcp_command
from tests.utils.mcp_transport_harness import LOOPBACK_PORT
from tests.utils.tool_guard import stub_tool_probes


@pytest.fixture(autouse=True)
def _no_tool_probe(monkeypatch):
    """check_installation runs every scanner's dependency check, which ran ``uv tool
    list`` and ``uv tool run --offline ... --version`` for bandit, checkov,
    detect-secrets and semgrep; these tests are about the transport, and answer the
    probes as a host without uv would."""
    stub_tool_probes(monkeypatch)


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
    # mcp_command sets ASH_LOG_TO_STDERR for as long as it runs, and this server
    # runs until the test process ends, so the variable stayed set for every test
    # the worker ran after this module. Set here first, through a MonkeyPatch,
    # it is put back once this module's tests are done, however they end.
    log_to_stderr_before = os.environ.get("ASH_LOG_TO_STDERR")
    with pytest.MonkeyPatch.context() as env:
        env.setenv("ASH_LOG_TO_STDERR", "1")
        yield from _serve(host, port, mount_path, header_name, header_value)
    # A local, not os.environ itself: an assertion that fails shows its operands.
    log_to_stderr_after = os.environ.get("ASH_LOG_TO_STDERR")
    assert log_to_stderr_after == log_to_stderr_before, (
        "ASH_LOG_TO_STDERR is left set for the tests after this module"
    )


def _serve(host, port, mount_path, header_name, header_value):
    """Start the server thread, yield what the tests need, then check the thread."""
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
        auth_header_name="X-ASH-Auth", auth_header_value="secret", port=LOOPBACK_PORT
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
        auth_header_name="X-ASH-Auth", auth_header_value="secret", port=LOOPBACK_PORT
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
        auth_header_name=None, auth_header_value=None, port=LOOPBACK_PORT
    )
    middleware_names = {m.cls.__name__ for m in app.user_middleware}
    assert "_StaticHeaderAuth" not in middleware_names


def test_build_streamable_http_app_installs_auth_middleware() -> None:
    """When both auth options are set, the middleware is on the app."""
    app = build_streamable_http_app(
        auth_header_name="X-ASH-Auth", auth_header_value="secret", port=LOOPBACK_PORT
    )
    middleware_names = {m.cls.__name__ for m in app.user_middleware}
    assert "_StaticHeaderAuth" in middleware_names


def test_streamable_http_rejects_unauthenticated_request(streamable_server) -> None:
    """A live server returns 401 when the auth header is missing."""
    url = f"http://{streamable_server['host']}:{streamable_server['port']}{streamable_server['mount_path']}"
    with httpx.Client(timeout=5.0) as client:
        resp = client.post(url, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert resp.status_code == 401


def test_streamable_http_check_installation_via_client(
    streamable_server, monkeypatch
) -> None:
    """A full MCP handshake over streamable-HTTP returns a non-empty response.

    Uses the official MCP streamable-http client and ClientSession to call
    ``check_installation`` (the tool registered by ``mcp_server.py``).

    What this tests is the transport, so the scanners' dependency checks are a
    stand-in. The real ones start every built-in scanner's tool (seconds for
    checkov and semgrep), which made this the slowest call over HTTP: its read
    timeout had been raised to 60 s to survive a parallel run. The real checks
    are covered in tests/unit/cli/mcp/test_check_installation_status.py.
    """
    import json as _json

    import anyio
    import httpx
    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    from automated_security_helper.cli import mcp_tools

    inventories: list = []

    def stand_in_inventory(provider, **kwargs):
        inventories.append(provider)
        return [
            {
                "name": "stand_in_scanner",
                "enabled": True,
                "dependencies_satisfied": True,
                "installs_on_first_scan": False,
                "version": "1.0",
                "offline_strategy": "bundled",
            }
        ]

    # The server runs in this process, on the fixture's thread, and reads the
    # module attribute when the tool runs.
    monkeypatch.setattr(mcp_tools, "list_scanner_inventory", stand_in_inventory)
    # An ash on PATH whatever the runner has, so the path check below can fail.
    import shutil

    real_which = shutil.which

    def which(name, *args, **kwargs):
        if name == "ash":
            return "/opt/operator-only/bin/ash"
        return real_which(name, *args, **kwargs)

    monkeypatch.setattr(shutil, "which", which)

    url = f"http://{streamable_server['host']}:{streamable_server['port']}{streamable_server['mount_path']}"
    headers = {streamable_server["header_name"]: streamable_server["header_value"]}

    result_holder: Dict[str, Any] = {}

    async def _run() -> None:
        async with httpx.AsyncClient(headers=headers, timeout=10.0) as http_client:
            # MCP SDK v2 yields two streams. FastMCP's client also handed back a
            # get_session_id callable, so unpacking three raised
            # "not enough values to unpack (expected 3, got 2)".
            async with streamable_http_client(url, http_client=http_client) as (
                read_stream,
                write_stream,
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
    assert inventories, "the tool did not run the stand-in checks"
    report = _json.loads(call_result.content[0].text)
    assert [s["name"] for s in report["scanners"]] == ["stand_in_scanner"], report
    # A session over HTTP is remote: it is told whether ash is on the server's
    # PATH, never where.
    assert report["ash_command_available"] is True, report
    assert not os.path.isabs(report["ash_command_output"]), report


def test_mcp_wrapper_exposes_streamable_http_flags() -> None:
    """``ash mcp --help`` must list the streamable-HTTP flags from the wrapper.

    The typer wrapper in ``automated_security_helper/cli/main.py`` has to mirror
    the parameters added to ``mcp_command`` — otherwise users hit
    ``unknown option`` for ``--transport`` etc. when invoking the real CLI.
    """
    runner = CliRunner()
    # Rendered wide, as the CDK entrypoint reads it (COLUMNS=200). At the default
    # 80 columns Rich truncates the longer option names to fit the table, for
    # example "--auth-header-na…", once --log-level shows its choices; `ash scan
    # --help` truncates the same way, so the width is not what this test is about.
    result = runner.invoke(ash_app, ["mcp", "--help"], env={"COLUMNS": "200"})
    assert result.exit_code == 0, result.output
    # Typer renders help through Rich, which styles each flag segment separately:
    # "--log-level" arrives as ESC[..m- ESC[..m-log ESC[..m-level. The escape codes
    # sit *inside* the flag token, so a substring search on the raw output never
    # matches. Strip ANSI first, then collapse whitespace so a flag that Rich wrapped
    # across two lines still reads as one token.
    plain = re.sub(r"\x1b\[[0-9;]*m", "", result.output)
    flat = " ".join(plain.split())
    for flag in (
        "--transport",
        "--host",
        "--port",
        "--mount-path",
        "--auth-header-name",
        "--auth-header-value",
        "--stateless-http",
        "--allowed-host",
    ):
        assert flag in flat, f"Missing {flag} in `ash mcp --help`:\n{result.output}"
