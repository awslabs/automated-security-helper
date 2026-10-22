# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A caller on a network transport is remote, whatever headers it sends.

The scan-target and config-input boundaries give two tiers of trust. stdio's
single client is the process that launched the server, so it keeps the local
tier: anything outside a short system denylist. Every other caller is remote and
is confined to the operator's grant plus its own session sandbox.

What decides the tier has to be the transport the call arrived on. A session
header is client-supplied: a client that omits it must not fall back to the
local tier, and a client that sets it must not thereby choose whose sandbox it
reads. On sse the session is the one the server issued for the stream, never a
header the client adds to its posts. On stateless streamable-HTTP there is no
server-issued session at all, so tools that need a session identity refuse
unless the operator has declared that a fronting platform issues and
authenticates the header; these tests run without that declaration.

Each transport is driven in process -- streamable-HTTP through ``TestClient``,
sse at the ASGI level, stdio through the SDK's in-memory client -- so the server
sees the same request objects a real client produces.
"""

from __future__ import annotations

import asyncio
import base64
import io
import zipfile
from pathlib import Path
from typing import Dict

import pytest
from starlette.testclient import TestClient

from automated_security_helper.cli.mcp import build_sse_app, build_streamable_http_app
from tests.utils.mcp_transport_harness import (
    AsgiSseConnection,
    LOOPBACK_BASE_URL,
    LOOPBACK_PORT,
    StreamableHttpClient,
    stdio_tool_calls,
)

#: A session id some other client holds. Its sandbox exists on disk.
OTHER_SESSION = "other-client-session-1"


@pytest.fixture(autouse=True)
def layout(tmp_path, monkeypatch) -> Dict[str, Path]:
    """Workspace root with another session's sandbox, plus ungranted and granted trees."""
    workspace = tmp_path / "mcp-workspaces"
    other_output = workspace / OTHER_SESSION / "source" / ".ash" / "ash_output"
    (other_output / "reports").mkdir(parents=True)
    ungranted_output = tmp_path / "ungranted" / ".ash" / "ash_output"
    (ungranted_output / "reports").mkdir(parents=True)
    ungranted_config = tmp_path / "ungranted" / ".ash" / ".ash.yaml"
    ungranted_config.write_text("project_name: ungranted\n", encoding="utf-8")
    granted_output = tmp_path / "granted" / ".ash" / "ash_output"
    (granted_output / "reports").mkdir(parents=True)

    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    for name in (
        "ASH_MCP_ALLOWED_ROOTS",
        "ASH_MCP_ALLOWED_CONFIG_ROOTS",
        "ASH_MCP_TRANSPORT",
    ):
        monkeypatch.delenv(name, raising=False)
    return {
        "workspace": workspace,
        "other_sandbox": workspace / OTHER_SESSION,
        "other_output": other_output,
        "ungranted_output": ungranted_output,
        "ungranted_config": ungranted_config,
        "granted": tmp_path / "granted",
        "granted_output": granted_output,
    }


def _zip_chunk_args() -> Dict[str, object]:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("app.py", "print('hello')\n")
    return {
        "upload_id": "upload-1",
        "sequence": 0,
        "data_b64": base64.b64encode(buffer.getvalue()).decode(),
        "last": True,
    }


def _refused(result: Dict[str, object]) -> bool:
    return isinstance(result, dict) and result.get("success") is False


# ---------------------------------------------------------------------------
# Stateless streamable-HTTP
# ---------------------------------------------------------------------------


@pytest.fixture
def stateless():
    app = build_streamable_http_app(
        mount_path="/mcp", stateless_http=True, host="127.0.0.1", port=LOOPBACK_PORT
    )
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        yield StreamableHttpClient(client)


class TestStatelessStreamableHttp:
    def test_a_caller_without_a_session_header_cannot_read_an_ungranted_tree(
        self, stateless, layout
    ) -> None:
        _issued, headers = stateless.open_session()

        result = stateless.call_tool(
            "get_scan_result_paths",
            {"output_dir": str(layout["ungranted_output"])},
            headers,
        )

        assert _refused(result), (
            f"a stateless HTTP caller with no session header got local trust: {result}"
        )

    def test_a_caller_without_a_session_header_gets_config_confinement_under_a_grant(
        self, stateless, layout, monkeypatch
    ) -> None:
        """A grant narrows scan targets for every caller; config confinement is the
        remote tier's, and a caller with no session header is remote."""
        monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(layout["granted"]))
        _issued, headers = stateless.open_session()

        result = stateless.call_tool(
            "get_config",
            {"config_path": str(layout["ungranted_config"]), "raw": True},
            headers,
        )

        assert _refused(result), (
            f"a stateless HTTP caller read a config outside every grant: {result}"
        )

    def test_a_client_chosen_session_id_does_not_open_that_sandbox(
        self, stateless, layout
    ) -> None:
        _issued, headers = stateless.open_session({"Mcp-Session-Id": OTHER_SESSION})

        result = stateless.call_tool(
            "get_scan_result_paths",
            {"output_dir": str(layout["other_output"])},
            headers,
        )

        assert _refused(result), (
            f"naming another session's id read its sandbox: {result}"
        )

    def test_a_client_chosen_session_id_does_not_remove_that_sandbox(
        self, stateless, layout
    ) -> None:
        _issued, headers = stateless.open_session({"Mcp-Session-Id": OTHER_SESSION})

        stateless.call_tool("clear_source", {}, headers)

        assert layout["other_sandbox"].exists(), (
            "naming another session's id removed its sandbox"
        )

    @pytest.mark.parametrize(
        "session_header",
        [None, "client-chosen-session"],
        ids=["no-session-header", "client-chosen-session-header"],
    )
    def test_source_delivery_is_refused_without_an_operator_declared_session_issuer(
        self, stateless, session_header
    ) -> None:
        headers_in = {"Mcp-Session-Id": session_header} if session_header else None
        _issued, headers = stateless.open_session(headers_in)
        result = stateless.call_tool("set_source_zip_chunk", _zip_chunk_args(), headers)

        assert _refused(result), (
            f"stateless source delivery was accepted under a client-chosen "
            f"identity: {result}"
        )
        assert result.get("error"), f"the refusal carries no explanation: {result}"

    def test_a_granted_tree_stays_readable(
        self, stateless, layout, monkeypatch
    ) -> None:
        """Control: the operator's grant still applies to a remote caller."""
        monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(layout["granted"]))
        _issued, headers = stateless.open_session()

        result = stateless.call_tool(
            "get_scan_result_paths",
            {"output_dir": str(layout["granted_output"])},
            headers,
        )

        assert result.get("success") is True, result


# ---------------------------------------------------------------------------
# Stateful streamable-HTTP (control: already remote, because a header is required)
# ---------------------------------------------------------------------------


def test_a_stateful_session_cannot_read_an_ungranted_tree(layout) -> None:
    app = build_streamable_http_app(
        mount_path="/mcp", host="127.0.0.1", port=LOOPBACK_PORT
    )
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        http = StreamableHttpClient(client)
        _issued, headers = http.open_session()
        result = http.call_tool(
            "get_scan_result_paths",
            {"output_dir": str(layout["ungranted_output"])},
            headers,
        )

    assert _refused(result), result


def test_a_stateful_session_gets_config_confinement_under_a_grant(
    layout, monkeypatch
) -> None:
    """Control: the refusal shape the stateless config test expects."""
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(layout["granted"]))
    app = build_streamable_http_app(
        mount_path="/mcp", host="127.0.0.1", port=LOOPBACK_PORT
    )
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        http = StreamableHttpClient(client)
        _issued, headers = http.open_session()
        result = http.call_tool(
            "get_config",
            {"config_path": str(layout["ungranted_config"]), "raw": True},
            headers,
        )

    assert _refused(result), result


# ---------------------------------------------------------------------------
# sse
# ---------------------------------------------------------------------------


def _sse(coro_factory):
    async def _run():
        app = build_sse_app(mount_path="/sse", host="127.0.0.1", port=LOOPBACK_PORT)
        return await coro_factory(app)

    return asyncio.run(_run())


class TestSse:
    def test_a_caller_without_a_session_header_cannot_read_an_ungranted_tree(
        self, layout
    ) -> None:
        async def _call(app):
            async with AsgiSseConnection(app) as sse:
                return await sse.call_tool(
                    "get_scan_result_paths",
                    {"output_dir": str(layout["ungranted_output"])},
                )

        result = _sse(_call)

        assert _refused(result), (
            f"an sse caller with no session header got local trust: {result}"
        )

    def test_a_session_header_on_a_post_does_not_open_that_sandbox(
        self, layout
    ) -> None:
        async def _call(app):
            async with AsgiSseConnection(
                app, post_headers={"Mcp-Session-Id": OTHER_SESSION}
            ) as sse:
                return await sse.call_tool(
                    "get_scan_result_paths", {"output_dir": str(layout["other_output"])}
                )

        result = _sse(_call)

        assert _refused(result), (
            f"an sse client chose its session with a header and read it: {result}"
        )

    def test_a_session_header_on_a_post_does_not_remove_that_sandbox(
        self, layout
    ) -> None:
        async def _call(app):
            async with AsgiSseConnection(
                app, post_headers={"Mcp-Session-Id": OTHER_SESSION}
            ) as sse:
                return await sse.call_tool("clear_source", {})

        result = _sse(_call)

        assert layout["other_sandbox"].exists(), (
            f"an sse client chose its session with a header and removed it: {result}"
        )
        assert result.get("session_id") != OTHER_SESSION, result

    def test_a_granted_tree_stays_readable(self, layout, monkeypatch) -> None:
        """Control: the harness reaches the tool, and a grant still applies."""
        monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(layout["granted"]))

        async def _call(app):
            async with AsgiSseConnection(app) as sse:
                return await sse.call_tool(
                    "get_scan_result_paths",
                    {"output_dir": str(layout["granted_output"])},
                )

        result = _sse(_call)

        assert result.get("success") is True, result


# ---------------------------------------------------------------------------
# stdio keeps the local tier (control)
# ---------------------------------------------------------------------------


def test_a_stdio_caller_keeps_local_trust(layout) -> None:
    (result,) = asyncio.run(
        stdio_tool_calls(
            [("get_scan_result_paths", {"output_dir": str(layout["ungranted_output"])})]
        )
    )

    assert result.get("success") is True, result


def test_serving_a_network_transport_leaves_stdio_trust_unchanged(
    layout, monkeypatch
) -> None:
    """Guard: the transport marker is per app or per request, not process-wide.

    ``mcp_command`` serves a stateless app (one request through it, in place of
    uvicorn); a stdio-shaped call in the same process afterwards still has the
    local tier. Process-wide state would carry into every later call in the
    process (cli/mcp/sandbox.py).
    """
    from automated_security_helper.cli.mcp import mcp_command

    served = {}

    def _serve_one_request(app, host, port, log_level, listen_socket=None):
        with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
            http = StreamableHttpClient(client)
            _issued, headers = http.open_session()
            served["result"] = http.call_tool("list_profiles", {}, headers)

    class _Ctx:
        resilient_parsing = False

    monkeypatch.setattr(
        "automated_security_helper.cli.mcp._run_uvicorn", _serve_one_request
    )
    mcp_command(
        ctx=_Ctx(),
        transport="streamable-http",
        host="127.0.0.1",
        stateless_http=True,
        quiet=True,
    )
    assert "profiles" in served.get("result", {}), served

    (result,) = asyncio.run(
        stdio_tool_calls(
            [("get_scan_result_paths", {"output_dir": str(layout["ungranted_output"])})]
        )
    )

    assert result.get("success") is True, result
