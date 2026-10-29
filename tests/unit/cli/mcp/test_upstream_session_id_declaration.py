# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--trust-upstream-session-id``: the operator's switch for a stateless server.

A stateless streamable-HTTP server issues no session, so by default its callers
have no session identity and the tools that need one refuse
(``test_network_callers_are_remote.py``). An operator whose platform issues and
authenticates ``Mcp-Session-Id`` -- Bedrock AgentCore Runtime is the case ASH
deploys to -- declares that with ``--trust-upstream-session-id``, and the header
then names the session. These tests cover the declared mode, the reserved ids a
header may never name, the refusal shape for the scan registry tools, the
command-line validation, and the stateful server ignoring a header it did not
issue on the request path that skips the SDK's own session check.
"""

from __future__ import annotations

import base64
import hashlib
import io
import zipfile
from pathlib import Path
from typing import Dict

import pytest
import typer
from starlette.testclient import TestClient
from types import SimpleNamespace

from automated_security_helper.cli.mcp import build_streamable_http_app, mcp_command
from automated_security_helper.cli.mcp.session_identity import (
    SESSION_IDENTITY_REQUIRED,
)
from automated_security_helper.core.constants import (
    ASH_EXIT_CODES,
    ASH_EXIT_USAGE_ERROR,
)
from tests.utils.mcp_transport_harness import (
    LOOPBACK_BASE_URL,
    LOOPBACK_PORT,
    STREAMABLE_HEADERS,
    StreamableHttpClient,
    boundary_of,
    tool_payload,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def workspace(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "mcp-workspaces"
    root.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    for name in (
        "ASH_MCP_ALLOWED_ROOTS",
        "ASH_MCP_ALLOWED_CONFIG_ROOTS",
        "ASH_MCP_TRANSPORT",
    ):
        monkeypatch.delenv(name, raising=False)
    return root


def _zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("app.py", "print('hello')\n")
    return buffer.getvalue()


def _deliver(http: StreamableHttpClient, headers: Dict[str, str]) -> Dict:
    data = _zip()
    chunk = http.call_tool(
        "set_source_zip_chunk",
        {
            "upload_id": "u1",
            "sequence": 0,
            "data_b64": base64.b64encode(data).decode(),
            "last": True,
        },
        headers,
    )
    if chunk.get("success") is not True:
        return chunk
    return http.call_tool(
        "set_source_zip_finalize",
        {"upload_id": "u1", "expected_sha256": hashlib.sha256(data).hexdigest()},
        headers,
    )


@pytest.fixture
def declared():
    app = build_streamable_http_app(
        mount_path="/mcp",
        stateless_http=True,
        host="127.0.0.1",
        trust_upstream_session_id=True,
        port=LOOPBACK_PORT,
    )
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        yield StreamableHttpClient(client)


class TestDeclaredUpstreamSessions:
    def test_the_header_names_the_session_and_its_sandbox(
        self, declared, workspace
    ) -> None:
        _issued, headers = declared.open_session({"Mcp-Session-Id": "platform-a"})

        final = _deliver(declared, headers)

        assert final.get("success") is True, final
        assert Path(final["source_dir"]).is_relative_to(workspace / "platform-a")
        assert final.get("session_id") == "platform-a"

    def test_another_header_cannot_read_that_sandbox(self, declared, workspace) -> None:
        _issued, owner = declared.open_session({"Mcp-Session-Id": "platform-a"})
        final = _deliver(declared, owner)
        output = Path(final["source_dir"]) / ".ash" / "ash_output"
        (output / "reports").mkdir(parents=True)
        _issued, other = declared.open_session({"Mcp-Session-Id": "platform-b"})

        result = declared.call_tool(
            "get_scan_result_paths", {"output_dir": str(output)}, other
        )

        assert result.get("success") is False, result

    @pytest.mark.parametrize(
        "reserved",
        [
            "__default__",
            "__unidentified__",
            # A case-insensitive filesystem (macOS, Windows) opens the same
            # directory for these spellings.
            "__DEFAULT__",
            "__Default__",
            "__UNIDENTIFIED__",
            # The stdio servers' presence registry under the workspace root.
            ".stdio-servers",
            ".STDIO-SERVERS",
        ],
    )
    def test_a_reserved_id_is_refused(self, declared, reserved) -> None:
        _issued, headers = declared.open_session({"Mcp-Session-Id": reserved})

        result = declared.call_tool("clear_source", {}, headers)

        assert result.get("success") is False, result
        assert result.get("error_type") == "invalid_session_id", result

    def test_a_header_cannot_name_the_stdio_presence_registry(
        self, declared, workspace
    ) -> None:
        presence = workspace / ".stdio-servers"
        presence.mkdir()
        entry = presence / "4242"
        entry.write_text("")
        _issued, headers = declared.open_session({"Mcp-Session-Id": ".stdio-servers"})

        declared.call_tool("clear_source", {}, headers)
        _deliver(declared, headers)

        assert entry.is_file(), "a header removed the stdio presence registry"
        assert sorted(p.name for p in presence.iterdir()) == ["4242"]

    def test_a_missing_header_still_has_no_session(self, declared) -> None:
        _issued, headers = declared.open_session()

        result = _deliver(declared, headers)

        assert result.get("error_type") == SESSION_IDENTITY_REQUIRED, result


@pytest.mark.parametrize(
    "tool, arguments",
    [
        ("list_active_scans", {}),
        ("get_scan_progress", {"scan_id": "00000000-0000-0000-0000-000000000000"}),
        ("cancel_scan", {"scan_id": "00000000-0000-0000-0000-000000000000"}),
        ("select_profile", {"profile_name": "default"}),
        ("set_source_git", {"url": "https://git.example.invalid/r.git"}),
        ("run_ash_scan", {}),
    ],
)
def test_session_tools_refuse_a_stateless_caller_without_the_declaration(
    tool, arguments
) -> None:
    app = build_streamable_http_app(
        mount_path="/mcp", stateless_http=True, host="127.0.0.1", port=LOOPBACK_PORT
    )
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        http = StreamableHttpClient(client)
        _issued, headers = http.open_session({"Mcp-Session-Id": "client-chosen"})
        result = http.call_tool(tool, arguments, headers)

    assert result.get("success") is False, result
    assert result.get("error_type") == SESSION_IDENTITY_REQUIRED, result
    assert "--trust-upstream-session-id" in result.get("error", ""), result


def test_a_stateless_caller_without_the_declaration_starts_no_scan(
    tmp_path, monkeypatch
) -> None:
    """A scan it named a directory for would be one it could neither poll nor cancel."""
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    granted = tmp_path / "granted"
    granted.mkdir()
    (granted / "app.py").write_text("print('hello')\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(granted))
    registry = scan_registry_module.ScanRegistry()
    monkeypatch.setattr(scan_registry_module, "_scan_registry", registry)
    monkeypatch.setattr(
        "automated_security_helper.interactions.run_ash_scan.run_ash_scan",
        lambda **kwargs: pytest.fail("a scan ran for a caller with no session"),
    )
    app = build_streamable_http_app(
        mount_path="/mcp", stateless_http=True, host="127.0.0.1", port=LOOPBACK_PORT
    )
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        http = StreamableHttpClient(client)
        _issued, headers = http.open_session()
        result = http.call_tool("run_ash_scan", {"source_dir": str(granted)}, headers)

    assert result.get("success") is False, result
    assert result.get("error_type") == SESSION_IDENTITY_REQUIRED, result
    assert "--trust-upstream-session-id" in result.get("error", ""), result
    assert registry.get_scan_by_directory(str(granted)) is None
    assert not (granted / ".ash").exists(), "the refused scan wrote into the target"


def test_the_scan_tool_reports_an_exit_code_for_the_session_identity_refusal() -> None:
    """run_ash_scan documents an exit_code on every refusal it returns.

    A caller that branches on it, as a script branches on the CLI's status, must
    find the key on this refusal too. A call with no session is the request's own
    fault, so it reports the usage-error code, as an unusable session header does.
    """
    app = build_streamable_http_app(
        mount_path="/mcp", stateless_http=True, host="127.0.0.1", port=LOOPBACK_PORT
    )
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        http = StreamableHttpClient(client)
        _issued, headers = http.open_session()
        result = http.call_tool("run_ash_scan", {}, headers)

    assert result.get("error_type") == SESSION_IDENTITY_REQUIRED, result
    assert result.get("exit_code") == ASH_EXIT_USAGE_ERROR, result
    assert result.get("exit_code_meaning") == ASH_EXIT_CODES[ASH_EXIT_USAGE_ERROR], (
        result
    )


def test_the_scan_backend_refuses_a_caller_with_no_session(tmp_path) -> None:
    import asyncio

    from automated_security_helper.cli.mcp.session_identity import (
        UNIDENTIFIED_SESSION_ID,
    )
    from automated_security_helper.cli.mcp_tools import mcp_scan_directory

    result = asyncio.run(
        mcp_scan_directory(
            directory_path=str(tmp_path), session_id=UNIDENTIFIED_SESSION_ID
        )
    )

    assert result.get("success") is False, result
    assert result.get("error_type") == SESSION_IDENTITY_REQUIRED, result
    assert not (tmp_path / ".ash").exists()


class _Ctx:
    resilient_parsing = False


@pytest.mark.parametrize(
    "transport, stateless",
    [("streamable-http", False), ("sse", False), ("stdio", False)],
)
def test_the_declaration_is_refused_where_the_server_issues_sessions(
    monkeypatch, transport, stateless
) -> None:
    monkeypatch.setattr(
        "automated_security_helper.cli.mcp._run_uvicorn",
        lambda *a, **k: pytest.fail("the server started"),
    )

    with pytest.raises(typer.Exit) as excinfo:
        mcp_command(
            ctx=_Ctx(),
            transport=transport,
            host="127.0.0.1",
            stateless_http=stateless,
            trust_upstream_session_id=True,
            quiet=True,
        )

    assert excinfo.value.exit_code == ASH_EXIT_USAGE_ERROR


def test_a_stateful_server_ignores_a_header_it_did_not_issue_on_the_newer_protocol(
    workspace,
) -> None:
    """Requests naming the 2026-07-28 protocol skip the SDK's session check.

    The header on such a request names no session this server issued, so it
    must not open that session's sandbox.
    """
    other_output = workspace / "other-session" / "source" / ".ash" / "ash_output"
    (other_output / "reports").mkdir(parents=True)
    app = build_streamable_http_app(
        mount_path="/mcp", host="127.0.0.1", port=LOOPBACK_PORT
    )
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "get_scan_result_paths",
            "arguments": {"output_dir": str(other_output)},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    }
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        response = client.post(
            "/mcp",
            json=body,
            headers={
                **STREAMABLE_HEADERS,
                "Mcp-Protocol-Version": "2026-07-28",
                "Mcp-Session-Id": "other-session",
                "Mcp-Method": "tools/call",
                "Mcp-Name": "get_scan_result_paths",
            },
        )

    assert response.status_code == 200, response.text[:300]
    result = tool_payload(response.json())
    assert result.get("success") is False, result
    assert result.get("error_type") == "scan_target_not_permitted", result
    assert boundary_of(app)._issued == set()


def test_a_stateful_server_gives_an_issued_id_no_identity_on_the_newer_protocol() -> (
    None
):
    """The id this server issued still names no session on the newer path.

    Requests naming the 2026-07-28 protocol skip the SDK's session check, so
    the server's record of which ids it issued is not what answers them. The
    documented rule is that such a request carries no identity.
    """
    app = build_streamable_http_app(
        mount_path="/mcp", host="127.0.0.1", port=LOOPBACK_PORT
    )
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "clear_source",
            "arguments": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    }
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        issued, _headers = StreamableHttpClient(client).open_session()
        assert issued, "a stateful server issues an id at initialize"
        response = client.post(
            "/mcp",
            json=body,
            headers={
                **STREAMABLE_HEADERS,
                "Mcp-Protocol-Version": "2026-07-28",
                "Mcp-Session-Id": issued,
                "Mcp-Method": "tools/call",
                "Mcp-Name": "clear_source",
            },
        )

    assert response.status_code == 200, response.text[:300]
    result = tool_payload(response.json())
    assert result.get("success") is False, result
    assert result.get("error_type") == SESSION_IDENTITY_REQUIRED, result
    # The refusal names the cause, a protocol version that is not a handshake
    # version, so a caller on this server has something it can change.
    assert "Mcp-Protocol-Version" in result.get("error", ""), result
    assert "handshake" in result.get("error", ""), result
    assert "newer protocol version" in result.get("error", ""), result


def test_a_stateful_refusal_advises_initialize_not_an_operator_mode_change() -> None:
    """On a stateful server the refusal tells the caller what works there.

    The caller's remedy on a stateful server is a session: open one with
    ``initialize`` and send the ``Mcp-Session-Id`` it returns. Advice to run the
    server "without --stateless-http" is for an operator and already holds, and
    an id this server never issued gains nothing from a version change, so the
    refusal must not name the protocol version as the cause either. Reachable
    only on the newer-protocol path: a handshake-version request without a
    session is refused by the SDK before any tool runs.
    """
    app = build_streamable_http_app(
        mount_path="/mcp", host="127.0.0.1", port=LOOPBACK_PORT
    )
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "clear_source",
            "arguments": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    }
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        response = client.post(
            "/mcp",
            json=body,
            headers={
                **STREAMABLE_HEADERS,
                "Mcp-Protocol-Version": "2026-07-28",
                "Mcp-Session-Id": "client-chosen",
                "Mcp-Method": "tools/call",
                "Mcp-Name": "clear_source",
            },
        )

    assert response.status_code == 200, response.text[:300]
    result = tool_payload(response.json())
    assert result.get("success") is False, result
    assert result.get("error_type") == SESSION_IDENTITY_REQUIRED, result
    assert "initialize" in result.get("error", ""), result
    assert "--stateless-http" not in result.get("error", ""), result
    assert "newer protocol version" not in result.get("error", ""), result


def _version_refused_stateful_caller():
    """The stamp a stateful boundary leaves on an issued id refused for its version."""
    from automated_security_helper.cli.mcp.http_sessions import (
        MODE_STATEFUL,
        STREAMABLE_HTTP,
        HttpCaller,
    )

    return HttpCaller(
        STREAMABLE_HTTP,
        None,
        protocol_version_is_cause=True,
        server_mode=MODE_STATEFUL,
    )


def _ctx_carrying(caller):
    """A stand-in context whose request carries ``caller``'s scope stamp.

    ``session_identity_refusal`` reads the stamp from the request behind the
    context it is given, so handing it one request's stamp fixes what the
    refusal may say about cause and mode; no state outside the request can.
    """
    from mcp.server.mcpserver import Context

    from automated_security_helper.cli.mcp.http_sessions import CALLER_SCOPE_KEY

    # A Context the SDK built: the refusal reads a stamp only through the same
    # type test the resolution applies, so a plain stand-in carries none.
    request = SimpleNamespace(scope={CALLER_SCOPE_KEY: caller})
    return Context(request_context=SimpleNamespace(request=request))


def test_the_refusal_names_the_protocol_version_as_a_cause() -> None:
    """An issued id refused for its version alone: the request's own stamp says so."""
    from automated_security_helper.cli.mcp.session_identity import (
        UNIDENTIFIED_SESSION_ID,
        session_identity_refusal,
    )

    refusal = session_identity_refusal(
        UNIDENTIFIED_SESSION_ID,
        "clear_source",
        ctx=_ctx_carrying(_version_refused_stateful_caller()),
    )

    assert refusal is not None
    assert "newer protocol version" in refusal["error"], refusal
    assert "Mcp-Protocol-Version" in refusal["error"], refusal
    assert "--stateless-http" not in refusal["error"], refusal


def test_a_refusal_the_protocol_version_did_not_cause_does_not_name_it() -> None:
    """A stateless caller changes nothing by changing its protocol version."""
    app = build_streamable_http_app(
        mount_path="/mcp", stateless_http=True, host="127.0.0.1", port=LOOPBACK_PORT
    )
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        http = StreamableHttpClient(client)
        _issued, headers = http.open_session()
        result = http.call_tool("clear_source", {}, headers)

    assert result.get("error_type") == SESSION_IDENTITY_REQUIRED, result
    assert "newer protocol version" not in result.get("error", ""), result
    assert "Mcp-Protocol-Version" not in result.get("error", ""), result
    assert "--trust-upstream-session-id" in result.get("error", ""), result


def test_the_protocol_version_cause_does_not_outlive_the_request_that_set_it() -> None:
    """Only a refusal handed that request's context names the version."""
    from automated_security_helper.cli.mcp.session_identity import (
        UNIDENTIFIED_SESSION_ID,
        session_identity_refusal,
    )

    ctx = _ctx_carrying(_version_refused_stateful_caller())
    with_request = session_identity_refusal(
        UNIDENTIFIED_SESSION_ID, "clear_source", ctx=ctx
    )
    without_request = session_identity_refusal(
        UNIDENTIFIED_SESSION_ID, "clear_source", ctx=None
    )

    assert with_request is not None and without_request is not None
    assert "newer protocol version" in with_request["error"], with_request
    assert "newer protocol version" not in without_request["error"], without_request


def test_an_interleaved_resolution_does_not_change_the_refusals_cause() -> None:
    """The refusal depends on the request it is given, not on call order."""
    from automated_security_helper.cli.mcp.session_identity import (
        UNIDENTIFIED_SESSION_ID,
        resolve_caller_session_id,
        session_identity_refusal,
    )

    class _StandIn:
        headers = {"mcp-session-id": "tenant-a"}

    ctx = _ctx_carrying(_version_refused_stateful_caller())
    # Another caller's resolution runs between the request and its refusal.
    assert resolve_caller_session_id(_StandIn()) == "tenant-a"
    refusal = session_identity_refusal(UNIDENTIFIED_SESSION_ID, "clear_source", ctx=ctx)

    assert refusal is not None
    assert "newer protocol version" in refusal["error"], refusal
    assert "initialize" in refusal["error"], refusal


def test_a_refusal_for_a_passed_down_id_claims_no_cause() -> None:
    """mcp_scan_directory's shape: an id another tool resolved and passed down.

    No request stamp is in reach here, so the refusal must not claim the
    protocol version is the cause and must not pick a mode it cannot know.
    """
    from automated_security_helper.cli.mcp.session_identity import (
        UNIDENTIFIED_SESSION_ID,
        session_identity_refusal,
    )

    refusal = session_identity_refusal(
        UNIDENTIFIED_SESSION_ID, "scan_directory", ctx=None
    )

    assert refusal is not None
    assert "newer protocol version" not in refusal["error"], refusal
    assert "Mcp-Protocol-Version" not in refusal["error"], refusal
    assert "--trust-upstream-session-id" in refusal["error"], refusal


def test_a_request_no_ash_app_stamped_gets_the_mode_less_advice() -> None:
    """A context whose request carries no stamp claims neither cause nor mode."""
    from automated_security_helper.cli.mcp.session_identity import (
        UNIDENTIFIED_SESSION_ID,
        session_identity_refusal,
    )

    from mcp.server.mcpserver import Context

    ctx = Context(request_context=SimpleNamespace(request=SimpleNamespace(scope={})))
    refusal = session_identity_refusal(UNIDENTIFIED_SESSION_ID, "clear_source", ctx=ctx)

    assert refusal is not None
    assert "newer protocol version" not in refusal["error"], refusal
    assert "--trust-upstream-session-id" in refusal["error"], refusal


def test_the_ash_command_line_forwards_the_declaration(monkeypatch) -> None:
    """``ash mcp`` exposes the flag and hands it to the server command."""
    from typer.testing import CliRunner

    from automated_security_helper.cli.main import app as ash_app

    seen = {}

    def _record(**kwargs):
        seen.update(kwargs)

    monkeypatch.setattr("automated_security_helper.cli.mcp.mcp_command", _record)

    result = CliRunner().invoke(
        ash_app,
        [
            "mcp",
            "--transport",
            "streamable-http",
            "--stateless-http",
            "--trust-upstream-session-id",
        ],
    )

    assert result.exit_code == 0, result.output
    assert seen.get("trust_upstream_session_id") is True, seen
