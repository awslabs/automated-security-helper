# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A session's sandbox and bound profile are removed when the session ends.

Source delivered over MCP lands in ``<workspace root>/<session id>``, and
``select_profile`` binds a config to the session. Both belong to the session, so
both go when it ends:

* stateful streamable-HTTP: when the session is terminated (``DELETE``);
* sse: when the client disconnects;
* stdio: when the server shuts down;
* stateless streamable-HTTP has no end of session, so sandboxes older than an
  operator-set TTL are swept; these tests require the sweep to have run by the
  time the first request after startup is answered, and use an age far beyond
  any reasonable default.

``MCPSessionRegistry.disconnect`` removes a session's directory, and it has to
be the same directory source delivery wrote, so the registry and delivery must
agree on one workspace root.

The removal is required to be complete when the ending event has been handled:
the ``DELETE`` response received, the sse request finished, the stdio process
exited. The controls show the harness reaches deletion (``clear_source``) and
that ending one session leaves every other session's sandbox alone.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import os
import subprocess
import sys
import threading
import time
import zipfile
from pathlib import Path
from typing import Any, Dict

import pytest
import yaml
from starlette.testclient import TestClient

from automated_security_helper.cli.mcp import build_sse_app, build_streamable_http_app
from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_session_state,
    register_profiles,
    resolve_session_config_path,
    set_profile_registry,
)
from tests.utils.mcp_transport_harness import (
    LOOPBACK_BASE_URL,
    AsgiSseConnection,
    StreamableHttpClient,
)

#: Old enough to be past any sensible stateless-sandbox TTL.
STALE_AGE_SECONDS = 400 * 24 * 3600


@pytest.fixture(autouse=True)
def workspace_root(tmp_path, monkeypatch) -> Path:
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


@pytest.fixture(autouse=True)
def _isolate_profile_state():
    clear_profile_registry()
    clear_session_state()
    yield
    clear_profile_registry()
    clear_session_state()


def _zip_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("app.py", "print('hello')\n")
    return buffer.getvalue()


def _chunk_args(data: bytes) -> Dict[str, Any]:
    return {
        "upload_id": "upload-1",
        "sequence": 0,
        "data_b64": base64.b64encode(data).decode(),
        "last": True,
    }


def _finalize_args(data: bytes) -> Dict[str, Any]:
    return {
        "upload_id": "upload-1",
        "expected_sha256": hashlib.sha256(data).hexdigest(),
    }


def _deliver_http(http: StreamableHttpClient, headers: Dict[str, str]) -> Path:
    data = _zip_bytes()
    chunk = http.call_tool("set_source_zip_chunk", _chunk_args(data), headers)
    assert chunk.get("success") is True, chunk
    final = http.call_tool("set_source_zip_finalize", _finalize_args(data), headers)
    assert final.get("success") is True, final
    return Path(final["source_dir"])


@pytest.fixture
def http():
    app = build_streamable_http_app(mount_path="/mcp", host="127.0.0.1")
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        yield StreamableHttpClient(client)


# ---------------------------------------------------------------------------
# Stateful streamable-HTTP
# ---------------------------------------------------------------------------


class TestStatefulSessionTermination:
    def test_delete_removes_the_sessions_sandbox(self, http, workspace_root) -> None:
        session_id, headers = http.open_session()
        source_dir = _deliver_http(http, headers)
        sandbox = workspace_root / session_id
        assert source_dir.is_relative_to(sandbox) and sandbox.is_dir()

        status = http.end_session(headers)

        assert status == 200, f"DELETE answered {status}"
        assert not sandbox.exists(), (
            f"the sandbox of a terminated session is still on disk: {sandbox}"
        )

    def test_delete_clears_the_sessions_bound_profile(self, http, tmp_path) -> None:
        profile_file = tmp_path / "profile.yaml"
        profile_file.write_text(
            yaml.safe_dump({"project_name": "operator-profile"}), encoding="utf-8"
        )
        set_profile_registry(register_profiles([f"team={profile_file}"]))
        session_id, headers = http.open_session()
        bound = http.call_tool("select_profile", {"profile_name": "team"}, headers)
        assert bound.get("success") is True, bound
        materialized = resolve_session_config_path(session_id)
        assert materialized and Path(materialized).is_file()

        http.end_session(headers)

        assert resolve_session_config_path(session_id) is None, (
            "a terminated session still has a bound profile"
        )
        assert not Path(materialized).exists(), (
            f"a terminated session's profile file is still on disk: {materialized}"
        )

    def test_ending_one_session_leaves_another_sessions_sandbox(
        self, http, workspace_root
    ) -> None:
        """Control: removal is scoped to the session that ended."""
        ending_id, ending = http.open_session()
        _deliver_http(http, ending)
        live_id, live = http.open_session()
        _deliver_http(http, live)

        http.end_session(ending)

        assert (workspace_root / live_id / "source").is_dir()
        still_served = http.call_tool("list_profiles", {}, live)
        assert "profiles" in still_served, still_served

    def test_clear_source_removes_the_callers_sandbox(
        self, http, workspace_root
    ) -> None:
        """Control: the harness reaches the deletion path, before and after."""
        session_id, headers = http.open_session()
        _deliver_http(http, headers)

        cleared = http.call_tool("clear_source", {}, headers)

        assert cleared.get("success") is True, cleared
        assert not (workspace_root / session_id / "source").exists()


# ---------------------------------------------------------------------------
# sse
# ---------------------------------------------------------------------------


def test_an_sse_disconnect_removes_the_sessions_sandbox() -> None:
    async def _run() -> Path:
        app = build_sse_app(mount_path="/sse", host="127.0.0.1")
        data = _zip_bytes()
        async with AsgiSseConnection(app) as sse:
            chunk = await sse.call_tool("set_source_zip_chunk", _chunk_args(data))
            assert chunk.get("success") is True, chunk
            final = await sse.call_tool("set_source_zip_finalize", _finalize_args(data))
            assert final.get("success") is True, final
            return Path(final["source_dir"])

    source_dir = asyncio.run(_run())

    sandbox = source_dir.parent
    assert not sandbox.exists(), (
        f"the sandbox of a disconnected sse session is still on disk: {sandbox}"
    )


# ---------------------------------------------------------------------------
# stdio
# ---------------------------------------------------------------------------


def _stdio_server(workspace_root: Path, stderr) -> subprocess.Popen:
    env = {k: v for k, v in os.environ.items() if not k.startswith("ASH_MCP_")}
    env["ASH_MCP_WORKSPACE_ROOT"] = str(workspace_root)
    return subprocess.Popen(
        [sys.executable, "-m", "automated_security_helper.cli.main", "mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=stderr,
        env=env,
        text=True,
    )


def _exchange(
    proc: subprocess.Popen, request_id: int, method: str, params: Dict
) -> Dict:
    proc.stdin.write(
        json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        )
        + "\n"
    )
    proc.stdin.flush()
    for line in proc.stdout:
        message = json.loads(line)
        if message.get("id") == request_id:
            return message
    raise AssertionError(f"the stdio server closed stdout before answering {method}")


def test_stdio_server_shutdown_removes_the_default_sessions_sandbox(
    workspace_root, tmp_path
) -> None:
    stderr_path = tmp_path / "stdio-server.stderr"
    with stderr_path.open("w", encoding="utf-8") as stderr:
        proc = _stdio_server(workspace_root, stderr)
        returncode = _deliver_then_shut_down(proc, workspace_root)

    assert returncode == 0, stderr_path.read_text(encoding="utf-8")[-2000:]
    assert not (workspace_root / "__default__").exists(), (
        "the stdio session's sandbox survived server shutdown"
    )


def _deliver_then_shut_down(proc: subprocess.Popen, workspace_root: Path) -> int:
    """Deliver a tree over stdio, close stdin, and return the exit status."""
    watchdog = threading.Timer(180, proc.kill)
    watchdog.start()
    try:
        _exchange(
            proc,
            1,
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "ash-test", "version": "0"},
            },
        )
        proc.stdin.write(
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
        )
        proc.stdin.flush()
        data = _zip_bytes()
        _exchange(
            proc,
            2,
            "tools/call",
            {"name": "set_source_zip_chunk", "arguments": _chunk_args(data)},
        )
        finalized = _exchange(
            proc,
            3,
            "tools/call",
            {"name": "set_source_zip_finalize", "arguments": _finalize_args(data)},
        )
        assert "result" in finalized, finalized
        assert (workspace_root / "__default__" / "source").is_dir(), (
            "the stdio delivery did not land in the default session's sandbox"
        )

        proc.stdin.close()
        return proc.wait(timeout=120)
    finally:
        watchdog.cancel()
        if proc.returncode is None:
            proc.kill()
            proc.wait()


# ---------------------------------------------------------------------------
# Stateless streamable-HTTP: TTL sweep
# ---------------------------------------------------------------------------


def _sandbox_with_age(root: Path, session_id: str, age_seconds: float) -> Path:
    from automated_security_helper.cli.mcp.session_paths import (
        mark_session_workspace,
    )

    # Created the way ASH creates a session workspace, marker included: the
    # sweep removes only directories ASH created.
    sandbox = mark_session_workspace(root / session_id)
    (sandbox / "source").mkdir(parents=True)
    (sandbox / "source" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    stamp = time.time() - age_seconds
    for path in [*sandbox.rglob("*"), sandbox]:
        os.utime(path, (stamp, stamp))
    return sandbox


def test_a_stateless_server_sweeps_sandboxes_older_than_the_ttl(workspace_root) -> None:
    stale = _sandbox_with_age(workspace_root, "stale-session", STALE_AGE_SECONDS)
    fresh = _sandbox_with_age(workspace_root, "fresh-session", 0)

    app = build_streamable_http_app(
        mount_path="/mcp", stateless_http=True, host="127.0.0.1"
    )
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        http = StreamableHttpClient(client)
        _issued, headers = http.open_session()
        http.call_tool("list_profiles", {}, headers)

        assert not stale.exists(), (
            f"a sandbox {STALE_AGE_SECONDS // 86400} days old was not swept: {stale}"
        )
        assert fresh.is_dir(), "a fresh sandbox was swept"


# ---------------------------------------------------------------------------
# One workspace root
# ---------------------------------------------------------------------------


def test_the_session_registry_removes_the_tree_source_delivery_wrote(
    workspace_root,
) -> None:
    from automated_security_helper.cli.mcp.sessions import MCPSessionRegistry

    data = _zip_bytes()
    sd.set_source_zip_chunk(**_chunk_args(data), session_id="agree-1")
    source_dir = sd.set_source_zip_finalize(
        **_finalize_args(data), session_id="agree-1"
    )
    assert source_dir.is_relative_to(workspace_root / "agree-1")

    registry = MCPSessionRegistry()
    registry.get_or_create("agree-1")
    registry.disconnect("agree-1")

    assert not (workspace_root / "agree-1").exists(), (
        "MCPSessionRegistry.disconnect left the delivered tree behind: the "
        "registry and source delivery use different workspace roots"
    )
