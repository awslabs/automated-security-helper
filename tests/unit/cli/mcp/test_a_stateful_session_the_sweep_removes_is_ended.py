# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A stateful session the TTL sweep removes is ended, and is told so.

The sweep removes the workspace, the bound profile and the delivered source of a
session nobody used for the TTL. A stateful boundary went on holding that
session's id as issued, so the session's next ``run_ash_scan`` was taken for a
live session's: it ran with the profile the client had selected gone, under
in-tree discovery, and nothing said so to the client.

* The sweep's removals end the stateful sessions the boundary still holds as
  issued: the id leaves ``_issued``, so the request that names it carries no
  identity and the tools that need a session refuse it, and the stamp says the
  session expired so the refusal can.
* A session whose standalone ``GET`` stream is open is kept, as an open sse
  stream is: a client that holds the stream is live however long it has sent
  nothing.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import anyio
import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp.http_sessions import (
    CALLER_SCOPE_KEY,
    MODE_SSE,
    MODE_STATEFUL,
    STREAMABLE_HTTP,
    HttpCaller,
    SessionBoundary,
)
from automated_security_helper.cli.mcp.session_identity import (
    SESSION_IDENTITY_REQUIRED,
    UNIDENTIFIED_SESSION_ID,
    session_identity_refusal,
)
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace

pytestmark = pytest.mark.unit

SESSION = "stateful-idle-session"
OTHER = "stateful-other-session"
ENDPOINT = "/mcp"


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    sessions.reset_default_registry_for_tests()
    sessions._ended_while_scanning.clear()
    yield workspace
    sessions.reset_default_registry_for_tests()
    sessions._ended_while_scanning.clear()


def _workspace(root: Path, session_id: str) -> Path:
    sandbox = mark_session_workspace(root / session_id)
    (sandbox / "source").mkdir()
    (sandbox / "source" / "app.py").write_text("x = 1\n", encoding="utf-8")
    return sandbox


def _age(sandbox: Path, seconds: float) -> None:
    then = time.time() - seconds
    for path in (sandbox, *sandbox.iterdir()):
        os.utime(path, (then, then))


async def _app(scope, receive, send) -> None:
    raise AssertionError("the sweep never reaches the app")


async def _receive() -> Dict[str, Any]:
    return {"type": "http.request", "body": b"", "more_body": False}


async def _discard(message: Dict[str, Any]) -> None:
    return None


def _stateful_boundary(app=_app) -> SessionBoundary:
    return SessionBoundary(
        app, mode=MODE_STATEFUL, endpoint_path=ENDPOINT, session_workspace_ttl=60.0
    )


def _scope(session_id: str, method: str = "POST") -> Dict[str, Any]:
    return {
        "type": "http",
        "method": method,
        "path": ENDPOINT,
        "root_path": "",
        "headers": [(b"mcp-session-id", session_id.encode("ascii"))],
        "query_string": b"",
    }


def test_the_sweep_ends_an_issued_stateful_session_it_removes(root) -> None:
    """Red at the base: the removed session stayed in ``_issued``, so its next
    request named a live session and a scan ran unbound."""
    idle = _workspace(root, SESSION)
    _age(idle, 7200)
    boundary = _stateful_boundary()
    boundary._issued.add(SESSION)

    anyio.run(boundary._sweep_if_due)

    assert not idle.exists(), "control: the sweep did not remove the workspace"
    assert SESSION not in boundary._issued
    caller = boundary._identify(_scope(SESSION), True)
    assert caller == HttpCaller(
        STREAMABLE_HTTP, None, server_mode=MODE_STATEFUL, session_expired=True
    )


def test_a_session_the_sweep_kept_stays_issued(root) -> None:
    kept = _workspace(root, SESSION)
    removed = _workspace(root, OTHER)
    _age(removed, 7200)
    boundary = _stateful_boundary()
    boundary._issued.update({SESSION, OTHER})

    anyio.run(boundary._sweep_if_due)

    assert kept.is_dir() and not removed.exists()
    assert SESSION in boundary._issued
    assert OTHER not in boundary._issued
    assert boundary._identify(_scope(SESSION), True).session_id == SESSION


def test_an_id_the_server_never_issued_is_not_called_expired(root) -> None:
    boundary = _stateful_boundary()

    caller = boundary._identify(_scope("never-issued"), True)

    assert caller == HttpCaller(STREAMABLE_HTTP, None, server_mode=MODE_STATEFUL)


def test_only_the_most_recent_expired_ids_are_remembered() -> None:
    boundary = _stateful_boundary()
    ids = [f"expired-{n}" for n in range(1100)]
    boundary._issued.update(ids)

    boundary._end_what_the_sweep_removed(ids)

    assert len(boundary._expired) == 1024
    assert "expired-1099" in boundary._expired
    assert "expired-0" not in boundary._expired
    # An id forgotten by the cap is answered as one never issued: still refused.
    assert boundary._identify(_scope("expired-0"), True).session_id is None


def test_a_boundary_that_is_not_stateful_leaves_its_issued_set_alone() -> None:
    boundary = SessionBoundary(_app, mode=MODE_SSE)
    boundary._issued.add(SESSION)

    boundary._end_what_the_sweep_removed([SESSION])

    assert SESSION in boundary._issued
    assert not boundary._expired


def _a_context_carrying(caller: HttpCaller) -> Context:
    request = SimpleNamespace(scope={CALLER_SCOPE_KEY: caller})
    return Context(request_context=SimpleNamespace(request=request))


def test_the_refusal_says_the_session_expired() -> None:
    expired = HttpCaller(
        STREAMABLE_HTTP, None, server_mode=MODE_STATEFUL, session_expired=True
    )
    refusal = session_identity_refusal(
        UNIDENTIFIED_SESSION_ID, "run_ash_scan", ctx=_a_context_carrying(expired)
    )

    assert refusal is not None
    assert refusal["error_type"] == SESSION_IDENTITY_REQUIRED
    assert "expired" in refusal["error"], refusal
    assert "did not issue" not in refusal["error"], refusal
    assert "initialize" in refusal["error"], refusal


def test_the_refusal_for_an_unissued_id_does_not_say_expired() -> None:
    never = HttpCaller(STREAMABLE_HTTP, None, server_mode=MODE_STATEFUL)
    refusal = session_identity_refusal(
        UNIDENTIFIED_SESSION_ID, "run_ash_scan", ctx=_a_context_carrying(never)
    )

    assert refusal is not None
    assert "expired" not in refusal["error"], refusal
    assert "did not issue" in refusal["error"], refusal


def test_the_holds_on_a_session_are_counted() -> None:
    boundary = _stateful_boundary()

    boundary._stream_opened(SESSION)
    boundary._stream_opened(SESSION)
    boundary._stream_closed(SESSION)
    assert SESSION in boundary._open_streams, "one stream is still open"

    boundary._stream_closed(SESSION)
    assert SESSION not in boundary._open_streams
    assert SESSION not in boundary._stream_holds


def test_a_stateful_sessions_get_stream_keeps_it_while_it_is_open(root) -> None:
    """Red at the base: only an sse stream counted as open, so a stateful
    client that held its standalone GET stream lost its tree to the sweep after
    the TTL, with the stream still open."""
    idle = _workspace(root, SESSION)
    seen: List[str] = []

    async def scenario() -> None:
        entered = anyio.Event()
        release = anyio.Event()

        async def app(scope, receive, send) -> None:
            entered.set()
            await release.wait()

        boundary = _stateful_boundary(app)
        boundary._issued.add(SESSION)

        async def the_get_request() -> None:
            await boundary(_scope(SESSION, "GET"), _receive, _discard)

        async with anyio.create_task_group() as group:
            group.start_soon(the_get_request)
            with anyio.fail_after(30):
                await entered.wait()
            assert SESSION in boundary._open_streams
            # The stream is open and the workspace has not been used for hours.
            _age(idle, 7200)
            boundary._next_sweep = 0.0
            await boundary._sweep_if_due()
            seen.append("kept" if idle.is_dir() else "removed")
            seen.append("issued" if SESSION in boundary._issued else "ended")
            release.set()
        # The request returned: the stream is closed, and the next sweep removes
        # the idle session and ends it.
        assert SESSION not in boundary._open_streams
        _age(idle, 7200)
        boundary._next_sweep = 0.0
        await boundary._sweep_if_due()
        seen.append("removed" if not idle.exists() else "kept")
        seen.append("issued" if SESSION in boundary._issued else "ended")

    anyio.run(scenario)

    assert seen == ["kept", "issued", "removed", "ended"], seen


def test_a_post_does_not_hold_the_session_open(root) -> None:
    """Only the standalone GET stream is an event stream the client holds."""
    boundary = _stateful_boundary()
    boundary._issued.add(SESSION)
    held: List[bool] = []

    async def app(scope, receive, send) -> None:
        held.append(SESSION in boundary._open_streams)

    boundary.app = app

    async def the_post_request() -> None:
        await boundary(_scope(SESSION, "POST"), _receive, _discard)

    anyio.run(the_post_request)

    assert held == [False]
