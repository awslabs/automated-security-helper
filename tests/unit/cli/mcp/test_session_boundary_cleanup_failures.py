# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A cleanup that fails is logged, and fails only the answer that promised it.

``SessionBoundary`` removes a session's state when it sees the session end (a
stateful ``DELETE``, an sse stream finishing, an app shutting down) and runs the
TTL sweep before it answers a request. If ``end_session`` raises while an sse
stream finishes or the app shuts down, the client still gets its answer, the
failure is logged with the session it concerned, and a later sweep removes what
the failed removal left behind.

A stateful ``DELETE`` is different: it is answered 2xx only after the removal
succeeded. When the removal fails the answer is a 500 and the session stays
issued, so the same ``DELETE`` sent again ends it. A failing sweep never fails
the request that started it, and still moves the next-sweep time, so it is not
retried on every request.
"""

from __future__ import annotations

import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List

import anyio
import pytest

from automated_security_helper.cli.mcp import http_sessions, sessions
from automated_security_helper.cli.mcp.http_sessions import (
    MODE_SSE,
    MODE_STATEFUL,
    MODE_STATELESS,
    SessionBoundary,
)
from automated_security_helper.cli.mcp.profile_registry import clear_session_state

pytestmark = pytest.mark.unit

LONG_AGO = 400 * 24 * 3600

_REAL_END_SESSION = sessions.end_session


class _Log:
    """Records warnings; any other log call is ignored."""

    def __init__(self) -> None:
        self.warnings: List[str] = []

    def warning(self, message: str) -> None:
        self.warnings.append(message)

    def __getattr__(self, name: str) -> Any:
        return lambda *args, **kwargs: None


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    sessions.reset_default_registry_for_tests()
    yield workspace
    sessions.reset_default_registry_for_tests()
    clear_session_state(None)


@pytest.fixture
def log(monkeypatch) -> _Log:
    recorder = _Log()
    monkeypatch.setattr(http_sessions, "_logger", lambda: recorder)
    return recorder


@pytest.fixture
def failing_end(monkeypatch) -> List[str]:
    """``end_session`` raises, and records the ids it was asked to end."""
    asked: List[str] = []

    def end_session(session_id: str) -> bool:
        asked.append(session_id)
        raise OSError("simulated removal failure")

    monkeypatch.setattr(sessions, "end_session", end_session)
    return asked


async def _receive() -> Dict[str, Any]:
    return {"type": "http.request", "body": b"", "more_body": False}


def _scope(method: str, path: str, headers=(), query: bytes = b"") -> Dict[str, Any]:
    return {
        "type": "http",
        "method": method,
        "path": path,
        "root_path": "",
        "headers": list(headers),
        "query_string": query,
    }


def _answering(body: bytes = b""):
    async def app(scope, receive, send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": body})

    return app


def _drive(boundary: SessionBoundary, scope: Dict[str, Any]) -> List[Dict[str, Any]]:
    sent: List[Dict[str, Any]] = []

    async def send(message: Dict[str, Any]) -> None:
        sent.append(message)

    async def main() -> None:
        await boundary(scope, _receive, send)

    anyio.run(main)
    return sent


def _age(workspace: Path, seconds: float) -> None:
    then = time.time() - seconds
    for path in (workspace, *workspace.iterdir()):
        os.utime(path, (then, then))


def _later_sweep_removes(
    boundary: SessionBoundary, session_id: str, root: Path
) -> None:
    """The boundary's own sweep, run as the server runs it before a request,
    removes what the failed removal left. Being issued keeps nothing by itself:
    only an open event stream does (``_sweep_if_due``), so what the sweep needs
    is that the session has none open. That is what is asserted, not that the id
    stays issued: for a shutdown or a finished sse stream nothing can send the
    removal again, and a DELETE that can (the tests above) pins the issued id
    itself. A sweep called directly with no ``in_use`` would show a removal the
    server never makes."""
    workspace = root / session_id
    assert workspace.is_dir(), "the failed removal should leave the tree"
    assert session_id not in boundary._open_streams, (
        "the failed removal should leave no event stream open"
    )
    _age(workspace, 2 * boundary.session_workspace_ttl)
    boundary._next_sweep = 0.0
    anyio.run(boundary._sweep_if_due)
    assert not workspace.exists(), "the boundary's sweep kept the ended session"


def _delete(session_id: str) -> Dict[str, Any]:
    return _scope("DELETE", "/mcp", headers=[(b"mcp-session-id", session_id.encode())])


def test_a_failed_removal_on_delete_answers_5xx_and_leaves_the_session_issued(
    root, log, failing_end
) -> None:
    session_id = "sess-delete"
    sessions.get_default_registry().get_or_create(session_id)
    boundary = SessionBoundary(_answering(), mode=MODE_STATEFUL, endpoint_path="/mcp")
    boundary._issued.add(session_id)

    sent = _drive(boundary, _delete(session_id))

    # The SDK's 2xx is replaced, and nothing of it follows the 500.
    assert [m["type"] for m in sent] == ["http.response.start", "http.response.body"]
    assert sent[0]["status"] == 500
    assert sent[1]["body"] == http_sessions._REMOVAL_FAILED_BODY
    assert failing_end == [session_id]
    assert len(log.warnings) == 1 and session_id in log.warnings[0], log.warnings
    assert session_id in boundary._issued
    # Inside the 24 h time to live the sweep leaves the tree: only a DELETE sent
    # again removes it.
    assert (root / session_id).is_dir()
    assert sessions.sweep_stale_workspaces(24 * 3600, now=time.time() + 3600) == []
    assert (root / session_id).is_dir()


def test_a_delete_sent_again_after_a_failed_removal_removes_the_workspace(
    root, log, failing_end, monkeypatch
) -> None:
    session_id = "sess-delete-retry"
    sessions.get_default_registry().get_or_create(session_id)
    boundary = SessionBoundary(_answering(), mode=MODE_STATEFUL, endpoint_path="/mcp")
    boundary._issued.add(session_id)

    first = _drive(boundary, _delete(session_id))
    assert first[0]["status"] == 500
    assert (root / session_id).is_dir()

    monkeypatch.setattr(sessions, "end_session", _REAL_END_SESSION)
    second = _drive(boundary, _delete(session_id))

    assert [m["type"] for m in second] == [
        "http.response.start",
        "http.response.body",
    ]
    assert second[0]["status"] == 200
    assert failing_end == [session_id], "only the first DELETE met the failure"
    assert not (root / session_id).exists()
    assert session_id not in boundary._issued


def test_a_failed_removal_at_shutdown_still_reports_shutdown(
    root, log, failing_end
) -> None:
    session_id = "sess-shutdown"
    sessions.get_default_registry().get_or_create(session_id)

    async def lifespan(scope, receive, send) -> None:
        await send({"type": "lifespan.shutdown.complete"})

    boundary = SessionBoundary(lifespan, mode=MODE_STATELESS)
    boundary._issued.add(session_id)

    sent = _drive(boundary, {"type": "lifespan"})

    assert sent == [{"type": "lifespan.shutdown.complete"}]
    assert failing_end == [session_id]
    assert len(log.warnings) == 1 and session_id in log.warnings[0], log.warnings
    _later_sweep_removes(boundary, session_id, root)


def test_a_failed_removal_when_an_sse_stream_ends_still_finishes_it(
    root, log, failing_end
) -> None:
    session_id = uuid.uuid4().hex
    sessions.get_default_registry().get_or_create(session_id)
    event = f"event: endpoint\ndata: /messages/?session_id={session_id}\n\n".encode()
    boundary = SessionBoundary(_answering(event), mode=MODE_SSE)

    sent = _drive(boundary, _scope("GET", "/sse"))

    assert [m["type"] for m in sent] == ["http.response.start", "http.response.body"]
    assert sent[0]["status"] == 200
    assert failing_end == [session_id]
    assert len(log.warnings) == 1 and session_id in log.warnings[0], log.warnings
    _later_sweep_removes(boundary, session_id, root)


def test_a_failing_sweep_does_not_fail_the_request(root, log, monkeypatch) -> None:
    calls: List[float] = []

    def sweep_stale_workspaces(ttl_seconds: float, now=None, *, in_use=None):
        calls.append(ttl_seconds)
        raise RuntimeError("simulated sweep failure")

    monkeypatch.setattr(sessions, "sweep_stale_workspaces", sweep_stale_workspaces)
    boundary = SessionBoundary(_answering(), mode=MODE_STATELESS)
    assert boundary._next_sweep == 0.0

    first = _drive(boundary, _scope("POST", "/mcp"))

    assert first[0]["status"] == 200
    assert calls == [boundary.session_workspace_ttl]
    assert len(log.warnings) == 1, log.warnings
    assert "sweep failed" in log.warnings[0]
    assert "simulated sweep failure" in log.warnings[0]
    # The failure moved the next-sweep time, so the next request does not retry.
    assert boundary._next_sweep - time.monotonic() > 60

    second = _drive(boundary, _scope("POST", "/mcp"))

    assert second[0]["status"] == 200
    assert calls == [boundary.session_workspace_ttl], "the failed sweep was retried"
    assert len(log.warnings) == 1, log.warnings
