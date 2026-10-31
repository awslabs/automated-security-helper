# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The issued sessions end when the app is asked to shut down.

Why: the app's own lifespan exit can end the process without returning (a signal
ended the HTTP server while a scan was still running), and that exit comes before
Starlette sends ``lifespan.shutdown.complete``. A ``SessionBoundary`` that ended
sessions on that message alone ended none on such an exit, so every issued
session's workspace stayed on disk. The sessions are now ended at the
``lifespan.shutdown`` message, before the app sees it; the pass at
``lifespan.shutdown.complete`` stays as the retry of a removal that failed.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List

import anyio
import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp.http_sessions import (
    MODE_STATELESS,
    SessionBoundary,
)

pytestmark = pytest.mark.unit


def _run_lifespan(
    app: Callable[..., Any], issued: List[str]
) -> tuple[SessionBoundary, List[Dict[str, Any]]]:
    """Drive ``app`` through one lifespan under a boundary that issued ``issued``."""
    boundary = SessionBoundary(app, mode=MODE_STATELESS)
    boundary._issued.update(issued)
    messages = iter([{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}])
    sent: List[Dict[str, Any]] = []

    async def receive() -> Dict[str, Any]:
        return next(messages)

    async def send(message: Dict[str, Any]) -> None:
        sent.append(message)

    async def main() -> None:
        await boundary({"type": "lifespan"}, receive, send)

    anyio.run(main)
    return boundary, sent


def test_sessions_end_at_the_shutdown_request_when_no_complete_follows(
    monkeypatch,
) -> None:
    """An app whose lifespan exit ends the process still gets its sessions ended."""
    ended: List[str] = []
    monkeypatch.setattr(sessions, "end_session", lambda sid: ended.append(sid))

    async def app(scope, receive, send) -> None:
        await receive()
        await send({"type": "lifespan.startup.complete"})
        await receive()
        # The process exits inside the lifespan exit here, so no
        # ``lifespan.shutdown.complete`` is ever sent.

    boundary, sent = _run_lifespan(app, ["session-b", "session-a"])

    assert ended == ["session-a", "session-b"]
    assert boundary._issued == set()
    assert [m["type"] for m in sent] == ["lifespan.startup.complete"]


def test_a_shutdown_that_completes_ends_each_session_once(monkeypatch) -> None:
    ended: List[str] = []
    monkeypatch.setattr(sessions, "end_session", lambda sid: ended.append(sid))
    received: List[Dict[str, Any]] = []

    async def app(scope, receive, send) -> None:
        received.append(await receive())
        await send({"type": "lifespan.startup.complete"})
        received.append(await receive())
        await send({"type": "lifespan.shutdown.complete"})

    boundary, sent = _run_lifespan(app, ["session-b", "session-a"])

    assert ended == ["session-a", "session-b"]
    assert boundary._issued == set()
    # The lifespan messages reach the app and the server unchanged.
    assert [m["type"] for m in received] == ["lifespan.startup", "lifespan.shutdown"]
    assert [m["type"] for m in sent] == [
        "lifespan.startup.complete",
        "lifespan.shutdown.complete",
    ]


def test_a_removal_that_fails_at_the_request_is_tried_again_at_complete(
    monkeypatch,
) -> None:
    attempts: List[str] = []

    def end_session(session_id: str) -> bool:
        attempts.append(session_id)
        if session_id == "session-a" and attempts.count("session-a") == 1:
            raise OSError("the workspace could not be removed this time")
        return True

    monkeypatch.setattr(sessions, "end_session", end_session)

    async def app(scope, receive, send) -> None:
        await receive()
        await send({"type": "lifespan.startup.complete"})
        await receive()
        await send({"type": "lifespan.shutdown.complete"})

    boundary, _sent = _run_lifespan(app, ["session-a", "session-b"])

    assert attempts == ["session-a", "session-b", "session-a"]
    assert boundary._issued == set()
