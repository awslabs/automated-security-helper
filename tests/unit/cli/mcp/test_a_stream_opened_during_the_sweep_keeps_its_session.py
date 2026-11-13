# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A stateful session whose stream opens while the sweep runs is not ended.

The sweep reads the open streams once, before its worker thread starts, and the
boundary applies the worker's result on the event loop afterwards. A client can
open its standalone ``GET`` stream in between, after the worker last read the
workspace's age and before the result is applied. The apply used to forget every
id the worker removed, so that session left ``_issued`` with its stream open and
its next request was answered as an expired session.

The interleaving here is deterministic: the worker is replaced by one that runs
the real sweep and then opens the stream before it returns, so the stream opens
after the removal and before the apply, with no sleep and no timing.

* The session stays issued and is not remembered as expired.
* Its workspace, removed by the worker, is put back empty and marked, so a later
  sweep ages it and ends the session once the stream has closed.
* A removed session with no open stream is still ended.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Dict

import anyio
import pytest

from automated_security_helper.cli.mcp import http_sessions, sessions
from automated_security_helper.cli.mcp.http_sessions import (
    MODE_STATEFUL,
    SessionBoundary,
)
from automated_security_helper.cli.mcp.session_paths import (
    SESSION_MARKER,
    mark_session_workspace,
)

pytestmark = pytest.mark.unit

SESSION = "stateful-stream-opens-mid-sweep"
OTHER = "stateful-no-stream-mid-sweep"
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


def _stateful_boundary() -> SessionBoundary:
    return SessionBoundary(
        _app, mode=MODE_STATEFUL, endpoint_path=ENDPOINT, session_workspace_ttl=60.0
    )


def _scope(session_id: str) -> Dict[str, Any]:
    return {
        "type": "http",
        "method": "POST",
        "path": ENDPOINT,
        "root_path": "",
        "headers": [(b"mcp-session-id", session_id.encode("ascii"))],
        "query_string": b"",
    }


def _a_sweep_during_which_a_stream_opens(
    monkeypatch, boundary: SessionBoundary, session_id: str
) -> None:
    """Replace the worker with the real sweep followed by the stream opening.

    The real worker runs first, with the snapshot the boundary took before it
    (no open stream), so it removes the idle workspace; the stream opens after
    that and before the worker returns, which is before the boundary applies.
    """
    real = http_sessions._sweep_keeping_open_streams

    def worker(ttl_seconds, open_streams):
        removed = real(ttl_seconds, open_streams)
        boundary._stream_opened(session_id)
        return removed

    monkeypatch.setattr(http_sessions, "_sweep_keeping_open_streams", worker)


def test_a_stream_opened_during_the_sweep_keeps_its_session_issued(
    root, monkeypatch
) -> None:
    """Red at the head the sweep's forgetting step entered: the apply forgot the
    removed id without reading the open streams again, so the session left
    ``_issued`` with its stream open and its next request read as expired."""
    idle = _workspace(root, SESSION)
    _age(idle, 7200)
    boundary = _stateful_boundary()
    boundary._issued.add(SESSION)
    _a_sweep_during_which_a_stream_opens(monkeypatch, boundary, SESSION)

    anyio.run(boundary._sweep_if_due)

    assert SESSION in boundary._open_streams, "control: the stream did not open"
    assert SESSION in boundary._issued
    assert SESSION not in boundary._expired
    caller = boundary._identify(_scope(SESSION), True)
    assert caller.session_id == SESSION
    assert not caller.session_expired


def test_the_workspace_the_sweep_removed_is_put_back_for_the_kept_session(
    root, monkeypatch
) -> None:
    """The worker removed the tree before the stream opened, so a kept session
    needs a workspace of its own again or no later sweep would ever end it."""
    idle = _workspace(root, SESSION)
    _age(idle, 7200)
    boundary = _stateful_boundary()
    boundary._issued.add(SESSION)
    _a_sweep_during_which_a_stream_opens(monkeypatch, boundary, SESSION)

    anyio.run(boundary._sweep_if_due)

    assert (root / SESSION).is_dir()
    assert (root / SESSION / SESSION_MARKER).exists()
    assert not (root / SESSION / "source").exists(), "the removed tree is not restored"


def test_a_kept_session_is_ended_by_a_later_sweep_once_its_stream_has_closed(
    root, monkeypatch
) -> None:
    """Kept for the stream, not for good: when the stream closes and the
    workspace ages past the TTL, the next sweep removes it and ends the session."""
    idle = _workspace(root, SESSION)
    _age(idle, 7200)
    boundary = _stateful_boundary()
    boundary._issued.add(SESSION)
    real = http_sessions._sweep_keeping_open_streams
    _a_sweep_during_which_a_stream_opens(monkeypatch, boundary, SESSION)
    anyio.run(boundary._sweep_if_due)
    assert SESSION in boundary._issued, "control: the first sweep kept the session"

    monkeypatch.setattr(http_sessions, "_sweep_keeping_open_streams", real)
    boundary._stream_closed(SESSION)
    _age(root / SESSION, 7200)
    boundary._next_sweep = 0.0
    anyio.run(boundary._sweep_if_due)

    assert not (root / SESSION).exists()
    assert SESSION not in boundary._issued
    assert SESSION in boundary._expired


def test_a_removed_session_with_no_open_stream_is_still_ended(root) -> None:
    """Control: the apply keeps only the ids that have a stream open."""
    idle = _workspace(root, OTHER)
    _age(idle, 7200)
    boundary = _stateful_boundary()
    boundary._issued.add(OTHER)

    anyio.run(boundary._sweep_if_due)

    assert not idle.exists(), "control: the sweep did not remove the workspace"
    assert OTHER not in boundary._issued
    assert OTHER in boundary._expired
    assert not (root / OTHER).exists(), "an ended session gets no workspace back"
    assert boundary._identify(_scope(OTHER), True).session_expired


def test_the_apply_keeps_the_ids_with_an_open_stream_and_ends_the_rest() -> None:
    boundary = _stateful_boundary()
    boundary._issued.update({SESSION, OTHER})
    boundary._stream_opened(SESSION)

    boundary._end_what_the_sweep_removed([SESSION, OTHER])

    assert SESSION in boundary._issued
    assert SESSION not in boundary._expired
    assert OTHER not in boundary._issued
    assert OTHER in boundary._expired
