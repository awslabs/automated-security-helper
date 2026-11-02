# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The TTL sweep keeps a session whose sse event stream the boundary holds open.

An sse event stream that is open but has sent no message for longer than the
workspace TTL is idle, not ended. The sweep decided liveness by the workspace's
age alone, so it removed the workspace, the bound profile and the
delivered-source record of such a session while its transport still served it;
the session's next scan then ran without the profile it selected. The boundary
now names the sessions whose streams are open, the sweep keeps them whatever
their age (they end through ``end_session`` when the stream ends), and each
sweep marks their workspaces used, so another server sharing the root, which
sweeps by age alone, keeps them too.

Being issued is not being live: a stateful session the SDK dropped for being
idle stays issued, since nothing tells the boundary it ended, and keeping every
issued session kept the tree of every client that disconnected without a DELETE
until shutdown. Those are the TTL's to cover, as every request refreshes the
session it names.
"""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp.http_sessions import (
    MODE_SSE,
    MODE_STATEFUL,
    SessionBoundary,
)
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace

pytestmark = pytest.mark.unit

OPEN_STREAM = "open-stream-session"
IDLE = "idle-session"


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


def test_the_sweep_keeps_a_session_named_as_in_use(root) -> None:
    held = _workspace(root, OPEN_STREAM)
    idle = _workspace(root, IDLE)

    # A cutoff in the future: every workspace is older than the TTL.
    removed = sessions.sweep_stale_workspaces(
        1.0, now=time.time() + 3600, in_use={OPEN_STREAM}
    )

    assert removed == [IDLE]
    assert held.is_dir(), "the sweep removed a session the boundary still holds"
    assert not idle.exists()


def test_the_sweep_without_the_set_removes_every_stale_workspace(root) -> None:
    held = _workspace(root, OPEN_STREAM)
    idle = _workspace(root, IDLE)

    removed = sessions.sweep_stale_workspaces(1.0, now=time.time() + 3600)

    assert sorted(removed) == [IDLE, OPEN_STREAM]
    assert not held.exists() and not idle.exists()


async def _app(scope, receive, send) -> None:
    raise AssertionError("the sweep never reaches the app")


def test_the_boundary_sweeps_around_the_sessions_whose_streams_are_open(root) -> None:
    held = _workspace(root, OPEN_STREAM)
    idle = _workspace(root, IDLE)
    _age(held, 7200)
    _age(idle, 7200)
    boundary = SessionBoundary(_app, mode=MODE_SSE, session_workspace_ttl=60.0)
    # The id the open event stream's endpoint event carried, its stream open.
    boundary._issued.add(OPEN_STREAM)
    boundary._open_streams.add(OPEN_STREAM)

    asyncio.run(boundary._sweep_if_due())

    assert held.is_dir(), "the boundary's sweep removed a session it still holds"
    assert not idle.exists(), "the sweep kept a session nobody holds"


@pytest.mark.parametrize("mode", [MODE_SSE, MODE_STATEFUL])
def test_an_issued_session_with_no_open_stream_is_swept(root, mode) -> None:
    """Being issued keeps nothing by itself. A stateful session the SDK dropped
    for being idle stays issued for the life of the process, since nothing tells
    the boundary it ended; kept on that account, the tree of every client that
    disconnects without a DELETE stayed until shutdown. Only an open stream is
    kept; the TTL covers the rest, as every request names its session. Run in
    both modes that hold issued ids: the stateful one is the case the sentence
    is about, and the sse one is the other server that keeps an issued set."""
    issued = _workspace(root, OPEN_STREAM)
    _age(issued, 7200)
    boundary = SessionBoundary(
        _app,
        mode=mode,
        session_workspace_ttl=60.0,
        endpoint_path="/mcp" if mode == MODE_STATEFUL else None,
    )
    boundary._issued.add(OPEN_STREAM)

    asyncio.run(boundary._sweep_if_due())

    assert not issued.exists(), "an issued session with no open stream was kept"


def test_the_sweep_marks_an_open_streams_workspace_used(root) -> None:
    """The keep is this process's knowledge; another server sharing the root
    sweeps by age alone. So each sweep marks the open streams' workspaces used,
    and a replica's sweep reads them as fresh."""
    held = _workspace(root, OPEN_STREAM)
    _age(held, 7200)
    boundary = SessionBoundary(_app, mode=MODE_SSE, session_workspace_ttl=60.0)
    boundary._issued.add(OPEN_STREAM)
    boundary._open_streams.add(OPEN_STREAM)

    asyncio.run(boundary._sweep_if_due())

    assert held.is_dir()
    assert time.time() - held.stat().st_mtime < 600, "the workspace was not touched"
