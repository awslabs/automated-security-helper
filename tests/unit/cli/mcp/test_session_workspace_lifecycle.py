# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Session workspace removal: the cases around the ends the transports report.

``test_session_workspace_is_removed_when_the_session_ends.py`` covers each
transport's end of session. These cover what surrounds it: a session that ends
while its scan runs keeps its tree until the scan returns, an app that shuts
down removes every session it issued, the TTL sweep's limits (the stdio
session, symlinks, a running scan, a session in use) and the operator's TTL
setting.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest
import typer
from starlette.testclient import TestClient

from automated_security_helper.cli.mcp import build_streamable_http_app, mcp_command
from automated_security_helper.cli.mcp import sessions
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from tests.utils.mcp_transport_harness import (
    LOOPBACK_BASE_URL,
    LOOPBACK_PORT,
    StreamableHttpClient,
)

pytestmark = pytest.mark.unit

DAY = 24 * 3600


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    sessions.reset_default_registry_for_tests()
    yield workspace
    sessions.reset_default_registry_for_tests()


def _sandbox(root: Path, session_id: str, age: float) -> Path:
    from automated_security_helper.cli.mcp.session_paths import (
        mark_session_workspace,
    )

    sandbox = mark_session_workspace(root / session_id)
    (sandbox / "source").mkdir(parents=True)
    stamp = time.time() - age
    for path in [*sandbox.rglob("*"), sandbox]:
        os.utime(path, (stamp, stamp))
    return sandbox


def test_a_session_that_ends_during_its_scan_keeps_its_tree_until_the_scan_returns(
    root,
) -> None:
    sandbox = _sandbox(root, "scanning", 0)
    lock = sessions.get_default_registry().get_or_create("scanning").lock

    with lock:  # stands in for a running scan of the session
        removed_now = sessions.end_session("scanning")
        still_there = sandbox.exists()
    sessions.finish_ended_session("scanning")

    assert removed_now is False
    assert still_there, "the tree was removed under a running scan"
    assert not sandbox.exists(), "the tree outlived the scan of an ended session"


def test_an_app_shutting_down_removes_every_session_it_issued(root) -> None:
    app = build_streamable_http_app(
        mount_path="/mcp", host="127.0.0.1", port=LOOPBACK_PORT
    )
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        http = StreamableHttpClient(client)
        issued = [http.open_session()[0] for _ in range(2)]
        for session_id in issued:
            (root / session_id / "source").mkdir(parents=True)

    for session_id in issued:
        assert not (root / session_id).exists(), session_id


def test_the_sweep_spares_what_it_must(root, tmp_path) -> None:
    default = _sandbox(root, "__default__", 400 * DAY)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (root / "a-link").symlink_to(elsewhere, target_is_directory=True)
    busy = _sandbox(root, "busy", 400 * DAY)
    stale = _sandbox(root, "stale", 400 * DAY)
    lock = sessions.get_default_registry().get_or_create("busy").lock
    # get_or_create made the busy directory new again; age it back.
    os.utime(busy, (time.time() - 400 * DAY,) * 2)

    with lock:
        removed = sessions.sweep_stale_workspaces(DAY)
        busy_during = busy.is_dir()
    # What a scan does when it returns: the sweep must not have queued a removal.
    sessions.finish_ended_session("busy")

    assert removed == ["stale"] and not stale.exists()
    assert default.is_dir(), "the stdio session's workspace is its server's to remove"
    assert elsewhere.is_dir() and (root / "a-link").is_symlink()
    assert busy_during, "a workspace a scan is reading was swept"
    assert busy.is_dir(), "the sweep's removal of a busy workspace ran after the scan"


def test_a_request_naming_a_session_keeps_its_workspace(root) -> None:
    named = _sandbox(root, "platform-a", 400 * DAY)
    unnamed = _sandbox(root, "platform-b", 400 * DAY)
    app = build_streamable_http_app(
        mount_path="/mcp",
        stateless_http=True,
        host="127.0.0.1",
        trust_upstream_session_id=True,
        port=LOOPBACK_PORT,
    )
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        http = StreamableHttpClient(client)
        _issued, headers = http.open_session({"Mcp-Session-Id": "platform-a"})

    assert named.is_dir()
    assert not unnamed.exists()


def test_the_operator_ttl_decides_what_is_stale(root) -> None:
    two_hours = _sandbox(root, "two-hours", 2 * 3600)
    fresh = _sandbox(root, "fresh", 0)
    app = build_streamable_http_app(
        mount_path="/mcp",
        stateless_http=True,
        host="127.0.0.1",
        session_workspace_ttl=3600,
        port=LOOPBACK_PORT,
    )
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        StreamableHttpClient(client).open_session()

    assert not two_hours.exists()
    assert fresh.is_dir()


class _Ctx:
    resilient_parsing = False


@pytest.mark.parametrize(
    "kwargs",
    [
        {"transport": "streamable-http", "session_workspace_ttl": 0},
        {"transport": "sse", "session_workspace_ttl": -5},
        {"transport": "stdio", "session_workspace_ttl": 3600},
    ],
    ids=["zero", "negative", "stdio"],
)
def test_an_unusable_ttl_is_refused_at_startup(monkeypatch, kwargs) -> None:
    monkeypatch.setattr(
        "automated_security_helper.cli.mcp._run_uvicorn",
        lambda *a, **k: pytest.fail("the server started"),
    )

    with pytest.raises(typer.Exit) as excinfo:
        mcp_command(ctx=_Ctx(), host="127.0.0.1", quiet=True, **kwargs)

    assert excinfo.value.exit_code == ASH_EXIT_USAGE_ERROR


async def _answer_ok(scope, receive, send) -> None:
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b""})


async def _request(boundary, answered: list, name: str) -> None:
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message) -> None:
        if message["type"] == "http.response.body":
            answered.append(name)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "headers": [],
        "query_string": b"",
    }
    await boundary(scope, receive, send)


def test_a_request_does_not_wait_for_another_requests_sweep(monkeypatch) -> None:
    """Only the request that starts a sweep waits for it."""
    import threading

    import anyio

    from automated_security_helper.cli.mcp.http_sessions import (
        MODE_STATELESS,
        SessionBoundary,
    )

    started = threading.Event()
    release = threading.Event()

    def slow_sweep(ttl_seconds, now=None, *, in_use=None):
        started.set()
        release.wait(30)
        return []

    monkeypatch.setattr(sessions, "sweep_stale_workspaces", slow_sweep)
    boundary = SessionBoundary(_answer_ok, mode=MODE_STATELESS)
    answered: list = []

    async def main() -> bool:
        async with anyio.create_task_group() as group:
            group.start_soon(_request, boundary, answered, "starts-the-sweep")
            await anyio.to_thread.run_sync(started.wait, 30)
            try:
                with anyio.fail_after(5):
                    await _request(boundary, answered, "arrives-during-it")
                return not release.is_set()
            finally:
                release.set()

    answered_while_sweeping = anyio.run(main)

    assert answered_while_sweeping
    assert answered == ["arrives-during-it", "starts-the-sweep"], answered
