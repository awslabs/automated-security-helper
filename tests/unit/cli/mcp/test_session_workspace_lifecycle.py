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
from tests.utils.mcp_transport_harness import LOOPBACK_BASE_URL, StreamableHttpClient

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
    sandbox = root / session_id
    (sandbox / "source").mkdir(parents=True)
    stamp = time.time() - age
    for path in (sandbox / "source", sandbox):
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
    app = build_streamable_http_app(mount_path="/mcp", host="127.0.0.1")
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

    assert removed == ["stale"] and not stale.exists()
    assert default.is_dir(), "the stdio session's workspace is its server's to remove"
    assert elsewhere.is_dir() and (root / "a-link").is_symlink()
    assert busy.is_dir(), "a workspace a scan is reading was swept"


def test_a_request_naming_a_session_keeps_its_workspace(root) -> None:
    named = _sandbox(root, "platform-a", 400 * DAY)
    unnamed = _sandbox(root, "platform-b", 400 * DAY)
    app = build_streamable_http_app(
        mount_path="/mcp",
        stateless_http=True,
        host="127.0.0.1",
        trust_upstream_session_id=True,
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

    assert excinfo.value.exit_code == 3
