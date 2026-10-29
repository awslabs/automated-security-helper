# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A deferred end of the stdio session asks again whether a server is live.

The stdio session is shared by every stdio server of one user. An exiting server
ends it only when, under the presence registry's lock, no other server is live.
When a scan of that server was still running, the end was deferred and
``finish_ended_session`` completed it later without asking again, so a server
that had started in between had the default workspace, with the tree it had
delivered, removed under it. The deferred end now keeps the workspace when a
live server holds a registry entry, and completes when none does.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp.profile_registry import DEFAULT_SESSION_ID
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace

pytestmark = pytest.mark.unit


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


def _default_workspace(root: Path) -> Path:
    sandbox = mark_session_workspace(root / DEFAULT_SESSION_ID)
    (sandbox / "source").mkdir()
    (sandbox / "source" / "app.py").write_text("x = 1\n", encoding="utf-8")
    return sandbox


def _a_live_servers_entry(root: Path) -> Any:
    """A locked presence entry, as a running stdio server holds one."""
    registry = root / sessions.STDIO_SERVERS_DIR
    registry.mkdir()
    handle = open(registry / "4242-live", "a+b")
    assert sessions._try_lock(handle), "the stand-in entry could not be locked"
    return handle


def test_a_deferred_end_keeps_the_workspace_a_live_server_uses(root) -> None:
    sandbox = _default_workspace(root)
    handle = _a_live_servers_entry(root)
    try:
        sessions._ended_while_scanning.add(DEFAULT_SESSION_ID)

        sessions.finish_ended_session(DEFAULT_SESSION_ID)

        assert sandbox.is_dir(), "the default workspace was removed under a live server"
        assert DEFAULT_SESSION_ID not in sessions._ended_while_scanning
    finally:
        handle.close()


def test_a_deferred_end_completes_when_no_server_is_live(root) -> None:
    sandbox = _default_workspace(root)
    (root / sessions.STDIO_SERVERS_DIR).mkdir()
    sessions._ended_while_scanning.add(DEFAULT_SESSION_ID)

    sessions.finish_ended_session(DEFAULT_SESSION_ID)

    assert not sandbox.exists()
    assert DEFAULT_SESSION_ID not in sessions._ended_while_scanning


def test_a_deferred_end_of_another_session_does_not_ask_the_registry(root) -> None:
    sandbox = mark_session_workspace(root / "remote-session")
    handle = _a_live_servers_entry(root)
    try:
        sessions._ended_while_scanning.add("remote-session")

        sessions.finish_ended_session("remote-session")

        assert not sandbox.exists(), "a live stdio server kept another session"
    finally:
        handle.close()
