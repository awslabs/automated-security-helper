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

The question and the removal are one step under the registry's lock file, as
the exit check is: a server registering between them is counted, or starts
after the removal. And the question fails closed: a registry that cannot be
read (a file table full, a directory listing that fails) answers as a live
server would, and the workspace stays; it was the exit check's answer to an
error already, while the deferred end read it as "no server is live".
"""

from __future__ import annotations

import shutil
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


def test_a_deferred_end_keeps_the_workspace_when_the_registry_cannot_be_read(
    root, monkeypatch
) -> None:
    """A passing failure while the entries are read answers as a live server
    would: the workspace stays, as it does when the exit check meets one. Read
    as "no server is live", the failure removed the tree of a live sibling."""
    sandbox = _default_workspace(root)
    (root / sessions.STDIO_SERVERS_DIR).mkdir()

    def cannot_list(registry: Path) -> bool:
        raise OSError(24, "Too many open files")

    monkeypatch.setattr(
        sessions.StdioServerPresence, "_another_server_is_live", cannot_list
    )
    sessions._ended_while_scanning.add(DEFAULT_SESSION_ID)

    sessions.finish_ended_session(DEFAULT_SESSION_ID)

    assert sandbox.is_dir(), "a read failure was taken as no live server"
    assert DEFAULT_SESSION_ID not in sessions._ended_while_scanning


def test_a_deferred_end_removes_the_workspace_under_the_registrys_lock(
    root, monkeypatch
) -> None:
    """The removal runs where the question was answered, before the registry's
    lock is dropped, so a server registering meanwhile is counted or starts after
    it. Released first, the lock let a server register into the removal."""
    sandbox = _default_workspace(root)
    registry = root / sessions.STDIO_SERVERS_DIR
    registry.mkdir()
    lock_was_held: list = []
    real_end_session = sessions.end_session

    def end_session_reading_the_lock(session_id: str) -> bool:
        with open(registry / sessions._STDIO_SERVERS_LOCK, "a+b") as probe:
            lock_was_held.append(not sessions._try_lock(probe))
        return real_end_session(session_id)

    monkeypatch.setattr(sessions, "end_session", end_session_reading_the_lock)
    sessions._ended_while_scanning.add(DEFAULT_SESSION_ID)

    sessions.finish_ended_session(DEFAULT_SESSION_ID)

    assert lock_was_held == [True], lock_was_held
    assert not sandbox.exists()


def test_a_deferred_end_forgets_the_session_in_memory_when_the_root_is_gone(
    root,
) -> None:
    """With no workspace root there is nothing on disk to remove, and the
    deferred end makes no root to say so; it still drops this server's own
    memory of the ended session (its registry entry here), as the end would
    have. Kept, the entry outlived the session for the life of the process."""
    sessions.get_default_registry().session_for(DEFAULT_SESSION_ID)
    sessions._ended_while_scanning.add(DEFAULT_SESSION_ID)
    shutil.rmtree(root)

    sessions.finish_ended_session(DEFAULT_SESSION_ID)

    assert sessions.get_default_registry().get(DEFAULT_SESSION_ID) is None
    assert DEFAULT_SESSION_ID not in sessions._ended_while_scanning
    assert not root.exists(), "the deferred end made the workspace root"


def test_a_deferred_end_forgets_the_session_in_memory_under_a_live_server(
    root,
) -> None:
    """The workspace stays for the live sibling; the exiting server's memory of
    the session is its own and goes."""
    sandbox = _default_workspace(root)
    handle = _a_live_servers_entry(root)
    try:
        sessions.get_default_registry().session_for(DEFAULT_SESSION_ID)
        sessions._ended_while_scanning.add(DEFAULT_SESSION_ID)

        sessions.finish_ended_session(DEFAULT_SESSION_ID)

        assert sandbox.is_dir()
        assert sessions.get_default_registry().get(DEFAULT_SESSION_ID) is None
    finally:
        handle.close()


def test_a_deferred_end_of_another_session_does_not_ask_the_registry(
    root, monkeypatch
) -> None:
    sandbox = mark_session_workspace(root / "remote-session")
    handle = _a_live_servers_entry(root)

    def asked(**kwargs: Any) -> bool:
        raise AssertionError("the stdio registry was asked about another session")

    monkeypatch.setattr(
        sessions.StdioServerPresence, "a_server_is_live", staticmethod(asked)
    )
    try:
        sessions._ended_while_scanning.add("remote-session")

        sessions.finish_ended_session("remote-session")

        assert not sandbox.exists(), "a live stdio server kept another session"
    finally:
        handle.close()
