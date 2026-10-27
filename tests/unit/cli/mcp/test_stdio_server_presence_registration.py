# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Registering a stdio server drops the entries of dead ones and needs its own lock.

An entry left by a server that was killed stays until some server exits normally, so
a root that only ever sees killed servers keeps them all. A server whose lock on its
own entry silently failed would read as dead to an exiting sibling, which would then
remove the default workspace under it. Registration therefore sweeps dead entries and,
when its own lock cannot be taken, raises ``PresenceLockError`` naming the entry's
path: the server does not start, so no running server is ever without a locked entry.
The entry is a new file nobody else holds, so the refusal comes from the filesystem and
there is no retry. A scan's presence entry follows the same rule.
"""

from __future__ import annotations

import errno
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace


@pytest.fixture
def root(tmp_path: Path, monkeypatch) -> Path:
    workspace = tmp_path / "ws"
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    return workspace


def _entries(root: Path) -> List[str]:
    registry = root / sessions.STDIO_SERVERS_DIR
    return sorted(p.name for p in registry.iterdir() if p.name != ".lock")


def test_an_entry_left_by_a_killed_server_is_removed_by_the_next_start(root) -> None:
    killed = sessions.StdioServerPresence()
    killed.__enter__()
    killed.abandon_for_tests()
    assert len(_entries(root)) == 1

    with sessions.StdioServerPresence() as started:
        names = _entries(root)

        assert started._entry is not None
        assert names == [started._entry.name]


def test_a_live_servers_entry_survives_the_next_start(root) -> None:
    with sessions.StdioServerPresence() as first:
        with sessions.StdioServerPresence() as second:
            assert first._entry is not None and second._entry is not None
            assert _entries(root) == sorted([first._entry.name, second._entry.name])


def test_a_lock_that_cannot_be_taken_refuses_the_start_and_names_the_entry(
    root, monkeypatch
) -> None:
    monkeypatch.setattr(sessions, "_try_lock", lambda handle: False)

    presence = sessions.StdioServerPresence()
    with pytest.raises(sessions.PresenceLockError) as refused:
        presence.__enter__()

    assert presence._entry is None
    assert presence._handle is None
    assert _entries(root) == []
    assert str(root / sessions.STDIO_SERVERS_DIR) in str(refused.value)


def test_the_lock_is_asked_for_once_not_retried(root, monkeypatch) -> None:
    asked: List[object] = []

    def refuse(handle) -> bool:
        asked.append(handle)
        return False

    monkeypatch.setattr(sessions, "_try_lock", refuse)

    with pytest.raises(sessions.PresenceLockError):
        sessions.StdioServerPresence().__enter__()

    assert len(asked) == 1


def test_a_server_whose_lock_fails_never_runs_without_an_entry(
    root, monkeypatch
) -> None:
    """The sibling case: the exiting server removes the default workspace, and the
    refused server is not running under it."""
    default = root / "__default__" / "source"
    default.mkdir(parents=True)
    sibling = sessions.StdioServerPresence()
    sibling.__enter__()
    ran: List[str] = []

    with monkeypatch.context() as patched:
        patched.setattr(sessions, "_try_lock", lambda handle: False)
        with pytest.raises(sessions.PresenceLockError):
            with sessions.StdioServerPresence():
                ran.append("the refused server ran")

    assert ran == []
    assert _entries(root) == [sibling._entry.name]
    sibling.__exit__(None, None, None)
    assert not default.exists(), "the last registered server exits and cleans up"


def test_a_scan_whose_presence_lock_fails_does_not_start(root, monkeypatch) -> None:
    mark_session_workspace(root / "scanning")
    monkeypatch.setattr(sessions, "_try_lock", lambda handle: False)
    ran: List[str] = []

    with pytest.raises(sessions.PresenceLockError) as refused:
        with sessions.ScanPresence("scanning"):
            ran.append("the scan ran")

    assert ran == []
    assert str(root / sessions.SCAN_PRESENCE_DIR / "scanning") in str(refused.value)
    assert not (root / sessions.SCAN_PRESENCE_DIR / "scanning").exists()


def test_the_stdio_server_does_not_serve_when_its_lock_fails(root, monkeypatch) -> None:
    from automated_security_helper.cli import mcp_server

    served: List[str] = []
    monkeypatch.setattr(mcp_server.mcp, "run", lambda: served.append("served"))
    monkeypatch.setattr(sessions, "_try_lock", lambda handle: False)

    with pytest.raises(sessions.PresenceLockError):
        mcp_server.run_mcp_server()

    assert served == []


class _Refused:
    """What ``_try_lock`` returns for a refusal: false, carrying the error."""

    def __init__(self, error: OSError) -> None:
        self.error = error

    def __bool__(self) -> bool:
        return False


def test_a_refused_try_lock_carries_the_error_that_refused_it(tmp_path: Path) -> None:
    lock_file = tmp_path / "held.lock"
    with open(lock_file, "a+b") as holder, open(lock_file, "a+b") as contender:
        taken = sessions._try_lock(holder)
        assert taken and taken.error is None

        refused = sessions._try_lock(contender)

        assert not refused
        assert isinstance(refused.error, OSError), "a refusal carries its OSError"


def test_the_start_refusal_names_the_errno_and_does_not_blame_lock_support(
    root, monkeypatch
) -> None:
    monkeypatch.setattr(
        sessions,
        "_try_lock",
        lambda handle: _Refused(OSError(errno.ENOSPC, "No space left on device")),
    )

    with pytest.raises(sessions.PresenceLockError) as refused:
        sessions.StdioServerPresence().__enter__()

    text = str(refused.value)
    assert f"errno {errno.ENOSPC} ENOSPC: No space left on device" in text, text
    assert "the filesystem does lock files there" in text, text
    assert "ASH_MCP_WORKSPACE_ROOT" in text, text
    assert "supports file locks" not in text, text


def test_a_scan_refusal_names_the_errno_too(root, monkeypatch) -> None:
    mark_session_workspace(root / "scanning")
    monkeypatch.setattr(
        sessions,
        "_try_lock",
        lambda handle: _Refused(OSError(errno.EIO, "Input/output error")),
    )

    with pytest.raises(sessions.PresenceLockError) as refused:
        with sessions.ScanPresence("scanning"):
            pass

    text = str(refused.value)
    assert f"errno {errno.EIO} EIO: Input/output error" in text, text
    assert str(root / sessions.SCAN_PRESENCE_DIR / "scanning") in text, text


def test_a_refusal_with_no_recorded_error_says_so(root, monkeypatch) -> None:
    monkeypatch.setattr(sessions, "_try_lock", lambda handle: False)

    with pytest.raises(sessions.PresenceLockError) as refused:
        sessions.StdioServerPresence().__enter__()

    assert "no error was reported" in str(refused.value)
