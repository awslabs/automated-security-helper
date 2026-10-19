# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Registering a stdio server drops the entries of dead ones and needs its own lock.

An entry left by a server that was killed stays until some server exits normally, so
a root that only ever sees killed servers keeps them all. A server whose lock on its
own entry silently failed would read as dead to an exiting sibling, which would then
remove the default workspace under it. Registration therefore sweeps dead entries
and fails, leaving nothing behind, when its own lock cannot be taken.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from automated_security_helper.cli.mcp import sessions


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


def test_a_lock_that_cannot_be_taken_fails_the_registration(root, monkeypatch) -> None:
    monkeypatch.setattr(sessions, "_try_lock", lambda handle: False)

    presence = sessions.StdioServerPresence()
    presence.__enter__()

    assert presence._entry is None
    assert presence._handle is None
    assert _entries(root) == []


def test_a_failed_registration_leaves_the_default_workspace_alone_on_exit(
    root, monkeypatch
) -> None:
    default = root / "__default__" / "source"
    default.mkdir(parents=True)
    monkeypatch.setattr(sessions, "_try_lock", lambda handle: False)

    with sessions.StdioServerPresence():
        pass

    assert default.is_dir()
