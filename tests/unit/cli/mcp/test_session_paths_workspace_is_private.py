# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A session workspace, and the root it is created under, belong to the owner alone.

``mark_session_workspace`` created the session directory and any missing
ancestor with the process umask's default permissions, so under a 022 umask
every other account on the host could list the workspace root (the live
session ids) and read a session's delivered source. The directories this call
creates are now 0o700 whatever the umask; a directory that already exists keeps
the mode it has.
"""

from __future__ import annotations

import logging
import os
import stat
import sys
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp.session_paths import (
    SESSION_MARKER,
    mark_session_workspace,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits"),
]


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_a_new_workspace_and_the_root_it_creates_are_private(tmp_path) -> None:
    root = tmp_path / "ws-root"
    previous = os.umask(0o022)
    try:
        sandbox = mark_session_workspace(root / "session-a")
    finally:
        os.umask(previous)

    assert _mode(sandbox) == 0o700, oct(_mode(sandbox))
    assert _mode(root) == 0o700, oct(_mode(root))
    assert (sandbox / SESSION_MARKER).is_file()


def test_an_existing_root_keeps_the_mode_it_has(tmp_path) -> None:
    root = tmp_path / "ws-root"
    root.mkdir()
    os.chmod(root, 0o755)
    previous = os.umask(0o022)
    try:
        sandbox = mark_session_workspace(root / "session-b")
    finally:
        os.umask(previous)

    assert _mode(root) == 0o755, "an existing directory's mode was changed"
    assert _mode(sandbox) == 0o700, oct(_mode(sandbox))


def test_marking_an_existing_workspace_again_changes_nothing(tmp_path) -> None:
    sandbox = tmp_path / "ws-root" / "session-c"
    sandbox.mkdir(parents=True)
    os.chmod(sandbox, 0o750)

    mark_session_workspace(sandbox)

    assert _mode(sandbox) == 0o750
    assert (sandbox / SESSION_MARKER).is_file()


def test_each_directory_is_private_from_the_moment_it_exists(
    tmp_path, monkeypatch
) -> None:
    """The mode is the creating call's own, not a chmod after the fact: between
    a mkdir under the umask and a later chmod, another account could open the
    new directory and keep a handle whose listing outlives the chmod."""
    chmods: list = []
    real_chmod = os.chmod

    def recording_chmod(path, mode, *args, **kwargs):
        chmods.append((Path(path), mode))
        return real_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(os, "chmod", recording_chmod)
    root = tmp_path / "ws-root"
    previous = os.umask(0o022)
    try:
        sandbox = mark_session_workspace(root / "session-d")
    finally:
        os.umask(previous)

    assert chmods == [], f"a directory was made open and tightened after: {chmods}"
    assert _mode(root) == 0o700, oct(_mode(root))
    assert _mode(sandbox) == 0o700, oct(_mode(sandbox))


def test_an_existing_root_other_accounts_can_list_is_warned_about_once(
    tmp_path, monkeypatch, caplog
) -> None:
    """A root ASH did not make keeps its mode, and the operator is told once,
    not once per session, that other accounts can read the live session ids."""
    from automated_security_helper.cli.mcp import session_paths

    monkeypatch.setattr(session_paths, "_listable_parents_warned", set())
    root = tmp_path / "ws-root"
    root.mkdir()
    os.chmod(root, 0o755)

    with caplog.at_level(logging.WARNING):
        mark_session_workspace(root / "session-e")
        mark_session_workspace(root / "session-f")

    about_the_root = [
        record.getMessage()
        for record in caplog.records
        if str(root) in record.getMessage()
        and "live session ids" in record.getMessage()
    ]
    assert len(about_the_root) == 1, caplog.text
    assert "0o755" in about_the_root[0], about_the_root[0]
    assert _mode(root) == 0o755, "an existing directory's mode was changed"


def test_the_presence_registries_are_private_too(tmp_path, monkeypatch) -> None:
    """The stdio and scan presence registries sit beside the session
    directories under the root; made under the umask, they and the root they
    created first were listable by every account on the host."""
    from automated_security_helper.cli.mcp import sessions

    root = tmp_path / "ws-root"
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    sessions.reset_default_registry_for_tests()
    previous = os.umask(0o022)
    try:
        with sessions.StdioServerPresence():
            pass
        with sessions._scan_presence_guard(root):
            pass
    finally:
        os.umask(previous)
        sessions.reset_default_registry_for_tests()

    assert _mode(root) == 0o700, oct(_mode(root))
    assert _mode(root / sessions.STDIO_SERVERS_DIR) == 0o700
    assert _mode(root / sessions.SCAN_PRESENCE_DIR) == 0o700


def test_an_explicit_registry_parent_is_private_too(tmp_path, caplog) -> None:
    """A registry given its workspace parent made it under the umask (0o755),
    so every session directory created beneath it warned that other accounts
    could list the live session ids: the parent is made private as the
    default root is, and a session under it draws no warning."""
    from automated_security_helper.cli.mcp import session_paths
    from automated_security_helper.cli.mcp.sessions import MCPSessionRegistry

    parent = tmp_path / "sessions"
    previous = os.umask(0o022)
    try:
        registry = MCPSessionRegistry(workspace_parent=parent)
        with caplog.at_level(logging.WARNING):
            registry.get_or_create("session-g")
    finally:
        os.umask(previous)

    assert _mode(parent) == 0o700, oct(_mode(parent))
    assert parent not in session_paths._listable_parents_warned
    assert not [
        record.getMessage()
        for record in caplog.records
        if "live session ids" in record.getMessage()
    ], caplog.text
