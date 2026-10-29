# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``disconnect`` does not serialize the registry behind the workspace rmtree.

``disconnect`` renames the workspace to a hidden sibling while holding the
registry lock, releases the lock, and only then removes the renamed directory.
The rename and the map-entry removal share one lock hold, so a concurrent
``get_or_create`` of the same id never finds the half-deleted tree: either the
directory is still the session's (before the disconnect took the lock) or it is
gone from the session's path and a fresh, empty one is built.

The cells gate ``_remove_workspace`` with a recorded stand-in so the concurrent
lookup runs exactly while the removal is in flight. Everything waits on events,
not on real time, and every directory is under ``tmp_path``.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.cli.mcp.sessions import MCPSessionRegistry

pytestmark = pytest.mark.unit

_JOIN_S = 30.0


@pytest.fixture
def registry(tmp_path: Path) -> MCPSessionRegistry:
    return MCPSessionRegistry(workspace_parent=tmp_path / "sessions")


class _GatedRemoval:
    """A recorded ``_remove_workspace`` double that holds each call until released."""

    def __init__(self, original) -> None:
        self._original = original
        self.calls: List[Path] = []
        self.started = threading.Event()
        self.go = threading.Event()

    def __call__(self, registry: MCPSessionRegistry, workspace: Path) -> None:
        self.calls.append(workspace)
        self.started.set()
        assert self.go.wait(_JOIN_S)
        self._original(registry, workspace)


def _hidden_siblings(parent: Path, session_id: str) -> List[Path]:
    return sorted(parent.glob(f".{session_id}.deleting-*"))


def test_a_concurrent_get_or_create_during_the_removal_gets_a_fresh_empty_directory(
    registry: MCPSessionRegistry, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = _GatedRemoval(MCPSessionRegistry._remove_workspace)

    def _gated(self: MCPSessionRegistry, workspace: Path) -> None:
        # A plain function binds as a method; the gate object alone would not.
        gate(self, workspace)

    monkeypatch.setattr(MCPSessionRegistry, "_remove_workspace", _gated)
    session = registry.get_or_create("racing")
    workspace = session.workspace_root
    (workspace / "doomed.txt").write_text("x", encoding="utf-8")
    del session

    worker = threading.Thread(target=registry.disconnect, args=("racing",))
    worker.start()
    try:
        assert gate.started.wait(_JOIN_S)
        # The registry lock is not held while the removal double runs.
        assert registry._lock.acquire(blocking=False)
        registry._lock.release()
        # The removal works on the renamed sibling, never on the live path.
        assert gate.calls == [workspace.parent / gate.calls[0].name]
        assert gate.calls[0] != workspace
        assert gate.calls[0].name.startswith(".racing.deleting-")
        # A caller that arrives mid-removal gets a fresh directory with none of
        # the old session's files in it.
        fresh = registry.get_or_create("racing")
        assert fresh.workspace_root == workspace
        assert fresh.workspace_root.is_dir()
        assert not (fresh.workspace_root / "doomed.txt").exists()
    finally:
        gate.go.set()
        worker.join(_JOIN_S)

    assert not worker.is_alive()
    # The rmtree removed the renamed sibling and left the fresh directory.
    assert workspace.is_dir()
    assert _hidden_siblings(workspace.parent, "racing") == []


def test_a_disconnect_with_no_concurrent_caller_leaves_no_renamed_sibling(
    registry: MCPSessionRegistry,
) -> None:
    """Control: the ordinary path still removes the tree, and nothing is left behind."""
    session = registry.get_or_create("plain")
    workspace = session.workspace_root
    (workspace / "note.txt").write_text("x", encoding="utf-8")
    del session

    registry.disconnect("plain")

    assert not workspace.exists()
    assert _hidden_siblings(workspace.parent, "plain") == []
    # Idempotent, as before.
    registry.disconnect("plain")
    assert not workspace.exists()


def test_a_disconnect_whose_rename_fails_still_removes_the_tree(
    registry: MCPSessionRegistry, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The rename is the race guard, not the removal: when the filesystem refuses
    it, the best-effort rmtree still runs at the original name."""
    from automated_security_helper.cli.mcp import sessions as sessions_module

    session = registry.get_or_create("refused")
    workspace = session.workspace_root
    (workspace / "note.txt").write_text("x", encoding="utf-8")
    del session

    def a_rename_the_filesystem_refuses(*args: object, **kwargs: object) -> None:
        raise PermissionError("a planted refusal of the rename")

    monkeypatch.setattr(sessions_module.os, "rename", a_rename_the_filesystem_refuses)

    registry.disconnect("refused")

    assert not workspace.exists()
    assert "refused" not in registry
