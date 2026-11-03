# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Ending a session removes its directory even when the session was handed out without a path.

``MCPSessionRegistry.session_for`` resolves the session's directory under the
workspace root once, when it makes the entry, and keeps a session whose path
could not be resolved (a passing ``OSError`` resolving the parent, or no
workspace root for the moment) with ``workspace_root`` None rather than
refusing it. ``get_or_create`` resolves the path again; ``disconnect`` did not,
and passed the None on to the rename-aside, which answers None for it, so the
end of such a session removed nothing. Meanwhile the source-delivery tools
resolve the root for themselves and may have built the directory, so a tree
stayed on disk, with the session's uploads and config in it, until the TTL
sweep found it.

``disconnect`` now resolves the path again before the rename-aside, as
``get_or_create`` does. A root that still cannot be resolved leaves nothing to
remove, as before.
"""

from __future__ import annotations

import errno
from pathlib import Path
from typing import Iterator

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace

pytestmark = pytest.mark.unit

LATE = "late-session"


@pytest.fixture
def root(tmp_path, monkeypatch) -> Iterator[Path]:
    workspace = tmp_path / "ws"
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    yield workspace


def _failing_then_real(monkeypatch, failures: int):
    """``session_directory`` that fails ``failures`` times, then answers as the real one."""
    real = sessions.session_directory
    calls = {"failed": 0}

    def resolve(parent: Path, session_id: str) -> Path:
        if calls["failed"] < failures:
            calls["failed"] += 1
            raise OSError(errno.EIO, "Input/output error")
        return real(parent, session_id)

    monkeypatch.setattr(sessions, "session_directory", resolve)
    return calls


def test_a_session_handed_out_without_a_path_has_its_directory_removed(
    root: Path, monkeypatch
) -> None:
    registry = sessions.MCPSessionRegistry(workspace_parent=root)
    calls = _failing_then_real(monkeypatch, failures=1)
    session = registry.session_for(LATE)
    assert session.workspace_root is None, "the precondition: no path was resolved"
    assert calls["failed"] == 1
    # What a delivery does for the session meanwhile: it builds the directory.
    sandbox = mark_session_workspace(root / LATE)
    (sandbox / "source").mkdir()
    (sandbox / "source" / "app.py").write_text("x = 1\n", encoding="utf-8")

    registry.disconnect(LATE)

    assert not sandbox.exists(), "the session's directory stayed on disk"
    assert [p.name for p in root.iterdir()] == [], (
        "the rename-aside left a hidden delete name behind"
    )
    assert registry.get(LATE) is None


def test_a_session_whose_path_was_resolved_is_removed_as_before(root: Path) -> None:
    """The control: the path resolved at session_for, the directory goes."""
    registry = sessions.MCPSessionRegistry(workspace_parent=root)
    registry.get_or_create(LATE)
    sandbox = root / LATE
    assert sandbox.is_dir()

    registry.disconnect(LATE)

    assert not sandbox.exists()
    assert [p.name for p in root.iterdir()] == []


def test_a_root_that_still_cannot_be_resolved_leaves_nothing_to_remove(
    root: Path, monkeypatch
) -> None:
    """A path that cannot be resolved at the end either: the entry goes, nothing
    is raised, and whatever stands under the root is left as it is."""
    registry = sessions.MCPSessionRegistry(workspace_parent=root)
    _failing_then_real(monkeypatch, failures=10)
    registry.session_for(LATE)
    bystander = mark_session_workspace(root / "other-session")

    registry.disconnect(LATE)

    assert registry.get(LATE) is None
    assert bystander.is_dir(), "a directory the session did not own was removed"
