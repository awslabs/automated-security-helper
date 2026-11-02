# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A disconnect that cannot remove all of a workspace says so, and clears read-only entries.

``MCPSessionRegistry.disconnect`` deleted the workspace, renamed aside to its
hidden delete name, with ``shutil.rmtree(ignore_errors=True)`` and returned, so a
delete that left entries behind was reported as a removal; a read-only entry,
which git makes of its pack files and Windows refuses to delete, was one such
entry. The removal runs through ``source_delivery._remove_tree``, which clears the
read-only bit and tries again, and what still cannot be removed is named in one
warning: under the hidden delete name the TTL sweep clears it later; at the
session's own path (the rename aside was refused) it stays until removed by hand.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.sessions import MCPSessionRegistry

pytestmark = pytest.mark.unit


@pytest.fixture
def registry(tmp_path) -> MCPSessionRegistry:
    return MCPSessionRegistry(workspace_parent=tmp_path / "sessions")


@pytest.fixture
def warnings(monkeypatch) -> List[str]:
    """Every warning the module logs, rendered."""
    from automated_security_helper.utils.log import ASH_LOGGER

    seen: List[str] = []

    def record(message, *args, **kwargs) -> None:
        seen.append(message % args if args else message)

    monkeypatch.setattr(ASH_LOGGER, "warning", record)
    return seen


def _hidden_siblings(parent: Path, session_id: str) -> List[Path]:
    return sorted(parent.glob(f".{session_id}.deleting-*"))


def test_a_delete_that_leaves_entries_behind_is_reported_once(
    registry, monkeypatch, warnings
) -> None:
    workspace = registry.get_or_create("stuck").workspace_root
    (workspace / "payload.txt").write_text("delivered\n", encoding="utf-8")
    deleted: List[Path] = []

    def a_delete_that_cannot_finish(path) -> bool:
        deleted.append(Path(path))
        return False

    monkeypatch.setattr(sd, "_remove_tree", a_delete_that_cannot_finish)

    registry.disconnect("stuck")

    assert len(deleted) == 1, deleted
    assert deleted[0].name.startswith(".stuck.deleting-"), deleted
    assert len(warnings) == 1, warnings
    assert str(deleted[0]) in warnings[0]
    assert "TTL sweep" in warnings[0]
    assert "stuck" not in registry


def test_a_delete_refused_the_rename_aside_is_reported_as_staying_in_place(
    registry, monkeypatch, warnings
) -> None:
    workspace = registry.get_or_create("refused").workspace_root
    (workspace / "payload.txt").write_text("delivered\n", encoding="utf-8")
    monkeypatch.setattr(sd, "_remove_tree", lambda path: False)

    def a_rename_the_filesystem_refuses(*args, **kwargs) -> None:
        raise PermissionError(13, "a planted refusal of the rename")

    monkeypatch.setattr(os, "rename", a_rename_the_filesystem_refuses)

    registry.disconnect("refused")

    assert len(warnings) == 1, warnings
    assert str(workspace) in warnings[0]
    assert "by hand" in warnings[0]


def test_a_delete_that_finishes_reports_nothing(registry, warnings) -> None:
    workspace = registry.get_or_create("clean").workspace_root
    (workspace / "payload.txt").write_text("delivered\n", encoding="utf-8")

    registry.disconnect("clean")

    assert not workspace.exists()
    assert _hidden_siblings(workspace.parent, "clean") == []
    assert warnings == []


@pytest.mark.skipif(
    sys.platform == "win32" or getattr(os, "geteuid", lambda: 0)() == 0,
    reason="a directory's mode refuses the delete only to a non-root POSIX account",
)
def test_a_read_only_directory_inside_the_workspace_is_removed(
    registry, warnings
) -> None:
    workspace = registry.get_or_create("packed").workspace_root
    objects = workspace / "objects"
    objects.mkdir()
    (objects / "pack.idx").write_text("x", encoding="utf-8")
    objects.chmod(0o555)
    try:
        registry.disconnect("packed")
    finally:
        if objects.exists():
            objects.chmod(0o755)

    assert not workspace.exists()
    assert _hidden_siblings(workspace.parent, "packed") == []
    assert warnings == []
