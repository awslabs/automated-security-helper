# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A directory set aside for deleting is young, and a leftover that stays is logged.

What the code does, by path
---------------------------
A same-parent rename does not change the moved directory's own modification
time, so a workspace idle for longer than the TTL would be past the TTL under its
hidden delete name the moment it was renamed. The TTL sweep of a second server
sharing the root would then start a second delete halfway through the first.

* ``source_delivery._set_aside_for_removal`` and the registry's
  ``_rename_for_removal_locked`` set the renamed directory's modification time to
  the time of the rename, so a delete in progress is younger than any TTL.
* The sweep reads the answer of its delete. A leftover that cannot be deleted is
  logged once per name, not walked on every pass in silence.

Every cell is DISARMED: the workspace root is the cell's own tmp_path, and nothing
runs git, a scanner or the network.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.sessions import (
    MCPSessionRegistry,
    sweep_stale_workspaces,
)
from automated_security_helper.utils.log import ASH_LOGGER

LONG_AGO_SECONDS = 10_000.0
TTL_SECONDS = 600.0
#: How recent "just renamed" has to be: far above the time a rename takes, far
#: below the TTL.
FRESH_WITHIN_SECONDS = 120.0


@pytest.fixture(autouse=True)
def workspace_root(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "ws"
    root.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.setattr(sd, "_SESSION_SOURCE_DIRS", {})
    monkeypatch.setattr(sessions, "_leftovers_warned", set())
    return root


def _an_old_workspace(root: Path, session_id: str) -> Path:
    workspace = root / session_id
    workspace.mkdir()
    (workspace / "tree.txt").write_text("delivered\n", encoding="utf-8")
    then = time.time() - LONG_AGO_SECONDS
    os.utime(workspace / "tree.txt", (then, then))
    os.utime(workspace, (then, then))
    return workspace


def _age(path: Path) -> float:
    return time.time() - path.lstat().st_mtime


def test_a_workspace_set_aside_by_source_delivery_is_as_new_as_the_rename(
    workspace_root,
) -> None:
    workspace = _an_old_workspace(workspace_root, "idle-session")

    doomed = sd._set_aside_for_removal(workspace, "idle-session")

    assert doomed is not None and doomed != workspace
    assert _age(doomed) < FRESH_WITHIN_SECONDS, _age(doomed)


def test_a_workspace_set_aside_by_the_registry_is_as_new_as_the_rename(
    workspace_root,
) -> None:
    workspace = _an_old_workspace(workspace_root, "idle-session")
    registry = MCPSessionRegistry(workspace_parent=workspace_root)

    doomed = registry._rename_for_removal_locked("idle-session", workspace)

    assert doomed is not None and doomed != workspace
    assert _age(doomed) < FRESH_WITHIN_SECONDS, _age(doomed)


def test_the_sweep_leaves_a_directory_that_was_just_set_aside(workspace_root) -> None:
    """A delete is running on the hidden name (its workspace was idle for longer
    than the TTL before the rename): the sweep must not start a second delete."""
    workspace = _an_old_workspace(workspace_root, "idle-session")
    doomed = sd._set_aside_for_removal(workspace, "idle-session")
    assert doomed is not None

    sweep_stale_workspaces(ttl_seconds=TTL_SECONDS)

    assert (doomed / "tree.txt").is_file()


def test_a_leftover_that_cannot_be_deleted_is_logged_once(
    workspace_root, monkeypatch, caplog
) -> None:
    leftover = workspace_root / f".stuck.deleting-{uuid.uuid4()}"
    leftover.mkdir()
    (leftover / "kept.bin").write_text("x", encoding="utf-8")
    then = time.time() - LONG_AGO_SECONDS
    os.utime(leftover, (then, then))
    deletes: list = []

    def a_delete_that_cannot_finish(path) -> bool:
        deletes.append(Path(path).name)
        return False

    monkeypatch.setattr(sd, "_remove_tree", a_delete_that_cannot_finish)

    with caplog.at_level(logging.WARNING, logger=ASH_LOGGER.name):
        sweep_stale_workspaces(ttl_seconds=TTL_SECONDS)
        sweep_stale_workspaces(ttl_seconds=TTL_SECONDS)

    named = [
        record for record in caplog.records if leftover.name in record.getMessage()
    ]
    assert len(named) == 1, [record.getMessage() for record in caplog.records]
    # The second pass does not walk what the first one could not delete: the same
    # leftover would cost two full delete passes on every sweep for the life of the
    # process.
    assert deletes == [leftover.name], deletes


def test_giving_up_on_one_leftover_does_not_stop_the_sweep_clearing_another(
    workspace_root, monkeypatch
) -> None:
    """The skip is per name: a leftover the sweep reported and gave up on is not
    walked again, and a different old leftover that appears later is still deleted."""

    def an_old_leftover(name: str) -> Path:
        directory = workspace_root / name
        directory.mkdir()
        (directory / "kept.bin").write_text("x", encoding="utf-8")
        then = time.time() - LONG_AGO_SECONDS
        os.utime(directory, (then, then))
        return directory

    stuck = an_old_leftover(f".stuck.deleting-{uuid.uuid4()}")
    real_remove_tree = sd._remove_tree
    deletes: list = []

    def a_delete_that_cannot_finish_the_stuck_one(path) -> bool:
        deletes.append(Path(path).name)
        if Path(path).name == stuck.name:
            return False
        return real_remove_tree(path)

    monkeypatch.setattr(sd, "_remove_tree", a_delete_that_cannot_finish_the_stuck_one)

    sweep_stale_workspaces(ttl_seconds=TTL_SECONDS)
    other = an_old_leftover(f".other.deleting-{uuid.uuid4()}")
    sweep_stale_workspaces(ttl_seconds=TTL_SECONDS)

    assert not other.exists()
    assert stuck.exists()
    assert deletes == [stuck.name, other.name], deletes


def test_a_leftover_that_is_deleted_logs_nothing(workspace_root, caplog) -> None:
    """Control: the same old leftover with a delete that works is removed and
    leaves no warning."""
    leftover = workspace_root / f".gone.deleting-{uuid.uuid4()}"
    leftover.mkdir()
    (leftover / "kept.bin").write_text("x", encoding="utf-8")
    then = time.time() - LONG_AGO_SECONDS
    os.utime(leftover, (then, then))

    with caplog.at_level(logging.WARNING, logger=ASH_LOGGER.name):
        sweep_stale_workspaces(ttl_seconds=TTL_SECONDS)

    assert not leftover.exists()
    assert [
        r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING
    ] == []
