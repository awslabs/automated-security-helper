# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Ending a session deletes its workspace under a hidden name.

What the code does, by path
---------------------------
``sessions.end_session`` removes a session's state through
``_remove_session_state``, which removes the workspace tree, clears the bound
profile and the delivered-source record, and drops the registry entry. The tree
delete is the long step.

* ``source_delivery.remove_session_workspace`` renames the workspace to a hidden
  sibling, ``.<session id>.deleting-<uuid4>``, and deletes that. The rename is
  instant, so the session's own path is free for the whole delete. A request for
  the same id that arrives during the delete builds a fresh workspace there.
* ``_remove_session_state`` then drops the registry entry without touching the
  disk. It used to rename and delete whatever stood at the session's path after
  the tree delete, which was the fresh workspace.
* A hidden sibling a delete could not finish stays on disk. The TTL sweep removes
  one once it is older than the TTL, marker or no marker, because the delete may
  have removed the marker first.

How the cells work
------------------
The delete is held open with an event the cell releases after the racing request.
Every cell is DISARMED: the workspace root is the cell's own tmp_path, and nothing
runs git, a scanner or the network.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.session_paths import (
    SESSION_MARKER,
    hidden_deleting_name,
)
from automated_security_helper.cli.mcp.sessions import (
    SCAN_PRESENCE_DIR,
    end_session,
    get_default_registry,
    reset_default_registry_for_tests,
    sweep_stale_workspaces,
)

SESSION = "racing-session"
#: How long a held delete waits before it gives up: far past any cell, so a cell
#: that fails early cannot leave a thread behind for long.
HOLD_SECONDS = 30.0
#: Older than the TTL the sweep cells pass.
LONG_AGO_SECONDS = 10_000.0
TTL_SECONDS = 600.0


@pytest.fixture(autouse=True)
def workspace_root(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "ws"
    root.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.setattr(sd, "_SESSION_SOURCE_DIRS", {})
    reset_default_registry_for_tests()
    yield root
    reset_default_registry_for_tests()


def _a_workspace_with_a_file(root: Path) -> Path:
    workspace = sd._session_workspace(root, SESSION)
    workspace.mkdir(parents=True)
    (workspace / SESSION_MARKER).touch()
    (workspace / "payload.txt").write_text("delivered\n", encoding="utf-8")
    return workspace


def _hidden_siblings(root: Path) -> list:
    return sorted(root.glob(f".{SESSION}.deleting-*"))


def _made_old(path: Path) -> None:
    """Give ``path`` an mtime far past any TTL the cells pass."""
    then = time.time() - LONG_AGO_SECONDS
    os.utime(path, (then, then))


def test_a_request_during_the_delete_of_an_ended_session_keeps_its_workspace(
    workspace_root, monkeypatch
):
    """The delete of an ended session's tree is held open and a request for the
    same id arrives. The request gets a workspace of its own, and it is still
    there, with its marker, after the ended session's delete finishes: the end of
    the old session does not delete the new one's directory."""
    registry = get_default_registry()
    session = registry.get_or_create(SESSION)
    workspace = session.workspace_root
    (workspace / "payload.txt").write_text("delivered\n", encoding="utf-8")
    entered = threading.Event()
    release = threading.Event()
    real_remove_tree = sd._remove_tree

    def a_delete_held_open(path):
        entered.set()
        release.wait(timeout=HOLD_SECONDS)
        return real_remove_tree(path)

    monkeypatch.setattr(sd, "_remove_tree", a_delete_held_open)
    outcome: dict = {}

    def end_it() -> None:
        outcome["ended"] = end_session(SESSION)

    ender = threading.Thread(target=end_it, daemon=True)
    ender.start()
    try:
        assert entered.wait(HOLD_SECONDS), "control: the delete never began"
        registry.get_or_create(SESSION)
    finally:
        release.set()
    ender.join(HOLD_SECONDS)

    assert not ender.is_alive(), "control: the end of the session never returned"
    assert outcome.get("ended") is True, outcome
    assert workspace.is_dir(), "the new request's workspace was deleted"
    assert (workspace / SESSION_MARKER).is_file()
    assert not (workspace / "payload.txt").exists()
    assert _hidden_siblings(workspace_root) == []


def test_the_end_of_a_session_wins_over_a_request_that_binds_state_during_the_delete(
    workspace_root, monkeypatch
):
    """Pins today's behavior; it is not a decision that this is the right one. A
    request for the ended session's id arrives during the delete and records a
    delivered source. The end of the session finishes by dropping the session's
    registry entry and its delivered-source record, so the racing request's record
    and entry are gone afterwards, though its workspace directory stays on disk (the
    test above). Whether the request should instead be refused, or keep its state,
    is a product decision for a later change: when it is made, this test changes
    with it."""
    registry = get_default_registry()
    session = registry.get_or_create(SESSION)
    workspace = session.workspace_root
    entered = threading.Event()
    release = threading.Event()
    real_remove_tree = sd._remove_tree

    def a_delete_held_open(path):
        entered.set()
        release.wait(timeout=HOLD_SECONDS)
        return real_remove_tree(path)

    monkeypatch.setattr(sd, "_remove_tree", a_delete_held_open)
    ender = threading.Thread(target=end_session, args=(SESSION,), daemon=True)
    ender.start()
    try:
        assert entered.wait(HOLD_SECONDS), "control: the delete never began"
        registry.get_or_create(SESSION)
        sd._set_session_source_dir(SESSION, workspace / "source")
        assert sd.get_session_source_dir(SESSION) is not None, (
            "control: the racing record was not made"
        )
    finally:
        release.set()
    ender.join(HOLD_SECONDS)

    assert not ender.is_alive(), "control: the end of the session never returned"
    assert registry.get(SESSION) is None
    assert sd.get_session_source_dir(SESSION) is None


def test_the_delete_of_a_session_workspace_runs_on_a_hidden_name(
    workspace_root, monkeypatch
):
    """The tree delete never runs at the session's own path: it is renamed aside
    first, so the path is free while the delete runs."""
    workspace = _a_workspace_with_a_file(workspace_root)
    seen: list = []
    real_remove_tree = sd._remove_tree

    def a_delete_that_is_recorded(path):
        seen.append((Path(path).name, workspace.exists()))
        return real_remove_tree(path)

    monkeypatch.setattr(sd, "_remove_tree", a_delete_that_is_recorded)

    gone = sd.remove_session_workspace(SESSION, workspace_root=workspace_root)

    assert gone is True
    assert len(seen) == 1, seen
    name, live_path_present = seen[0]
    assert name.startswith(f".{SESSION}.deleting-"), name
    assert live_path_present is False
    assert not workspace.exists()
    assert _hidden_siblings(workspace_root) == []


def test_a_workspace_that_cannot_be_renamed_is_still_deleted_in_place(
    workspace_root, monkeypatch
):
    """Control: a rename the filesystem refuses falls back to deleting the
    workspace where it stands, as before."""
    workspace = _a_workspace_with_a_file(workspace_root)
    seen: list = []
    real_remove_tree = sd._remove_tree

    def a_delete_that_is_recorded(path):
        seen.append(Path(path).name)
        return real_remove_tree(path)

    def a_rename_that_is_refused(src, dst, *args, **kwargs):
        raise PermissionError(13, "a planted refusal of the rename")

    monkeypatch.setattr(sd, "_remove_tree", a_delete_that_is_recorded)
    monkeypatch.setattr(os, "rename", a_rename_that_is_refused)

    gone = sd.remove_session_workspace(SESSION, workspace_root=workspace_root)

    assert gone is True
    assert seen == [SESSION], seen
    assert not workspace.exists()


def test_removing_a_workspace_that_is_not_on_disk_deletes_nothing(
    workspace_root, monkeypatch
):
    """No workspace, no rename and no delete; the answer is still True and the
    delivered-source record is dropped."""
    sd._set_session_source_dir(SESSION, workspace_root / SESSION / "source")
    seen: list = []
    real_remove_tree = sd._remove_tree

    def a_delete_that_is_recorded(path):
        seen.append(Path(path).name)
        return real_remove_tree(path)

    monkeypatch.setattr(sd, "_remove_tree", a_delete_that_is_recorded)

    gone = sd.remove_session_workspace(SESSION, workspace_root=workspace_root)

    assert gone is True
    assert seen == [], seen
    assert sd.get_session_source_dir(SESSION) is None


def test_the_sweep_removes_an_old_hidden_leftover_whatever_it_holds(workspace_root):
    """A delete that could not finish leaves its hidden sibling, and the marker
    may be the first thing it removed. The sweep removes the leftover once it is
    older than the TTL, and returns no session id for it: it is no session."""
    leftover = workspace_root / hidden_deleting_name(SESSION)
    leftover.mkdir()
    (leftover / "stuck.bin").write_text("x", encoding="utf-8")
    _made_old(leftover)

    removed = sweep_stale_workspaces(ttl_seconds=TTL_SECONDS)

    assert not leftover.exists()
    assert removed == []


def test_the_sweep_leaves_what_is_not_an_old_hidden_leftover(workspace_root):
    """Controls for the cell above, each a must-not-remove input: a leftover
    younger than the TTL (a delete may still be running on it), a directory
    with the leftover's shape but not its uuid, and a directory of the
    operator's own with no marker."""
    young = workspace_root / hidden_deleting_name(SESSION)
    young.mkdir()
    shaped = workspace_root / f".{SESSION}.deleting-not-a-uuid"
    shaped.mkdir()
    _made_old(shaped)
    notes = workspace_root / "operator-notes"
    notes.mkdir()
    (notes / "todo.txt").write_text("keep\n", encoding="utf-8")
    _made_old(notes)

    removed = sweep_stale_workspaces(ttl_seconds=TTL_SECONDS)

    assert young.is_dir()
    assert shaped.is_dir()
    assert (notes / "todo.txt").is_file()
    assert removed == []


def test_the_sweep_leaves_an_old_hidden_name_a_scan_presence_owns(workspace_root):
    """Control, a must-not-remove input the tests above lack: the name, built by the
    producer, is old and holds a tree, but a scan of another server registered a
    presence directory under it. The tree is live, so the sweep keeps it."""
    owned = workspace_root / hidden_deleting_name(SESSION)
    owned.mkdir()
    (owned / "tree.txt").write_text("a scan reads this\n", encoding="utf-8")
    _made_old(owned)
    (workspace_root / SCAN_PRESENCE_DIR / owned.name).mkdir(parents=True)

    removed = sweep_stale_workspaces(ttl_seconds=TTL_SECONDS)

    assert (owned / "tree.txt").is_file()
    assert removed == []
