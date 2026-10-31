# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace whose rename aside is refused is deleted inside the presence guard.

The guarded removals (``end_session``, the TTL sweep) rename the workspace to
its hidden delete name under the presence guard, release the guard, and delete
the renamed tree: safe, because a scan registering meanwhile finds no marker at
the session's path. ``source_delivery._set_aside_for_removal`` returns the
workspace ITSELF when the rename is refused, or when the stat fails with
anything but FileNotFoundError, and then the tree still stands at the session's
own path with its marker. Deleted after the release, as the split first did it,
that tree was deleted while another server's ScanPresence could take the guard,
find the marker and register under the deletion. That arm now deletes inside
the guard, as every delete did before the split.

Measured at the delete, as the released-guard tests measure theirs:
``source_delivery._remove_tree`` is stood in for by a function that asks for
the presence lock on a handle of its own without waiting. A lock that is
refused was held by the caller.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path
from typing import Any, Dict, Iterator

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace

pytestmark = pytest.mark.unit

ENDED = "ended-session"


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Iterator[Path]:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    sessions.reset_default_registry_for_tests()
    sessions.reset_guard_refusal_warning_for_tests()
    sessions._ended_while_scanning.clear()
    yield workspace
    sessions._ended_while_scanning.clear()
    sessions.reset_guard_refusal_warning_for_tests()
    sessions.reset_default_registry_for_tests()


@pytest.fixture
def delete_reads_the_lock(root: Path, monkeypatch) -> Dict[str, Any]:
    """``_remove_tree`` that records whether the presence lock was free when it ran."""
    real = sd._remove_tree
    seen: Dict[str, Any] = {"deleted": [], "lock_free": []}
    lock_path = root / sessions.SCAN_PRESENCE_DIR / sessions._SCAN_PRESENCE_LOCK

    def remove(path: Path) -> bool:
        with open(lock_path, "a+b") as probe:
            seen["lock_free"].append(sessions._try_lock(probe).error is None)
        seen["deleted"].append(path)
        return real(path)

    monkeypatch.setattr(sd, "_remove_tree", remove)
    return seen


def _workspace(root: Path) -> Path:
    sandbox = mark_session_workspace(root / ENDED)
    (sandbox / "source").mkdir()
    (sandbox / "source" / "app.py").write_text("x = 1\n", encoding="utf-8")
    return sandbox


def _refuse_the_rename_of(sandbox: Path, monkeypatch) -> None:
    """``os.rename`` refuses the one rename that sets the workspace aside; every
    other rename (the delete's own retries included) runs as it is."""
    real_rename = os.rename

    def refuse(src, dst, *args, **kwargs):
        if Path(src) == sandbox:
            raise PermissionError(errno.EACCES, "Permission denied", str(src))
        return real_rename(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "rename", refuse)


def test_a_refused_rename_deletes_in_place_with_the_guard_held(
    root: Path, delete_reads_the_lock, monkeypatch
) -> None:
    """Red at the base: the in-place delete ran with the lock free."""
    sandbox = _workspace(root)
    _refuse_the_rename_of(sandbox, monkeypatch)

    ended = sessions.end_session(ENDED)

    assert ended is True
    assert delete_reads_the_lock["deleted"] == [sandbox], delete_reads_the_lock
    assert delete_reads_the_lock["lock_free"] == [False], (
        "the tree was deleted at the session's own path with the guard released"
    )
    assert not sandbox.exists()
    assert [
        p.name for p in root.iterdir() if p.name != sessions.SCAN_PRESENCE_DIR
    ] == []


def test_a_rename_that_succeeds_still_deletes_with_the_guard_released(
    root: Path, delete_reads_the_lock
) -> None:
    """Control: the hidden-name path is unchanged by the fallback arm's cure."""
    sandbox = _workspace(root)

    ended = sessions.end_session(ENDED)

    assert ended is True
    (deleted,) = delete_reads_the_lock["deleted"]
    assert deleted != sandbox and deleted.name.startswith("."), deleted
    assert delete_reads_the_lock["lock_free"] == [True], delete_reads_the_lock
    assert not sandbox.exists()
