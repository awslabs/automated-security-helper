# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A profile bound while the sweep deletes a stale session's tree is refused as busy.

The TTL sweep renames a stale workspace aside under the presence guard
(``_set_session_state_aside``), then releases the guard and deletes the renamed
tree (``_remove_set_aside_tree``). The session reads busy through the whole
removal: from the start of the sweep's hold until the delete of the set-aside
tree is done, a write for the session is refused ``session_workspace_busy``.
The registry entry that carries the hold is forgotten only when the delete is
done, so a request that lands during the delete does not build a fresh
workspace at the freed path.

The presence lock stays free during the delete (the other servers' registrations
do not wait out an rmtree); only this session's writes are held. A write after
the sweep has returned is admitted into a fresh workspace.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterator

import pytest
import yaml

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.profile_registry import (
    clear_all_session_state,
    clear_profile_registry,
    register_profiles,
    set_profile_registry,
)
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace
from automated_security_helper.cli.mcp_tools import mcp_select_profile

pytestmark = pytest.mark.unit

STALE = "stale-session"


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Iterator[Path]:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    sessions.reset_default_registry_for_tests()
    sessions.reset_guard_refusal_warning_for_tests()
    sessions._ended_while_scanning.clear()
    clear_profile_registry()
    clear_all_session_state()
    yield workspace
    clear_profile_registry()
    clear_all_session_state()
    sessions._ended_while_scanning.clear()
    sessions.reset_guard_refusal_warning_for_tests()
    sessions.reset_default_registry_for_tests()


def _stale_workspace(root: Path) -> Path:
    sandbox = mark_session_workspace(root / STALE)
    (sandbox / "source").mkdir()
    (sandbox / "source" / "app.py").write_text("x = 1\n", encoding="utf-8")
    then = time.time() - 3600
    for path in (sandbox, *sandbox.iterdir()):
        os.utime(path, (then, then))
    return sandbox


def _register_strict(tmp_path: Path) -> None:
    profile = tmp_path / "strict.yaml"
    profile.write_text(yaml.safe_dump({"project_name": "strict"}), encoding="utf-8")
    set_profile_registry(register_profiles([f"strict={profile}"]))


def test_a_profile_bound_during_the_delete_is_refused_as_busy(
    root: Path, monkeypatch, tmp_path
) -> None:
    sandbox = _stale_workspace(root)
    _register_strict(tmp_path)

    entered, release = threading.Event(), threading.Event()
    seen: Dict[str, Any] = {"deleted": [], "lock_free": []}
    lock_path = root / sessions.SCAN_PRESENCE_DIR / sessions._SCAN_PRESENCE_LOCK
    real_remove = sd._remove_tree

    def a_delete_that_waits(path: Path) -> bool:
        with open(lock_path, "a+b") as probe:
            seen["lock_free"].append(sessions._try_lock(probe).error is None)
        seen["deleted"].append(path)
        entered.set()
        release.wait(30)
        return real_remove(path)

    monkeypatch.setattr(sd, "_remove_tree", a_delete_that_waits)
    removed: Dict[str, Any] = {}

    def sweep() -> None:
        removed["ids"] = sessions.sweep_stale_workspaces(1.0)

    sweeper = threading.Thread(target=sweep, name="test-sweep")
    sweeper.start()
    try:
        assert entered.wait(30), "control: the sweep never reached the delete"
        refused = mcp_select_profile("strict", session_id=STALE)
        # No fresh workspace was built at the freed path by the refused write.
        built_during_delete = sandbox.exists()
    finally:
        release.set()
        sweeper.join(30)
    assert not sweeper.is_alive(), "the sweep did not finish"

    # The sweep removed the stale session, deleting the renamed tree with the
    # presence lock free (the other servers do not wait out the delete).
    assert removed["ids"] == [STALE], removed
    assert seen["lock_free"] == [True], seen
    (deleted,) = seen["deleted"]
    assert deleted != sandbox and deleted.name.startswith("."), deleted
    # The write that landed during the delete was refused as busy, and it
    # created nothing at the session's freed path.
    assert refused["success"] is False, refused
    assert refused["error_type"] == sessions.SESSION_WORKSPACE_BUSY, refused
    assert built_during_delete is False, "a refused write built a workspace"
    assert not sandbox.exists(), "the sweep left a workspace at the session's path"


def test_a_profile_bound_after_the_sweep_returns_is_admitted_fresh(
    root: Path, tmp_path
) -> None:
    """The control: the hold ends with the delete, not before and not after."""
    sandbox = _stale_workspace(root)
    _register_strict(tmp_path)

    assert sessions.sweep_stale_workspaces(1.0) == [STALE]
    assert not sandbox.exists()

    bound = mcp_select_profile("strict", session_id=STALE)

    assert bound["success"] is True, bound
    config_path = Path(bound["config_path"])
    assert config_path.is_file()
    assert sandbox in config_path.parents, (config_path, sandbox)


def test_a_delete_that_fails_does_not_leave_the_session_busy(
    root: Path, monkeypatch, tmp_path
) -> None:
    """The hold is released in a finally: a delete that raises frees the session.

    The sweep renames the workspace aside before it deletes, so a failed delete
    leaves the aside tree for the next pass, never the session busy.
    """
    sandbox = _stale_workspace(root)
    _register_strict(tmp_path)

    def a_delete_that_raises(path: Path) -> bool:
        raise OSError(13, "Permission denied", str(path))

    monkeypatch.setattr(sd, "_remove_tree", a_delete_that_raises)
    sessions.sweep_stale_workspaces(1.0)
    monkeypatch.undo()

    bound = mcp_select_profile("strict", session_id=STALE)

    assert bound["success"] is True, bound
    assert not sandbox.exists()
    assert len(list(sandbox.parent.glob(f".{STALE}.deleting-*"))) == 1
