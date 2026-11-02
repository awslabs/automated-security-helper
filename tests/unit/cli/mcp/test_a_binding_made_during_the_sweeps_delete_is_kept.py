# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A profile bound while the sweep deletes a stale session's tree is admitted and kept.

The TTL sweep renames a stale workspace aside and forgets the session under the
presence guard (``_set_session_state_aside``), then releases the guard and
deletes the renamed tree (``_remove_set_aside_tree``). From the rename on, the
session's path is free and its registry entry is gone, so a request for the
same id that lands during the delete is not refused as busy: it builds a fresh
workspace at the session's path, which the delete of the hidden-named tree does
not touch, and keeps it. Held through the whole delete, as the guard was before
the two steps were split, the delete ran with the lock held and every other
server's registration waited on it; this pins the window the split opened: the
lock is free during the delete, the binding is admitted, and its file survives
the sweep.
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


def test_a_profile_bound_during_the_delete_is_admitted_and_kept(
    root: Path, monkeypatch, tmp_path
) -> None:
    sandbox = _stale_workspace(root)
    profile = tmp_path / "strict.yaml"
    profile.write_text(yaml.safe_dump({"project_name": "strict"}), encoding="utf-8")
    set_profile_registry(register_profiles([f"strict={profile}"]))

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
        bound = mcp_select_profile("strict", session_id=STALE)
    finally:
        release.set()
        sweeper.join(30)
    assert not sweeper.is_alive(), "the sweep did not finish"

    # The sweep removed the stale session, deleting the renamed tree with the
    # presence lock free (the window the split opened).
    assert removed["ids"] == [STALE], removed
    assert seen["lock_free"] == [True], seen
    (deleted,) = seen["deleted"]
    assert deleted != sandbox and deleted.name.startswith("."), deleted
    # The binding that landed during the delete was admitted, not refused as
    # busy: the old session was forgotten under the guard, so the request is a
    # fresh session at the freed path.
    assert bound["success"] is True, bound
    config_path = Path(bound["config_path"])
    assert config_path.is_file(), "the binding's file was removed with the stale tree"
    assert sandbox in config_path.parents, (config_path, sandbox)
    assert sandbox.is_dir()
