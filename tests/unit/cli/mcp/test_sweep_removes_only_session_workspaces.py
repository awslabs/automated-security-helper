# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The TTL sweep removes only directories ASH created as session workspaces.

ASH marks each session workspace when it creates one, and the sweep removes
marked directories only, so anything else under ``ASH_MCP_WORKSPACE_ROOT`` --
notes, backups, a ``.git`` directory -- stays. Every way a workspace comes into
being is covered: source delivery, the session registry, and a profile bound with
``select_profile``.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.profile_registry import (
    clear_all_session_state,
    materialize_session_config,
)
from automated_security_helper.config.ash_config import AshConfig

OLD = 400 * 24 * 3600


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    sessions.reset_default_registry_for_tests()
    yield workspace
    sessions.reset_default_registry_for_tests()
    clear_all_session_state()


def _age(path: Path) -> None:
    stamp = time.time() - OLD
    # Windows cannot set a link's own times (os.utime has no follow_symlinks
    # there); nothing aged here is a link, so following is the same call.
    follow = os.utime not in os.supports_follow_symlinks
    for item in [*path.rglob("*"), path]:
        os.utime(item, (stamp, stamp), follow_symlinks=follow)


def test_directories_ash_did_not_create_survive(root) -> None:
    for name in ("notes", "backups/2026", ".git/objects"):
        (root / name).mkdir(parents=True)
        (root / name / "keep.txt").write_text("operator data\n")
    for name in ("notes", "backups", ".git"):
        _age(root / name)

    removed = sessions.sweep_stale_workspaces(24 * 3600)

    assert removed == [], removed
    for name in ("notes/keep.txt", "backups/2026/keep.txt", ".git/objects/keep.txt"):
        assert (root / name).is_file(), name


@pytest.mark.parametrize("how", ["zip-upload", "session-registry", "bound-profile"])
def test_every_way_a_workspace_is_created_marks_it(root, how) -> None:
    session_id = f"made-by-{how}"
    if how == "zip-upload":
        sd.set_source_zip_chunk("u1", 0, "", False, session_id=session_id)
    elif how == "session-registry":
        sessions.get_default_registry().get_or_create(session_id)
    else:
        materialize_session_config(session_id, AshConfig())
    _age(root / session_id)

    removed = sessions.sweep_stale_workspaces(24 * 3600)

    assert removed == [session_id], removed
    assert not (root / session_id).exists()


@pytest.mark.parametrize(
    "name", ["__default__", "__DEFAULT__", ".stdio-servers", ".Stdio-Servers"]
)
def test_names_ash_reserves_survive_in_any_case(root, name) -> None:
    """On a case-insensitive filesystem each spelling is stdio's own directory."""
    reserved = root / name
    reserved.mkdir()
    (reserved / ".ash-mcp-session").write_text("")
    _age(reserved)

    removed = sessions.sweep_stale_workspaces(24 * 3600)

    assert removed == [], removed
    assert reserved.is_dir()
