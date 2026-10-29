# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan's session claim and lock need the session, not its directory.

``run_ash_scan`` claims its session before it returns the scan id and takes the
session's lock on the worker thread. Both live on the in-memory ``MCPSession``
(``MCPSessionRegistry.session_for``), which creates nothing under the workspace
root. A change to the delivered tree takes the session the same way: the
functions that write into the session's directory create and mark it
themselves. So a scan of a directory the operator granted starts even when the
workspace root can't be created, and leaves no session directory behind, and a
change that is refused leaves none either.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.profile_registry import DEFAULT_SESSION_ID
from automated_security_helper.cli.mcp.session_identity import serving_local_client


@pytest.fixture
def root(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "workspaces"
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    sessions.reset_default_registry_for_tests()
    yield workspace
    sessions.reset_default_registry_for_tests()


@pytest.fixture
def scanned(monkeypatch) -> list:
    """Stand in for the scan itself; record the directories it was asked to scan."""
    calls: list = []

    def run_ash_scan(**kwargs):
        calls.append(kwargs["source_dir"])
        return None

    monkeypatch.setattr(
        "automated_security_helper.interactions.run_ash_scan.run_ash_scan",
        run_ash_scan,
    )
    return calls


def _scan(directory: Path) -> dict:
    from automated_security_helper.cli.mcp_tools import mcp_scan_directory
    from automated_security_helper.core.resource_management.scan_registry import (
        get_scan_registry,
    )

    async def main() -> dict:
        with serving_local_client():
            started = await mcp_scan_directory(
                directory_path=str(directory), session_id=DEFAULT_SESSION_ID
            )
            others = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
            await asyncio.gather(*others)
        return started

    started = asyncio.run(main())
    assert started.get("success") is True, started
    entry = get_scan_registry().get_scan(started["scan_id"])
    return {"started": started, "entry": entry}


def _granted(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return project


@pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs POSIX file modes that the current user can't override",
)
def test_a_scan_starts_when_the_workspace_root_cannot_be_created(
    tmp_path, monkeypatch, scanned
) -> None:
    locked = tmp_path / "read-only"
    locked.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(locked / "ash-mcp"))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    sessions.reset_default_registry_for_tests()
    project = _granted(tmp_path)
    locked.chmod(0o555)
    try:
        outcome = _scan(project)
    finally:
        locked.chmod(0o755)
        sessions.reset_default_registry_for_tests()

    assert scanned == [str(project)], outcome
    assert outcome["entry"].error_message is None, outcome["entry"].error_message
    assert not (locked / "ash-mcp").exists()


def test_a_scan_of_a_granted_directory_creates_no_session_directory(
    tmp_path, root, scanned
) -> None:
    project = _granted(tmp_path)

    outcome = _scan(project)

    assert scanned == [str(project)], outcome
    assert not (root / DEFAULT_SESSION_ID).exists()


def test_a_refused_change_leaves_no_session_directory(root) -> None:
    session = sessions.get_default_registry().session_for("fresh")
    assert session.try_claim_scan()
    try:
        with pytest.raises(sd.SourceDeliveryBusyError):
            sd.clear_source(session_id="fresh")
    finally:
        session.release_scan()

    assert not (root / "fresh").exists()


def test_get_or_create_still_gives_a_session_with_its_directory(root) -> None:
    registry = sessions.get_default_registry()
    in_memory = registry.session_for("later")
    assert not in_memory.workspace_root.exists()

    session = registry.get_or_create("later")

    assert session is in_memory
    assert (session.workspace_root / ".ash-mcp-session").is_file()
