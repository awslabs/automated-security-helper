# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A write a request makes while the TTL sweep removes its session is not lost.

Why this exists
---------------
An HTTP server runs ``sweep_stale_workspaces`` on a worker thread
(``http_sessions``), while the tools run on the event loop. A chunk of an upload
and a profile binding write a session's state without taking its change
(``MCPSession.try_begin_change``), which a running scan refuses, so the sweep
did not see them: one that landed after the sweep's last look at the session's
age was accepted, and then removed with the session. The client learned of a
lost chunk only at its next chunk ("out-of-order chunk") or at finalize, and of
a lost binding not at all: its next scan ran with no profile bound.

Each test makes the write land in that window: between the sweep's last look at
the age and the removal, where the sweep checks the scan presence registry.
The write must then either be refused, so that the client sends it again, or be
kept.
"""

from __future__ import annotations

import asyncio
import base64
import os
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_all_session_state,
    get_session_state,
    register_profiles,
    set_profile_registry,
)
from automated_security_helper.cli.mcp.session_paths import (
    SESSION_MARKER,
    mark_session_workspace,
)
from automated_security_helper.cli.mcp_tools import mcp_select_profile

DAY = 24 * 3600
SESSION = "idle-for-a-year"


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    sessions.reset_default_registry_for_tests()
    clear_profile_registry()
    clear_all_session_state()
    yield workspace
    clear_profile_registry()
    clear_all_session_state()
    sessions.reset_default_registry_for_tests()


def _stale_sandbox(root: Path) -> Path:
    sandbox = mark_session_workspace(root / SESSION)
    (sandbox / "source").mkdir()
    (sandbox / "source" / "app.py").write_text("x = 1\n", encoding="utf-8")
    stamp = time.time() - 400 * DAY
    # Every path this function made, named rather than walked.
    for path in [
        sandbox / "source" / "app.py",
        sandbox / "source",
        sandbox / SESSION_MARKER,
        sandbox,
    ]:
        os.utime(path, (stamp, stamp))
    return sandbox


def _sweep_with_a_write_in_its_window(monkeypatch, write) -> list:
    """Run the sweep, with ``write`` landing after its last look at the age."""
    real = sessions._a_scan_holds

    def the_write_lands_now(holder: Path) -> bool:
        write()
        return real(holder)

    monkeypatch.setattr(sessions, "_a_scan_holds", the_write_lands_now)
    try:
        return sessions.sweep_stale_workspaces(DAY)
    finally:
        monkeypatch.setattr(sessions, "_a_scan_holds", real)


def _chunk(sequence: int, data: bytes, last: bool) -> dict:
    return sd.set_source_zip_chunk(
        "upload",
        sequence,
        base64.b64encode(data).decode(),
        last,
        session_id=SESSION,
    )


def test_a_chunk_accepted_during_the_sweep_is_still_there_for_the_next(
    root, monkeypatch
) -> None:
    _stale_sandbox(root)
    landed: dict = {}

    def first_chunk() -> None:
        try:
            landed["accepted"] = _chunk(0, b"first ", last=False)
        except sessions.SessionWorkspaceBusyError as busy:
            landed["refused"] = busy

    _sweep_with_a_write_in_its_window(monkeypatch, first_chunk)

    assert landed, "the write never ran in the sweep's window"
    if "refused" in landed:
        # The client is told, and sends the upload again from its first chunk.
        assert _chunk(0, b"first ", last=False)["next_sequence"] == 1
        return
    # Accepted, so the server owes the client the bytes it said it received.
    assert landed["accepted"]["next_sequence"] == 1
    second = _chunk(1, b"second", last=True)
    assert second["received"] == len(b"first second")


def test_the_sweep_skips_a_session_while_a_request_writes_its_state(root) -> None:
    sandbox = _stale_sandbox(root)

    with sessions.writing_session_state(SESSION):
        during = sessions.sweep_stale_workspaces(DAY)
    kept = sandbox.is_dir()
    after = sessions.sweep_stale_workspaces(DAY)

    assert during == [] and kept
    # Skipped, not held off for good: the next sweep removes it.
    assert after == [SESSION]
    assert not sandbox.exists()


def test_a_profile_bound_during_the_sweep_stays_bound(
    root, monkeypatch, tmp_path
) -> None:
    _stale_sandbox(root)
    profile = tmp_path / "strict.yaml"
    profile.write_text(yaml.safe_dump({"project_name": "strict"}), encoding="utf-8")
    set_profile_registry(register_profiles([f"strict={profile}"]))
    landed: dict = {}

    def bind() -> None:
        landed["result"] = mcp_select_profile("strict", session_id=SESSION)

    _sweep_with_a_write_in_its_window(monkeypatch, bind)

    result = landed["result"]
    if result["success"] is not True:
        # The client is told, and selects the profile again.
        assert result["error_type"] == sessions.SESSION_WORKSPACE_BUSY, result
        assert mcp_select_profile("strict", session_id=SESSION)["success"] is True
    state = get_session_state(SESSION)
    assert state is not None
    assert state.profile_name == "strict", "the binding the client was told of is gone"
    assert state.config_path and Path(state.config_path).is_file(), state.config_path


def _ctx(session_id: str) -> MagicMock:
    ctx = MagicMock()
    ctx.headers = {"mcp-session-id": session_id}
    for name in ("info", "debug", "warning", "error", "report_progress"):
        setattr(ctx, name, AsyncMock())
    return ctx


def test_a_scan_after_the_profile_is_selected_again_runs_with_it_bound(
    root, monkeypatch, tmp_path
) -> None:
    """The case that matters: the bound profile is the operator's trusted base."""
    from automated_security_helper.cli import mcp_server, mcp_tools
    from automated_security_helper.core.resource_management.scan_registry import (
        ScanRegistry,
    )

    _stale_sandbox(root)
    target = tmp_path / "repo"
    target.mkdir()
    (target / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(target))
    profile = tmp_path / "strict.yaml"
    profile.write_text(yaml.safe_dump({"project_name": "strict"}), encoding="utf-8")
    set_profile_registry(register_profiles([f"strict={profile}"]))
    landed: dict = {}

    def bind() -> None:
        landed["result"] = mcp_select_profile("strict", session_id=SESSION)

    _sweep_with_a_write_in_its_window(monkeypatch, bind)
    if landed["result"]["success"] is not True:
        assert landed["result"]["error_type"] == sessions.SESSION_WORKSPACE_BUSY
        assert mcp_select_profile("strict", session_id=SESSION)["success"] is True

    started = AsyncMock()
    with (
        patch.object(mcp_tools, "_run_scan_async", new=started),
        patch.object(mcp_tools, "get_scan_registry", return_value=ScanRegistry()),
        patch.object(mcp_server, "monitor_scan_progress", new=AsyncMock()),
    ):
        scan = asyncio.run(
            mcp_server.run_ash_scan(_ctx(SESSION), source_dir=str(target))
        )

    assert started.await_count == 1, scan
    config_path = started.await_args.kwargs.get("config_path")
    assert config_path, "the scan ran with no profile bound"
    assert yaml.safe_load(Path(config_path).read_text())["project_name"] == "strict"
