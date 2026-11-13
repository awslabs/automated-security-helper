# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A cancelled MCP scan whose tool could not be stopped says so in its entry.

The runner's ``ScanCancelled`` arm closed the entry with ``finish_scan`` and
dropped ``ScanCancelled.could_not_stop``, the tools the stop could not end.
``finish_scan`` leaves an entry ``cancel_scan`` already closed alone, so nothing
was recorded, and a cancel that left a scanner's child running read back as a
clean cancel: a client could reuse the output directory while the tool still
wrote into it. The arm now attaches the outcome to the CANCELLED entry through
``record_cancel_outcome``, and a client polling the entry reads it.

The scan launcher is replaced by one that behaves like a scan stopped mid-tool:
it cancels its own entry, as ``cancel_scan`` would from another call, and raises
the ``ScanCancelled`` the cancel scope raises, carrying one tool its stop could
not end.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli import mcp_server
from automated_security_helper.core.cancellation import ScanCancelled
from automated_security_helper.core.resource_management import scan_registry
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from tests.utils.tasks import drain as _drain

pytestmark = pytest.mark.unit

_LAUNCHER = "automated_security_helper.interactions.run_ash_scan.run_ash_scan"


@pytest.fixture(autouse=True)
def isolated_mcp_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp.sessions import (
        reset_default_registry_for_tests,
    )

    monkeypatch.setattr(scan_registry, "_scan_registry", ScanRegistry())
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    reset_default_registry_for_tests()
    for name in ("ASH_MCP_ALLOWED_CONFIG_ROOTS", "ASH_MCP_TRANSPORT", "ASH_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "allowed"))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    (tmp_path / "allowed").mkdir()
    monkeypatch.setattr(mcp_server, "monitor_scan_progress", AsyncMock())
    yield
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    reset_default_registry_for_tests()


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "allowed" / "project"
    project.mkdir(parents=True)
    (project / "app.py").write_text("x = 1\n", encoding="utf-8")
    return project


def _ctx() -> MagicMock:
    ctx = MagicMock(spec=Context)
    ctx.headers = {}
    return ctx


def _a_scan_cancelled_with_a_tool_still_running(**kwargs: Any) -> None:
    """Stand in for a scan stopped while a scanner's child would not end."""
    registry = scan_registry.get_scan_registry()
    for active in registry.list_scans(active_only=True):
        registry.cancel_scan(active["scan_id"])
    raise ScanCancelled("the scan was cancelled", could_not_stop=(("bandit", 4242),))


@pytest.mark.asyncio
async def test_the_cancelled_entry_names_the_tool_that_could_not_stop(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(_LAUNCHER, _a_scan_cancelled_with_a_tool_still_running)
    ctx = _ctx()

    begun = await mcp_server.run_ash_scan(ctx, source_dir=str(_project(tmp_path)))
    assert begun["success"] is True, begun
    await _drain()

    entry = scan_registry.get_scan_registry().get_scan(begun["scan_id"])
    assert entry.status == MCScanStatus.CANCELLED, (entry.status, entry.error_message)
    assert any("bandit (pid 4242)" in warning for warning in entry.warnings), (
        "the cancelled entry carries no word of the tool still running",
        entry.warnings,
    )
    progress = await mcp_server.get_scan_progress(ctx, begun["scan_id"])
    assert progress["status"] == "cancelled", progress


@pytest.mark.asyncio
async def test_a_clean_cancel_stays_a_clean_cancel(tmp_path, monkeypatch):
    def a_scan_cancelled_cleanly(**kwargs: Any) -> None:
        registry = scan_registry.get_scan_registry()
        for active in registry.list_scans(active_only=True):
            registry.cancel_scan(active["scan_id"])
        raise ScanCancelled("the scan was cancelled")

    monkeypatch.setattr(_LAUNCHER, a_scan_cancelled_cleanly)
    ctx = _ctx()

    begun = await mcp_server.run_ash_scan(ctx, source_dir=str(_project(tmp_path)))
    assert begun["success"] is True, begun
    await _drain()

    entry = scan_registry.get_scan_registry().get_scan(begun["scan_id"])
    assert entry.status == MCScanStatus.CANCELLED, (entry.status, entry.error_message)
    assert entry.warnings == [], entry.warnings
