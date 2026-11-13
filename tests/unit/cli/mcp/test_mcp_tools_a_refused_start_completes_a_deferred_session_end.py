# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every path that releases a scan's claim completes a session end the claim deferred.

``end_session`` is refused while a scan claim is held and leaves the removal
pending for whoever releases the claim (``sessions.finish_ended_session``). Only
the runner's finally called it: a scan turned away at the per-session limit, one
whose start failed after the claim, and a task cancelled before the loop first
ran its coroutine (whose finally never runs) all gave the claim back without it,
so an end that arrived in that window waited for the TTL sweep. And a task
cancelled while its scan thread still held the session lock asked while the lock
refused the end, with nothing asking again once the thread released it. Each path
now asks: the start paths through ``_release_what_the_scan_held_off_the_loop`` (on a
worker thread, never raising; see
test_mcp_tools_a_refused_start_releases_its_session_off_the_loop.py), the
never-run callback through ``_release_what_the_scan_held``, the scan thread once
it has released the lock.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict, List

import pytest

pytestmark = pytest.mark.unit

SESSION = "client-one"


@pytest.fixture
def layout(tmp_path, monkeypatch) -> Dict[str, Path]:
    from automated_security_helper.cli.mcp import sessions, source_delivery
    from automated_security_helper.cli.mcp.profile_registry import (
        clear_all_session_state,
        clear_profile_registry,
    )
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    monkeypatch.setattr(source_delivery, "_SESSION_SOURCE_DIRS", {})
    scan = tmp_path / "scan"
    scan.mkdir()
    (scan / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setattr(
        scan_registry_module, "_scan_registry", scan_registry_module.ScanRegistry()
    )
    clear_profile_registry()
    clear_all_session_state()
    sessions.reset_default_registry_for_tests()
    yield {"scan": scan, "tmp": tmp_path}
    sessions.reset_default_registry_for_tests()
    clear_profile_registry()
    clear_all_session_state()


def _the_end_arrives_while_the_claim_is_held() -> None:
    """End the session now, as a client would: the scan's claim refuses the
    removal and leaves it pending for whoever releases the claim."""
    from automated_security_helper.cli.mcp import sessions

    assert sessions.end_session(SESSION) is False, "control: the claim did not refuse"
    with sessions._ended_lock:
        pending = SESSION in sessions._ended_while_scanning
    assert pending, "control: the refused end was not left pending"


def _the_end_was_completed() -> None:
    """The removal ran, as the real ``finish_ended_session`` runs it."""
    from automated_security_helper.cli.mcp import sessions

    with sessions._ended_lock:
        still_pending = SESSION in sessions._ended_while_scanning
    assert not still_pending, "the end waited for the TTL sweep"
    assert sessions.get_default_registry().get(SESSION) is None


def _scan(**kwargs: Any) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp_tools import mcp_scan_directory

    return asyncio.run(mcp_scan_directory(session_id=SESSION, **kwargs))


def test_a_start_that_fails_after_the_claim_completes_the_end(
    layout, monkeypatch
) -> None:
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.cli.mcp import sessions

    def cannot_start(scan_id, coroutine, **kwargs) -> None:
        coroutine.close()
        # The claim is held here: the end arrives and waits for its release.
        _the_end_arrives_while_the_claim_is_held()
        raise RuntimeError("the loop is gone")

    monkeypatch.setattr(mcp_tools, "_start_scan_task", cannot_start)

    response = _scan(directory_path=str(layout["scan"]))

    assert response["success"] is False, response
    _the_end_was_completed()
    # The claim itself went back too.
    session = sessions.get_default_registry().session_for(SESSION)
    assert session.try_begin_change() is None
    session.end_change()


def test_a_scan_turned_away_at_the_limit_completes_the_end(layout, monkeypatch) -> None:
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.cli.mcp import sessions

    operator = layout["tmp"] / "operator.yaml"
    operator.write_text(
        "project_name: operator\n"
        "mcp-resource-management:\n"
        "  max_concurrent_scans_per_session: 1\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    monkeypatch.setattr(
        mcp_tools,
        "_start_scan_task",
        lambda scan_id, coroutine, **kwargs: coroutine.close(),
    )
    session = sessions.get_default_registry().session_for(SESSION)
    assert session.try_start_scan(1)
    real_try_start_scan = sessions.MCPSession.try_start_scan

    def end_while_the_claim_is_held(self, limit):
        # The scan's claim is held when the limit is asked: the end arrives
        # here and waits for the claim's release.
        _the_end_arrives_while_the_claim_is_held()
        return real_try_start_scan(self, limit)

    monkeypatch.setattr(
        sessions.MCPSession, "try_start_scan", end_while_the_claim_is_held
    )
    try:
        response = _scan(directory_path=str(layout["scan"]))
    finally:
        session.scan_returned()

    assert response["error_type"] == "session_scan_limit", response
    _the_end_was_completed()


def test_a_task_cancelled_before_it_ran_gives_everything_back(layout) -> None:
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.cli.mcp import sessions
    from automated_security_helper.core.resource_management.scan_registry import (
        MCScanStatus,
        get_scan_registry,
    )

    async def start_then_cancel_at_once() -> Dict[str, Any]:
        response = await mcp_tools.mcp_scan_directory(
            directory_path=str(layout["scan"]), session_id=SESSION
        )
        assert response["success"] is True, response
        task = next(
            task
            for task, scan_id in mcp_tools._scan_tasks.items()
            if scan_id == response["scan_id"]
        )
        # The end arrives while the scan's claim is held, and waits for it.
        _the_end_arrives_while_the_claim_is_held()
        # Cancelled before the loop first ran it: no line of the runner runs.
        task.cancel()
        await asyncio.wait([task])
        await asyncio.sleep(0)
        return response

    response = asyncio.run(start_then_cancel_at_once())

    entry = get_scan_registry().get_scan(response["scan_id"])
    assert entry is not None
    assert entry.status is MCScanStatus.FAILED, entry.status
    assert "could not be started" in (entry.error_message or ""), entry.error_message
    _the_end_was_completed()
    session = sessions.get_default_registry().session_for(SESSION)
    assert session.try_begin_change() is None, "the scan's claim is still held"
    session.end_change()


def test_the_scan_thread_completes_an_end_the_lock_refused(layout) -> None:
    from unittest.mock import patch

    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.cli.mcp import sessions
    from automated_security_helper.core.resource_management.scan_registry import (
        MCScanStatus,
        ScanRegistry,
    )
    from automated_security_helper.interactions import run_ash_scan as ras

    source = layout["scan"]
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )
    refused: List[Any] = []

    def ends_the_session_while_scanning(**kwargs: Any) -> Any:
        # On the scan thread, under the session lock: the end is refused by
        # the lock and left pending.
        refused.append(sessions.end_session(SESSION))
        return None

    # The runner alone, without _run_scan_async's finally: what completes the
    # end here is the scan thread, once it has released the lock.
    with (
        patch.object(ras, "run_ash_scan", ends_the_session_while_scanning),
        patch.object(mcp_tools, "get_scan_registry", return_value=registry),
    ):
        asyncio.run(
            mcp_tools._run_scan(
                scan_id=scan_id,
                directory_path=str(source),
                output_dir=str(output),
                severity_threshold=None,
                session_id=SESSION,
            )
        )

    assert refused == [False], refused
    entry = registry.get_scan(scan_id)
    assert entry is not None and entry.status is MCScanStatus.COMPLETED
    with sessions._ended_lock:
        still_pending = SESSION in sessions._ended_while_scanning
    assert not still_pending, "the end waited for the TTL sweep"
    assert sessions.get_default_registry().get(SESSION) is None
