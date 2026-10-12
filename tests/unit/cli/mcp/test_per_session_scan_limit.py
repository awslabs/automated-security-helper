# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A session of a network transport runs at most N scans at once; others are unaffected.

An HTTP server serves many sessions, and without a limit one of them can start as
many scans as it likes and take the host for itself. The operator's config
(``ASH_CONFIG``, never a scanned or delivered one) sets
``mcp-resource-management.max_concurrent_scans_per_session``, default 2; 0 turns
the limit off. A session at its limit is refused with
``error_type: session_scan_limit``, and every other session goes on scanning.

A ``run_ash_scan`` counts from its start until its scan returns. A
``run_ash_workspace_scan`` counts once, however many projects it has, until its
worker thread returns, even when the call is cancelled first. stdio's one
session is not limited.
"""

from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp import workspace as workspace_module
from automated_security_helper.cli.mcp.profile_registry import DEFAULT_SESSION_ID
from automated_security_helper.cli.mcp.session_identity import serving_local_client
from automated_security_helper.cli.mcp_tools import mcp_scan_directory

LIMIT_REFUSED = "session_scan_limit"


@pytest.fixture
def granted(tmp_path, monkeypatch) -> Path:
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    root = tmp_path / "granted"
    for name in ("one", "two", "three", "four", "api", "web"):
        (root / name).mkdir(parents=True)
        (root / name / "app.py").write_text("print('x')\n", encoding="utf-8")
    (root / "dev.code-workspace").write_text(
        json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}), encoding="utf-8"
    )
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(root))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setattr(
        scan_registry_module, "_scan_registry", scan_registry_module.ScanRegistry()
    )
    sessions.reset_default_registry_for_tests()
    yield root
    sessions.reset_default_registry_for_tests()


def _limit(tmp_path: Path, monkeypatch, value: int) -> None:
    config = tmp_path / "operator.yaml"
    config.write_text(
        "project_name: operator\n"
        "mcp-resource-management:\n"
        f"  max_concurrent_scans_per_session: {value}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(config))


@pytest.fixture
def held(monkeypatch) -> Dict[str, Any]:
    """Scans that wait until released, so they stay running."""
    state: Dict[str, Any] = {"release": threading.Event(), "started": []}
    lock = threading.Lock()

    def run_ash_scan(**kwargs):
        with lock:
            state["started"].append(kwargs["source_dir"])
        state["release"].wait(30)
        return None

    monkeypatch.setattr(
        "automated_security_helper.interactions.run_ash_scan.run_ash_scan",
        run_ash_scan,
    )
    return state


async def _start(granted: Path, session_id: str, name: str) -> Dict[str, Any]:
    return await mcp_scan_directory(
        directory_path=str(granted / name), session_id=session_id
    )


async def _finish(held: Dict[str, Any]) -> None:
    held["release"].set()
    others = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    await asyncio.gather(*others)


def test_a_session_at_its_limit_is_refused_and_another_still_scans(
    tmp_path, monkeypatch, granted, held
) -> None:
    _limit(tmp_path, monkeypatch, 1)

    async def main() -> List[Dict[str, Any]]:
        try:
            return [
                await _start(granted, "session-a", "one"),
                await _start(granted, "session-a", "two"),
                await _start(granted, "session-b", "three"),
            ]
        finally:
            await _finish(held)

    first, second, other = asyncio.run(main())

    assert first.get("success") is True, first
    assert second.get("success") is False, second
    assert second.get("error_type") == LIMIT_REFUSED, second
    assert "max_concurrent_scans_per_session" in second.get("error", ""), second
    assert other.get("success") is True, other


def test_the_default_limit_is_two(granted, held) -> None:
    async def main() -> List[Dict[str, Any]]:
        try:
            return [
                await _start(granted, "session-a", name)
                for name in ("one", "two", "three")
            ]
        finally:
            await _finish(held)

    results = asyncio.run(main())

    assert [r.get("success") for r in results] == [True, True, False], results
    assert results[2].get("error_type") == LIMIT_REFUSED


def test_a_session_can_scan_again_once_its_scan_returned(
    tmp_path, monkeypatch, granted, held
) -> None:
    _limit(tmp_path, monkeypatch, 1)

    async def main() -> Dict[str, Any]:
        await _start(granted, "session-a", "one")
        await _finish(held)
        held["release"] = threading.Event()
        try:
            return await _start(granted, "session-a", "two")
        finally:
            await _finish(held)

    again = asyncio.run(main())

    assert again.get("success") is True, again


def test_a_scan_that_does_not_start_leaves_no_count(
    tmp_path, monkeypatch, granted, held
) -> None:
    """The second scan of one directory is refused, and it must not use up the limit."""
    _limit(tmp_path, monkeypatch, 2)

    async def main() -> List[Dict[str, Any]]:
        try:
            return [
                await _start(granted, "session-a", "one"),
                await _start(granted, "session-a", "one"),
                await _start(granted, "session-a", "two"),
            ]
        finally:
            await _finish(held)

    first, same_directory, second = asyncio.run(main())

    assert first.get("success") is True, first
    assert same_directory.get("success") is False, same_directory
    assert same_directory.get("error_type") != LIMIT_REFUSED, same_directory
    assert second.get("success") is True, second


def test_zero_turns_the_limit_off(tmp_path, monkeypatch, granted, held) -> None:
    _limit(tmp_path, monkeypatch, 0)

    async def main() -> List[Dict[str, Any]]:
        try:
            return [
                await _start(granted, "session-a", name)
                for name in ("one", "two", "three", "four")
            ]
        finally:
            await _finish(held)

    assert all(r.get("success") for r in asyncio.run(main()))


def test_stdio_is_not_limited(tmp_path, monkeypatch, granted, held) -> None:
    _limit(tmp_path, monkeypatch, 1)

    async def main() -> List[Dict[str, Any]]:
        with serving_local_client():
            try:
                return [
                    await _start(granted, DEFAULT_SESSION_ID, name)
                    for name in ("one", "two")
                ]
            finally:
                await _finish(held)

    assert all(r.get("success") for r in asyncio.run(main()))


def test_a_scan_config_cannot_raise_the_limit(
    tmp_path, monkeypatch, granted, held
) -> None:
    """The limit is the operator's: a config inside the scanned tree is not read for it."""
    _limit(tmp_path, monkeypatch, 1)
    for name in ("one", "two"):
        (granted / name / ".ash").mkdir()
        (granted / name / ".ash" / ".ash.yaml").write_text(
            "project_name: tree\n"
            "mcp-resource-management:\n"
            "  max_concurrent_scans_per_session: 5\n",
            encoding="utf-8",
        )

    async def main() -> List[Dict[str, Any]]:
        try:
            return [
                await _start(granted, "session-a", "one"),
                await _start(granted, "session-a", "two"),
            ]
        finally:
            await _finish(held)

    first, second = asyncio.run(main())

    assert first.get("success") is True, first
    assert second.get("error_type") == LIMIT_REFUSED, second


# -- workspace scans ------------------------------------------------------------


@pytest.fixture
def blocked_workspace(monkeypatch) -> Dict[str, Any]:
    from automated_security_helper.models.workspace import WorkspaceResults
    from automated_security_helper.workspace.execution import WorkspaceRunResult

    state: Dict[str, Any] = {"started": threading.Event(), "release": threading.Event()}

    def execute(plan, settings, **kwargs):
        state["started"].set()
        state["release"].wait(30)
        return WorkspaceRunResult(
            results_path=Path(settings.output_dir) / "ash_workspace_results.json",
            exit_code=0,
            payload=WorkspaceResults(
                workspace_file=plan.workspace_file,
                workspace_root=plan.workspace_root,
                status="completed",
                exit_code=0,
                projects=[],
                unconvertible_finding_paths=0,
            ),
        )

    monkeypatch.setattr(workspace_module, "execute_workspace", execute)
    return state


def test_a_workspace_scan_counts_once_however_many_projects(
    tmp_path, monkeypatch, granted, held, blocked_workspace
) -> None:
    _limit(tmp_path, monkeypatch, 1)

    async def main():
        scan = asyncio.create_task(
            workspace_module.mcp_scan_workspace(
                workspace_file=str(granted / "dev.code-workspace"),
                session_id="session-a",
            )
        )
        await asyncio.to_thread(blocked_workspace["started"].wait, 30)
        try:
            same_session = await _start(granted, "session-a", "one")
            other_session = await _start(granted, "session-b", "two")
        finally:
            blocked_workspace["release"].set()
            held["release"].set()
        workspace = await scan
        await _finish(held)
        return workspace, same_session, other_session

    workspace, same_session, other_session = asyncio.run(main())

    assert workspace.get("success") is True, workspace
    assert same_session.get("error_type") == LIMIT_REFUSED, same_session
    assert other_session.get("success") is True, other_session


def test_a_workspace_scan_at_the_limit_is_refused(
    tmp_path, monkeypatch, granted, held, blocked_workspace
) -> None:
    _limit(tmp_path, monkeypatch, 1)

    async def main():
        try:
            await _start(granted, "session-a", "one")
            return await workspace_module.mcp_scan_workspace(
                workspace_file=str(granted / "dev.code-workspace"),
                session_id="session-a",
            )
        finally:
            await _finish(held)

    refused = asyncio.run(main())

    assert refused.get("success") is False, refused
    assert refused.get("error_type") == LIMIT_REFUSED, refused
    assert not blocked_workspace["started"].is_set()


def test_a_cancelled_workspace_scan_counts_until_its_worker_returns(
    tmp_path, monkeypatch, granted, held, blocked_workspace
) -> None:
    _limit(tmp_path, monkeypatch, 1)
    observed: Dict[str, Any] = {}

    async def main():
        scan = asyncio.create_task(
            workspace_module.mcp_scan_workspace(
                workspace_file=str(granted / "dev.code-workspace"),
                session_id="session-a",
            )
        )
        await asyncio.to_thread(blocked_workspace["started"].wait, 30)
        scan.cancel()
        with pytest.raises(asyncio.CancelledError):
            await scan
        try:
            observed["while_running"] = await _start(granted, "session-a", "one")
        finally:
            blocked_workspace["release"].set()
            await _finish(held)

    asyncio.run(main())

    assert observed["while_running"].get("error_type") == LIMIT_REFUSED


# -- over the protocol ------------------------------------------------------------


def test_the_refusal_reaches_a_client_over_streamable_http(
    tmp_path, monkeypatch, granted, held
) -> None:
    from starlette.testclient import TestClient

    from automated_security_helper.cli.mcp import build_streamable_http_app
    from tests.utils.mcp_transport_harness import (
        LOOPBACK_BASE_URL,
        LOOPBACK_PORT,
        StreamableHttpClient,
    )

    _limit(tmp_path, monkeypatch, 1)
    app = build_streamable_http_app(
        mount_path="/mcp", host="127.0.0.1", port=LOOPBACK_PORT
    )
    try:
        with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
            http = StreamableHttpClient(client)
            _a, session_a = http.open_session()
            _b, session_b = http.open_session()
            first = http.call_tool(
                "run_ash_scan", {"source_dir": str(granted / "one")}, session_a
            )
            second = http.call_tool(
                "run_ash_scan", {"source_dir": str(granted / "two")}, session_a
            )
            other = http.call_tool(
                "run_ash_scan", {"source_dir": str(granted / "three")}, session_b
            )
            held["release"].set()
    finally:
        held["release"].set()

    assert first.get("success") is True, first
    assert second.get("success") is False, second
    assert second.get("error_type") == LIMIT_REFUSED, second
    assert other.get("success") is True, other
