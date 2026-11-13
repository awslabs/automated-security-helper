# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan registry tools act only on the calling session's scans.

``list_active_scans``, ``get_scan_progress`` and ``cancel_scan`` read and change
the process-wide scan registry. A network MCP server serves many sessions from
one process, so each of those tools has to answer for the caller's own scans
only: another session's scan id must behave exactly like an id that was never
issued, and nothing in a response may carry another session's id or sandbox
path. A sandbox path names its session (``<workspace root>/<session id>/...``),
and a session id selects a sandbox on every later call, so neither appears in
a response to another session.

How the tests reach the code
----------------------------
Every scan here is started the way a client starts one: a session delivers a
tree and calls ``run_ash_scan`` over the streamable-HTTP app ASH builds, driven
in process by ``TestClient``. Only the scan body is replaced (by a coroutine that
returns at once, leaving the entry pending), because these tests are about the
registry's bookkeeping and not about scanners. The registry is a fresh real
``ScanRegistry`` per test.

The stdio test is the control for the opposite direction: stdio has one client,
which must keep seeing its own scans.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib
import io
import json
import uuid
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest
from starlette.testclient import TestClient

from automated_security_helper.cli.mcp import build_streamable_http_app
from tests.utils.mcp_transport_harness import (
    LOOPBACK_BASE_URL,
    LOOPBACK_PORT,
    StreamableHttpClient,
    stdio_tool_calls,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def workspace_root(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "mcp-workspaces"
    root.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    for name in (
        "ASH_MCP_ALLOWED_ROOTS",
        "ASH_MCP_ALLOWED_CONFIG_ROOTS",
        "ASH_MCP_TRANSPORT",
    ):
        monkeypatch.delenv(name, raising=False)
    return root


@pytest.fixture(autouse=True)
def isolated_registry(monkeypatch):
    """A fresh registry: the production one is a module-level singleton."""
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    fresh = scan_registry_module.ScanRegistry()
    monkeypatch.setattr(scan_registry_module, "_scan_registry", fresh)
    return fresh


@pytest.fixture(autouse=True)
def scans_do_not_run(monkeypatch):
    """Register scans for real, but run nothing behind them."""

    async def _no_scan(**_kwargs):
        return None

    async def _no_monitor(*_args, **_kwargs):
        return None

    monkeypatch.setattr(
        "automated_security_helper.cli.mcp_tools._run_scan_async", _no_scan
    )
    monkeypatch.setattr(
        "automated_security_helper.cli.mcp_server.monitor_scan_progress", _no_monitor
    )


@pytest.fixture
def http():
    app = build_streamable_http_app(
        mount_path="/mcp", host="127.0.0.1", port=LOOPBACK_PORT
    )
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        yield StreamableHttpClient(client)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _zip_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("app.py", "print('hello')\n")
    return buffer.getvalue()


def _deliver(http: StreamableHttpClient, headers: Dict[str, str]) -> str:
    data = _zip_bytes()
    chunk = http.call_tool(
        "set_source_zip_chunk",
        {
            "upload_id": "upload-1",
            "sequence": 0,
            "data_b64": base64.b64encode(data).decode(),
            "last": True,
        },
        headers,
    )
    assert chunk.get("success") is True, chunk
    final = http.call_tool(
        "set_source_zip_finalize",
        {"upload_id": "upload-1", "expected_sha256": hashlib.sha256(data).hexdigest()},
        headers,
    )
    assert final.get("success") is True, final
    return final["source_dir"]


def _session_with_a_scan(
    http: StreamableHttpClient,
) -> Tuple[str, Dict[str, str], str, str]:
    """Open a session, deliver a tree, start a scan of it.

    Returns (session id, call headers, scan id, delivered source dir).
    """
    session_id, headers = http.open_session()
    assert session_id, "a stateful server issues a session id at initialize"
    source_dir = _deliver(http, headers)
    started = http.call_tool("run_ash_scan", {}, headers)
    assert started.get("success") is True, started
    return session_id, headers, started["scan_id"], source_dir


def _scan_ids(listing: Dict[str, Any]) -> List[str]:
    entries = list(listing.get("all_scans") or []) + list(
        listing.get("active_scans") or []
    )
    return [entry.get("scan_id") for entry in entries]


def _shape(response: Dict[str, Any], scan_id: str) -> Dict[str, Any]:
    """What a response tells a caller, with the asked-for id and clocks removed."""
    text = json.dumps(response, sort_keys=True, default=str).replace(scan_id, "<id>")
    normalized = json.loads(text)
    for volatile in ("timestamp", "start_time", "end_time"):
        normalized.pop(volatile, None)
        if isinstance(normalized.get("context"), dict):
            normalized["context"].pop(volatile, None)
    return normalized


# ---------------------------------------------------------------------------
# Another session's scan is invisible
# ---------------------------------------------------------------------------


class TestAnotherSessionsScanIsInvisible:
    def test_list_active_scans_omits_another_sessions_scan(self, http) -> None:
        owner_id, _owner, scan_id, source_dir = _session_with_a_scan(http)
        _other_id, other = http.open_session()

        listing = http.call_tool("list_active_scans", {}, other)

        assert listing.get("success") is True, listing
        assert scan_id not in _scan_ids(listing), (
            f"another session's scan is listed: {listing}"
        )
        rendered = json.dumps(listing, default=str)
        assert owner_id not in rendered, "the listing carries the owner's session id"
        assert source_dir not in rendered, "the listing carries the owner's sandbox"

    def test_get_scan_progress_of_another_sessions_scan_answers_like_an_unknown_id(
        self, http
    ) -> None:
        owner_id, _owner, scan_id, source_dir = _session_with_a_scan(http)
        _other_id, other = http.open_session()
        unknown_id = str(uuid.uuid4())

        foreign = http.call_tool("get_scan_progress", {"scan_id": scan_id}, other)
        unknown = http.call_tool("get_scan_progress", {"scan_id": unknown_id}, other)

        rendered = json.dumps(foreign, default=str)
        assert owner_id not in rendered and source_dir not in rendered, (
            f"progress of another session's scan reveals it: {foreign}"
        )
        assert _shape(foreign, scan_id) == _shape(unknown, unknown_id), (
            "another session's scan id must answer exactly like an unknown id:\n"
            f"foreign: {foreign}\nunknown: {unknown}"
        )

    def test_cancel_scan_of_another_sessions_scan_answers_like_an_unknown_id(
        self, http
    ) -> None:
        _owner_id, owner, scan_id, _source_dir = _session_with_a_scan(http)
        _other_id, other = http.open_session()
        unknown_id = str(uuid.uuid4())

        foreign = http.call_tool("cancel_scan", {"scan_id": scan_id}, other)
        unknown = http.call_tool("cancel_scan", {"scan_id": unknown_id}, other)

        assert _shape(foreign, scan_id) == _shape(unknown, unknown_id), (
            "cancelling another session's scan must answer exactly like an "
            f"unknown id:\nforeign: {foreign}\nunknown: {unknown}"
        )
        still = http.call_tool("get_scan_progress", {"scan_id": scan_id}, owner)
        assert still.get("status") != "cancelled", (
            f"another session cancelled the owner's scan: {still}"
        )


# ---------------------------------------------------------------------------
# The owner keeps its scans (controls)
# ---------------------------------------------------------------------------


class TestTheOwningSessionKeepsItsScans:
    def test_the_owner_lists_its_own_scan(self, http) -> None:
        _owner_id, owner, scan_id, _source_dir = _session_with_a_scan(http)

        listing = http.call_tool("list_active_scans", {}, owner)

        assert scan_id in _scan_ids(listing), listing

    def test_the_owner_reads_the_progress_of_its_own_scan(self, http) -> None:
        _owner_id, owner, scan_id, source_dir = _session_with_a_scan(http)

        progress = http.call_tool("get_scan_progress", {"scan_id": scan_id}, owner)

        assert progress.get("scan_id") == scan_id, progress
        assert progress.get("status") in {"pending", "running"}, progress

    def test_the_owner_cancels_its_own_scan(self, http) -> None:
        _owner_id, owner, scan_id, _source_dir = _session_with_a_scan(http)

        cancelled = http.call_tool("cancel_scan", {"scan_id": scan_id}, owner)

        assert cancelled.get("success") is True, cancelled
        after = http.call_tool("get_scan_progress", {"scan_id": scan_id}, owner)
        assert after.get("status") == "cancelled", after


# ---------------------------------------------------------------------------
# Workspace scans register under the session that started them
# ---------------------------------------------------------------------------


@pytest.fixture
def workspace_runs_nothing(monkeypatch):
    """Replace project execution with a recorder returning a real-shaped result."""
    from automated_security_helper.models.workspace import (
        ProjectRunStatus,
        WorkspaceProjectResult,
        WorkspaceResults,
    )
    from automated_security_helper.workspace import execution as execution_module
    from automated_security_helper.workspace.execution import WorkspaceRunResult

    def _record(plan, settings, **_kwargs):
        projects = [
            WorkspaceProjectResult(
                project=project.key,
                relative_path=project.relative_path,
                display_label=project.display_label,
                status=ProjectRunStatus.COMPLETED,
                severity_threshold=project.gate_threshold,
                output_path=f"projects/{project.key}",
                finding_count=0,
                actionable_finding_count=0,
            )
            for project in plan.projects
        ]
        payload = WorkspaceResults(
            workspace_file=plan.workspace_file,
            workspace_root=plan.workspace_root,
            status="completed",
            exit_code=0,
            projects=projects,
            unconvertible_finding_paths=0,
        )
        return WorkspaceRunResult(
            results_path=Path(settings.output_dir) / "ash_workspace_results.json",
            exit_code=0,
            payload=payload,
        )

    monkeypatch.setattr(execution_module, "execute_workspace", _record)
    workspace_module = importlib.import_module(
        "automated_security_helper.cli.mcp.workspace"
    )
    if hasattr(workspace_module, "execute_workspace"):
        monkeypatch.setattr(workspace_module, "execute_workspace", _record)


def _workspace_scan(
    http: StreamableHttpClient, headers: Dict[str, str], root: Path
) -> List[str]:
    for project in ("api", "web"):
        (root / project).mkdir(parents=True, exist_ok=True)
    workspace_file = root / "dev.code-workspace"
    workspace_file.write_text(
        json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}), encoding="utf-8"
    )
    response = http.call_tool(
        "run_ash_workspace_scan", {"workspace_file": str(workspace_file)}, headers
    )
    assert response.get("success") is True, response
    scan_ids = list((response.get("scan_ids") or {}).values())
    assert len(scan_ids) == 2, response
    return scan_ids


class TestWorkspaceScansAreSessionScoped:
    def test_another_session_does_not_see_a_workspace_scans_projects(
        self, http, tmp_path, monkeypatch, workspace_runs_nothing
    ) -> None:
        root = tmp_path / "work"
        root.mkdir()
        monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(root))
        _owner_id, owner = http.open_session()
        project_scan_ids = _workspace_scan(http, owner, root)
        _other_id, other = http.open_session()

        listing = http.call_tool("list_active_scans", {}, other)

        leaked = set(project_scan_ids) & set(_scan_ids(listing))
        assert not leaked, f"another session sees workspace project scans: {listing}"

    def test_the_owner_sees_its_workspace_scans_projects(
        self, http, tmp_path, monkeypatch, workspace_runs_nothing
    ) -> None:
        root = tmp_path / "work"
        root.mkdir()
        monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(root))
        _owner_id, owner = http.open_session()
        project_scan_ids = _workspace_scan(http, owner, root)

        listing = http.call_tool("list_active_scans", {}, owner)

        assert set(project_scan_ids) <= set(_scan_ids(listing)), listing


# ---------------------------------------------------------------------------
# stdio keeps seeing its own scans (control)
# ---------------------------------------------------------------------------


def test_a_stdio_client_sees_and_cancels_its_own_scans(tmp_path) -> None:
    target = tmp_path / "project"
    target.mkdir()
    (target / "app.py").write_text("print('hello')\n", encoding="utf-8")

    async def _run():
        (started,) = await stdio_tool_calls(
            [("run_ash_scan", {"source_dir": str(target)})]
        )
        assert started.get("success") is True, started
        scan_id = started["scan_id"]
        listing, progress, cancelled = await stdio_tool_calls(
            [
                ("list_active_scans", {}),
                ("get_scan_progress", {"scan_id": scan_id}),
                ("cancel_scan", {"scan_id": scan_id}),
            ]
        )
        return scan_id, listing, progress, cancelled

    scan_id, listing, progress, cancelled = asyncio.run(_run())

    assert scan_id in _scan_ids(listing), listing
    assert progress.get("scan_id") == scan_id, progress
    assert cancelled.get("success") is True, cancelled
