# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace scan holds its session's delivered tree for its whole run.

A workspace scan of a tree the session delivered reads that tree for as long as
its projects take to scan. It claims the session the way a single scan does
(``MCPSession.try_claim_scan``), from before it resolves the workspace until the
run returns, so ``clear_source`` and ``set_source_git`` are refused meanwhile with
``error_type: source_delivery_busy``, and the session's removal waits for the
scan. A workspace scan is refused the same way while one of those calls is
changing the tree.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import threading
import zipfile
from pathlib import Path
from typing import Any, Dict

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp import workspace as workspace_module
from automated_security_helper.cli.mcp.sessions import (
    end_session,
    reset_default_registry_for_tests,
)

SESSION = "workspace-session"
WORKSPACE_FILE = "dev.code-workspace"


@pytest.fixture(autouse=True)
def _environment(tmp_path, monkeypatch):
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    for name in ("ASH_MCP_ALLOWED_ROOTS", "ASH_MCP_ALLOWED_CONFIG_ROOTS", "ASH_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "ws"))
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.invalid")
    monkeypatch.setattr(
        scan_registry_module, "_scan_registry", scan_registry_module.ScanRegistry()
    )
    monkeypatch.setattr(
        sd, "_run_git", lambda *a, **k: pytest.fail("git ran during the scan")
    )
    reset_default_registry_for_tests()
    profile_registry.clear_session_state()
    yield
    reset_default_registry_for_tests()
    profile_registry.clear_session_state()


def _zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(
            WORKSPACE_FILE,
            json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}),
        )
        archive.writestr("api/app.py", "print('api')\n")
        archive.writestr("web/app.py", "print('web')\n")
    return buffer.getvalue()


@pytest.fixture
def delivered() -> Path:
    data = _zip()
    sd.set_source_zip_chunk(
        "tree", 0, base64.b64encode(data).decode(), True, session_id=SESSION
    )
    return sd.set_source_zip_finalize(
        "tree", hashlib.sha256(data).hexdigest(), session_id=SESSION
    )


@pytest.fixture
def blocking_execution(monkeypatch) -> Dict[str, Any]:
    """Replace ``execute_workspace`` with one that waits until released."""
    from automated_security_helper.models.workspace import (
        ProjectRunStatus,
        WorkspaceProjectResult,
        WorkspaceResults,
    )
    from automated_security_helper.workspace.execution import WorkspaceRunResult

    state: Dict[str, Any] = {
        "started": threading.Event(),
        "release": threading.Event(),
    }

    def _execute(plan, settings, **kwargs):
        state["started"].set()
        state["release"].wait(30)
        state["tree_present"] = all(
            (Path(project.path) / "app.py").is_file() for project in plan.projects
        )
        payload = WorkspaceResults(
            workspace_file=plan.workspace_file,
            workspace_root=plan.workspace_root,
            status="completed",
            exit_code=0,
            projects=[
                WorkspaceProjectResult(
                    project=project.key,
                    relative_path=project.relative_path,
                    display_label=project.display_label,
                    status=ProjectRunStatus.COMPLETED,
                    severity_threshold=project.gate_threshold,
                    output_path=f"projects/{project.key}",
                )
                for project in plan.projects
            ],
            unconvertible_finding_paths=0,
        )
        return WorkspaceRunResult(
            results_path=Path(settings.output_dir) / "ash_workspace_results.json",
            exit_code=0,
            payload=payload,
        )

    monkeypatch.setattr(workspace_module, "execute_workspace", _execute)
    return state


def _scan(delivered: Path):
    return workspace_module.mcp_scan_workspace(
        workspace_file=str(delivered / WORKSPACE_FILE), session_id=SESSION
    )


def _while_the_scan_runs(delivered: Path, state: Dict[str, Any], during):
    async def main():
        scan = asyncio.create_task(_scan(delivered))
        started = await asyncio.to_thread(state["started"].wait, 30)
        assert started, "the workspace scan never reached execution"
        try:
            observed = during()
        finally:
            state["release"].set()
        return await scan, observed

    return asyncio.run(main())


def test_clear_source_is_refused_during_a_workspace_scan(
    delivered, blocking_execution
) -> None:
    response, refused = _while_the_scan_runs(
        delivered,
        blocking_execution,
        lambda: mcp_tools.mcp_clear_source(session_id=SESSION),
    )

    assert refused.get("error_type") == "source_delivery_busy", refused
    assert blocking_execution["tree_present"] is True, "the scan read a removed tree"
    assert response.get("success") is True, response
    assert mcp_tools.mcp_clear_source(session_id=SESSION).get("success") is True


def test_a_clone_is_refused_during_a_workspace_scan(
    delivered, blocking_execution
) -> None:
    _response, refused = _while_the_scan_runs(
        delivered,
        blocking_execution,
        lambda: mcp_tools.mcp_set_source_git(
            url="https://git.example.invalid/team/repo.git", session_id=SESSION
        ),
    )

    assert refused.get("error_type") == "source_delivery_busy", refused
    assert blocking_execution["tree_present"] is True


def test_a_session_ending_during_a_workspace_scan_waits_for_it(
    delivered, blocking_execution
) -> None:
    _response, ended_now = _while_the_scan_runs(
        delivered, blocking_execution, lambda: end_session(SESSION)
    )

    assert ended_now is False
    assert blocking_execution["tree_present"] is True, "the scan read a removed tree"
    assert not delivered.exists(), "the tree outlived the scan of an ended session"


def test_a_workspace_scan_is_refused_while_the_tree_is_changing(
    delivered, blocking_execution
) -> None:
    async def main():
        with sd._no_scan_running(SESSION):
            return await _scan(delivered)

    response = asyncio.run(main())

    assert response.get("success") is False, response
    assert response.get("error_type") == "source_delivery_busy", response
    assert not blocking_execution["started"].is_set(), "the workspace scan ran"
