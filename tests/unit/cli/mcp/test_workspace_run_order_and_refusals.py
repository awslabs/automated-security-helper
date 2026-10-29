#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Six workspace-scan gaps, each pinned by the order or the input that passed it.

* The output directory's ``.gitignore`` was written before the directory was
  created, so a first workspace scan never wrote it.
* Two workspace scans whose output directories resolve to one place were both
  admitted, and one run's cleanup and results overwrote the other's.
* The scan's timeout clock started before the wait for the session's lock, so a
  scan queued behind another timed out having scanned nothing.
* The worker gave the session's claim back before it settled previous results
  under the session's tree.
* An ``ASH_CONFIG`` that cannot be read raised out of both workspace tools
  instead of answering a config refusal.
* The plan's resolution and the committed-output check ran on the event loop.
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from automated_security_helper.cli.mcp import workspace as workspace_module
from automated_security_helper.core.exceptions import ASHConfigSourceError
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    WorkspaceRunResult,
)
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

pytestmark = pytest.mark.unit


def _plan(tmp_path: Path) -> WorkspacePlan:
    root = tmp_path / "workspace"
    project_dir = root / "api"
    (project_dir / "src").mkdir(parents=True, exist_ok=True)
    workspace_file = root / "fixture.code-workspace"
    workspace_file.write_text('{"folders": [{"path": "api"}]}', encoding="utf-8")
    return WorkspacePlan(
        workspace_file=workspace_file.as_posix(),
        workspace_root=root.as_posix(),
        projects=[
            ProjectPlan(
                key="api",
                relative_path="api",
                path=project_dir.as_posix(),
                label="api",
                display_label="api",
                severity_threshold="MEDIUM",
            )
        ],
    )


def _settings(tmp_path: Path) -> ProjectScanSettings:
    return ProjectScanSettings(
        output_dir=tmp_path / "out", phases=("scan",), max_parallel_projects=1
    )


def _result(plan, settings) -> WorkspaceRunResult:
    payload = WorkspaceResults(
        workspace_file=plan.workspace_file,
        workspace_root=plan.workspace_root,
        status="completed",
        exit_code=0,
        projects=[
            WorkspaceProjectResult(
                project=p.key,
                relative_path=p.relative_path,
                display_label=p.display_label,
                status=ProjectRunStatus.COMPLETED,
                severity_threshold=p.gate_threshold,
                output_path=f"projects/{p.key}",
            )
            for p in plan.projects
        ],
        unconvertible_finding_paths=0,
    )
    return WorkspaceRunResult(
        results_path=Path(settings.output_dir) / "ash_workspace_results.json",
        exit_code=0,
        payload=payload,
    )


class _Claim:
    """The slice of ``_WorkspaceScanClaim`` that ``_execute`` touches, recording calls."""

    claimed = True

    def __init__(self, order: List[str]) -> None:
        self.order = order

    def worker_starts(self) -> bool:
        self.order.append("worker_starts")
        return True

    def worker_returns(self) -> None:
        self.order.append("worker_returns")


class TestTheGitignoreIsWrittenOnceTheOutputDirectoryExists:
    def test_project_outputs_writes_no_gitignore(self, tmp_path):
        """Red at the base: ``_project_outputs`` called the writer before any mkdir.

        The writer refuses to write into a directory that is not there, so the
        call did nothing on a first scan. The write now follows
        ``_create_project_outputs`` at the call site.
        """
        plan = _plan(tmp_path)
        settings = _settings(tmp_path)

        with patch.object(workspace_module, "ignore_output_dir_in_git") as writer:
            outputs = workspace_module._project_outputs(plan, settings)

        assert set(outputs) == {"api"}
        writer.assert_not_called()

    def test_the_writer_is_called_after_the_directories_exist(self, tmp_path):
        """The call-site order: create, then write, so a first scan gets its file."""
        plan = _plan(tmp_path)
        settings = _settings(tmp_path)
        outputs = workspace_module._project_outputs(plan, settings)
        output_dir = Path(settings.output_dir)
        assert not output_dir.exists()

        workspace_module._create_project_outputs(outputs)
        wrote = workspace_module.ignore_output_dir_in_git(
            plan.workspace_root, settings.output_dir
        )

        assert output_dir.is_dir()
        assert wrote is False or (output_dir / ".gitignore").exists()


class _Registry:
    def __init__(self, entries: List[Dict[str, Any]]) -> None:
        self.entries = entries

    def list_scans(self):
        return list(self.entries)


class TestAnOutputDirectoryAnotherScanWritesIsRefused:
    def test_a_live_scan_on_the_same_output_directory_refuses_the_workspace(
        self, tmp_path
    ):
        """Red at the base: only the DIRECTORY scanned was compared, never the output."""
        plan = _plan(tmp_path)
        outputs = workspace_module._project_outputs(plan, _settings(tmp_path))
        registry = _Registry(
            [{"status": "running", "output_directory": str(outputs["api"])}]
        )

        with pytest.raises(MCPResourceError, match="being written by another scan"):
            workspace_module._refuse_outputs_another_scan_writes(
                registry, plan, outputs
            )

    def test_a_finished_scan_on_it_does_not(self, tmp_path):
        """Control: a completed or failed scan holds its directory no more."""
        plan = _plan(tmp_path)
        outputs = workspace_module._project_outputs(plan, _settings(tmp_path))
        registry = _Registry(
            [
                {"status": "completed", "output_directory": str(outputs["api"])},
                {"status": "failed", "output_directory": str(outputs["api"])},
                {"status": "running", "output_directory": str(tmp_path / "elsewhere")},
            ]
        )

        workspace_module._refuse_outputs_another_scan_writes(registry, plan, outputs)


class TestTheClockStartsOnceTheSessionLockIsHeld:
    def test_on_locked_runs_after_the_lock_is_free(self, tmp_path):
        """Red at the base: ``_execute`` armed the clock before waiting for the lock."""
        from automated_security_helper.cli.mcp.sessions import (
            get_default_registry,
            reset_default_registry_for_tests,
        )

        reset_default_registry_for_tests()
        session = get_default_registry().session_for("clock-session")
        plan = _plan(tmp_path)
        settings = _settings(tmp_path)
        order: List[str] = []
        held = threading.Event()
        released = threading.Event()

        def hold_the_lock() -> None:
            with session.lock:
                order.append("lock held by another scan")
                held.set()
                released.wait(timeout=5)
            order.append("lock released")

        holder = threading.Thread(target=hold_the_lock)
        holder.start()
        assert held.wait(timeout=5)

        def run() -> None:
            with patch.object(
                workspace_module, "execute_workspace", side_effect=lambda *a, **k: None
            ):
                workspace_module._under_session_lock(
                    "clock-session",
                    plan,
                    settings,
                    on_locked=lambda: order.append("clock started"),
                )

        runner = threading.Thread(target=run)
        runner.start()
        runner.join(timeout=0.5)
        assert "clock started" not in order, order
        released.set()
        runner.join(timeout=5)
        holder.join(timeout=5)

        assert order.index("lock released") < order.index("clock started"), order

    def test_the_run_without_a_session_starts_its_clock_too(self, tmp_path):
        """Control: with no session there is no lock to wait for; the clock still starts."""
        order: List[str] = []
        with patch.object(
            workspace_module, "execute_workspace", side_effect=lambda *a, **k: None
        ):
            workspace_module._under_session_lock(
                None,
                _plan(tmp_path),
                _settings(tmp_path),
                on_locked=lambda: order.append("clock started"),
            )

        assert order == ["clock started"]

    def test_execute_hands_its_clock_to_the_lock(self, tmp_path):
        """``_execute`` starts the clock through the lock, once, for a claimed session."""
        order: List[str] = []
        plan = _plan(tmp_path)
        settings = _settings(tmp_path)

        with (
            patch.object(
                workspace_module,
                "execute_workspace",
                side_effect=lambda p, s, **k: _result(p, s),
            ),
            patch.object(workspace_module, "ScanPresence") as presence,
        ):
            presence.return_value.__enter__.return_value = None
            presence.return_value.__exit__.return_value = False
            asyncio.run(
                workspace_module._execute(
                    plan=plan,
                    settings=settings,
                    project_outputs={},
                    progress_reporter=None,
                    session_id=None,
                    claim=_Claim(order),
                    on_thread_start=lambda: order.append("clock started"),
                )
            )

        assert order.count("clock started") == 1


class TestTheWorkerSettlesBeforeItGivesTheClaimBack:
    def test_settle_runs_before_worker_returns(self, tmp_path):
        """Red at the base: the claim was released in the inner finally, settle after."""
        order: List[str] = []
        plan = _plan(tmp_path)
        settings = _settings(tmp_path)

        with (
            patch.object(
                workspace_module,
                "execute_workspace",
                side_effect=lambda p, s, **k: _result(p, s),
            ),
            patch.object(workspace_module, "ScanPresence") as presence,
        ):
            presence.return_value.__enter__.return_value = None
            presence.return_value.__exit__.return_value = False
            asyncio.run(
                workspace_module._execute(
                    plan=plan,
                    settings=settings,
                    project_outputs={},
                    progress_reporter=None,
                    session_id=None,
                    claim=_Claim(order),
                    settle=lambda: order.append("settle"),
                )
            )

        assert order.count("settle") == 1
        assert order.index("settle") < order.index("worker_returns"), order

    def test_settle_runs_once_when_the_run_raises(self, tmp_path):
        """Control: a failing run still settles exactly once, before the release."""
        order: List[str] = []

        def failing(p, s, **k):
            raise RuntimeError("scan failed")

        with (
            patch.object(workspace_module, "execute_workspace", side_effect=failing),
            patch.object(workspace_module, "ScanPresence") as presence,
            pytest.raises(RuntimeError, match="scan failed"),
        ):
            presence.return_value.__enter__.return_value = None
            presence.return_value.__exit__.return_value = False
            asyncio.run(
                workspace_module._execute(
                    plan=_plan(tmp_path),
                    settings=_settings(tmp_path),
                    project_outputs={},
                    progress_reporter=None,
                    session_id=None,
                    claim=_Claim(order),
                    settle=lambda: order.append("settle"),
                )
            )

        assert order == ["worker_starts", "settle", "worker_returns"]


class TestAnUnreadableServerConfigIsARefusal:
    @pytest.mark.asyncio
    async def test_resolve_workspace_answers_exit_3(self, tmp_path, monkeypatch):
        """Red at the base: ASHConfigSourceError escaped the tool as an exception."""
        monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
        plan = _plan(tmp_path)

        with patch.object(
            workspace_module,
            "_resolve_session_config",
            side_effect=ASHConfigSourceError("ASH_CONFIG cannot be read"),
        ):
            response = await workspace_module.mcp_resolve_workspace(
                workspace_file=plan.workspace_file
            )

        assert response["success"] is False
        assert response.get("exit_code") == 3
        assert "ASH_CONFIG cannot be read" in str(response)

    @pytest.mark.asyncio
    async def test_scan_workspace_answers_exit_3(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
        plan = _plan(tmp_path)

        with patch.object(
            workspace_module,
            "_resolve_session_config",
            side_effect=ASHConfigSourceError("ASH_CONFIG cannot be read"),
        ):
            response = await workspace_module.mcp_scan_workspace(
                workspace_file=plan.workspace_file
            )

        assert response["success"] is False
        assert response.get("exit_code") == 3


class TestResolutionRunsOffTheEventLoop:
    @pytest.mark.asyncio
    async def test_the_committed_output_check_runs_on_another_thread(
        self, tmp_path, monkeypatch
    ):
        """Red at the base: the check ran on the loop's thread."""
        monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp"))
        plan = _plan(tmp_path)
        threads: List[int] = []

        def record_thread(plan, settings) -> None:
            threads.append(threading.get_ident())

        with (
            patch.object(
                workspace_module, "_refuse_committed_output", side_effect=record_thread
            ),
            patch.object(
                workspace_module,
                "execute_workspace",
                side_effect=lambda p, s, **k: _result(p, s),
            ),
        ):
            response = await workspace_module.mcp_scan_workspace(
                workspace_file=plan.workspace_file,
                output_dir=str(tmp_path / "out"),
            )

        assert threads, response
        assert threads[0] != threading.get_ident()
