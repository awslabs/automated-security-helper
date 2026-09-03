#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``offline=True`` over the workspace-MCP path has to reach the scanners.

Why this file exists
--------------------
Review finding: ``offline=True`` was accepted by the workspace MCP tools, threaded into
``ProjectScanSettings.offline``, passed on to the orchestrator as a declared field -- and never
consumed by anything. The gate scanners actually use is ``is_offline_mode()`` in
``core/constants.py``, which reads ``os.environ["ASH_OFFLINE"]``. So the flag was a silent no-op:
a caller asked for no network access, the response reported success, and the scan ran with full
egress. The CLI sets the variable around its own invocations (``run_ash_scan.py``); this path
bypassed that.

The distinction that makes this testable at all is that ``ASH_OFFLINE`` has to be visible *during*
execution and gone *afterwards*. A test that only checks the value after the call cannot fail --
the variable is absent both when the fix works and when nothing was ever set. So the double under
test records what it observed at the moment it ran, which is the only point where the answer differs.

Restoration is checked as its own property, not as a tidiness nicety. The CLI pops the variable
unconditionally, which is safe for a process that runs one scan and exits. A long-lived MCP server
started with ``ASH_OFFLINE=YES`` in its own environment would have that deployment-level setting
silently cleared by the first offline scan, turning one request's flag into a permanent change in
the opposite direction.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.cli.mcp import workspace as workspace_module
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


@pytest.fixture
def observed(monkeypatch, tmp_path) -> Dict[str, Any]:
    """Substitute ``execute_workspace`` with a double that records the live env var.

    ``observed["during"]`` is the whole point: the value at the moment the scan would consult it.
    Reading ``os.environ`` after ``_execute`` returns cannot distinguish a working fix from a
    no-op, because a correct implementation restores the variable and a broken one never set it.
    """
    record: Dict[str, Any] = {"during": "__unset__", "calls": 0}

    def _double(plan, settings, **kwargs):
        record["calls"] += 1
        record["during"] = os.environ.get("ASH_OFFLINE", "__absent__")
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

    monkeypatch.setattr(workspace_module, "execute_workspace", _double)
    return record


def _settings(tmp_path: Path, *, offline: bool) -> ProjectScanSettings:
    return ProjectScanSettings(
        output_dir=tmp_path / "out",
        phases=("scan",),
        max_parallel_projects=1,
        offline=offline,
    )


def _run(plan, settings) -> Any:
    return asyncio.run(
        workspace_module._execute(
            plan=plan,
            settings=settings,
            project_outputs={},
            progress_reporter=None,
        )
    )


def test_offline_true_sets_the_variable_the_scanners_read(observed, tmp_path, monkeypatch):
    """The scanners consult ASH_OFFLINE, so offline=True must set it before they run."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)

    _run(_plan(tmp_path), _settings(tmp_path, offline=True))

    assert observed["calls"] == 1
    assert observed["during"] == "YES", (
        "ASH_OFFLINE must be set while the workspace executes; scanners gate on "
        "is_offline_mode() reading it, so anything else means offline=True did nothing"
    )


def test_offline_false_does_not_set_the_variable(observed, tmp_path, monkeypatch):
    """The negative control: a normal scan must not silently become offline.

    Without this, an implementation that always set the variable would pass the test above and
    would quietly cut network access for every workspace scan.
    """
    monkeypatch.delenv("ASH_OFFLINE", raising=False)

    _run(_plan(tmp_path), _settings(tmp_path, offline=False))

    assert observed["during"] == "__absent__"


def test_the_variable_is_removed_again_when_it_was_not_set_before(
    observed, tmp_path, monkeypatch
):
    """One request's flag must not outlive the request."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)

    _run(_plan(tmp_path), _settings(tmp_path, offline=True))

    assert "ASH_OFFLINE" not in os.environ


def test_an_ambient_value_survives_an_offline_scan(observed, tmp_path, monkeypatch):
    """A server started with ASH_OFFLINE set keeps that setting afterwards.

    This is why the value is snapshotted rather than popped. The CLI pops unconditionally, which
    is harmless in a process that runs one scan and exits, but here it would turn a
    deployment-level "always offline" into "offline until the first offline scan finishes" --
    a silent flip to the less safe state, caused by a request asking for the safer one.
    """
    monkeypatch.setenv("ASH_OFFLINE", "TRUE")

    _run(_plan(tmp_path), _settings(tmp_path, offline=True))

    assert os.environ.get("ASH_OFFLINE") == "TRUE"


def test_the_variable_is_restored_even_when_execution_raises(tmp_path, monkeypatch):
    """Restoration is in a finally, so a failing scan does not leak the flag."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)

    def _boom(plan, settings, **kwargs):
        raise RuntimeError("scan blew up")

    monkeypatch.setattr(workspace_module, "execute_workspace", _boom)

    with pytest.raises(RuntimeError, match="scan blew up"):
        _run(_plan(tmp_path), _settings(tmp_path, offline=True))

    assert "ASH_OFFLINE" not in os.environ


def test_settings_offline_is_still_carried_to_execute_workspace(tmp_path, monkeypatch):
    """The env var is the mechanism, not a replacement for the setting.

    ``settings.offline`` is still what the orchestrator receives, and a future change that made
    the orchestrator honour it directly should not have to reinstate this. So the setting reaching
    execution is pinned separately from the environment variable being set.
    """
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    seen: List[Optional[bool]] = []

    def _capture(plan, settings, **kwargs):
        seen.append(settings.offline)
        payload = WorkspaceResults(
            workspace_file=plan.workspace_file,
            workspace_root=plan.workspace_root,
            status="completed",
            exit_code=0,
            projects=[],
            unconvertible_finding_paths=0,
        )
        return WorkspaceRunResult(
            results_path=Path(settings.output_dir) / "ash_workspace_results.json",
            exit_code=0,
            payload=payload,
        )

    monkeypatch.setattr(workspace_module, "execute_workspace", _capture)

    _run(_plan(tmp_path), _settings(tmp_path, offline=True))

    assert seen == [True]
