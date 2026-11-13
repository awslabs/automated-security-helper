# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan whose scanner selection is refused answers ``success`` False at the tool.

Why this exists
---------------
The workspace scan tool takes ``scanners`` and ``excluded_scanners``. A selection
no project can run (a name that matches no registered scanner, or an allowlist its
own exclusion cancels) is refused before any project starts. The refusal has to
reach the MCP client as a failure: ``success`` False, the usage-error exit code,
and the refusal's own reason. A response that says ``success`` True for it reads
as a scan that ran, with nothing checked.

These cells drive the registered tool itself, not the layer under it, so a wrapper
that rebuilt or defaulted the response would be caught here.
"""

from __future__ import annotations

import json
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock

import pytest

from automated_security_helper.cli import mcp_server
from automated_security_helper.core.constants import ASH_EXIT_CODES
from automated_security_helper.models.workspace import WorkspaceExitCode

pytestmark = pytest.mark.unit

#: The usage-error code the CLI exits with for the same selection.
USAGE = int(WorkspaceExitCode.USAGE_ERROR)


@pytest.fixture
def workspace(tmp_path, monkeypatch) -> Dict[str, Any]:
    """A one-project workspace the session may scan, with the MCP state isolated.

    The tool resolves a session from the headers, and a session's config inputs
    are confined, so the workspace sits inside a granted root: the cells are
    about the selection, and a confinement refusal would shadow it. The profile
    and session registries are cleared and ASH_CONFIG is unset, as every sibling
    MCP suite does, so state cannot leak between tests and a developer's own
    config cannot change what is selectable; the session workspace root points
    into tmp_path so nothing lands in the real default location.
    """
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp.sessions import (
        reset_default_registry_for_tests,
    )
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    reset_default_registry_for_tests()
    for name in ("ASH_MCP_ALLOWED_CONFIG_ROOTS", "ASH_MCP_TRANSPORT", "ASH_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    registry = scan_registry_module.ScanRegistry()
    monkeypatch.setattr(scan_registry_module, "_scan_registry", registry)
    root = tmp_path / "work"
    (root / "api").mkdir(parents=True)
    (root / "api" / "app.py").write_text("x = 1\n", encoding="utf-8")
    workspace_file = root / "dev.code-workspace"
    workspace_file.write_text(
        json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8"
    )
    yield {
        "workspace_file": workspace_file,
        "output": tmp_path / "out",
        "registry": registry,
    }
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    reset_default_registry_for_tests()


def _ctx() -> MagicMock:
    ctx = MagicMock()
    ctx.headers = {"mcp-session-id": "client-one"}
    for name in ("info", "debug", "warning", "error", "report_progress"):
        setattr(ctx, name, AsyncMock())
    return ctx


async def _scan(workspace, **selection: Any) -> tuple[Dict[str, Any], MagicMock]:
    ctx = _ctx()
    response = await mcp_server.run_ash_workspace_scan(
        ctx,
        workspace_file=str(workspace["workspace_file"]),
        output_dir=str(workspace["output"]),
        **selection,
    )
    return response, ctx


def _assert_no_scan_ran(registry) -> None:
    """No project scan is running or ran. A refusal may come before or after the
    projects are registered, so no entry at all is fine; any entry there is must
    be closed as failed, never left running, completed, or even incomplete (a
    terminal status for a scan that did run). That the registry here is the one
    the tool writes to is shown by the control, which requires an entry."""
    assert registry.list_scans(active_only=True) == [], "a project scan is running"
    wrong = [
        entry
        for entry in registry.list_scans()
        if not str(entry.get("status", "")).lower().endswith("failed")
    ]
    assert not wrong, wrong


def _assert_refused(response: Dict[str, Any], ctx: MagicMock, reason: str) -> None:
    assert response.get("success") is False, response
    error = str(response.get("error"))
    assert reason in error, error
    assert response.get("exit_code") == USAGE, response
    assert response.get("exit_code_meaning") == ASH_EXIT_CODES[USAGE], response
    # The refusal is also told to the client as an error, with its reason.
    told = [str(call.args[0]) for call in ctx.error.await_args_list]
    assert any(reason in text for text in told), told


@pytest.mark.asyncio
async def test_a_selection_matching_no_scanner_is_a_failure(workspace) -> None:
    """An allowlist that matches nothing selects nothing: the scan is refused, and
    the tool's answer says so rather than reporting a scan that ran."""
    response, ctx = await _scan(workspace, scanners=["no-such-scanner"])

    _assert_refused(
        response, ctx, "None of the requested scanners exist: no-such-scanner"
    )
    # Nothing ran in its place: no scan id was issued, and any registry entry made
    # for the project was closed as failed rather than left running.
    assert not response.get("scan_ids"), response
    _assert_no_scan_ran(workspace["registry"])


@pytest.mark.asyncio
async def test_a_selection_that_cancels_itself_is_a_failure(workspace) -> None:
    response, ctx = await _scan(
        workspace, scanners=["bandit"], excluded_scanners=["bandit"]
    )

    _assert_refused(response, ctx, "the selection cancels itself")
    assert not response.get("scan_ids"), response
    _assert_no_scan_ran(workspace["registry"])


@pytest.mark.asyncio
async def test_a_refused_selection_makes_no_registry_entries(workspace) -> None:
    """The refusal is a judgment on the command line, made before any project
    work: nothing is registered for it, not even entries closed as failed. An
    entry per project would tell a client polling the registry that scans were
    attempted, when none was."""
    response, _ctx = await _scan(workspace, scanners=["no-such-scanner"])

    assert response.get("exit_code") == USAGE, response
    assert workspace["registry"].list_scans() == [], workspace["registry"].list_scans()


@pytest.mark.asyncio
async def test_a_refused_selection_leaves_the_output_tree_alone(workspace) -> None:
    """One selection typo must not move aside every project's previous results
    or create their output directories: the pre-check runs before any output or
    registry work, so a refused command line changes nothing on disk."""
    from automated_security_helper.workspace.execution import PROJECTS_DIR_NAME

    out = workspace["output"]
    project_dir = out / PROJECTS_DIR_NAME / "api"
    project_dir.mkdir(parents=True)
    previous = project_dir / "ash_aggregated_results.json"
    previous.write_text('{"previous": true}', encoding="utf-8")
    before = sorted(str(path.relative_to(out)) for path in out.rglob("*"))

    response, _ctx = await _scan(workspace, scanners=["no-such-scanner"])

    assert response.get("exit_code") == USAGE, response
    after = sorted(str(path.relative_to(out)) for path in out.rglob("*"))
    assert after == before, (before, after)
    assert previous.read_text(encoding="utf-8") == '{"previous": true}'


@pytest.mark.asyncio
async def test_control_a_selection_a_project_can_run_is_not_refused(
    workspace, monkeypatch
) -> None:
    """The cells above are not met by refusing every selection: a selection naming
    a registered scanner gets past the refusal, down to the execution itself.

    The stand-in replaces ``execute_workspace``, which sits below the tool's own
    selection preflight, so the call still traverses the real prewarm and the
    real pre-check on its way here: an implementation that refused every
    selection anywhere above the execution would fail this control. It raises
    rather than fabricate a result: the point shown is that the selection was
    not refused as usage, not that a scan succeeds."""
    from automated_security_helper.cli.mcp import workspace as workspace_module

    reached: list = []

    def execute(plan, settings, **kwargs: Any):
        reached.append(settings)
        raise RuntimeError("stand-in execution failed")

    monkeypatch.setattr(workspace_module, "execute_workspace", execute)

    response, _ctx = await _scan(workspace, scanners=["bandit"])

    assert reached, "the selection never reached the execution"
    assert tuple(reached[0].enabled_scanners) == ("bandit",), reached[0]
    assert response.get("exit_code") != USAGE, response
    # The registry the refusal cells read is the one the tool writes to: a
    # selection that gets through registers its project there.
    assert workspace["registry"].list_scans(), "the tool registered no entry here"
