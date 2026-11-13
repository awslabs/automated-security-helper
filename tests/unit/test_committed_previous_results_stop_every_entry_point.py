# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Committed files where a scan sets the previous results aside stop it first.

An MCP scan sets the previous results aside in ``.ash_previous_results`` and puts
them back, leaving the ``.ash_previous_results_restored`` marker, when it ends
without results of its own (core/previous_results.py). A file git tracks in the
results entries, in the held set or at the marker is refused by the orchestrator,
and code that runs before it, unrefused, would move or remove them:

* the MCP scan tool's ``clean_output`` would set the previous results aside,
  moving a committed ``reports/ash.html`` into ``.ash_previous_results``;
* with a committed ``.ash_previous_results``, it would take that for the held
  set of an interrupted scan, which a failed scan then puts back at the top
  level;
* container and Nix mode would remove the held set and the marker on the host;
* the MCP workspace tool would set each project's previous results aside.

Each entry point refuses first. Every directory handed over lies inside
``tmp_path``, because with a check missing these tests execute the moves and
deletions.
"""

from __future__ import annotations

import asyncio
from typing import Dict, List
from unittest.mock import AsyncMock

import pytest

from automated_security_helper.core.enums import RunMode
from automated_security_helper.core.previous_results import (
    HELD_DIR_NAME,
    RESTORED_MARKER_NAME,
)
from automated_security_helper.interactions import run_ash_scan as run_ash_scan_module
from automated_security_helper.interactions.run_ash_scan import run_ash_scan
from automated_security_helper.utils.subprocess_utils import create_completed_process
from tests.unit.test_committed_output_refused_at_entry_points import (
    _execute_with_a_fake_orchestrator,
    _repo,
    _workspace_plan,
)
from tests.unit.test_committed_results_paths_are_never_deleted import (
    _confined,
    _snapshot,
)

pytestmark = pytest.mark.integration

#: A held set and a restore marker, as a repository could commit them.
HELD = {
    f"{HELD_DIR_NAME}/notes.txt": "committed notes\n",
    RESTORED_MARKER_NAME: "committed marker\n",
}


@pytest.mark.parametrize("mode", [RunMode.container, RunMode.nix])
def test_an_outer_mode_stops_before_the_host_removes_a_committed_held_set(
    tmp_path, monkeypatch, capsys, mode
):
    source, output = _repo(tmp_path, monkeypatch, committed=HELD)
    _confined(tmp_path, source, output)
    before = _snapshot(output)
    started: List[Dict[str, bytes]] = []

    def _run(**_kwargs):
        started.append(_snapshot(output))
        return create_completed_process(args=["inner"], returncode=0)

    monkeypatch.setattr(run_ash_scan_module, "run_ash_container", _run)
    monkeypatch.setattr(run_ash_scan_module, "run_ash_nix", _run)
    monkeypatch.setattr(run_ash_scan_module, "nix_preflight", lambda: None)

    with pytest.raises(SystemExit) as exited:
        run_ash_scan(
            source_dir=source,
            output_dir=output,
            mode=mode,
            progress=False,
            show_summary=False,
        )

    assert _snapshot(output) == before, "the committed held set was removed"
    assert started == [], "the inner scan was started"
    assert exited.value.code == 3
    printed = capsys.readouterr().out.replace("\n", "")
    for name in HELD:
        assert name in printed, printed


@pytest.fixture
def isolated_registry(monkeypatch):
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    fresh = scan_registry_module.ScanRegistry()
    monkeypatch.setattr(scan_registry_module, "_scan_registry", fresh)
    return fresh


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "committed",
    [
        {"reports/ash.html": "<p>committed report</p>\n"},
        {f"{HELD_DIR_NAME}/notes.txt": "committed notes\n"},
        {RESTORED_MARKER_NAME: "committed marker\n"},
    ],
    ids=["a-results-entry", "the-held-set", "the-marker"],
)
async def test_the_mcp_scan_refuses_before_it_sets_the_previous_results_aside(
    tmp_path, monkeypatch, isolated_registry, committed
):
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.cli.mcp.scan_target import (
        ASH_MCP_ALLOWED_ROOTS_ENV,
    )

    source, output = _repo(tmp_path, monkeypatch, committed=committed)
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    _confined(tmp_path, source, output)
    before = _snapshot(output)
    runner = AsyncMock()
    monkeypatch.setattr(mcp_tools, "_run_scan_async", runner)

    result = await mcp_tools.mcp_scan_directory(
        directory_path=str(source), clean_output=True
    )
    await asyncio.sleep(0)

    assert _snapshot(output) == before, "the committed file was moved"
    assert result["success"] is False, result
    assert next(iter(committed)) in result["error"], result
    assert isolated_registry.get_scan_count() == 0
    runner.assert_not_called()


def test_a_report_over_existing_results_is_not_stopped_by_a_committed_held_set(
    tmp_path, monkeypatch, capsys
):
    """A report over existing results sets nothing aside and removes no held set
    or marker, so committed ones neither stop it nor are touched, in the
    orchestrator or in the CLI."""
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator
    from tests.unit.test_committed_output_use_existing_scope import (
        _existing_results,
        _report_over,
        _run_use_existing,
        _written,
    )

    source, output = _repo(tmp_path, monkeypatch, committed=HELD)
    existing = _existing_results(tmp_path)
    _confined(tmp_path, source, output, existing)
    before = _snapshot(output)

    engine = _report_over(source, output, existing, phases=["report"])

    assert engine.phases == [["report"]]
    # The run's own .gitignore aside (_written), nothing in the directory changed.
    assert _written(output) == before
    monkeypatch.setattr(
        ASHScanOrchestrator,
        "create",
        classmethod(
            lambda cls, **kw: (_ for _ in ()).throw(
                AssertionError("the orchestrator was reached")
            )
        ),
    )
    capsys.readouterr()

    assert _run_use_existing(source, output, existing) == 1
    assert "the orchestrator was reached" in capsys.readouterr().out.replace("\n", "")


@pytest.mark.asyncio
async def test_the_mcp_workspace_refuses_before_it_sets_a_projects_results_aside(
    tmp_path, monkeypatch, isolated_registry
):
    from automated_security_helper.cli.mcp.workspace import mcp_scan_workspace

    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    committed = {
        "projects/api/reports/ash.sarif": '{"committed": "sarif"}\n',
        f"projects/api/{HELD_DIR_NAME}/notes.txt": "committed notes\n",
    }
    source, output = _repo(tmp_path, monkeypatch, committed=committed)
    plan = _workspace_plan(source)
    _confined(tmp_path, source, output)
    before = _snapshot(output)
    executed = _execute_with_a_fake_orchestrator(monkeypatch)

    result = await mcp_scan_workspace(
        workspace_file=plan.workspace_file, clean_output=True
    )

    assert _snapshot(output) == before, "a committed file was moved"
    assert executed == [], "the workspace was scanned"
    assert result["success"] is False, result
    assert result["exit_code"] == 3, result
    for name in committed:
        assert name in result["error"], result
    assert isolated_registry.get_scan_count() == 0
