# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every entry point refuses a committed results path before it changes anything.

The orchestrator refused a scan whose output directory held a file git tracks
where the scan deletes and writes its own, but other code ran first and deleted
or overwrote those files:

* container and Nix mode cleared the output directory on the host before the
  inner scan started, so the inner scan found nothing committed there, ran, and
  wrote its results over the paths (Nix mode then exited 1, not 3);
* the CLI's logger truncated a committed ``ash.log`` before the orchestrator ran;
* a workspace scan writes its unified results file at the root of its output
  directory, which no orchestrator checks;
* the MCP scan tool's ``clean_output`` removed the results file, and the MCP
  workspace tool removed each project's, before any scan started.

Each test commits files where one of those writes lands, runs the entry point
with the part that would scan stubbed, and checks that the run exits 3 or returns
an error and that the committed files are as they were. The red run of these
tests executed the deletions, so each checks first that every directory it hands
over lies inside ``tmp_path``.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions import run_ash_scan as run_ash_scan_module
from automated_security_helper.interactions.run_ash_scan import run_ash_scan
from automated_security_helper.utils.subprocess_utils import create_completed_process
from tests.unit.test_committed_results_paths_are_never_deleted import (
    _confined,
    _results_json,
    _snapshot,
)
from tests.unit.workspace.test_execution import _git

pytestmark = pytest.mark.integration


def _isolate_git(monkeypatch, tmp_path: Path) -> None:
    """Keep the developer's git config, and any checkout above tmp_path, out."""
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))


def _commit(repository: Path, files: Dict[str, str]) -> None:
    """Write *files* (paths relative to *repository*) and add them to its index."""
    for relative, text in files.items():
        path = repository / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    if not (repository / ".git").exists():
        assert _git(repository, "init", "-q").returncode == 0
    assert _git(repository, "add", "--", *files).returncode == 0
    listed = _git(repository, "ls-files", "--", *files).stdout.split()
    # A control: git has to track what the test calls committed.
    assert sorted(listed) == sorted(files), listed


#: Committed under the output directory: the results file container and Nix mode
#: read back, and the report a CI step publishes.
COMMITTED = {
    "ash_aggregated_results.json": _results_json("committed-results"),
    "reports/ash.sarif": '{"committed": "sarif"}\n',
}


def _repo(tmp_path: Path, monkeypatch, committed=COMMITTED) -> tuple[Path, Path]:
    _isolate_git(monkeypatch, tmp_path)
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = source / ".ash" / "ash_output"
    _commit(
        source,
        {
            "app.py": "x = 1\n",
            **{f".ash/ash_output/{name}": text for name, text in committed.items()},
        },
    )
    monkeypatch.chdir(tmp_path)
    return source, output


# ---------------------------------------------------------------------------
# Container and Nix mode
# ---------------------------------------------------------------------------


def test_container_mode_stops_before_the_host_clears_the_output_directory(
    tmp_path, monkeypatch, capsys
):
    source, output = _repo(tmp_path, monkeypatch)
    _confined(tmp_path, source, output)
    before = _snapshot(output)
    seen_by_the_container: List[Dict[str, bytes]] = []

    def _container(**_kwargs):
        # What the inner scan would have found in the output directory.
        seen_by_the_container.append(_snapshot(output))
        return create_completed_process(args=["container"], returncode=0)

    monkeypatch.setattr(run_ash_scan_module, "run_ash_container", _container)

    with pytest.raises(SystemExit) as exited:
        run_ash_scan(
            source_dir=source,
            output_dir=output,
            mode=RunMode.container,
            progress=False,
            show_summary=False,
        )

    assert _snapshot(output) == before, "the committed files were removed"
    assert seen_by_the_container == [], "the container was started"
    assert exited.value.code == 3
    printed = capsys.readouterr().out
    for name in COMMITTED:
        assert name in printed, printed


def test_nix_mode_stops_before_the_host_clears_the_output_directory(
    tmp_path, monkeypatch, capsys
):
    source, output = _repo(tmp_path, monkeypatch)
    _confined(tmp_path, source, output)
    before = _snapshot(output)
    seen_by_the_shell: List[Dict[str, bytes]] = []

    def _nix(**_kwargs):
        seen_by_the_shell.append(_snapshot(output))
        return create_completed_process(args=["nix"], returncode=0)

    monkeypatch.setattr(run_ash_scan_module, "run_ash_nix", _nix)
    monkeypatch.setattr(run_ash_scan_module, "nix_preflight", lambda: None)

    with pytest.raises(SystemExit) as exited:
        run_ash_scan(
            source_dir=source,
            output_dir=output,
            mode=RunMode.nix,
            progress=False,
            show_summary=False,
        )

    assert _snapshot(output) == before, "the committed files were removed"
    assert seen_by_the_shell == [], "the Nix shell was started"
    assert exited.value.code == 3
    assert "reports/ash.sarif" in capsys.readouterr().out


def test_a_container_build_without_a_run_is_not_stopped_by_committed_reports(
    tmp_path, monkeypatch
):
    """``--no-run`` builds the image and writes nothing in the output directory but
    the log and, inside the tree, the directory's ``.gitignore``
    (run_ash_scan._ignore_output_dir_in_git, before any mode starts), so committed
    reports do not end it and are not touched."""
    from automated_security_helper.utils.output_dir_links import OUTPUT_GITIGNORE

    source, output = _repo(tmp_path, monkeypatch)
    _confined(tmp_path, source, output)
    before = _snapshot(output)
    built: List[bool] = []

    def _container(**kwargs):
        built.append(kwargs["run"])
        return create_completed_process(args=["container"], returncode=0)

    monkeypatch.setattr(run_ash_scan_module, "run_ash_container", _container)

    with pytest.raises(SystemExit) as exited:
        run_ash_scan(
            source_dir=source,
            output_dir=output,
            mode=RunMode.container,
            run=False,
            progress=False,
            show_summary=False,
        )

    assert exited.value.code == 0
    assert built == [False]
    after = _snapshot(output)
    after.pop("ash.log", None)
    after.pop(OUTPUT_GITIGNORE, None)
    assert after == before


# ---------------------------------------------------------------------------
# The CLI's log files
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("log_name", ["ash.log", "ash.log.jsonl"])
def test_a_committed_log_file_stops_the_scan_before_the_logger_opens_it(
    tmp_path, monkeypatch, capsys, log_name
):
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    source, output = _repo(
        tmp_path, monkeypatch, committed={log_name: "committed log\n"}
    )
    _confined(tmp_path, source, output)
    before = _snapshot(output)
    monkeypatch.setattr(
        ASHScanOrchestrator,
        "create",
        classmethod(
            lambda cls, **kw: (_ for _ in ()).throw(AssertionError("scan started"))
        ),
    )

    with pytest.raises(SystemExit) as exited:
        run_ash_scan(
            source_dir=source,
            output_dir=output,
            mode=RunMode.local,
            progress=False,
            show_summary=False,
        )

    assert _snapshot(output) == before, "the committed log was rewritten"
    assert exited.value.code == 3
    assert log_name in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Workspace mode: the unified results at the root of the output directory
# ---------------------------------------------------------------------------


def _workspace_plan(root: Path):
    from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

    project = root / "api"
    (project / "src").mkdir(parents=True, exist_ok=True)
    (project / "src" / "app.py").write_text("print('x')\n", encoding="utf-8")
    workspace_file = root / "fixture.code-workspace"
    workspace_file.write_text(
        json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8"
    )
    return WorkspacePlan(
        workspace_file=workspace_file.as_posix(),
        workspace_root=root.as_posix(),
        projects=[
            ProjectPlan(
                key="api",
                relative_path="api",
                path=project.as_posix(),
                label="api",
                display_label="api",
                severity_threshold="MEDIUM",
            )
        ],
    )


def _execute_with_a_fake_orchestrator(monkeypatch) -> List[object]:
    """execute_workspace as it runs, with no scanner: projects scan to nothing.

    Replaced where the CLI looks it up and where the MCP workspace tool imported
    it, and it writes what the real one writes: the per-project results files,
    the unified results file and the report manifest.
    """
    from automated_security_helper.cli.mcp import workspace as mcp_workspace
    from automated_security_helper.workspace import execution
    from tests.unit.workspace.test_execution import FakeOrchestrator

    real = execution.execute_workspace
    calls: List[object] = []

    def _execute(plan, settings, **_kwargs):
        calls.append(plan)
        return real(
            plan,
            settings,
            orchestrator_factory=FakeOrchestrator.create,
            reporter_classes=[],
        )

    monkeypatch.setattr(execution, "execute_workspace", _execute)
    monkeypatch.setattr(mcp_workspace, "execute_workspace", _execute)
    return calls


def test_a_workspace_scan_stops_before_writing_over_a_committed_unified_results_file(
    tmp_path, monkeypatch, capsys
):
    source, output = _repo(tmp_path, monkeypatch)
    plan = _workspace_plan(source)
    _confined(tmp_path, source, output)
    before = _snapshot(output)
    executed = _execute_with_a_fake_orchestrator(monkeypatch)

    exit_code = None
    try:
        run_ash_scan(
            source_dir=source,
            output_dir=output,
            workspace_plan=plan,
            progress=False,
            show_summary=False,
        )
    except SystemExit as exited:
        exit_code = exited.code

    assert _snapshot(output) == before, "the committed results were written over"
    assert executed == [], "the workspace was scanned"
    assert exit_code == 3
    assert "ash_aggregated_results.json" in capsys.readouterr().out


@pytest.mark.parametrize("mode", [RunMode.local, RunMode.container])
def test_a_workspace_scan_stops_before_any_project_for_a_committed_project_output(
    tmp_path, monkeypatch, capsys, mode
):
    """A project's ``projects/<key>/`` is a fresh scan's output directory. Locally
    its orchestrator would refuse it after the others had run; in a container it
    cannot ask the host's git at all. The workspace stops before any project."""
    source, output = _repo(
        tmp_path,
        monkeypatch,
        committed={"projects/api/reports/ash.sarif": '{"committed": "sarif"}\n'},
    )
    plan = _workspace_plan(source)
    _confined(tmp_path, source, output)
    before = _snapshot(output)
    executed = _execute_with_a_fake_orchestrator(monkeypatch)
    started: List[bool] = []

    def _container(**_kwargs):
        started.append(True)
        return create_completed_process(args=["container"], returncode=0)

    monkeypatch.setattr(run_ash_scan_module, "run_ash_container", _container)

    exit_code = None
    try:
        run_ash_scan(
            source_dir=source,
            output_dir=output,
            workspace_plan=plan,
            mode=mode,
            progress=False,
            show_summary=False,
        )
    except SystemExit as exited:
        exit_code = exited.code

    assert executed == [] and started == [], "the workspace was scanned"
    assert exit_code == 3
    assert "projects/api/reports/ash.sarif" in capsys.readouterr().out.replace("\n", "")
    assert _snapshot(output) == before


def test_every_log_file_the_logger_writes_is_a_results_path(tmp_path, monkeypatch):
    """The logger's file names are named twice, in core/committed_output.py and in
    utils/scan_output_dirs.py; this keeps the two lists the same."""
    from automated_security_helper.core.committed_output import (
        LOG_FILE_NAMES,
        committed_entries_in_the_way,
    )

    source, output = _repo(
        tmp_path, monkeypatch, committed=dict.fromkeys(LOG_FILE_NAMES, "log\n")
    )

    found = committed_entries_in_the_way(output, files=LOG_FILE_NAMES, directories=())

    assert [path.name for path in found] == sorted(LOG_FILE_NAMES)


def test_a_workspace_scan_is_not_stopped_by_committed_files_it_never_writes(
    tmp_path, monkeypatch
):
    """At its root a workspace scan writes the unified results and reports/ only,
    so a committed scanners/ there neither stops it nor is touched."""
    source, output = _repo(
        tmp_path,
        monkeypatch,
        committed={"scanners/bandit/notes.txt": "committed notes\n"},
    )
    plan = _workspace_plan(source)
    _confined(tmp_path, source, output)
    executed = _execute_with_a_fake_orchestrator(monkeypatch)

    run_ash_scan(
        source_dir=source,
        output_dir=output,
        workspace_plan=plan,
        progress=False,
        show_summary=False,
    )

    assert len(executed) == 1
    assert (output / "scanners/bandit/notes.txt").read_text(
        encoding="utf-8"
    ) == "committed notes\n"
    assert (output / "ash_aggregated_results.json").is_file()


# ---------------------------------------------------------------------------
# The MCP tools
# ---------------------------------------------------------------------------


@pytest.fixture
def mcp_ctx():
    ctx = MagicMock()
    for name in ("info", "debug", "warning", "error", "report_progress"):
        setattr(ctx, name, AsyncMock())
    return ctx


@pytest.fixture
def isolated_registry(monkeypatch):
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    fresh = scan_registry_module.ScanRegistry()
    monkeypatch.setattr(scan_registry_module, "_scan_registry", fresh)
    return fresh


@pytest.mark.asyncio
async def test_the_mcp_scan_tool_refuses_before_clean_output_removes_the_results(
    tmp_path, monkeypatch, mcp_ctx, isolated_registry
):
    from automated_security_helper.cli.mcp.scan_target import (
        ASH_MCP_ALLOWED_ROOTS_ENV,
    )
    from automated_security_helper.cli.mcp_server import run_ash_scan as scan_tool

    committed = {
        "ash_aggregated_results.json": _results_json("committed-results"),
        "reports/ash.html": "<p>committed report</p>\n",
    }
    source, output = _repo(tmp_path, monkeypatch, committed=committed)
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    _confined(tmp_path, source, output)
    before = _snapshot(output)

    with (
        patch(
            "automated_security_helper.cli.mcp_server.mcp_scan_directory",
            new_callable=AsyncMock,
            return_value={"success": True, "scan_id": "should-not-start"},
        ) as started,
        patch("automated_security_helper.cli.mcp_server.asyncio.create_task"),
    ):
        result = await scan_tool(ctx=mcp_ctx, source_dir=str(source), clean_output=True)

    assert _snapshot(output) == before, "clean_output removed a committed file"
    assert result["success"] is False, result
    assert result["error_type"] == "committed_output_files", result
    assert "reports/ash.html" in result["error"], result
    started.assert_not_called()


@pytest.mark.asyncio
async def test_the_mcp_scan_directory_tool_refuses_before_starting_a_scan(
    tmp_path, monkeypatch, isolated_registry
):
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.cli.mcp.scan_target import (
        ASH_MCP_ALLOWED_ROOTS_ENV,
    )

    source, output = _repo(tmp_path, monkeypatch)
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    _confined(tmp_path, source, output)
    before = _snapshot(output)
    runner = AsyncMock()
    monkeypatch.setattr(mcp_tools, "_run_scan_async", runner)

    result = await mcp_tools.mcp_scan_directory(directory_path=str(source))
    await asyncio.sleep(0)

    assert result["success"] is False, result
    assert "ash_aggregated_results.json" in result["error"], result
    assert isolated_registry.get_scan_count() == 0
    runner.assert_not_called()
    assert _snapshot(output) == before


def _mcp_workspace(tmp_path: Path, monkeypatch, committed: Dict[str, str]):
    """A workspace whose root is a git repository, with *committed* in its output."""
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    source, output = _repo(tmp_path, monkeypatch, committed=committed)
    plan = _workspace_plan(source)
    return source, output, Path(plan.workspace_file)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "committed",
    [
        "projects/api/ash_aggregated_results.json",
        "projects/api/reports/ash.sarif",
        "ash_aggregated_results.json",
        "reports/ash.sarif",
    ],
)
async def test_the_mcp_workspace_tool_refuses_before_it_clears_a_project_output(
    tmp_path, monkeypatch, isolated_registry, committed
):
    from automated_security_helper.cli.mcp.workspace import mcp_scan_workspace

    source, output, workspace_file = _mcp_workspace(
        tmp_path, monkeypatch, {committed: _results_json("committed-results")}
    )
    _confined(tmp_path, source, output)
    before = _snapshot(output)
    executed = _execute_with_a_fake_orchestrator(monkeypatch)

    result = await mcp_scan_workspace(
        workspace_file=str(workspace_file), clean_output=True
    )

    # The two results files are removed or written over by the run itself; the
    # two reports would be by a real project scan and a real SARIF reporter,
    # which the fake does not run, so for those the run starting is the failure.
    assert _snapshot(output).get(committed) == before[committed], (
        "the committed file was removed or written over"
    )
    assert executed == [], "the workspace was scanned"
    assert result["success"] is False, result
    assert result["exit_code"] == 3, result
    assert committed in result["error"], result
    assert isolated_registry.get_scan_count() == 0
    assert _snapshot(output) == before


@pytest.mark.asyncio
async def test_the_mcp_workspace_tool_scans_beside_committed_files_it_never_writes(
    tmp_path, monkeypatch, isolated_registry
):
    source, output, workspace_file = _mcp_workspace(
        tmp_path, monkeypatch, {"scanners/notes.txt": "committed notes\n"}
    )
    from automated_security_helper.cli.mcp.workspace import mcp_scan_workspace

    _confined(tmp_path, source, output)
    executed = _execute_with_a_fake_orchestrator(monkeypatch)

    result = await mcp_scan_workspace(workspace_file=str(workspace_file))

    assert result["success"] is True, result
    assert len(executed) == 1
    assert (output / "scanners/notes.txt").read_text(
        encoding="utf-8"
    ) == "committed notes\n"


# ---------------------------------------------------------------------------
# A committed file in one project's output refuses the whole workspace
# ---------------------------------------------------------------------------
#
# Workspace mode refuses the whole workspace for what it finds before execution
# starts (permitted roots, tool versions, plugin sets, scanner selection, and
# committed files where a project would write), and fails only one project for a
# failure during that project's run. A committed file under projects/a/ is found
# before execution, so project b does not run either.


def _two_project_workspace(tmp_path: Path, monkeypatch):
    """Projects a and b, with a file committed in a's output directory, and the
    output a previous run left in b's and at the workspace root."""
    from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

    source, output = _repo(
        tmp_path,
        monkeypatch,
        committed={"projects/a/reports/ash.sarif": '{"committed": "sarif"}\n'},
    )
    projects = []
    for key in ("a", "b"):
        (source / key / "src").mkdir(parents=True, exist_ok=True)
        (source / key / "src" / "app.py").write_text("print('x')\n", encoding="utf-8")
        projects.append(
            ProjectPlan(
                key=key,
                relative_path=key,
                path=(source / key).as_posix(),
                label=key,
                display_label=key,
                severity_threshold="MEDIUM",
            )
        )
    (output / "projects" / "b" / "reports").mkdir(parents=True)
    (output / "projects" / "b" / "ash_aggregated_results.json").write_text(
        _results_json("previous-b"), encoding="utf-8"
    )
    (output / "projects" / "b" / "reports" / "ash.sarif").write_text(
        '{"previous": "b"}\n', encoding="utf-8"
    )
    (output / "ash_aggregated_results.json").write_text(
        _results_json("previous-workspace"), encoding="utf-8"
    )
    workspace_file = source / "fixture.code-workspace"
    workspace_file.write_text(
        json.dumps({"folders": [{"path": "a"}, {"path": "b"}]}), encoding="utf-8"
    )
    plan = WorkspacePlan(
        workspace_file=workspace_file.as_posix(),
        workspace_root=source.as_posix(),
        projects=projects,
    )
    return source, output, plan


def _names_a_not_b(message: str) -> None:
    flat = message.replace("\n", "")
    assert "projects/a/reports/ash.sarif" in flat, message
    assert "projects/b" not in flat, message


def test_a_committed_file_in_one_projects_output_refuses_the_whole_workspace(
    tmp_path, monkeypatch, capsys
):
    from tests.unit.workspace.test_execution import FakeOrchestrator

    source, output, plan = _two_project_workspace(tmp_path, monkeypatch)
    _confined(tmp_path, source, output)
    before = _snapshot(output)
    executed = _execute_with_a_fake_orchestrator(monkeypatch)
    FakeOrchestrator.built = []

    exit_code = None
    try:
        run_ash_scan(
            source_dir=source,
            output_dir=output,
            workspace_plan=plan,
            progress=False,
            show_summary=False,
        )
    except SystemExit as exited:
        exit_code = exited.code

    assert exit_code == 3
    assert executed == [] and FakeOrchestrator.built == [], "a project ran"
    # b's output directory and the workspace root are as the previous run left them.
    assert _snapshot(output) == before
    _names_a_not_b(capsys.readouterr().out)


@pytest.mark.asyncio
async def test_the_mcp_workspace_tool_refuses_the_whole_workspace_the_same_way(
    tmp_path, monkeypatch, isolated_registry
):
    from automated_security_helper.cli.mcp.workspace import mcp_scan_workspace
    from tests.unit.workspace.test_execution import FakeOrchestrator

    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    source, output, plan = _two_project_workspace(tmp_path, monkeypatch)
    _confined(tmp_path, source, output)
    before = _snapshot(output)
    executed = _execute_with_a_fake_orchestrator(monkeypatch)
    FakeOrchestrator.built = []

    result = await mcp_scan_workspace(
        workspace_file=str(plan.workspace_file), clean_output=True
    )

    assert result["success"] is False, result
    assert result["exit_code"] == 3, result
    assert executed == [] and FakeOrchestrator.built == [], "a project ran"
    assert isolated_registry.get_scan_count() == 0
    assert _snapshot(output) == before
    _names_a_not_b(result["error"])
