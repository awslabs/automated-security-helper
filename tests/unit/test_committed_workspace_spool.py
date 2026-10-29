# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace scan's spool is refused when committed and never written through.

A workspace scan spools each project's SARIF run to
``<output>/.workspace-spool/<key>.run.json`` and removes the directory when it
writes the unified results. A committed entry under ``.workspace-spool`` stops
the scan before anything is written or removed, and the spool is written without
following links: a link at a spool name or at the directory's name is replaced,
never written through.

A committed entry anywhere under ``.workspace-spool`` stops the workspace at
each entry point that checks the others (the CLI, locally and in container mode,
and the MCP workspace tool) before anything is written or removed. And the spool
is written without following links: a link at the directory's name is replaced by
a directory, and each spool file replaces whatever is at its name. The red run of
these tests did the writes they guard against, so every path is under
``tmp_path``.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions import run_ash_scan as run_ash_scan_module
from automated_security_helper.interactions.run_ash_scan import run_ash_scan
from automated_security_helper.utils.subprocess_utils import create_completed_process
from automated_security_helper.workspace.aggregation import WorkspaceAggregator
from tests.unit.test_committed_output_refused_at_entry_points import (
    _execute_with_a_fake_orchestrator,
    _isolate_git,
    _workspace_plan,
)
from tests.unit.test_committed_results_paths_are_never_deleted import (
    _confined,
    _entries,
)
from tests.unit.workspace.test_execution import _git
from tests.unit.workspace.test_workspace_reporting import _outcome, _plan, _run

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)

SPOOL = ".workspace-spool"


def _outside(tmp_path: Path) -> Path:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "target.json").write_text("outside the repository\n", encoding="utf-8")
    return outside


def _committed_spool(
    tmp_path: Path, monkeypatch, layout: str
) -> Tuple[Path, Path, Path]:
    """A git repository whose default output directory has a committed spool.

    ``inside``: a committed file under the spool, and a committed link at the
    spool name of the workspace's one project, ``api``, pointing outside.
    ``the-directory``: the spool directory itself committed as a link to a
    directory outside.
    """
    _isolate_git(monkeypatch, tmp_path)
    outside = _outside(tmp_path)
    source = tmp_path / "repo"
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    if layout == "inside":
        (output / SPOOL).mkdir()
        (output / SPOOL / "notes.txt").write_text("committed notes\n", encoding="utf-8")
        (output / SPOOL / "api.run.json").symlink_to(outside / "target.json")
        committed = [f"{SPOOL}/notes.txt", f"{SPOOL}/api.run.json"]
    else:
        (output / SPOOL).symlink_to(outside, target_is_directory=True)
        committed = [SPOOL]
    assert _git(source, "init", "-q").returncode == 0
    paths = [f".ash/ash_output/{name}" for name in committed]
    assert _git(source, "add", "app.py", *paths).returncode == 0
    staged = _git(source, "ls-files", "-s", "--", *paths).stdout.splitlines()
    # A control: git tracks each entry, a link as a link.
    assert len(staged) == len(committed), staged
    assert any(line.startswith("120000 ") for line in staged), staged
    monkeypatch.chdir(tmp_path)
    return source, output, outside


LAYOUTS = ["inside", "the-directory"]


@pytest.mark.integration
@pytest.mark.parametrize("mode", [RunMode.local, RunMode.container])
@pytest.mark.parametrize("layout", LAYOUTS)
def test_a_cli_workspace_scan_stops_before_it_touches_a_committed_spool(
    tmp_path, monkeypatch, capsys, layout, mode
):
    source, output, outside = _committed_spool(tmp_path, monkeypatch, layout)
    plan = _workspace_plan(source)
    _confined(tmp_path, source, output, outside)
    before, outside_before = _entries(output), _entries(outside)
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

    assert _entries(outside) == outside_before, "a spool file was written outside"
    assert _entries(output) == before, "a committed spool entry was changed"
    assert executed == [] and started == [], "the workspace was scanned"
    assert exit_code == 3
    assert SPOOL in capsys.readouterr().out.replace("\n", "")


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.parametrize("layout", LAYOUTS)
async def test_the_mcp_workspace_tool_refuses_a_committed_spool(
    tmp_path, monkeypatch, layout
):
    from automated_security_helper.cli.mcp.workspace import mcp_scan_workspace
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    monkeypatch.setattr(
        scan_registry_module, "_scan_registry", scan_registry_module.ScanRegistry()
    )
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    source, output, outside = _committed_spool(tmp_path, monkeypatch, layout)
    plan = _workspace_plan(source)
    _confined(tmp_path, source, output, outside)
    before, outside_before = _entries(output), _entries(outside)
    executed = _execute_with_a_fake_orchestrator(monkeypatch)

    result = await mcp_scan_workspace(workspace_file=plan.workspace_file)

    assert _entries(outside) == outside_before, "a spool file was written outside"
    assert _entries(output) == before, "a committed spool entry was changed"
    assert executed == [], "the workspace was scanned"
    assert result["success"] is False, result
    assert result["exit_code"] == 3, result
    assert SPOOL in result["error"], result


# ---------------------------------------------------------------------------
# Links git does not track: nothing stops the run, and nothing follows them.
# ---------------------------------------------------------------------------


def _aggregator(tmp_path: Path) -> Tuple[WorkspaceAggregator, Path]:
    output = tmp_path / "out"
    output.mkdir()
    plan = _plan(tmp_path / "ws", "api")
    return WorkspaceAggregator(plan=plan, output_dir=output), output


def _spool_one_project(aggregator: WorkspaceAggregator) -> Dict[str, object]:
    project = aggregator.plan.projects[0]
    run = _run(project.key, rule="RULE-API", uri="src/a.py")
    aggregator.add(_outcome(project), run, project)
    return run


@pytest.mark.unit
def test_a_link_at_the_spool_directory_is_replaced_not_written_through(tmp_path):
    outside = _outside(tmp_path)
    aggregator, output = _aggregator(tmp_path)
    (output / SPOOL).symlink_to(outside, target_is_directory=True)
    outside_before = _entries(outside)

    _spool_one_project(aggregator)

    assert _entries(outside) == outside_before, "the run was spooled outside"
    assert not (output / SPOOL).is_symlink()
    assert sorted(p.name for p in (output / SPOOL).iterdir()) == ["api.run.json"]

    results = aggregator.write(exit_code=2, wall_clock_seconds=1.0)

    assert _entries(outside) == outside_before
    assert not os.path.lexists(output / SPOOL), "the spool was left behind"
    runs = json.loads(results.read_text(encoding="utf-8"))["sarif"]["runs"]
    assert [run["results"][0]["ruleId"] for run in runs] == ["RULE-API"]


@pytest.mark.unit
@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_a_junction_at_the_spool_name_is_replaced_not_written_through(
    tmp_path, monkeypatch
):
    """A Windows junction's lstat reads as a directory, with the reparse-point
    attribute and a name-surrogate tag (IO_REPARSE_TAG_MOUNT_POINT), and
    ``Path.is_symlink()`` is False for it, so the spool code reads the reparse
    tag and replaces a junction rather than writing through it. Modeled with a
    symlink whose lstat reads as such a junction until it is unlinked; the spool
    must be unlinked, then made."""
    outside = _outside(tmp_path)
    aggregator, output = _aggregator(tmp_path)
    spool = output / SPOOL
    spool.symlink_to(outside, target_is_directory=True)
    outside_before = _entries(outside)

    class JunctionStat:
        st_mode = stat.S_IFDIR | 0o755
        st_file_attributes = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT
        st_reparse_tag = 0xA0000003  # IO_REPARSE_TAG_MOUNT_POINT

    present = [True]
    calls: List[str] = []
    real_lstat, real_unlink, real_mkdir = os.lstat, Path.unlink, Path.mkdir

    def lstat(path, *args, **kwargs):
        if present[0] and os.fspath(path) == os.fspath(spool):
            return JunctionStat()
        return real_lstat(path, *args, **kwargs)

    def unlink(self, *args, **kwargs):
        if self == spool:
            calls.append("unlink")
            present[0] = False
        return real_unlink(self, *args, **kwargs)

    def mkdir(self, *args, **kwargs):
        if self == spool:
            calls.append("mkdir")
        return real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(Path, "is_symlink", lambda self: False)
    monkeypatch.setattr(Path, "unlink", unlink)
    monkeypatch.setattr(Path, "mkdir", mkdir)

    _spool_one_project(aggregator)

    monkeypatch.undo()
    assert calls[:2] == ["unlink", "mkdir"], calls
    assert _entries(outside) == outside_before, "the run was spooled outside"
    assert not os.path.islink(spool)
    assert sorted(p.name for p in spool.iterdir()) == ["api.run.json"]


@pytest.mark.unit
def test_a_link_at_a_spool_file_is_replaced_not_written_through(tmp_path):
    """A link at a spool file's name is refused, not written through and not
    replaced: the spool is written with ``fs_guard.open_for_atomic_write`` below
    the workspace output directory (workspace/aggregation.WorkspaceAggregator.add),
    which refuses a link at the name. The link and its target are left as they
    were."""
    from automated_security_helper.utils.sandbox.fs_guard import OutputLinkRefused

    outside = _outside(tmp_path)
    aggregator, output = _aggregator(tmp_path)
    (output / SPOOL).mkdir()
    (output / SPOOL / "api.run.json").symlink_to(outside / "target.json")
    outside_before = _entries(outside)

    with pytest.raises(OutputLinkRefused, match="symlink"):
        _spool_one_project(aggregator)

    assert _entries(outside) == outside_before, "the run was written into the target"
    spooled = output / SPOOL / "api.run.json"
    assert spooled.is_symlink()
    assert sorted(p.name for p in (output / SPOOL).iterdir()) == ["api.run.json"]
