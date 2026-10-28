# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash scan`` deletes the previous results when it starts; only MCP scans keep them.

Why this file exists
--------------------
Keeping the previous scan's results until a new scan has its own is right over MCP
and wrong for the CLI. A crashed or interrupted ``ash scan`` would leave an output
directory holding a complete, parseable earlier run with a marker file beside it
that only the MCP server reads. Anything else that reads the directory, a CI
publish step or the container and Nix wrappers' read-back, would take those files
for the run that just failed, and the container host could exit 0 on them.

So the previous results are kept only over MCP, where the server
records on the scan's registry entry that the files are not that scan's and its
tools say so. The orchestrator keeps them only when asked
(``keep_previous_results``); the CLI and the CLI workspace scan do not ask, and
delete them at the start.

Deleting at the start also removes what a kept set leaves behind: the held set
(``.ash_previous_results``), its staging directory and the restored-results
marker. A held set left by a killed MCP scan is the last complete results only
to the MCP server; if a CLI scan ran after it and left it, the next MCP scan
would take it for the last complete set and remove the CLI scan's newer results.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict
from unittest.mock import patch

import pytest

from automated_security_helper.core.previous_results import (
    HELD_DIR_NAME,
    RESTORED_MARKER_NAME,
    PreviousResults,
    holds_restored_results,
)

PREVIOUS = {
    "reports/ash.sarif": '{"previous": "sarif"}',
    "reports/ash.summary.md": "# previous summary\n",
    "scanners/bandit/source/ASH.ScanResults.json": '{"status": "PASSED"}',
    "ash_aggregated_results.json": '{"previous": "results"}',
    "ash-scan-set-files-list.txt": "previous/file.py\n",
}

_ENGINE = (
    "automated_security_helper.core.execution_engine.ScanExecutionEngine.execute_phases"
)


def _seed(root: Path, files: Dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def _project(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "project"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = source / ".ash" / "ash_output"
    _seed(output, PREVIOUS)
    return source, output


def _contents(output: Path) -> Dict[str, str]:
    return {
        p.relative_to(output).as_posix(): p.read_text(encoding="utf-8")
        for p in sorted(output.rglob("*"))
        if p.is_file() and not p.name.startswith("ash.log")
    }


def _surviving(output: Path) -> set:
    """The previous files still there with their previous content.

    By content, because the new scan writes some of the same names (its own
    ash-scan-set-files-list.txt, for one) before it fails.
    """
    return {k for k, v in _contents(output).items() if PREVIOUS.get(k) == v}


def _plant_a_kept_set(output: Path) -> None:
    """What a killed MCP scan, and a restore, leave in the directory."""
    _seed(output / HELD_DIR_NAME, {"ash_aggregated_results.json": '{"held": 1}'})
    _seed(output / (HELD_DIR_NAME + ".partial"), {"reports/x.sarif": "{}"})
    (output / RESTORED_MARKER_NAME).write_text("restored\n", encoding="utf-8")


def _orchestrator(source: Path, output: Path, **kwargs):
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    return ASHScanOrchestrator.create(
        source_dir=source,
        output_dir=output,
        show_progress=False,
        show_summary=False,
        **kwargs,
    )


def test_the_orchestrator_deletes_them_unless_asked_to_keep_them(tmp_path):
    source, output = _project(tmp_path)

    _orchestrator(source, output)

    assert not _surviving(output), sorted(_surviving(output))
    assert not (output / HELD_DIR_NAME).exists()


def test_a_failed_cli_scan_leaves_none_of_them_and_no_marker(tmp_path):
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    source, output = _project(tmp_path)
    with patch(_ENGINE, side_effect=RuntimeError("scanner orchestration crashed")):
        with pytest.raises(SystemExit) as exited:
            run_ash_scan(
                source_dir=str(source),
                output_dir=str(output),
                progress=False,
                show_summary=False,
                quiet=True,
            )

    assert exited.value.code == 1
    assert not _surviving(output), sorted(_surviving(output))
    assert not holds_restored_results(output)
    assert not (output / HELD_DIR_NAME).exists()


def test_an_interrupted_cli_scan_leaves_none_of_them(tmp_path):
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    source, output = _project(tmp_path)
    with patch(_ENGINE, side_effect=KeyboardInterrupt()):
        with pytest.raises(BaseException):
            run_ash_scan(
                source_dir=str(source),
                output_dir=str(output),
                progress=False,
                show_summary=False,
                quiet=True,
            )

    assert not _surviving(output), sorted(_surviving(output))
    assert not holds_restored_results(output)


def test_a_cli_scan_removes_what_a_kept_set_left_behind(tmp_path):
    source, output = _project(tmp_path)
    _plant_a_kept_set(output)

    _orchestrator(source, output)

    assert not (output / HELD_DIR_NAME).exists()
    assert not (output / (HELD_DIR_NAME + ".partial")).exists()
    assert not holds_restored_results(output)


def test_the_next_mcp_scan_keeps_a_cli_scans_results_not_an_older_held_set(tmp_path):
    """The failure the removal prevents: a CLI scan's results lost to a stale held set."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    source, output = _project(tmp_path)
    _plant_a_kept_set(output)

    def cli_phases(*args, **kwargs):
        _seed(output, {"reports/ash.sarif": '{"cli": "run"}'})
        return AshAggregatedResults()

    with patch(_ENGINE, side_effect=cli_phases):
        _orchestrator(source, output).execute_scan()

    with patch(_ENGINE, side_effect=RuntimeError("the MCP scan fails")):
        with pytest.raises(Exception, match="the MCP scan fails"):
            _orchestrator(source, output, keep_previous_results=True).execute_scan()

    assert _contents(output)["reports/ash.sarif"] == '{"cli": "run"}'


def test_the_cli_workspace_scan_settings_default_to_deleting_them(tmp_path):
    from automated_security_helper.workspace.execution import ProjectScanSettings

    assert ProjectScanSettings(output_dir=tmp_path).keep_previous_results is False


@pytest.mark.asyncio
async def test_the_mcp_workspace_scan_asks_its_projects_to_keep_them(
    tmp_path, monkeypatch
):
    import json

    from automated_security_helper.cli.mcp import workspace as workspace_module
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    monkeypatch.setattr(
        scan_registry_module, "_scan_registry", scan_registry_module.ScanRegistry()
    )
    root = tmp_path / "work"
    (root / "api").mkdir(parents=True)
    (root / "api" / "app.py").write_text("x = 1\n", encoding="utf-8")
    workspace_file = root / "dev.code-workspace"
    workspace_file.write_text(
        json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8"
    )
    seen = {}

    def execute_workspace(plan, settings, **kwargs):
        seen["keep"] = settings.keep_previous_results
        raise RuntimeError("stop here")

    monkeypatch.setattr(workspace_module, "execute_workspace", execute_workspace)
    await workspace_module.mcp_scan_workspace(
        workspace_file=str(workspace_file), output_dir=str(tmp_path / "out")
    )

    assert seen == {"keep": True}


@pytest.mark.parametrize("keep", [False, True])
def test_each_project_orchestrator_is_told_whether_to_keep_them(tmp_path, keep):
    """execute_workspace passes the setting on, so the CLI's False reaches the scan."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.workspace.execution import (
        ProjectScanSettings,
        execute_workspace,
    )
    from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

    root = tmp_path / "workspace"
    (root / "api").mkdir(parents=True)
    (root / "api" / "app.py").write_text("x = 1\n", encoding="utf-8")
    workspace_file = root / "dev.code-workspace"
    workspace_file.write_text('{"folders": [{"path": "api"}]}', encoding="utf-8")
    plan = WorkspacePlan(
        workspace_file=workspace_file.as_posix(),
        workspace_root=root.as_posix(),
        projects=[
            ProjectPlan(
                key="api",
                relative_path="api",
                path=(root / "api").as_posix(),
                label="api",
                display_label="api",
                severity_threshold="MEDIUM",
            )
        ],
    )
    told = []

    class Recording:
        def __init__(self, **kwargs):
            told.append(kwargs.get("keep_previous_results"))

        def execute_scan(self, phases=None):
            return AshAggregatedResults()

    execute_workspace(
        plan,
        ProjectScanSettings(
            output_dir=tmp_path / "out", phases=("scan",), keep_previous_results=keep
        ),
        orchestrator_factory=lambda **kwargs: Recording(**kwargs),
    )

    assert told == [keep]


def test_held_set_removal_never_follows_a_link(tmp_path):
    outside = tmp_path / "outside"
    _seed(outside, {"keep.txt": "outside data"})
    output = tmp_path / "out"
    output.mkdir()
    (output / HELD_DIR_NAME).symlink_to(outside, target_is_directory=True)
    (output / (HELD_DIR_NAME + ".partial")).symlink_to(
        outside, target_is_directory=True
    )
    (output / RESTORED_MARKER_NAME).symlink_to(outside / "keep.txt")

    PreviousResults(output).discard()

    assert (outside / "keep.txt").read_text(encoding="utf-8") == "outside data"
    assert not any(p.is_symlink() for p in output.iterdir())
