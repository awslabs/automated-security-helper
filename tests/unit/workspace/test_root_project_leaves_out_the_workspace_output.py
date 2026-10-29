# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace project at the workspace root does not scan the workspace's output.

A workspace scan writes each project's output to ``<output>/projects/<key>/``, and
its unified results and reports to ``<output>`` itself. Each project is scanned by
an orchestrator of its own, whose output directory is the project's. For a project
at the workspace root, with the workspace's output directory inside it (the default
``.ash/ash_output``, or ``--output-dir ws-out``), naming only the project's own
directory as ASH's output would leave the scan set holding
``ws-out/ash_aggregated_results.json`` and ``ws-out/projects/api/reports/ash.html``,
a sibling project's report from the same run. The workspace's output directory
goes with each project's orchestrator to its plugins' context
(``workspace_output_dir``) and is named like this run's output directory.

Every path here is under ``tmp_path``.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.scan_output_dirs import (
    named_output_dirs,
    output_dirs_to_exclude,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.usefixtures("no_checkout_above_tmp_path"),
]


def _workspace(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A root project holding the workspace's output, with a sibling's report."""
    root = tmp_path / "workspace"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    workspace_output = root / "ws-out"
    project_output = workspace_output / "projects" / "root"
    project_output.mkdir(parents=True)
    (workspace_output / "ash_aggregated_results.json").write_text(
        "{}\n", encoding="utf-8"
    )
    sibling_report = workspace_output / "projects" / "api" / "reports" / "ash.html"
    sibling_report.parent.mkdir(parents=True)
    sibling_report.write_text("<html/>\n", encoding="utf-8")
    return root, workspace_output, project_output


def test_the_workspace_output_dir_is_named_for_a_root_project(tmp_path):
    root, workspace_output, project_output = _workspace(tmp_path)

    named = named_output_dirs(
        root, project_output, workspace_output_dir=workspace_output
    )

    assert named == [workspace_output], named
    assert output_dirs_to_exclude(
        root, project_output, workspace_output_dir=workspace_output
    ) == [workspace_output]


def test_a_root_projects_scan_set_holds_none_of_the_workspace_output(
    tmp_path, monkeypatch
):
    root, workspace_output, project_output = _workspace(tmp_path)
    monkeypatch.chdir(tmp_path)

    files = scan_set(
        source=str(root),
        output=str(project_output),
        workspace_output_dir=str(workspace_output),
    )

    relative = sorted(Path(os.path.relpath(f, root)).as_posix() for f in files)
    assert relative == ["src/app.py"], relative


def test_each_projects_orchestrator_is_given_the_workspace_output_dir(tmp_path):
    from tests.unit.workspace.test_execution import (
        FakeOrchestrator,
        _make_workspace,
        _run,
    )

    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))

    _run(tmp_path, plan)

    given = {
        o.key: o.kwargs.get("workspace_output_dir") for o in FakeOrchestrator.built
    }
    assert given == {"api": tmp_path / "out", "web": tmp_path / "out"}, given


def test_the_orchestrator_hands_it_to_the_plugins_context(tmp_path, monkeypatch):
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    root, workspace_output, project_output = _workspace(tmp_path)
    monkeypatch.chdir(tmp_path)
    orchestrator = ASHScanOrchestrator(
        source_dir=root,
        output_dir=project_output,
        workspace_output_dir=workspace_output,
        config_path=None,
        config_overrides=None,
        no_cleanup=False,
        metadata=None,
        ash_plugin_modules=[],
    )
    engine = MagicMock()
    with (
        patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=AshConfig(project_name="test"),
        ),
        patch(
            "automated_security_helper.core.orchestrator.ScanExecutionEngine",
            engine,
        ),
    ):
        orchestrator.initialize()

    context = engine.call_args.kwargs["context"]
    assert context.workspace_output_dir == workspace_output
    relative = sorted(
        Path(os.path.relpath(f, root)).as_posix()
        for f in orchestrator.scan_set_for_this_run()
    )
    assert relative == ["src/app.py"], relative
