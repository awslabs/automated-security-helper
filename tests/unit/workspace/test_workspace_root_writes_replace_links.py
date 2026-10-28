# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace scan's root output replaces a link at its name, never writes through it.

Writing the unified ``ash_aggregated_results.json`` with ``open(target, "w")``,
or the workspace reports and their manifest with ``write_text``, would follow a
link at that name: a link committed at
``.ash/ash_output/ash_aggregated_results.json`` would have the workspace aggregate
written into its target, outside the repository. Each is written to a staging file
beside it and renamed over the name, so a link there is replaced by the file and
its target is left as it was. (A committed link there stops the scan before it
starts; these tests use a link git does not track, which nothing stops.)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from automated_security_helper.workspace.aggregation import WorkspaceAggregator
from automated_security_helper.workspace.reporting import emit_workspace_reports
from tests.unit.workspace.test_workspace_reporting import (
    FakeMergedReporter,
    _outcome,
    _plan,
    _run,
)

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


def _outside(tmp_path: Path, name: str) -> Path:
    target = tmp_path / "outside" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("outside the output directory\n", encoding="utf-8")
    return target


def _link(path: Path, target: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        path.unlink()
    path.symlink_to(target)


def _aggregate(tmp_path: Path, output_dir: Path):
    plan = _plan(tmp_path / "ws", "api")
    aggregator = WorkspaceAggregator(plan=plan, output_dir=output_dir)
    project = plan.projects[0]
    aggregator.add(
        _outcome(project), _run(project.key, rule="RULE-API", uri="src/a.py"), project
    )
    return plan, aggregator


def test_the_unified_results_file_replaces_a_link_at_its_name(tmp_path):
    output_dir = tmp_path / "out"
    target = _outside(tmp_path, "results.json")
    link = output_dir / "ash_aggregated_results.json"
    _link(link, target)
    _, aggregator = _aggregate(tmp_path, output_dir)

    written = aggregator.write(exit_code=2, wall_clock_seconds=1.0)

    assert target.read_text(encoding="utf-8") == "outside the output directory\n"
    assert written == link
    assert not link.is_symlink()
    parsed = json.loads(link.read_text(encoding="utf-8"))
    assert parsed["workspace"]["exit_code"] == 2
    assert [p.name for p in output_dir.iterdir()] == ["ash_aggregated_results.json"]


def test_the_workspace_reports_and_manifest_replace_a_link_at_their_names(tmp_path):
    output_dir = tmp_path / "out"
    plan, aggregator = _aggregate(tmp_path, output_dir)
    results_path = aggregator.write(exit_code=2, wall_clock_seconds=1.0)
    first = emit_workspace_reports(
        plan=plan,
        output_dir=output_dir,
        results_path=results_path,
        reporter_classes=[FakeMergedReporter],
    )
    artifact = first.workspace_artifacts["fake-merged"]
    written = {
        artifact: artifact.read_text(encoding="utf-8"),
        first.manifest_path: first.manifest_path.read_text(encoding="utf-8"),
    }
    targets = {}
    for path in written:
        targets[path] = _outside(tmp_path, path.name)
        _link(path, targets[path])

    emit_workspace_reports(
        plan=plan,
        output_dir=output_dir,
        results_path=results_path,
        reporter_classes=[FakeMergedReporter],
    )

    for path, text in written.items():
        assert targets[path].read_text(encoding="utf-8") == (
            "outside the output directory\n"
        ), path
        assert not path.is_symlink(), path
        assert path.read_text(encoding="utf-8") == text, path
    leftovers = sorted(p.name for p in artifact.parent.iterdir() if p not in written)
    assert leftovers == [], leftovers
