# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace scan names every project's inputs that a scanner did not scan.

A single-directory scan lists them (``ScanResultsContainer.inputs_not_scanned``,
read by ``unified_metrics.inputs_not_scanned``) in ash.summary.md, the text summary
and the console: an offline npm-audit names each lockfile it could not audit,
because its MISSING row cannot say which. The workspace's unified results file
carried no per-target reports (``additional_reports`` is ``{}`` there), so the
merged summaries and the workspace console said nothing about them, and nor did
the ``workspace`` block. Each project's list now travels on its entry, with paths
made workspace-relative, and every one of the three surfaces reads it.

The console line for such a project said ``pass`` too, while the run exited 1.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.workspace.execution import execute_workspace
from tests.unit.workspace.test_execution import _make_workspace, _sarif, _settings

pytestmark = pytest.mark.unit

REASON = "ASH is running offline, and npm audit asks the registry"


class _Orchestrator:
    """A project scan that ran bandit and could not run npm-audit on its lockfiles."""

    not_scanned: Dict[str, List[str]] = {}

    def __init__(self, **kwargs: Any) -> None:
        self.key = Path(kwargs["source_dir"]).name

    @classmethod
    def create(cls, **kwargs: Any) -> "_Orchestrator":
        return cls(**kwargs)

    def execute_scan(self, phases=None):
        from automated_security_helper.models.asharp_model import (
            AshAggregatedResults,
            ScannerTargetStatusInfo,
        )
        from automated_security_helper.schemas.sarif_schema_model import SarifReport

        model = AshAggregatedResults()
        model.sarif = SarifReport.model_validate(_sarif(count=0))
        model.scanner_results["bandit"] = ScannerTargetStatusInfo(
            status="PASSED", excluded=False, dependencies_satisfied=True
        )
        paths = self.not_scanned.get(self.key)
        if paths:
            model.scanner_results["npm-audit"] = ScannerTargetStatusInfo(
                status="MISSING", excluded=False, dependencies_satisfied=False
            )
            model.additional_reports = {
                "npm-audit": {
                    "source": {
                        "scanner_name": "npm-audit",
                        "inputs_not_scanned": [
                            {"path": path, "reason": REASON} for path in paths
                        ],
                    }
                }
            }
        return model


@pytest.fixture
def scanned(tmp_path):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))
    _Orchestrator.not_scanned = {
        "web": ["package-lock.json", "admin/yarn.lock"],
    }
    try:
        result = execute_workspace(
            plan,
            _settings(tmp_path),
            orchestrator_factory=_Orchestrator.create,
        )
    finally:
        _Orchestrator.not_scanned = {}
    return result


EXPECTED = [
    ("npm-audit", "web/package-lock.json", REASON),
    ("npm-audit", "web/admin/yarn.lock", REASON),
]


def _entries(project) -> List[tuple]:
    return [
        (item["scanner"], item["path"], item["reason"])
        for item in project.get("inputs_not_scanned", [])
    ]


def test_each_project_entry_names_its_inputs_with_workspace_paths(scanned):
    projects = {
        project.project: project.model_dump(mode="json")
        for project in scanned.payload.projects
    }
    assert _entries(projects["web"]) == EXPECTED
    assert _entries(projects["api"]) == []


def test_the_unified_results_file_carries_them(scanned):
    document = json.loads(scanned.results_path.read_text(encoding="utf-8"))
    projects = {p["project"]: p for p in document["workspace"]["projects"]}
    assert _entries(projects["web"]) == EXPECTED


def test_the_unified_metrics_read_them_off_the_workspace_model(scanned):
    from automated_security_helper.core.unified_metrics import inputs_not_scanned
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    model = AshAggregatedResults.model_validate_json(
        scanned.results_path.read_text(encoding="utf-8")
    )
    assert inputs_not_scanned(model) == EXPECTED


def test_the_merged_summaries_list_them(scanned, test_plugin_context):
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
        MarkdownReporter,
    )
    from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
        TextReporter,
    )

    model = AshAggregatedResults.model_validate_json(
        scanned.results_path.read_text(encoding="utf-8")
    )
    markdown = MarkdownReporter(context=test_plugin_context).report(model)
    text = TextReporter(context=test_plugin_context).report(model)
    for path in ("web/package-lock.json", "web/admin/yarn.lock"):
        assert path in markdown, markdown
        assert path in text, text


def test_the_workspace_console_lists_them_and_does_not_say_pass(
    scanned, tmp_path, monkeypatch
):
    from automated_security_helper.interactions import run_ash_scan as ras
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _print_workspace_summary,
    )
    from tests.snapshot.console.console_inputs import (
        recording_console,
        rendered,
        route_rich_print,
    )

    console = recording_console(200, soft_wrap=True)
    route_rich_print(monkeypatch, console)
    opts = ScanOptions(source_dir=tmp_path / "workspace", output_dir=tmp_path / "out")
    _print_workspace_summary(scanned, opts, ras.time.time())
    output = rendered(console)

    for scanner, path, reason in EXPECTED:
        assert f"Not scanned: {scanner} did not scan {path}: {reason}" in output
    web = [line for line in output.splitlines() if " web " in f" {line} "]
    assert web and all("pass" not in line for line in web), output
    assert any("incomplete" in line.lower() for line in web), output


def test_the_console_escapes_a_path_from_the_scanned_tree(tmp_path, monkeypatch):
    """The input's path is the repository's; it must not start a line of its own."""
    from automated_security_helper.interactions import run_ash_scan as ras
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _print_workspace_summary,
    )
    from tests.snapshot.console.console_inputs import (
        recording_console,
        rendered,
        route_rich_print,
    )

    _, plan = _make_workspace(tmp_path, ("web", "MEDIUM"))
    _Orchestrator.not_scanned = {"web": ["evil\n[bold]x[/bold]/package-lock.json"]}
    try:
        result = execute_workspace(
            plan, _settings(tmp_path), orchestrator_factory=_Orchestrator.create
        )
    finally:
        _Orchestrator.not_scanned = {}
    console = recording_console(200, soft_wrap=True)
    route_rich_print(monkeypatch, console)
    opts = ScanOptions(source_dir=tmp_path / "workspace", output_dir=tmp_path / "out")
    _print_workspace_summary(result, opts, ras.time.time())
    output = rendered(console)

    # The newline is written as the console's escape (``\x0a``), the markup shown as text.
    assert "web/evil\\x0a[bold]x[/bold]/package-lock.json" in output, output


def test_a_projects_scan_set_drops_are_listed_as_ashs(tmp_path):
    """The files a project's scan set left out travel on its entry, as ASH's."""
    from automated_security_helper.models.asharp_model import (
        AshAggregatedResults,
        InputNotScanned,
    )
    from automated_security_helper.workspace.aggregation import (
        inputs_not_scanned_for_project,
    )

    results = AshAggregatedResults()
    results.metadata.inputs_not_scanned = [
        InputNotScanned(path="lib/x.py", reason="link leaves the scanned tree")
    ]

    entries = inputs_not_scanned_for_project(results, "api")

    assert [(e.scanner, e.path, e.reason) for e in entries] == [
        ("ASH", "api/lib/x.py", "link leaves the scanned tree")
    ]
