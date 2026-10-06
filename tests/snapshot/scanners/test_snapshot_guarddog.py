# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What a user sees when the opt-in GuardDog scanner is enabled.

The scan runs the real GuardDogScanner through the real ScanPhase and ReportPhase
over the inert fixture packages in tests/test_data/scanners/guarddog/fixture_repo.
GuardDog itself is replaced by the output it printed for those packages at the
pinned version (tests/test_data/scanners/guarddog/captured), so the snapshot does
not depend on the tool being installed; tests/integration/scanners/
test_guarddog_scanner.py checks that the real tool still prints the same findings.

A disabled GuardDog leaves no trace in a default scan. That direction is pinned by
the existing default-scan snapshots, which do not change when GuardDog is added,
and by tests/unit/core/phases/test_scan_phase_opt_in_scanners.py.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.guarddog_scanner import (
    GuardDogScanner,
)

# This module is written against the snapshot suite from #717 (tests/snapshot/conftest.py
# and tests/snapshot/support/). On a tree without that suite there is nothing for it to
# run against; once the suite is present, any failure here is a real failure.
if not (Path(__file__).resolve().parents[1] / "conftest.py").exists():
    pytest.skip(
        "needs the snapshot suite from #717 (tests/snapshot/conftest.py)",
        allow_module_level=True,
    )

pytestmark = pytest.mark.snapshot_masking(mask_instants=True, mask_durations=True)

DATA = Path(__file__).resolve().parents[2] / "test_data" / "scanners" / "guarddog"
FIXTURE_REPO = DATA / "fixture_repo"
CAPTURED = DATA / "captured"

CAPTURE_FOR = {
    ("pypi", "pypi_suspicious"): "scan_pypi_pypi_suspicious.json",
    ("pypi", "pypi_clean"): "scan_pypi_pypi_clean.json",
    ("npm", "npm_suspicious"): "scan_npm_npm_suspicious.json",
    ("npm", "npm_clean"): "scan_npm_npm_clean.json",
    ("go", "go_suspicious"): "scan_go_go_suspicious.json",
    ("github_action", "action_suspicious"): "scan_github_action_action_suspicious.json",
    ("rubygems", "gem_suspicious"): "scan_rubygems_gem_suspicious.json",
    ("crates", "crate_suspicious"): "scan_crates_crate_suspicious.json",
}


def _tree(root: Path) -> frozenset:
    return frozenset(
        (p.relative_to(root).as_posix(), p.read_bytes())
        for p in root.rglob("*")
        if p.is_file()
    )


class _CapturedGuardDog:
    """Answers each GuardDog invocation with the capture for the staged package."""

    def __init__(self) -> None:
        self.packages = {pkg.name: _tree(pkg) for pkg in FIXTURE_REPO.iterdir()}

    def __call__(self, scanner: GuardDogScanner, **kw: Any) -> Dict[str, Any]:
        command: List[str] = kw["command"]
        staged = _tree(Path(command[3]))
        name = next(n for n, files in self.packages.items() if files == staged)
        stdout = (CAPTURED / CAPTURE_FOR[(command[1], name)]).read_text()
        (Path(kw["results_dir"]) / "GuardDogScanner.stdout.log").write_text(stdout)
        return {"returncode": 0}


@pytest.fixture
def guarddog_run(tmp_path, monkeypatch):
    fake = _CapturedGuardDog()
    monkeypatch.setattr(
        GuardDogScanner, "_run_subprocess", lambda self, **kw: fake(self, **kw)
    )
    monkeypatch.setattr(
        GuardDogScanner, "validate_plugin_dependencies", lambda self: True
    )
    monkeypatch.setattr(
        GuardDogScanner, "_get_uv_tool_version", lambda self, name: "3.2.0"
    )

    source = tmp_path / "src"
    shutil.copytree(FIXTURE_REPO, source)
    out = tmp_path / "out"
    out.mkdir()
    config = get_default_config()
    config.scanners.guarddog.enabled = True
    context = PluginContext(
        source_dir=source, output_dir=out, work_dir=out / "converted", config=config
    )
    aggregated = AshAggregatedResults()
    results = ScanPhase(
        plugin_context=context,
        plugins=[GuardDogScanner],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )._execute_phase(aggregated_results=aggregated, parallel=False)
    results = populate_metrics_from_unified_source(aggregated_results=results)
    return context, results


def test_guarddog_findings(guarddog_run, snapshot):
    _, results = guarddog_run
    rows = []
    for result in results.sarif.runs[0].results:
        location = result.locations[0].physicalLocation.root
        rows.append(
            {
                "rule": result.ruleId,
                "level": getattr(result.level, "value", result.level),
                "severity": result.properties.issue_severity,
                "uri": location.artifactLocation.uri,
                "line": location.region.startLine if location.region else None,
                "message": result.message.root.text,
            }
        )
    assert rows, "the GuardDog run produced no findings to snapshot"
    assert sorted(rows, key=lambda r: (r["uri"], r["line"], r["rule"])) == snapshot


@pytest.mark.parametrize(
    "reporter_cls,extension",
    [(TextReporter, "txt"), (MarkdownReporter, "md")],
)
def test_guarddog_summary_reports(guarddog_run, text_snapshot, reporter_cls, extension):
    context, results = guarddog_run
    reports = context.output_dir / "reports"
    ReportPhase(
        plugins=[reporter_cls],
        plugin_context=context,
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=results,
    ).execute(
        report_dir=reports,
        cli_output_formats=None,
        aggregated_results=results,
        python_based_plugins_only=False,
    )
    written = sorted(reports.glob(f"*.{extension}"))
    assert len(written) == 1, written
    assert written[0].read_text(encoding="utf-8") == text_snapshot(extension)
