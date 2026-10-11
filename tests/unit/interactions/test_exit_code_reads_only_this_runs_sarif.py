# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The exit code counts ``reports/ash.sarif`` only when this run wrote it.

``_compute_exit_code`` counts actionable findings from ``reports/ash.sarif``, which
records every suppression, in preference to the model. ``--use-existing`` keeps
``reports/``, so with no SARIF reporter selected the file there is an earlier
run's, and it used to decide the exit code. The report phase records the report
files it wrote (a ``reports_written`` validation checkpoint), and the file is
counted only when that record lists it. A model with no such record is counted
as before.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, Optional

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _compute_exit_code,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults

#: A SARIF report with no findings: an earlier run's, of a clean tree.
CLEAN_SARIF = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "ASH"}}}]}


class _OtherConfig(ReporterPluginConfigBase):
    name: Literal["other-format"] = "other-format"
    extension: str = "other.json"
    enabled: bool = True


class _OtherReporter(ReporterPluginBase[_OtherConfig]):
    """A reporter that is not the SARIF reporter."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = _OtherConfig()
        return super().model_post_init(context)

    def report(self, model) -> Optional[str]:
        return "{}"


def _report(output_dir: Path, results: AshAggregatedResults, *reporters):
    return ReportPhase(
        plugins=list(reporters),
        plugin_context=PluginContext(
            source_dir=output_dir.parent / "src",
            output_dir=output_dir,
            config=AshConfig(),
        ),
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=results,
    ).execute(
        report_dir=output_dir / "reports",
        aggregated_results=results,
        cli_output_formats=None,
        python_based_plugins_only=False,
    )


def _opts(tmp_path: Path) -> ScanOptions:
    return ScanOptions(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        fail_on_findings=True,
        fail_on_incomplete_scanners=False,
    )


def _earlier_runs_sarif(output_dir: Path) -> Path:
    reports = output_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    sarif = reports / "ash.sarif"
    sarif.write_text(json.dumps(CLEAN_SARIF), encoding="utf-8")
    return sarif


def _with_findings(tmp_path: Path) -> AshAggregatedResults:
    """The fixture scan, whose actionable findings make the exit code 2."""
    from tests.snapshot.support.fixture_model import build_fixture_model

    return build_fixture_model(tmp_path / "fixture")


def test_the_report_phase_records_the_files_it_wrote(tmp_path):
    output_dir = tmp_path / "out"
    results = _report(output_dir, AshAggregatedResults(), _OtherReporter)
    results = _report(output_dir, results, _OtherReporter)

    records = [
        checkpoint
        for checkpoint in results.validation_checkpoints
        if checkpoint.get("type") == "reports_written"
    ]
    assert [record["metadata"]["files"] for record in records] == [["ash.other.json"]]


def test_an_earlier_runs_clean_sarif_report_does_not_clear_this_run(tmp_path):
    """--use-existing with no SARIF reporter: the model's findings decide, as 2."""
    opts = _opts(tmp_path)
    assert _compute_exit_code(_with_findings(tmp_path), opts) == 2
    sarif = _earlier_runs_sarif(opts.output_dir)

    results = _report(opts.output_dir, _with_findings(tmp_path), _OtherReporter)

    assert _compute_exit_code(results, opts) == 2
    assert json.loads(sarif.read_text(encoding="utf-8")) == CLEAN_SARIF


def test_a_sarif_report_this_run_wrote_is_counted(tmp_path):
    """Listed as written, the file is counted as before: here it has no findings."""
    opts = _opts(tmp_path)
    _earlier_runs_sarif(opts.output_dir)
    results = _with_findings(tmp_path)
    results.validation_checkpoints.append(
        {"type": "reports_written", "metadata": {"files": ["ash.sarif"]}}
    )

    assert _compute_exit_code(results, opts) == 0
