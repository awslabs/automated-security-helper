# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One reporter's failing config lookup does not abort every report.

``ReportPhase`` looks up each reporter's config section
(``reporter_section``) and the off-host refusal before building the instance.
Those lookups run inside the same ``try`` as the construction: an exception
there is logged ("Error creating reporter ...") and skips that one reporter,
and the other reporters still write their files. Before the containment was
restored, the exception escaped the loop and no report was written at all.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional, Sequence

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases import report_phase as report_phase_module
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.loader import load_plugins

pytestmark = pytest.mark.unit


def _run_report_phase(
    tmp_path: Path, requested: Optional[Sequence[object]]
) -> List[str]:
    """The real report phase over the real registry; the filenames written."""
    output_dir = tmp_path / "out"
    config = AshConfig()
    context = PluginContext(
        source_dir=tmp_path,
        output_dir=output_dir,
        work_dir=output_dir / "work",
        config=config,
    )
    ash_plugin_manager.set_context(context)
    load_plugins(plugin_context=context)

    phase = ReportPhase(
        plugins=ash_plugin_manager.plugin_modules(plugin_type="reporter"),
        plugin_context=context,
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=AshAggregatedResults(),
    )
    reports_dir = output_dir / "reports"
    phase.execute(
        report_dir=reports_dir,
        cli_output_formats=list(requested) if requested is not None else None,
        aggregated_results=AshAggregatedResults(),
        python_based_plugins_only=False,
    )
    return sorted(p.name for p in reports_dir.iterdir()) if reports_dir.exists() else []


def test_a_failing_section_lookup_is_logged_and_skips_only_that_reporter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    real_reporter_section = report_phase_module.reporter_section

    def broken_for_csv(config, reporter_class):
        if reporter_class.__name__ == "CsvReporter":
            raise RuntimeError("planted: this section lookup fails")
        return real_reporter_section(config, reporter_class)

    monkeypatch.setattr(report_phase_module, "reporter_section", broken_for_csv)

    with caplog.at_level(logging.ERROR):
        written = _run_report_phase(tmp_path, ["markdown", "csv"])

    # The other reporter still reports; the broken one wrote nothing.
    assert "ash.summary.md" in written
    assert "ash.csv" not in written
    # The skip is said, naming the reporter.
    assert "Error creating reporter CsvReporter" in caplog.text


def test_without_the_plant_both_reporters_report(tmp_path: Path) -> None:
    """The control: the harness itself produces both files."""
    written = _run_report_phase(tmp_path, ["markdown", "csv"])

    assert "ash.summary.md" in written
    assert "ash.csv" in written
