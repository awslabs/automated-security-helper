# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The report phase survives its own display, cleans up after a cancel, and keeps its record.

Three defects of ``ReportPhase``, each pinned by a test red on the tree that
carried it:

* The reporter loop's exception handler read ``reporter_task`` and
  ``display_name``, both bound inside the ``try``: unbound on the first
  reporter when ``add_task`` raised, the handler died with a NameError and took
  every remaining reporter with it.
* A cancel during the report phase removed only the files the phase wrote by
  path, so a file a reporter wrote itself beside its report stayed, and the
  reports directory with it.
* ``record_reports_written`` at the end of each run replaced the previous run's
  record, so the second ReportPhase ``ash merge`` runs (the off-host reporters)
  erased the record that ``ash.sarif`` had been written.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import ClassVar, Literal, Sequence, Tuple
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    write_report_file,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.cancellation import ScanCancelled
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.loader import load_plugins
from automated_security_helper.utils.inner_run_outcome import (
    REPORTS_WRITTEN_CHECKPOINT,
    report_file_written_as,
)

pytestmark = pytest.mark.unit


def _context(tmp_path: Path) -> PluginContext:
    output_dir = tmp_path / "out"
    return PluginContext(
        source_dir=tmp_path,
        output_dir=output_dir,
        work_dir=output_dir / "work",
        config=AshConfig(),
    )


def _registry_phase(context: PluginContext, progress, results) -> ReportPhase:
    """The real report phase over the real reporter registry."""
    ash_plugin_manager.set_context(context)
    load_plugins(plugin_context=context)
    return ReportPhase(
        plugins=ash_plugin_manager.plugin_modules(plugin_type="reporter"),
        plugin_context=context,
        progress_display=progress,
        asharp_model=results,
    )


def _execute(
    phase: ReportPhase, context: PluginContext, results, formats: Sequence[str]
):
    return phase.execute(
        report_dir=context.output_dir / "reports",
        cli_output_formats=list(formats),
        aggregated_results=results,
        python_based_plugins_only=False,
    )


class TestADisplayFailureOnOneReporterDoesNotStopTheOthers:
    def test_the_other_reporter_still_writes(self, tmp_path, caplog):
        context = _context(tmp_path)
        progress = MagicMock()
        calls = {"n": 0}

        def add_task(**_kwargs):
            # The first call is the phase's own task; the second is the first
            # reporter's, and it fails.
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("the display is gone")
            return calls["n"]

        progress.add_task.side_effect = add_task
        results = AshAggregatedResults()
        phase = _registry_phase(context, progress, results)

        with caplog.at_level(logging.ERROR):
            # Red at the base: the handler's NameError escaped the phase.
            _execute(phase, context, results, ["markdown", "csv"])

        reports_dir = context.output_dir / "reports"
        written = sorted(p.name for p in reports_dir.iterdir())
        # Exactly one of the two reporters lost its display; the other wrote.
        assert len([n for n in written if n in ("ash.summary.md", "ash.csv")]) == 1
        assert "Error in reporter" in caplog.text


class _ProbeReporterConfig(ReporterPluginConfigBase):
    name: Literal["cancel-probe"] = "cancel-probe"
    extension: str = "cancel-probe.json"


class _CancellingCompanionReporter(ReporterPluginBase[_ProbeReporterConfig]):
    """Writes a file of its own beside its report, then the scan is cancelled."""

    # A pydantic model: a plain class attribute needs ClassVar, or the model
    # reads it as a field with no annotation and refuses to build.
    COMPANION: ClassVar[str] = "ash.cancel-probe.md"

    def model_post_init(self, context):
        if self.config is None:
            self.config = _ProbeReporterConfig()
        return super().model_post_init(context)

    def companion_file_names(self) -> Tuple[str, ...]:
        return (self.COMPANION,)

    def report(self, model: AshAggregatedResults) -> str:
        write_report_file(
            self.context.output_dir / "reports", self.COMPANION, "# companion\n"
        )
        raise ScanCancelled("cancelled while the probe reporter ran")


class TestACancelRemovesWhatAReporterWroteItself:
    def test_the_companion_and_the_directory_are_gone(self, tmp_path):
        context = _context(tmp_path)
        results = AshAggregatedResults()
        phase = ReportPhase(
            plugins=[_CancellingCompanionReporter],
            plugin_context=context,
            progress_display=LiveProgressDisplay(show_progress=False),
            asharp_model=results,
        )
        reports_dir = context.output_dir / "reports"
        assert not reports_dir.exists()

        with pytest.raises(ScanCancelled):
            _execute(phase, context, results, ["cancel-probe"])

        # Red at the base: the companion stayed, and so the directory.
        assert not (reports_dir / _CancellingCompanionReporter.COMPANION).exists()
        assert not reports_dir.exists()


class TestASecondRunKeepsTheFirstRunsRecord:
    def test_the_sarif_written_by_the_first_run_stays_recorded(self, tmp_path):
        context = _context(tmp_path)
        results = AshAggregatedResults()
        progress = LiveProgressDisplay(show_progress=False)

        first = _registry_phase(context, progress, results)
        results = _execute(first, context, results, ["sarif"])
        assert report_file_written_as(results, "sarif") == "ash.sarif"

        second = _registry_phase(context, progress, results)
        results = _execute(second, context, results, ["csv"])

        assert report_file_written_as(results, "csv") == "ash.csv"
        # Red at the base: the second run's record replaced the first's.
        assert report_file_written_as(results, "sarif") == "ash.sarif"


def _record_another_run_left(**metadata) -> dict:
    return {
        "type": REPORTS_WRITTEN_CHECKPOINT,
        "severity": "info",
        "message": "The report files this run wrote.",
        "metadata": {"files": ["ash.sarif"], "formats": {"ash.sarif": "sarif"}}
        | metadata,
    }


class TestARecordAnotherRunLeftIsNotCarriedIntoThisRunsRecord:
    @pytest.mark.parametrize(
        "metadata",
        [{}, {"run_token": "a-token-from-another-process"}],
        ids=["no token", "another process's token"],
    )
    def test_its_sarif_does_not_become_this_runs_sarif(self, tmp_path, metadata):
        context = _context(tmp_path)
        results = AshAggregatedResults()
        # What a loader that did not strip the run records would hand the phase:
        # an earlier run's record, naming a SARIF file this run does not write.
        results.validation_checkpoints = [_record_another_run_left(**metadata)]
        progress = LiveProgressDisplay(show_progress=False)

        phase = _registry_phase(context, progress, results)
        results = _execute(phase, context, results, ["csv"])

        assert report_file_written_as(results, "csv") == "ash.csv"
        # Red at the base: the phase read the other run's record token-blind and
        # passed its files back in as its own, so the earlier ash.sarif was
        # recorded again under this process's token.
        assert report_file_written_as(results, "sarif") is None
        (record,) = [
            checkpoint
            for checkpoint in results.validation_checkpoints
            if checkpoint["type"] == REPORTS_WRITTEN_CHECKPOINT
        ]
        assert "ash.csv" in record["metadata"]["files"]
        assert "ash.sarif" not in record["metadata"]["files"]
