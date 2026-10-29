# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A run without a report phase still gets the aggregated suppression pass.

The final suppression pass over the merged SARIF used to run only in the report
arm of ``execute_phases``, so a run whose phases omit report (``--phases scan``)
wrote a results file and took an exit code that counted findings a full scan
suppresses. The pass now runs at the end of the last phase that shapes the
findings: the report arm when the run reports, else the scan arm, once per run.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.execution_engine import ScanExecutionEngine
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

_ENGINE_MODULE = "automated_security_helper.core.execution_engine"
_SARIF_UTILS = "automated_security_helper.utils.sarif_utils"


class _StubPhase:
    def __init__(self, **kwargs):
        self._completed_scanners = []
        self._shard_assignment = None

    def execute(self, **kwargs):
        return kwargs.get("aggregated_results")


def _engine(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    context = PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=tmp_path / "work",
        config=AshConfig(project_name="suppress-without-report"),
    )
    with patch("automated_security_helper.plugins.loader.load_internal_plugins"):
        engine = ScanExecutionEngine(
            context=context,
            show_progress=False,
            show_summary=False,
            asharp_model=AshAggregatedResults(),
        )
    engine.progress_display = MagicMock()
    engine.progress_display.live = None
    assert engine._asharp_model.sarif, "the model carries a SARIF report to pass over"
    return engine


def _run(engine, phases):
    """Run *phases* with the phases stubbed; return the suppression pass's calls."""
    with (
        patch(f"{_ENGINE_MODULE}.ConvertPhase", _StubPhase),
        patch(f"{_ENGINE_MODULE}.ScanPhase", _StubPhase),
        patch(f"{_ENGINE_MODULE}.ReportPhase", _StubPhase),
        patch(f"{_ENGINE_MODULE}.InspectPhase", _StubPhase),
        patch(
            f"{_ENGINE_MODULE}.populate_metrics_from_unified_source",
            side_effect=lambda aggregated_results: aggregated_results,
        ),
        patch(f"{_ENGINE_MODULE}.display_metrics_table"),
        patch(
            f"{_SARIF_UTILS}.apply_suppressions_to_sarif",
            side_effect=lambda sarif_report, **kwargs: sarif_report,
        ) as suppress,
        patch(
            "automated_security_helper.utils.suppression_matcher."
            "warn_unmatched_directory_suppressions"
        ),
    ):
        engine.execute_phases(phases=phases)
    return suppress


def test_a_scan_only_run_gets_the_aggregated_suppression_pass(tmp_path):
    """Red before the fix: the pass ran only in the report arm."""
    suppress = _run(_engine(tmp_path), ["scan"])

    assert suppress.call_count == 1


def test_a_full_run_takes_the_pass_once_in_the_report_arm(tmp_path):
    """Control: scan then report passes once, not twice."""
    suppress = _run(_engine(tmp_path), ["scan", "report"])

    assert suppress.call_count == 1


def test_a_report_only_run_still_takes_the_pass(tmp_path):
    """Control: the report arm's pass is unchanged."""
    suppress = _run(_engine(tmp_path), ["report"])

    assert suppress.call_count == 1
