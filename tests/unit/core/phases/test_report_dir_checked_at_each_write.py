# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The reports directory is checked for a link when the phase starts and at each write.

A dangling link at ``reports/`` refuses the run rather than failing ``mkdir``; a
reports directory that becomes a link while the phase runs gets no more
reports; and the exit code is never read from a ``reports/ash.sarif`` that is a
link, whether or not findings gate the run.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Literal, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    confined_report_path,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.report_path_links import ReportPathLinkRefused

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    ),
]


def _phase(output_dir: Path, plugins) -> ReportPhase:
    return ReportPhase(
        plugins=plugins,
        plugin_context=PluginContext(
            source_dir=output_dir.parent / "src",
            output_dir=output_dir,
            work_dir=output_dir / "work",
            config=AshConfig(),
        ),
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=AshAggregatedResults(),
    )


def _run(phase: ReportPhase, reports: Path, formats) -> None:
    phase._execute_phase(
        report_dir=reports,
        aggregated_results=AshAggregatedResults(),
        cli_output_formats=formats,
        python_based_plugins_only=False,
    )


class _SwapConfig(ReporterPluginConfigBase):
    name: Literal["aaa-swapper"] = "aaa-swapper"
    extension: str = "swap.json"
    enabled: bool = True


class _Swapper(ReporterPluginBase[_SwapConfig]):
    """Replaces reports/ with a link to a directory outside it, then reports nothing."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = _SwapConfig()
        return super().model_post_init(context)

    def report(self, model) -> Optional[str]:
        reports = Path(self.context.output_dir) / "reports"
        outside = Path(self.context.output_dir).parent / "outside"
        outside.mkdir()
        os.rename(reports, reports.with_name("reports.moved"))
        reports.symlink_to(outside, target_is_directory=True)
        return None


class _LaterConfig(ReporterPluginConfigBase):
    name: Literal["zzz-later"] = "zzz-later"
    extension: str = "later.json"
    enabled: bool = True


class _Later(ReporterPluginBase[_LaterConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = _LaterConfig()
        return super().model_post_init(context)

    def report(self, model) -> Optional[str]:
        return "{}"


def test_a_dangling_link_at_the_reports_directory_refuses_the_run(tmp_path) -> None:
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    reports = output_dir / "reports"
    reports.symlink_to(tmp_path / "missing", target_is_directory=True)

    with pytest.raises(ReportPathLinkRefused) as excinfo:
        _run(_phase(output_dir, [_Later]), reports, ["zzz-later"])

    assert "is a symlink" in str(excinfo.value)
    assert not (tmp_path / "missing").exists()


def test_a_reports_directory_that_becomes_a_link_gets_no_more_reports(tmp_path) -> None:
    output_dir = tmp_path / "out"
    reports = output_dir / "reports"
    reports.mkdir(parents=True)

    _run(_phase(output_dir, [_Swapper, _Later]), reports, ["aaa-swapper", "zzz-later"])

    assert not (tmp_path / "outside" / "ash.later.json").exists()


def test_the_confined_path_refuses_a_reports_directory_that_is_a_link(tmp_path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "reports"
    link.symlink_to(real, target_is_directory=True)

    assert confined_report_path(link, "ash.json") is None
    assert confined_report_path(real, "ash.json") == real / "ash.json"


def test_the_exit_code_is_not_read_through_a_sarif_link_with_gating_off(
    tmp_path,
) -> None:
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _compute_exit_code,
    )

    out = tmp_path / "out"
    (out / "reports").mkdir(parents=True)
    outside = tmp_path / "outside.sarif"
    outside.write_text('{"version": "2.1.0", "runs": []}', encoding="utf-8")
    (out / "reports" / "ash.sarif").symlink_to(outside)
    options = ScanOptions(
        source_dir=tmp_path / "src", output_dir=out, fail_on_findings=False
    )

    with pytest.raises(SystemExit) as refused:
        _compute_exit_code(AshAggregatedResults(), options)

    assert refused.value.code == 1
