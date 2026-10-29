# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A file a reporter writes beside its report has to be a file in the reports directory.

A reporter declares those files in ``companion_file_names``. One whose name is not
a single path component, such as ``../summary.md``, would not be written
(``write_report_file`` refuses it), so it refuses the run before any reporter
writes, as a report file name outside the directory does, in the report phase
and in the workspace report step. Built-in reporters only declare fixed names or
validated options, so these use a reporter that declares such a name itself.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal, Optional, Tuple

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
    write_report_file,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.report_path_links import ReportPathRefused

pytestmark = pytest.mark.unit

ESCAPING = "../companion-escape.md"


class _CompanionConfig(ReporterPluginConfigBase):
    name: Literal["companion-escaper"] = "companion-escaper"
    extension: str = "companion.json"
    enabled: bool = True


class _CompanionEscaper(ReporterPluginBase[_CompanionConfig]):
    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = _CompanionConfig()
        return super().model_post_init(context)

    def companion_file_names(self) -> Tuple[str, ...]:
        return (ESCAPING,)

    def report(self, model) -> Optional[str]:
        write_report_file(Path(self.context.output_dir) / "reports", ESCAPING, "c")
        return "{}"


class _PlainConfig(ReporterPluginConfigBase):
    name: Literal["aaa-plain"] = "aaa-plain"
    extension: str = "plain.json"
    enabled: bool = True


class _Plain(ReporterPluginBase[_PlainConfig]):
    """Runs first, so a refusal after reporters started would leave its file."""

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = _PlainConfig()
        return super().model_post_init(context)

    def report(self, model) -> Optional[str]:
        return "{}"


def _assert_refused(refused: pytest.ExceptionInfo, reports: Path) -> None:
    message = str(refused.value)
    assert repr(ESCAPING) in message, message
    assert "companion-escaper" in message, message
    assert f"is not a file in {reports.as_posix()}" in message, message


def test_the_report_phase_refuses_a_companion_name_outside_reports(tmp_path):
    output_dir = tmp_path / "out"
    reports = output_dir / "reports"
    reports.mkdir(parents=True)
    phase = ReportPhase(
        plugins=[_Plain, _CompanionEscaper],
        plugin_context=PluginContext(
            source_dir=tmp_path / "src",
            output_dir=output_dir,
            work_dir=output_dir / "work",
            config=AshConfig(),
        ),
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=AshAggregatedResults(),
    )

    with pytest.raises(ReportPathRefused) as refused:
        phase._execute_phase(
            report_dir=reports,
            aggregated_results=AshAggregatedResults(),
            cli_output_formats=["aaa-plain", "companion-escaper"],
            python_based_plugins_only=False,
        )

    _assert_refused(refused, reports)
    assert list(reports.iterdir()) == []
    assert not list(tmp_path.rglob("companion-escape.md"))


def test_the_workspace_report_step_refuses_a_companion_name_outside_reports(
    tmp_path,
):
    from automated_security_helper.workspace.aggregation import WorkspaceAggregator
    from automated_security_helper.workspace.plan import WorkspacePlan
    from automated_security_helper.workspace.reporting import (
        REPORTS_DIR_NAME,
        emit_workspace_reports,
    )

    root = tmp_path / "ws"
    root.mkdir()
    plan = WorkspacePlan(
        workspace_file=(root / "fixture.code-workspace").as_posix(),
        workspace_root=root.as_posix(),
        projects=[],
    )
    output_dir = tmp_path / "out"
    results_path = WorkspaceAggregator(plan=plan, output_dir=output_dir).write(
        exit_code=0, wall_clock_seconds=0.1
    )
    reports = output_dir / REPORTS_DIR_NAME

    with pytest.raises(ReportPathRefused) as refused:
        emit_workspace_reports(
            plan=plan,
            output_dir=output_dir,
            results_path=results_path,
            reporter_classes=[_Plain, _CompanionEscaper],
        )

    _assert_refused(refused, reports)
    assert list(reports.iterdir()) == []
    assert not list(tmp_path.rglob("companion-escape.md"))
