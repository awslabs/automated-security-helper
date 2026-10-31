# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A reporter that fails after its file is written is not said to have left an old one.

Why these tests exist
---------------------
The report phase warns that "ash.<name> in <reports> is from an earlier run" when a
reporter wrote no file and one is there. The warning also ran in the arm for a
reporter that raised. A reporter that raised after its own file was written (in the
progress update that follows the write, for one) left the file this run just
wrote, and the warning called it an earlier run's. The warning now reads the
files this run has written and stays silent for one of them.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable, ClassVar, Literal, Tuple

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

WARNING = "wrote no report this run"


def _reporter(report: Callable):
    config_class = type(
        "XfmtConfig",
        (ReporterPluginConfigBase,),
        {
            "__annotations__": {
                "name": Literal["x-fmt"],
                "extension": str,
                "enabled": bool,
            },
            "name": "x-fmt",
            "extension": "x.json",
            "enabled": True,
        },
    )

    class _Reporter(ReporterPluginBase[config_class]):  # type: ignore[valid-type]
        sends_off_host: ClassVar[bool] = False

        def model_post_init(self, context):
            if self.config is None:
                self.config = config_class()
            return super().model_post_init(context)

        def companion_file_names(self) -> Tuple[str, ...]:
            return ()

        def report(self, model):
            return report(self, model)

    _Reporter.__name__ = "XfmtReporter"
    return _Reporter


class _DisplayThatFailsAfterTheWrite(LiveProgressDisplay):
    def update_task(self, phase, task_id, *args, **kwargs):
        if "Generated report" in str(kwargs.get("description", "")):
            raise RuntimeError("the display went away")
        return super().update_task(phase, task_id, *args, **kwargs)


def _run(tmp_path: Path, reporter, display):
    output_dir = tmp_path / "out"
    reports = output_dir / "reports"
    reports.mkdir(parents=True)
    (reports / "ash.x.json").write_text("an earlier run's report")
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=output_dir,
        work_dir=output_dir / "work",
        config=AshConfig(),
    )
    phase = ReportPhase(
        plugins=[reporter],
        plugin_context=context,
        progress_display=display,
        asharp_model=AshAggregatedResults(),
    )
    phase.execute(
        report_dir=reports,
        cli_output_formats=["x-fmt"],
        aggregated_results=AshAggregatedResults(),
        python_based_plugins_only=False,
    )
    return reports


def test_a_failure_after_the_write_does_not_blame_an_earlier_run(tmp_path, caplog):
    reporter = _reporter(lambda self, model: "this run's report")

    with caplog.at_level(logging.WARNING):
        reports = _run(
            tmp_path, reporter, _DisplayThatFailsAfterTheWrite(show_progress=False)
        )

    assert (reports / "ash.x.json").read_text() == "this run's report"
    # Red at the base: the file this run wrote was called an earlier run's.
    assert WARNING not in caplog.text


def test_a_reporter_that_raised_before_writing_still_gets_the_warning(tmp_path, caplog):
    """The control: the earlier run's file stays, and the warning says so."""

    def boom(self, model):
        raise RuntimeError("the reporter failed")

    with caplog.at_level(logging.WARNING):
        reports = _run(
            tmp_path, _reporter(boom), LiveProgressDisplay(show_progress=False)
        )

    assert (reports / "ash.x.json").read_text() == "an earlier run's report"
    assert WARNING in caplog.text
