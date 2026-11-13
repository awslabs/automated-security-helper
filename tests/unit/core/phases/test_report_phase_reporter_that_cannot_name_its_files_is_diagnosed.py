# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A requested format whose reporter cannot name its files is diagnosed as that.

Why these tests exist
---------------------
The report phase reads every enabled reporter's ``companion_file_names`` before
any reporter runs, and leaves out one whose declaration raises. The left-out
reporter stayed among the instances the format diagnosis reads, enabled and not
excluded by the python-only flag, so a requested format of it fell through to
"its reporter's dependencies are not satisfied ... typically missing credentials,
no network, or an uninstalled tool". That sent the operator to the wrong place;
the line the phase logged for the reporter names the cause. The phase now passes
the reporters it left out, and the format reads as its own reason.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar, Literal, Tuple

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.report_phase import (
    FORMAT_REPORTER_DEPENDENCIES,
    FORMAT_REPORTER_FILES_UNNAMED,
    _FORMAT_REASON_MESSAGES,
    ReportPhase,
    unsatisfied_output_formats,
)
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit


def _reporter(name: str, extension: str, *, companions_raise: bool = False):
    config_class = type(
        f"{name.title().replace('-', '')}Config",
        (ReporterPluginConfigBase,),
        {
            "__annotations__": {
                "name": Literal[name],
                "extension": str,
                "enabled": bool,
            },
            "name": name,
            "extension": extension,
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
            if companions_raise:
                raise RuntimeError("cannot say which files it writes")
            return ()

        def report(self, model):
            return "{}"

    _Reporter.__name__ = f"{name.title().replace('-', '')}Reporter"
    return _Reporter


def _run(tmp_path: Path, classes, formats):
    output_dir = tmp_path / "out"
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=output_dir,
        work_dir=output_dir / "work",
        config=AshConfig(),
    )
    phase = ReportPhase(
        plugins=list(classes),
        plugin_context=context,
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=AshAggregatedResults(),
    )
    return phase.execute(
        report_dir=output_dir / "reports",
        cli_output_formats=formats,
        aggregated_results=AshAggregatedResults(),
        python_based_plugins_only=False,
    )


def test_the_function_reads_a_left_out_reporter_as_files_unnamed():
    instance = SimpleNamespace(config=SimpleNamespace(name="x", enabled=True))

    reasons = unsatisfied_output_formats(
        ["x"], [], [instance], files_unnamed={id(instance)}
    )

    # Red at the base: no such parameter.
    assert reasons == {"x": FORMAT_REPORTER_FILES_UNNAMED}


def test_without_the_parameter_an_enabled_reporter_is_still_a_dependency_problem():
    """The control: a reporter the phase did not leave out keeps its old reason."""
    instance = SimpleNamespace(config=SimpleNamespace(name="x", enabled=True))

    assert unsatisfied_output_formats(["x"], [], [instance]) == {
        "x": FORMAT_REPORTER_DEPENDENCIES
    }


def test_the_new_reason_has_a_message_that_is_not_the_dependency_one():
    message = _FORMAT_REASON_MESSAGES[FORMAT_REPORTER_FILES_UNNAMED]

    assert "could not name the files it writes" in message
    assert "credentials" not in message


def test_the_phase_names_the_files_error_not_the_dependencies(tmp_path, caplog):
    bad = _reporter("bad-fmt", "bad.json", companions_raise=True)

    with caplog.at_level(logging.ERROR):
        _run(tmp_path, [bad], ["bad-fmt"])

    assert "is not run: it could not name the files it writes" in caplog.text
    # Red at the base: the format line sent the operator to credentials and a
    # network.
    assert "its reporter could not name the files it writes, so it was not run" in (
        caplog.text
    )
    assert "dependencies are not satisfied" not in caplog.text
