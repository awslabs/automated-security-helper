# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A reporter that crashed and a reporter with nothing to say are not the same.

``ReportPhase`` gates all file writing on ``if report_result:``, and everything
falsy took one shared arm: a DEBUG log line -- invisible at default verbosity and
absent from the console under ``--quiet``, which is what CI runs -- followed by
the reporter task painted a yellow "No report generated" and counted among the
phase's normal outcomes. So a reporter whose transform blew up was reported
exactly like one that had no findings to write, and the crash is the one that
needs acting on.

Two reporters in this repository reached that arm by returning ``None``: the
GitLab SAST reporter, whose only ``return`` sat inside a ``try`` whose ``except``
was the last statement of the method, and the GHAS reporter, which now returns
``None`` deliberately rather than emitting a SARIF document asserting zero
findings. Fixing each of them separately would leave the next reporter to make
the same choice again, so the arm itself is the fix -- it covers every reporter,
including ones not yet written.

Driven through ``_execute_phase`` with stub reporters rather than through a real
one, because the subject here is the phase's handling of a return value, not any
particular reporter's transform. The three stubs differ only in what they return.
"""

import logging
from typing import Literal, Optional
from unittest.mock import patch

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
from automated_security_helper.plugins.events import AshEventType


class _StubReporterConfig(ReporterPluginConfigBase):
    name: Literal["stub-reporter"] = "stub-reporter"
    extension: str = "stub.json"
    enabled: bool = True


class _StubReporter(ReporterPluginBase[_StubReporterConfig]):
    """Base for the three stubs; subclasses choose what ``report`` returns."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = _StubReporterConfig()
        return super().model_post_init(context)

    def report(self, model: AshAggregatedResults) -> Optional[str]:
        raise NotImplementedError


class _NoneReporter(_StubReporter):
    def report(self, model: AshAggregatedResults) -> Optional[str]:
        return None


class _EmptyStringReporter(_StubReporter):
    def report(self, model: AshAggregatedResults) -> Optional[str]:
        return ""


class _WorkingReporter(_StubReporter):
    def report(self, model: AshAggregatedResults) -> Optional[str]:
        return '{"findings": []}'


@pytest.fixture
def context(tmp_path):
    output_dir = tmp_path / "out"
    return PluginContext(
        source_dir=tmp_path / "src",
        output_dir=output_dir,
        work_dir=output_dir / "work",
        config=AshConfig(),
    )


def _run(context, reporter_class, tmp_path):
    """Run the report phase with exactly one stub reporter, and return the log."""
    phase = ReportPhase(
        plugins=[reporter_class],
        plugin_context=context,
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=AshAggregatedResults(),
    )
    reports_dir = tmp_path / "out" / "reports"
    phase._execute_phase(
        report_dir=reports_dir,
        aggregated_results=AshAggregatedResults(),
        cli_output_formats=["stub-reporter"],
        python_based_plugins_only=False,
    )
    return sorted(path.name for path in reports_dir.iterdir())


class TestANoneReturnIsAnError:
    def test_no_file_is_written(self, context, tmp_path):
        assert _run(context, _NoneReporter, tmp_path) == []

    def test_it_is_logged_where_quiet_cannot_hide_it(self, context, tmp_path, caplog):
        """Asserted on the record's level, because the text is the same at any level.

        ``--quiet`` maps the console to ERROR, and that is the invocation CI uses.
        At DEBUG this diagnosis reached ``ash.log`` and nowhere an operator looks.
        """
        caplog.set_level(logging.DEBUG)

        _run(context, _NoneReporter, tmp_path)

        diagnoses = [
            record
            for record in caplog.records
            if "_NoneReporter" in record.getMessage()
            or "stub-reporter" in record.getMessage()
        ]
        assert diagnoses, (
            "the phase said nothing about a reporter that produced nothing"
        )
        assert any(record.levelno >= logging.ERROR for record in diagnoses), (
            "a reporter that returned None was reported at "
            f"{[record.levelname for record in diagnoses]}, which --quiet suppresses"
        )

    def test_the_task_is_not_painted_as_a_success(self, context, tmp_path):
        """The progress display is the only signal most operators see."""
        display = LiveProgressDisplay(show_progress=False)
        phase = ReportPhase(
            plugins=[_NoneReporter],
            plugin_context=context,
            progress_display=display,
            asharp_model=AshAggregatedResults(),
        )
        descriptions = []
        original = display.update_task

        def record(*args, **kwargs):
            if "description" in kwargs:
                descriptions.append(kwargs["description"])
            return original(*args, **kwargs)

        display.update_task = record
        phase._execute_phase(
            report_dir=tmp_path / "out" / "reports",
            aggregated_results=AshAggregatedResults(),
            cli_output_formats=["stub-reporter"],
            python_based_plugins_only=False,
        )

        final = [text for text in descriptions if "stub-reporter" in text][-1]
        assert "[red]" in final, final
        assert "No report generated" not in final, final

    def test_an_error_event_is_emitted_and_not_report_complete(self, context, tmp_path):
        """``REPORT_COMPLETE`` is how a subscriber learns a reporter succeeded.

        ``notify`` is patched rather than a subscriber registered, because
        ``ash_plugin_manager`` is a process-global singleton and its handler
        registry has no "forget everything" API -- a test that registers one leaks
        it into every case that runs after it.
        ``test_project_isolation.py::test_nothing_outside_the_manager_touches_the_registry``
        fails on any file but the plugin system's own test reaching into
        ``plugin_library``, which is how this test found out.
        """
        notified = []

        with patch(
            "automated_security_helper.plugins.ash_plugin_manager.notify",
            side_effect=lambda event_type, **kwargs: notified.append(
                (event_type, kwargs)
            ),
        ):
            _run(context, _NoneReporter, tmp_path)

        assert [
            kwargs
            for event, kwargs in notified
            if event is AshEventType.ERROR and kwargs.get("phase") == "report"
        ]
        assert not [
            kwargs
            for event, kwargs in notified
            if event is AshEventType.REPORT_COMPLETE
        ]


class TestAnEmptyReportIsNotSilent:
    """Falsy but not None: the reporter ran, and still wrote nothing."""

    def test_no_file_is_written(self, context, tmp_path):
        assert _run(context, _EmptyStringReporter, tmp_path) == []

    def test_it_is_not_logged_at_debug(self, context, tmp_path, caplog):
        caplog.set_level(logging.DEBUG)

        _run(context, _EmptyStringReporter, tmp_path)

        diagnoses = [
            record for record in caplog.records if "empty report" in record.getMessage()
        ]
        assert diagnoses
        assert all(record.levelno >= logging.WARNING for record in diagnoses)

    def test_it_is_not_reported_as_a_crash(self, context, tmp_path, caplog):
        """A reporter that returned a string did not crash, and must not read as one."""
        caplog.set_level(logging.DEBUG)

        _run(context, _EmptyStringReporter, tmp_path)

        assert not [
            record
            for record in caplog.records
            if record.levelno >= logging.ERROR
            and "returned None" in record.getMessage()
        ]


class TestTheWriteBranchIsUnchanged:
    """The positive control: a reporter that works must still be written and green."""

    def test_the_file_is_written(self, context, tmp_path):
        assert _run(context, _WorkingReporter, tmp_path) == ["ash.stub.json"]

    def test_nothing_is_logged_at_error(self, context, tmp_path, caplog):
        caplog.set_level(logging.DEBUG)

        _run(context, _WorkingReporter, tmp_path)

        assert not [
            record
            for record in caplog.records
            if record.levelno >= logging.ERROR
            and "stub-reporter" in record.getMessage()
        ]
