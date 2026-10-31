# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Report phase: format diagnoses, a reporter that cannot declare its files, and
what a reporter's failure or a cancel leaves behind.

Each test is red on the tree that carried its defect:

* The "disabled" diagnosis told the operator to set the flag in "the ASH config"
  and did not say that a file inside the scanned repository cannot turn on a
  reporter that sends findings off the host.
* ``_excluded_reporter_reason`` read only an explicit ``False`` as disabled
  although the filter drops on any falsy value, and an off-host reporter the
  phase held back (its config could not be set disabled) fell through to the
  dependency reason.
* A requested format whose reporter could not be built was diagnosed as a format
  no reporter has.
* One reporter whose ``companion_file_names`` raised aborted the phase before any
  report was written.
* A reporter with no configured name was named ``None`` in the logs and events.
* A reporter that raised got REPORT_START and no ERROR event; a reporter that
  wrote nothing left an earlier run's file in ``reports/`` with no word that it
  was not this run's.
* A cancel that landed after the last reporter's write was not seen, and a
  cancel seen after an off-host reporter returned removed the record of what it
  had already sent.
"""

from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, ClassVar, Literal, Optional, Tuple

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    write_report_file,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.cancellation import (
    CancelEvent,
    ScanCancelled,
    cancel_scope,
)
from automated_security_helper.core.phases.report_phase import (
    FORMAT_NO_REPORTER,
    FORMAT_REPORTER_DEPENDENCIES,
    FORMAT_REPORTER_DISABLED,
    FORMAT_REPORTER_FAILED,
    ReportPhase,
    _log_unsatisfied_output_formats,
    unsatisfied_output_formats,
)
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugins.events import AshEventType

pytestmark = pytest.mark.unit


def _make_reporter(
    name: str,
    extension: str,
    report: Callable,
    *,
    off_host: bool = False,
    companions: Tuple[str, ...] = (),
    nameless: bool = False,
    companions_raise: bool = False,
    cannot_be_built: bool = False,
):
    """A reporter class: its report comes from *report(self, model)*."""
    annotations = {
        "name": Optional[str] if nameless else Literal[name],
        "extension": str,
        "enabled": bool,
    }
    config_class = type(
        f"{name.title().replace('-', '')}Config",
        (ReporterPluginConfigBase,),
        {
            "__annotations__": annotations,
            "name": None if nameless else name,
            "extension": extension,
            "enabled": True,
        },
    )

    class _Reporter(ReporterPluginBase[config_class]):  # type: ignore[valid-type]
        sends_off_host: ClassVar[bool] = off_host

        def model_post_init(self, context):
            if cannot_be_built:
                raise RuntimeError("the reporter cannot be built")
            if self.config is None:
                self.config = config_class()
            return super().model_post_init(context)

        def companion_file_names(self) -> Tuple[str, ...]:
            if companions_raise:
                raise RuntimeError("cannot say which files it writes")
            return companions

        def report(self, model):
            return report(self, model)

    _Reporter.__name__ = f"{name.title().replace('-', '')}Reporter"
    return _Reporter


def _context(tmp_path: Path, config: Optional[AshConfig] = None) -> PluginContext:
    output_dir = tmp_path / "out"
    return PluginContext(
        source_dir=tmp_path / "src",
        output_dir=output_dir,
        work_dir=output_dir / "work",
        config=config or AshConfig(),
    )


def _phase(context: PluginContext, classes) -> ReportPhase:
    return ReportPhase(
        plugins=list(classes),
        plugin_context=context,
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=AshAggregatedResults(),
    )


def _execute(phase: ReportPhase, context: PluginContext, formats=None):
    return phase.execute(
        report_dir=context.output_dir / "reports",
        cli_output_formats=formats,
        aggregated_results=AshAggregatedResults(),
        python_based_plugins_only=False,
    )


def _enabling_off_host(name: str) -> AshConfig:
    return AshConfig.model_validate({"reporters": {name: {"enabled": True}}})


def _recording(phase: ReportPhase):
    events = []

    def notify(event_type, **kwargs):
        events.append((event_type, kwargs))
        return []

    phase.notify_event = notify  # type: ignore[method-assign]
    return events


class TestTheFormatDiagnoses:
    def test_the_disabled_message_says_a_repository_file_cannot_enable_an_off_host_reporter(
        self, caplog
    ):
        with caplog.at_level(logging.ERROR):
            _log_unsatisfied_output_formats({"s3": FORMAT_REPORTER_DISABLED})

        assert "its reporter is disabled in the configuration" in caplog.text
        # Red at the base: nothing said which config counts.
        assert "inside the scanned repository does not count" in caplog.text

    def test_a_falsy_enabled_value_reads_as_disabled(self):
        instance = SimpleNamespace(config=SimpleNamespace(name="x", enabled=None))

        # Red at the base: only an explicit False read as disabled.
        assert unsatisfied_output_formats(["x"], [], [instance]) == {
            "x": FORMAT_REPORTER_DISABLED
        }

    def test_an_enabled_reporter_is_still_a_dependency_problem(self):
        """The control: a truthy flag falls through to the dependency reason."""
        instance = SimpleNamespace(config=SimpleNamespace(name="x", enabled=True))

        assert unsatisfied_output_formats(["x"], [], [instance]) == {
            "x": FORMAT_REPORTER_DEPENDENCIES
        }

    def test_an_off_host_reporter_the_phase_held_back_reads_as_disabled(self):
        instance = SimpleNamespace(config=SimpleNamespace(name="x", enabled=True))

        # Red at the base: no such parameter, and the reason was the dependencies.
        assert unsatisfied_output_formats(
            ["x"], [], [instance], off_host_refused={id(instance)}
        ) == {"x": FORMAT_REPORTER_DISABLED}

    def test_a_format_whose_reporter_failed_to_build_is_not_a_missing_reporter(self):
        failed = unsatisfied_output_formats(
            ["broken"], [], [], failed_to_build={"broken"}
        )
        unknown = unsatisfied_output_formats(["broken"], [], [])

        # Red at the base: no such parameter, and the reason was FORMAT_NO_REPORTER.
        assert failed == {"broken": FORMAT_REPORTER_FAILED}
        assert unknown == {"broken": FORMAT_NO_REPORTER}

    def test_the_phase_names_the_build_error_not_a_plugin_module(
        self, tmp_path, caplog
    ):
        broken = _make_reporter(
            "broken-fmt",
            "broken.json",
            lambda self, model: "{}",
            cannot_be_built=True,
        )
        context = _context(tmp_path)
        with caplog.at_level(logging.ERROR):
            _execute(_phase(context, [broken]), context, ["broken-fmt"])

        assert "Error creating reporter" in caplog.text
        assert "its reporter could not be created" in caplog.text
        assert "no reporter produces it" not in caplog.text


class TestAReporterThatCannotNameItsFiles:
    def test_the_other_reports_are_still_written(self, tmp_path, caplog):
        good = _make_reporter("good-fmt", "good.json", lambda self, model: "{}")
        bad = _make_reporter(
            "bad-fmt", "bad.json", lambda self, model: "{}", companions_raise=True
        )
        context = _context(tmp_path)

        with caplog.at_level(logging.ERROR):
            # Red at the base: the RuntimeError escaped before any report.
            _execute(_phase(context, [good, bad]), context)

        reports = context.output_dir / "reports"
        assert (reports / "ash.good.json").is_file()
        assert not (reports / "ash.bad.json").exists()
        assert "could not name the files it writes" in caplog.text


class TestANamelessReporter:
    def test_its_class_name_stands_in_for_the_missing_name(self, tmp_path):
        nameless = _make_reporter(
            "ignored", "nameless.json", lambda self, model: "{}", nameless=True
        )
        context = _context(tmp_path)
        phase = _phase(context, [nameless])
        events = _recording(phase)

        _execute(phase, context)

        started = [kw for kind, kw in events if kind == AshEventType.REPORT_START]
        assert started
        # Red at the base: the reporter was named None.
        assert started[0]["reporter"] == nameless.__name__


class TestAReporterThatFailsToWrite:
    def test_a_reporter_that_raised_sends_an_error_event(self, tmp_path):
        def boom(self, model):
            raise RuntimeError("the reporter failed")

        failing = _make_reporter("failing-fmt", "failing.json", boom)
        context = _context(tmp_path)
        phase = _phase(context, [failing])
        events = _recording(phase)

        _execute(phase, context)

        errors = [kw for kind, kw in events if kind == AshEventType.ERROR]
        # Red at the base: REPORT_START and nothing after it.
        assert len(errors) == 1
        assert errors[0]["reporter"] == "failing-fmt"
        assert "the reporter failed" in errors[0]["message"]

    @pytest.mark.parametrize("result", [None, ""], ids=["none", "empty"])
    def test_an_earlier_runs_file_is_named_as_not_this_runs(
        self, tmp_path, caplog, result
    ):
        silent = _make_reporter("silent-fmt", "silent.json", lambda self, model: result)
        context = _context(tmp_path)
        reports = context.output_dir / "reports"
        reports.mkdir(parents=True)
        (reports / "ash.silent.json").write_text("from the run before")

        with caplog.at_level(logging.WARNING):
            _execute(_phase(context, [silent]), context)

        # Red at the base: nothing said so; the file stayed as if it were new.
        assert "ash.silent.json" in caplog.text
        assert "from an earlier run" in caplog.text
        assert (reports / "ash.silent.json").read_text() == "from the run before"

    def test_there_is_no_such_notice_without_an_earlier_file(self, tmp_path, caplog):
        silent = _make_reporter("silent-fmt", "silent.json", lambda self, model: None)
        context = _context(tmp_path)

        with caplog.at_level(logging.WARNING):
            _execute(_phase(context, [silent]), context)

        assert "from an earlier run" not in caplog.text


class TestACancelDuringTheReportPhase:
    def test_a_cancel_after_the_last_write_removes_the_reports(self, tmp_path):
        local = _make_reporter("local-fmt", "local.json", lambda self, model: "{}")
        context = _context(tmp_path)
        phase = _phase(context, [local])
        event = CancelEvent()

        def cancel_when_complete(event_type, **kwargs):
            if event_type == AshEventType.REPORT_COMPLETE:
                event.set()
            return []

        phase.notify_event = cancel_when_complete  # type: ignore[method-assign]

        with cancel_scope(event):
            # Red at the base: the phase returned with the report kept.
            with pytest.raises(ScanCancelled):
                _execute(phase, context)

        assert not (context.output_dir / "reports" / "ash.local.json").exists()

    def test_an_off_host_reporters_record_survives_a_cancel(self, tmp_path):
        event = CancelEvent()
        companion = "ash.off-host.record"

        def upload_then_cancel(self, model):
            write_report_file(
                self.context.output_dir / "reports", companion, "sent to the service\n"
            )
            event.set()
            return "{}"

        local = _make_reporter("local-fmt", "local.json", lambda self, model: "{}")
        off_host = _make_reporter(
            "fake-off-host",
            "off-host.json",
            upload_then_cancel,
            off_host=True,
            companions=(companion,),
        )
        context = _context(tmp_path, _enabling_off_host("fake-off-host"))
        phase = _phase(context, [local, off_host])

        with cancel_scope(event):
            with pytest.raises(ScanCancelled):
                _execute(phase, context)

        reports = context.output_dir / "reports"
        # Red at the base: the record of the upload was removed with the rest.
        assert (reports / companion).read_text() == "sent to the service\n"
        assert (reports / "ash.off-host.json").is_file()
        # The control: a local reporter's report is still removed.
        assert not (reports / "ash.local.json").exists()
