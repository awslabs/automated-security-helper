# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The report phase's cancel cleanup removes only what it can tell is new.

``test_report_phase_handler_cancel_cleanup_and_record`` pinned the cleanup that
removes everything that appeared under the reports directory while the
reporters ran. A review found that the listing it compared against could be
incomplete: ``_entries_under`` caught an OSError and returned what it had
listed, an empty set when ``exists()`` itself raised, and the cleanup then
removed every entry the after-listing found, pre-existing ones included (an
earlier run's reports kept by ``--use-existing``). The tests here are red on the
tree that carried it:

* when the before-listing does not complete, a pre-existing report survives a
  cancel, and only what the phase wrote by path goes;
* the control: with a complete baseline the pre-existing report survives AND
  the reporter's companion goes, and the info log counts both kinds.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import ClassVar, Literal, Sequence, Tuple

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    write_report_file,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.cancellation import ScanCancelled
from automated_security_helper.core.phases import report_phase
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

EARLIER_REPORT = "ash.sarif"


def _context(tmp_path: Path) -> PluginContext:
    output_dir = tmp_path / "out"
    return PluginContext(
        source_dir=tmp_path,
        output_dir=output_dir,
        work_dir=output_dir / "work",
        config=AshConfig(),
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


class _ProbeReporterConfig(ReporterPluginConfigBase):
    name: Literal["cancel-probe"] = "cancel-probe"
    extension: str = "cancel-probe.json"


class _CancellingCompanionReporter(ReporterPluginBase[_ProbeReporterConfig]):
    """Writes a file of its own beside its report, then the scan is cancelled."""

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


class _WrittenByPathConfig(ReporterPluginConfigBase):
    name: Literal["written-probe"] = "written-probe"
    extension: str = "written-probe.json"


class _WrittenByPathReporter(ReporterPluginBase[_WrittenByPathConfig]):
    """Returns a report, which the phase writes by path before the next reporter."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = _WrittenByPathConfig()
        return super().model_post_init(context)

    def companion_file_names(self) -> Tuple[str, ...]:
        return ()

    def report(self, model: AshAggregatedResults) -> str:
        return "{}"


WRITTEN_BY_PATH = "ash.written-probe.json"


def _phase_over_an_earlier_report(tmp_path: Path, plugins=None):
    context = _context(tmp_path)
    reports_dir = context.output_dir / "reports"
    reports_dir.mkdir(parents=True)
    (reports_dir / EARLIER_REPORT).write_text("{}")
    results = AshAggregatedResults()
    phase = ReportPhase(
        plugins=plugins or [_CancellingCompanionReporter],
        plugin_context=context,
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=results,
    )
    return phase, context, results, reports_dir


class TestAnIncompleteBaselineRemovesOnlyWhatThePhaseWrote:
    def test_a_pre_existing_report_survives_the_cancel(self, tmp_path, monkeypatch):
        phase, context, results, reports_dir = _phase_over_an_earlier_report(tmp_path)
        original_rglob = Path.rglob
        failed = {"n": 0}

        def rglob_failing_on_the_first_listing(self: Path, pattern, *args, **kwargs):
            if self == reports_dir and failed["n"] == 0:
                failed["n"] += 1
                raise PermissionError(13, "Permission denied", str(self))
            return original_rglob(self, pattern, *args, **kwargs)

        monkeypatch.setattr(Path, "rglob", rglob_failing_on_the_first_listing)

        with pytest.raises(ScanCancelled):
            _execute(phase, context, results, ["cancel-probe"])

        assert failed["n"] == 1
        # Red at the base: the failed listing read as an empty baseline, so the
        # after-listing's every entry looked new and the earlier report went.
        assert (reports_dir / EARLIER_REPORT).exists()
        assert reports_dir.exists()

    def test_the_file_the_phase_wrote_by_path_goes_and_the_companion_stays(
        self, tmp_path, monkeypatch
    ):
        """Both halves of the rule: with no baseline to tell new from old, the report
        the phase wrote by path is removed (it knows that one is its own), and a
        companion file the reporter wrote under a name the phase never learns is
        kept, since it cannot be told from a pre-existing one."""
        phase, context, results, reports_dir = _phase_over_an_earlier_report(
            tmp_path, plugins=[_WrittenByPathReporter, _CancellingCompanionReporter]
        )
        original_rglob = Path.rglob
        failed = {"n": 0}

        def rglob_failing_on_the_first_listing(self: Path, pattern, *args, **kwargs):
            if self == reports_dir and failed["n"] == 0:
                failed["n"] += 1
                raise PermissionError(13, "Permission denied", str(self))
            return original_rglob(self, pattern, *args, **kwargs)

        monkeypatch.setattr(Path, "rglob", rglob_failing_on_the_first_listing)

        with pytest.raises(ScanCancelled):
            _execute(phase, context, results, ["written-probe", "cancel-probe"])

        assert failed["n"] == 1
        assert not (reports_dir / WRITTEN_BY_PATH).exists()
        assert (reports_dir / EARLIER_REPORT).exists()
        assert (reports_dir / _CancellingCompanionReporter.COMPANION).exists()

    def test_the_helper_answers_none_for_a_listing_that_did_not_complete(
        self, tmp_path, monkeypatch
    ):
        directory = tmp_path / "reports"
        directory.mkdir()
        (directory / "a.txt").write_text("a")

        original_rglob = Path.rglob

        def rglob_raising(self: Path, pattern, *args, **kwargs):
            # Only the directory under test: the test runner's own fixtures
            # walk other directories with rglob at teardown.
            if self == directory:
                raise OSError(5, "Input/output error", str(self))
            return original_rglob(self, pattern, *args, **kwargs)

        monkeypatch.setattr(Path, "rglob", rglob_raising)

        # Red at the base: an empty set, indistinguishable from an empty directory.
        assert report_phase._entries_under(directory) is None

    def test_the_helper_answers_an_empty_set_for_an_absent_directory(self, tmp_path):
        """The control: absent is empty, and complete."""
        assert report_phase._entries_under(tmp_path / "nowhere") == set()


class TestACompleteBaselineRemovesWhatAppearedAndNothingElse:
    def test_the_earlier_report_stays_and_the_companion_goes(self, tmp_path, caplog):
        phase, context, results, reports_dir = _phase_over_an_earlier_report(tmp_path)

        with caplog.at_level(logging.INFO):
            with pytest.raises(ScanCancelled):
                _execute(phase, context, results, ["cancel-probe"])

        assert (reports_dir / EARLIER_REPORT).exists()
        assert not (reports_dir / _CancellingCompanionReporter.COMPANION).exists()
        # The directory was there before the phase ran, so it stays.
        assert reports_dir.exists()
        # The log counts the companion as well as the reports written by path.
        assert "1 other entry that appeared under" in caplog.text
