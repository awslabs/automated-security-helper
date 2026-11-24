# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The reports say why a SKIPPED or MISSING scanner did not run.

A scanner's row in ``ash_aggregated_results.json`` records the reason
(``skipped_reason``, ``missing_reason``), and the scanner table of the HTML,
Markdown and text reports showed only the status. A reader saw that npm-audit was
SKIPPED and had to open ``ash.log`` or the JSON to learn that the project has no
lockfile. Each report now lists the reason under its scanner table.
"""

import pytest

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
    MarkdownReporterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
)
from automated_security_helper.schemas.sarif_schema_model import Result

pytestmark = pytest.mark.unit

HEADING = "Scanners that did not run"
NO_LOCKFILE = "no lockfile beside a package.json in the scanned files"
NO_TOOL = "grype was not found on PATH"


def _model(**rows: ScannerStatusInfo) -> AshAggregatedResults:
    """A scan in which bandit ran and failed, plus the given scanner rows."""
    model = AshAggregatedResults(ash_config=get_default_config())
    model.sarif.runs[0].results = [
        Result.model_validate(
            {
                "ruleId": "R1",
                "level": "error",
                "message": {"text": "fixture"},
                "properties": {"scanner_name": "bandit"},
            }
        )
    ]
    model.additional_reports["bandit"] = {
        "source": {"scanner_name": "bandit", "status": "FAILED", "duration": 1.0}
    }
    for name, row in rows.items():
        model.scanner_results[name.replace("_", "-")] = row
    model._flat_cache = None
    return model


def _skipped(reason: str | None) -> ScannerStatusInfo:
    return ScannerStatusInfo(status=ScannerStatus.SKIPPED, skipped_reason=reason)


def _missing(reason: str | None) -> ScannerStatusInfo:
    return ScannerStatusInfo(
        status=ScannerStatus.MISSING,
        dependencies_satisfied=False,
        missing_reason=reason,
    )


def _entries(model: AshAggregatedResults) -> dict[str, tuple[str, str]]:
    """Each scanner's status and reason, read off the grouped entries."""
    return {
        name: (entry["status"], entry["reason"])
        for entry in ReportContentEmitter(model).get_scanners_not_run()
        for name in entry["scanners"]
    }


class TestTheEmitterListsEachReason:
    def test_a_skipped_and_a_missing_scanner_each_have_their_recorded_reason(self):
        found = _entries(
            _model(npm_audit=_skipped(NO_LOCKFILE), grype=_missing(NO_TOOL))
        )

        assert found["npm-audit"] == ("SKIPPED", NO_LOCKFILE)
        assert found["grype"] == ("MISSING", NO_TOOL)

    def test_a_scanner_that_ran_has_no_entry(self):
        found = _entries(_model(npm_audit=_skipped(NO_LOCKFILE)))

        assert "bandit" not in found

    def test_the_entries_are_in_scanner_results_order(self):
        model = _model(npm_audit=_skipped(NO_LOCKFILE), grype=_missing(NO_TOOL))
        emitter = ReportContentEmitter(model)

        in_table = [
            row["scanner_name"]
            for row in emitter.get_scanner_results()
            if row["status"] in ("SKIPPED", "MISSING")
        ]

        assert [
            name
            for entry in emitter.get_scanners_not_run()
            for name in entry["scanners"]
        ] == in_table

    def test_a_scan_in_which_every_scanner_ran_has_no_entries(self):
        assert _entries(_model()) == {}


class TestScannersThatShareAReasonShareAnEntry:
    """One option often leaves many scanners out: ``--scanners npm-audit`` skips
    every other scanner for the one reason."""

    NOT_NAMED = "not named by --scanners"

    def _model(self) -> AshAggregatedResults:
        return _model(
            checkov=_skipped(self.NOT_NAMED),
            npm_audit=_skipped(NO_LOCKFILE),
            semgrep=_skipped(self.NOT_NAMED),
        )

    def test_the_emitter_groups_them_in_first_seen_order(self):
        found = [
            (entry["scanners"], entry["reason"])
            for entry in ReportContentEmitter(self._model()).get_scanners_not_run()
        ]

        assert found == [
            (["checkov", "semgrep"], self.NOT_NAMED),
            (["npm-audit"], NO_LOCKFILE),
        ]

    def test_a_status_is_not_merged_with_another_that_has_the_same_text(self):
        found = ReportContentEmitter(
            _model(checkov=_skipped("same text"), grype=_missing("same text"))
        ).get_scanners_not_run()

        assert [(e["scanners"], e["status"]) for e in found] == [
            (["checkov"], "SKIPPED"),
            (["grype"], "MISSING"),
        ]

    def test_the_text_report_has_one_line_per_reason(self, test_plugin_context):
        document = TextReporter(context=test_plugin_context).report(self._model())

        assert f"- checkov, semgrep (SKIPPED): {self.NOT_NAMED}" in document
        assert document.count(self.NOT_NAMED) == 1


REPORTERS = [HtmlReporter, MarkdownReporter, TextReporter]


@pytest.mark.parametrize("reporter", REPORTERS, ids=lambda r: r.__name__)
class TestEachReportShowsTheReasons:
    def test_the_reason_is_under_the_scanner_table(self, reporter, test_plugin_context):
        document = reporter(context=test_plugin_context).report(
            _model(npm_audit=_skipped(NO_LOCKFILE), grype=_missing(NO_TOOL))
        )

        assert HEADING in document
        assert NO_LOCKFILE in document
        assert NO_TOOL in document
        assert document.index(HEADING) < document.index(NO_LOCKFILE)

    def test_a_report_with_no_such_scanner_has_no_section(
        self, reporter, test_plugin_context
    ):
        document = reporter(context=test_plugin_context).report(_model())

        assert HEADING not in document

    def test_a_reason_is_shown_on_one_line_and_not_obeyed(
        self, reporter, test_plugin_context
    ):
        # A results file a repository committed can carry any text as a reason.
        reason = "first line\n::error::second line \x1b[31mred"
        document = reporter(context=test_plugin_context).report(
            _model(npm_audit=_skipped(reason))
        )

        assert "first line" in document
        assert "\n::error::" not in document
        assert "\x1b" not in document


class TestTheHtmlReportEscapesTheReason:
    def test_markup_in_a_reason_is_text(self, test_plugin_context):
        document = HtmlReporter(context=test_plugin_context).report(
            _model(npm_audit=_skipped("<script>alert(1)</script>"))
        )

        assert "<script>alert(1)</script>" not in document
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in document


class TestTheCompactMarkdownReport:
    """Compact view leaves SKIPPED rows out of the table, and their reasons with
    them. A MISSING scanner needs attention in every view."""

    def _compact(self, context) -> MarkdownReporter:
        reporter = MarkdownReporter(context=context)
        reporter.config = MarkdownReporterConfig.model_validate(
            {"options": {"compact": True}}
        )
        return reporter

    def test_a_skipped_scanners_reason_is_left_out(self, test_plugin_context):
        document = self._compact(test_plugin_context).report(
            _model(npm_audit=_skipped(NO_LOCKFILE))
        )

        assert HEADING not in document
        assert NO_LOCKFILE not in document

    def test_a_missing_scanners_reason_stays(self, test_plugin_context):
        document = self._compact(test_plugin_context).report(
            _model(npm_audit=_skipped(NO_LOCKFILE), grype=_missing(NO_TOOL))
        )

        assert HEADING in document
        assert NO_TOOL in document
        assert NO_LOCKFILE not in document
