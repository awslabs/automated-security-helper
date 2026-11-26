# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The reports say why a scanner ended in ERROR.

The scanner table showed ERROR and the summary said "Check their dependencies and
execution logs"; the reason was only in ``ash.log`` and in the ``errors`` of the
scanner's per-target reports in ``ash_aggregated_results.json``. The reports now
list an ERROR scanner under "Scanners that did not run" with the first sentence
of its recorded failure, without the paths, stderr and details that follow it.
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
    SHORT_ERROR_REASON_LIMIT,
    ReportContentEmitter,
    short_error_reason,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
)

pytestmark = pytest.mark.unit

HEADING = "Scanners that did not run"

#: Recorded by a checkov run that exited 2 (a Kustomize overlay, checkov 3.4.6).
CHECKOV_EXIT = (
    "Failed to execute checkov scanner on source: CheckovScanner scan failed: its "
    "tool (launched through uv tool run as ~/repo/.venv/bin/uv) exited with code 2, "
    "which this scanner does not accept as a completed run, so its results file is "
    "not graded (exit code 2: not an accepted exit code; success_exit_codes=[0, 1]). "
    "Stderr not read: ASH refused this result, so its outputs (the stderr log at "
    "/home/me/out/scanners/checkov/source/CheckovScanner.stderr.log) were not read. "
    "The tool's output is in /home/me/out/scanners/checkov/source/"
    "CheckovScanner.stdout.log"
)
CHECKOV_REASON = (
    "its tool exited with code 2, which this scanner does not accept as a completed "
    "run, so its results file is not graded"
)
#: Recorded by gitleaks for a report SARIF validation refused.
GITLEAKS_SARIF = (
    "Failed to execute gitleaks scanner on source: GitleaksScanner scan failed: its "
    "results file is not SARIF ASH can read, so its findings could not be graded: 9 "
    "validation errors for SarifReport: Invalid value at 'runs[0].results[1]...'"
)
GITLEAKS_REASON = (
    "its results file is not SARIF ASH can read, so its findings could not be graded"
)
#: The prefix the scan phase writes for a scanner whose scan failed.
FAILED = "Failed to execute x scanner on source: XScanner scan failed: "
TIMED_OUT = (
    "Failed to execute gitleaks scanner on source: GitleaksScanner timed out after "
    "'1' s and was killed. Raise scanners.gitleaks.options.scan_timeout"
)


def _model(**errors: list) -> AshAggregatedResults:
    """A scan in which each named scanner ended in ERROR with the given errors."""
    model = AshAggregatedResults(ash_config=get_default_config())
    for name, recorded in errors.items():
        scanner = name.replace("_", "-")
        model.scanner_results[scanner] = ScannerStatusInfo(status=ScannerStatus.ERROR)
        model.additional_reports[scanner] = {
            "source": {"scanner_name": scanner, "status": "ERROR", "errors": recorded}
        }
    model._flat_cache = None
    return model


def _entries(model: AshAggregatedResults) -> dict:
    return {
        name: (entry["status"], entry["reason"])
        for entry in ReportContentEmitter(model).get_scanners_not_run()
        for name in entry["scanners"]
    }


class TestTheShortReason:
    @pytest.mark.parametrize(
        "error, reason",
        [
            (CHECKOV_EXIT, CHECKOV_REASON),
            (GITLEAKS_SARIF, GITLEAKS_REASON),
            (TIMED_OUT, "GitleaksScanner timed out after '1' s and was killed"),
        ],
    )
    def test_the_first_sentence_without_its_asides(self, error, reason):
        assert short_error_reason(error) == reason

    @pytest.mark.parametrize(
        "error",
        [
            "",
            "something the scan phase did not write",
            "Failed to execute x scanner on source: ",
            FAILED + "could not read /etc/hosts",
            FAILED + "could not read C:\\scan\\out",
            FAILED + "could not read ~/scan",
            FAILED + "an unclosed (aside",
            FAILED + "y" * (SHORT_ERROR_REASON_LIMIT + 1),
        ],
    )
    def test_a_failure_without_a_safe_short_sentence_has_none(self, error):
        assert short_error_reason(error) is None

    def test_a_sentence_at_the_limit_is_kept(self):
        sentence = "y" * SHORT_ERROR_REASON_LIMIT
        error = FAILED + sentence + ". more"

        assert short_error_reason(error) == sentence


class TestTheEmitterListsEachErroredScanner:
    def test_each_scanner_has_the_reason_of_its_error(self):
        found = _entries(_model(checkov=[CHECKOV_EXIT], gitleaks=[GITLEAKS_SARIF]))

        assert found == {
            "checkov": ("ERROR", CHECKOV_REASON),
            "gitleaks": ("ERROR", GITLEAKS_REASON),
        }

    def test_the_first_error_with_a_short_reason_is_used(self):
        found = _entries(_model(checkov=["not the scan phase's", CHECKOV_EXIT]))

        assert found == {"checkov": ("ERROR", CHECKOV_REASON)}

    @pytest.mark.parametrize(
        "recorded",
        [[], ["something the scan phase did not write"], None, "a string", [7]],
    )
    def test_a_scanner_with_no_short_reason_has_no_entry(self, recorded):
        assert _entries(_model(checkov=recorded)) == {}

    def test_scanners_that_failed_the_same_way_share_an_entry(self):
        same = CHECKOV_EXIT.replace("checkov", "trivy").replace("Checkov", "Trivy")
        entries = ReportContentEmitter(
            _model(checkov=[CHECKOV_EXIT], trivy=[same])
        ).get_scanners_not_run()

        assert entries == [
            {
                "scanners": ["checkov", "trivy"],
                "status": "ERROR",
                "reason": CHECKOV_REASON,
            }
        ]

    def test_a_scanner_in_error_for_a_stale_database_is_left_to_its_own_heading(
        self, monkeypatch
    ):
        from automated_security_helper.utils import content_db_staleness

        monkeypatch.setattr(
            content_db_staleness,
            "scanners_in_error_for_a_stale_database",
            lambda model: {"checkov"},
        )

        assert _entries(_model(checkov=[CHECKOV_EXIT])) == {}


class TestEveryReportShowsIt:
    def test_text(self, test_plugin_context):
        text = TextReporter(context=test_plugin_context).report(
            _model(checkov=[CHECKOV_EXIT])
        )

        assert HEADING in text
        assert f"- checkov (ERROR): {CHECKOV_REASON}" in text
        assert "/home/me" not in text

    @pytest.mark.parametrize("compact", [False, True])
    def test_markdown(self, test_plugin_context, compact):
        reporter = MarkdownReporter(context=test_plugin_context)
        reporter.config = MarkdownReporterConfig.model_validate(
            {"options": {"compact": compact}}
        )

        markdown = reporter.report(_model(checkov=[CHECKOV_EXIT]))

        assert HEADING in markdown
        assert "- checkov (ERROR): its tool exited with code 2" in markdown
        assert "/home/me" not in markdown

    def test_html(self, test_plugin_context):
        page = HtmlReporter(context=test_plugin_context).report(
            _model(checkov=[CHECKOV_EXIT])
        )

        assert f"<strong>checkov</strong> (ERROR): {CHECKOV_REASON}" in page
        assert "/home/me" not in page
