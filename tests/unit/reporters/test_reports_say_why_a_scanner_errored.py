# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The reports say why a scanner ended in ERROR.

The scanner table showed ERROR and the summary said "Check their dependencies and
execution logs"; the reason was only in ``ash.log`` and in the ``errors`` of the
scanner's per-target reports in ``ash_aggregated_results.json``. The reports now
list an ERROR scanner under "Scanners that did not run" with the first sentence
of its recorded failure, without the paths, stderr and details that follow it.

A scanner whose row records why it failed (``error_reason``, which the scan phase
and the executor write) is listed with that sentence instead, once it passes the
check for a short sentence with no path in it that the scan phase writes by. The
first sentence of the error is read for an error that recorded no reason.
"""

import pytest

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
    ScannerTargetStatusInfo,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters import (
    report_content_emitter,
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


#: What a scanner's row records when the scan phase or the executor said why it
#: failed: a code and one sentence with no path in it. It is not what the first
#: sentence of CHECKOV_EXIT says, so a test that finds it in a report knows the
#: recorded reason was shown and not the error beside it.
RECORDED_CODE = "timed_out"
RECORDED_REASON = "it timed out after 30 s and was killed"
#: A recorded sentence with a path in it, as a results file edited by hand or
#: written by another tool can hold.
PLANTED = "could not read /home/me/secret/results.json"


def _recorded(
    *names: str,
    sentence: object = RECORDED_REASON,
    code: object = RECORDED_CODE,
    errors: tuple = (),
) -> AshAggregatedResults:
    """A scan in which each named scanner's ERROR row records why it failed.

    ``errors`` are the errors its per-target report holds beside the row, the text
    the first-sentence reading starts from. None by default, so the row's own
    reason is all there is to show; ``sentence=None`` and ``code=None`` record
    no reason.
    """
    model = AshAggregatedResults(ash_config=get_default_config())
    for name in names or ("checkov",):
        model.scanner_results[name] = ScannerTargetStatusInfo(
            status=ScannerStatus.ERROR,
            error_reason=sentence,
            error_reason_code=code,
        )
        model.additional_reports[name] = {
            "source": {
                "scanner_name": name,
                "status": "ERROR",
                "errors": list(errors),
            }
        }
    model._flat_cache = None
    return model


def _beside_a_recorded_reason(model: AshAggregatedResults) -> AshAggregatedResults:
    """``model`` with a second scanner whose row records a reason a report must list.

    A test that expects a report to leave something out passes before the reasons
    are read at all, when nothing is read to be left out. Beside a scanner whose
    reason is listed, it passes only once a recorded reason is read and this one
    is the only thing the report holds back.
    """
    model.scanner_results["trivy"] = ScannerTargetStatusInfo(
        status=ScannerStatus.ERROR,
        error_reason=RECORDED_REASON,
        error_reason_code=RECORDED_CODE,
    )
    model.additional_reports["trivy"] = {
        "source": {"scanner_name": "trivy", "status": "ERROR", "errors": []}
    }
    model._flat_cache = None
    return model


#: What the second scanner of ``_beside_a_recorded_reason`` is listed with.
BESIDE = ("ERROR", RECORDED_REASON)

#: What a report says for a scanner that failed on 1 of its 3 targets and recorded no
#: reason, when no error gives a sentence to show.
COUNTED = "it failed on 1 of its 3 target(s)"


def _counted(error: str = CHECKOV_EXIT, home: str = "errors") -> AshAggregatedResults:
    """A scan in which checkov ended in ERROR with *error*, after it counted 1 of 3
    targets failed: how a scan() that raised after a failed target leaves its report.

    ``home`` is where the error is recorded: the report's own ``errors`` (the scan
    phase's, for a scanner it could not build) or the ``errors`` of its
    ``raw_results``, the failure dict the executor writes for a scan that raised.
    """
    model = _model(checkov=[error] if home == "errors" else [])
    report = model.additional_reports["checkov"]["source"]
    report.update(targets_attempted=3, targets_failed=1)
    if home == "raw_results":
        report["raw_results"] = {
            "status": "failed",
            "errors": [error],
            "exception": "the scan raised",
        }
    model._flat_cache = None
    return model


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


class TestTheEmitterListsTheRecordedReason:
    """The reason a row records is listed in place of the first sentence of the error."""

    def test_the_recorded_reason_is_listed(self):
        assert _entries(_recorded()) == {"checkov": ("ERROR", RECORDED_REASON)}

    def test_it_is_listed_instead_of_the_first_sentence_of_the_error(self):
        model = _recorded(errors=(CHECKOV_EXIT,))

        assert _entries(model) == {"checkov": ("ERROR", RECORDED_REASON)}

    def test_an_error_that_recorded_no_reason_is_listed_by_its_first_sentence(self):
        model = _recorded(sentence=None, code=None, errors=(CHECKOV_EXIT,))

        assert _entries(_beside_a_recorded_reason(model)) == {
            "checkov": ("ERROR", CHECKOV_REASON),
            "trivy": BESIDE,
        }

    @pytest.mark.parametrize(
        "errors", [(), ("something the scan phase did not write",)]
    )
    def test_a_scanner_with_neither_has_no_entry(self, errors):
        model = _recorded(sentence=None, code=None, errors=errors)

        assert _entries(_beside_a_recorded_reason(model)) == {"trivy": BESIDE}

    def test_a_sentence_with_no_code_is_not_a_recorded_reason(self):
        model = _recorded(code=None, errors=(CHECKOV_EXIT,))

        assert _entries(_beside_a_recorded_reason(model)) == {
            "checkov": ("ERROR", CHECKOV_REASON),
            "trivy": BESIDE,
        }

    def test_scanners_that_recorded_the_same_reason_share_an_entry(self):
        entries = ReportContentEmitter(
            _recorded("checkov", "trivy")
        ).get_scanners_not_run()

        assert entries == [
            {
                "scanners": ["checkov", "trivy"],
                "status": "ERROR",
                "reason": RECORDED_REASON,
            }
        ]

    def test_the_counts_of_an_error_only_the_statistics_decided_are_listed(self):
        model = AshAggregatedResults(ash_config=get_default_config())
        model.additional_reports["checkov"] = {
            "source": {
                "scanner_name": "checkov",
                "status": "ERROR",
                "targets_attempted": 3,
                "targets_failed": 2,
            }
        }
        model._flat_cache = None

        assert _entries(model) == {
            "checkov": ("ERROR", "it failed on 2 of its 3 target(s)")
        }

    def test_a_scanner_in_error_for_a_stale_database_is_still_left_to_its_own_heading(
        self, monkeypatch
    ):
        from automated_security_helper.utils import content_db_staleness

        monkeypatch.setattr(
            content_db_staleness,
            "scanners_in_error_for_a_stale_database",
            lambda model: {"checkov"},
        )

        assert _entries(_beside_a_recorded_reason(_recorded())) == {"trivy": BESIDE}


class TestASentenceThatSaysWhyOutranksTheCounts:
    """A scanner that raised after it counted a failed target is listed with its error.

    The counts of a scan that raised read as a partial loss, and the first sentence of
    its error says what failed. The reports list the sentence, and the row records no
    reason made from the counts beside it, so the row and the reports agree.
    """

    @pytest.mark.parametrize("home", ["errors", "raw_results"])
    def test_the_emitter_lists_the_first_sentence(self, home):
        assert _entries(_counted(home=home)) == {"checkov": ("ERROR", CHECKOV_REASON)}

    @pytest.mark.parametrize("home", ["errors", "raw_results"])
    def test_the_row_records_no_reason_beside_it(self, home):
        rebuilt = populate_metrics_from_unified_source(_counted(home=home))

        row = rebuilt.scanner_results["checkov"]

        assert row.error_reason is None
        assert row.error_reason_code is None

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param("something the scan phase did not write", id="no prefix"),
            pytest.param(FAILED + "could not read /etc/hosts", id="a path"),
        ],
    )
    def test_control_an_error_with_no_sentence_to_show_leaves_the_counts_listed(
        self, error
    ):
        assert _entries(_counted(error)) == {"checkov": ("ERROR", COUNTED)}

    def test_the_first_sentence_is_read_from_the_report_read_first(self):
        """The report with no scan phase decision, then the source tree's, then any
        other, as the unified metrics read a scanner's reports; not the order a results
        file happened to write them in."""
        model = _model(checkov=[])
        model.additional_reports["checkov"] = {
            "converted": {
                "scanner_name": "checkov",
                "status": "ERROR",
                "errors": [GITLEAKS_SARIF],
            },
            "source": {
                "scanner_name": "checkov",
                "status": "ERROR",
                "errors": [CHECKOV_EXIT],
            },
        }
        model._flat_cache = None

        assert _entries(model) == {"checkov": ("ERROR", CHECKOV_REASON)}

    def test_text(self, test_plugin_context):
        text = TextReporter(context=test_plugin_context).report(_counted())

        assert f"- checkov (ERROR): {CHECKOV_REASON}" in text
        assert COUNTED not in text

    @pytest.mark.parametrize("compact", [False, True])
    def test_markdown(self, test_plugin_context, compact):
        reporter = MarkdownReporter(context=test_plugin_context)
        reporter.config = MarkdownReporterConfig.model_validate(
            {"options": {"compact": compact}}
        )

        markdown = reporter.report(_counted())

        assert f"- checkov (ERROR): {CHECKOV_REASON}" in markdown
        assert COUNTED not in markdown

    def test_html(self, test_plugin_context):
        page = HtmlReporter(context=test_plugin_context).report(_counted())

        assert f"<strong>checkov</strong> (ERROR): {CHECKOV_REASON}" in page
        assert COUNTED not in page


class TestTheFirstSentenceIsOneLine:
    """The first sentence of an error is held to the rule a recorded reason is held to.

    A bare line break does not end a sentence, so the text up to the next full stop
    could run over two lines and break a Markdown bullet or table row.
    """

    @pytest.mark.parametrize(
        "sentence",
        [
            "line one\nline two",
            "line one\r\nline two",
            "tab\tseparated",
            "escape \x1b[31m red",
        ],
    )
    def test_an_error_whose_first_sentence_is_not_one_line_has_no_entry(self, sentence):
        assert _entries(_model(checkov=[FAILED + sentence])) == {}

    def test_a_first_sentence_that_ends_at_the_line_break_is_still_listed(self):
        model = _model(checkov=[FAILED + "its tool failed.\nthe next line"])

        assert _entries(model) == {"checkov": ("ERROR", "its tool failed")}


class TestAPathInARecordedReasonIsNotShown:
    """A results file read back by ``ash report`` can hold any text in ``error_reason``.

    The scan phase writes sentences with no path in them, but this is where a
    results file's text reaches a reader, so the emitter holds it to the same
    check again.
    """

    NOT_SHORT_REASONS = [
        pytest.param(PLANTED, id="posix-path"),
        pytest.param("could not read C:\\Users\\me\\scan\\out", id="drive-path"),
        pytest.param("could not read ~/scan/out", id="home-path"),
        pytest.param("its tool wrote to \\\\server\\share\\out", id="unc-path"),
        pytest.param("y" * (SHORT_ERROR_REASON_LIMIT + 1), id="over-the-limit"),
        pytest.param("its tool said\nsomething else", id="two-lines"),
        pytest.param("its tool said\tsomething else", id="control-character"),
    ]

    @pytest.mark.parametrize("sentence", NOT_SHORT_REASONS)
    def test_it_is_not_listed(self, sentence):
        model = _beside_a_recorded_reason(_recorded(sentence=sentence))

        assert _entries(model) == {"trivy": BESIDE}

    @pytest.mark.parametrize("sentence", NOT_SHORT_REASONS)
    def test_the_first_sentence_of_the_error_is_read_instead(self, sentence):
        model = _beside_a_recorded_reason(
            _recorded(sentence=sentence, errors=(CHECKOV_EXIT,))
        )

        assert _entries(model) == {
            "checkov": ("ERROR", CHECKOV_REASON),
            "trivy": BESIDE,
        }

    def test_control_without_the_check_the_path_is_listed(self, monkeypatch):
        """The check at render is what keeps the planted path out: remove it and it shows."""
        monkeypatch.setattr(
            report_content_emitter,
            "is_short_reason",
            lambda text: isinstance(text, str) and bool(text),
        )

        assert _entries(_recorded(sentence=PLANTED)) == {"checkov": ("ERROR", PLANTED)}


class TestEveryReportShowsTheRecordedReason:
    def test_text(self, test_plugin_context):
        text = TextReporter(context=test_plugin_context).report(
            _recorded(errors=(CHECKOV_EXIT,))
        )

        assert HEADING in text
        assert f"- checkov (ERROR): {RECORDED_REASON}" in text
        assert CHECKOV_REASON not in text

    @pytest.mark.parametrize("compact", [False, True])
    def test_markdown(self, test_plugin_context, compact):
        reporter = MarkdownReporter(context=test_plugin_context)
        reporter.config = MarkdownReporterConfig.model_validate(
            {"options": {"compact": compact}}
        )

        markdown = reporter.report(_recorded(errors=(CHECKOV_EXIT,)))

        assert HEADING in markdown
        assert f"- checkov (ERROR): {RECORDED_REASON}" in markdown
        assert CHECKOV_REASON not in markdown

    def test_html(self, test_plugin_context):
        page = HtmlReporter(context=test_plugin_context).report(
            _recorded(errors=(CHECKOV_EXIT,))
        )

        assert f"<strong>checkov</strong> (ERROR): {RECORDED_REASON}" in page
        assert CHECKOV_REASON not in page


class TestNoReportShowsAPlantedPath:
    """The scanner with the planted path is held back; the one beside it is listed."""

    def test_text(self, test_plugin_context):
        text = TextReporter(context=test_plugin_context).report(
            _beside_a_recorded_reason(_recorded(sentence=PLANTED))
        )

        assert "/home/me" not in text
        assert "- checkov (ERROR)" not in text
        assert f"- trivy (ERROR): {RECORDED_REASON}" in text

    @pytest.mark.parametrize("compact", [False, True])
    def test_markdown(self, test_plugin_context, compact):
        reporter = MarkdownReporter(context=test_plugin_context)
        reporter.config = MarkdownReporterConfig.model_validate(
            {"options": {"compact": compact}}
        )

        markdown = reporter.report(
            _beside_a_recorded_reason(_recorded(sentence=PLANTED))
        )

        assert "/home/me" not in markdown
        assert "- checkov (ERROR)" not in markdown
        assert f"- trivy (ERROR): {RECORDED_REASON}" in markdown

    def test_html(self, test_plugin_context):
        page = HtmlReporter(context=test_plugin_context).report(
            _beside_a_recorded_reason(_recorded(sentence=PLANTED))
        )

        assert "/home/me" not in page
        assert "<strong>checkov</strong> (ERROR)" not in page
        assert f"<strong>trivy</strong> (ERROR): {RECORDED_REASON}" in page


class TestTheScannerResultsRowsCarryTheReason:
    """``ash.flat.json`` writes these rows as they are, so the reason reaches it too."""

    def test_an_error_row_has_the_recorded_reason_and_its_code(self):
        (row,) = ReportContentEmitter(_recorded()).get_scanner_results()

        assert row["error_reason"] == RECORDED_REASON
        assert row["error_reason_code"] == RECORDED_CODE

    def test_an_error_row_that_recorded_none_has_none(self):
        model = _recorded(sentence=None, code=None, errors=(CHECKOV_EXIT,))

        (row,) = ReportContentEmitter(model).get_scanner_results()

        assert row["error_reason"] is None
        assert row["error_reason_code"] is None

    def test_a_row_that_is_not_in_error_has_none_whatever_its_row_kept(self):
        model = _recorded()
        model.scanner_results["bandit"] = ScannerTargetStatusInfo(
            status=ScannerStatus.PASSED,
            error_reason=RECORDED_REASON,
            error_reason_code=RECORDED_CODE,
        )
        model.additional_reports["bandit"] = {
            "source": {"scanner_name": "bandit", "status": "PASSED"}
        }
        model._flat_cache = None

        rows = {
            row["scanner_name"]: row
            for row in ReportContentEmitter(model).get_scanner_results()
        }

        assert rows["bandit"]["error_reason"] is None
        assert rows["bandit"]["error_reason_code"] is None
        assert rows["checkov"]["error_reason"] == RECORDED_REASON
