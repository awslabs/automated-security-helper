# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How much of a scanner's input it actually evaluated has to reach the output.

WHAT WAS MEASURED
-----------------
A scanner reports per-target counters -- ``targets_attempted`` and ``targets_failed`` -- and
``ScanResultsContainer.determine_status`` only returns ERROR once ``targets_failed >=
targets_attempted``. So total coverage loss is loud and partial coverage loss is silent. Measured
end to end with the real cdk-nag scanner over four trees of three targets each, with the findings
gate off so the exit code reflects coverage alone:

    failing   determine_status   executionSuccessful   exit   summary status
    0/3       PASSED             True                  0      PASSED
    1/3       PASSED             True                  0      PASSED
    2/3       PASSED             True                  0      PASSED
    3/3       ERROR              False                 0      ERROR

The cliff is exactly at "all failed", and 1/3 and 2/3 are indistinguishable from 0/3 in every
status channel. ``scanner_evaluated_nothing`` does not cover this: it keys on
``targets_attempted <= 0``, and here three targets were attempted every time.

On ASH's own repository cdk-nag attempts 10 targets and fails 4 -- a 40% loss reported as a clean
scan. Two of those four are genuine CloudFormation templates that went unscanned; the other two
are a ``mkdocs.yml`` and a ``tsconfig.json`` that were never templates. The signal is hidden among
the noise, which is the reason the counts have to be legible rather than merely present.

WHY THIS FIXES VISIBILITY AND NOT THE VERDICT
---------------------------------------------
``ScannerMetrics`` is the single model the summary table and every reporter read, and it had no
field for either counter. So the counters existed in ``ash_aggregated_results.json`` and in the
scanner's own SARIF and could not reach the table, ``ash.flat.json``, or any human-facing report
even in principle. That is the half of the defect that is purely additive to fix.

Whether a partially-covered scan should FAIL is a separate question with a real blast radius --
at a 40% rate on this repository, "ERROR on any failed target" would turn a routine condition
into a permanent red -- so the status and the exit code are deliberately unchanged here. The
tests below assert that they are unchanged, so that a later change to them is a visible decision
rather than a side effect.

ASSERTIONS ARE ON COUNTS AND CHANNELS, NEVER ON WORDING
-------------------------------------------------------
A test that checked the output mentions unevaluated targets would pass on a cosmetic change while
the numbers stayed wrong. So the counts are asserted through ``coverage_shortfalls``, which
returns structured tuples, and the rendering is asserted only for presence-versus-absence -- the
channel. Each status assertion names the status it requires rather than "not PASSED", which any
wrong status would also satisfy, and every case has a matching negative control.
"""

from unittest.mock import MagicMock

import pytest


def _model(reports: dict):
    """An AshAggregatedResults stand-in carrying the serialized per-target reports.

    ``ScanResultProcessor`` dumps each container with ``exclude_unset=True``, so a scanner that
    does not track targets has no counter keys at all rather than zeroes. That distinction is the
    subject of one of the tests below, so the fixture has to be able to express it.

    ``sarif.runs`` is empty, which keeps every severity count at zero. Without that the findings
    gate would decide the status and the coverage assertions would be measuring the wrong thing.
    """
    model = MagicMock()
    model.sarif = MagicMock()
    model.sarif.runs = []
    model.scanner_results = {}
    model.ash_config = MagicMock()
    model.ash_config.global_settings.severity_threshold = "MEDIUM"
    model.ash_config.get_plugin_config.return_value = None
    model.additional_reports = reports
    return model


def _report(status: str, attempted=None, failed=None, name="cdk-nag") -> dict:
    report = {"scanner_name": name, "status": status, "duration": 1.0}
    if attempted is not None:
        report["targets_attempted"] = attempted
    if failed is not None:
        report["targets_failed"] = failed
    return report


PARTIAL = {
    "cdk-nag": {
        # Two of three source targets could not be evaluated; the converted tree was clean.
        "source": _report("PASSED", attempted=3, failed=2),
        "converted": _report("PASSED", attempted=1, failed=0),
    }
}


class TestTargetCountsReachTheMetrics:
    def test_counts_are_summed_across_every_target_report(self):
        """Both targets contribute, because a scanner gets two and either can lose coverage.

        Exact totals are asserted rather than "greater than zero": summing only the source report
        would give (3, 2) and reading only the converted one (1, 0), and both would satisfy a
        loose assertion while dropping half the input.
        """
        from automated_security_helper.core.unified_metrics import (
            get_unified_scanner_metrics,
        )

        metrics = {
            m.scanner_name: m for m in get_unified_scanner_metrics(_model(PARTIAL))
        }

        assert metrics["cdk-nag"].targets_attempted == 4
        assert metrics["cdk-nag"].targets_failed == 2

    def test_a_scanner_that_does_not_track_targets_makes_no_claim(self):
        """None, not zero. The distinction is load-bearing.

        ``targets_attempted`` is tri-state in the container for a documented reason: absent means
        "this scanner does not track targets", and 0 means "it tracked and attempted none". bandit,
        checkov, semgrep, grype, syft, detect-secrets, opengrep, cfn-nag and npm-audit are all in
        the first state. Collapsing them to 0 would report every one of them as having evaluated
        nothing.
        """
        from automated_security_helper.core.unified_metrics import (
            get_unified_scanner_metrics,
        )

        model = _model({"bandit": {"source": _report("PASSED", name="bandit")}})
        metrics = {m.scanner_name: m for m in get_unified_scanner_metrics(model)}

        assert metrics["bandit"].targets_attempted is None
        assert metrics["bandit"].targets_failed == 0

    def test_the_counts_are_serialized_with_the_rest_of_the_metrics(self):
        """``ash.flat.json`` is a verbatim dump of these rows, so presence here is user-visible.

        Asserted on the dump rather than on the attributes, because a field excluded from
        serialization would satisfy the attribute assertions above and still never reach a file.
        """
        from automated_security_helper.core.unified_metrics import (
            get_unified_scanner_metrics,
        )

        dumped = get_unified_scanner_metrics(_model(PARTIAL))[0].model_dump()

        assert dumped["targets_attempted"] == 4
        assert dumped["targets_failed"] == 2


class TestTheCountsReachTheMachineReadableReports:
    """``ReportContentEmitter.get_scanner_results()`` is a hand-built dict, not a model dump.

    Worth its own test because assuming otherwise was wrong. Adding the fields to
    ``ScannerMetrics`` made them serializable but did NOT put them in ``ash.flat.json``: that
    reporter goes through this emitter, which enumerates its keys explicitly, so a new field on
    the model reaches the file only if it is listed here too. Measured before the fix --
    ``targets_attempted`` was absent from a real ``ash.flat.json`` even with the model field
    populated.
    """

    def test_the_emitted_scanner_row_carries_both_counts(self):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
            ReportContentEmitter,
        )

        emitter = ReportContentEmitter(_model(PARTIAL))
        rows = {r["scanner_name"]: r for r in emitter.get_scanner_results()}

        assert rows["cdk-nag"]["targets_attempted"] == 4
        assert rows["cdk-nag"]["targets_failed"] == 2

    def test_a_non_tracking_scanner_emits_null_rather_than_zero(self):
        """null and 0 are different claims, and a consumer has to be able to tell them apart."""
        from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
            ReportContentEmitter,
        )

        emitter = ReportContentEmitter(
            _model({"bandit": {"source": _report("PASSED", name="bandit")}})
        )
        rows = {r["scanner_name"]: r for r in emitter.get_scanner_results()}

        assert rows["bandit"]["targets_attempted"] is None
        assert rows["bandit"]["targets_failed"] == 0


class TestCoverageShortfallsAreEnumerated:
    def test_a_scanner_that_lost_targets_is_reported_with_its_counts(self):
        """The structured channel the renderer formats, asserted as data rather than as prose."""
        from automated_security_helper.core.unified_metrics import coverage_shortfalls

        assert coverage_shortfalls(_model(PARTIAL)) == [("cdk-nag", 4, 2)]

    def test_a_scanner_that_lost_nothing_is_absent(self):
        """The negative control that stops the fix from warning about every scan."""
        from automated_security_helper.core.unified_metrics import coverage_shortfalls

        clean = {"cdk-nag": {"source": _report("PASSED", attempted=3, failed=0)}}
        assert coverage_shortfalls(_model(clean)) == []

    def test_a_non_tracking_scanner_is_absent(self):
        """No claim is not a shortfall.

        Without this, a fix reading the absent counters as zeroes would list every non-tracking
        scanner as having lost coverage.
        """
        from automated_security_helper.core.unified_metrics import coverage_shortfalls

        model = _model({"bandit": {"source": _report("PASSED", name="bandit")}})
        assert coverage_shortfalls(model) == []

    def test_a_total_loss_is_reported_too(self):
        """The all-failed case is a shortfall as well, not only the partial one.

        Its status already says ERROR, but the count of what went unevaluated is exactly as
        absent from the table there as it is in the partial case.
        """
        from automated_security_helper.core.unified_metrics import coverage_shortfalls

        total = {"cdk-nag": {"source": _report("ERROR", attempted=3, failed=3)}}
        assert coverage_shortfalls(_model(total)) == [("cdk-nag", 3, 3)]


class TestTheVerdictIsDeliberatelyUnchanged:
    @pytest.mark.parametrize("failed", [1, 2])
    def test_partial_coverage_loss_still_reports_passed(self, failed: int):
        """Named as PASSED, not as "not ERROR".

        This change makes the loss legible and does not turn it into a failure, because at the
        measured 40% rate on this repository that would make a routine condition a permanent red.
        Asserting the exact status means a later decision to fail on partial coverage has to
        change this test, which is where such a decision should be visible.
        """
        from automated_security_helper.core.unified_metrics import (
            get_unified_scanner_metrics,
        )

        model = _model(
            {"cdk-nag": {"source": _report("PASSED", attempted=3, failed=failed)}}
        )
        metrics = {m.scanner_name: m for m in get_unified_scanner_metrics(model)}

        assert metrics["cdk-nag"].status == "PASSED"
        assert metrics["cdk-nag"].passed is True

    def test_total_coverage_loss_still_reports_error(self):
        """The existing cliff is preserved, so the fix cannot flatten it either."""
        from automated_security_helper.core.unified_metrics import (
            get_unified_scanner_metrics,
        )

        model = _model({"cdk-nag": {"source": _report("ERROR", attempted=3, failed=3)}})
        metrics = {m.scanner_name: m for m in get_unified_scanner_metrics(model)}

        assert metrics["cdk-nag"].status == "ERROR"
        assert metrics["cdk-nag"].passed is False


class TestTheShortfallReachesTheMarkdownSummary:
    """``ash.summary.md`` is the artifact a human pastes into a pull request.

    Presence, absence, and the counts -- but not the sentence around them. The scanner table in
    that report keeps its fixed ten-column shape, which is asserted elsewhere and parsed
    positionally, so the shortfall is appended after it rather than added to it.
    """

    def _render(self, reports: dict, test_plugin_context, compact: bool = False) -> str:
        """Constructed with ``context=`` because the reporter is a pydantic model whose
        ``AshAggregatedResults`` annotation is a TYPE_CHECKING forward reference; without a
        context it is not fully defined and instantiation raises. Every existing reporter test
        uses the same form.
        """
        from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
            MarkdownReporter,
        )

        reporter = MarkdownReporter(context=test_plugin_context)
        reporter.report(_model(reports))  # resolves self.config from defaults
        reporter.config.options.compact = compact
        return reporter.report(_model(reports))

    def test_a_shortfall_is_listed_with_its_counts(self, test_plugin_context):
        out = self._render(PARTIAL, test_plugin_context)

        assert "cdk-nag" in out
        # 2 of 4 evaluated, 2 failed -- the arithmetic, not the phrasing.
        assert "2 of 4" in out
        assert "2 could not be evaluated" in out

    def test_nothing_is_listed_when_no_coverage_was_lost(self, test_plugin_context):
        """The negative control. Without it, a section emitted unconditionally would pass above."""
        clean = {"cdk-nag": {"source": _report("PASSED", attempted=3, failed=0)}}

        assert "Incomplete coverage" not in self._render(clean, test_plugin_context)

    def test_compact_mode_still_reports_it(self, test_plugin_context):
        """Compact mode drops noise; a coverage gap is signal.

        Asserted because compact is the rendering most likely to be pasted into a pull request,
        so suppressing the notice there would remove it from the place it matters most.
        """
        out = self._render(PARTIAL, test_plugin_context, compact=True)

        assert "2 of 4" in out

    def test_the_scanner_table_keeps_its_column_count(self, test_plugin_context):
        """The shortfall must not have been implemented as an extra column after all.

        Counts the pipes in the header row. A test asserting only that the shortfall appears
        would pass either way, and a twelfth column would silently break every positional
        consumer of this table.
        """
        out = self._render(PARTIAL, test_plugin_context)
        header = [line for line in out.splitlines() if line.startswith("| Scanner")]
        assert header, f"no scanner table header found in:\n{out[:600]}"
        assert header[0].count("|") == 11, (
            f"the ten-column scanner table changed shape: {header[0]}"
        )


class TestTheShortfallReachesTheConsole:
    """Presence versus absence only -- the channel, not the wording.

    The counts are already pinned by ``TestCoverageShortfallsAreEnumerated`` against structured
    output. Asserting the rendered sentence here as well would be asserting prose, which is what
    passes on a cosmetic change while a miscount survives.
    """

    def _render(self, model) -> str:
        from io import StringIO

        from rich.console import Console

        from automated_security_helper.core.metrics_table import (
            print_coverage_shortfalls,
        )

        buffer = StringIO()
        print_coverage_shortfalls(
            model, Console(file=buffer, width=200, color_system=None)
        )
        return buffer.getvalue()

    def test_a_shortfall_is_printed_and_names_the_scanner_and_both_counts(self):
        out = self._render(_model(PARTIAL))

        assert out.strip(), "a scanner lost coverage and the console said nothing"
        assert "cdk-nag" in out
        # The numbers, so a renderer that printed a bare warning without them fails here.
        assert "4" in out and "2" in out

    def test_nothing_is_printed_when_no_coverage_was_lost(self):
        clean = {"cdk-nag": {"source": _report("PASSED", attempted=3, failed=0)}}

        assert self._render(_model(clean)) == ""
