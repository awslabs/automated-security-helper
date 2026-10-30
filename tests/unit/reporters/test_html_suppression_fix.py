"""Regression tests for #182: HTML report must filter suppressed findings.

Before the fix, suppressed findings were grouped alongside active findings
by severity.  Now ``_is_suppressed`` detects the ``suppressions`` list and
``_group_results_by_severity`` routes those results into a dedicated
"SUPPRESSED" bucket instead of inflating the active severity counts.
"""

import pytest

from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Kind1,
    Level,
    Message,
    Result,
    State,
    Suppression,
)

pytestmark = pytest.mark.unit


def _make_result(
    *, level: Level, suppressed: bool = False, state: State | None = None
) -> Result:
    """Build a minimal Result with or without a suppression entry.

    *state* is the suppression's SARIF ``state``; None leaves it unset, which
    reads as in effect.
    """
    suppressions = None
    if suppressed:
        suppressions = [
            Suppression(kind=Kind1.inSource, justification="test", state=state)
        ]
    return Result(
        ruleId="TEST-001",
        level=level,
        message=Message(text="test finding"),
        suppressions=suppressions,
    )


class TestIsSuppressed:
    """_is_suppressed must return True only for a suppression in effect."""

    def test_result_without_suppressions_is_not_suppressed(self):
        result = _make_result(level=Level.error, suppressed=False)
        assert HtmlReporter._is_suppressed(result) is False

    def test_result_with_suppressions_is_suppressed(self):
        result = _make_result(level=Level.warning, suppressed=True)
        assert HtmlReporter._is_suppressed(result) is True

    def test_an_accepted_suppression_suppresses(self):
        result = _make_result(
            level=Level.warning, suppressed=True, state=State.accepted
        )
        assert HtmlReporter._is_suppressed(result) is True

    @pytest.mark.parametrize("state", [State.rejected, State.underReview])
    def test_a_suppression_not_in_effect_does_not_suppress(self, state):
        """A suppression rejected by the reviewer or still under review has not
        taken effect (SARIF 3.35.4): the gate still fails the scan on the finding,
        and the report filed it under Suppressed on the entry's presence alone."""
        result = _make_result(level=Level.error, suppressed=True, state=state)
        assert HtmlReporter._is_suppressed(result) is False


class TestSuppressedRowReasons:
    """The Reason column names the suppressions in effect, not the rejected ones."""

    def test_only_the_reasons_in_effect_are_shown(self, test_plugin_context):
        finding = Result(
            ruleId="TEST-002",
            level=Level.error,
            message=Message(text="test finding"),
            suppressions=[
                Suppression(
                    kind=Kind1.external,
                    justification="rejected-by-review",
                    state=State.rejected,
                ),
                Suppression(
                    kind=Kind1.inSource,
                    justification="accepted-reason",
                    state=State.accepted,
                ),
            ],
        )
        reporter = HtmlReporter(context=test_plugin_context)

        table = reporter._format_findings_table([finding])

        assert "Suppressed Findings (1)" in table
        assert "accepted-reason" in table
        assert "rejected-by-review" not in table

    def test_a_finding_with_only_a_rejected_suppression_is_active(
        self, test_plugin_context
    ):
        finding = _make_result(level=Level.error, suppressed=True, state=State.rejected)
        reporter = HtmlReporter(context=test_plugin_context)

        table = reporter._format_findings_table([finding])

        # The finding is in the table as an active row: the rule column names
        # it, no suppressed group is rendered, and the empty-table notice is
        # absent. Absence alone would also pass for an empty string.
        assert "TEST-001" in table
        assert "Suppressed Findings" not in table
        assert "No active findings to display" not in table


class TestGroupResultsBySeverity:
    """Suppressed findings must land in the SUPPRESSED group, not a severity group."""

    def _group(self, results, test_plugin_context):
        reporter = HtmlReporter(context=test_plugin_context)
        return reporter._group_results_by_severity(results)

    def test_suppressed_finding_in_suppressed_group(self, test_plugin_context):
        active = _make_result(level=Level.error, suppressed=False)
        suppressed = _make_result(level=Level.error, suppressed=True)

        groups = self._group([active, suppressed], test_plugin_context)

        assert "SUPPRESSED" in groups
        assert len(groups["SUPPRESSED"]) == 1
        assert groups["SUPPRESSED"][0] is suppressed

    def test_active_finding_not_in_suppressed_group(self, test_plugin_context):
        active = _make_result(level=Level.warning, suppressed=False)

        groups = self._group([active], test_plugin_context)

        # Grouped by the gate's severity (warning is MEDIUM), not by SARIF level.
        assert "SUPPRESSED" not in groups
        assert "MEDIUM" in groups
        assert len(groups["MEDIUM"]) == 1

    def test_mixed_results_separated_correctly(self, test_plugin_context):
        active_err = _make_result(level=Level.error, suppressed=False)
        active_note = _make_result(level=Level.note, suppressed=False)
        suppressed_err = _make_result(level=Level.error, suppressed=True)
        suppressed_note = _make_result(level=Level.note, suppressed=True)

        groups = self._group(
            [active_err, active_note, suppressed_err, suppressed_note],
            test_plugin_context,
        )

        assert len(groups.get("SUPPRESSED", [])) == 2
        assert len(groups.get("CRITICAL", [])) == 1
        assert len(groups.get("LOW", [])) == 1
