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
    Suppression,
)


def _make_result(*, level: Level, suppressed: bool = False) -> Result:
    """Build a minimal Result with or without a suppression entry."""
    suppressions = None
    if suppressed:
        suppressions = [Suppression(kind=Kind1.inSource, justification="test")]
    return Result(
        ruleId="TEST-001",
        level=level,
        message=Message(text="test finding"),
        suppressions=suppressions,
    )


class TestIsSuppressed:
    """_is_suppressed must return True only when suppressions is non-empty."""

    def test_result_without_suppressions_is_not_suppressed(self):
        result = _make_result(level=Level.error, suppressed=False)
        assert HtmlReporter._is_suppressed(result) is False

    def test_result_with_suppressions_is_suppressed(self):
        result = _make_result(level=Level.warning, suppressed=True)
        assert HtmlReporter._is_suppressed(result) is True


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

        assert "SUPPRESSED" not in groups
        assert "WARNING" in groups
        assert len(groups["WARNING"]) == 1

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
        assert len(groups.get("ERROR", [])) == 1
        assert len(groups.get("NOTE", [])) == 1
