# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests: the junitxml reporter honours every severity threshold.

The reporter used to decide actionability with a cascade that had branches for
CRITICAL, HIGH and MEDIUM only. LOW and ALL fell through, leaving is_actionable
at its initial True. For ALL that coincided with the right answer, because
every SARIF level qualifies under ALL. For LOW it did not: a result at level
`none` maps to INFO, which is below a LOW threshold, yet the reporter treated
it as actionable.

That cell is reachable. cdk_nag_wrapper.py:321-342 emits Level.none with
Kind.informational for compliant results, so under a LOW threshold a passing
compliance check was rendered as a bare passing test case rather than
`<skipped type="threshold">`. Any scanner leaving `kind` at the model default
of Kind.fail got worse: its below-threshold finding was rendered as `<error>`.
Either way the reporter disagreed with the exit code, which reads level `none`
as below a LOW threshold.

The matrix below pins all twenty cells so the fall-through cannot come back.
"""

import xml.etree.ElementTree as ET  # nosec B405

import pytest

from automated_security_helper.schemas.sarif_schema_model import Kind, Level

from tests.unit.plugin_modules.ash_builtin.reporters.test_junitxml_reporter import (
    _get_reporter,
    _make_model,
    _make_result,
    _make_run,
)


# ---------------------------------------------------------------------------
# The qualifying-level table, transcribed from the exit-code path
#
# Copied verbatim from _THRESHOLD_QUALIFYING_LEVELS in
# run_ash_scan._compute_exit_code. It is a function-local dict there, so it
# cannot be imported; transcribing it is the point -- if the reporter and the
# exit code ever disagree about a level again, this table catches it.
# ---------------------------------------------------------------------------

THRESHOLD_QUALIFYING_LEVELS = {
    "ALL": {"error", "warning", "note", "none"},
    "LOW": {"error", "warning", "note"},
    "MEDIUM": {"error", "warning"},
    "HIGH": {"error"},
    "CRITICAL": {"error"},
}

ALL_SARIF_LEVELS = ("error", "warning", "note", "none")


def _render_one(tmp_path, level, threshold, kind=None):
    """Report a single finding and return its testcase element."""
    result = _make_result(
        level=level,
        scanner_name="scanner1",
        severity_threshold=threshold,
    )
    if kind is not None:
        result.kind = kind
    model = _make_model(runs=[_make_run(results=[result])])
    output = _get_reporter(tmp_path).report(model)
    return ET.fromstring(output).find(".//testcase")  # nosec B314


def _outcome(testcase) -> str:
    """Reduce a testcase to 'actionable', 'below-threshold' or 'silent'."""
    if testcase.find("skipped") is not None:
        return "below-threshold"
    if testcase.find("error") is not None:
        return "actionable"
    return "silent"


# ---------------------------------------------------------------------------
# Tests: the cell that was wrong
# ---------------------------------------------------------------------------


class TestLowThresholdIgnoresInfoFindings:
    """The bug: level `none` was actionable under a LOW threshold."""

    def test_none_level_under_low_threshold_is_below_threshold(self, tmp_path):
        """Was <error> (kind defaults to fail); must be skipped as below threshold."""
        testcase = _render_one(tmp_path, level="none", threshold="LOW")
        assert _outcome(testcase) == "below-threshold"
        skipped = testcase.find("skipped")
        assert skipped.get("type") == "threshold"

    def test_none_level_as_cdk_nag_emits_it(self, tmp_path):
        """cdk-nag's real shape: Level.none plus Kind.informational.

        Was rendered as a bare passing test case, which silently claimed a
        below-threshold finding had been evaluated and passed.
        """
        testcase = _render_one(
            tmp_path, level=Level.none, threshold="LOW", kind=Kind.informational
        )
        assert _outcome(testcase) == "below-threshold"

    def test_note_level_under_low_threshold_stays_actionable(self, tmp_path):
        """LOW does gate on `note`, so this cell was already right."""
        assert _outcome(_render_one(tmp_path, "note", "LOW")) == "actionable"


# ---------------------------------------------------------------------------
# Tests: ALL was right by accident; keep it right on purpose
# ---------------------------------------------------------------------------


class TestAllThresholdGatesEverything:
    """Under ALL, no level is below threshold -- including `none`."""

    @pytest.mark.parametrize("level", ALL_SARIF_LEVELS)
    def test_every_level_is_actionable(self, tmp_path, level):
        assert _outcome(_render_one(tmp_path, level, "ALL")) == "actionable"

    def test_nothing_is_ever_skipped_as_below_threshold(self, tmp_path):
        for level in ALL_SARIF_LEVELS:
            testcase = _render_one(tmp_path, level, "ALL")
            assert testcase.find("skipped") is None, level


# ---------------------------------------------------------------------------
# Tests: the whole matrix, and agreement with the exit-code table
# ---------------------------------------------------------------------------


class TestThresholdMatrix:
    """All five thresholds against all four levels."""

    @pytest.mark.parametrize("threshold", sorted(THRESHOLD_QUALIFYING_LEVELS))
    @pytest.mark.parametrize("level", ALL_SARIF_LEVELS)
    def test_matches_the_exit_code_qualifying_levels(self, tmp_path, level, threshold):
        """The reporter and the exit code must agree on every cell."""
        qualifies = level in THRESHOLD_QUALIFYING_LEVELS[threshold]
        expected = "actionable" if qualifies else "below-threshold"
        actual = _outcome(_render_one(tmp_path, level, threshold))
        assert actual == expected, (
            f"threshold={threshold} level={level}: exit code says "
            f"{'qualifying' if qualifies else 'below threshold'}, "
            f"reporter says {actual}"
        )

    def test_raising_the_threshold_never_adds_actionable_findings(self, tmp_path):
        """Monotonicity, end to end through the reporter."""
        ladder = ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        sets = [
            {
                lvl
                for lvl in ALL_SARIF_LEVELS
                if _outcome(_render_one(tmp_path, lvl, t)) == "actionable"
            }
            for t in ladder
        ]
        for looser, stricter in zip(sets[1:], sets[:-1]):
            assert looser <= stricter, "a higher threshold must not gate on more"

    def test_both_outcomes_occur_in_the_matrix(self, tmp_path):
        """Guards against a matrix that is uniformly one value."""
        outcomes = {
            _outcome(_render_one(tmp_path, lvl, t))
            for t in THRESHOLD_QUALIFYING_LEVELS
            for lvl in ALL_SARIF_LEVELS
        }
        assert outcomes == {"actionable", "below-threshold"}


# ---------------------------------------------------------------------------
# Tests: the paths the fix must not disturb
# ---------------------------------------------------------------------------


class TestUntouchedPaths:
    """The fix is scoped to the level cascade; these paths must not move."""

    def test_no_threshold_property_leaves_findings_actionable(self, tmp_path):
        """With no threshold in properties, the reporter still fails the finding.

        The ladder treats a falsy threshold as the most permissive value, but
        here a missing threshold means "not stated" rather than "gate off", so
        the reporter's `if threshold and result.level` guard is preserved and
        the finding stays actionable.
        """
        for level in ALL_SARIF_LEVELS:
            testcase = _render_one(tmp_path, level, threshold=None)
            assert testcase.find("skipped") is None, level

    def test_below_threshold_property_still_wins(self, tmp_path):
        """An explicit below_threshold property short-circuits the level check."""
        result = _make_result(
            level="error", scanner_name="scanner1", below_threshold=True
        )
        model = _make_model(runs=[_make_run(results=[result])])
        output = _get_reporter(tmp_path).report(model)
        testcase = ET.fromstring(output).find(".//testcase")  # nosec B314
        assert _outcome(testcase) == "below-threshold"

    def test_respect_severity_threshold_disabled_bypasses_the_ladder(self, tmp_path):
        """The opt-out must still skip threshold evaluation entirely."""
        from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
            JUnitXMLReporterConfig,
            JUnitXMLReporterConfigOptions,
        )

        config = JUnitXMLReporterConfig(
            options=JUnitXMLReporterConfigOptions(respect_severity_threshold=False)
        )
        result = _make_result(
            level="none", scanner_name="scanner1", severity_threshold="LOW"
        )
        model = _make_model(runs=[_make_run(results=[result])])
        output = _get_reporter(tmp_path, config=config).report(model)
        testcase = ET.fromstring(output).find(".//testcase")  # nosec B314
        assert testcase.find("skipped") is None
