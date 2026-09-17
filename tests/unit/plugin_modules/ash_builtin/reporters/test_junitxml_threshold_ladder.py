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
    ALL_SARIF_LEVELS,
    THRESHOLD_QUALIFYING_LEVELS,
    _get_reporter,
    _make_model,
    _make_result,
    _make_run,
    _outcome,
)

# THRESHOLD_QUALIFYING_LEVELS, ALL_SARIF_LEVELS and _outcome used to be defined
# here as a second copy. They now live in the helper module both threshold test
# files import from, next to the test that ties the table to the ladder.

# The two sources a threshold can come from. Every cell below runs against both.
#
# `property` was the only source these tests ever exercised, which made them
# unrepresentative rather than useless: the branch is live code and a broken
# ladder mapping would still fail here, but after the threshold-source fix the
# path a real scan takes is `config`, and no shipped scanner writes the property.
# Testing one source told you nothing about the other, and the one being tested
# was the one nothing uses.
THRESHOLD_SOURCES = ("config", "property")


def _render_one(tmp_path, level, threshold, kind=None, source="config"):
    """Report a single finding and return its testcase element.

    *source* selects where the reporter is made to read *threshold* from:

    ``config``
        ``model.ash_config.global_settings.severity_threshold`` -- the
        production path, and what the exit code reads.
    ``property``
        ``result.properties.severity_threshold`` -- the per-result override,
        which takes precedence where a producer supplies it. Nothing in ASH
        writes it today, so this arm guards the precedence rule rather than a
        shipped code path.

    When *source* is ``property`` the config is pinned to a threshold that would
    give the opposite answer wherever the two differ, so a cell that passes
    because the reporter silently fell back to the config cannot be mistaken for
    the property being honoured.
    """
    if source == "property":
        result = _make_result(
            level=level, scanner_name="scanner1", severity_threshold=threshold
        )
    else:
        result = _make_result(level=level, scanner_name="scanner1")

    if kind is not None:
        result.kind = kind

    model = _make_model(runs=[_make_run(results=[result])])
    if source == "property":
        # A deliberate disagreement: ALL makes everything actionable, so any cell
        # expecting below-threshold can only pass if the property won. CRITICAL
        # is used when the property itself is ALL, for the same reason inverted.
        model.ash_config.global_settings.severity_threshold = (
            "CRITICAL" if threshold == "ALL" else "ALL"
        )
    else:
        model.ash_config.global_settings.severity_threshold = threshold

    output = _get_reporter(tmp_path).report(model)
    return ET.fromstring(output).find(".//testcase")  # nosec B314


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

    @pytest.mark.parametrize("source", THRESHOLD_SOURCES)
    @pytest.mark.parametrize("threshold", sorted(THRESHOLD_QUALIFYING_LEVELS))
    @pytest.mark.parametrize("level", ALL_SARIF_LEVELS)
    def test_matches_the_exit_code_qualifying_levels(
        self, tmp_path, level, threshold, source
    ):
        """The reporter and the exit code must agree on every cell, from either source.

        Forty cells, not twenty: five thresholds by four levels by both threshold
        sources. The `config` arm is the production path; the `property` arm
        guards the precedence rule, and is constructed so the config would give
        the opposite answer, which is what makes it a test of precedence rather
        than a second run of the config arm.
        """
        qualifies = level in THRESHOLD_QUALIFYING_LEVELS[threshold]
        expected = "actionable" if qualifies else "below-threshold"
        actual = _outcome(_render_one(tmp_path, level, threshold, source=source))
        assert actual == expected, (
            f"source={source} threshold={threshold} level={level}: exit code says "
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

    def test_no_threshold_property_falls_back_to_the_configured_threshold(
        self, tmp_path
    ):
        """With no threshold in properties, the config decides.

        What changed, and why. This test used to assert the opposite: that a
        finding with no ``properties.severity_threshold`` stayed actionable at
        every level. The reasoning was that an absent property means "threshold
        not stated" rather than "gate off", so the finding should not be
        silently skipped.

        The rebuttal, and it is the whole argument: **"not stated" is the only
        case that ever occurs in production.** Nothing in ASH writes
        ``properties.severity_threshold`` -- it had exactly one reader, in the
        reporter, and no writer anywhere in the repository. So a policy defined
        for the not-stated case is not an edge-case policy at all; it is the
        policy for every real finding. Measured, not argued: the ``ash.sarif``
        that CI published on this branch carries 217 results and *zero* of them
        have that property.

        Read that way the old reasoning inverts. "Leave it actionable because the
        threshold was not stated" sounds conservative when you picture it firing
        on the odd finding that lost its metadata. Applied to every finding, it
        means the threshold never gates anything, which is not conservatism --
        it is the gate being switched off while appearing to be on. What the test
        pinned was the bug: with no threshold in hand the reporter never
        consulted the ladder, ``is_actionable`` kept its initial True, and the
        ``Skipped`` branch was dead code. A sub-threshold finding was reported as
        ``<error>`` -- ``result.kind`` defaults to ``Kind.fail``, which satisfies
        the kind check before ``level`` is looked at -- so the reporter
        contradicted the exit code on exactly the findings the threshold exists
        to filter.

        Recorded because a future reader who finds only a flipped assertion here
        will reasonably suspect someone weakened a test to make a change pass.
        The assertion is stricter, not weaker: it now names an expected outcome
        per level, so both directions of drift fail it, where the original only
        checked for the absence of one element.

        The threshold is now read from
        ``model.ash_config.global_settings.severity_threshold``, the field the
        exit code reads. An absent property is no longer an absent threshold, so
        "not stated" no longer arises: under MEDIUM, `note` and `none` are below
        the gate and `error` and `warning` are not.

        The original concern survives one step further down, at the
        ``if threshold and ...`` guards, which are kept for the case where the
        configured threshold really is falsy. See
        test_junitxml_config_threshold.py for the config-driven matrix.
        """
        gated = {}
        for level in ALL_SARIF_LEVELS:
            result = _make_result(level=level, scanner_name="scanner1")
            model = _make_model(runs=[_make_run(results=[result])])
            # Set explicitly rather than relying on the default, which
            # get_default_config() reads from ASH_CONFIG when that is set.
            model.ash_config.global_settings.severity_threshold = "MEDIUM"
            output = _get_reporter(tmp_path).report(model)
            testcase = ET.fromstring(output).find(".//testcase")  # nosec B314
            gated[level] = testcase.find("skipped") is not None

        assert gated == {
            "error": False,
            "warning": False,
            "note": True,
            "none": True,
        }

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
