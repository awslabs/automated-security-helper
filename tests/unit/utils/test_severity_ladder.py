# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the shared severity-threshold ladder.

The ladder encodes one counter-intuitive rule that these tests pin down:
raising a threshold LOOSENS the gate. Every assertion here is written as a
literal expectation rather than derived from the implementation, so that a
change in the ladder's internals cannot quietly move the gate.
"""

import pytest

from automated_security_helper.utils.severity_ladder import (
    SEVERITIES,
    SEVERITY_THRESHOLDS,
    sarif_level_fails_threshold,
    severity_fails_threshold,
    stricter_of,
)


# ---------------------------------------------------------------------------
# Tests: the ordering is data, and it is the documented one
# ---------------------------------------------------------------------------


class TestOrdering:
    """SEVERITY_THRESHOLDS runs strictest to loosest."""

    def test_threshold_order_is_strictest_first(self):
        assert SEVERITY_THRESHOLDS == ("ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_severities_are_most_severe_first(self):
        assert SEVERITIES == ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

    def test_order_is_immutable(self):
        """A tuple, not a list -- callers cannot reorder the ladder in place."""
        assert isinstance(SEVERITY_THRESHOLDS, tuple)
        assert isinstance(SEVERITIES, tuple)


# ---------------------------------------------------------------------------
# Tests: stricter_of
# ---------------------------------------------------------------------------


class TestStricterOf:
    """stricter_of picks whichever threshold gates more findings."""

    @pytest.mark.parametrize(
        "a,b,expected",
        [
            ("ALL", "CRITICAL", "ALL"),
            ("LOW", "HIGH", "LOW"),
            ("MEDIUM", "HIGH", "MEDIUM"),
            ("MEDIUM", "LOW", "LOW"),
            ("CRITICAL", "HIGH", "HIGH"),
            ("ALL", "ALL", "ALL"),
            ("HIGH", "HIGH", "HIGH"),
        ],
    )
    def test_known_pairs(self, a, b, expected):
        assert stricter_of(a, b) == expected

    @pytest.mark.parametrize(
        "a,b,expected",
        [
            ("ALL", "CRITICAL", "ALL"),
            ("LOW", "HIGH", "LOW"),
            ("CRITICAL", "MEDIUM", "MEDIUM"),
        ],
    )
    def test_commutative(self, a, b, expected):
        assert stricter_of(a, b) == expected
        assert stricter_of(b, a) == expected

    def test_commutative_over_full_cross_product(self):
        """Total and commutative for every combination, including the falsy ones."""
        candidates = list(SEVERITY_THRESHOLDS) + [None, "", "BOGUS", "low"]
        for a in candidates:
            for b in candidates:
                assert stricter_of(a, b) == stricter_of(b, a), f"{a!r} vs {b!r}"

    @pytest.mark.parametrize("known", SEVERITY_THRESHOLDS)
    def test_any_real_threshold_beats_no_threshold(self, known):
        """No threshold at all is the loosest value, so it never wins."""
        assert stricter_of(known, None) == known
        assert stricter_of(None, known) == known
        assert stricter_of(known, "") == known
        assert stricter_of("", known) == known

    def test_no_threshold_on_both_sides_is_no_threshold(self):
        assert stricter_of(None, None) is None
        assert stricter_of("", "") is None
        assert stricter_of(None, "") is None
        assert stricter_of("", None) is None

    def test_unrecognised_loses_to_every_recognised_threshold(self):
        """An unrecognised value gates like CRITICAL but never outranks a real one."""
        for known in SEVERITY_THRESHOLDS:
            assert stricter_of("BOGUS", known) == known

    def test_unrecognised_beats_no_threshold(self):
        assert stricter_of("BOGUS", None) == "BOGUS"

    def test_two_unrecognised_values_are_deterministic(self):
        assert stricter_of("BOGUS", "OTHER") == stricter_of("OTHER", "BOGUS")


# ---------------------------------------------------------------------------
# Tests: severity_fails_threshold
#
# The literal table below IS the specification. Each row states, for one
# threshold, exactly which severities fail the gate.
# ---------------------------------------------------------------------------


EXPECTED_FAILING_SEVERITIES = {
    "ALL": {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"},
    "LOW": {"CRITICAL", "HIGH", "MEDIUM", "LOW"},
    "MEDIUM": {"CRITICAL", "HIGH", "MEDIUM"},
    "HIGH": {"CRITICAL", "HIGH"},
    "CRITICAL": {"CRITICAL"},
}


class TestSeverityFailsThreshold:
    """Raising the threshold shrinks the set of severities that fail."""

    @pytest.mark.parametrize("threshold", sorted(EXPECTED_FAILING_SEVERITIES))
    def test_failing_set_matches_the_table(self, threshold):
        actual = {s for s in SEVERITIES if severity_fails_threshold(s, threshold)}
        assert actual == EXPECTED_FAILING_SEVERITIES[threshold]

    def test_raising_the_threshold_never_adds_failures(self):
        """Monotonicity: each step toward CRITICAL is a subset of the last."""
        sets = [
            {s for s in SEVERITIES if severity_fails_threshold(s, t)}
            for t in SEVERITY_THRESHOLDS
        ]
        for looser, stricter in zip(sets[1:], sets[:-1]):
            assert looser < stricter, "each step should strictly shrink the gate"

    @pytest.mark.parametrize("severity", SEVERITIES)
    @pytest.mark.parametrize("empty", [None, ""])
    def test_no_threshold_is_the_most_permissive_value(self, severity, empty):
        """Even CRITICAL passes when no threshold is configured."""
        assert severity_fails_threshold(severity, empty) is False

    def test_no_threshold_is_looser_than_critical(self):
        """The falsy threshold is not a synonym for CRITICAL -- it is looser."""
        assert severity_fails_threshold("CRITICAL", "CRITICAL") is True
        assert severity_fails_threshold("CRITICAL", None) is False

    def test_severity_names_are_case_insensitive(self):
        assert severity_fails_threshold("critical", "HIGH") is True
        assert severity_fails_threshold("MeDiUm", "HIGH") is False

    def test_unrecognised_threshold_gates_like_critical(self):
        """Preserves determine_status, where the critical check is unconditional."""
        assert severity_fails_threshold("CRITICAL", "BOGUS") is True
        assert severity_fails_threshold("HIGH", "BOGUS") is False
        assert severity_fails_threshold("INFO", "BOGUS") is False

    def test_lowercase_threshold_is_not_recognised(self):
        """Threshold matching is case-sensitive, matching the historical cascade."""
        assert severity_fails_threshold("LOW", "low") is False
        assert severity_fails_threshold("CRITICAL", "low") is True

    def test_unrecognised_severity_fails_closed(self):
        """An unexpected severity name must not silently slip past a gate."""
        assert severity_fails_threshold("SEVERE", "CRITICAL") is True
        assert severity_fails_threshold("SEVERE", "ALL") is True
        # ... but a configured absence of a gate still wins.
        assert severity_fails_threshold("SEVERE", None) is False


# ---------------------------------------------------------------------------
# Tests: sarif_level_fails_threshold
#
# SARIF has four levels where ASH has five severities, so the level view
# cannot tell CRITICAL from HIGH. The table below records that.
# ---------------------------------------------------------------------------


EXPECTED_QUALIFYING_LEVELS = {
    "ALL": {"error", "warning", "note", "none"},
    "LOW": {"error", "warning", "note"},
    "MEDIUM": {"error", "warning"},
    "HIGH": {"error"},
    "CRITICAL": {"error"},
}

ALL_SARIF_LEVELS = ("error", "warning", "note", "none")


class TestSarifLevelFailsThreshold:
    """The SARIF-level view of the same ladder."""

    @pytest.mark.parametrize("threshold", sorted(EXPECTED_QUALIFYING_LEVELS))
    def test_qualifying_levels_match_the_table(self, threshold):
        actual = {
            lvl
            for lvl in ALL_SARIF_LEVELS
            if sarif_level_fails_threshold(lvl, threshold)
        }
        assert actual == EXPECTED_QUALIFYING_LEVELS[threshold]

    def test_error_level_cannot_be_told_apart_from_high(self):
        """SARIF collapses CRITICAL and HIGH into 'error', so both gate alike."""
        assert sarif_level_fails_threshold("error", "CRITICAL") is True
        assert sarif_level_fails_threshold("error", "HIGH") is True

    def test_level_is_case_insensitive(self):
        assert sarif_level_fails_threshold("ERROR", "HIGH") is True
        assert sarif_level_fails_threshold("Warning", "MEDIUM") is True

    @pytest.mark.parametrize("empty", [None, ""])
    def test_no_threshold_is_the_most_permissive_value(self, empty):
        for level in ALL_SARIF_LEVELS:
            assert sarif_level_fails_threshold(level, empty) is False

    def test_missing_level_is_treated_as_note(self):
        """Matches run_ash_scan, which reads a missing level as 'note'."""
        assert sarif_level_fails_threshold(None, "LOW") is True
        assert sarif_level_fails_threshold(None, "MEDIUM") is False

    def test_unrecognised_level_is_treated_as_note(self):
        assert sarif_level_fails_threshold("wibble", "LOW") is True
        assert sarif_level_fails_threshold("wibble", "MEDIUM") is False

    def test_accepts_a_sarif_level_enum(self):
        """The reporter reads result.level, which is a str-backed enum."""
        from automated_security_helper.schemas.sarif_schema_model import Level

        assert sarif_level_fails_threshold(Level.error, "HIGH") is True
        assert sarif_level_fails_threshold(Level.warning, "HIGH") is False


# ---------------------------------------------------------------------------
# Tests: the two views agree wherever SARIF is expressive enough
# ---------------------------------------------------------------------------


class TestTheTwoViewsAgree:
    """Guards against the level view and the severity view drifting apart."""

    LEVEL_TO_SEVERITY = {
        "error": "HIGH",
        "warning": "MEDIUM",
        "note": "LOW",
        "none": "INFO",
    }

    @pytest.mark.parametrize("threshold", ["ALL", "LOW", "MEDIUM", "HIGH"])
    def test_views_agree_below_critical(self, threshold):
        """For thresholds that SARIF can express, the two views must match."""
        for level, severity in self.LEVEL_TO_SEVERITY.items():
            assert sarif_level_fails_threshold(
                level, threshold
            ) == severity_fails_threshold(severity, threshold), (
                f"{level}/{severity} disagree at {threshold}"
            )

    def test_views_diverge_only_at_critical_for_error_level(self):
        """The one documented divergence: a HIGH finding under a CRITICAL gate."""
        assert sarif_level_fails_threshold("error", "CRITICAL") is True
        assert severity_fails_threshold("HIGH", "CRITICAL") is False
