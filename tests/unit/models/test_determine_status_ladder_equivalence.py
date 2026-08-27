# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Byte-identical equivalence check for ScanResultsContainer.determine_status.

determine_status was refactored to consume automated_security_helper.utils.
severity_ladder instead of an inline if/elif cascade. This module exists to
prove the refactor changed nothing.

The oracle below is a literal transcription of the cascade as it stood before
the refactor, deliberately kept in its original shape: a sequence of
`counts.X > 0 and threshold in (...)` membership tests. The implementation now
compares integer ranks instead. Two differently-shaped encodings that agree on
the entire cross-product is a real cross-check; asserting the new code against
a rank-based oracle would only assert it against itself.

The oracle is a copy, not an import. If someone changes the gate on purpose,
this file has to be edited too -- that is the point. A test that read the
current implementation could never fail.
"""

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import ScannerSeverityCount
from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)


# ---------------------------------------------------------------------------
# The oracle: the pre-refactor cascade, transcribed verbatim
# ---------------------------------------------------------------------------


def _cascade_oracle(counts: ScannerSeverityCount, threshold) -> ScannerStatus:
    """The exact cascade that lived in scan_results_container.py before.

    Reproduced from git history at beae9ff, lines 144-161. Note that the
    critical check is unconditional, which is why an unrecognised threshold
    string behaves like CRITICAL rather than like a syntax error.
    """
    if not threshold:
        return ScannerStatus.PASSED

    if counts.critical > 0:
        return ScannerStatus.FAILED
    if counts.high > 0 and threshold in ("ALL", "LOW", "MEDIUM", "HIGH"):
        return ScannerStatus.FAILED
    if counts.medium > 0 and threshold in ("ALL", "LOW", "MEDIUM"):
        return ScannerStatus.FAILED
    if counts.low > 0 and threshold in ("ALL", "LOW"):
        return ScannerStatus.FAILED
    if counts.info > 0 and threshold == "ALL":
        return ScannerStatus.FAILED
    return ScannerStatus.PASSED


# ---------------------------------------------------------------------------
# The cross-product inputs
# ---------------------------------------------------------------------------

# Every documented threshold, both falsy forms, plus the values that exercise
# the fall-through arm of the cascade: a wrong-case value and an unknown one.
ALL_THRESHOLDS = [
    "ALL",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
    None,
    "",
    "low",
    "critical",
    "BOGUS",
]

# Each severity alone, several combined, and the all-zero vector.
COUNT_VECTORS = [
    # name, kwargs
    ("all-zero", {}),
    ("critical-only", {"critical": 1}),
    ("high-only", {"high": 1}),
    ("medium-only", {"medium": 1}),
    ("low-only", {"low": 1}),
    ("info-only", {"info": 1}),
    ("high-and-medium", {"high": 2, "medium": 3}),
    ("medium-and-low", {"medium": 1, "low": 5}),
    ("low-and-info", {"low": 1, "info": 9}),
    ("everything", {"critical": 1, "high": 1, "medium": 1, "low": 1, "info": 1}),
    ("everything-but-critical", {"high": 1, "medium": 1, "low": 1, "info": 1}),
    # suppressed is a sibling field on the same model and must not be read by
    # the gate; a vector that sets only suppressed has to pass everywhere.
    ("suppressed-only", {"suppressed": 7}),
]


def _container(**counts) -> ScanResultsContainer:
    return ScanResultsContainer(
        scanner_name="equivalence-probe",
        severity_counts=ScannerSeverityCount(**counts),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDetermineStatusEquivalence:
    """The refactor must agree with the old cascade on every input pair."""

    @pytest.mark.parametrize("threshold", ALL_THRESHOLDS)
    @pytest.mark.parametrize("vector_name,vector", COUNT_VECTORS)
    def test_matches_the_old_cascade(self, threshold, vector_name, vector):
        container = _container(**vector)
        expected = _cascade_oracle(container.severity_counts, threshold)
        actual = container.determine_status(threshold)
        assert actual == expected, (
            f"{vector_name} at threshold {threshold!r}: "
            f"cascade said {expected}, ladder said {actual}"
        )

    def test_the_cross_product_is_actually_covered(self):
        """Guard against a shrinking parametrize list quietly narrowing the proof."""
        assert len(ALL_THRESHOLDS) == 10
        assert len(COUNT_VECTORS) == 12

    def test_both_outcomes_occur(self):
        """A vacuous oracle that always returned PASSED would pass the above."""
        outcomes = {
            _cascade_oracle(ScannerSeverityCount(**vector), threshold)
            for _, vector in COUNT_VECTORS
            for threshold in ALL_THRESHOLDS
        }
        assert outcomes == {ScannerStatus.PASSED, ScannerStatus.FAILED}


class TestDetermineStatusLiteralExpectations:
    """Hand-written expectations, so the gate is readable without the oracle."""

    @pytest.mark.parametrize(
        "threshold,expected",
        [
            ("ALL", ScannerStatus.FAILED),
            ("LOW", ScannerStatus.FAILED),
            ("MEDIUM", ScannerStatus.FAILED),
            ("HIGH", ScannerStatus.FAILED),
            ("CRITICAL", ScannerStatus.PASSED),
        ],
    )
    def test_a_single_high_finding_across_the_ladder(self, threshold, expected):
        """Raising the threshold to CRITICAL lets a HIGH finding through."""
        assert _container(high=1).determine_status(threshold) == expected

    @pytest.mark.parametrize(
        "threshold,expected",
        [
            ("ALL", ScannerStatus.FAILED),
            ("LOW", ScannerStatus.PASSED),
            ("MEDIUM", ScannerStatus.PASSED),
            ("HIGH", ScannerStatus.PASSED),
            ("CRITICAL", ScannerStatus.PASSED),
        ],
    )
    def test_a_single_info_finding_only_fails_under_all(self, threshold, expected):
        assert _container(info=1).determine_status(threshold) == expected

    @pytest.mark.parametrize("threshold", ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    def test_critical_fails_at_every_configured_threshold(self, threshold):
        assert (
            _container(critical=1).determine_status(threshold) == ScannerStatus.FAILED
        )

    @pytest.mark.parametrize("empty", [None, ""])
    def test_a_falsy_threshold_passes_even_a_critical_finding(self, empty):
        """The one case where CRITICAL does not fail: no gate is configured."""
        assert _container(critical=1).determine_status(empty) == ScannerStatus.PASSED

    @pytest.mark.parametrize("threshold", ALL_THRESHOLDS)
    def test_no_findings_always_passes(self, threshold):
        assert _container().determine_status(threshold) == ScannerStatus.PASSED

    def test_determine_status_does_not_mutate_the_container(self):
        """The caller assigns the result; determine_status is a query."""
        container = _container(critical=1)
        container.status = ScannerStatus.PASSED
        assert container.determine_status("HIGH") == ScannerStatus.FAILED
        assert container.status == ScannerStatus.PASSED
