# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import warnings

import pytest

from automated_security_helper.models.asharp_model import (
    ScannerSeverityCount,
    SummaryStats,
)


class TestSummaryStatsNoPydanticWarning:
    def test_no_shadow_warning_on_instantiation(self):
        with warnings.catch_warnings():
            warnings.simplefilter("error", UserWarning)
            # Must not raise UserWarning about 'total' shadowing a parent attribute
            stats = SummaryStats()
        assert stats is not None

    def test_no_shadow_warning_with_kwargs(self):
        with warnings.catch_warnings():
            warnings.simplefilter("error", UserWarning)
            stats = SummaryStats(total=5, critical=2, high=3)
        assert stats.total == 5


class TestSummaryStatsTotalDelegation:
    def test_total_delegates_to_severity_counts_when_not_set(self):
        stats = SummaryStats(severity_counts=ScannerSeverityCount(critical=2, high=3))
        # total not explicitly passed — should sum severity_counts
        assert stats.total == 5

    def test_explicit_total_overrides_severity_counts_sum(self):
        stats = SummaryStats(
            severity_counts=ScannerSeverityCount(critical=2, high=3),
            total=99,
        )
        assert stats.total == 99

    def test_total_default_zero_with_empty_severity_counts(self):
        stats = SummaryStats()
        assert stats.total == 0

    def test_total_reflects_all_severity_levels(self):
        sc = ScannerSeverityCount(critical=1, high=2, medium=3, low=4, info=5)
        stats = SummaryStats(severity_counts=sc)
        assert stats.total == 15


class TestSummaryStatsSeverityForwarding:
    def test_critical_forwards_to_severity_counts(self):
        stats = SummaryStats(severity_counts=ScannerSeverityCount(critical=7))
        assert stats.critical == 7

    def test_high_forwards_to_severity_counts(self):
        stats = SummaryStats(severity_counts=ScannerSeverityCount(high=4))
        assert stats.high == 4

    def test_medium_forwards_to_severity_counts(self):
        stats = SummaryStats(severity_counts=ScannerSeverityCount(medium=3))
        assert stats.medium == 3

    def test_low_forwards_to_severity_counts(self):
        stats = SummaryStats(severity_counts=ScannerSeverityCount(low=2))
        assert stats.low == 2

    def test_info_forwards_to_severity_counts(self):
        stats = SummaryStats(severity_counts=ScannerSeverityCount(info=1))
        assert stats.info == 1

    def test_suppressed_forwards_to_severity_counts(self):
        stats = SummaryStats(severity_counts=ScannerSeverityCount(suppressed=6))
        assert stats.suppressed == 6


class TestSummaryStatsSeverityCountsIndependent:
    def test_mutate_severity_counts_reflects_in_forwarding_property(self):
        # The forwarding properties are live — mutations to severity_counts are visible.
        sc = ScannerSeverityCount(critical=1)
        stats = SummaryStats(severity_counts=sc)
        sc.critical = 5
        assert stats.critical == 5

    def test_total_captured_at_construction_from_severity_counts(self):
        # total is an int field computed at construction; it does not update live.
        sc = ScannerSeverityCount(critical=1)
        stats = SummaryStats(severity_counts=sc)
        assert stats.total == 1  # computed at construction
        sc.critical = 5
        # total still reflects the construction-time value; callers must pass total= explicitly
        # or use bump() to track incremental changes.
        assert stats.total == 1

    def test_mutate_suppressed_reflects_in_forwarding_property(self):
        sc = ScannerSeverityCount(suppressed=2)
        stats = SummaryStats(severity_counts=sc)
        sc.suppressed = 10
        assert stats.suppressed == 10


class TestSummaryStatsBumpCompatibility:
    def test_bump_total_works(self):
        stats = SummaryStats()
        stats.bump("total", 3)
        assert stats.total == 3

    def test_bump_actionable_works(self):
        stats = SummaryStats()
        stats.bump("actionable", 2)
        assert stats.actionable == 2

    def test_bump_passed_works(self):
        stats = SummaryStats()
        stats.bump("passed", 1)
        assert stats.passed == 1


class TestSummaryStatsSerialization:
    def test_model_dump_contains_severity_counts_nested(self):
        stats = SummaryStats(
            severity_counts=ScannerSeverityCount(critical=2, high=1),
            total=3,
            actionable=3,
        )
        d = stats.model_dump()
        assert d["severity_counts"]["critical"] == 2
        assert d["severity_counts"]["high"] == 1
        assert d["total"] == 3
        assert d["actionable"] == 3
        assert "severity_counts" in d

    def test_model_dump_roundtrip(self):
        stats = SummaryStats(
            severity_counts=ScannerSeverityCount(critical=1, high=2, medium=3),
            total=6,
            actionable=6,
            passed=2,
            failed=1,
        )
        d = stats.model_dump()
        restored = SummaryStats.model_validate(d)
        assert restored.critical == 1
        assert restored.high == 2
        assert restored.medium == 3
        assert restored.total == 6
        assert restored.passed == 2
        assert restored.failed == 1
