# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for methods on ScannerSeverityCount, SummaryStats, ScannerTargetStatusInfo,
and ScannerStatusInfo."""

import pytest
from datetime import datetime

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import (
    ScannerSeverityCount,
    SummaryStats,
    ScannerTargetStatusInfo,
    ScannerStatusInfo,
)


class TestScannerSeverityCountTotal:
    """ScannerSeverityCount.total property."""

    def test_total_is_zero_when_all_counts_zero(self):
        sc = ScannerSeverityCount()
        assert sc.total == 0

    def test_total_sums_all_severity_fields(self):
        sc = ScannerSeverityCount(
            critical=1, high=2, medium=3, low=4, info=5
        )
        assert sc.total == 15

    def test_total_excludes_suppressed(self):
        sc = ScannerSeverityCount(
            suppressed=10, critical=1, high=1, medium=1, low=1, info=1
        )
        # suppressed is NOT included in total
        assert sc.total == 5

    def test_total_with_only_critical(self):
        sc = ScannerSeverityCount(critical=7)
        assert sc.total == 7

    def test_total_with_only_suppressed_is_zero(self):
        sc = ScannerSeverityCount(suppressed=42)
        assert sc.total == 0


class TestScannerSeverityCountActionableCount:
    """ScannerSeverityCount.actionable_count(threshold)."""

    def test_critical_threshold_only_critical(self):
        sc = ScannerSeverityCount(
            critical=2, high=3, medium=4, low=5, info=6
        )
        assert sc.actionable_count("critical") == 2

    def test_high_threshold_includes_critical_and_high(self):
        sc = ScannerSeverityCount(
            critical=2, high=3, medium=4, low=5, info=6
        )
        assert sc.actionable_count("high") == 5

    def test_medium_threshold(self):
        sc = ScannerSeverityCount(
            critical=2, high=3, medium=4, low=5, info=6
        )
        assert sc.actionable_count("medium") == 9

    def test_low_threshold(self):
        sc = ScannerSeverityCount(
            critical=2, high=3, medium=4, low=5, info=6
        )
        assert sc.actionable_count("low") == 14

    def test_info_threshold_same_as_total(self):
        sc = ScannerSeverityCount(
            critical=2, high=3, medium=4, low=5, info=6
        )
        assert sc.actionable_count("info") == 20
        assert sc.actionable_count("info") == sc.total

    def test_threshold_is_case_insensitive(self):
        sc = ScannerSeverityCount(critical=2, high=3)
        assert sc.actionable_count("HIGH") == 5
        assert sc.actionable_count("High") == 5

    def test_invalid_threshold_raises(self):
        sc = ScannerSeverityCount()
        with pytest.raises(ValueError):
            sc.actionable_count("bogus")


class TestScannerSeverityCountIncrement:
    """ScannerSeverityCount.increment(severity)."""

    def test_increment_critical(self):
        sc = ScannerSeverityCount()
        sc.increment("critical")
        assert sc.critical == 1
        assert sc.high == 0

    def test_increment_multiple_times(self):
        sc = ScannerSeverityCount()
        sc.increment("high")
        sc.increment("high")
        sc.increment("high")
        assert sc.high == 3

    def test_increment_suppressed_allowed(self):
        sc = ScannerSeverityCount()
        sc.increment("suppressed")
        assert sc.suppressed == 1

    def test_increment_is_case_insensitive(self):
        sc = ScannerSeverityCount()
        sc.increment("HIGH")
        assert sc.high == 1

    def test_increment_invalid_raises(self):
        sc = ScannerSeverityCount()
        with pytest.raises(ValueError):
            sc.increment("not-a-severity")


class TestScannerSeverityCountMaxSeverity:
    """ScannerSeverityCount.max_severity()."""

    def test_critical_wins(self):
        sc = ScannerSeverityCount(critical=1, high=10, medium=100, low=1, info=1)
        assert sc.max_severity() == "critical"

    def test_high_when_no_critical(self):
        sc = ScannerSeverityCount(critical=0, high=3, low=1)
        assert sc.max_severity() == "high"

    def test_medium_when_no_critical_or_high(self):
        sc = ScannerSeverityCount(medium=2, low=5, info=10)
        assert sc.max_severity() == "medium"

    def test_low_when_only_low(self):
        sc = ScannerSeverityCount(low=1)
        assert sc.max_severity() == "low"

    def test_info_when_only_info(self):
        sc = ScannerSeverityCount(info=1)
        assert sc.max_severity() == "info"

    def test_all_zero_returns_none(self):
        sc = ScannerSeverityCount()
        # Either "none" or "info" are acceptable; we pick "none" as distinct signal.
        assert sc.max_severity() == "none"

    def test_suppressed_does_not_influence_max(self):
        sc = ScannerSeverityCount(suppressed=99)
        assert sc.max_severity() == "none"


class TestSummaryStatsSetTiming:
    """SummaryStats.set_timing(start, end, duration)."""

    def test_set_timing_sets_all_three_fields(self):
        stats = SummaryStats()
        start = datetime(2024, 1, 1, 12, 0, 0)
        end = datetime(2024, 1, 1, 12, 5, 30)
        stats.set_timing(start, end, 330.0)
        assert stats.start == start
        assert stats.end == end
        assert stats.duration == 330.0

    def test_set_timing_accepts_string_timestamps(self):
        stats = SummaryStats()
        stats.set_timing("2024-01-01T12:00:00", "2024-01-01T12:05:00", 300.0)
        assert stats.start == "2024-01-01T12:00:00"
        assert stats.end == "2024-01-01T12:05:00"
        assert stats.duration == 300.0


class TestScannerTargetStatusInfoTotalDuration:
    """ScannerTargetStatusInfo.total_duration property (alias for duration)."""

    def test_total_duration_matches_duration(self):
        info = ScannerTargetStatusInfo(duration=12.5)
        assert info.total_duration == 12.5

    def test_total_duration_zero_default(self):
        info = ScannerTargetStatusInfo()
        assert info.total_duration == 0.0

    def test_total_duration_handles_none(self):
        info = ScannerTargetStatusInfo(duration=None)
        # When duration is None, total_duration should be 0.0 (not crash)
        assert info.total_duration == 0.0


class TestScannerStatusInfoIsDualLayer:
    """ScannerStatusInfo.is_dual_layer property."""

    def test_is_dual_layer_false_when_both_default(self):
        info = ScannerStatusInfo()
        # Both source and converted are default (PASSED, zero counts) — not dual
        assert info.is_dual_layer is False

    def test_is_dual_layer_true_when_both_have_findings(self):
        source = ScannerTargetStatusInfo(
            severity_counts=ScannerSeverityCount(critical=1)
        )
        converted = ScannerTargetStatusInfo(
            severity_counts=ScannerSeverityCount(high=2)
        )
        info = ScannerStatusInfo(source=source, converted=converted)
        assert info.is_dual_layer is True

    def test_is_dual_layer_false_when_only_source_has_findings(self):
        source = ScannerTargetStatusInfo(
            severity_counts=ScannerSeverityCount(critical=1)
        )
        info = ScannerStatusInfo(source=source)
        assert info.is_dual_layer is False

    def test_is_dual_layer_true_when_both_failed(self):
        source = ScannerTargetStatusInfo(status=ScannerStatus.FAILED)
        converted = ScannerTargetStatusInfo(status=ScannerStatus.FAILED)
        info = ScannerStatusInfo(source=source, converted=converted)
        assert info.is_dual_layer is True
