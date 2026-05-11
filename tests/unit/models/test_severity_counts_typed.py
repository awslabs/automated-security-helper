"""Tests for typed severity_counts refactors.

Covers:
- ScanResultsContainer.severity_counts field is a ScannerSeverityCount instance
- ScannerMetrics inherits from ScannerSeverityCount
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.unified_metrics import ScannerMetrics
from automated_security_helper.models.asharp_model import ScannerSeverityCount
from automated_security_helper.models.scan_results_container import ScanResultsContainer


# ---------------------------------------------------------------------------
# Refactor A: ScanResultsContainer.severity_counts as ScannerSeverityCount
# ---------------------------------------------------------------------------


class TestContainerSeverityCountsType:
    """ScanResultsContainer.severity_counts is a typed ScannerSeverityCount."""

    def test_default_severity_counts_is_scanner_severity_count_instance(self):
        container = ScanResultsContainer()
        assert isinstance(container.severity_counts, ScannerSeverityCount)

    def test_default_severity_counts_all_zero(self):
        container = ScanResultsContainer()
        sc = container.severity_counts
        assert sc.critical == 0
        assert sc.high == 0
        assert sc.medium == 0
        assert sc.low == 0
        assert sc.info == 0
        assert sc.suppressed == 0

    def test_two_containers_have_independent_severity_counts(self):
        """Regression: default_factory must not share the same instance."""
        a = ScanResultsContainer(scanner_name="a")
        b = ScanResultsContainer(scanner_name="b")
        assert a.severity_counts is not b.severity_counts
        a.severity_counts.critical = 5
        assert b.severity_counts.critical == 0


class TestContainerSeverityCountsIncrement:
    """increment() works through the container."""

    def test_increment_critical_via_attribute(self):
        container = ScanResultsContainer()
        container.severity_counts.increment("critical")
        assert container.severity_counts.critical == 1

    def test_increment_is_case_insensitive(self):
        container = ScanResultsContainer()
        container.severity_counts.increment("HIGH")
        assert container.severity_counts.high == 1

    def test_increment_multiple_times(self):
        container = ScanResultsContainer()
        for _ in range(3):
            container.severity_counts.increment("medium")
        assert container.severity_counts.medium == 3

    def test_increment_invalid_raises(self):
        container = ScanResultsContainer()
        with pytest.raises(ValueError):
            container.severity_counts.increment("bogus")


class TestContainerSeverityCountsTotal:
    """The .total property is accessible through the container."""

    def test_total_default_zero(self):
        container = ScanResultsContainer()
        assert container.severity_counts.total == 0

    def test_total_sums_severities_excluding_suppressed(self):
        container = ScanResultsContainer()
        container.severity_counts.critical = 1
        container.severity_counts.high = 2
        container.severity_counts.medium = 3
        container.severity_counts.low = 4
        container.severity_counts.info = 5
        container.severity_counts.suppressed = 99  # excluded
        assert container.severity_counts.total == 15


class TestContainerDetermineStatus:
    """determine_status() works after the type change."""

    def _container_with(self, **counts) -> ScanResultsContainer:
        c = ScanResultsContainer(scanner_name="test")
        for key, value in counts.items():
            setattr(c.severity_counts, key, value)
        return c

    def test_determine_status_passed_with_no_counts(self):
        c = ScanResultsContainer(scanner_name="test")
        assert c.determine_status("HIGH") == ScannerStatus.PASSED

    def test_determine_status_critical_triggers_failure(self):
        c = self._container_with(critical=1)
        assert c.determine_status("CRITICAL") == ScannerStatus.FAILED

    def test_determine_status_high_over_high_threshold(self):
        c = self._container_with(high=3)
        assert c.determine_status("HIGH") == ScannerStatus.FAILED

    def test_determine_status_high_under_critical_threshold_passed(self):
        c = self._container_with(high=3)
        assert c.determine_status("CRITICAL") == ScannerStatus.PASSED

    def test_determine_status_medium_over_medium_threshold(self):
        c = self._container_with(medium=5)
        assert c.determine_status("MEDIUM") == ScannerStatus.FAILED

    def test_determine_status_info_only_at_all_threshold(self):
        c = self._container_with(info=2)
        assert c.determine_status("ALL") == ScannerStatus.FAILED
        assert c.determine_status("LOW") == ScannerStatus.PASSED

    def test_determine_status_empty_threshold_is_passed(self):
        c = self._container_with(critical=99)
        assert c.determine_status(None) == ScannerStatus.PASSED
        assert c.determine_status("") == ScannerStatus.PASSED


class TestContainerSerialization:
    """Serialization produces the expected dict structure."""

    def test_model_dump_contains_severity_counts_dict(self):
        """severity_counts dumps as a dict with the expected keys."""
        container = ScanResultsContainer(scanner_name="test")
        container.severity_counts.critical = 2
        container.severity_counts.high = 3
        dumped = container.model_dump()
        assert "severity_counts" in dumped
        sc = dumped["severity_counts"]
        assert isinstance(sc, dict)
        # All expected severity fields present
        for key in ("critical", "high", "medium", "low", "info", "suppressed"):
            assert key in sc
        assert sc["critical"] == 2
        assert sc["high"] == 3

    def test_model_dump_roundtrip_restores_counts(self):
        """Dumping then validating restores the counts."""
        container = ScanResultsContainer(scanner_name="test")
        container.severity_counts.critical = 7
        container.severity_counts.low = 4
        dumped = container.model_dump()
        restored = ScanResultsContainer.model_validate(dumped)
        assert restored.severity_counts.critical == 7
        assert restored.severity_counts.low == 4
        assert isinstance(restored.severity_counts, ScannerSeverityCount)

    def test_validate_from_dict_input(self):
        """A raw dict input for severity_counts is coerced to ScannerSeverityCount."""
        container = ScanResultsContainer.model_validate(
            {
                "scanner_name": "test",
                "severity_counts": {
                    "critical": 1,
                    "high": 2,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                    "suppressed": 0,
                },
            }
        )
        assert isinstance(container.severity_counts, ScannerSeverityCount)
        assert container.severity_counts.critical == 1
        assert container.severity_counts.high == 2


# ---------------------------------------------------------------------------
# Refactor B: ScannerMetrics inherits ScannerSeverityCount
# ---------------------------------------------------------------------------


def _make_metrics(**overrides) -> ScannerMetrics:
    defaults = dict(
        scanner_name="test_scanner",
        duration=1.5,
        status="PASSED",
        threshold="HIGH",
        threshold_source="config",
        excluded=False,
        dependencies_missing=False,
    )
    defaults.update(overrides)
    return ScannerMetrics(**defaults)


class TestScannerMetricsInheritance:
    """ScannerMetrics inherits severity fields from ScannerSeverityCount."""

    def test_scanner_metrics_is_scanner_severity_count_subclass(self):
        assert issubclass(ScannerMetrics, ScannerSeverityCount)

    def test_scanner_metrics_instance_is_scanner_severity_count(self):
        m = _make_metrics()
        assert isinstance(m, ScannerSeverityCount)

    def test_scanner_metrics_has_inherited_severity_fields(self):
        m = _make_metrics(critical=1, high=2, medium=3, low=4, info=5, suppressed=6)
        assert m.critical == 1
        assert m.high == 2
        assert m.medium == 3
        assert m.low == 4
        assert m.info == 5
        assert m.suppressed == 6


class TestScannerMetricsTotalProperty:
    """Inherited .total property works on ScannerMetrics."""

    def test_total_defaults_to_zero(self):
        m = _make_metrics()
        assert m.total == 0

    def test_total_sums_severities(self):
        m = _make_metrics(critical=1, high=2, medium=3, low=4, info=5)
        assert m.total == 15

    def test_total_excludes_suppressed(self):
        m = _make_metrics(suppressed=10, critical=1)
        assert m.total == 1


class TestScannerMetricsActionableCount:
    """Inherited actionable_count() works on ScannerMetrics."""

    def test_actionable_count_at_high_threshold(self):
        m = _make_metrics(critical=2, high=3, medium=4, low=5, info=6)
        assert m.actionable_count("high") == 5

    def test_actionable_count_at_critical_threshold(self):
        m = _make_metrics(critical=2, high=3, medium=4, low=5, info=6)
        assert m.actionable_count("critical") == 2

    def test_actionable_count_at_low_threshold(self):
        m = _make_metrics(critical=2, high=3, medium=4, low=5, info=6)
        assert m.actionable_count("low") == 14


class TestScannerMetricsOwnFields:
    """ScannerMetrics still declares its own non-severity fields."""

    def test_has_scanner_name(self):
        m = _make_metrics(scanner_name="bandit")
        assert m.scanner_name == "bandit"

    def test_has_duration(self):
        m = _make_metrics(duration=4.2)
        assert m.duration == 4.2

    def test_has_status(self):
        m = _make_metrics(status="FAILED")
        assert m.status == "FAILED"

    def test_has_threshold(self):
        m = _make_metrics(threshold="MEDIUM", threshold_source="global")
        assert m.threshold == "MEDIUM"
        assert m.threshold_source == "global"

    def test_has_excluded_and_dependencies_missing(self):
        m = _make_metrics(excluded=True, dependencies_missing=True)
        assert m.excluded is True
        assert m.dependencies_missing is True

    def test_has_actionable(self):
        """actionable is retained as a stored field (distinct from actionable_count())."""
        m = _make_metrics(actionable=5)
        assert m.actionable == 5


class TestScannerMetricsPassed:
    """passed is a computed property based on status."""

    def test_passed_true_when_status_is_passed(self):
        m = _make_metrics(status="PASSED")
        assert m.passed is True

    def test_passed_true_when_status_is_skipped(self):
        m = _make_metrics(status="SKIPPED")
        assert m.passed is True

    def test_passed_true_when_status_is_missing(self):
        m = _make_metrics(status="MISSING")
        assert m.passed is True

    def test_passed_false_when_status_is_failed(self):
        m = _make_metrics(status="FAILED")
        assert m.passed is False

    def test_passed_false_when_status_is_error(self):
        m = _make_metrics(status="ERROR")
        assert m.passed is False
