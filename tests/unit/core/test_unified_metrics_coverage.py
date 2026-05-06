"""Tests for core/unified_metrics.py — covers metric functions."""

from unittest.mock import MagicMock
import pytest

from automated_security_helper.core.unified_metrics import (
    ScannerMetrics,
    format_duration,
    get_unified_scanner_metrics,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults

AshAggregatedResults.model_rebuild()


class TestScannerMetrics:
    """Tests for ScannerMetrics model."""

    def test_construction(self):
        metrics = ScannerMetrics(
            scanner_name="bandit",
            suppressed=0,
            critical=0,
            high=1,
            medium=2,
            low=3,
            info=0,
            total=6,
            actionable=6,
            duration=1.5,
            status="passed",
            status_text="PASSED",
            threshold="MEDIUM",
            threshold_source="default",
            excluded=False,
            dependencies_missing=False,
            passed=True,
        )
        assert metrics.scanner_name == "bandit"
        assert metrics.high == 1
        assert metrics.total == 6


class TestFormatDuration:
    """Tests for format_duration."""

    def test_none_duration(self):
        result = format_duration(None)
        assert isinstance(result, str)

    def test_zero_duration(self):
        result = format_duration(0.0)
        assert isinstance(result, str)

    def test_short_duration(self):
        result = format_duration(1.5)
        assert isinstance(result, str)

    def test_long_duration(self):
        result = format_duration(125.7)
        assert isinstance(result, str)


class TestGetUnifiedScannerMetrics:
    """Tests for get_unified_scanner_metrics."""

    def test_with_empty_results(self):
        results = AshAggregatedResults()
        metrics = get_unified_scanner_metrics(results)
        assert isinstance(metrics, list)
