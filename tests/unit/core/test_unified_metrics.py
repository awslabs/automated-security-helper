"""Unit tests for the unified metrics service."""

from unittest.mock import patch

from automated_security_helper.core.unified_metrics import (
    ScannerMetrics,
    format_duration,
    get_unified_scanner_metrics,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults


class TestUnifiedMetrics:
    """Test cases for unified metrics service."""

    def test_scanner_metrics_model(self):
        """Test the ScannerMetrics data model."""
        metrics = ScannerMetrics(
            scanner_name="test_scanner",
            suppressed=1,
            critical=2,
            high=3,
            medium=4,
            low=5,
            info=6,
            total=20,
            actionable=9,
            duration=10.5,
            status="PASSED",
            status_text="PASSED",
            threshold="MEDIUM",
            threshold_source="global",
            excluded=False,
            dependencies_missing=False,
            passed=True,
        )

        assert metrics.scanner_name == "test_scanner"
        assert metrics.suppressed == 1
        assert metrics.critical == 2
        assert metrics.high == 3
        assert metrics.medium == 4
        assert metrics.low == 5
        assert metrics.info == 6
        assert metrics.total == 20
        assert metrics.actionable == 9
        assert metrics.duration == 10.5
        assert metrics.status == "PASSED"
        assert metrics.status_text == "PASSED"
        assert metrics.threshold == "MEDIUM"
        assert metrics.threshold_source == "global"
        assert metrics.excluded is False
        assert metrics.dependencies_missing is False
        assert metrics.passed is True

    def test_format_duration(self):
        """Test formatting duration in seconds to a human-readable string."""
        # Test with None
        assert format_duration(None) == "N/A"

        # Test with less than 1 millisecond
        assert format_duration(0.0005) == "<1ms"

        # Test with milliseconds
        assert format_duration(0.123) == "123ms"

        # Test with seconds
        assert format_duration(5.7) == "5.7s"

        # Test with minutes and seconds
        assert format_duration(125.3) == "2m 5s"

        # Test with large duration
        assert format_duration(3661) == "61m 1s"

    def test_get_unified_scanner_metrics_empty_model(self):
        """Test getting unified scanner metrics from an empty model."""
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.config.default_config import get_default_config

        # First define AshConfig and rebuild the model
        AshConfig.model_rebuild()
        AshAggregatedResults.model_rebuild()

        model = AshAggregatedResults()
        model.ash_config = get_default_config()

        with patch(
            "automated_security_helper.core.scanner_statistics_calculator.ScannerStatisticsCalculator.extract_scanner_statistics"
        ) as mock_extract:
            mock_extract.return_value = {}
            metrics = get_unified_scanner_metrics(model)

            assert isinstance(metrics, list)
            assert len(metrics) == 0

    def test_get_unified_scanner_metrics_with_data(self):
        """Test getting unified scanner metrics with scanner data."""
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.config.default_config import get_default_config

        # First define AshConfig and rebuild the model
        AshConfig.model_rebuild()
        AshAggregatedResults.model_rebuild()

        model = AshAggregatedResults()
        model.ash_config = get_default_config()

        with patch(
            "automated_security_helper.core.scanner_statistics_calculator.ScannerStatisticsCalculator.extract_scanner_statistics"
        ) as mock_extract:
            mock_extract.return_value = {
                "scanner1": {
                    "suppressed": 1,
                    "critical": 2,
                    "high": 3,
                    "medium": 4,
                    "low": 5,
                    "info": 6,
                    "total": 20,
                    "actionable": 9,
                    "duration": 10.5,
                    "threshold": "MEDIUM",
                    "threshold_source": "global",
                    "excluded": False,
                    "dependencies_missing": False,
                    "error": False,
                },
                "scanner2": {
                    "suppressed": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                    "total": 0,
                    "actionable": 0,
                    "duration": 5.2,
                    "threshold": "HIGH",
                    "threshold_source": "config",
                    "excluded": True,
                    "dependencies_missing": False,
                    "error": False,
                },
                "scanner3": {
                    "suppressed": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                    "total": 0,
                    "actionable": 0,
                    "duration": 0.0,
                    "threshold": "MEDIUM",
                    "threshold_source": "global",
                    "excluded": False,
                    "dependencies_missing": True,
                    "error": False,
                },
            }

            metrics = get_unified_scanner_metrics(model)

            assert isinstance(metrics, list)
            assert len(metrics) == 3

            # Check that metrics are sorted by scanner name
            assert metrics[0].scanner_name == "scanner1"
            assert metrics[1].scanner_name == "scanner2"
            assert metrics[2].scanner_name == "scanner3"

            # Check scanner1 metrics
            assert metrics[0].suppressed == 1
            assert metrics[0].critical == 2
            assert metrics[0].high == 3
            assert metrics[0].medium == 4
            assert metrics[0].low == 5
            assert metrics[0].info == 6
            assert metrics[0].total == 20
            assert metrics[0].actionable == 9
            assert metrics[0].duration == 10.5
            assert metrics[0].status == "FAILED"
            assert metrics[0].status_text == "FAILED"
            assert metrics[0].threshold == "MEDIUM"
            assert metrics[0].threshold_source == "global"
            assert metrics[0].excluded is False
            assert metrics[0].dependencies_missing is False
            assert metrics[0].passed is False

            # Check scanner2 metrics (excluded)
            assert metrics[1].status == "SKIPPED"
            assert metrics[1].passed is True

            # Check scanner3 metrics (dependencies missing)
            assert metrics[2].status == "MISSING"
            assert metrics[2].passed is True

    def test_get_unified_scanner_metrics_with_error_scanner(self):
        """Test getting unified scanner metrics when a scanner fails to execute."""
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.config.default_config import get_default_config

        # First define AshConfig and rebuild the model
        AshConfig.model_rebuild()
        AshAggregatedResults.model_rebuild()

        model = AshAggregatedResults()
        model.ash_config = get_default_config()

        with patch(
            "automated_security_helper.core.scanner_statistics_calculator.ScannerStatisticsCalculator.extract_scanner_statistics"
        ) as mock_extract:
            mock_extract.return_value = {
                "error_scanner": {
                    "suppressed": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                    "total": 0,
                    "actionable": 0,
                    "duration": None,
                    "threshold": "MEDIUM",
                    "threshold_source": "global",
                    "excluded": False,
                    "dependencies_missing": False,
                    "error": True,
                },
            }

            metrics = get_unified_scanner_metrics(model)

            assert isinstance(metrics, list)
            assert len(metrics) == 1

            # Check error scanner metrics
            error_metrics = metrics[0]
            assert error_metrics.scanner_name == "error_scanner"
            assert error_metrics.status == "ERROR"
            assert error_metrics.status_text == "ERROR"
            assert (
                error_metrics.passed is False
            )  # Error scanners should not be considered as passed
            assert error_metrics.duration is None
            assert error_metrics.total == 0
            assert error_metrics.actionable == 0
