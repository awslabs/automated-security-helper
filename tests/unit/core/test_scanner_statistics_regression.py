"""Regression tests for scanner_statistics_calculator bug fixes.

PR#274 Bug #67: total includes suppressed, but verify adds suppressed again.

Batch 2:
  #78 - duration None crash in f-string formatting
"""

import inspect
from unittest.mock import MagicMock

import pytest


class TestTotalDoesNotDoubleCountSuppressed:
    """total must NOT include suppressed so verify doesn't double-count.

    We verify by inspecting the source code for the formula, since
    properly mocking the full asharp model is brittle.
    """

    def test_total_formula_excludes_suppressed(self):
        """The total computation must not add suppressed."""
        from automated_security_helper.core import scanner_statistics_calculator

        source = inspect.getsource(scanner_statistics_calculator)
        # Find the line that computes total
        for line in source.split("\n"):
            stripped = line.strip()
            if stripped.startswith("total = ") and "critical" in stripped:
                assert "suppressed" not in stripped, (
                    f"total formula must not include suppressed: {stripped}"
                )
                return
        pytest.fail("Could not find 'total = ...' line in scanner_statistics_calculator")


# ---------------------------------------------------------------------------
# Batch 2: Bug #78 -- duration None crash
# ---------------------------------------------------------------------------


class TestBug78DurationNoneCrash:
    """duration stored as None must not crash downstream f-string formatting."""

    def test_duration_none_from_additional_reports_becomes_safe_value(self):
        from automated_security_helper.core.scanner_statistics_calculator import (
            ScannerStatisticsCalculator,
        )

        asharp = MagicMock()
        asharp.sarif = MagicMock()
        asharp.sarif.runs = []
        asharp.additional_reports = {
            "test-scanner": {
                "source": {
                    "scanner_name": "test-scanner",
                    "status": "PASSED",
                    "duration": None,  # The bug: this None flows into stats
                }
            }
        }
        asharp.scanner_results = {}
        asharp.ash_config = MagicMock()
        asharp.ash_config.global_settings.severity_threshold = "MEDIUM"

        stats = ScannerStatisticsCalculator.extract_scanner_statistics(asharp)
        duration = stats["test-scanner"]["duration"]
        # duration must be a number, not None, so f"{duration:.2f}s" won't crash
        assert duration is not None
        assert isinstance(duration, (int, float))
        # Verify it doesn't crash when formatted
        formatted = f"{duration:.2f}s"
        assert "s" in formatted

    def test_duration_zero_still_works(self):
        from automated_security_helper.core.scanner_statistics_calculator import (
            ScannerStatisticsCalculator,
        )

        asharp = MagicMock()
        asharp.sarif = MagicMock()
        asharp.sarif.runs = []
        asharp.additional_reports = {
            "scanner-a": {
                "source": {
                    "scanner_name": "scanner-a",
                    "status": "PASSED",
                    "duration": 0.0,
                }
            }
        }
        asharp.scanner_results = {}
        asharp.ash_config = MagicMock()
        asharp.ash_config.global_settings.severity_threshold = "MEDIUM"

        stats = ScannerStatisticsCalculator.extract_scanner_statistics(asharp)
        assert stats["scanner-a"]["duration"] == 0.0
