"""Regression tests for scanner_statistics_calculator bug fixes.

PR#274 Bug #67: total includes suppressed, but verify adds suppressed again.

Batch 2:
  #78 - duration None crash in f-string formatting
"""

import inspect
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.unit


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
        pytest.fail(
            "Could not find 'total = ...' line in scanner_statistics_calculator"
        )


# ---------------------------------------------------------------------------
# Batch 2: Bug #78 -- duration None crash
# ---------------------------------------------------------------------------


class TestBug78DurationNoneCrash:
    """A duration recorded as None must not crash the readers that format it.

    The first cure coerced the None to 0.0 in the statistics, which made a
    scanner that never ran read "<1ms"; every reader of the field now formats
    None itself (format_duration, the tables, the reporters), so the statistics
    keep the None and the pin is that the formatter takes it."""

    def test_duration_none_from_additional_reports_reads_none_and_formats(self):
        from automated_security_helper.core.scanner_statistics_calculator import (
            ScannerStatisticsCalculator,
        )
        from automated_security_helper.core.unified_metrics import format_duration

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
        # No duration was recorded, so none is invented: the readers format the
        # None as "N/A" rather than a 0.0 that reads "<1ms".
        assert duration is None
        assert format_duration(duration) == "N/A"

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
