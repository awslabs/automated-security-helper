"""Regression tests for metrics bug fixes.

PR#274 Bug #54: Typo "errorn" in metrics_table.py (from low)
PR#274 Bug #69: error log on success in unified_metrics (from low)
PR#274 Bug #21: print() calls in unified_metrics.py (from low)
"""

import inspect

import pytest


# ---------------------------------------------------------------------------
# PR#274 Bug #54 -- Typo "errorn" in metrics_table.py
# ---------------------------------------------------------------------------
class TestErrornTypo:
    """The literal string 'errorn' should not appear in the metrics table legend."""

    def test_no_errorn_in_metrics_table(self):
        from automated_security_helper.core import metrics_table

        source = inspect.getsource(metrics_table)
        assert "errorn" not in source, (
            "Typo 'errorn' still present in metrics_table module"
        )


# ---------------------------------------------------------------------------
# PR#274 Bug #69 -- error log on success in unified_metrics
