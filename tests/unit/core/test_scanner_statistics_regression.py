"""Regression tests for scanner_statistics_calculator bug fixes.

PR#274 Bug #67: total includes suppressed, but verify adds suppressed again.
"""

import inspect

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
