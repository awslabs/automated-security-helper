"""Regression tests for metrics bug fixes.

Bug #64: Typo "errorn" in metrics_table.py (from low)
Bug #79: error log on success in metrics_alignment (from low)
Bug #80: print() calls in metrics_alignment.py (from low)
"""

import inspect

import pytest


# ---------------------------------------------------------------------------
# Bug #64 -- Typo "errorn" in metrics_table.py
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
# Bug #79 -- error log on success in metrics_alignment
# ---------------------------------------------------------------------------
class TestMetricsAlignmentSuccessNotLoggedAsError:
    """On the SUCCESS branch of verify_metrics_alignment, the logger should not
    emit at ERROR level."""

    def test_success_branch_no_error_log(self):
        """When all metrics align, no ERROR-level log should be emitted for the
        per-metric success messages."""
        from automated_security_helper.core import metrics_alignment

        source = inspect.getsource(metrics_alignment.verify_metrics_alignment)
        # In the else branch (alignment passed), we should see info/debug, not error
        # Find the "alignment passed" line and check its log level
        lines = source.splitlines()
        for i, line in enumerate(lines):
            if "alignment passed" in line.lower():
                # The line or a nearby line should use info or debug, not error
                assert "error(" not in line.lower(), (
                    f"Line {i}: 'alignment passed' message still logged at ERROR level"
                )


# ---------------------------------------------------------------------------
# Bug #80 -- print() calls in metrics_alignment.py
# ---------------------------------------------------------------------------
class TestMetricsAlignmentNoPrintCalls:
    """verify_metrics_alignment should not use print() -- only logger calls."""

    def test_no_print_in_verify_function(self):
        from automated_security_helper.core import metrics_alignment

        source = inspect.getsource(metrics_alignment.verify_metrics_alignment)
        # Count bare print() calls (not inside comments or strings referring to "print")
        lines = source.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            # Skip comments
            if stripped.startswith("#"):
                continue
            if stripped.startswith("print("):
                pytest.fail(
                    f"Line {i}: bare print() call found in verify_metrics_alignment: {stripped}"
                )
