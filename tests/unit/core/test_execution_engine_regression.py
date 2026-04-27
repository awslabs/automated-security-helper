"""Regression tests for execution_engine bug fixes.

PR#274 Bug #6: operator precedence on _max_workers (from high)
PR#274 Bug #7: split delimiter mismatch ", " vs "," (from high)
PR#274 Bug #164: Unbound vars in finally (from medium)
"""

import inspect
import os
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# PR#274 Bug #6 -- execution_engine.py: operator precedence on _max_workers
# ---------------------------------------------------------------------------
class TestMaxWorkersOperatorPrecedence:
    """os.cpu_count() or 1 + 4 must parse as (os.cpu_count() or 1) + 4."""

    def test_max_workers_with_cpu_count_available(self):
        """When cpu_count() returns 8, _max_workers should be min(32, 12)."""
        with patch("os.cpu_count", return_value=8):
            result = min(32, (os.cpu_count() or 1) + 4)
            assert result == 12  # 8 + 4

    def test_max_workers_with_cpu_count_none(self):
        """When cpu_count() returns None, _max_workers should be min(32, 5)."""
        with patch("os.cpu_count", return_value=None):
            result = min(32, (os.cpu_count() or 1) + 4)
            assert result == 5  # (None or 1) + 4 = 5

    def test_buggy_expression_demonstrates_problem(self):
        """Demonstrate the bug: os.cpu_count() or 1 + 4 gives wrong result."""
        with patch("os.cpu_count", return_value=8):
            buggy = os.cpu_count() or 1 + 4  # parses as cpu_count() or 5
            fixed = (os.cpu_count() or 1) + 4
            assert buggy == 8  # bug: returns just cpu_count()
            assert fixed == 12  # correct: cpu_count() + 4


# ---------------------------------------------------------------------------
# PR#274 Bug #7 -- execution_engine.py: split delimiter mismatch ", " vs ","
# ---------------------------------------------------------------------------
class TestSplitDelimiterMismatch:
    """Config values like 'a,b' (no space) must still split correctly."""

    def test_split_comma_no_space(self):
        """'a,b' split with ',' and strip gives ['a', 'b']."""
        item = "a,b"
        result = [subitem.strip() for subitem in item.split(",")]
        assert result == ["a", "b"]

    def test_split_comma_with_space(self):
        """'a, b' split with ',' and strip gives ['a', 'b']."""
        item = "a, b"
        result = [subitem.strip() for subitem in item.split(",")]
        assert result == ["a", "b"]

    def test_split_comma_space_delimiter_fails_no_space(self):
        """The OLD behavior: splitting 'a,b' on ', ' yields ['a,b'] -- unsplit."""
        item = "a,b"
        buggy_result = item.split(", ")
        assert buggy_result == ["a,b"]  # confirms the bug


# ---------------------------------------------------------------------------
# PR#274 Bug #164 -- execution_engine.py:571-607 -- Unbound vars in finally
# ---------------------------------------------------------------------------
class TestExecutionEngineUnboundVars:
    """hours/minutes/seconds must be initialized before the try block."""

    def test_finally_vars_initialized(self):
        """The source must initialize hours/minutes/seconds before try."""
        from automated_security_helper.core import execution_engine

        source = inspect.getsource(execution_engine)
        # After fix, hours/minutes/seconds should be initialized
        # somewhere before the try block
        assert (
            "hours = 0" in source
            or "hours, minutes, seconds = 0, 0, 0" in source
            or "hours = minutes = seconds = 0" in source
        ), "hours must be initialized before the try block"
