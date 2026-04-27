"""Tests for medium-severity bug fixes (Batch 9).

Each test validates the fix for a specific bug. Tests are written to
confirm the correct behavior after fixes are applied.
"""

import logging
import os
import sys
from collections import Counter
from datetime import date, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Bug #44 -- sarif_utils.py:65-79 -- str(None) produces "None"
# ---------------------------------------------------------------------------
class TestGetFindingIdNoneValues:
    """get_finding_id must not include 'None' strings in the seed."""

    def test_none_start_line_excluded_from_seed(self):
        """When start_line is None the seed must not contain 'None'."""
        from automated_security_helper.utils.sarif_utils import get_finding_id

        id_with_none = get_finding_id("RULE-1", file="f.py", start_line=None)
        id_without = get_finding_id("RULE-1", file="f.py")
        # Both should produce the same UUID because None should be excluded
        assert id_with_none == id_without

    def test_none_end_line_excluded_from_seed(self):
        from automated_security_helper.utils.sarif_utils import get_finding_id

        id1 = get_finding_id("RULE-1", file="f.py", start_line=1, end_line=None)
        id2 = get_finding_id("RULE-1", file="f.py", start_line=1)
        assert id1 == id2

    def test_none_file_excluded_from_seed(self):
        from automated_security_helper.utils.sarif_utils import get_finding_id

        id1 = get_finding_id("RULE-1", file=None, start_line=1)
        id2 = get_finding_id("RULE-1", start_line=1)
        assert id1 == id2

    def test_zero_start_line_kept(self):
        """0 is a valid line number and must be included in the seed."""
        from automated_security_helper.utils.sarif_utils import get_finding_id

        id_zero = get_finding_id("R", file="f", start_line=0)
        id_none = get_finding_id("R", file="f", start_line=None)
        assert id_zero != id_none


# ---------------------------------------------------------------------------
# Bug #41 -- sarif_utils.py:191 -- Mutable default dict
# Batch 2 already fixed this (= None + guard). Verify it stays fixed.
# ---------------------------------------------------------------------------
class TestAttachScannerDetailsNoMutableDefault:
    """invocation_details default must be None, not {}."""

    def test_default_is_none_in_signature(self):
        import inspect
        from automated_security_helper.utils.sarif_utils import attach_scanner_details

        sig = inspect.signature(attach_scanner_details)
        default = sig.parameters["invocation_details"].default
        assert default is None, f"Expected None, got {default!r}"


# ---------------------------------------------------------------------------
# Bug #51 -- suppression_matcher.py:247-251 -- Invalid expiration silently skips
# ---------------------------------------------------------------------------
class TestInvalidExpirationWarnsInsteadOfSilentSkip:
    """A malformed expiration date must log a warning, not silently continue.

    NOTE: This was already fixed by a previous batch. This test verifies
    the fix remains in place.
    """

    def test_invalid_expiration_logs_warning(self, caplog):
        """When expiration is 'not-a-date', a warning must be logged."""
        from automated_security_helper.utils.suppression_matcher import (
            should_suppress_finding,
        )
        from automated_security_helper.models.flat_vulnerability import FlatVulnerability
        from automated_security_helper.utils.log import ASH_LOGGER

        # Build minimal finding
        finding = MagicMock(spec=FlatVulnerability)
        finding.rule_id = "TEST-RULE"
        finding.file_path = "test.py"
        finding.line_start = 1
        finding.line_end = 1

        suppression = MagicMock()
        suppression.rule_id = "TEST-RULE"
        suppression.expiration = "not-a-date"
        suppression.paths = []
        suppression.reason = "test"
        suppression.justification = "test"

        # ASH_LOGGER uses name "ash" and propagate=False, so caplog won't
        # capture it by default. Temporarily enable propagation.
        old_propagate = ASH_LOGGER.propagate
        ASH_LOGGER.propagate = True
        try:
            with caplog.at_level(logging.WARNING, logger="ash"):
                should_suppress_finding(finding, [suppression])
        finally:
            ASH_LOGGER.propagate = old_propagate

        warning_msgs = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        assert any("Invalid expiration" in m for m in warning_msgs), (
            f"Expected a warning about invalid expiration, got: {warning_msgs}"
        )


# ---------------------------------------------------------------------------
# Bug #77 -- scanner_statistics_calculator.py:162, 875-877
# total includes suppressed, but verify adds suppressed again
# ---------------------------------------------------------------------------
class TestTotalDoesNotDoubleCountSuppressed:
    """total must NOT include suppressed so verify doesn't double-count.

    We verify by inspecting the source code for the formula, since
    properly mocking the full asharp model is brittle.
    """

    def test_total_formula_excludes_suppressed(self):
        """The total computation must not add suppressed."""
        import inspect
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
# Bug #125 -- cdk_nag_wrapper.py:80 -- except FileNotFoundError on import
# ---------------------------------------------------------------------------
class TestCdkNagImportErrorHandling:
    """Missing cdk_nag module raises ImportError, not just FileNotFoundError."""

    def test_except_clause_catches_import_error(self):
        """The except clause must catch ImportError in addition to FileNotFoundError."""
        import inspect
        from automated_security_helper.utils import cdk_nag_wrapper

        source = inspect.getsource(cdk_nag_wrapper)
        # After fix, the except clause should catch both ImportError and FileNotFoundError
        assert "except (ImportError, FileNotFoundError)" in source, (
            "cdk_nag_wrapper must catch ImportError for missing cdk_nag module"
        )


# ---------------------------------------------------------------------------
# Bug #126 -- cdk_nag_wrapper.py:263-266 -- Off-by-one line numbers
# ---------------------------------------------------------------------------
class TestCdkNagLineNumbers:
    """enumerate without start=1 gives 0-based line numbers."""

    def test_enumerate_is_one_based(self):
        """Line numbers reported for resources must be 1-based."""
        # We verify the source code uses enumerate(..., start=1) or
        # adds 1 to the index. Read the function source and check.
        import inspect
        from automated_security_helper.utils import cdk_nag_wrapper

        source = inspect.getsource(cdk_nag_wrapper)
        # After fix, enumerate should use start=1, or resource_line should be i+1
        # Check that the old pattern (enumerate without start) is gone
        # and the fix is in place
        assert "enumerate(template_lines, start=1)" in source or "i + 1" in source, (
            "cdk_nag_wrapper must use 1-based line numbering for template_lines"
        )


# ---------------------------------------------------------------------------
# Bug #147/148 -- are_values_equivalent.py:37-46 -- Broken list/dict comparison
# ---------------------------------------------------------------------------
class TestAreValuesEquivalent:
    """List comparison is broken for duplicates; dict ignores values."""

    def test_list_multiset_different(self):
        """[1,1,2] != [1,2,2] -- different multiplicities."""
        from automated_security_helper.utils.meta_analysis.are_values_equivalent import (
            are_values_equivalent,
        )

        assert are_values_equivalent([1, 1, 2], [1, 2, 2]) is False

    def test_list_multiset_same(self):
        """[1,1,2] == [1,1,2] even if order differs."""
        from automated_security_helper.utils.meta_analysis.are_values_equivalent import (
            are_values_equivalent,
        )

        assert are_values_equivalent([1, 2, 1], [1, 1, 2]) is True

    def test_dict_values_matter(self):
        """{"a": 1} != {"a": 2} -- values must be compared."""
        from automated_security_helper.utils.meta_analysis.are_values_equivalent import (
            are_values_equivalent,
        )

        assert are_values_equivalent({"a": 1}, {"a": 2}) is False

    def test_dict_equal_values(self):
        from automated_security_helper.utils.meta_analysis.are_values_equivalent import (
            are_values_equivalent,
        )

        assert are_values_equivalent({"a": 1, "b": 2}, {"b": 2, "a": 1}) is True

    def test_dict_nested_values(self):
        from automated_security_helper.utils.meta_analysis.are_values_equivalent import (
            are_values_equivalent,
        )

        assert are_values_equivalent({"a": [1, 2]}, {"a": [1, 2]}) is True
        assert are_values_equivalent({"a": [1, 2]}, {"a": [2, 1]}) is True
        assert are_values_equivalent({"a": [1, 1]}, {"a": [1, 2]}) is False


# ---------------------------------------------------------------------------
# Bug #164 -- execution_engine.py:571-607 -- Unbound vars in finally
# ---------------------------------------------------------------------------
class TestExecutionEngineUnboundVars:
    """hours/minutes/seconds must be initialized before the try block."""

    def test_finally_vars_initialized(self):
        """The source must initialize hours/minutes/seconds before try."""
        import inspect
        from automated_security_helper.core import execution_engine

        source = inspect.getsource(execution_engine)
        # After fix, hours/minutes/seconds should be initialized
        # somewhere before the try block
        assert (
            "hours = 0" in source
            or "hours, minutes, seconds = 0, 0, 0" in source
            or "hours = minutes = seconds = 0" in source
        ), "hours must be initialized before the try block"


# ---------------------------------------------------------------------------
# Bug #167 -- models/core.py:83-98 -- except ValueError rewraps semantic error
# ---------------------------------------------------------------------------
class TestExpirationValidatorPreservesMessage:
    """'expiration must be in the future' must not be rewrapped as format error."""

    def test_past_date_gives_future_error(self):
        """A past date should say 'must be in the future', not 'Invalid format'."""
        from automated_security_helper.models.core import AshSuppression

        yesterday = (date.today() - timedelta(days=1)).strftime("%Y-%m-%d")
        with pytest.raises(Exception) as exc_info:
            AshSuppression(
                rule_id="R1",
                reason="test",
                justification="test",
                expiration=yesterday,
            )
        # The error should mention "future", not "Invalid format"
        error_str = str(exc_info.value)
        assert "future" in error_str.lower(), (
            f"Expected 'future' in error message, got: {error_str}"
        )

    def test_bad_format_gives_format_error(self):
        """A truly malformed date should give the format error."""
        from automated_security_helper.models.core import AshSuppression

        with pytest.raises(Exception) as exc_info:
            AshSuppression(
                rule_id="R1",
                reason="test",
                justification="test",
                expiration="not-a-date",
            )
        error_str = str(exc_info.value)
        assert "format" in error_str.lower() or "YYYY-MM-DD" in error_str, (
            f"Expected format-related error, got: {error_str}"
        )


# ---------------------------------------------------------------------------
# Bug #194 -- base/reporter_plugin.py:45-51 -- configure() writes self._config
# ---------------------------------------------------------------------------
class TestReporterPluginConfigure:
    """configure() must write self.config, not self._config."""

    def test_configure_sets_public_config(self):
        """After configure(cfg), self.config should be cfg."""
        import inspect
        from automated_security_helper.base.reporter_plugin import ReporterPluginBase

        source = inspect.getsource(ReporterPluginBase.configure)
        # The fix should write self.config = config, not self._config = config
        assert "self.config = config" in source, (
            "configure() must assign to self.config, not self._config"
        )
        assert "self._config" not in source, (
            "configure() must not use self._config"
        )
