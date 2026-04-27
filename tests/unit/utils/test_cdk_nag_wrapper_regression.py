"""Regression tests for cdk_nag_wrapper bug fixes.

PR#274 Bug #125: except FileNotFoundError on import (should also catch ImportError)
PR#274 Bug #126: Off-by-one line numbers from enumerate without start=1
"""

import inspect

import pytest


class TestCdkNagImportErrorHandling:
    """Missing cdk_nag module raises ImportError, not just FileNotFoundError."""

    def test_except_clause_catches_import_error(self):
        """The except clause must catch ImportError in addition to FileNotFoundError."""
        from automated_security_helper.utils import cdk_nag_wrapper

        source = inspect.getsource(cdk_nag_wrapper)
        # After fix, the except clause should catch both ImportError and FileNotFoundError
        assert "except (ImportError, FileNotFoundError)" in source, (
            "cdk_nag_wrapper must catch ImportError for missing cdk_nag module"
        )


class TestCdkNagLineNumbers:
    """enumerate without start=1 gives 0-based line numbers."""

    def test_enumerate_is_one_based(self):
        """Line numbers reported for resources must be 1-based."""
        from automated_security_helper.utils import cdk_nag_wrapper

        source = inspect.getsource(cdk_nag_wrapper)
        # After fix, enumerate should use start=1, or resource_line should be i+1
        assert "enumerate(template_lines, start=1)" in source or "i + 1" in source, (
            "cdk_nag_wrapper must use 1-based line numbering for template_lines"
        )
