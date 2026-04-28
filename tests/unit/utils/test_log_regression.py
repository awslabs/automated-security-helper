"""Regression tests for log utility bug fixes (batch 2).

Covers bug: #165 -- addLoggingLevel AttributeError on re-import
"""

import logging

import pytest


# ---------------------------------------------------------------------------
# Bug #165 -- addLoggingLevel AttributeError on re-import
# ---------------------------------------------------------------------------
class TestBug165AddLoggingLevelReimport:
    """addLoggingLevel must not raise on re-import if level already exists."""

    def test_add_logging_level_idempotent(self):
        from automated_security_helper.utils.log import addLoggingLevel

        # VERBOSE and TRACE are already registered at module load time.
        # Calling again must NOT raise.
        try:
            addLoggingLevel("VERBOSE", 15)
        except AttributeError:
            pytest.fail(
                "addLoggingLevel raised AttributeError on duplicate level name"
            )

    def test_add_logging_level_new_level_works(self):
        from automated_security_helper.utils.log import addLoggingLevel

        level_name = "TESTLEVEL_165"
        # Clean up in case a previous test run left it
        if hasattr(logging, level_name):
            return  # already registered, skip

        addLoggingLevel(level_name, 7)
        assert hasattr(logging, level_name)
        assert getattr(logging, level_name) == 7
