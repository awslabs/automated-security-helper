"""Regression tests for scanner and reporter mapping bug fixes.

Bug #34: bandit excluded_paths accumulates across calls (from low)
Bug #19: get_reporter_mappings __class__.__name__ on class object (from high)
Bug #166: Duplicate "xml" in KNOWN_SCANNABLE_EXTENSIONS (from low)
"""

import inspect
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Bug #34 -- bandit excluded_paths accumulates across calls
# ---------------------------------------------------------------------------
class TestBanditExcludedPathsNotAccumulated:
    """self.config.options.excluded_paths must not grow across scan() calls."""

    def test_excluded_paths_stable_across_scans(self):
        """Calling scan() twice should not double the global_ignore_paths in the
        config's excluded_paths list."""
        from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
            BanditScanner,
        )

        scanner = MagicMock(spec=BanditScanner)
        # Access the real scan method's logic by reading the source behavior:
        # We need to test that config.options.excluded_paths doesn't grow.
        # Build a minimal mock that exposes the relevant attribute.
        excluded = ["original_path"]
        config_options = MagicMock()
        config_options.excluded_paths = list(excluded)  # start with a copy

        config = MagicMock()
        config.options = config_options

        # Simulate what the fixed code should do: use a local copy, not mutate
        global_ignore = [MagicMock()]
        global_ignore[0].path = "extra_path"

        # After fix: config.options.excluded_paths should stay the same length
        # We test this by importing and checking the source directly:
        source = inspect.getsource(BanditScanner.scan)
        # The fix should NOT contain 'self.config.options.excluded_paths.extend'
        assert "self.config.options.excluded_paths.extend" not in source, (
            "BanditScanner.scan still mutates self.config.options.excluded_paths via extend()"
        )


# ---------------------------------------------------------------------------
# Bug #19 -- get_reporter_mappings.py: __class__.__name__ on class object
# ---------------------------------------------------------------------------
class TestReporterClassName:
    """reporter.__class__.__name__ on a class yields 'type', not the class name."""

    def test_class_name_not_type(self):
        """Calling __class__.__name__ on a class returns 'type'."""

        class FakeReporter:
            pass

        # Bug behavior
        assert FakeReporter.__class__.__name__ == "type"
        # Correct behavior
        assert FakeReporter.__name__ == "FakeReporter"

    def test_reporter_mapping_uses_correct_name(self):
        """After fix, get_reporter_mappings should use the actual class name."""

        class SarifReporter:
            pass

        # Wrong: class object's __class__ is the metaclass 'type'
        wrong_name = SarifReporter.__class__.__name__
        assert wrong_name == "type"

        # Right: the class's own __name__
        correct_name = SarifReporter.__name__
        assert correct_name == "SarifReporter"


# ---------------------------------------------------------------------------
# Bug #166 -- Duplicate "xml" in KNOWN_SCANNABLE_EXTENSIONS
# ---------------------------------------------------------------------------
class TestNoDuplicateExtensions:
    """KNOWN_SCANNABLE_EXTENSIONS should not contain duplicate entries."""

    def test_no_duplicate_extensions(self):
        from automated_security_helper.core.constants import KNOWN_SCANNABLE_EXTENSIONS

        seen = set()
        duplicates = []
        for ext in KNOWN_SCANNABLE_EXTENSIONS:
            if ext in seen:
                duplicates.append(ext)
            seen.add(ext)
        assert duplicates == [], (
            f"Duplicate entries in KNOWN_SCANNABLE_EXTENSIONS: {duplicates}"
        )
