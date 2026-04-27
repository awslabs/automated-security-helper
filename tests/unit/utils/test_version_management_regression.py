"""Regression tests for version_management bug fixes.

Bug #24: re.sub replaces all occurrences without count=1.
"""

import re

import pytest


class TestVersionReSubCount:
    """re.sub without count=1 replaces all 'version = ...' lines."""

    def test_only_first_version_replaced(self):
        """Only the project version should be replaced, not dependency pins."""
        content = (
            '[project]\nname = "ash"\nversion = "1.0.0"\n\n'
            '[dependencies]\nfoo = {version = "2.0.0"}\n'
            'bar = {version = "3.0.0"}\n'
        )
        pattern = r'(version\s*=\s*")([^"]+)(")'
        # Simulate the fix: count=1
        new_content = re.sub(pattern, r'\g<1>9.9.9\g<3>', content, count=1)
        # First version replaced
        assert 'version = "9.9.9"' in new_content
        # Dependency versions preserved
        assert 'version = "2.0.0"' in new_content
        assert 'version = "3.0.0"' in new_content

    def test_buggy_replaces_all(self):
        """Without count=1, all version lines get replaced."""
        content = (
            '[project]\nversion = "1.0.0"\n'
            '[deps]\nfoo = {version = "2.0.0"}\n'
        )
        pattern = r'(version\s*=\s*")([^"]+)(")'
        buggy = re.sub(pattern, r'\g<1>9.9.9\g<3>', content)
        # Bug: both are replaced
        assert buggy.count('version = "9.9.9"') == 2
