"""Tests for utils/normalizers.py — covers path normalization functions."""

import pytest
from automated_security_helper.utils.normalizers import (
    get_normalized_filename,
    get_shortest_name,
)
from automated_security_helper.utils.suppression_matcher import file_path_matches as path_matches_pattern


class TestGetNormalizedFilename:
    """Tests for get_normalized_filename."""

    def test_basic_path(self):
        result = get_normalized_filename("/home/user/project/src/main.py")
        assert isinstance(result, str)
        assert "main" in result

    def test_relative_path(self):
        result = get_normalized_filename("src/main.py")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_just_filename(self):
        result = get_normalized_filename("main.py")
        assert isinstance(result, str)
        assert "main" in result


class TestGetShortestName:
    """Tests for get_shortest_name."""

    def test_basic(self):
        result = get_shortest_name("/home/user/project/src/main.py")
        assert isinstance(result, str)

    def test_short_name(self):
        result = get_shortest_name("main.py")
        assert result == "main.py"


class TestPathMatchesPattern:
    """Tests for path_matches_pattern."""

    def test_glob_match(self):
        assert path_matches_pattern("src/main.py", "*.py") is True

    def test_no_match(self):
        assert path_matches_pattern("src/main.py", "*.js") is False

    def test_directory_pattern(self):
        result = path_matches_pattern("node_modules/pkg/index.js", "node_modules/*")
        assert isinstance(result, bool)
