# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for detect_secrets_scanner global_ignore_paths functionality."""

import fnmatch
import pytest
from pathlib import Path

from automated_security_helper.models.core import IgnorePathWithReason


class TestGlobalIgnorePathsFiltering:
    """Tests for the global_ignore_paths filtering logic in detect_secrets_scanner."""

    @pytest.fixture
    def sample_files(self):
        """Sample file paths for testing."""
        return [
            "/project/src/main.py",
            "/project/src/config.py",
            "/project/.cruft.json",
            "/project/tests/test_main.py",
            "/project/node_modules/package/index.js",
            "/project/secrets.json",
            "/project/data/credentials.json",
        ]

    @pytest.fixture
    def ignore_paths(self):
        """Sample ignore paths configuration."""
        return [
            IgnorePathWithReason(path=".cruft.json", reason="Template metadata file"),
            IgnorePathWithReason(path="*/node_modules/*", reason="Third-party packages"),
            IgnorePathWithReason(path="**/credentials.json", reason="Credentials file"),
        ]

    def test_exact_filename_match(self, sample_files, ignore_paths):
        """Test that exact filename matches are filtered out."""
        # Filter logic from detect_secrets_scanner.py
        filtered = [
            file_path
            for file_path in sample_files
            if not any(
                fnmatch.fnmatch(file_path, ignore_path.path)
                or fnmatch.fnmatch(Path(file_path).name, ignore_path.path)
                or file_path.endswith(ignore_path.path)
                for ignore_path in ignore_paths
            )
        ]

        # .cruft.json should be filtered out
        assert "/project/.cruft.json" not in filtered
        # Other files should remain
        assert "/project/src/main.py" in filtered
        assert "/project/src/config.py" in filtered

    def test_glob_pattern_match(self, sample_files, ignore_paths):
        """Test that glob patterns filter matching files."""
        filtered = [
            file_path
            for file_path in sample_files
            if not any(
                fnmatch.fnmatch(file_path, ignore_path.path)
                or fnmatch.fnmatch(Path(file_path).name, ignore_path.path)
                or file_path.endswith(ignore_path.path)
                for ignore_path in ignore_paths
            )
        ]

        # node_modules should be filtered out
        assert "/project/node_modules/package/index.js" not in filtered
        # credentials.json should be filtered out
        assert "/project/data/credentials.json" not in filtered

    def test_no_ignore_paths_returns_all_files(self, sample_files):
        """Test that empty global_ignore_paths returns all files."""
        ignore_paths = []

        filtered = [
            file_path
            for file_path in sample_files
            if not any(
                fnmatch.fnmatch(file_path, ignore_path.path)
                or fnmatch.fnmatch(Path(file_path).name, ignore_path.path)
                or file_path.endswith(ignore_path.path)
                for ignore_path in ignore_paths
            )
        ]

        assert len(filtered) == len(sample_files)

    def test_all_files_filtered(self):
        """Test when all files match ignore patterns."""
        files = ["/project/.cruft.json", "/other/.cruft.json"]
        ignore_paths = [
            IgnorePathWithReason(path=".cruft.json", reason="Template file")
        ]

        filtered = [
            file_path
            for file_path in files
            if not any(
                fnmatch.fnmatch(file_path, ignore_path.path)
                or fnmatch.fnmatch(Path(file_path).name, ignore_path.path)
                or file_path.endswith(ignore_path.path)
                for ignore_path in ignore_paths
            )
        ]

        assert len(filtered) == 0

    def test_ignore_paths_with_expiration(self):
        """Test that ignore paths with expiration dates are handled correctly."""
        # Note: Expiration is validated when creating the model, not during filtering
        files = ["/project/temp_secret.json"]
        ignore_paths = [
            IgnorePathWithReason(
                path="temp_secret.json",
                reason="Temporary file",
                expiration="2027-12-31",  # Future date
            )
        ]

        filtered = [
            file_path
            for file_path in files
            if not any(
                fnmatch.fnmatch(file_path, ignore_path.path)
                or fnmatch.fnmatch(Path(file_path).name, ignore_path.path)
                or file_path.endswith(ignore_path.path)
                for ignore_path in ignore_paths
            )
        ]

        # File should be filtered (expiration is handled elsewhere)
        assert len(filtered) == 0
