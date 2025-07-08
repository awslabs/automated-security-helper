# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for offline mode validation utilities."""

import os
from datetime import datetime, timedelta
from unittest.mock import patch

from automated_security_helper.utils.offline_mode_validator import (
    validate_semgrep_offline_mode,
    validate_opengrep_offline_mode,
    validate_grype_offline_mode,
    validate_npm_audit_offline_mode,
    OfflineModeValidator,
)


class TestValidateSemgrepOfflineMode:
    """Tests for validate_semgrep_offline_mode function."""

    def test_missing_cache_dir_env_var(self):
        """Test validation fails when SEMGREP_RULES_CACHE_DIR is not set."""
        with patch.dict(os.environ, {}, clear=True):
            is_valid, messages = validate_semgrep_offline_mode()

            assert not is_valid
            assert len(messages) == 1
            assert "SEMGREP_RULES_CACHE_DIR environment variable not set" in messages[0]

    def test_cache_dir_does_not_exist(self, tmp_path):
        """Test validation fails when cache directory doesn't exist."""
        non_existent_dir = str(tmp_path / "non_existent")

        with patch.dict(os.environ, {"SEMGREP_RULES_CACHE_DIR": non_existent_dir}):
            is_valid, messages = validate_semgrep_offline_mode()

            assert not is_valid
            assert len(messages) == 1
            assert f"Cache directory does not exist: {non_existent_dir}" in messages[0]

    def test_no_rule_files_in_cache(self, tmp_path):
        """Test validation fails when no rule files are found."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # Create some non-rule files
        (cache_dir / "readme.txt").write_text("not a rule file")
        (cache_dir / "config.json").write_text("{}")

        with patch.dict(os.environ, {"SEMGREP_RULES_CACHE_DIR": str(cache_dir)}):
            is_valid, messages = validate_semgrep_offline_mode()

            assert not is_valid
            assert len(messages) == 1
            assert f"No rule files found in cache directory: {cache_dir}" in messages[0]

    def test_successful_validation_with_yaml_files(self, tmp_path):
        """Test successful validation with YAML rule files."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # Create rule files
        (cache_dir / "rule1.yaml").write_text("rules: []")
        (cache_dir / "rule2.yml").write_text("rules: []")

        # Create subdirectory with more rules
        subdir = cache_dir / "subdir"
        subdir.mkdir()
        (subdir / "rule3.yaml").write_text("rules: []")

        with patch.dict(os.environ, {"SEMGREP_RULES_CACHE_DIR": str(cache_dir)}):
            is_valid, messages = validate_semgrep_offline_mode()

            assert is_valid
            assert len(messages) == 1
            assert "Found 3 rule files in cache directory" in messages[0]

    def test_mixed_files_in_cache(self, tmp_path):
        """Test validation succeeds when rule files exist alongside other files."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # Create rule files
        (cache_dir / "rule1.yaml").write_text("rules: []")
        (cache_dir / "rule2.yml").write_text("rules: []")

        # Create non-rule files (should be ignored)
        (cache_dir / "readme.txt").write_text("documentation")
        (cache_dir / "config.json").write_text("{}")

        with patch.dict(os.environ, {"SEMGREP_RULES_CACHE_DIR": str(cache_dir)}):
            is_valid, messages = validate_semgrep_offline_mode()

            assert is_valid
            assert len(messages) == 1
            assert "Found 2 rule files in cache directory" in messages[0]


class TestValidateOpengrepOfflineMode:
    """Tests for validate_opengrep_offline_mode function."""

    def test_missing_cache_dir_env_var(self):
        """Test validation fails when OPENGREP_RULES_CACHE_DIR is not set."""
        with patch.dict(os.environ, {}, clear=True):
            is_valid, messages = validate_opengrep_offline_mode()

            assert not is_valid
            assert len(messages) == 1
            assert (
                "OPENGREP_RULES_CACHE_DIR environment variable not set" in messages[0]
            )

    def test_cache_dir_does_not_exist(self, tmp_path):
        """Test validation fails when cache directory doesn't exist."""
        non_existent_dir = str(tmp_path / "non_existent")

        with patch.dict(os.environ, {"OPENGREP_RULES_CACHE_DIR": non_existent_dir}):
            is_valid, messages = validate_opengrep_offline_mode()

            assert not is_valid
            assert len(messages) == 1
            assert f"Cache directory does not exist: {non_existent_dir}" in messages[0]

    def test_no_rule_files_in_cache(self, tmp_path):
        """Test validation fails when no rule files are found."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        with patch.dict(os.environ, {"OPENGREP_RULES_CACHE_DIR": str(cache_dir)}):
            is_valid, messages = validate_opengrep_offline_mode()

            assert not is_valid
            assert len(messages) == 1
            assert f"No rule files found in cache directory: {cache_dir}" in messages[0]

    def test_successful_validation_with_rule_files(self, tmp_path):
        """Test successful validation with rule files."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # Create rule files
        (cache_dir / "rule1.yaml").write_text("rules: []")
        (cache_dir / "rule2.yml").write_text("rules: []")

        with patch.dict(os.environ, {"OPENGREP_RULES_CACHE_DIR": str(cache_dir)}):
            is_valid, messages = validate_opengrep_offline_mode()

            assert is_valid
            assert len(messages) == 1
            assert "Found 2 rule files in cache directory" in messages[0]


class TestValidateGrypeOfflineMode:
    """Tests for validate_grype_offline_mode function."""

    def test_missing_cache_dir_env_var(self):
        """Test validation fails when GRYPE_DB_CACHE_DIR is not set."""
        with patch.dict(os.environ, {}, clear=True):
            is_valid, messages = validate_grype_offline_mode()

            assert not is_valid
            assert len(messages) == 1
            assert "GRYPE_DB_CACHE_DIR environment variable not set" in messages[0]

    def test_cache_dir_does_not_exist(self, tmp_path):
        """Test validation fails when cache directory doesn't exist."""
        non_existent_dir = str(tmp_path / "non_existent")

        with patch.dict(os.environ, {"GRYPE_DB_CACHE_DIR": non_existent_dir}):
            is_valid, messages = validate_grype_offline_mode()

            assert not is_valid
            assert len(messages) == 1
            assert f"Cache directory does not exist: {non_existent_dir}" in messages[0]

    def test_no_database_files_in_cache(self, tmp_path):
        """Test validation fails when no database files are found."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # Create some non-database files
        (cache_dir / "readme.txt").write_text("not a database")

        with patch.dict(os.environ, {"GRYPE_DB_CACHE_DIR": str(cache_dir)}):
            is_valid, messages = validate_grype_offline_mode()

            assert not is_valid
            assert len(messages) == 1
            assert (
                f"No database files found in cache directory: {cache_dir}"
                in messages[0]
            )

    def test_successful_validation_with_recent_db(self, tmp_path):
        """Test successful validation with recent database files."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # Create database files
        db_file = cache_dir / "vulnerability.db"
        db_file.write_text("database content")

        # Set recent modification time
        recent_time = datetime.now().timestamp()
        os.utime(db_file, (recent_time, recent_time))

        with patch.dict(os.environ, {"GRYPE_DB_CACHE_DIR": str(cache_dir)}):
            is_valid, messages = validate_grype_offline_mode()

            assert is_valid
            assert len(messages) == 1
            assert "Found 1 database files, newest is 0 days old" in messages[0]

    def test_validation_with_old_database(self, tmp_path):
        """Test validation warns about old database files."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # Create database file
        db_file = cache_dir / "vulnerability.db"
        db_file.write_text("database content")

        # Set old modification time (10 days ago)
        old_time = (datetime.now() - timedelta(days=10)).timestamp()
        os.utime(db_file, (old_time, old_time))

        with patch.dict(os.environ, {"GRYPE_DB_CACHE_DIR": str(cache_dir)}):
            is_valid, messages = validate_grype_offline_mode()

            assert is_valid  # Still valid, just warns
            assert len(messages) == 1
            assert "Database is 10 days old, consider updating" in messages[0]

    def test_multiple_database_file_types(self, tmp_path):
        """Test validation with different database file types."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # Create different types of database files
        (cache_dir / "grype.db").write_text("database")
        (cache_dir / "data.sqlite").write_text("sqlite database")
        (cache_dir / "vulnerability-data.json").write_text("{}")

        with patch.dict(os.environ, {"GRYPE_DB_CACHE_DIR": str(cache_dir)}):
            is_valid, messages = validate_grype_offline_mode()

            assert is_valid
            assert len(messages) == 1
            assert "Found 3 database files" in messages[0]


class TestValidateNpmAuditOfflineMode:
    """Tests for validate_npm_audit_offline_mode function."""

    @patch("os.path.expanduser")
    def test_no_npm_cache_found(self, mock_expanduser, tmp_path):
        """Test validation fails when no npm cache is found."""
        # Mock expanduser to return non-existent paths
        mock_expanduser.side_effect = lambda path: str(tmp_path / "non_existent")

        with patch.dict(os.environ, {}, clear=True):
            is_valid, messages = validate_npm_audit_offline_mode()

            assert not is_valid
            assert len(messages) == 1
            assert "No npm cache directory found" in messages[0]

    @patch("os.path.expanduser")
    def test_npm_cache_found_via_env_var(self, mock_expanduser, tmp_path):
        """Test successful validation when NPM_CONFIG_CACHE is set."""
        cache_dir = tmp_path / "npm_cache"
        cache_dir.mkdir()

        with patch.dict(os.environ, {"NPM_CONFIG_CACHE": str(cache_dir)}):
            is_valid, messages = validate_npm_audit_offline_mode()

            assert is_valid
            assert len(messages) == 1
            assert f"Found npm cache at {cache_dir}" in messages[0]

    @patch("os.path.expanduser")
    def test_npm_cache_found_in_home_directory(self, mock_expanduser, tmp_path):
        """Test successful validation when npm cache is in home directory."""
        cache_dir = tmp_path / ".npm"
        cache_dir.mkdir()

        def mock_expand(path):
            if path == "~/.npm":
                return str(cache_dir)
            return str(tmp_path / "non_existent")

        mock_expanduser.side_effect = mock_expand

        with patch.dict(os.environ, {}, clear=True):
            is_valid, messages = validate_npm_audit_offline_mode()

            assert is_valid
            assert len(messages) == 1
            assert f"Found npm cache at {cache_dir}" in messages[0]

    @patch("os.path.expanduser")
    def test_yarn_cache_found(self, mock_expanduser, tmp_path):
        """Test that yarn cache is also detected."""
        npm_cache_dir = tmp_path / ".npm"
        yarn_cache_dir = tmp_path / ".yarn" / "cache"

        npm_cache_dir.mkdir()
        yarn_cache_dir.mkdir(parents=True)

        def mock_expand(path):
            if path == "~/.npm":
                return str(npm_cache_dir)
            elif path == "~/.yarn/cache":
                return str(yarn_cache_dir)
            return str(tmp_path / "non_existent")

        mock_expanduser.side_effect = mock_expand

        with patch.dict(os.environ, {}, clear=True):
            is_valid, messages = validate_npm_audit_offline_mode()

            assert is_valid
            assert len(messages) == 2
            assert f"Found npm cache at {npm_cache_dir}" in messages[0]
            assert f"Found yarn cache at {yarn_cache_dir}" in messages[1]


class TestOfflineModeValidator:
    """Tests for OfflineModeValidator helper class."""

    def test_validate_cache_directory_missing_dir(self):
        """Test validation fails when cache directory is not specified."""
        is_valid, messages = OfflineModeValidator.validate_cache_directory(
            "", [".yaml", ".yml"], "TestScanner"
        )

        assert not is_valid
        assert len(messages) == 1
        assert "TestScanner cache directory not specified" in messages[0]

    def test_validate_cache_directory_nonexistent(self, tmp_path):
        """Test validation fails when cache directory doesn't exist."""
        non_existent_dir = str(tmp_path / "non_existent")

        is_valid, messages = OfflineModeValidator.validate_cache_directory(
            non_existent_dir, [".yaml", ".yml"], "TestScanner"
        )

        assert not is_valid
        assert len(messages) == 1
        assert f"Cache directory does not exist: {non_existent_dir}" in messages[0]

    def test_validate_cache_directory_no_matching_files(self, tmp_path):
        """Test validation fails when no files with specified extensions are found."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # Create files with different extensions
        (cache_dir / "file.txt").write_text("content")
        (cache_dir / "file.json").write_text("{}")

        is_valid, messages = OfflineModeValidator.validate_cache_directory(
            str(cache_dir), [".yaml", ".yml"], "TestScanner"
        )

        assert not is_valid
        assert len(messages) == 1
        assert "No cache files found with extensions ['.yaml', '.yml']" in messages[0]

    def test_validate_cache_directory_success(self, tmp_path):
        """Test successful validation with matching files."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # Create files with matching extensions
        (cache_dir / "file1.yaml").write_text("content")
        (cache_dir / "file2.yml").write_text("content")

        # Create subdirectory with more files
        subdir = cache_dir / "subdir"
        subdir.mkdir()
        (subdir / "file3.yaml").write_text("content")

        is_valid, messages = OfflineModeValidator.validate_cache_directory(
            str(cache_dir), [".yaml", ".yml"], "TestScanner"
        )

        assert is_valid
        assert len(messages) == 1
        assert "Found 3 cache files" in messages[0]

    def test_log_validation_results_success(self, caplog):
        """Test logging of successful validation results."""
        messages = ["Found 5 cache files", "Database is up to date"]

        OfflineModeValidator.log_validation_results("TestScanner", True, messages)

        # Check for either emoji or Windows-safe ASCII version
        success_patterns = [
            "TestScanner offline mode validation passed",
            "[OK] TestScanner offline mode validation passed",
        ]
        assert any(pattern in caplog.text for pattern in success_patterns), (
            f"Expected success pattern not found in: {caplog.text}"
        )
        assert "Found 5 cache files" in caplog.text
        assert "Database is up to date" in caplog.text

    def test_log_validation_results_failure(self, caplog):
        """Test logging of failed validation results."""
        messages = ["Cache directory not found", "No database files"]

        OfflineModeValidator.log_validation_results("TestScanner", False, messages)

        # Check for either emoji or Windows-safe ASCII version
        failure_patterns = [
            "TestScanner offline mode validation failed",
            "[WARNING] TestScanner offline mode validation failed",
        ]
        assert any(pattern in caplog.text for pattern in failure_patterns), (
            f"Expected failure pattern not found in: {caplog.text}"
        )
        assert "Cache directory not found" in caplog.text
        assert "No database files" in caplog.text


class TestIntegrationScenarios:
    """Integration tests for realistic offline mode scenarios."""

    def test_complete_semgrep_offline_setup(self, tmp_path):
        """Test a complete Semgrep offline setup scenario."""
        # Create a realistic cache structure
        cache_dir = tmp_path / "semgrep_cache"
        cache_dir.mkdir()

        # Create rule directories and files like Semgrep would
        (cache_dir / "p" / "ci").mkdir(parents=True)
        (cache_dir / "p" / "ci" / "python.yaml").write_text("rules: []")
        (cache_dir / "p" / "ci" / "javascript.yaml").write_text("rules: []")

        (cache_dir / "p" / "security-audit").mkdir(parents=True)
        (cache_dir / "p" / "security-audit" / "audit.yml").write_text("rules: []")

        with patch.dict(os.environ, {"SEMGREP_RULES_CACHE_DIR": str(cache_dir)}):
            is_valid, messages = validate_semgrep_offline_mode()

            assert is_valid
            assert len(messages) == 1
            assert "Found 3 rule files in cache directory" in messages[0]

    def test_complete_grype_offline_setup(self, tmp_path):
        """Test a complete Grype offline setup scenario."""
        # Create a realistic database cache structure
        cache_dir = tmp_path / "grype_cache"
        cache_dir.mkdir()

        # Create database files like Grype would
        db_file = cache_dir / "vulnerability.db"
        db_file.write_text("vulnerability database content")

        metadata_file = cache_dir / "metadata.json"
        metadata_file.write_text('{"version": "5", "built": "2024-01-01"}')

        # Set recent modification time
        recent_time = datetime.now().timestamp()
        os.utime(db_file, (recent_time, recent_time))

        with patch.dict(os.environ, {"GRYPE_DB_CACHE_DIR": str(cache_dir)}):
            is_valid, messages = validate_grype_offline_mode()

            assert is_valid
            assert len(messages) == 1
            assert "Found 1 database files, newest is 0 days old" in messages[0]

    def test_partial_offline_setup_warnings(self, tmp_path):
        """Test scenarios where offline setup is partially complete."""
        # Test Grype with old database
        cache_dir = tmp_path / "grype_cache"
        cache_dir.mkdir()

        db_file = cache_dir / "vulnerability.db"
        db_file.write_text("old database content")

        # Set old modification time (15 days ago)
        old_time = (datetime.now() - timedelta(days=15)).timestamp()
        os.utime(db_file, (old_time, old_time))

        with patch.dict(os.environ, {"GRYPE_DB_CACHE_DIR": str(cache_dir)}):
            is_valid, messages = validate_grype_offline_mode()

            # Should still be valid but with warning
            assert is_valid
            assert len(messages) == 1
            assert "Database is 15 days old, consider updating" in messages[0]
