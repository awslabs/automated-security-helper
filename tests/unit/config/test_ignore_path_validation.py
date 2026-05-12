# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for ignore_path and suppression path validation in config linter and validator.

Covers two bugs:
1. Invalid ignore_paths pass validation silently (no error from `ash config validate`)
2. Folder paths without `**` are silently ignored (should warn to add `/**`)
"""

import pytest
import yaml

from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
    LintSeverity,
)
from automated_security_helper.config.config_validator import ConfigValidator


@pytest.fixture
def project_with_dirs(tmp_path):
    """Create a project structure with directories for testing path validation."""
    # Create project structure
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('hello')")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_data").mkdir()
    (tmp_path / "tests" / "test_data" / "sample.json").write_text("{}")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "guide.md").write_text("# Guide")
    (tmp_path / ".ash").mkdir()
    return tmp_path


@pytest.fixture
def config_with_dir_ignore_path(project_with_dirs):
    """Config with ignore_path pointing to a directory without **."""
    config_path = project_with_dirs / ".ash" / ".ash.yaml"
    config_data = {
        "project_name": "test-project",
        "global_settings": {
            "ignore_paths": [
                {
                    "path": "tests/test_data",
                    "reason": "Test data only",
                },
            ],
        },
    }
    config_path.write_text(yaml.dump(config_data))
    return config_path


@pytest.fixture
def config_with_trailing_slash_ignore_path(project_with_dirs):
    """Config with ignore_path pointing to a directory with trailing slash but no **."""
    config_path = project_with_dirs / ".ash" / ".ash.yaml"
    config_data = {
        "project_name": "test-project",
        "global_settings": {
            "ignore_paths": [
                {
                    "path": "tests/test_data/",
                    "reason": "Test data only",
                },
            ],
        },
    }
    config_path.write_text(yaml.dump(config_data))
    return config_path


@pytest.fixture
def config_with_valid_ignore_paths(project_with_dirs):
    """Config with properly formed ignore_paths using **."""
    config_path = project_with_dirs / ".ash" / ".ash.yaml"
    config_data = {
        "project_name": "test-project",
        "global_settings": {
            "ignore_paths": [
                {
                    "path": "tests/test_data/**",
                    "reason": "Test data only",
                },
                {
                    "path": "**/.venv/**",
                    "reason": "Virtual environment",
                },
                {
                    "path": "src/*.py",
                    "reason": "Source files with wildcard",
                },
            ],
        },
    }
    config_path.write_text(yaml.dump(config_data))
    return config_path


@pytest.fixture
def config_with_nonexistent_dir_path(project_with_dirs):
    """Config with ignore_path pointing to a non-existent directory (e.g., uninitialized venv)."""
    config_path = project_with_dirs / ".ash" / ".ash.yaml"
    config_data = {
        "project_name": "test-project",
        "global_settings": {
            "ignore_paths": [
                {
                    "path": ".venv",
                    "reason": "Virtual environment (not initialized)",
                },
                {
                    "path": "node_modules",
                    "reason": "Node modules (not installed)",
                },
            ],
        },
    }
    config_path.write_text(yaml.dump(config_data))
    return config_path


@pytest.fixture
def config_with_suppression_dir_path(project_with_dirs):
    """Config with suppression path pointing to a directory without **."""
    config_path = project_with_dirs / ".ash" / ".ash.yaml"
    config_data = {
        "project_name": "test-project",
        "global_settings": {
            "suppressions": [
                {
                    "path": "docs",
                    "rule_id": "SECRET-*",
                    "reason": "Documentation examples",
                },
            ],
        },
    }
    config_path.write_text(yaml.dump(config_data))
    return config_path


class TestIgnorePathLinting:
    """Tests for ignore_path validation in the config linter."""

    def test_warns_on_directory_without_glob(
        self, config_with_dir_ignore_path, project_with_dirs
    ):
        """A path pointing to an existing directory without ** should produce a warning."""
        result = ConfigLinter.lint(config_with_dir_ignore_path)

        ignore_path_issues = [
            i for i in result.issues if i.category == LintCategory.IGNORE_PATH_ISSUE
        ]
        assert len(ignore_path_issues) == 1
        assert ignore_path_issues[0].severity == LintSeverity.WARNING
        assert "tests/test_data" in ignore_path_issues[0].message
        assert "/**" in ignore_path_issues[0].message

    def test_warns_on_directory_with_trailing_slash(
        self, config_with_trailing_slash_ignore_path
    ):
        """A path with trailing slash pointing to an existing directory should also warn."""
        result = ConfigLinter.lint(config_with_trailing_slash_ignore_path)

        ignore_path_issues = [
            i for i in result.issues if i.category == LintCategory.IGNORE_PATH_ISSUE
        ]
        assert len(ignore_path_issues) == 1
        assert ignore_path_issues[0].severity == LintSeverity.WARNING
        assert "tests/test_data" in ignore_path_issues[0].message

    def test_no_warning_for_valid_glob_paths(self, config_with_valid_ignore_paths):
        """Paths with ** or file wildcards should not produce warnings."""
        result = ConfigLinter.lint(config_with_valid_ignore_paths)

        ignore_path_issues = [
            i for i in result.issues if i.category == LintCategory.IGNORE_PATH_ISSUE
        ]
        assert len(ignore_path_issues) == 0

    def test_no_warning_for_nonexistent_directory(
        self, config_with_nonexistent_dir_path
    ):
        """Paths that don't exist as directories should not produce warnings.

        This handles the case of virtual environments that haven't been initialized,
        or node_modules that haven't been installed.
        """
        result = ConfigLinter.lint(config_with_nonexistent_dir_path)

        ignore_path_issues = [
            i for i in result.issues if i.category == LintCategory.IGNORE_PATH_ISSUE
        ]
        assert len(ignore_path_issues) == 0

    def test_warns_on_suppression_directory_path(
        self, config_with_suppression_dir_path
    ):
        """Suppression paths pointing to existing directories without ** should also warn."""
        result = ConfigLinter.lint(config_with_suppression_dir_path)

        ignore_path_issues = [
            i for i in result.issues if i.category == LintCategory.IGNORE_PATH_ISSUE
        ]
        assert len(ignore_path_issues) == 1
        assert "docs" in ignore_path_issues[0].message
        assert "/**" in ignore_path_issues[0].message

    def test_respects_source_dir_parameter(self, tmp_path):
        """The source_dir parameter should be used for resolving paths."""
        # Create a separate source directory with a 'lib' folder
        source_dir = tmp_path / "source"
        source_dir.mkdir()
        (source_dir / "lib").mkdir()
        (source_dir / "lib" / "utils.py").write_text("pass")

        # Config is in a different location
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        config_path = config_dir / "config.yaml"
        config_data = {
            "project_name": "test-project",
            "global_settings": {
                "ignore_paths": [
                    {"path": "lib", "reason": "Library folder"},
                ],
            },
        }
        config_path.write_text(yaml.dump(config_data))

        # Without source_dir, 'lib' won't resolve (config_dir has no 'lib')
        result_no_source = ConfigLinter.lint(config_path)
        issues_no_source = [
            i
            for i in result_no_source.issues
            if i.category == LintCategory.IGNORE_PATH_ISSUE
        ]
        assert (
            len(issues_no_source) == 0
        )  # No warning because dir doesn't exist relative to config

        # With source_dir, 'lib' resolves to an existing directory
        result_with_source = ConfigLinter.lint(config_path, source_dir=source_dir)
        issues_with_source = [
            i
            for i in result_with_source.issues
            if i.category == LintCategory.IGNORE_PATH_ISSUE
        ]
        assert len(issues_with_source) == 1
        assert "lib" in issues_with_source[0].message

    def test_multiple_issues_reported(self, project_with_dirs):
        """Multiple directory paths without ** should each produce a warning."""
        config_path = project_with_dirs / ".ash" / ".ash.yaml"
        config_data = {
            "project_name": "test-project",
            "global_settings": {
                "ignore_paths": [
                    {"path": "tests/test_data", "reason": "Test data"},
                    {"path": "docs", "reason": "Documentation"},
                ],
            },
        }
        config_path.write_text(yaml.dump(config_data))

        result = ConfigLinter.lint(config_path)

        ignore_path_issues = [
            i for i in result.issues if i.category == LintCategory.IGNORE_PATH_ISSUE
        ]
        assert len(ignore_path_issues) == 2

    def test_path_prefix_in_issue(self, config_with_dir_ignore_path):
        """The issue should include the correct config path prefix for identification."""
        result = ConfigLinter.lint(config_with_dir_ignore_path)

        ignore_path_issues = [
            i for i in result.issues if i.category == LintCategory.IGNORE_PATH_ISSUE
        ]
        assert len(ignore_path_issues) == 1
        assert "global_settings.ignore_paths[0].path" in ignore_path_issues[0].path


class TestIgnorePathValidation:
    """Tests for ignore_path validation in the config validator (ash config validate)."""

    def test_validate_warns_on_directory_without_glob(
        self, config_with_dir_ignore_path
    ):
        """ash config validate should flag directory paths without **."""
        is_valid, errors = ConfigValidator.validate_config_file(
            config_with_dir_ignore_path
        )

        # Should not be valid because of the path warning
        assert not is_valid
        assert any("tests/test_data" in e and "/**" in e for e in errors)

    def test_validate_passes_with_valid_paths(self, config_with_valid_ignore_paths):
        """ash config validate should pass with properly formed paths."""
        is_valid, errors = ConfigValidator.validate_config_file(
            config_with_valid_ignore_paths
        )

        # Should be valid (no path-related errors)
        path_errors = [e for e in errors if "directory" in e.lower() and "/**" in e]
        assert len(path_errors) == 0

    def test_validate_no_warning_for_nonexistent_path(
        self, config_with_nonexistent_dir_path
    ):
        """ash config validate should not warn about paths that don't exist as directories."""
        is_valid, errors = ConfigValidator.validate_config_file(
            config_with_nonexistent_dir_path
        )

        path_errors = [e for e in errors if "directory" in e.lower() and "/**" in e]
        assert len(path_errors) == 0

    def test_validate_warns_on_suppression_directory_path(
        self, config_with_suppression_dir_path
    ):
        """ash config validate should also flag suppression paths pointing to directories."""
        is_valid, errors = ConfigValidator.validate_config_file(
            config_with_suppression_dir_path
        )

        assert not is_valid
        assert any("docs" in e and "/**" in e for e in errors)

    def test_validate_with_source_dir(self, tmp_path):
        """ash config validate should accept source_dir for path resolution."""
        # Create source with a directory
        source_dir = tmp_path / "project"
        source_dir.mkdir()
        (source_dir / "vendor").mkdir()
        (source_dir / ".ash").mkdir()

        config_path = source_dir / ".ash" / ".ash.yaml"
        config_data = {
            "project_name": "test-project",
            "global_settings": {
                "ignore_paths": [
                    {"path": "vendor", "reason": "Third-party code"},
                ],
            },
        }
        config_path.write_text(yaml.dump(config_data))

        is_valid, errors = ConfigValidator.validate_config_file(
            config_path, source_dir=source_dir
        )

        assert not is_valid
        path_errors = [e for e in errors if "vendor" in e and "/**" in e]
        assert len(path_errors) == 1


class TestEdgeCases:
    """Edge cases for path validation."""

    def test_path_with_glob_in_middle(self, project_with_dirs):
        """Paths like 'src/*/test.py' should not trigger the warning."""
        config_path = project_with_dirs / ".ash" / ".ash.yaml"
        config_data = {
            "project_name": "test-project",
            "global_settings": {
                "ignore_paths": [
                    {"path": "src/*/test.py", "reason": "Test files"},
                ],
            },
        }
        config_path.write_text(yaml.dump(config_data))

        result = ConfigLinter.lint(config_path)
        ignore_path_issues = [
            i for i in result.issues if i.category == LintCategory.IGNORE_PATH_ISSUE
        ]
        assert len(ignore_path_issues) == 0

    def test_path_with_question_mark_glob(self, project_with_dirs):
        """Paths with ? glob should not trigger the warning."""
        config_path = project_with_dirs / ".ash" / ".ash.yaml"
        config_data = {
            "project_name": "test-project",
            "global_settings": {
                "ignore_paths": [
                    {"path": "src/app?.py", "reason": "App files"},
                ],
            },
        }
        config_path.write_text(yaml.dump(config_data))

        result = ConfigLinter.lint(config_path)
        ignore_path_issues = [
            i for i in result.issues if i.category == LintCategory.IGNORE_PATH_ISSUE
        ]
        assert len(ignore_path_issues) == 0

    def test_exact_file_path_no_warning(self, project_with_dirs):
        """An exact file path should not trigger the warning even if it exists."""
        config_path = project_with_dirs / ".ash" / ".ash.yaml"
        config_data = {
            "project_name": "test-project",
            "global_settings": {
                "ignore_paths": [
                    {"path": "src/app.py", "reason": "Specific file"},
                ],
            },
        }
        config_path.write_text(yaml.dump(config_data))

        result = ConfigLinter.lint(config_path)
        ignore_path_issues = [
            i for i in result.issues if i.category == LintCategory.IGNORE_PATH_ISSUE
        ]
        assert len(ignore_path_issues) == 0

    def test_empty_ignore_paths_no_crash(self, project_with_dirs):
        """Empty ignore_paths list should not cause issues."""
        config_path = project_with_dirs / ".ash" / ".ash.yaml"
        config_data = {
            "project_name": "test-project",
            "global_settings": {
                "ignore_paths": [],
            },
        }
        config_path.write_text(yaml.dump(config_data))

        result = ConfigLinter.lint(config_path)
        ignore_path_issues = [
            i for i in result.issues if i.category == LintCategory.IGNORE_PATH_ISSUE
        ]
        assert len(ignore_path_issues) == 0

    def test_no_global_settings_no_crash(self, project_with_dirs):
        """Config without global_settings should not crash."""
        config_path = project_with_dirs / ".ash" / ".ash.yaml"
        config_data = {
            "project_name": "test-project",
        }
        config_path.write_text(yaml.dump(config_data))

        result = ConfigLinter.lint(config_path)
        ignore_path_issues = [
            i for i in result.issues if i.category == LintCategory.IGNORE_PATH_ISSUE
        ]
        assert len(ignore_path_issues) == 0

    def test_mixed_valid_and_invalid_paths(self, project_with_dirs):
        """Only directory paths without ** should be flagged, valid ones should pass."""
        config_path = project_with_dirs / ".ash" / ".ash.yaml"
        config_data = {
            "project_name": "test-project",
            "global_settings": {
                "ignore_paths": [
                    {"path": "tests/test_data/**", "reason": "Valid - has **"},
                    {"path": "docs", "reason": "Invalid - directory without **"},
                    {"path": "src/app.py", "reason": "Valid - specific file"},
                    {"path": "nonexistent_dir", "reason": "Valid - doesn't exist"},
                ],
            },
        }
        config_path.write_text(yaml.dump(config_data))

        result = ConfigLinter.lint(config_path)
        ignore_path_issues = [
            i for i in result.issues if i.category == LintCategory.IGNORE_PATH_ISSUE
        ]
        # Only 'docs' should be flagged (exists as directory, no **)
        assert len(ignore_path_issues) == 1
        assert "docs" in ignore_path_issues[0].message
