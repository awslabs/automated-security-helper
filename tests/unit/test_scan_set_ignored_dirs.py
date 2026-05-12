# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for scan_set behavior with nested .gitignore files in ignored directories.

Covers the bug where .gitignore files inside ignored directories (e.g., .venv/)
containing '*' would cause the entire project to have 0 scannable files.
"""

import pytest
from pathlib import Path

from automated_security_helper.utils.get_scan_set import (
    _collect_ignorefiles_and_all_files,
    scan_set,
)


@pytest.fixture
def project_with_venv_gitignore(tmp_path):
    """Create a project that reproduces the 0-files bug.

    Structure:
        project/
        ├── .gitignore          (ignores .venv/, .ruff_cache/, etc.)
        ├── app.py
        ├── config.yaml
        ├── templates/
        │   └── deploy.yml
        ├── .venv/
        │   └── .gitignore      (contains just '*')
        ├── .ruff_cache/
        │   └── .gitignore      (contains just '*')
        └── .pytest_cache/
            └── .gitignore      (contains just '*')
    """
    project = tmp_path / "project"
    project.mkdir()

    # Root .gitignore - ignores .venv, .ruff_cache, .pytest_cache
    (project / ".gitignore").write_text(
        ".venv/\n"
        "venv/\n"
        ".ruff_cache/\n"
        ".pytest_cache/\n"
        "htmlcov/\n"
        "__pycache__/\n"
        "*.pyc\n"
        ".ash/\n"
    )

    # Project files that should be found
    (project / "app.py").write_text("print('hello')")
    (project / "config.yaml").write_text("key: value")
    templates = project / "templates"
    templates.mkdir()
    (templates / "deploy.yml").write_text("stages: [build]")

    # .venv with a .gitignore that contains '*' (standard venv pattern)
    venv = project / ".venv"
    venv.mkdir()
    (venv / ".gitignore").write_text("*\n")
    (venv / "pyvenv.cfg").write_text("home = /usr/bin")
    lib = venv / "lib"
    lib.mkdir()
    (lib / "site.py").write_text("pass")

    # .ruff_cache with a .gitignore that contains '*'
    ruff = project / ".ruff_cache"
    ruff.mkdir()
    (ruff / ".gitignore").write_text("# Automatically created by ruff.\n*\n")
    (ruff / "cache.bin").write_text("binary")

    # .pytest_cache with a .gitignore that contains '*'
    pytest_cache = project / ".pytest_cache"
    pytest_cache.mkdir()
    (pytest_cache / ".gitignore").write_text("# Created by pytest automatically.\n*\n")
    (pytest_cache / "v" / "cache").mkdir(parents=True)

    return project


class TestScanSetIgnoredDirectories:
    """Tests that .gitignore files inside ignored directories don't pollute the global spec."""

    def test_venv_gitignore_does_not_cause_zero_files(self, project_with_venv_gitignore):
        """The '*' rule in .venv/.gitignore should NOT cause 0 files to be found."""
        result = scan_set(source=str(project_with_venv_gitignore))

        # Should find at least app.py, config.yaml, deploy.yml
        assert len(result) >= 3, f"Expected at least 3 files, got {len(result)}: {result}"

        # Verify specific files are included
        filenames = [Path(f).name for f in result]
        assert "app.py" in filenames
        assert "config.yaml" in filenames
        assert "deploy.yml" in filenames

    def test_ignored_dir_gitignore_not_collected(self, project_with_venv_gitignore):
        """_collect_ignorefiles_and_all_files should NOT collect .gitignore from ignored dirs."""
        ignore_files, all_files = _collect_ignorefiles_and_all_files(
            str(project_with_venv_gitignore)
        )

        # Should only find the root .gitignore, not the ones in .venv/, .ruff_cache/, etc.
        ignore_basenames = [Path(f).parent.name for f in ignore_files]
        assert "project" in ignore_basenames or any(
            f.endswith("project/.gitignore") or f == str(project_with_venv_gitignore / ".gitignore")
            for f in ignore_files
        )

        # Should NOT contain .venv/.gitignore
        venv_ignores = [f for f in ignore_files if ".venv" in f]
        assert len(venv_ignores) == 0, f"Found .venv/.gitignore that should be skipped: {venv_ignores}"

        # Should NOT contain .ruff_cache/.gitignore
        ruff_ignores = [f for f in ignore_files if ".ruff_cache" in f]
        assert len(ruff_ignores) == 0, f"Found .ruff_cache/.gitignore that should be skipped: {ruff_ignores}"

    def test_ignored_dir_files_not_in_all_files(self, project_with_venv_gitignore):
        """Files inside ignored directories should not be collected at all."""
        _ignore_files, all_files = _collect_ignorefiles_and_all_files(
            str(project_with_venv_gitignore)
        )

        # Should NOT contain files from .venv/
        venv_files = [f for f in all_files if ".venv" in f]
        assert len(venv_files) == 0, f"Found .venv files that should be skipped: {venv_files}"

    def test_scan_set_excludes_venv_files(self, project_with_venv_gitignore):
        """scan_set should not include files from .venv/ in the result."""
        result = scan_set(source=str(project_with_venv_gitignore))

        venv_files = [f for f in result if ".venv" in f]
        assert len(venv_files) == 0, f"Found .venv files in scan set: {venv_files}"

    def test_scan_set_excludes_ruff_cache_files(self, project_with_venv_gitignore):
        """scan_set should not include files from .ruff_cache/ in the result."""
        result = scan_set(source=str(project_with_venv_gitignore))

        ruff_files = [f for f in result if ".ruff_cache" in f]
        assert len(ruff_files) == 0, f"Found .ruff_cache files in scan set: {ruff_files}"

    def test_non_ignored_subdirs_still_walked(self, project_with_venv_gitignore):
        """Directories NOT in .gitignore should still be walked normally."""
        result = scan_set(source=str(project_with_venv_gitignore))

        # templates/ is not ignored, so deploy.yml should be found
        template_files = [f for f in result if "templates" in f]
        assert len(template_files) >= 1

    def test_no_root_gitignore_still_works(self, tmp_path):
        """If there's no root .gitignore, all directories should be walked."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "app.py").write_text("pass")
        sub = project / "subdir"
        sub.mkdir()
        (sub / "lib.py").write_text("pass")

        result = scan_set(source=str(project))

        assert len(result) == 2


class TestExcludeKeyValidation:
    """Tests that the --exclude=value pattern is accepted by the flag key validator."""

    def test_exclude_equals_pattern_is_valid(self):
        """The --exclude='...' pattern should pass the key validation regex."""
        import re
        pattern = re.compile(r"^-{1,2}[A-Za-z][A-Za-z0-9_\-]*(=.*)?$")

        # These should all be valid
        assert pattern.match("--exclude=\".venv/**\"")
        assert pattern.match("--skip-path=\".venv/\"")
        assert pattern.match("--config=p/ci")
        assert pattern.match("--format")
        assert pattern.match("-f")
        assert pattern.match("--no-rewrite-rule-ids")

        # These should still be invalid (injection attempts)
        assert not pattern.match("; rm -rf /")
        assert not pattern.match("| cat /etc/passwd")
        assert not pattern.match("--")
        assert not pattern.match("-")
        assert not pattern.match("")
