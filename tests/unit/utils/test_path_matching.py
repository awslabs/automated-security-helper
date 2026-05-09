# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the canonical _recursive_glob_match / _path_pattern_matches in utils/path_matching."""

import pytest

from automated_security_helper.utils.path_matching import (
    _path_pattern_matches,
    _recursive_glob_match,
    match_glob,
)


class TestRecursiveGlobMatch:
    """Direct tests for _recursive_glob_match (lowercase paths assumed by caller)."""

    def test_bare_double_star_matches_everything(self):
        assert _recursive_glob_match("a/b/c.py", "**") is True

    def test_trailing_double_star_matches_files_under_prefix(self):
        assert _recursive_glob_match("tests/foo.py", "tests/**") is True

    def test_trailing_double_star_matches_deep_nesting(self):
        assert _recursive_glob_match("tests/a/b/c/foo.py", "tests/**") is True

    def test_trailing_double_star_no_match_wrong_prefix(self):
        assert _recursive_glob_match("src/foo.py", "tests/**") is False

    def test_leading_double_star_matches_any_depth(self):
        assert _recursive_glob_match("a/b/c/file.py", "**/*.py") is True

    def test_leading_double_star_matches_root_level(self):
        assert _recursive_glob_match("file.py", "**/*.py") is True

    def test_leading_double_star_no_match_wrong_extension(self):
        assert _recursive_glob_match("a/b/file.txt", "**/*.py") is False

    def test_middle_double_star_matches_zero_dirs(self):
        assert _recursive_glob_match("tests/test_foo.py", "tests/**/*.py") is True

    def test_middle_double_star_matches_one_dir(self):
        assert _recursive_glob_match("tests/sub/test_foo.py", "tests/**/*.py") is True

    def test_middle_double_star_matches_many_dirs(self):
        assert _recursive_glob_match("tests/a/b/c/test_foo.py", "tests/**/*.py") is True

    def test_middle_double_star_no_match_wrong_extension(self):
        assert _recursive_glob_match("tests/sub/test_foo.txt", "tests/**/*.py") is False

    def test_double_star_on_both_sides_matches_middle_anywhere(self):
        assert _recursive_glob_match(".venv/lib/foo.py", "**/.venv/**") is True

    def test_double_star_on_both_sides_matches_nested_prefix(self):
        assert _recursive_glob_match("src/.venv/lib/foo.py", "**/.venv/**") is True

    def test_double_star_on_both_sides_no_match_absent_segment(self):
        assert _recursive_glob_match("src/lib/foo.py", "**/.venv/**") is False

    def test_backslash_normalized_to_forward_slash(self):
        assert _recursive_glob_match("tests\\sub\\foo.py", "tests/**/*.py") is True

    def test_simple_pattern_without_double_star_falls_through_to_fnmatch(self):
        # No ** — function shouldn't be called normally, but must not crash.
        assert _recursive_glob_match("src/app.py", "src/app.py") is True

    def test_github_workflows_pattern(self):
        assert _recursive_glob_match(
            ".github/workflows/run-ash.yml", ".github/**/*.yml"
        ) is True

    def test_deeply_nested_test_data_pattern(self):
        assert _recursive_glob_match(
            "tests/test_data/scanners/cdk/foo.yaml_results/cfn.json",
            "tests/test_data/**",
        ) is True


class TestPathPatternMatches:
    """Tests for _path_pattern_matches (handles None, case-insensitivity, dispatch)."""

    def test_none_file_path_returns_false(self):
        assert _path_pattern_matches(None, "src/*.py") is False

    def test_exact_match_case_insensitive(self):
        assert _path_pattern_matches("SRC/App.py", "src/app.py") is True

    def test_simple_glob_match(self):
        assert _path_pattern_matches("src/app.py", "src/*.py") is True

    def test_simple_glob_no_match(self):
        assert _path_pattern_matches("src/app.txt", "src/*.py") is False

    def test_double_star_dispatches_to_recursive(self):
        assert _path_pattern_matches("tests/sub/foo.py", "tests/**/*.py") is True

    def test_double_star_no_match(self):
        assert _path_pattern_matches("src/app.py", "tests/**/*.py") is False

    def test_case_insensitive_glob(self):
        assert _path_pattern_matches("SRC/APP.PY", "src/*.py") is True


class TestMatchGlob:
    """Tests for the public match_glob entry point."""

    def test_basic_double_star(self):
        assert match_glob("tests/sub/foo.py", "tests/**/*.py") is True

    def test_simple_exact(self):
        assert match_glob("src/app.py", "src/app.py") is True

    def test_non_match(self):
        assert match_glob("src/app.txt", "tests/**/*.py") is False

    def test_none_path_returns_false(self):
        assert match_glob(None, "tests/**") is False  # type: ignore[arg-type]


class TestSingleCanonicalDefinition:
    """Architectural guard: _recursive_glob_match must live in exactly one module."""

    def test_only_one_definition_in_codebase(self):
        import ast
        import pathlib

        root = pathlib.Path(__file__).parents[3] / "automated_security_helper"
        definitions = []
        for py_file in root.rglob("*.py"):
            try:
                tree = ast.parse(py_file.read_text())
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == "_recursive_glob_match":
                    definitions.append(str(py_file.relative_to(root.parent)))

        assert len(definitions) == 1, (
            f"_recursive_glob_match defined in {len(definitions)} files: {definitions}. "
            "It must live in exactly one place: automated_security_helper/utils/path_matching.py"
        )
