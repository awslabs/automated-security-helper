"""Regression test: glob calls use recursive=True for nested ignore files (M7)."""

import tempfile
from pathlib import Path

from automated_security_helper.utils.get_scan_set import get_ash_ignorespec_lines


def test_nested_gitignore_found_recursively():
    with tempfile.TemporaryDirectory() as tmpdir:
        nested = Path(tmpdir) / "sub" / "deep"
        nested.mkdir(parents=True)
        (nested / ".gitignore").write_text("*.log\n")

        lines = get_ash_ignorespec_lines(tmpdir)

        found = any(
            "sub/deep/.gitignore" in line or "sub\\deep\\.gitignore" in line
            for line in lines
        )
        assert found, f"Nested .gitignore not found in lines: {lines}"


def test_nested_dotignore_found_recursively():
    with tempfile.TemporaryDirectory() as tmpdir:
        nested = Path(tmpdir) / "a" / "b"
        nested.mkdir(parents=True)
        (nested / ".ignore").write_text("*.tmp\n")

        lines = get_ash_ignorespec_lines(tmpdir)

        found = any(
            "a/b/.ignore" in line or "a\\b\\.ignore" in line
            for line in lines
        )
        assert found, f"Nested .ignore not found in lines: {lines}"
