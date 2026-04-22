"""Test that suppression glob patterns with ** match correctly."""

import pytest

from automated_security_helper.utils.suppression_matcher import _file_path_matches


@pytest.mark.parametrize(
    "pattern,path,expected",
    [
        # ** matches zero or more directories
        ("tests/**/*.py", "tests/test_example.py", True),
        ("tests/**/*.py", "tests/sub/test_foo.py", True),
        ("tests/**/*.py", "tests/a/b/test.py", True),
        # trailing ** matches everything under prefix
        ("tests/**", "tests/test_example.py", True),
        ("tests/**", "tests/sub/test.py", True),
        # leading ** matches from any depth
        ("**/*.py", "any/path/file.py", True),
        ("**/*.py", "file.py", True),
        # ** on both sides matches anywhere
        ("**/.venv/**", ".venv/lib/foo.py", True),
        ("**/.venv/**", "src/.venv/lib/foo.py", True),
        # simple glob still works
        ("src/*.py", "src/app.py", True),
        ("src/app.py", "src/app.py", True),
        # non-matches
        ("tests/**/*.py", "src/app.py", False),
        ("tests/**/*.py", "tests/test.txt", False),
        ("tests/**", "src/test.py", False),
    ],
)
def test_file_path_matches(pattern, path, expected):
    assert _file_path_matches(path, pattern) == expected
