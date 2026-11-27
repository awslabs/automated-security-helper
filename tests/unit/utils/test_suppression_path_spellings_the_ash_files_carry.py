# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The path spellings the repository's own suppression files carry match what they say.

Why this exists
---------------
`.ash.yaml` and `.ash/.ash_alpha_plugins.yaml` once said, in comments, that
ASH's path matcher ignores a trailing ``**`` on a multi-segment pattern, and a
neighbouring comment said ``/**`` is what makes ``tests/pytest-temp/**`` match
anything. Both cannot be true. ``file_path_matches`` is the matcher the SARIF
ignore filter and every suppression use, so this pins its answer for the exact
spellings the files carry: a trailing ``**`` matches every file below the
directory and not the directory entry alone.
"""

from pathlib import Path

import pytest
import yaml

from automated_security_helper.utils.suppression_matcher import file_path_matches

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
FILES = (".ash.yaml", ".ash/.ash_alpha_plugins.yaml")


@pytest.mark.parametrize(
    "pattern,path,expected",
    [
        ("tests/pytest-temp/**", "tests/pytest-temp/a/b.py", True),
        ("tests/pytest-temp/**", "tests/pytest-temp/b.py", True),
        ("tests/pytest-temp/**", "tests/other/b.py", False),
        # A bare directory name matches the subtree below it, like the "/**"
        # spelling (tests/unit/utils/test_bare_directory_path_matching.py pins
        # that behavior; this row only keeps the two suites agreeing). A
        # sibling that only shares the leading characters stays unmatched.
        ("tests/pytest-temp", "tests/pytest-temp/b.py", True),
        ("tests/pytest-temp", "tests/pytest-temp-other/b.py", False),
        ("docs/**", "docs/content/x.md", True),
        ("docs/content/**", "docs/content/reference/x.md", True),
        ("docs/content/**", "docs/ui-tests/specs/x.spec.cjs", False),
        ("tests/**/__snapshots__/**", "tests/unit/__snapshots__/a.json", True),
        ("tests/**/__snapshots__/**/*", "tests/unit/__snapshots__/a.json", True),
        ("tests/**/__snapshots__/**", "src/unit/__snapshots__/a.json", False),
        ("tests/**", "tests/unit/test_a.py", True),
        ("deploy/cdk-constructs/test/**", "deploy/cdk-constructs/test/a.ts", True),
    ],
)
def test_a_trailing_double_star_matches_files_below_the_directory(
    pattern, path, expected
):
    assert file_path_matches(path, pattern) is expected


def _spellings():
    found = []
    for name in FILES:
        text = (REPO_ROOT / name).read_text(encoding="utf-8")
        doc = yaml.safe_load(text) or {}
        settings = doc.get("global_settings") or {}
        for entry in (settings.get("suppressions") or []) + (
            settings.get("ignore_paths") or []
        ):
            path = (entry or {}).get("path")
            if isinstance(path, str) and path.endswith("/**") and "*" not in path[:-3]:
                found.append((name, path))
    return found


def test_every_literal_directory_double_star_entry_matches_a_file_below_it():
    """Each `<dir>/**` the files carry matches a file inside `<dir>`."""
    spellings = _spellings()
    assert spellings, "no `<dir>/**` entry found; the check is vacuous"
    unmatched = [
        f"{name}: {path}"
        for name, path in spellings
        if not file_path_matches(f"{path[:-3]}/a/b.py", path)
    ]
    assert not unmatched, "\n".join(unmatched)


def test_the_files_do_not_claim_a_trailing_double_star_is_ignored():
    for name in FILES:
        text = (REPO_ROOT / name).read_text(encoding="utf-8")
        assert 'ignores a trailing "**"' not in text, name
