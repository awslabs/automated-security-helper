# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests: a ``**`` at either end of a multi-segment pattern is honored.

``_recursive_glob_match`` used to split a pattern on ``**`` and, once there were
two or more segments, anchor the first segment to the start of the path and the
last to the end, whatever surrounded them. A trailing or leading ``**`` was
dropped on the floor. Measured before the fix:

* ``file_path_matches('a/x/b/c', 'a/**/b/**')`` returned False.
* ``tests/**/__snapshots__/**`` matched no file under a snapshot directory.
* ``**/x/**/y`` did not match ``p/x/q/y``.

The matcher serves two consumers that a user configures directly, and both
are exercised here end to end rather than only through the helper:

* ``global_settings.ignore_paths`` -- through ``apply_suppressions_to_sarif``,
  which calls ``suppression_matcher.file_path_matches``.
* ``global_settings.suppressions`` -- through ``AshSuppression.matches``
  (``path_matching._path_pattern_matches``) and ``should_suppress_finding``
  (``suppression_matcher.file_path_matches``).
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.models.core import AshSuppression, IgnorePathWithReason
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.sarif_schema_model import Run, SarifReport
from automated_security_helper.utils.path_matching import (
    _recursive_glob_match,
    match_glob,
)
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif
from automated_security_helper.utils.suppression_matcher import (
    file_path_matches,
    should_suppress_finding,
)

# (pattern, path, expected). The first block is the defect; the rest pin the
# shapes the old matcher already handled, so the rewrite is shown not to have
# moved them.
CASES = [
    # Trailing ** after a middle **: the reported failures.
    ("a/**/b/**", "a/x/b/c", True),
    ("a/**/b/**", "a/b/c", True),
    ("a/**/b/**", "a/x/y/b/c/d", True),
    ("a/**/b/**", "a/x/b", True),
    ("a/**/b/**", "a/x/c", False),
    ("a/**/b/**", "z/a/x/b/c", False),
    ("tests/**/__snapshots__/**", "tests/unit/__snapshots__/test_x.ambr", True),
    ("tests/**/__snapshots__/**", "tests/__snapshots__/a/b.ambr", True),
    ("tests/**/__snapshots__/**", "tests/unit/test_x.py", False),
    # Leading ** before a middle **: also anchored to the start before.
    ("**/x/**/y", "p/x/q/y", True),
    ("**/x/**/y", "x/y", True),
    ("**/x/**/y", "p/x/q/z", False),
    ("**/node_modules/**/*.js", "web/node_modules/pkg/lib/index.js", True),
    # Several ** in a row, and three of them interleaved.
    ("a/**/**/b", "a/x/b", True),
    ("**/a/**/b/**/c", "q/a/r/b/s/c", True),
    ("**/a/**/b/**/c", "q/a/r/c/s/b", False),
    # Behavior the old matcher already had, unchanged.
    ("**", "a/b/c.py", True),
    ("**", "", True),
    ("tests/**", "tests", True),
    ("tests/**", "tests/a/b.py", True),
    ("tests/**", "testsuite/a.py", False),
    ("tests/**/", "tests/a.py", True),
    ("**/*.py", "a.py", True),
    ("**/*.py", "a/b/c.py", True),
    ("**/*.py", "a/b/c.txt", False),
    ("/**/x.py", "a/x.py", True),
    ("tests/**/*.py", "tests/test_foo.py", True),
    ("tests/**/*.py", "tests/a/b/test_foo.py", True),
    ("a/**/b", "a/b", True),
    ("a/*/b/**", "a/x/b/c", True),
    ("a/*/b/**", "a/x/y/b/c", False),
    ("**/.venv/**", "src/.venv/lib/foo.py", True),
    # A ** inside a longer component is an ordinary *, as in gitignore.
    ("src/**.py", "src/app.py", True),
    ("src/**.py", "src/sub/app.py", False),
]


@pytest.mark.parametrize("pattern,path,expected", CASES)
def test_recursive_glob_match(pattern, path, expected):
    assert _recursive_glob_match(path, pattern) is expected


@pytest.mark.parametrize("pattern,path,expected", CASES)
def test_both_public_entry_points_agree(pattern, path, expected):
    """``file_path_matches`` and ``match_glob`` route ``**`` to the same matcher."""
    assert file_path_matches(path, pattern) is expected
    assert match_glob(path, pattern) is expected


def test_the_reported_example_verbatim():
    assert file_path_matches("a/x/b/c", "a/**/b/**") is True


def test_backslash_separators_are_normalized_on_both_sides():
    assert _recursive_glob_match("a\\x\\b\\c", "a/**/b/**") is True
    assert _recursive_glob_match("a/x/b/c", "a\\**\\b\\**") is True


def test_case_is_folded_by_the_callers():
    assert file_path_matches(
        "Tests/Unit/__snapshots__/X.ambr", "tests/**/__snapshots__/**"
    )
    assert match_glob("Tests/Unit/__snapshots__/X.ambr", "TESTS/**/__SNAPSHOTS__/**")


def test_a_long_path_does_not_blow_up():
    """Memoized: many ** against a deep path stays linear-ish rather than exponential."""
    path = "/".join(["d"] * 200) + "/end"
    pattern = "/".join(["**"] * 3 + ["d", "**", "nope"])
    assert _recursive_glob_match(path, pattern) is False
    assert _recursive_glob_match(path, "**/d/**/d/**/end") is True


# ---------------------------------------------------------------------------
# Consumer 1: global_settings.ignore_paths
# ---------------------------------------------------------------------------


def _sarif_with_finding(uri: str) -> SarifReport:
    return SarifReport(
        runs=[
            Run(
                tool={"driver": {"name": "checkov", "version": "3.2.0"}},
                results=[
                    {
                        "ruleId": "CKV_AWS_56",
                        "message": {"text": "Finding"},
                        "level": "warning",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": uri},
                                    "region": {"startLine": 3},
                                }
                            }
                        ],
                    }
                ],
            )
        ]
    )


def _context(ignore_paths=(), suppressions=()) -> MagicMock:
    ctx = MagicMock()
    ctx.source_dir = Path("/src")
    ctx.output_dir = Path("/out")
    ctx.ignore_suppressions = False
    ctx.config = MagicMock()
    ctx.config.global_settings = MagicMock()
    ctx.config.global_settings.ignore_paths = [
        IgnorePathWithReason(path=p, reason="test ignore") for p in ignore_paths
    ]
    ctx.config.global_settings.suppressions = list(suppressions)
    return ctx


def _remaining(sarif: SarifReport) -> list:
    return [r for run in sarif.runs for r in (run.results or [])]


@pytest.mark.parametrize(
    "ignore_path,uri",
    [
        ("tests/**/__snapshots__/**", "tests/unit/__snapshots__/test_x.ambr"),
        ("a/**/b/**", "a/x/b/c"),
        ("**/x/**/y", "p/x/q/y"),
    ],
)
def test_ignore_paths_drop_a_finding_under_a_trailing_double_star(ignore_path, uri):
    result = apply_suppressions_to_sarif(
        _sarif_with_finding(uri), _context([ignore_path])
    )
    assert _remaining(result) == [], (
        f"ignore_paths entry {ignore_path!r} did not drop the finding at {uri!r}"
    )


def test_ignore_paths_keep_a_finding_outside_the_pattern():
    result = apply_suppressions_to_sarif(
        _sarif_with_finding("tests/unit/test_x.py"),
        _context(["tests/**/__snapshots__/**"]),
    )
    assert len(_remaining(result)) == 1


# ---------------------------------------------------------------------------
# Consumer 2: global_settings.suppressions
# ---------------------------------------------------------------------------


def _finding(file_path: str) -> FlatVulnerability:
    return FlatVulnerability(
        id="test-id",
        title="Test Finding",
        description="Test Description",
        severity="HIGH",
        scanner="test-scanner",
        scanner_type="SAST",
        rule_id="TEST-001",
        file_path=file_path,
        line_start=3,
        line_end=3,
    )


@pytest.mark.parametrize(
    "pattern,file_path,expected",
    [
        ("tests/**/__snapshots__/**", "tests/unit/__snapshots__/test_x.ambr", True),
        ("a/**/b/**", "a/x/b/c", True),
        ("**/x/**/y", "p/x/q/y", True),
        ("tests/**/__snapshots__/**", "tests/unit/test_x.py", False),
    ],
)
def test_suppressions_honor_a_trailing_double_star(pattern, file_path, expected):
    suppression = AshSuppression(reason="r", rule_id="TEST-001", path=pattern)
    finding = _finding(file_path)
    assert suppression.matches(finding) is expected
    assert should_suppress_finding(finding, [suppression])[0] is expected
