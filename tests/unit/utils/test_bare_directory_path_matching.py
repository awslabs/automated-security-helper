# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A glob-free pattern names a directory and matches the files below it (#894).

The defect: ``file_path_matches`` and ``ignore_path_matches`` read a bare
directory name (``tests``, or ``tests/`` in a suppression) as a literal path,
which no finding's file has, so a bare-directory ignore path or suppression
silently matched nothing. The rule these tests pin: a pattern with no glob
character (``*``, ``?``, ``[``) also matches every path below the directory it
names, anchored at the start of the path -- ``tests`` covers
``tests/test_x.py`` and ``tests/sub/test_y.py`` and nothing in
``pkg/tests/``. Glob patterns keep their meaning exactly.
"""

import pytest

from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.suppression_matcher import (
    file_path_matches,
    ignore_path_matches,
    should_suppress_finding,
)

pytestmark = pytest.mark.unit


def _finding(file_path: str, **extra) -> FlatVulnerability:
    return FlatVulnerability(
        id="finding-1",
        title="Test finding",
        description="Test finding",
        severity="MEDIUM",
        scanner="bandit",
        scanner_type="SAST",
        rule_id="B101",
        file_path=file_path,
        **extra,
    )


class TestBareDirectoryMatches:
    """The issue's repro: a bare directory name matches the subtree below it."""

    @pytest.mark.parametrize(
        "path",
        ["tests/test_x.py", "tests/sub/test_y.py"],
    )
    @pytest.mark.parametrize("pattern", ["tests", "tests/"])
    def test_bare_and_trailing_slash_directory_match_the_subtree(
        self, path: str, pattern: str
    ):
        assert file_path_matches(path, pattern) is True
        assert ignore_path_matches(path, pattern) is True

    def test_nested_bare_directory_is_anchored_at_its_spelling(self):
        # ``a/b`` names the directory a/b, so a path below it matches ...
        assert file_path_matches("a/b/c.py", "a/b") is True
        # ... and a path below a directory elsewhere does not.
        assert file_path_matches("x/a/b/c.py", "a/b") is False

    def test_bare_directory_suppression_matches_findings_below_it(self):
        suppression = AshSuppression(
            rule_id="B101", path="tests", reason="pytest assert idiom"
        )
        matched, matching = should_suppress_finding(
            _finding("tests/test_x.py"), [suppression]
        )
        assert matched is True
        assert matching is suppression


class TestNothingElseWidens:
    """Characterization: what must NOT change with the directory rule."""

    @pytest.mark.parametrize("pattern", ["tests", "tests/"])
    def test_a_bare_segment_never_matches_mid_path(self, pattern: str):
        assert file_path_matches("pkg/tests/test_x.py", pattern) is False
        assert ignore_path_matches("pkg/tests/test_x.py", pattern) is False

    @pytest.mark.parametrize("pattern", ["tests", "tests/"])
    def test_a_name_that_merely_starts_with_the_directory_does_not_match(
        self, pattern: str
    ):
        assert file_path_matches("tests2/x.py", pattern) is False
        assert ignore_path_matches("tests2/x.py", pattern) is False

    def test_the_exact_path_still_matches_a_bare_pattern(self):
        # A FILE named like the pattern: the exact-text match, unchanged.
        assert file_path_matches("tests", "tests") is True
        # The trailing-slash spelling names the directory only, never a file.
        assert file_path_matches("tests", "tests/") is False

    def test_glob_patterns_keep_their_meaning(self):
        # ``**`` globs are anchored component matches, as before.
        assert file_path_matches("tests/x.py", "tests/**") is True
        assert file_path_matches("pkg/tests/x.py", "tests/**") is False
        assert file_path_matches("pkg/tests/x.py", "**/tests/**") is True
        # A glob pattern gains no directory-prefix reading: the files below a
        # directory a glob names match only as the glob reads them.
        assert file_path_matches("src/sub/deep/a.py", "src/*.py") is True
        assert file_path_matches("src/app.py/below", "src/*.py") is False

    @pytest.mark.parametrize("pattern", ["", ".", "./", "/", "//"])
    def test_patterns_naming_no_path_still_match_nothing(self, pattern: str):
        assert file_path_matches("tests/x.py", pattern) is False
        assert ignore_path_matches("tests/x.py", pattern) is False

    def test_dot_prefixed_directory_still_matches_nothing(self):
        assert file_path_matches("tests/x.py", "./tests") is False

    def test_package_path_is_an_identity_and_gains_no_directory_reading(self):
        # package_path separates two installed copies; a suppression naming one
        # copy must not also cover packages nested below it.
        suppression = AshSuppression(
            rule_id="B101",
            path="**",
            package_path="deploy/node_modules/foo",
            reason="one copy only",
        )
        nested_copy = _finding(
            "deploy/node_modules/foo/node_modules/bar/index.js",
            package_name="bar",
            package_path="deploy/node_modules/foo/node_modules/bar",
        )
        matched, _ = should_suppress_finding(nested_copy, [suppression])
        assert matched is False
        named_copy = _finding(
            "deploy/node_modules/foo/index.js",
            package_name="foo",
            package_path="deploy/node_modules/foo",
        )
        matched, _ = should_suppress_finding(named_copy, [suppression])
        assert matched is True

    def test_case_stays_sensitive(self):
        assert file_path_matches("TESTS/x.py", "tests") is False
