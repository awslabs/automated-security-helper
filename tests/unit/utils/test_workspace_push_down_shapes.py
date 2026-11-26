# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One pushed-down pattern per shape and kind (``workspace_paths.to_project_pattern``).

The contract sweeps in ``test_workspace_paths.py`` check that every pushed-down
pattern gives its kind's matcher the workspace pattern's answer. These cells pin
the answer itself for the shapes an operator writes, so a change that keeps the
contract by refusing, or by dropping a pattern for a project, shows up here.
"""

import pytest

from automated_security_helper.core.exceptions import WorkspacePatternError
from automated_security_helper.utils.suppression_matcher import (
    file_path_matches,
    ignore_path_matches,
)
from automated_security_helper.utils.workspace_paths import (
    IGNORE_PATH,
    SUPPRESSION,
    to_project_pattern,
    to_workspace_pattern,
)

pytestmark = pytest.mark.unit

#: The answer for a pattern with no correct rewrite.
REFUSED = "refused"


def _answer(pattern, prefix, kind):
    try:
        return to_project_pattern(pattern, prefix, kind=kind)
    except WorkspacePatternError:
        return REFUSED


@pytest.mark.parametrize(
    "kind, prefix, pattern, expected",
    [
        # Reaching the project root: an ignore path covers it all, a suppression
        # covers no file there.
        (IGNORE_PATH, "api", "api/", "**"),
        (IGNORE_PATH, "api/sub", "api/", "**"),
        # The bare-directory rule (issue #894): a glob-free suppression ending
        # in "/" names the directory in both matchers, so it converts as the
        # ignore path does.
        (SUPPRESSION, "api", "api/", "**"),
        (SUPPRESSION, "api/sub", "api/", "**"),
        # A directory at any depth reaches every project.
        (IGNORE_PATH, "api", "**/vendor/**", "**/vendor/**"),
        (IGNORE_PATH, "vendor", "**/vendor/**", "**"),
        (SUPPRESSION, "api", "**/vendor/**", "**/vendor/**"),
        (IGNORE_PATH, "api", "**/vendor/", "**/vendor/"),
        # A suppression's trailing "/" stays literal.
        (SUPPRESSION, "api", "**/vendor/", "**/vendor/"),
        (SUPPRESSION, "vendor", "**/vendor/", "**/vendor/"),
        (SUPPRESSION, "a/b", "**/?/", "**/?/"),
        (SUPPRESSION, "a/vendor", "**/**/a*/", "**/a*/"),
        # One component after a leading "*" converts only when it is a literal,
        # "*" or "*literal": under fnmatch "a*" spans "/", under "**/a*" it cannot.
        (IGNORE_PATH, "x.py", "*/a*", REFUSED),
        (SUPPRESSION, "x", "*/a*", REFUSED),
        (SUPPRESSION, "api", "*/x*", REFUSED),
        (IGNORE_PATH, "api", "*/?", REFUSED),
        (IGNORE_PATH, "api/sub", "*/[ab]", REFUSED),
        (IGNORE_PATH, "api", "*/x.py", "**/x.py"),
        # A pattern holding "**" is walked component by component.
        (IGNORE_PATH, "a/b", "**/", "**"),
        (IGNORE_PATH, "a/b", "**/*", "**"),
        (IGNORE_PATH, "api", "api/**/", "**"),
        (IGNORE_PATH, "api", "api/**/*", "**"),
        (IGNORE_PATH, "a/b", "*.py/", None),
        (IGNORE_PATH, "a/b", "*.py/**", None),
        (IGNORE_PATH, "a/b", "???/**", None),
        (IGNORE_PATH, "a/vendor", "***", None),
        (IGNORE_PATH, "a/vendor", "***/", "**"),
    ],
)
def test_each_shape_is_pushed_down_as_its_kind_reads_it(
    kind, prefix, pattern, expected
):
    assert _answer(pattern, prefix, kind) == expected


class TestTrailingSlash:
    """A trailing slash keeps its meaning in both directions.

    As an ignore path it names the directory's files, and since the
    bare-directory rule (issue #894) a glob-free suppression path reads the same
    way, so both kinds convert a glob-free "api/vendor/" to "vendor/" and the
    project root to "**". A GLOB suppression's trailing slash stays literal and
    matches no file, and the pushed-down pattern keeps the slash and a glob
    character, so it matches none in the project either; after "**" the matcher
    absorbs the slash.
    """

    @pytest.mark.parametrize(
        "pattern,prefix,expected",
        [
            ("api/vendor/", "api", "vendor/"),
            ("api/vendor/lib/", "api", "vendor/lib/"),
            ("api/", "api", "**"),
            ("services/api/", "services/api", "**"),
            ("api-v2/vendor/", "api", None),
        ],
    )
    def test_down(self, pattern, prefix, expected):
        assert to_project_pattern(pattern, prefix, kind=IGNORE_PATH) == expected

    @pytest.mark.parametrize(
        "pattern,prefix,expected",
        [
            ("api/vendor/", "api", "vendor/"),
            ("api/", "api", "**"),
            ("**/vendor/", "api", "**/vendor/"),
            ("api/**/", "api", "**"),
            ("api/vendor/**/", "api", "vendor/**"),
            ("**/", "api", "**"),
        ],
    )
    def test_down_as_a_suppression_path(self, pattern, prefix, expected):
        """A glob-free suppression path ending in "/" names the directory (the
        bare-directory rule, issue #894), so it converts as the ignore path
        does, the project root becoming "**". A GLOB suppression's slash stays
        literal: it matches no file at workspace level, and the pushed-down
        pattern keeps the slash and a glob character, so it matches none in the
        project either."""
        if any(c in pattern for c in "*?[") and (
            expected is not None and expected.endswith("/")
        ):
            for path in ("api/vendor/x.py", "api/x.py", "api/a/b/c.py"):
                assert not file_path_matches(path, pattern), pattern
                assert not file_path_matches(path[len("api/") :], expected)
        assert to_project_pattern(pattern, prefix, kind=SUPPRESSION) == expected

    @pytest.mark.parametrize(
        "pattern,prefix,expected",
        [
            ("**/vendor/", "api", "**/vendor/"),
            ("**/vendor/**", "api", "**/vendor/**"),
            ("**/node_modules/", "services/api", "**/node_modules/"),
            # X matches a component of the project path, so the workspace
            # pattern covers every file of the project.
            ("**/api/", "services/api", "**"),
            ("**/api/**", "api", "**"),
            ("**/sub/", "api/sub", "**"),
            ("**/a*/", "api", "**"),
            ("**/a*/", "project-a", "**/a*/"),
        ],
    )
    def test_an_any_depth_directory_is_converted(self, pattern, prefix, expected):
        """ "**/X/" and "**/X/**": the match needs a component matching X, which
        is either in the project path (then every file of the project matches) or
        below it (then the same pattern does, project-side). As ignore paths."""
        assert to_project_pattern(pattern, prefix, kind=IGNORE_PATH) == expected

    @pytest.mark.parametrize(
        "pattern,prefix,expected",
        [
            ("**/a/b/", "api", "**/a/b/"),
            ("**/a/b/**", "api", "**/a/b/**"),
            ("**/a/b/**", "x/a", REFUSED),
            ("**/a/*/", "x/a", REFUSED),
        ],
    )
    def test_two_directory_components_are_refused_only_where_they_straddle(
        self, pattern, prefix, expected
    ):
        """Over a project whose path ends in "a", "a" can be its last component
        and "b" the first one inside, or both can be inside it, and no single
        project-side pattern covers both. Over "api" neither can be in the
        project path, so the pattern comes down as it is. As ignore paths."""
        assert _answer(pattern, prefix, IGNORE_PATH) == expected

    @pytest.mark.parametrize(
        "pattern,expected",
        [
            ("vendor/", "api/vendor/"),
            ("/vendor/", "api/vendor/"),
            ("**/gen/", "api/**/gen/"),
        ],
    )
    def test_up(self, pattern, expected):
        assert to_workspace_pattern(pattern, "api") == expected

    @pytest.mark.parametrize(
        "pattern",
        ["./", ".//", "././", ".\\", "api/./", "api//vendor/", "api/./vendor/"],
    )
    def test_a_pattern_the_matcher_reads_as_nothing_is_refused(self, pattern):
        """The matcher reads "./", ".\\" and any "." or empty component
        literally, so each of these names no file. The rewrite must not turn one
        into "**" or "vendor/"; it is refused."""
        for kind in (SUPPRESSION, IGNORE_PATH):
            with pytest.raises(WorkspacePatternError):
                to_project_pattern(pattern, "api", kind=kind)

    @pytest.mark.parametrize("pattern", ["api/./src/x.py", "api//src/x.py"])
    def test_without_a_trailing_slash_too(self, pattern):
        assert file_path_matches("api/src/x.py", pattern) is False
        with pytest.raises(WorkspacePatternError):
            to_project_pattern(pattern, "api", kind=SUPPRESSION)

    @pytest.mark.parametrize(
        "pattern,expected",
        [("api//", "**"), ("api/vendor//", "vendor/"), ("api\\vendor\\\\", "vendor/")],
    )
    def test_a_trailing_run_of_slashes_reads_as_one(self, pattern, expected):
        """As an ignore path the matcher reads "api/vendor//" as "api/vendor/"
        (ignore_path_pattern), and so does the push-down."""
        assert ignore_path_matches("api/vendor/x.py", pattern) is True
        assert to_project_pattern(pattern, "api", kind=IGNORE_PATH) == expected

    @pytest.mark.parametrize(
        "pattern,expected",
        [("***", None), ("****", None), ("***/x.py", REFUSED), ("api/***", REFUSED)],
    )
    def test_a_run_of_three_or_more_stars_is_read_as_one_star(self, pattern, expected):
        """The matcher reads a run of three or more stars as one "*" in a single
        component, and so does the push-down: "***" covers no file of a project at
        workspace level, and "***/x.py" covers "api/x.py" of project api. Read
        as "**", "***" would suppress every finding in every project.
        "***/x.py" is refused: its only remainder, "x.py", has no glob
        character, and under the bare-directory rule (issue #894) a glob-free
        pattern also covers the subtree below the path it names, which the
        workspace pattern never matched. "api/***" leaves one starred component
        with no "**", which the project side would read across "/", so it is
        refused too."""
        assert _answer(pattern, "api", SUPPRESSION) == expected
        if expected == REFUSED:
            return
        for path in ("x.py", "sub/x.py", "a/b/c.py"):
            pushed = expected is not None and file_path_matches(path, expected)
            assert pushed == file_path_matches(f"api/{path}", pattern), path

    @pytest.mark.parametrize("pattern", ["***", "****"])
    def test_a_run_of_stars_alone_covers_no_project_file(self, pattern):
        assert not any(
            file_path_matches(path, pattern)
            for path in ("api/x.py", "api/sub/x.py", "services/api/x.py")
        )

    @pytest.mark.parametrize(
        "pattern",
        ["./api/vendor/", ".\\api\\vendor\\", "././api/", "./vendor/", "./api/x.py"],
    )
    def test_a_leading_dot_slash_is_refused(self, pattern):
        """The matcher drops no leading "./", so "./api/vendor/" names no file of
        project api (whose paths are "api/vendor/..."). Rebased as "vendor/" it
        would cover the project's vendor files; it is refused instead."""
        assert not ignore_path_matches("api/vendor/x.py", pattern)
        assert not file_path_matches("api/vendor/x.py", pattern)
        for kind in (SUPPRESSION, IGNORE_PATH):
            with pytest.raises(WorkspacePatternError):
                to_project_pattern(pattern, "api", kind=kind)
