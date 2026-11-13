# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for moving glob patterns between the project and workspace spaces.

Up-conversion takes a pattern written against a project root and rebases it on
the workspace root. Down-conversion is the inverse, used to push a
workspace-level policy into one project, and returns None when the pattern
cannot possibly match inside that project.
"""

import itertools

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
from tests.unit.utils.workspace_path_contract import (
    MATCHERS as _MATCHERS,
    assert_contract,
    disagreeing_paths,
)

pytestmark = pytest.mark.unit


def _down_suppression(pattern, prefix):
    """``to_project_pattern`` for a suppression.

    The cells that use it check the answer with ``file_path_matches``, a
    suppression's matcher. ``TestDownConversionPerKind`` covers both kinds.
    """
    return to_project_pattern(pattern, prefix, kind=SUPPRESSION)


# ---------------------------------------------------------------------------
# Tests: up-conversion, the table from the RFC
# ---------------------------------------------------------------------------


class TestUpConversionRelative:
    """A relative pattern is prefixed with the project path."""

    @pytest.mark.parametrize(
        "pattern,expected",
        [
            ("src/x.py", "project-a/src/x.py"),
            ("tests/**/*.py", "project-a/tests/**/*.py"),
            ("*.py", "project-a/*.py"),
            ("x[0-9].py", "project-a/x[0-9].py"),
            ("a/b/c/d.py", "project-a/a/b/c/d.py"),
            ("file.py", "project-a/file.py"),
        ],
    )
    def test_prefixed(self, pattern, expected):
        assert to_workspace_pattern(pattern, "project-a") == expected

    def test_nested_project_prefix(self):
        assert to_workspace_pattern("src/x.py", "apps/web") == "apps/web/src/x.py"

    def test_leading_dot_slash_is_normalised_away(self):
        assert to_workspace_pattern("./src/x.py", "project-a") == "project-a/src/x.py"


class TestUpConversionProjectRooted:
    """A project-rooted pattern loses its leading separator before prefixing."""

    @pytest.mark.parametrize(
        "pattern,expected",
        [
            ("/src/x.py", "project-a/src/x.py"),
            ("/tests/**/*.py", "project-a/tests/**/*.py"),
            ("/file.py", "project-a/file.py"),
        ],
    )
    def test_separator_stripped_then_prefixed(self, pattern, expected):
        assert to_workspace_pattern(pattern, "project-a") == expected

    def test_never_produces_a_doubled_separator(self):
        """The specific bug this guards: project-a//src/x.py.

        PurePosixPath('project-a') / '/src/x.py' silently DISCARDS the prefix
        and yields '/src/x.py', so the strip has to happen before the join.
        """
        result = to_workspace_pattern("/src/x.py", "project-a")
        assert "//" not in result
        assert result.startswith("project-a/")

    # The leading-separator contract, pinned by count. Asserted directly on the
    # outcome rather than through PureWindowsPath, because that attribute is
    # exactly what made this version-dependent: PureWindowsPath("///src/x.py")
    # .drive is '' on 3.10/3.11 and '\\\\\\src' on 3.12+, so a .drive-based test
    # would agree with a .drive-based implementation on every interpreter and
    # never catch the divergence. This project supports 3.10 through 3.13.
    LEADING_SEPARATOR_CONTRACT = [
        ("src/x.py", "project-a/src/x.py"),
        ("/src/x.py", "project-a/src/x.py"),
        ("//src/x.py", None),
        ("///src/x.py", None),
        ("////src/x.py", None),
    ]

    @pytest.mark.parametrize("pattern,expected", LEADING_SEPARATOR_CONTRACT)
    def test_leading_separator_count_decides_the_outcome(self, pattern, expected):
        """Zero or one separator converts; two or more is rejected, on every version.

        Two-or-more cannot be told from a UNC share, and a pattern author almost
        certainly meant a project-rooted path with a stray extra slash. Rejecting
        a malformed pattern with an error beats guessing which was meant.
        """
        if expected is None:
            with pytest.raises(WorkspacePatternError) as excinfo:
                to_workspace_pattern(pattern, "project-a")
            assert "separator" in str(excinfo.value)
        else:
            assert to_workspace_pattern(pattern, "project-a") == expected

    @pytest.mark.parametrize("pattern,expected", LEADING_SEPARATOR_CONTRACT)
    def test_backslash_separators_follow_the_same_contract(self, pattern, expected):
        """A Windows-style pattern normalises first, then obeys the same counts."""
        backslashed = pattern.replace("/", "\\")
        if expected is None:
            with pytest.raises(WorkspacePatternError):
                to_workspace_pattern(backslashed, "project-a")
        else:
            assert to_workspace_pattern(backslashed, "project-a") == expected

    def test_a_real_unc_share_is_still_rejected(self):
        """The separator count subsumes the UNC case rather than bypassing it."""
        for pattern in ("//server/share/x.py", "\\\\server\\share\\x.py"):
            with pytest.raises(WorkspacePatternError):
                to_workspace_pattern(pattern, "project-a")

    def test_a_drive_letter_is_still_rejected(self):
        """A drive anchor has no leading separator, so it needs its own check."""
        for pattern in ("C:/Windows/x.dll", "C:\\Windows\\x.dll"):
            with pytest.raises(WorkspacePatternError) as excinfo:
                to_workspace_pattern(pattern, "project-a")
            assert "drive" in str(excinfo.value)

    def test_project_rooted_and_relative_agree(self):
        """'/src/x.py' and 'src/x.py' mean the same thing to a project."""
        assert to_workspace_pattern("/src/x.py", "project-a") == to_workspace_pattern(
            "src/x.py", "project-a"
        )


class TestUpConversionRecursiveAnchored:
    """A '**'-anchored pattern keeps its recursive semantics."""

    @pytest.mark.parametrize(
        "pattern,expected",
        [
            ("**/test_*.py", "project-a/**/test_*.py"),
            ("**", "project-a/**"),
            ("**/*.py", "project-a/**/*.py"),
            ("src/**", "project-a/src/**"),
            ("a/**/b/**/c.py", "project-a/a/**/b/**/c.py"),
        ],
    )
    def test_double_star_preserved(self, pattern, expected):
        assert to_workspace_pattern(pattern, "project-a") == expected

    def test_double_star_is_not_collapsed_to_one(self):
        result = to_workspace_pattern("**/test_*.py", "project-a")
        assert "**" in result


class TestUpConversionRejections:
    """Patterns that cannot be rebased are rejected with a clear error."""

    @pytest.mark.parametrize(
        "pattern",
        [
            "../outside/x.py",
            "..",
            "src/../../x.py",
            "src/..",
            "/../x.py",
            "**/../x.py",
        ],
    )
    def test_parent_traversal_rejected(self, pattern):
        with pytest.raises(WorkspacePatternError) as excinfo:
            to_workspace_pattern(pattern, "project-a")
        assert ".." in str(excinfo.value)

    def test_backslash_traversal_rejected(self):
        """'..' behind a Windows separator must still be seen."""
        with pytest.raises(WorkspacePatternError):
            to_workspace_pattern("src\\..\\..\\x.py", "project-a")

    @pytest.mark.parametrize(
        "pattern",
        [
            "C:/Windows/System32/x.dll",
            "C:\\Windows\\System32\\x.dll",
            "//server/share/x.py",
            "\\\\server\\share\\x.py",
        ],
    )
    def test_drive_anchored_absolute_paths_rejected(self, pattern):
        """A drive or UNC anchor is unambiguously a filesystem path."""
        with pytest.raises(WorkspacePatternError):
            to_workspace_pattern(pattern, "project-a")

    def test_a_dotdot_in_a_filename_is_not_traversal(self):
        assert to_workspace_pattern("v1..2/x.py", "project-a") == (
            "project-a/v1..2/x.py"
        )

    def test_empty_pattern_rejected(self):
        with pytest.raises(WorkspacePatternError):
            to_workspace_pattern("", "project-a")

    def test_empty_project_prefix_rejected(self):
        with pytest.raises(WorkspacePatternError):
            to_workspace_pattern("src/x.py", "")

    def test_project_prefix_with_traversal_rejected(self):
        with pytest.raises(WorkspacePatternError):
            to_workspace_pattern("src/x.py", "../project-a")

    @pytest.mark.parametrize("degenerate", ["/", ".", "./", "//"])
    def test_a_pattern_naming_no_component_is_rejected(self, degenerate):
        """'/' and '.' are non-empty strings that carry no component.

        They survive the empty-string check but reduce to zero components once
        the root anchor is dropped, so they need their own guard: joining them
        onto a prefix would silently yield the bare project directory.
        """
        with pytest.raises(WorkspacePatternError):
            to_workspace_pattern(degenerate, "project-a")

    @pytest.mark.parametrize("degenerate", ["/", ".", "./"])
    def test_a_prefix_naming_no_component_is_rejected(self, degenerate):
        with pytest.raises(WorkspacePatternError):
            to_workspace_pattern("src/x.py", degenerate)


class TestUpConversionPosixRootedIsReinterpreted:
    """The one case the RFC table cannot decide by text alone.

    '/src/x.py' (project-rooted, must be prefixed) and '/etc/passwd'
    (a filesystem path, nominally rejected) are the same shape on POSIX. The
    leading separator is therefore always read as project-rooted, which makes
    an escape structurally impossible rather than merely rejected: the result
    is confined to the project either way.
    """

    def test_posix_absolute_is_confined_not_rejected(self):
        assert to_workspace_pattern("/etc/passwd", "project-a") == (
            "project-a/etc/passwd"
        )

    def test_the_result_can_never_escape_the_project(self):
        for pattern in ("/etc/passwd", "/src/x.py", "/var/log/**", "/root/.ssh/id_rsa"):
            assert to_workspace_pattern(pattern, "project-a").startswith("project-a/")


# ---------------------------------------------------------------------------
# Tests: down-conversion
# ---------------------------------------------------------------------------


class TestDownConversionAnchored:
    """A pattern anchored to this project is rebased onto the project root."""

    @pytest.mark.parametrize(
        "pattern,prefix,expected",
        [
            ("project-a/src/x.py", "project-a", "src/x.py"),
            ("project-a/tests/**/*.py", "project-a", "tests/**/*.py"),
            ("apps/web/src/x.py", "apps/web", "src/x.py"),
            # "/project-a/src/x.py" is not here: the matcher reads its leading
            # separator literally, so it matches no workspace-relative path, and
            # down-conversion refuses it (test_workspace_paths_down_conversion_edges).
            ("project-a/a/b/c.py", "project-a", "a/b/c.py"),
        ],
    )
    def test_prefix_stripped(self, pattern, prefix, expected):
        assert _down_suppression(pattern, prefix) == expected

    def test_prefix_matching_is_case_sensitive(self):
        """As file_path_matches compares paths: on a case-sensitive filesystem
        ``Project-A`` is another directory, so a workspace pattern naming it does
        not apply to the project ``project-a``."""
        assert _down_suppression("Project-A/src/x.py", "project-a") is None
        assert _down_suppression("project-a/src/x.py", "PROJECT-A") is None
        assert _down_suppression("project-a/src/x.py", "project-a") == "src/x.py"
        assert file_path_matches("project-a/src/x.py", "Project-A/src/x.py") is False

    def test_a_pattern_naming_only_the_project_directory_does_not_apply(self):
        """ "project-a" matches the directory, not the files inside it.

        An earlier version returned "**" here on the reading that naming a
        project means "all of it". The contract sweep disproved that:
        file_path_matches("project-a/src/x.py", "project-a") is False, so
        returning "**" would have suppressed a whole project that the
        workspace-level pattern never covered.
        """
        assert file_path_matches("project-a/src/x.py", "project-a") is False
        assert _down_suppression("project-a", "project-a") is None
        assert _down_suppression("project-a/", "project-a") is None


class TestDownConversionNotApplicable:
    """None means the pattern cannot match inside this project."""

    @pytest.mark.parametrize(
        "pattern,prefix",
        [
            ("project-b/src/x.py", "project-a"),
            ("apps/api/src/x.py", "apps/web"),
            ("other/x.py", "project-a"),
            ("src/x.py", "project-a"),
        ],
    )
    def test_returns_none(self, pattern, prefix):
        assert _down_suppression(pattern, prefix) is None

    def test_a_sibling_sharing_a_name_prefix_does_not_match(self):
        """Component-wise, not string-prefix: 'project-abc' is not 'project-a'."""
        assert _down_suppression("project-abc/src/x.py", "project-a") is None

    def test_a_shorter_path_than_the_prefix_does_not_match(self):
        assert _down_suppression("apps/x.py", "apps/web") is None

    def test_a_pattern_with_fewer_components_than_the_prefix(self):
        """'apps' cannot address anything inside 'apps/web'."""
        assert _down_suppression("apps", "apps/web") is None


class TestDownConversionWildcardFirstComponent:
    """A wildcard first component is not anchored to any one project."""

    @pytest.mark.parametrize(
        "pattern,expected",
        [
            # An UNBOUNDED leading glob ("*") becomes "**": it absorbed the
            # project prefix and can absorb further directories with it.
            ("*/src/x.py", "**/src/x.py"),
            ("project-*/src/x.py", "**/src/x.py"),
            ("**/src/x.py", "**/src/x.py"),
            ("**/test_*.py", "**/test_*.py"),
            # A BOUNDED leading glob ("?", "[...]") matches a fixed number of
            # characters, so it consumed exactly the prefix and nothing more.
            # Rewriting these to "**" would suppress "sub/src/x.py" too.
            ("?roject-a/src/x.py", "src/x.py"),
            ("[pq]roject-a/src/x.py", "src/x.py"),
            # An all-stars leading matches anything, so the whole project.
            ("*", "**"),
            ("**", "**"),
            # One leading "*" then a literal: the constraint is "ends with .py",
            # which the project-relative part decides on its own, so it carries
            # over unchanged.
            ("*.py", "*.py"),
            # Anchored at the workspace root but stretchy: everything in the
            # project matches.
            ("project-a*", "**"),
        ],
    )
    def test_leading_glob_rewrites(self, pattern, expected):
        assert _down_suppression(pattern, "project-a") == expected

    def test_a_leading_glob_that_cannot_reach_the_project_is_none(self):
        """ "api*" cannot match a project whose first component is "services"."""
        assert _down_suppression("api*/src/x.py", "services/api") is None

    def test_a_trailing_double_star_inside_the_prefix_span_covers_the_project(self):
        """ "api/**" covers everything below "api", so all of "api/sub"."""
        assert _down_suppression("api/**", "api/sub") == "**"


class TestDownConversionRejections:
    """Down-conversion rejects the same malformed inputs as up-conversion."""

    def test_parent_traversal_rejected(self):
        with pytest.raises(WorkspacePatternError):
            _down_suppression("project-a/../project-b/x.py", "project-a")

    def test_drive_anchored_rejected(self):
        with pytest.raises(WorkspacePatternError):
            _down_suppression("C:/Windows/x.dll", "project-a")

    def test_empty_prefix_rejected(self):
        with pytest.raises(WorkspacePatternError):
            _down_suppression("project-a/src/x.py", "")

    @pytest.mark.parametrize("degenerate", ["/", "."])
    def test_a_pattern_naming_no_component_is_rejected(self, degenerate):
        with pytest.raises(WorkspacePatternError):
            _down_suppression(degenerate, "project-a")

    @pytest.mark.parametrize("degenerate", ["/", "."])
    def test_a_prefix_naming_no_component_is_rejected(self, degenerate):
        with pytest.raises(WorkspacePatternError):
            _down_suppression("project-a/src/x.py", degenerate)


# ---------------------------------------------------------------------------
# Tests: the two directions are inverses
# ---------------------------------------------------------------------------


class TestDownConversionContract:
    """The behavioural contract, asserted through ASH's own matcher.

    For every project-relative path p::

        matches(_down_suppression(P, R), p)  ==  matches(P, R + "/" + p)

    A down-converted pattern has to reach exactly the files the workspace-level
    pattern reached inside that project -- no more, no less. Identity
    assertions cannot express this, which is why the earlier version of these
    tests passed while the conversion silently retargeted patterns.

    Where to_project_pattern returns None, no pattern is applied and the
    left-hand side is False for every path, so the contract still holds only if
    the workspace pattern matched nothing in the project either.

    A pattern that raises is excluded from the equality check by construction --
    it is the fail-closed class. TestFailClosedIsNecessary below proves each
    raise is earned rather than convenient.
    """

    PATTERNS = [
        "*/src/x.py",
        "api*/src/x.py",
        "*/*.py",
        "**/src/x.py",
        "api/src/x.py",
        "*",
        "**",
        # Beyond the reviewer's matrix: classes the sweep found and fixed.
        "*.py",
        "?roject-a/src/x.py",
        "[pq]roject-a/src/x.py",
        "project-*/src/x.py",
        "api*",
        "api/**",
        "api/sub/**",
        "**/*.py",
        "**/test_*.py",
        "api",
        "api/sub",
        "services/api",
        "src/*.py",
        "*x.py",
    ]
    PREFIXES = ["api", "api-v2", "services/api", "api/sub", "project-a"]
    PATHS = [
        "src/x.py",
        "sub/src/x.py",
        "deep/sub/src/x.py",
        "x.py",
        "other/y.py",
        # Beyond the reviewer's matrix: paths that discriminate the fixes.
        "x.txt",
        "api/src/x.py",
        "src/api/x.py",
        "asrc/x.py",
        "srcx.py",
        "test_a.py",
        "sub/test_a.py",
        "sub",
    ]

    @pytest.mark.parametrize("prefix", PREFIXES)
    @pytest.mark.parametrize("pattern", PATTERNS)
    def test_contract_holds(self, pattern, prefix):
        try:
            project_pattern = _down_suppression(pattern, prefix)
        except WorkspacePatternError:
            pytest.skip("fail-closed class; covered by TestFailClosedIsNecessary")

        assert_contract(pattern, prefix, SUPPRESSION, self.PATHS, project_pattern)

    def test_the_reported_regression(self):
        """The exact case from review: "*/src/x.py" over project "api"."""
        rewritten = _down_suppression("*/src/x.py", "api")
        # Was returned unchanged, which stopped matching the named file.
        assert file_path_matches("src/x.py", rewritten) is True
        assert file_path_matches("api/src/x.py", "*/src/x.py") is True

    def test_the_matrix_is_not_silently_narrowed(self):
        assert len(self.PATTERNS) == 21
        assert len(self.PREFIXES) == 5
        assert len(self.PATHS) == 13

    def test_both_verdicts_occur(self):
        """A conversion that matched nothing would satisfy the contract vacuously."""
        verdicts = set()
        for pattern in self.PATTERNS:
            for prefix in self.PREFIXES:
                try:
                    rewritten = _down_suppression(pattern, prefix)
                except WorkspacePatternError:
                    continue
                if rewritten is None:
                    verdicts.add(False)
                    continue
                for path in self.PATHS:
                    verdicts.add(file_path_matches(path, rewritten))
        assert verdicts == {True, False}


class TestFailClosedIsNecessary:
    """Each fail-closed class is unrepresentable, not merely inconvenient.

    For every pattern below, no single project-relative pattern reproduces the
    workspace verdict, so raising is the only honest option. Each test proves
    that by exhibiting a path where every candidate rewrite gets it wrong.
    """

    CANDIDATE_REWRITES = staticmethod(
        lambda pattern: [
            None,
            pattern,
            "**",
            "**/" + "/".join(pattern.split("/")[1:]),
            "/".join(pattern.split("/")[1:]),
        ]
    )

    PROBE_PATHS = [
        "src/x.py",
        "sub/src/x.py",
        "x.py",
        "x.txt",
        "api/src/x.py",
        "deep/sub/src/x.py",
    ]

    @pytest.mark.parametrize(
        "pattern,prefix",
        [
            # A literal component after the leading wildcard also matches part
            # of the project path, so the workspace match can begin INSIDE the
            # prefix -- unrepresentable once the prefix is stripped.
            ("*/api/src/x.py", "services/api"),
            ("**/api/src/x.py", "services/api"),
            ("*/sub/x.py", "api/sub"),
            # A wildcard falling inside the project path itself.
            ("api/*/x.py", "api/sub"),
        ],
    )
    def test_no_single_rewrite_satisfies_the_contract(self, pattern, prefix):
        with pytest.raises(WorkspacePatternError):
            _down_suppression(pattern, prefix)

        # Prove the raise is earned: every candidate rewrite is wrong somewhere.
        for rewrite in self.CANDIDATE_REWRITES(pattern):
            wrong = disagreeing_paths(
                pattern, prefix, SUPPRESSION, self.PROBE_PATHS, rewrite
            )
            assert wrong, (
                f"rewrite {rewrite!r} actually satisfies the contract for "
                f"{pattern!r} over {prefix!r} -- the fail-closed is unnecessary"
            )

    @pytest.mark.parametrize("prefix", ["api", "api-v2", "services/api"])
    @pytest.mark.parametrize("path", ["sub/src/x.py", "deep/sub/src/x.py"])
    def test_the_two_matcher_semantics_regression(self, prefix, path):
        """The six triples from review: "*/sub/*.py" cannot become "**/sub/*.py".

        A pattern with no "**" is matched by fnmatch, where the trailing "*.py"
        crosses "/" and so covers "sub/src/x.py". Prefixing "**" routes the
        pattern to _recursive_glob_match instead, which pins "*.py" to the final
        component -- so the rewritten pattern stopped covering the same files.
        Rewriting one glob silently re-interpreted the others.
        """
        # The workspace-level pattern does cover this path.
        assert file_path_matches(f"{prefix}/{path}", "*/sub/*.py") is True
        # The rewrite that would have been produced does not.
        assert file_path_matches(path, "**/sub/*.py") is False
        # So the conversion must refuse rather than silently narrow the pattern.
        with pytest.raises(WorkspacePatternError):
            _down_suppression("*/sub/*.py", prefix)

    def test_a_single_component_remainder_still_converts(self):
        """ "*/*.py" is unaffected and must not be rejected reflexively.

        With one component there is nothing for "**" to re-anchor, so the
        rewrite is meaning-preserving.
        """
        assert _down_suppression("*/*.py", "api") == "**/*.py"
        for path in ["x.py", "sub/x.py", "deep/sub/x.py"]:
            assert file_path_matches(path, "**/*.py") == file_path_matches(
                f"api/{path}", "*/*.py"
            )

    def test_an_all_literal_remainder_still_converts(self):
        """A literal suffix means the same thing under either matcher."""
        assert _down_suppression("*/src/x.py", "api") == "**/src/x.py"

    def test_a_wildcard_before_a_literal_is_rejected(self):
        """ "*v2/src" can land the "v2" inside another component's name."""
        assert file_path_matches("apiv2/xv2/src", "*v2/src") is True
        assert file_path_matches("xv2/src", "src") is False
        with pytest.raises(WorkspacePatternError):
            _down_suppression("*v2/src", "apiv2")

    def test_a_wildcard_between_literals_is_rejected(self):
        """ "a*b" is pinned to neither end, so its span is ambiguous."""
        with pytest.raises(WorkspacePatternError):
            _down_suppression("a*b/src", "a/b")

    def test_a_fixed_length_wildcard_alone_is_rejected(self):
        """ "?????????" matches "api/x.txt" by length coincidence alone.

        It matches neither "api" nor "x.txt", so the constraint lives in the
        length of the joined path and cannot survive stripping the prefix.
        """
        assert file_path_matches("api/x.txt", "?????????") is True
        assert file_path_matches("x.txt", "?????????") is False
        with pytest.raises(WorkspacePatternError):
            _down_suppression("?????????", "api")

    def test_the_error_names_the_pattern_and_the_remedy(self):
        with pytest.raises(WorkspacePatternError) as excinfo:
            _down_suppression("*/api/src/x.py", "services/api")
        message = str(excinfo.value)
        assert "*/api/src/x.py" in message
        assert "services/api" in message
        assert "**" in message, "the message must name the remedy"


class TestRoundTrip:
    """Down-converting an up-converted pattern returns the original."""

    @pytest.mark.parametrize(
        "pattern",
        [
            "src/x.py",
            "tests/**/*.py",
            "**/test_*.py",
            "*.py",
            "a/b/c/d.py",
            "src/**",
            "x[0-9].py",
        ],
    )
    @pytest.mark.parametrize("prefix", ["project-a", "apps/web", "a/b/c"])
    def test_round_trip_is_identity(self, pattern, prefix):
        workspace = to_workspace_pattern(pattern, prefix)
        assert _down_suppression(workspace, prefix) == pattern

    def test_round_trip_normalises_a_project_rooted_pattern(self):
        """The leading separator is dropped, since it carries no extra meaning."""
        workspace = to_workspace_pattern("/src/x.py", "project-a")
        assert _down_suppression(workspace, "project-a") == "src/x.py"

    def test_an_up_converted_pattern_never_reaches_another_project(self):
        workspace = to_workspace_pattern("**/*.py", "project-a")
        assert _down_suppression(workspace, "project-b") is None


# ---------------------------------------------------------------------------
# Tests: no string concatenation artefacts
# ---------------------------------------------------------------------------


class TestNoConcatenationArtefacts:
    """Both directions go through PurePosixPath, so separators stay sane."""

    @pytest.mark.parametrize("prefix", ["project-a", "project-a/", "/project-a"])
    def test_prefix_separator_variants_all_agree(self, prefix):
        assert to_workspace_pattern("src/x.py", prefix) == "project-a/src/x.py"

    def test_output_never_contains_a_backslash(self):
        assert "\\" not in to_workspace_pattern("src\\x.py", "project-a")

    def test_output_never_contains_a_doubled_separator(self):
        for pattern in ("src/x.py", "/src/x.py", "src//x.py", "**//*.py"):
            assert "//" not in to_workspace_pattern(pattern, "project-a"), pattern


# ---------------------------------------------------------------------------
# Tests: the contract for each kind of policy entry
# ---------------------------------------------------------------------------

#: Every project path of one to three components from these names.
_PATHS = [
    "/".join(parts)
    for length in (1, 2, 3)
    for parts in itertools.product(["x", "X", "y.py", "sub", "api"], repeat=length)
]

#: Every pattern of one or two components from these, with and without a
#: trailing "/": literals that collide with the prefixes and the paths, their
#: case variants, each glob shape, and ".".
_PATTERN_PARTS = ["x", "X", "sub", "y.py", "*", "**", "?", "x*", "*.py", "[xX]", "."]

#: The shapes named for this contract, over the project "x" and from the top,
#: and the two reported defects. The anchors "/" and "/**/" put a leading
#: separator in front of each shape, so both matchers decide it: a rooted pattern
#: is refused for each kind, and "/**/" is the one the matcher absorbs.
_NAMED_SHAPES = [
    anchor + shape
    for anchor in ("", "x/", "X/", "*/", "**/", "x/sub/", "/", "/**/")
    for shape in ("x/", "x/**", "./x", "x/./y", "x", "", "X", "X/", "x//y", "**/")
] + ["api/vendor/", "./api/x.py"]

_PATTERNS = sorted(
    set(_NAMED_SHAPES)
    | {
        "/".join(parts) + slash
        for length in (1, 2)
        for parts in itertools.product(_PATTERN_PARTS, repeat=length)
        for slash in ("", "/")
    }
)

_PREFIXES = ["x", "X", "x/sub", "api", "sub/x", "a/b"]


def _outcome(kind, pattern, prefix):
    """``(rewritten, disagreeing paths)``, or ``None`` when the pattern is refused."""
    try:
        rewritten = to_project_pattern(pattern, prefix, kind=kind)
    except WorkspacePatternError:
        return None
    return rewritten, disagreeing_paths(pattern, prefix, kind, _PATHS, rewritten)


class TestDownConversionPerKind:
    """The contract with each kind's own matcher, for every pattern and prefix.

    An ignore path is read by ``ignore_path_matches``, where a trailing ``/``
    names a directory, and a suppression by ``file_path_matches``, where it is
    literal. A pushed-down pattern has to give its kind's matcher the workspace
    pattern's answer for every project path, or be refused.
    """

    @pytest.mark.parametrize("prefix", _PREFIXES)
    @pytest.mark.parametrize("kind", [IGNORE_PATH, SUPPRESSION])
    def test_both_sides_agree_or_the_pattern_is_refused(self, kind, prefix):
        violations = {}
        for pattern in _PATTERNS:
            outcome = _outcome(kind, pattern, prefix)
            if outcome is not None and outcome[1]:
                violations[pattern] = outcome
        assert violations == {}

    @pytest.mark.parametrize("kind", [IGNORE_PATH, SUPPRESSION])
    def test_the_sweep_is_not_vacuous(self, kind):
        """Hundreds of pairs convert, and both verdicts occur among them.

        Of the 1,878 pairs, hundreds of suppressions and of ignore paths convert;
        the floor is below both, so a change that refused or dropped everything
        fails here instead of passing the agreement cells by having no answers.
        """
        outcomes = [
            _outcome(kind, pattern, prefix)
            for pattern in _PATTERNS
            for prefix in _PREFIXES
        ]
        converted = [o for o in outcomes if o is not None and o[0] is not None]
        assert len(_PATTERNS) == 313
        assert len(converted) >= 350
        verdicts = {
            _MATCHERS[kind](path, rewritten)
            for rewritten, _ in converted
            for path in _PATHS
        }
        assert verdicts == {True, False}

    def test_an_ignore_path_keeps_its_directory_form(self):
        """ "api/vendor/" covers what is inside api/vendor; "vendor" covers a file."""
        rewritten = to_project_pattern("api/vendor/", "api", kind=IGNORE_PATH)
        assert rewritten == "vendor/"
        assert ignore_path_matches("vendor/lib/x.py", rewritten) is True
        assert ignore_path_matches("api/vendor/lib/x.py", "api/vendor/") is True
        assert ignore_path_matches("vendor", rewritten) is False
        assert to_project_pattern("**/vendor/", "api", kind=IGNORE_PATH) == (
            "**/vendor/"
        )

    def test_an_ignore_path_naming_the_project_or_an_ancestor_covers_it_all(self):
        """ "api/" ignores everything below api, so all of project api or api/sub."""
        for prefix in ("api", "api/sub"):
            rewritten = to_project_pattern("api/", prefix, kind=IGNORE_PATH)
            assert rewritten == "**"
            assert ignore_path_matches(f"{prefix}/src/x.py", "api/") is True

    def test_a_suppression_keeps_its_literal_slash(self):
        """A file's path never ends in "/", so neither side matches a file."""
        rewritten = to_project_pattern("api/vendor/", "api", kind=SUPPRESSION)
        assert rewritten == "vendor/"
        assert file_path_matches("api/vendor", "api/vendor/") is False
        assert file_path_matches("vendor", "vendor/") is False

    @pytest.mark.parametrize("pattern", ["api/", "*/", "api*/", "?pi/"])
    def test_a_suppression_reaching_the_project_root_is_dropped_not_widened(
        self, pattern
    ):
        """ "**/" would be "**", which suppresses the whole project."""
        assert to_project_pattern(pattern, "api", kind=SUPPRESSION) is None

    @pytest.mark.parametrize("kind", [IGNORE_PATH, SUPPRESSION])
    @pytest.mark.parametrize(
        "pattern",
        ["./api/x.py", "api/./x.py", ".//api/x.py", "./*", "./**", "api//x.py"],
    )
    def test_a_dot_or_empty_component_is_refused(self, kind, pattern):
        """The top-level matcher reads it literally, so it matches no file there.

        Folded away ("./api/x.py" as "api/x.py", "./*" as "*"), the pushed-down
        ignore path would drop files the top level keeps.
        """
        for path in ("api/x.py", "x.py", "api/sub/x.py"):
            assert _MATCHERS[kind](path, pattern) is False
        with pytest.raises(WorkspacePatternError) as refused:
            to_project_pattern(pattern, "api", kind=kind)
        assert str(refused.value) == (
            f"pattern '{pattern}' has a '.' or empty component, which ASH's "
            "matcher reads literally, so it matches no file; remove the extra "
            "'.' or '/'"
        )

    @pytest.mark.parametrize("kind", [IGNORE_PATH, SUPPRESSION])
    @pytest.mark.parametrize("pattern", [".", "./", "/", ".\\"])
    def test_a_pattern_of_only_dots_and_separators_stays_refused(self, kind, pattern):
        with pytest.raises(WorkspacePatternError, match="at least one component"):
            to_project_pattern(pattern, "api", kind=kind)

    @pytest.mark.parametrize(
        "pattern, prefix",
        [("???/**", "a/b"), ("???/**/x.py", "a/b"), ("???????/**", "api/sub")],
    )
    def test_a_fixed_length_glob_under_double_star_spans_one_component(
        self, pattern, prefix
    ):
        """With "**" in the pattern every "?" stays inside one path component.

        "???" matches the text "a/b", but no component of "a/b/...", so the
        pattern covers nothing in the project, and "**" would cover all of it.
        """
        for path in ("x.py", "sub/x.py"):
            assert file_path_matches(f"{prefix}/{path}", pattern) is False
        for kind in (IGNORE_PATH, SUPPRESSION):
            assert to_project_pattern(pattern, prefix, kind=kind) is None

    def test_one_remainder_component_with_a_wildcard_inside_is_refused(self):
        """Under fnmatch "a*" in "*/a*" takes "api/sub"; under "**/a*" it cannot."""
        assert file_path_matches("x/api/sub", "*/a*") is True
        assert file_path_matches("api/sub", "**/a*") is False
        for kind in (IGNORE_PATH, SUPPRESSION):
            with pytest.raises(WorkspacePatternError):
                to_project_pattern("*/a*", "x", kind=kind)

    def test_an_unknown_kind_is_an_error(self):
        with pytest.raises(ValueError, match="kind"):
            to_project_pattern("api/x.py", "api", kind="ignore")  # type: ignore[arg-type]
