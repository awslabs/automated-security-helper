# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for moving glob patterns between the project and workspace spaces.

Up-conversion takes a pattern written against a project root and rebases it on
the workspace root. Down-conversion is the inverse, used to push a
workspace-level policy into one project, and returns None when the pattern
cannot possibly match inside that project.
"""

import pytest

from automated_security_helper.core.exceptions import WorkspacePatternError
from automated_security_helper.utils.workspace_paths import (
    to_project_pattern,
    to_workspace_pattern,
)


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

    @pytest.mark.parametrize("pattern", ["//src/x.py", "///src/x.py"])
    def test_a_repeated_leading_separator_is_rejected_as_unc(self, pattern):
        """Two leading separators is a UNC anchor, and cannot be told from one.

        PureWindowsPath('//src/x.py').drive is '\\\\src\\x.py', so the Windows
        flavour reads a doubled leading separator as a UNC share. A pattern
        author almost certainly meant a project-rooted path with a stray extra
        slash, but the two shapes are identical, and rejecting a malformed
        pattern with an error is safer than guessing which was meant.
        """
        with pytest.raises(WorkspacePatternError):
            to_workspace_pattern(pattern, "project-a")

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
            ("/project-a/src/x.py", "project-a", "src/x.py"),
            ("project-a/a/b/c.py", "project-a", "a/b/c.py"),
        ],
    )
    def test_prefix_stripped(self, pattern, prefix, expected):
        assert to_project_pattern(pattern, prefix) == expected

    def test_prefix_matching_is_case_insensitive(self):
        """Matches how file_path_matches compares paths elsewhere in ASH."""
        assert to_project_pattern("Project-A/src/x.py", "project-a") == "src/x.py"
        assert to_project_pattern("project-a/src/x.py", "PROJECT-A") == "src/x.py"

    def test_the_project_directory_itself_becomes_everything(self):
        """A pattern naming exactly the project means the whole project."""
        assert to_project_pattern("project-a", "project-a") == "**"
        assert to_project_pattern("project-a/", "project-a") == "**"


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
        assert to_project_pattern(pattern, prefix) is None

    def test_a_sibling_sharing_a_name_prefix_does_not_match(self):
        """Component-wise, not string-prefix: 'project-abc' is not 'project-a'."""
        assert to_project_pattern("project-abc/src/x.py", "project-a") is None

    def test_a_shorter_path_than_the_prefix_does_not_match(self):
        assert to_project_pattern("apps/x.py", "apps/web") is None

    def test_a_pattern_with_fewer_components_than_the_prefix(self):
        """'apps' cannot address anything inside 'apps/web'."""
        assert to_project_pattern("apps", "apps/web") is None


class TestDownConversionWildcardFirstComponent:
    """A wildcard first component is not anchored to any one project."""

    @pytest.mark.parametrize(
        "pattern",
        [
            "**/test_*.py",
            "**",
            "*/src/x.py",
            "*.py",
            "?roject-a/src/x.py",
            "[pq]roject-a/src/x.py",
        ],
    )
    def test_returned_unchanged(self, pattern):
        """Conservative: over-include rather than silently drop a policy."""
        assert to_project_pattern(pattern, "project-a") == pattern.lstrip("/")

    def test_a_wildcard_inside_the_prefix_span_is_still_unanchored(self):
        assert to_project_pattern("project-*/src/x.py", "project-a") == (
            "project-*/src/x.py"
        )


class TestDownConversionRejections:
    """Down-conversion rejects the same malformed inputs as up-conversion."""

    def test_parent_traversal_rejected(self):
        with pytest.raises(WorkspacePatternError):
            to_project_pattern("project-a/../project-b/x.py", "project-a")

    def test_drive_anchored_rejected(self):
        with pytest.raises(WorkspacePatternError):
            to_project_pattern("C:/Windows/x.dll", "project-a")

    def test_empty_prefix_rejected(self):
        with pytest.raises(WorkspacePatternError):
            to_project_pattern("project-a/src/x.py", "")

    @pytest.mark.parametrize("degenerate", ["/", "."])
    def test_a_pattern_naming_no_component_is_rejected(self, degenerate):
        with pytest.raises(WorkspacePatternError):
            to_project_pattern(degenerate, "project-a")

    @pytest.mark.parametrize("degenerate", ["/", "."])
    def test_a_prefix_naming_no_component_is_rejected(self, degenerate):
        with pytest.raises(WorkspacePatternError):
            to_project_pattern("project-a/src/x.py", degenerate)


# ---------------------------------------------------------------------------
# Tests: the two directions are inverses
# ---------------------------------------------------------------------------


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
        assert to_project_pattern(workspace, prefix) == pattern

    def test_round_trip_normalises_a_project_rooted_pattern(self):
        """The leading separator is dropped, since it carries no extra meaning."""
        workspace = to_workspace_pattern("/src/x.py", "project-a")
        assert to_project_pattern(workspace, "project-a") == "src/x.py"

    def test_an_up_converted_pattern_never_reaches_another_project(self):
        workspace = to_workspace_pattern("**/*.py", "project-a")
        assert to_project_pattern(workspace, "project-b") is None


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
