# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Down-conversion edges where the contract and the shipped rewrite disagreed.

Every case here is checked against the real matcher on both sides of the
contract ``to_project_pattern`` states::

    matches(to_project_pattern(P, R, kind=k), p) == matches(P, R + "/" + p)

so each expectation is earned by ``file_path_matches``, not by reasoning about
glob syntax. The shapes: a fixed-length leading that cannot span the project
path (``None``, not a refusal), a remainder the matcher's literal-equality
reading would widen (refused), a ``**`` pattern whose two surviving positions
nest (converted), a non-UTF-8 name's record-form escape (one component), and a
leading separator (refused, as the matcher matches no relative path with it).
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
)

pytestmark = pytest.mark.unit

PROBE_PATHS = [
    "src/x.py",
    "sub/src/x.py",
    "x.py",
    "x.txt",
    "api/src/x.py",
    "deep/sub/src/x.py",
    "[x].py",
    "sub/[x].py",
]


def _down(pattern, prefix, kind=SUPPRESSION):
    return to_project_pattern(pattern, prefix, kind=kind)


def _contract_holds(pattern, prefix, converted, paths=PROBE_PATHS):
    """The converted pattern reaches exactly the files the workspace one does."""
    for path in paths:
        project_side = (
            False if converted is None else file_path_matches(path, converted)
        )
        workspace_side = file_path_matches(f"{prefix}/{path}", pattern)
        assert project_side is workspace_side, (pattern, prefix, converted, path)


class TestFixedLengthLeadingThatCannotSpanThePrefix:
    """``?`` and ``[...]`` match a fixed number of characters, so where the
    pattern's separator lands is decided by the project path's length."""

    @pytest.mark.parametrize(
        "pattern,prefix",
        [
            # The separator after "?pi" would have to be the "v" of "services".
            ("?pi/src/x.py", "services"),
            # Spans the prefix's length, but does not match its text.
            ("?eb/src/x.py", "api"),
            # Alone, it matches only the bare project path, which names no file.
            ("?roject-a", "project-a"),
            ("[pq]roject-a", "project-a"),
        ],
    )
    def test_a_leading_that_cannot_match_under_the_prefix_is_none(
        self, pattern, prefix
    ):
        """None, as for a literal anchored elsewhere: the pattern is about
        another project, and refusing it failed the whole workspace scan."""
        converted = _down(pattern, prefix)

        assert converted is None
        _contract_holds(pattern, prefix, converted)

    def test_a_leading_spanning_the_prefix_exactly_still_converts(self):
        assert _down("?roject-a/src/x.py", "project-a") == "src/x.py"
        _contract_holds("?roject-a/src/x.py", "project-a", "src/x.py")

    @pytest.mark.parametrize(
        "pattern,prefix",
        [
            # The separator is the one between "a" and "b", so "src" would have
            # to be "b".
            ("?/src/x.py", "a/b"),
            # Written for the project "docs", pushed to "apps/web": the same
            # shape one component deeper, which refused the whole scan.
            ("????/src/x.py", "apps/web"),
            ("?/src/x.py", "a/b/c"),
        ],
    )
    def test_a_separator_inside_the_prefix_then_another_name_is_none(
        self, pattern, prefix
    ):
        """What follows the separator starts at the prefix's next component, and
        a plain name that is not that component matches nothing under the
        prefix: a pattern about another project, as for the rows above."""
        converted = _down(pattern, prefix)

        assert converted is None
        _contract_holds(pattern, prefix, converted)

    def test_an_ignore_path_of_that_shape_is_none_too(self):
        converted = _down("?/vendor", "a/b", kind=IGNORE_PATH)

        assert converted is None
        for path in PROBE_PATHS + ["vendor/x.py", "sub/vendor/x.py", "vendor"]:
            assert ignore_path_matches(f"a/b/{path}", "?/vendor") is False, path

    @pytest.mark.parametrize(
        "pattern,prefix",
        [
            # A glob there can absorb the rest of the prefix.
            ("?/*/x.py", "a/b"),
            # The next component itself: what is left past it has to be rewritten
            # for the project, which no rule here does.
            ("?/b/src/x.py", "a/b"),
        ],
    )
    def test_a_separator_inside_the_prefix_that_the_remainder_may_absorb_is_refused(
        self, pattern, prefix
    ):
        with pytest.raises(WorkspacePatternError) as excinfo:
            _down(pattern, prefix)

        assert "fixed number of characters" in str(excinfo.value)

    def test_a_remainder_the_literal_reading_widens_is_refused(self):
        """The matcher reads a path equal to the pattern's text as a match
        before any glob, so project-side ``[x].py`` covers the file ``[x].py``,
        which the workspace pattern ``?pi/[x].py`` never equals."""
        assert file_path_matches("[x].py", "[x].py") is True
        assert file_path_matches("api/[x].py", "?pi/[x].py") is False

        with pytest.raises(WorkspacePatternError, match=r"\[x\]\.py"):
            _down("?pi/[x].py", "api")


class TestDoubleStarPatternsWhoseSurvivingPositionsNest:
    def test_a_remainder_starting_with_double_star_covers_the_longer_one(self):
        """``**/api/**/*.py`` over ``api``: the walk leaves two positions, the
        whole pattern and ``**/*.py``, and the second covers the first. One
        pattern expresses their union, so refusing it failed the scan for a
        policy that was convertible."""
        converted = _down("**/api/**/*.py", "api")

        assert converted == "**/*.py"
        _contract_holds("**/api/**/*.py", "api", converted)

    def test_an_ignore_path_of_that_shape_converts_too(self):
        converted = _down("**/api/**/vendor/", "api", kind=IGNORE_PATH)

        assert converted == "**/vendor/"
        for path in PROBE_PATHS + ["vendor/x.py", "sub/vendor/x.py", "vendor"]:
            assert ignore_path_matches(path, converted) is ignore_path_matches(
                f"api/{path}", "**/api/**/vendor/"
            ), path

    def test_two_positions_neither_of_which_covers_the_other_stay_refused(self):
        """The guard the fix must not loosen: ``**/api/src/x.py`` over
        ``services/api`` leaves ``**/api/src/x.py`` and ``src/x.py``, and the
        one starting with ``**`` is the longer, which covers nothing shorter."""
        with pytest.raises(WorkspacePatternError, match="more than one point"):
            _down("**/api/src/x.py", "services/api")


class TestANonUtf8NameStaysOneComponent:
    """``\\udce9`` is how a report spells a file name byte that is not UTF-8,
    and the matcher reads it as that one character before it reads separators."""

    RECORDED = "api/secr\\udce9t.py"

    def test_the_escape_is_not_split_at_its_backslash(self):
        converted = _down(self.RECORDED, "api")

        assert converted == "secr\\udce9t.py"
        # The file as a scanner reports it, and as the tree holds it.
        for name in ("secr\\udce9t.py", "secr\udce9t.py"):
            assert file_path_matches(name, converted) is True
            assert file_path_matches(f"api/{name}", self.RECORDED) is True

    def test_an_ignore_path_keeps_the_escape_too(self):
        converted = _down("api/secr\\udce9t/", "api", kind=IGNORE_PATH)

        assert converted == "secr\\udce9t/"
        assert ignore_path_matches("secr\udce9t/x.py", converted) is True
        assert ignore_path_matches("secr/udce9t/x.py", converted) is False

    def test_the_validation_reads_the_escape_as_one_character_too(self):
        """``_normalise`` ran on the raw text with every backslash a separator,
        so the escape was split for the ``..``, drive and separator checks:
        the file ``..é.py`` was refused as a traversal and ``c:é x.py`` as a
        drive, and ``/é/x.py`` got the UNC message."""
        assert _down("api/..\\udce9.py", "api") == "..\\udce9.py"
        assert file_path_matches("..\udce9.py", "..\\udce9.py") is True
        assert _down("c:\\udce9x.py", "api") is None
        with pytest.raises(WorkspacePatternError) as excinfo:
            _down("/\\udce9/x.py", "api")
        message = str(excinfo.value)
        assert "leading '/'" in message
        assert "UNC" not in message
        assert "\\udce9" in message
        assert "\udce9" not in message

    def test_a_refusal_shows_the_escape_not_the_surrogate(self):
        with pytest.raises(WorkspacePatternError) as excinfo:
            _down("api/*/secr\\udce9t.py", "api/sub")

        message = str(excinfo.value)
        assert "\\udce9" in message
        message.encode("utf-8")

    @pytest.mark.parametrize(
        ("pattern", "prefix"),
        [
            # The remainder, quoted by the reason of the fnmatch-shape refusal.
            ("*/sub\udce9/*.py", "api"),
            # A fixed-length leading whose remainder is quoted by its reason.
            ("???/sub\udce9/[x].py", "api"),
            # The leading-separator refusal quotes the pattern as written.
            ("/api/sub\udce9/x.py", "api"),
            # The dot-component refusal quotes the pattern as written.
            ("api/./sub\udce9/x.py", "api"),
            # The separator count and the '..' refusals quote it too.
            ("//api/sub\udce9/x.py", "api"),
            ("api/../sub\udce9/x.py", "api"),
        ],
    )
    def test_every_refusal_shows_the_escape_wherever_it_quotes_the_pattern(
        self, pattern, prefix
    ):
        """The name as the matcher reads it holds the lone surrogate itself.
        A refusal's reason quotes components of the pattern, and the pattern as
        written, so each has to be shown as a report shows the name: the
        escape, which every sink can print."""
        with pytest.raises(WorkspacePatternError) as excinfo:
            _down(pattern, prefix)

        message = str(excinfo.value)
        assert "\\udce9" in message, message
        assert "\udce9" not in message, message
        message.encode("utf-8")


class TestALeadingSeparatorMatchesNoRelativePath:
    def test_a_rooted_workspace_pattern_is_refused(self):
        """The matcher reads the ``/`` literally, so ``/api/src/x.py`` matches
        no workspace-relative path; converted to ``src/x.py`` it suppressed a
        file it never matched."""
        assert file_path_matches("api/src/x.py", "/api/src/x.py") is False
        # The ignore kind is read by its own matcher, which turns a trailing '/'
        # into a directory form: the leading '/' is still literal there.
        for path in ("api/vendor/x.py", "api/vendor/lib/x.py", "vendor/x.py"):
            assert ignore_path_matches(path, "/api/vendor/") is False, path

        with pytest.raises(WorkspacePatternError, match="leading '/'"):
            _down("/api/src/x.py", "api")
        with pytest.raises(WorkspacePatternError, match="leading '/'"):
            _down("/api/vendor/", "api", kind=IGNORE_PATH)

    @pytest.mark.parametrize(
        ("pattern", "kind"),
        [("/api/src/x.py", SUPPRESSION), ("/api/vendor/", IGNORE_PATH)],
    )
    def test_the_refusal_tells_the_operator_to_remove_the_slash(self, pattern, kind):
        """A line copied from a project's config reads ``/api/src/x.py`` as
        rooted there and is refused here, so the message has to name the way out:
        the same entry without its leading ``/`` is the workspace-relative one."""
        with pytest.raises(WorkspacePatternError) as excinfo:
            _down(pattern, "api", kind=kind)

        message = str(excinfo.value)
        assert "remove the leading '/'" in message
        assert pattern in message

    def test_a_separator_before_a_leading_double_star_is_absorbed(self):
        """The one separator the matcher absorbs: ``/**/x.py`` is ``**/x.py``."""
        assert file_path_matches("api/sub/x.py", "/**/x.py") is True

        converted = _down("/**/x.py", "api")

        assert converted == "**/x.py"
        _contract_holds("/**/x.py", "api", converted)

    def test_the_absorbed_separator_is_absorbed_for_an_ignore_path_too(self):
        """The ignore kind has its own matcher: ``/**/vendor/`` is read as
        ``**/vendor/``, so it is converted, not refused, and agrees with it."""
        for path in ("api/vendor/x.py", "api/sub/vendor/lib/x.py", "api/other.py"):
            assert ignore_path_matches(path, "/**/vendor/") is ignore_path_matches(
                path, "**/vendor/"
            ), path

        converted = _down("/**/vendor/", "api", kind=IGNORE_PATH)

        assert converted == _down("**/vendor/", "api", kind=IGNORE_PATH)
        for path in ("vendor/x.py", "sub/vendor/lib/x.py", "other.py"):
            workspace_side = ignore_path_matches(f"api/{path}", "/**/vendor/")
            project_side = (
                False if converted is None else ignore_path_matches(path, converted)
            )
            assert project_side is workspace_side, path
