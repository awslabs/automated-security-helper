# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Pattern shapes the converters read wrongly, each checked against the matcher.

Four shapes, each a defect the base read the other way:

* A component ``c:notes.py`` is a POSIX name. ``PureWindowsPath(...).drive`` read
  it as a drive on every interpreter, and ``*:Zone.Identifier`` as one on 3.12
  and later only, so a pattern naming such a file was refused, and a finding in
  such a file lost its workspace attribution. A drive anchor is a letter, a colon
  and then a separator or the end.
* A project directory ``app[v2]`` is anchored by the matcher's equality reading:
  ``fnmatch`` never matches the text ``[v2]`` with the class ``[v2]``, so the
  glob reading covers nothing in the project and a path equal to the pattern's
  text is the one match. The base returned ``None`` for a pattern that matches
  a file, a contract violation in the direction that drops a stated suppression.
* ``*/*`` and ``*/*.py`` over a project directory ``lib.py`` were refused by the
  prefix-collision check although the module's own table converts them: a lone
  ``*`` or ``*<literal>`` remainder constrains the end of the joined path only.
* A pattern is text: a ``PurePosixPath`` has no trailing separator, so the
  converters' ``pattern`` parameter is typed ``str``.

Every down-conversion expectation here is earned by ``file_path_matches`` on
both sides of the contract the module states, not by reasoning about globs.
"""

import inspect

import pytest

from automated_security_helper.core.exceptions import WorkspacePatternError
from automated_security_helper.utils.suppression_matcher import file_path_matches
from automated_security_helper.utils.workspace_paths import (
    drive_anchor,
    SUPPRESSION,
    to_project_pattern,
    to_workspace_pattern,
)

pytestmark = pytest.mark.unit

PROBE_PATHS = [
    "x.py",
    "y.py",
    "a.py",
    "x.txt",
    "src/x.py",
    "sub/x.py",
    "sub/deep/x.py",
    "[v2]/x.py",
    "app[v2]/x.py",
    "*.py",
    "lib.py",
    "sub/lib.py",
]


def _contract_holds(pattern: str, prefix: str) -> None:
    """The module's contract, read on both sides with the real matcher."""
    converted = to_project_pattern(pattern, prefix, kind=SUPPRESSION)
    for path in PROBE_PATHS:
        workspace_side = file_path_matches(f"{prefix}/{path}", pattern)
        project_side = (
            False if converted is None else file_path_matches(path, converted)
        )
        assert project_side == workspace_side, (
            f"{pattern!r} over {prefix!r} -> {converted!r} disagrees with the "
            f"matcher at {path!r}: project {project_side}, workspace {workspace_side}"
        )


class TestAColonInANameIsNotADrive:
    @pytest.mark.parametrize("name", ["c:notes.py", "C:notes.py", "x:legacy"])
    def test_a_letter_colon_name_up_converts(self, name):
        assert to_workspace_pattern(name, "api") == f"api/{name}"

    @pytest.mark.parametrize("name", ["*:Zone.Identifier", "1:x.py", "a:b.yaml"])
    def test_a_non_letter_first_character_is_a_name_on_every_interpreter(self, name):
        """3.12+ read any ``X:`` prefix as a drive; 3.10 and 3.11 did not."""
        assert to_workspace_pattern(name, "api") == f"api/{name}"

    def test_a_letter_colon_project_prefix_is_a_directory(self):
        assert to_workspace_pattern("src/x.py", "x:legacy") == "x:legacy/src/x.py"

    @pytest.mark.parametrize("anchored", ["C:/Windows", "C:", "c:/", "D:\\x"])
    def test_a_real_drive_anchor_is_still_refused(self, anchored):
        with pytest.raises(WorkspacePatternError, match="drive anchor"):
            to_workspace_pattern(anchored, "api")

    def test_a_colon_name_down_converts_like_any_literal(self):
        assert to_project_pattern("api/c:notes.py", "api", kind=SUPPRESSION) == (
            "c:notes.py"
        )
        assert to_project_pattern("c:notes.py", "api", kind=SUPPRESSION) is None
        _contract_holds("api/c:notes.py", "api")

    @pytest.mark.parametrize(
        ("text", "anchor"),
        [
            ("C:/Windows", "C:"),
            ("c:\\x", "c:"),
            ("C:", "C:"),
            ("c:notes.py", ""),
            ("x:legacy/src/x.py", ""),
            ("1:x.py", ""),
            ("src/x.py", ""),
        ],
    )
    def test_the_drive_rule_is_shared_with_the_uri_reading(self, text, anchor):
        """``aggregation._posix_text`` strips the leading separator of a URI
        that reduced from ``file:///C:/x`` on the colon alone, so the POSIX URI
        ``/x:legacy/src/x.py`` read as unrooted and was rebased under its
        project. This is the rule the converters read, exported for the
        aggregator to adopt in place of its own colon test; until that
        adoption lands the two readings differ, and these rows pin the one the
        aggregator is to take."""
        assert drive_anchor(text) == anchor


class TestABracketNamedProjectIsAnchoredByEquality:
    def test_a_literal_remainder_is_the_rewrite(self):
        """``file_path_matches("app[v2]/x.py", "app[v2]/x.py")`` is True by
        equality, so the pattern covers one file of the project and the rewrite
        is that file's name; the base returned None and dropped the entry."""
        assert to_project_pattern("app[v2]/x.py", "app[v2]", kind=SUPPRESSION) == (
            "x.py"
        )
        _contract_holds("app[v2]/x.py", "app[v2]")

    def test_a_nested_bracket_component_is_anchored_too(self):
        assert (
            to_project_pattern("apps/x[1]/a.py", "apps/x[1]", kind=SUPPRESSION)
            == "a.py"
        )
        _contract_holds("apps/x[1]/a.py", "apps/x[1]")

    def test_a_glob_remainder_is_refused_not_widened(self):
        """Workspace-side only ``app[v2]/*.py`` spelled exactly matches; the
        project-side ``*.py`` would cover every Python file."""
        with pytest.raises(WorkspacePatternError, match="exact spelling"):
            to_project_pattern("app[v2]/*.py", "app[v2]", kind=SUPPRESSION)

    def test_a_bracket_pattern_over_another_project_is_none(self):
        """Over ``application`` the leading ends inside the prefix (``app[v2]``
        is four characters wide and the fifth is ``i``), so nothing matches."""
        assert (
            to_project_pattern("app[v2]/x.py", "application", kind=SUPPRESSION) is None
        )
        _contract_holds("app[v2]/x.py", "application")

    def test_a_later_wildcard_component_is_its_own_text_once_anchored_by_equality(
        self,
    ):
        """Once ``app[v2]`` has matched only by its spelling, the glob reading
        of the whole pattern matches nothing under the prefix, so a later
        component in the prefix span can only match as its own text: ``s?b``
        over ``s?b`` is that directory, over ``sub`` it is nothing. The base
        refused both as a wildcard inside the project path."""
        assert (
            to_project_pattern("app[v2]/s?b/x.py", "app[v2]/s?b", kind=SUPPRESSION)
            == "x.py"
        )
        _contract_holds("app[v2]/s?b/x.py", "app[v2]/s?b")
        assert (
            to_project_pattern("app[v2]/s?b/x.py", "app[v2]/sub", kind=SUPPRESSION)
            is None
        )
        _contract_holds("app[v2]/s?b/x.py", "app[v2]/sub")

    def test_a_lone_bracket_is_a_literal_to_fnmatch_and_converts_as_before(self):
        """``a]b`` and ``a[b`` are literals to ``fnmatch`` and were right already."""
        assert to_project_pattern("a]b/x.py", "a]b", kind=SUPPRESSION) == "x.py"
        assert to_project_pattern("a[b/x.py", "a[b", kind=SUPPRESSION) == "x.py"
        _contract_holds("a]b/x.py", "a]b")


class TestAStarRemainderConstrainsOnlyTheEnd:
    def test_star_slash_star_converts_to_everything(self):
        converted = to_project_pattern("*/*", "api", kind=SUPPRESSION)
        assert converted == "**/*"
        _contract_holds("*/*", "api")

    def test_star_slash_star_literal_converts_over_a_matching_prefix(self):
        """A project directory ``lib.py`` matches ``*.py`` itself, which the
        collision check read as the match beginning inside the prefix."""
        assert to_project_pattern("*/*.py", "lib.py", kind=SUPPRESSION) == "**/*.py"
        _contract_holds("*/*.py", "lib.py")
        _contract_holds("*/*.py", "api")

    def test_a_literal_after_the_leading_wildcard_still_fails_closed(self):
        """The collision check stays for the shape it exists for."""
        with pytest.raises(WorkspacePatternError, match="begin inside"):
            to_project_pattern("*/api/src/x.py", "services/api", kind=SUPPRESSION)


class TestAPatternIsText:
    @pytest.mark.parametrize("converter", [to_workspace_pattern, to_project_pattern])
    def test_the_pattern_parameter_is_typed_str(self, converter):
        """``PurePosixPath("vendor/")`` is ``vendor``: the directory form is gone
        before any call could keep it, so the parameter admits text only."""
        annotation = inspect.signature(converter).parameters["pattern"].annotation
        assert annotation in ("str", str)
