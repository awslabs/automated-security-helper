# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for directory containment validation.

Covers the five rejection rules, the at-or-below boundary, and the
cross-platform traps this module exists to avoid: string prefix comparison,
backslash separators, and branching on Path.is_absolute.
"""

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from automated_security_helper.utils.path_containment import (
    PathContainmentViolation,
    validate_contained_path,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _symlink_or_skip(link: Path, target: Path, target_is_directory: bool = True):
    """Create a symlink, skipping the test where the platform forbids it."""
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlink creation unavailable on this platform: {exc}")


@pytest.fixture
def root(tmp_path):
    """A real, resolved root directory with one child project."""
    workspace = tmp_path / "workspace"
    (workspace / "project-a" / "src").mkdir(parents=True)
    (workspace / "project-b").mkdir()
    return workspace


# ---------------------------------------------------------------------------
# Tests: accepted paths
# ---------------------------------------------------------------------------


class TestAccepted:
    """Paths at or below the root are accepted."""

    def test_direct_child(self, root):
        result = validate_contained_path("project-a", root)
        assert result.ok
        assert result.error is None
        assert result.resolved == (root / "project-a").resolve()

    def test_nested_child(self, root):
        result = validate_contained_path("project-a/src", root)
        assert result.ok
        assert result.resolved == (root / "project-a" / "src").resolve()

    def test_the_root_itself_is_at_or_below_the_root(self, root):
        """'at-or-below' includes 'at'."""
        assert validate_contained_path(".", root).ok
        assert validate_contained_path("", root).ok

    def test_accepts_a_path_object(self, root):
        assert validate_contained_path(Path("project-a"), root).ok

    def test_accepts_a_path_object_root(self, root):
        assert validate_contained_path("project-a", Path(root)).ok

    def test_absolute_path_inside_root_is_accepted(self, root):
        """Absolute is allowed when it canonicalises to at-or-below root."""
        result = validate_contained_path(root / "project-a", root)
        assert result.ok

    def test_nonexistent_child_is_accepted_by_default(self, root):
        """Existence is not one of the containment rules."""
        result = validate_contained_path("project-c", root)
        assert result.ok
        assert result.resolved == (root / "project-c").resolve()

    def test_backslash_separators_are_understood(self, root):
        """A Windows-style separator must not silently become one filename."""
        result = validate_contained_path("project-a\\src", root)
        assert result.ok

    def test_resolved_is_always_absolute(self, root):
        assert validate_contained_path("project-a", root).resolved.is_absolute()


# ---------------------------------------------------------------------------
# Tests: parent traversal
# ---------------------------------------------------------------------------


class TestParentTraversal:
    """Any '..' component is rejected outright, before resolution."""

    @pytest.mark.parametrize(
        "candidate",
        [
            "..",
            "../outside",
            "project-a/..",
            "project-a/../project-b",
            "project-a/../../escape",
            "./../x",
        ],
    )
    def test_rejected(self, root, candidate):
        result = validate_contained_path(candidate, root)
        assert not result.ok
        assert result.error.violation == PathContainmentViolation.PARENT_TRAVERSAL

    def test_rejected_even_when_it_resolves_back_inside(self, root):
        """project-a/../project-b lands inside root, and is still rejected.

        The rule is about the text of the input, not where it happens to land:
        a workspace definition that walks out of a project and back into
        another is not expressing containment, whatever it resolves to.
        """
        result = validate_contained_path("project-a/../project-b", root)
        assert not result.ok
        assert result.error.violation == PathContainmentViolation.PARENT_TRAVERSAL

    def test_backslash_traversal_is_rejected(self, root):
        """'..' hidden behind a Windows separator must still be seen."""
        result = validate_contained_path("project-a\\..\\project-b", root)
        assert not result.ok
        assert result.error.violation == PathContainmentViolation.PARENT_TRAVERSAL

    def test_a_dotdot_in_a_filename_is_not_traversal(self, root):
        """'a..b' is a legal name; only a whole '..' component counts."""
        assert validate_contained_path("a..b", root).ok
        assert validate_contained_path("project-a/v1..2", root).ok

    def test_traversal_in_the_root_is_reported_against_the_root(self, root):
        result = validate_contained_path("project-a", root / ".." / "workspace")
        assert not result.ok
        assert result.error.violation == PathContainmentViolation.PARENT_TRAVERSAL
        assert ".." in result.error.entry

    def test_error_names_the_offending_entry(self, root):
        result = validate_contained_path("project-a/../../escape", root)
        assert result.error.entry == "project-a/../../escape"


# ---------------------------------------------------------------------------
# Tests: outside the root
# ---------------------------------------------------------------------------


class TestOutsideRoot:
    """Anything that canonicalises above or beside the root is rejected."""

    def test_absolute_path_outside_root(self, root, tmp_path):
        outside = tmp_path / "elsewhere"
        outside.mkdir()
        result = validate_contained_path(outside, root)
        assert not result.ok
        assert result.error.violation == PathContainmentViolation.OUTSIDE_ROOT

    def test_absolute_system_path(self, root):
        result = validate_contained_path("/etc/passwd", root)
        assert not result.ok
        assert result.error.violation == PathContainmentViolation.OUTSIDE_ROOT

    def test_sibling_directory_sharing_a_name_prefix(self, root, tmp_path):
        """The classic string-prefix bug: 'workspace-evil' is not in 'workspace'.

        A slash-joined prefix comparison would accept this. is_relative_to
        compares path components, so it does not.
        """
        evil = tmp_path / "workspace-evil"
        evil.mkdir()
        result = validate_contained_path(evil, root)
        assert not result.ok
        assert result.error.violation == PathContainmentViolation.OUTSIDE_ROOT

    def test_error_carries_both_entry_and_root(self, root):
        result = validate_contained_path("/etc/passwd", root)
        assert result.error.entry
        assert result.error.root
        assert result.error.message


# ---------------------------------------------------------------------------
# Tests: symlinks
# ---------------------------------------------------------------------------


class TestSymlinks:
    """A candidate that is itself a symlink is rejected, wherever it points."""

    def test_symlink_pointing_outside_root(self, root, tmp_path):
        outside = tmp_path / "outside-target"
        outside.mkdir()
        _symlink_or_skip(root / "sneaky", outside)
        result = validate_contained_path("sneaky", root)
        assert not result.ok
        assert result.error.violation == PathContainmentViolation.SYMLINK

    def test_symlink_pointing_inside_root_is_still_rejected(self, root):
        """Resolution would hide this one, so it needs its own check."""
        _symlink_or_skip(root / "alias", root / "project-a")
        result = validate_contained_path("alias", root)
        assert not result.ok
        assert result.error.violation == PathContainmentViolation.SYMLINK

    def test_symlink_is_reported_as_symlink_not_as_outside_root(self, root, tmp_path):
        """The more specific violation wins, because it is the actionable one."""
        outside = tmp_path / "outside-target"
        outside.mkdir()
        _symlink_or_skip(root / "sneaky", outside)
        result = validate_contained_path("sneaky", root)
        assert result.error.violation == PathContainmentViolation.SYMLINK

    def test_a_real_directory_under_a_symlinked_root_is_accepted(self, root, tmp_path):
        """Only the candidate is checked; a symlinked root resolves normally."""
        link_root = tmp_path / "root-link"
        _symlink_or_skip(link_root, root)
        result = validate_contained_path("project-a", link_root)
        assert result.ok
        assert result.resolved == (root / "project-a").resolve()


# ---------------------------------------------------------------------------
# Tests: opt-in existence check
# ---------------------------------------------------------------------------


class TestMustExist:
    """must_exist is opt-in, so the default behaviour is unchanged."""

    def test_missing_directory_rejected_when_required(self, root):
        result = validate_contained_path("project-c", root, must_exist=True)
        assert not result.ok
        assert result.error.violation == PathContainmentViolation.MISSING

    def test_existing_directory_accepted_when_required(self, root):
        assert validate_contained_path("project-a", root, must_exist=True).ok

    def test_a_file_is_not_a_directory(self, root):
        """The validator guards directories, so a regular file is a violation."""
        (root / "project-a" / "notes.txt").write_text("x", encoding="utf-8")
        result = validate_contained_path("project-a/notes.txt", root, must_exist=True)
        assert not result.ok
        assert result.error.violation == PathContainmentViolation.MISSING


# ---------------------------------------------------------------------------
# Tests: result shape
# ---------------------------------------------------------------------------


class TestResultShape:
    """Callers turn these into exit code 2, so the shape has to be stable."""

    def test_ok_and_error_are_mutually_exclusive(self, root):
        good = validate_contained_path("project-a", root)
        bad = validate_contained_path("..", root)
        assert good.ok and good.error is None and good.resolved is not None
        assert not bad.ok and bad.error is not None and bad.resolved is None

    def test_result_is_immutable(self, root):
        result = validate_contained_path("project-a", root)
        with pytest.raises(FrozenInstanceError):
            # Any Path will do -- this only proves the dataclass is frozen and
            # never touches the filesystem. Deliberately not a temp-directory
            # literal: ASH scans its own repository in CI at MEDIUM, and
            # bandit's B108 flags those regardless of intent.
            result.resolved = Path("elsewhere")  # type: ignore[misc]

    def test_error_is_immutable(self, root):
        result = validate_contained_path("..", root)
        with pytest.raises(FrozenInstanceError):
            result.error.entry = "rewritten"  # type: ignore[misc]

    def test_violation_values_are_stable_strings(self):
        """These reach users in error output, so pin them."""
        assert PathContainmentViolation.PARENT_TRAVERSAL.value == "parent-traversal"
        assert PathContainmentViolation.OUTSIDE_ROOT.value == "outside-root"
        assert PathContainmentViolation.SYMLINK.value == "symlink"
        assert PathContainmentViolation.MISSING.value == "missing"

    def test_message_mentions_the_entry(self, root):
        result = validate_contained_path("project-a/../escape", root)
        assert "project-a/../escape" in result.error.message

    def test_error_paths_are_posix_shaped(self, root):
        """Stable across platforms, so callers can log them comparably."""
        result = validate_contained_path("project-a\\..\\x", root)
        assert "\\" not in result.error.entry
