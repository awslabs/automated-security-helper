# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Five readings of ``validate_contained_path`` at its edges.

- A Windows drive-relative ``C:..\\b`` holds a ``..`` component that the POSIX
  tokenizer read as one component ``C:..``, so the traversal passed the text rule.
- A NUL in the candidate or the root raised ``ValueError`` out of ``os.lstat`` and
  ``resolve()``, where the module promises a returned rejection.
- An absolute candidate naming the root by the root's own symlinked spelling was
  refused as a symlink, while ``.`` named the same root and was accepted.
- On a file system that compares names without regard to case, a candidate spelled
  in another case than the root was rejected as outside it by a text comparison;
  the candidate's ancestors are compared with the root by identity when the text
  says no.
- A rejection names the candidate and the root as given, never the real path the
  candidate resolves to, which the workspace resolver echoes to an MCP client. The
  one message that still printed the resolved root, the ``must_exist`` MISSING
  rejection, names the root as given too.

Every path here is under ``tmp_path``.
"""

from __future__ import annotations

import os
import sys

import pytest

from automated_security_helper.utils import output_dir_links
from automated_security_helper.utils.path_containment import (
    PathContainmentViolation,
    validate_contained_path,
)

pytestmark = pytest.mark.unit

needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


@pytest.fixture
def root(tmp_path):
    (tmp_path / "ws" / "project-a").mkdir(parents=True)
    return tmp_path / "ws"


@pytest.mark.parametrize("candidate", ["C:..\\ws\\b", "C:../ws/b", "c:..\\b"])
def test_a_drive_relative_parent_is_traversal(root, candidate):
    result = validate_contained_path(candidate, root)

    assert not result.ok
    assert result.error.violation == PathContainmentViolation.PARENT_TRAVERSAL


def test_control_a_drive_relative_name_without_a_parent_is_not_traversal(root):
    result = validate_contained_path("C:project-a", root)

    assert result.error is None or (
        result.error.violation != PathContainmentViolation.PARENT_TRAVERSAL
    )


@pytest.mark.parametrize("where", ["candidate", "root"])
def test_a_nul_is_returned_as_a_rejection(root, where):
    if where == "candidate":
        result = validate_contained_path("project\x00a", root)
    else:
        result = validate_contained_path("project-a", str(root) + "\x00")

    assert not result.ok
    assert result.error.violation == PathContainmentViolation.EMBEDDED_NUL
    assert result.error.violation.value == "embedded-nul"


@needs_symlinks
def test_the_roots_own_symlinked_spelling_names_the_root(root, tmp_path):
    link = tmp_path / "link"
    link.symlink_to(root, target_is_directory=True)

    by_dot = validate_contained_path(".", link)
    by_name = validate_contained_path(str(link), link)

    assert by_dot.ok
    assert by_name.ok
    assert by_name.resolved == by_dot.resolved == root.resolve()


@needs_symlinks
def test_control_a_link_inside_the_root_is_still_refused(root):
    (root / "alias").symlink_to(root / "project-a", target_is_directory=True)

    result = validate_contained_path("alias", root)

    assert result.error.violation == PathContainmentViolation.SYMLINK


def test_a_spelling_the_file_system_reads_as_the_root_is_inside_it(
    root, tmp_path, monkeypatch
):
    """Stood in for a case-insensitive file system: the identity both spellings of
    the root have is the root's own, and nothing else about the paths changes."""
    real_identity = output_dir_links._identity
    named_root = os.path.realpath(root).lower()

    def identity(path):
        if os.fspath(path).lower() == named_root:
            return real_identity(root)
        return real_identity(path)

    monkeypatch.setattr(output_dir_links, "_identity", identity)
    other_case = tmp_path / "WS" / "project-a"

    result = validate_contained_path(str(other_case), root)

    assert result.ok, result.error


def test_control_a_sibling_sharing_the_roots_name_prefix_is_outside(root, tmp_path):
    (tmp_path / "ws-evil").mkdir()

    result = validate_contained_path(str(tmp_path / "ws-evil"), root)

    assert result.error.violation == PathContainmentViolation.OUTSIDE_ROOT


@needs_symlinks
def test_a_rejection_does_not_name_where_the_candidate_resolves(root, tmp_path):
    secret = tmp_path / "secret-place"
    secret.mkdir()
    (root / "project-a" / "hop").symlink_to(secret, target_is_directory=True)

    result = validate_contained_path("project-a/hop/inner", root)

    assert result.error.violation == PathContainmentViolation.OUTSIDE_ROOT
    assert "secret-place" not in result.error.message
    assert "project-a/hop/inner" in result.error.message


@needs_symlinks
def test_a_missing_directory_rejection_names_the_root_as_given(tmp_path):
    """The must_exist rejection printed the resolved root, so a root spelled
    through a link told the client where the link leads."""
    real = tmp_path / "real-place"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)

    result = validate_contained_path("project-c", alias, must_exist=True)

    assert result.error.violation == PathContainmentViolation.MISSING
    assert str(alias) in result.error.message
    assert "real-place" not in result.error.message
