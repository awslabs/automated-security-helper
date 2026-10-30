# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``validate_contained_path`` returns a rejection when the path cannot be resolved.

The module promises that errors are returned, never raised, and the workspace
resolver that calls it catches only ``OSError`` and ``ValueError``. On CPython
3.10-3.12 ``Path.resolve()`` raises ``RuntimeError`` when an intermediate
component is a symlink loop, so a folder entry such as ``loop/sub``, or a root
reached through such a loop, escaped as a traceback instead of an exit code 2.

CPython 3.13 raises nothing there: it resolves as far as it can and appends the
rest unchecked, so the loop stayed in the answer, its text read as below the
root, and ``loop/sub`` was ACCEPTED, where the same entry was refused one
version earlier. The checks below therefore assert the rejection on every
version: the resolved path is asked about once more with ``os.lstat``, which the
kernel answers with ``ELOOP`` for a loop whatever the interpreter did.
"""

from __future__ import annotations

import sys

import pytest

from automated_security_helper.utils.path_containment import (
    PathContainmentViolation,
    validate_contained_path,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    ),
]


def _loop(directory):
    link = directory / "loop"
    link.symlink_to("loop")
    return link


def test_a_candidate_through_a_symlink_loop_is_rejected_not_raised(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    _loop(root)

    result = validate_contained_path("loop/sub", root)

    assert not result.ok
    assert result.error is not None
    assert result.error.violation is PathContainmentViolation.SYMLINK
    assert result.error.entry == "loop/sub"
    assert "cannot be resolved" in result.error.message


def test_a_root_through_a_symlink_loop_is_rejected_not_raised(tmp_path):
    _loop(tmp_path)

    result = validate_contained_path("project", tmp_path / "loop" / "ws")

    assert not result.ok
    assert result.error is not None
    assert result.error.violation is PathContainmentViolation.SYMLINK
    assert "root" in result.error.message


def test_a_root_that_is_itself_the_symlink_loop_is_rejected(tmp_path):
    """With the candidate ``.`` the joined path IS the root, so the loop is the
    last component; a probe that followed every component but the last read the
    link itself and accepted it on 3.13, where 3.10-3.12 refused."""
    loop = _loop(tmp_path)

    result = validate_contained_path(".", loop)

    assert not result.ok
    assert result.error is not None
    assert result.error.violation is PathContainmentViolation.SYMLINK
    assert "root" in result.error.message


def test_control_a_plain_candidate_is_still_accepted(tmp_path):
    root = tmp_path / "ws"
    (root / "project").mkdir(parents=True)

    result = validate_contained_path("project", root)

    assert result.ok
    assert result.resolved == (root / "project").resolve()


def test_control_a_candidate_that_does_not_exist_yet_is_still_accepted(tmp_path):
    """The loop probe answers ENOENT, not ELOOP, for a path that is not there, so
    ``must_exist=False`` keeps accepting a directory the caller will create."""
    root = tmp_path / "ws"
    root.mkdir()

    result = validate_contained_path("not/yet/made", root)

    assert result.ok
    assert result.resolved == root.resolve() / "not" / "yet" / "made"
