# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``validate_contained_path`` returns a rejection when the path cannot be resolved.

The module promises that errors are returned, never raised, and the workspace
resolver that calls it catches only ``OSError`` and ``ValueError``. On CPython
3.10-3.12 ``Path.resolve()`` raises ``RuntimeError`` when an intermediate
component is a symlink loop, so a folder entry such as ``loop/sub``, or a root
reached through such a loop, escaped as a traceback instead of an exit code 2.
CPython 3.13 resolves such a path without raising, so the checks below assert the
shape of the answer only where the interpreter raises.
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

RAISES_ON_A_LOOP = sys.version_info < (3, 13)


def _loop(directory):
    link = directory / "loop"
    link.symlink_to("loop")
    return link


def test_a_candidate_through_a_symlink_loop_is_rejected_not_raised(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    _loop(root)

    result = validate_contained_path("loop/sub", root)

    if RAISES_ON_A_LOOP:
        assert not result.ok
        assert result.error is not None
        assert result.error.violation is PathContainmentViolation.SYMLINK
        assert result.error.entry == "loop/sub"
        assert "cannot be resolved" in result.error.message


def test_a_root_through_a_symlink_loop_is_rejected_not_raised(tmp_path):
    _loop(tmp_path)

    result = validate_contained_path("project", tmp_path / "loop" / "ws")

    if RAISES_ON_A_LOOP:
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
