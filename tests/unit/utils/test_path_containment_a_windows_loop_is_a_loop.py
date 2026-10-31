# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The loop probe of ``validate_contained_path`` reads Windows' answer to a loop.

``_is_a_loop`` asks the file system about a resolved path with ``os.stat`` and
takes ``ELOOP`` for a symlink loop left in the answer. Windows has no ``ELOOP``:
a reparse-point loop fails ``os.stat`` with ``ERROR_CANT_RESOLVE_FILENAME``
(winerror 1921). With only the ``ELOOP`` test a loop there was accepted on
CPython 3.13, where 3.10-3.12 refused it through their own ``resolve()``. Here a
``stat`` that fails with the Windows error stands in for the file system, so
these tests run, and mean the same, on every platform.
"""

from __future__ import annotations

import errno
import os

import pytest

from automated_security_helper.utils import path_containment
from automated_security_helper.utils.path_containment import (
    PathContainmentViolation,
    validate_contained_path,
)

pytestmark = pytest.mark.unit

_WINDOWS_LOOP = 1921


def _windows_error(winerror):
    """An ``OSError`` as Windows raises it: no POSIX errno that names the cause."""
    error = OSError(errno.EINVAL, "The path cannot be resolved")
    error.winerror = winerror
    return error


def _stat_fails_for(monkeypatch, target, error):
    """Make ``os.stat`` raise *error* for *target* and answer every other path."""
    real_stat = os.stat
    wanted = os.fspath(target)

    def stat(path, *args, **kwargs):
        if isinstance(path, (str, os.PathLike)) and os.fspath(path) == wanted:
            raise error
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", stat)


def test_a_stat_that_fails_with_the_windows_loop_error_is_a_loop(tmp_path, monkeypatch):
    probe = tmp_path / "reparse-loop"
    _stat_fails_for(monkeypatch, probe, _windows_error(_WINDOWS_LOOP))

    assert path_containment._is_a_loop(probe) is True


def test_control_the_posix_loop_error_is_still_a_loop(tmp_path, monkeypatch):
    probe = tmp_path / "symlink-loop"
    error = OSError(errno.ELOOP, "Too many levels of symbolic links")
    _stat_fails_for(monkeypatch, probe, error)

    assert path_containment._is_a_loop(probe) is True


@pytest.mark.parametrize("winerror", [2, 5, 1920, 1922])
def test_control_any_other_windows_error_is_not_a_loop(tmp_path, monkeypatch, winerror):
    probe = tmp_path / "unreadable"
    _stat_fails_for(monkeypatch, probe, _windows_error(winerror))

    assert path_containment._is_a_loop(probe) is False


def test_control_an_error_with_no_windows_code_and_no_loop_errno_is_not_a_loop(
    tmp_path, monkeypatch
):
    probe = tmp_path / "invalid"
    _stat_fails_for(monkeypatch, probe, OSError(errno.EINVAL, "Invalid argument"))

    assert path_containment._is_a_loop(probe) is False


def test_control_a_path_that_does_not_exist_is_not_a_loop(tmp_path):
    assert path_containment._is_a_loop(tmp_path / "not-there") is False


def test_a_candidate_through_a_windows_reparse_loop_is_rejected(tmp_path, monkeypatch):
    root = tmp_path / "ws"
    root.mkdir()
    looping = root.resolve() / "loop" / "sub"
    _stat_fails_for(monkeypatch, looping, _windows_error(_WINDOWS_LOOP))

    result = validate_contained_path("loop/sub", root)

    assert not result.ok
    assert result.error is not None
    assert result.error.violation is PathContainmentViolation.SYMLINK
    assert "cannot be resolved" in result.error.message


def test_control_the_same_candidate_is_accepted_when_nothing_loops(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()

    result = validate_contained_path("loop/sub", root)

    assert result.ok
