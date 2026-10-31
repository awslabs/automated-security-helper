# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""On Windows only an invalid name is "missing"; any other EINVAL is unreadable.

Why this exists
---------------
Windows reports a name it cannot take (``<`` or ``?`` in it) as EINVAL, and
path_stat read that errno as MISSING. But Windows also gives EINVAL to every
error it has no errno for: a share's logon failure, a network name deleted,
ERROR_CANT_ACCESS_FILE. Those read "not found", and a named config path behind
one fell back to the default configuration, the outcome the classification
exists to rule out. On Windows the error carries ``winerror``; only
ERROR_INVALID_NAME (123) is an invalid name.

The stat's error is raised from the path's ``__fspath__``, which ``os.stat`` and
``os.lstat`` both call first, so the test needs no Windows and patches nothing.
"""

from __future__ import annotations

import errno
import os

import pytest

from automated_security_helper.utils.path_stat import (
    LOOP,
    MISSING,
    UNREADABLE,
    StatProblem,
    stat_named_path,
)

pytestmark = pytest.mark.unit

ERROR_INVALID_NAME = 123
ERROR_LOGON_FAILURE = 1326
ERROR_NETNAME_DELETED = 64
ERROR_CANT_ACCESS_FILE = 1920


class _RaisesOnStat:
    """A path whose use in a stat raises *error*."""

    def __init__(self, error: OSError) -> None:
        self._error = error

    def __fspath__(self) -> str:
        raise self._error


#: What Windows says for a logon failure; the errno's own text is "Invalid argument".
WINDOWS_TEXT = "The user name or password is incorrect"


def _einval(winerror: int | None, strerror: str = "Invalid argument") -> OSError:
    error = OSError(errno.EINVAL, strerror)
    if winerror is not None:
        error.winerror = winerror  # type: ignore[attr-defined]
    return error


def _problem(error: OSError) -> StatProblem:
    result = stat_named_path(_RaisesOnStat(error))

    assert isinstance(result, StatProblem), result
    return result


def test_an_invalid_name_is_missing_with_or_without_a_windows_error():
    assert _problem(_einval(ERROR_INVALID_NAME)).kind == MISSING
    assert _problem(_einval(None)).kind == MISSING


@pytest.mark.parametrize(
    "winerror",
    [ERROR_LOGON_FAILURE, ERROR_NETNAME_DELETED, ERROR_CANT_ACCESS_FILE],
    ids=["logon-failure", "network-name-deleted", "cant-access-file"],
)
def test_any_other_windows_error_behind_an_einval_is_unreadable(winerror):
    problem = _problem(_einval(winerror, WINDOWS_TEXT))

    assert problem.kind == UNREADABLE
    # The Windows error is kept, not folded into "EINVAL": a refusal prints the
    # code, and its cause carries the Windows text.
    assert problem.code == f"WinError {winerror}"
    assert problem.number == errno.EINVAL
    assert problem.strerror == WINDOWS_TEXT
    cause = problem.cause()
    assert cause.errno == errno.EINVAL
    assert cause.strerror == WINDOWS_TEXT
    assert cause.filename is None


def test_an_error_with_no_stored_text_still_reads_from_its_errno():
    """The control: every other kind stores no strerror, so its cause is the
    errno's own text as before."""
    problem = _problem(OSError(errno.EACCES, "Permission denied"))

    assert problem.strerror == ""
    assert problem.cause().strerror == os.strerror(errno.EACCES)


def test_an_enoent_with_a_windows_error_is_still_missing():
    error = OSError(errno.ENOENT, "No such file or directory")
    error.winerror = 2  # type: ignore[attr-defined]

    assert _problem(error).kind == MISSING


def test_an_eloop_is_still_a_loop():
    assert _problem(OSError(errno.ELOOP, "Too many levels of symbolic links")).kind == (
        LOOP
    )
