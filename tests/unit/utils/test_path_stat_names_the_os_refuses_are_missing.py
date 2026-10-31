# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A name the OS refuses is a path that is not there, on every platform.

stat_named_path classed every errno but ENOENT, ENOTDIR and ELOOP as UNREADABLE,
so a config path Windows refuses as an invalid name (EINVAL, a reserved
character) or a path longer than the OS allows (ENAMETOOLONG) fell back to the
defaults on POSIX and was refused on Windows, while the module's own docstring
put "a path the OS cannot take" under MISSING. A denied stat stays UNREADABLE.

Windows gives EINVAL to a symbolic link it cannot resolve as well (a link to
itself, which POSIX reports as ELOOP), so an EINVAL alone read a loop as a
missing path and the scan fell back to the defaults. An lstat of the path itself
tells the two apart: a link is the LOOP, anything else stays MISSING.
"""

from __future__ import annotations

import errno
import os
import stat

import pytest

from automated_security_helper.utils import path_stat

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("number", "kind"),
    [
        (errno.EINVAL, path_stat.MISSING),
        (errno.ENAMETOOLONG, path_stat.MISSING),
        (errno.ENOENT, path_stat.MISSING),
        (errno.EACCES, path_stat.UNREADABLE),
        (errno.ELOOP, path_stat.LOOP),
    ],
)
def test_the_errno_decides_the_kind(number, kind):
    # The fake stat is installed around the one call only (_refused_with): left
    # on the process-wide os module until the test's own monkeypatch unwound, it
    # was what the unit fixtures' teardown reached, and that teardown raised the
    # planted error (a TypeError: the fake took no follow_symlinks) in place of
    # the test's own result.
    problem = _refused_with(number, _file_stat())
    assert isinstance(problem, path_stat.StatProblem)
    assert problem.kind == kind
    assert problem.code == errno.errorcode[number]


def _link_stat() -> os.stat_result:
    return os.stat_result((stat.S_IFLNK | 0o777, 1, 1, 1, 0, 0, 0, 0, 0, 0))


def _file_stat() -> os.stat_result:
    return os.stat_result((stat.S_IFREG | 0o644, 1, 1, 1, 0, 0, 0, 0, 0, 0))


def _refused_with(number, lstat):
    """``stat_named_path`` with ``os.stat`` raising ``number`` and ``os.lstat``
    answering ``lstat`` (a stat_result, or an error to raise), the fakes
    installed around this one call only."""

    def refusing(path):
        raise OSError(number, os.strerror(number), path)

    def reading_the_link(path):
        if isinstance(lstat, BaseException):
            raise lstat
        return lstat

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(path_stat.os, "stat", refusing)
        patch.setattr(path_stat.os, "lstat", reading_the_link)
        return path_stat.stat_named_path("some/path")


def test_an_einval_on_a_path_that_is_a_link_is_the_loop():
    """Windows reports a symbolic link it cannot resolve (a link to itself) as
    EINVAL, the errno it gives an invalid name; lstat of the path itself tells
    the two apart. The loop is refused like ELOOP, with the errno kept."""
    problem = _refused_with(errno.EINVAL, _link_stat())

    assert isinstance(problem, path_stat.StatProblem)
    assert (problem.kind, problem.code, problem.number) == (
        path_stat.LOOP,
        "EINVAL",
        errno.EINVAL,
    )
    assert problem.cause().errno == errno.EINVAL


@pytest.mark.parametrize(
    "lstat",
    [
        pytest.param(_file_stat(), id="a-regular-file"),
        pytest.param(
            OSError(errno.EINVAL, os.strerror(errno.EINVAL)), id="lstat-refuses-too"
        ),
        pytest.param(ValueError("embedded null byte"), id="lstat-refuses-the-name"),
    ],
)
def test_an_einval_on_a_path_that_is_no_link_stays_missing(lstat):
    problem = _refused_with(errno.EINVAL, lstat)

    assert isinstance(problem, path_stat.StatProblem)
    assert (problem.kind, problem.code) == (path_stat.MISSING, "EINVAL")


def test_only_an_einval_reads_the_link():
    """The second read is for EINVAL alone: a denied stat is answered from the
    one stat, as the module promises."""
    read = []

    def refusing(path):
        raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), path)

    def counting(path):
        read.append(path)
        return _link_stat()

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(path_stat.os, "stat", refusing)
        patch.setattr(path_stat.os, "lstat", counting)
        problem = path_stat.stat_named_path("some/path")

    assert isinstance(problem, path_stat.StatProblem)
    assert problem.kind == path_stat.UNREADABLE
    assert read == []
