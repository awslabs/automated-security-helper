# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A name the OS refuses is a path that is not there, on every platform.

stat_named_path classed every errno but ENOENT, ENOTDIR and ELOOP as UNREADABLE,
so a config path Windows refuses as an invalid name (EINVAL, a reserved
character) or a path longer than the OS allows (ENAMETOOLONG) fell back to the
defaults on POSIX and was refused on Windows, while the module's own docstring
put "a path the OS cannot take" under MISSING. A denied stat stays UNREADABLE.
"""

from __future__ import annotations

import errno
import os

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
def test_the_errno_decides_the_kind(monkeypatch, number, kind):
    def refusing(path):
        raise OSError(number, os.strerror(number), path)

    monkeypatch.setattr(os, "stat", refusing)
    problem = path_stat.stat_named_path("some/path")
    assert isinstance(problem, path_stat.StatProblem)
    assert problem.kind == kind
    assert problem.code == errno.errorcode[number]
