# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The one stat every named-config site classifies a path by."""

from __future__ import annotations

import errno
import os

import pytest

from automated_security_helper.utils import path_stat
from automated_security_helper.utils.path_stat import (
    LOOP,
    MISSING,
    UNREADABLE,
    StatProblem,
    is_regular_file,
    stat_named_path,
)

pytestmark = pytest.mark.unit


def _stat_failing_with(error, path):
    """``stat_named_path(path)`` with ``os.stat`` raising ``error``, and the
    paths the stat was asked for.

    ``path_stat.os`` is the process-wide ``os`` module, so the fake stat is
    installed only around this one call: left in place until the test's own
    ``monkeypatch`` is undone, it is what every later fixture teardown's stat
    reached, and those teardowns raised the planted error instead of the test
    reporting its result.
    """
    calls = []

    def fake(path, *args, **kwargs):
        calls.append(os.fspath(path))
        raise error

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(path_stat.os, "stat", fake)
        result = stat_named_path(path)
    return result, calls


@pytest.mark.parametrize(
    "error, kind, code",
    [
        (FileNotFoundError(errno.ENOENT, "No such file"), MISSING, "ENOENT"),
        (NotADirectoryError(errno.ENOTDIR, "Not a directory"), MISSING, "ENOTDIR"),
        # The code is the errno's name as this platform's errno module spells
        # it: on Windows ELOOP and WSAELOOP share a number, and errorcode names
        # it WSAELOOP.
        (
            OSError(errno.ELOOP, "Too many levels of symbolic links"),
            LOOP,
            errno.errorcode[errno.ELOOP],
        ),
        (PermissionError(errno.EACCES, "Permission denied"), UNREADABLE, "EACCES"),
        (OSError(errno.EIO, "Input/output error"), UNREADABLE, "EIO"),
        (OSError("stat failed without an errno"), UNREADABLE, "no error code"),
        (ValueError("embedded null byte"), MISSING, ""),
    ],
)
def test_each_stat_failure_is_classified_by_its_own_error(error, kind, code):
    result, calls = _stat_failing_with(error, "named.yaml")
    assert isinstance(result, StatProblem), result
    assert (result.kind, result.code) == (kind, code)
    assert calls == ["named.yaml"], calls
    assert not is_regular_file(result)


def test_an_errno_without_a_name_is_named_by_its_number():
    unnamed = 1 + max(errno.errorcode)
    result, _ = _stat_failing_with(
        OSError(unnamed, "an errno with no name"), "named.yaml"
    )
    assert isinstance(result, StatProblem)
    assert (result.kind, result.code, result.number) == (
        UNREADABLE,
        str(unnamed),
        unnamed,
    )


def test_the_cause_carries_the_errno_and_never_the_path():
    result, _ = _stat_failing_with(
        PermissionError(errno.EACCES, "Permission denied", "/hidden/x"), "/hidden/x"
    )
    assert isinstance(result, StatProblem)
    cause = result.cause()
    assert (cause.errno, cause.strerror) == (errno.EACCES, os.strerror(errno.EACCES))
    assert cause.filename is None and cause.filename2 is None
    assert "/hidden/x" not in f"{cause!s}{cause!r}"


@pytest.mark.parametrize(
    "error, text",
    [
        (OSError("stat failed without an errno"), "no error code"),
        (OSError(None, "the device went away"), "the device went away"),
    ],
)
def test_the_cause_of_an_error_with_no_errno_carries_its_own_strerror(error, text):
    """An error that carried no errno is described by its own strerror, or by
    "no error code" when it has none, never by the text "None"."""
    result, _ = _stat_failing_with(error, "named.yaml")
    assert isinstance(result, StatProblem)
    cause = result.cause()
    assert (cause.errno, cause.strerror) == (None, text)
    assert "None" not in cause.strerror


def test_a_path_that_stats_is_returned_with_its_stat(tmp_path):
    named = tmp_path / "named.yaml"
    named.write_text("project_name: t\n", encoding="utf-8")
    result = stat_named_path(named)
    assert isinstance(result, os.stat_result)
    assert is_regular_file(result)
    assert not is_regular_file(stat_named_path(tmp_path))


def test_a_missing_path_and_a_link_loop_on_the_real_filesystem(tmp_path):
    missing = stat_named_path(tmp_path / "absent.yaml")
    assert isinstance(missing, StatProblem) and missing.kind == MISSING
    loop = tmp_path / "loop.yaml"
    loop.symlink_to(loop)
    looped = stat_named_path(loop)
    assert isinstance(looped, StatProblem) and looped.kind == LOOP


def test_a_link_to_a_missing_target_on_the_real_filesystem_is_missing(tmp_path):
    """A dangling link is a missing path, not a loop, on every platform: the
    control for the Windows reading of an unresolvable link as LOOP, which must
    not reach a link whose target is merely absent."""
    dangling = tmp_path / "dangling.yaml"
    dangling.symlink_to(tmp_path / "absent-target.yaml")
    result = stat_named_path(dangling)
    assert isinstance(result, StatProblem) and result.kind == MISSING, result
