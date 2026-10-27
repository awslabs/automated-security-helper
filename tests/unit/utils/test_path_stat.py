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


def _failing_stat(monkeypatch, error):
    calls = []

    def fake(path, *args, **kwargs):
        calls.append(os.fspath(path))
        raise error

    monkeypatch.setattr(path_stat.os, "stat", fake)
    return calls


@pytest.mark.parametrize(
    "error, kind, code",
    [
        (FileNotFoundError(errno.ENOENT, "No such file"), MISSING, "ENOENT"),
        (NotADirectoryError(errno.ENOTDIR, "Not a directory"), MISSING, "ENOTDIR"),
        (OSError(errno.ELOOP, "Too many levels of symbolic links"), LOOP, "ELOOP"),
        (PermissionError(errno.EACCES, "Permission denied"), UNREADABLE, "EACCES"),
        (OSError(errno.EIO, "Input/output error"), UNREADABLE, "EIO"),
        (OSError("stat failed without an errno"), UNREADABLE, "no error code"),
        (ValueError("embedded null byte"), MISSING, ""),
    ],
)
def test_each_stat_failure_is_classified_by_its_own_error(
    monkeypatch, error, kind, code
):
    calls = _failing_stat(monkeypatch, error)
    result = stat_named_path("named.yaml")
    assert isinstance(result, StatProblem), result
    assert (result.kind, result.code) == (kind, code)
    assert calls == ["named.yaml"], calls
    assert not is_regular_file(result)


def test_an_errno_without_a_name_is_named_by_its_number(monkeypatch):
    unnamed = 1 + max(errno.errorcode)
    _failing_stat(monkeypatch, OSError(unnamed, "an errno with no name"))
    result = stat_named_path("named.yaml")
    assert isinstance(result, StatProblem)
    assert (result.kind, result.code, result.number) == (
        UNREADABLE,
        str(unnamed),
        unnamed,
    )


def test_the_cause_carries_the_errno_and_never_the_path(monkeypatch):
    _failing_stat(
        monkeypatch, PermissionError(errno.EACCES, "Permission denied", "/hidden/x")
    )
    result = stat_named_path("/hidden/x")
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
def test_the_cause_of_an_error_with_no_errno_carries_its_own_strerror(
    monkeypatch, error, text
):
    """An error that carried no errno is described by its own strerror, or by
    "no error code" when it has none, never by the text "None"."""
    _failing_stat(monkeypatch, error)
    result = stat_named_path("named.yaml")
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
