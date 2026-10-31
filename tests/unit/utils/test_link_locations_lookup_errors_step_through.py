# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``link_locations`` reads a failed lookup as ``Path.is_symlink`` did.

The walk asks ``os.lstat`` about each component. ``Path.is_symlink`` answered
False for a component holding a NUL (``ValueError``) and for the Win32 errors
pathlib ignores (a device not ready, an invalid name, a name that cannot be
resolved: 21, 123 and 1921, each with ``EINVAL`` as its errno); the walk let the
``ValueError`` propagate to its callers, which used to get an empty list, and
ended on the Win32 errors, so a ``..`` later in the path was never applied. Both
are stepped through as plain names again.
"""

from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils import link_locations as module
from automated_security_helper.utils.link_locations import link_locations

pytestmark = pytest.mark.unit


def test_a_component_holding_a_nul_is_not_a_link_and_does_not_raise(tmp_path):
    # Built from the path with its own links resolved, as every test here is: a
    # temporary directory that passes through a link (macOS's /var) would have
    # the walk report that link, and "no links" would fail for that reason.
    tree = Path(os.path.realpath(tmp_path))

    assert link_locations(tree / "a\x00b" / "c") == []


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_a_component_holding_a_nul_is_stepped_through_to_a_later_link(tmp_path):
    """Not raising is the least of it: the walk goes on past the name it could not
    look up, so a ``..`` after it is applied and the link later in the path is
    found, as for the Win32 errors below."""
    tree = _layout(tmp_path)

    found = link_locations(tree / "a\x00b" / ".." / "dir" / "link" / "file")

    assert found == [tree / "dir" / "link"]


def _layout(tmp_path):
    tree = Path(os.path.realpath(tmp_path))
    (tree / "target").mkdir()
    (tree / "dir").mkdir()
    (tree / "dir" / "link").symlink_to(tree / "target", target_is_directory=True)
    return tree


def _lstat_failing_at(monkeypatch, name: str, error: OSError):
    real_lstat = os.lstat

    def failing(path, *args, **kwargs):
        if os.path.basename(os.fspath(path)) == name:
            raise error
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(module.os, "lstat", failing)


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
@pytest.mark.parametrize("winerror", [21, 123, 1921])
def test_a_win32_error_pathlib_ignores_is_stepped_through(
    tmp_path, monkeypatch, winerror
):
    tree = _layout(tmp_path)
    error = OSError(errno.EINVAL, "invalid name")
    error.winerror = winerror
    _lstat_failing_at(monkeypatch, "bad", error)

    found = link_locations(tree / "bad" / ".." / "dir" / "link" / "file")

    assert found == [tree / "dir" / "link"]


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_control_any_other_lookup_error_still_ends_the_walk(tmp_path, monkeypatch):
    tree = _layout(tmp_path)
    _lstat_failing_at(monkeypatch, "bad", OSError(errno.EINVAL, "invalid argument"))

    assert link_locations(tree / "bad" / ".." / "dir" / "link" / "file") == []


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_control_a_missing_component_is_stepped_through_as_before(tmp_path):
    tree = _layout(tmp_path)

    found = link_locations(tree / "missing" / ".." / "dir" / "link" / "file")

    assert found == [tree / "dir" / "link"]
