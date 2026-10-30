# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A results directory the sweep cannot list is refused, never skipped.

os.fwalk and os.walk call ``onerror`` for a subdirectory they cannot open and
otherwise pass over it in silence. Called without one, fs_guard's sweep left every
link below such a directory in place while reporting nothing, and the check that
runs before a sandboxed scanner (refuse_links_below) passed a link it never saw.
These run in-process on tmp_path only; the directory mode they set is POSIX, and
root lists every directory, so they skip where neither holds.
"""

import logging
import os
import sys

import pytest

from automated_security_helper.utils.sandbox import fs_guard

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="POSIX directory modes and symlinks"
    ),
    pytest.mark.skipif(
        hasattr(os, "geteuid") and os.geteuid() == 0,
        reason="root can list a directory whatever its mode",
    ),
]


@pytest.fixture
def locked_tree(tmp_path):
    """A results directory holding a subdirectory that cannot be listed, with a
    symlink inside it made before the mode was taken away. The mode is restored
    afterwards so tmp_path can be removed."""
    root = tmp_path / "results"
    locked = root / "locked"
    locked.mkdir(parents=True)
    (locked / "escape").symlink_to(tmp_path)
    locked.chmod(0o000)
    try:
        yield root, locked
    finally:
        locked.chmod(0o700)


def test_the_sweep_refuses_a_directory_it_cannot_list(locked_tree, caplog):
    root, locked = locked_tree

    with caplog.at_level(logging.WARNING, logger="ash"):
        with pytest.raises(PermissionError) as refused:
            fs_guard.sweep_writable([root], ("SWEEPSECRET-4471",))

    assert "locked" in str(refused.value)
    assert isinstance(refused.value.__cause__, PermissionError)
    lines = [
        record.getMessage()
        for record in caplog.records
        if "Could not list" in record.getMessage()
    ]
    assert lines, [record.getMessage() for record in caplog.records]
    locked.chmod(0o700)
    assert os.path.lexists(locked / "escape"), "the refused link is left as found"


def test_the_sweep_refusal_warning_hides_an_env_read_value(tmp_path, caplog):
    """The refusal names the directory and the root, and a tool can name a
    directory after an option it was given: the warning is redacted with the
    sweep's values, as the could-not-remove warning is."""
    value = "SWEEPSECRET-4472"
    root = tmp_path / "results"
    locked = root / f"dir-{value}"
    locked.mkdir(parents=True)
    locked.chmod(0o000)
    try:
        with caplog.at_level(logging.WARNING, logger="ash"):
            with pytest.raises(PermissionError):
                fs_guard.sweep_writable([root], (value,))
    finally:
        locked.chmod(0o700)

    lines = [
        record.getMessage()
        for record in caplog.records
        if "Could not list" in record.getMessage()
    ]
    assert lines, [record.getMessage() for record in caplog.records]
    assert not any(value in line for line in lines), lines


def test_the_sweep_refusal_is_value_free_when_the_values_could_not_be_read(
    tmp_path, caplog
):
    root = tmp_path / "results"
    locked = root / "dir-SWEEPSECRET-4473"
    locked.mkdir(parents=True)
    locked.chmod(0o000)
    try:
        with caplog.at_level(logging.WARNING, logger="ash"):
            with pytest.raises(PermissionError):
                fs_guard.sweep_writable([root], (), values_unread=True)
    finally:
        locked.chmod(0o700)

    lines = [
        record.getMessage()
        for record in caplog.records
        if "Could not list" in record.getMessage()
    ]
    assert lines, [record.getMessage() for record in caplog.records]
    assert all("SWEEPSECRET-4473" not in line for line in lines), lines
    assert all("redaction values could not be read" in line for line in lines), lines


def test_the_os_walk_fallback_refuses_a_directory_it_cannot_list(
    locked_tree, monkeypatch
):
    """The platform without fwalk takes the os.walk branch, which skips an
    unopenable directory the same way; it is given the same refusal."""
    root, _locked = locked_tree
    monkeypatch.delattr(os, "fwalk")

    with pytest.raises(PermissionError):
        fs_guard.sweep_writable([root])


def test_a_directory_removed_during_the_walk_is_not_a_refusal(tmp_path, monkeypatch):
    """fwalk reports a subdirectory that vanished between its listing and its
    open as ENOENT; nothing is below it, so the sweep goes on."""
    root = tmp_path / "results"
    (root / "gone").mkdir(parents=True)
    (root / "zzz-link").symlink_to(tmp_path)
    real_open = os.open

    def vanishing_open(path, flags, *args, **kwargs):
        if os.fspath(path) == "gone" and kwargs.get("dir_fd") is not None:
            raise FileNotFoundError(2, "No such file or directory", "gone")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", vanishing_open)

    removed = fs_guard.sweep_writable([root])

    assert removed == 1
    assert not os.path.lexists(root / "zzz-link")


def test_refuse_links_below_refuses_a_directory_it_cannot_list(locked_tree):
    root, _locked = locked_tree

    with pytest.raises(PermissionError) as refused:
        fs_guard.refuse_links_below(root)

    assert "locked" in str(refused.value)
    assert isinstance(refused.value.__cause__, PermissionError)


def test_a_root_that_cannot_be_checked_is_refused_not_skipped(tmp_path, caplog):
    """The sibling route at the root: ``Path.is_symlink`` already reads a missing
    root as False, so the handler around it only ever met the other errors (a
    parent the process cannot search, a link loop) and passed the whole root
    over in silence. Those are refused, logged as the other sweep failures are."""
    parent = tmp_path / "unsearchable"
    root = parent / "results"
    root.mkdir(parents=True)
    (root / "escape").symlink_to(tmp_path)
    parent.chmod(0o000)
    try:
        with caplog.at_level(logging.WARNING, logger="ash"):
            with pytest.raises(PermissionError):
                fs_guard.sweep_writable([root], ("SWEEPSECRET-4474",))
    finally:
        parent.chmod(0o700)

    lines = [
        record.getMessage()
        for record in caplog.records
        if "Could not check or remove the root" in record.getMessage()
    ]
    assert lines, [record.getMessage() for record in caplog.records]
    assert os.path.lexists(root / "escape"), "the link is left as found"
