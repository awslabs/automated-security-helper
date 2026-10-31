# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The atomic writer copies only the permission bits a results file should have.

open_for_atomic_write gives its staging file the mode of the regular file already
at the target name, so a 0o600 report is not replaced by a 0o644 one. It copied
the whole mode, so an entry a scanner put at the name handed its setuid, setgid
or sticky bit to the results file, and, outside every registered root (where no
hard-link refusal runs and the writer replaces the entry), a hard-linked entry
handed over its mode as well. Only the read, write and execute bits are copied
now, and only from a file no other name refers to; a hard-linked entry outside
every root leaves the new file at its umask-derived mode. Below a root a
hard-linked entry is refused before any of this (test_link_refusal_family.py).

The planted mode carries the sticky bit as well as setuid: Linux clears setuid
(and setgid) on a write by a process without CAP_FSETID, so a setuid bit alone
would vanish from the new file whether or not the mask ran, and the test could not
tell the mask from its absence. The sticky bit survives a write, so it is what
these tests measure on an unprivileged venue; the setuid assertion still holds on
a root one.

The mode is copied whoever owns the file at the name, and only as a best effort. A
root or container run that rewrites a host user's 0o600 results file must not leave
a 0o644 one in its place, so the permission bits follow the file being replaced and
the ownership is left alone (the new file is the process's own). A name with no file
at it still gets the umask-derived mode. A filesystem that refuses a mode change
(FUSE, SMB) keeps the write. A staging file that cannot be removed after a failed
write leaves the error that ended the write as the one raised. The tests that need
the owner to differ patch ``os.geteuid`` rather than rely on a second account; they
set the umask to 0o022 themselves, because the mode a fresh file gets is what the
bug showed.
"""

import errno
import os
import stat
import sys

import pytest

from automated_security_helper.utils.sandbox import fs_guard

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes and hard links"),
    pytest.mark.skipif(not hasattr(os, "fchmod"), reason="the mode copy uses fchmod"),
]


def _mode(path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def _default_mode(directory) -> int:
    """The mode a fresh file gets in ``directory`` under the current umask."""
    control = directory / "control"
    fd = os.open(control, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
    os.close(fd)
    return _mode(control)


def _plant(path, mode: int) -> None:
    path.write_bytes(b"planted\n")
    os.chmod(path, mode)
    if _mode(path) != mode:
        pytest.skip(f"this filesystem does not keep mode {mode:o} on a file")


@pytest.fixture(params=["unregistered", "registered"])
def where(request, tmp_path):
    """A directory to write in: not a registered root, then one that is.

    The guarded branch (a registered root) writes through a directory descriptor,
    the other by name; the mode copy runs on both.
    """
    if request.param == "unregistered":
        yield tmp_path
        return
    directory = tmp_path / "out"
    directory.mkdir()
    with fs_guard.writable_root(directory):
        yield directory


def _assert_setuid_and_sticky_bits_are_not_carried(directory) -> None:
    target = directory / "report.json"
    _plant(target, 0o5755)

    with fs_guard.open_for_atomic_write(target) as handle:
        handle.write("written\n")

    assert target.read_text() == "written\n"
    assert _mode(target) == 0o755, oct(_mode(target))
    assert not os.lstat(target).st_mode & (stat.S_ISUID | stat.S_ISVTX)


def test_setuid_and_sticky_bits_at_the_name_are_not_carried_onto_the_new_file(
    tmp_path,
):
    """The sticky bit is the one a write cannot clear, so it is the bit that
    tells the mask from no mask on an unprivileged venue (module docstring)."""
    _assert_setuid_and_sticky_bits_are_not_carried(tmp_path)


def test_setuid_and_sticky_bits_are_not_carried_below_a_registered_root_either(
    tmp_path,
):
    """The same mask on the branch that writes through a directory descriptor,
    which the unregistered test above does not reach."""
    directory = tmp_path / "out"
    directory.mkdir()
    with fs_guard.writable_root(directory):
        _assert_setuid_and_sticky_bits_are_not_carried(directory)


def test_a_hard_linked_file_at_the_name_lends_the_new_file_no_mode(tmp_path):
    """Outside every registered root (tmp_path is not one) the writer replaces
    the entry and spares the file the other name refers to; it also takes no mode
    from it. The new file has the mode a fresh file gets, and the other name keeps
    its bytes and its whole mode, setuid bit included. Below a root the same entry
    is refused with OutputHardLinkRefused before the staging file is made."""
    target = tmp_path / "report.json"
    other = tmp_path / "other-name"
    _plant(target, 0o5755)
    os.link(target, other)
    assert os.lstat(target).st_nlink == 2
    expected = _default_mode(tmp_path)

    with fs_guard.open_for_atomic_write(target) as handle:
        handle.write("written\n")

    assert target.read_text() == "written\n"
    assert _mode(target) == expected, (oct(_mode(target)), oct(expected))
    assert not os.lstat(target).st_mode & (stat.S_ISUID | stat.S_ISVTX)
    assert os.lstat(target).st_nlink == 1
    assert other.read_bytes() == b"planted\n"
    assert _mode(other) == 0o5755, oct(_mode(other))
    assert os.lstat(other).st_nlink == 1


def test_the_mode_of_a_file_the_caller_owns_is_copied(where):
    """The control for the next test: the same write, the owner unchanged."""
    target = where / "report.json"
    _plant(target, 0o755)

    with fs_guard.open_for_atomic_write(target) as handle:
        handle.write("written\n")

    assert target.read_text() == "written\n"
    assert _mode(target) == 0o755, oct(_mode(target))


@pytest.fixture
def umask_022():
    """The umask a host user's shell and most containers run with."""
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


def test_a_file_owned_by_another_user_keeps_its_mode_on_the_new_file(
    where, monkeypatch
):
    """Re-pinned from test_a_file_owned_by_another_user_lends_the_new_file_no_mode,
    which asserted the opposite (the new file took the umask default). A root or
    container run rewriting a host user's results file keeps the file's bits: the
    new file never ends wider than the one it replaced. The file's owner is made to
    differ from the process's by patching ``geteuid``."""
    target = where / "report.json"
    _plant(target, 0o755)
    owner = os.lstat(target).st_uid
    monkeypatch.setattr(fs_guard.os, "geteuid", lambda: owner + 1)

    with fs_guard.open_for_atomic_write(target) as handle:
        handle.write("written\n")

    assert target.read_text() == "written\n"
    assert _mode(target) == 0o755, oct(_mode(target))


def test_a_private_file_of_another_user_stays_private_under_umask_022(
    where, monkeypatch, umask_022
):
    """The reported case: a 0o600 results file, rewritten by a process that is not
    its owner (root, a container) under umask 022, came back 0o644 and readable by
    everyone. It stays 0o600. Control: the same write with the owner unchanged
    (the test below) and a name with no file (the one after it)."""
    target = where / "report.json"
    _plant(target, 0o600)
    owner = os.lstat(target).st_uid
    monkeypatch.setattr(fs_guard.os, "geteuid", lambda: owner + 1)

    with fs_guard.open_for_atomic_write(target) as handle:
        handle.write("written\n")

    assert target.read_text() == "written\n"
    assert _mode(target) == 0o600, oct(_mode(target))


def test_a_private_file_of_the_caller_stays_private_under_umask_022(where, umask_022):
    """The control for the test above: the owner unchanged."""
    target = where / "report.json"
    _plant(target, 0o600)

    with fs_guard.open_for_atomic_write(target) as handle:
        handle.write("written\n")

    assert target.read_text() == "written\n"
    assert _mode(target) == 0o600, oct(_mode(target))


def test_a_name_with_no_file_gets_the_umask_default_whoever_the_process_is(
    where, monkeypatch, umask_022
):
    """A new file keeps today's default: nothing is borrowed when there is no file
    to borrow from, so the mode is 0o644 under umask 022 (0o666 less the mask)."""
    target = where / "report.json"
    monkeypatch.setattr(fs_guard.os, "geteuid", lambda: os.getuid() + 1)

    with fs_guard.open_for_atomic_write(target) as handle:
        handle.write("written\n")

    assert target.read_text() == "written\n"
    assert _mode(target) == 0o644, oct(_mode(target))


def test_the_ownership_of_the_file_replaced_is_not_changed_to_follow(
    where, monkeypatch
):
    """Only the permission bits follow the old file: the writer makes no ownership
    call (the new file is the process's own), so a rewrite is not a chown."""
    target = where / "report.json"
    _plant(target, 0o600)
    owner = os.lstat(target).st_uid
    monkeypatch.setattr(fs_guard.os, "geteuid", lambda: owner + 1)
    chowned = []
    for name in ("fchown", "chown", "lchown"):
        if hasattr(os, name):
            monkeypatch.setattr(
                fs_guard.os, name, lambda *args, **kwargs: chowned.append(args)
            )

    with fs_guard.open_for_atomic_write(target) as handle:
        handle.write("written\n")

    assert chowned == []
    assert os.lstat(target).st_uid == owner


def test_a_filesystem_that_refuses_the_mode_change_keeps_the_write(where, monkeypatch):
    """FUSE and SMB mounts refuse fchmod. The mode is a courtesy to the file's
    owner; losing it must not fail the scan's results write."""
    target = where / "report.json"
    _plant(target, 0o755)

    def refuse(fd, mode):
        raise PermissionError(errno.EPERM, "the filesystem refuses a mode change")

    monkeypatch.setattr(fs_guard.os, "fchmod", refuse)

    with fs_guard.open_for_atomic_write(target) as handle:
        handle.write("written\n")

    assert target.read_text() == "written\n"
    assert [p.name for p in where.iterdir() if p.name != "report.json"] == []


def test_a_staging_file_that_cannot_be_removed_leaves_the_write_error_in_place(
    where, monkeypatch
):
    """The rename fails and so does the cleanup (Windows, for a staging file made
    read-only). The error raised is the rename's, not the cleanup's."""
    target = where / "report.json"

    def failing_replace(*args, **kwargs):
        raise OSError(errno.EIO, "the rename failed")

    def failing_unlink(*args, **kwargs):
        raise PermissionError(errno.EACCES, "the removal failed")

    monkeypatch.setattr(fs_guard.os, "replace", failing_replace)
    monkeypatch.setattr(fs_guard.os, "unlink", failing_unlink)

    with pytest.raises(OSError, match="the rename failed"):
        with fs_guard.open_for_atomic_write(target) as handle:
            handle.write("written\n")
