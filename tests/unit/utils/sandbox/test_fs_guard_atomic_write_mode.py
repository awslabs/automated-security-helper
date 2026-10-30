# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The atomic writer copies only the permission bits a results file should have.

open_for_atomic_write gives its staging file the mode of the regular file already
at the target name, so a 0o600 report is not replaced by a 0o644 one. It copied
the whole mode, so an entry a scanner put at the name handed its setuid, setgid
or sticky bit to the results file, and a hard-linked entry (a file another name
refers to, which the writer deliberately spares) handed over its mode as well.
Only the read, write and execute bits are copied now, and only from a file no
other name refers to; a hard-linked entry leaves the new file at its
umask-derived mode.
"""

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


def test_a_setuid_bit_at_the_name_is_not_carried_onto_the_new_file(tmp_path):
    target = tmp_path / "report.json"
    _plant(target, 0o4755)

    with fs_guard.open_for_atomic_write(target) as handle:
        handle.write("written\n")

    assert target.read_text() == "written\n"
    assert _mode(target) == 0o755, oct(_mode(target))
    assert not os.lstat(target).st_mode & stat.S_ISUID


def test_a_hard_linked_file_at_the_name_lends_the_new_file_no_mode(tmp_path):
    """The writer spares the file the other name refers to; it also takes no
    mode from it. The new file has the mode a fresh file gets, and the other
    name keeps its bytes and its whole mode, setuid bit included."""
    target = tmp_path / "report.json"
    other = tmp_path / "other-name"
    _plant(target, 0o4755)
    os.link(target, other)
    assert os.lstat(target).st_nlink == 2
    expected = _default_mode(tmp_path)

    with fs_guard.open_for_atomic_write(target) as handle:
        handle.write("written\n")

    assert target.read_text() == "written\n"
    assert _mode(target) == expected, (oct(_mode(target)), oct(expected))
    assert not os.lstat(target).st_mode & stat.S_ISUID
    assert os.lstat(target).st_nlink == 1
    assert other.read_bytes() == b"planted\n"
    assert _mode(other) == 0o4755, oct(_mode(other))
    assert os.lstat(other).st_nlink == 1
