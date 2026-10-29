# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Landlock wrapper's walk of its process tree is bounded.

utils/sandbox/landlock_exec.py reaps what a scanner left behind by walking its
descendants through /proc. Before these tests, any failure to read a thread's
children file (a descendant that exited between the listing and the read, a file
this process may not read) fell back to a listing of every /proc entry, once per
descendant, with no bound, so one reap pass could outlast the quarter second a
stopped wrapper has before ASH kills it.

Everything here runs in-process against a stand-in /proc: no fork, no sandbox.
"""

import errno
import io
import os
import sys
import types
from typing import Dict, List, Union

import pytest

# The wrapper binds libc at import (ctypes.CDLL(None)), which Windows rejects, so the
# module is skipped before the import, as test_sandbox_socket_filter.py does.
if sys.platform != "linux":
    pytest.skip("the wrapper uses prctl and /proc, Linux only", allow_module_level=True)

from automated_security_helper.utils.sandbox import landlock_exec  # noqa: E402

pytestmark = pytest.mark.unit

#: The pid the stand-in gives the wrapper.
ME = 1000

Entry = Union[bytes, List[str], BaseException]


class _Procfs:
    """A /proc made of a dict: bytes are files, lists are directories, an exception
    is what reading that path raises; a path with no entry does not exist."""

    def __init__(self, files: Dict[str, Entry]):
        self.files = files
        self.listed: List[str] = []
        self.opened: List[str] = []

    def listdir(self, path: str) -> List[str]:
        self.listed.append(path)
        entry = self.files.get(path)
        if isinstance(entry, list):
            return list(entry)
        if isinstance(entry, BaseException):
            raise entry
        raise FileNotFoundError(errno.ENOENT, "no such directory", path)

    def isdir(self, path: str) -> bool:
        return isinstance(self.files.get(path), list)

    def open(self, path: str, mode: str = "rb") -> io.BytesIO:
        self.opened.append(path)
        entry = self.files.get(path)
        if isinstance(entry, bytes):
            return io.BytesIO(entry)
        if isinstance(entry, BaseException):
            raise entry
        raise FileNotFoundError(errno.ENOENT, "no such file", path)


class _Os:
    """The os module with its /proc reads routed to the stand-in."""

    def __init__(self, proc: _Procfs):
        self.listdir = proc.listdir
        self.path = types.SimpleNamespace(isdir=proc.isdir)

    @staticmethod
    def getpid() -> int:
        return ME

    def __getattr__(self, name: str):
        return getattr(os, name)


@pytest.fixture
def procfs(monkeypatch):
    """Install a stand-in /proc for the wrapper and return it."""

    def install(files: Dict[str, Entry]) -> _Procfs:
        proc = _Procfs(files)
        monkeypatch.setattr(landlock_exec, "os", _Os(proc))
        monkeypatch.setattr(landlock_exec, "open", proc.open, raising=False)
        return proc

    return install


def _stat(pid: int, ppid: int) -> bytes:
    """What /proc/<pid>/stat reads: the pid, the name in parentheses, the state,
    then the parent pid."""
    return b"%d (scanner) S %d 1 1 0 -1 0 0" % (pid, ppid)


def _task(pid: Union[int, str]) -> str:
    return f"/proc/{pid}/task"


def _children_file(pid: Union[int, str], tid: Union[int, str]) -> str:
    return f"{_task(pid)}/{tid}/children"


def test_a_thread_whose_children_file_cannot_be_read_gives_what_was_read(procfs):
    """A permission error on one thread's file is not a reason to list /proc."""
    proc = procfs(
        {
            _task("self"): ["1", "2", "3"],
            _children_file("self", 1): b"11 12",
            _children_file("self", 2): PermissionError(errno.EACCES, "denied"),
            _children_file("self", 3): b"13",
        }
    )

    assert landlock_exec._children() == [11, 12]
    assert "/proc" not in proc.listed


def test_a_descendant_that_exited_before_its_read_has_no_children(procfs):
    """The walk reaches a pid whose /proc entry is already gone: nothing to reap
    below it, and no listing of /proc to find out."""
    proc = procfs({_task(4242): FileNotFoundError(errno.ENOENT, "gone")})

    assert landlock_exec._children(4242) == []
    assert "/proc" not in proc.listed


def test_a_kernel_without_children_files_lists_proc_up_to_the_cap(procfs, monkeypatch):
    """The thread is there and has no children file: the fallback lists /proc, and
    reads no more entries than PROC_SCAN_LIMIT allows."""
    monkeypatch.setattr(landlock_exec, "PROC_SCAN_LIMIT", 3)
    files: Dict[str, Entry] = {
        _task("self"): ["7"],
        f"{_task('self')}/7": [],
        "/proc": ["1", "2", "3", "4", "5", "6", "self", "meminfo"],
    }
    for pid in range(1, 7):
        files[f"/proc/{pid}/stat"] = _stat(pid, ME)
    proc = procfs(files)

    assert landlock_exec._children() == [1, 2, 3]
    stat_reads = [path for path in proc.opened if path.endswith("/stat")]
    assert len(stat_reads) == 3
    assert proc.listed.count("/proc") == 1


def test_a_three_level_tree_lists_proc_once_without_children_files(procfs):
    """The whole walk shares one listing of /proc, not one per descendant."""
    proc = procfs(
        {
            _task("self"): ["7"],
            f"{_task('self')}/7": [],
            "/proc": ["1", str(ME), "101", "201", "301", "self"],
            "/proc/1/stat": _stat(1, 0),
            f"/proc/{ME}/stat": _stat(ME, 1),
            "/proc/101/stat": _stat(101, ME),
            "/proc/201/stat": _stat(201, 101),
            "/proc/301/stat": _stat(301, 201),
        }
    )

    assert landlock_exec._descendants() == [101, 201, 301]
    assert proc.listed.count("/proc") == 1


def _three_levels() -> Dict[str, Entry]:
    """Children files for this process -> 11 -> 21 -> 31."""
    files: Dict[str, Entry] = {
        _task("self"): ["1"],
        _children_file("self", 1): b"11",
    }
    for pid, child in ((11, b"21"), (21, b"31"), (31, b"")):
        files[_task(pid)] = [str(pid)]
        files[_children_file(pid, pid)] = child
    return files


def test_a_walk_past_its_deadline_returns_what_it_has_found(procfs, monkeypatch):
    """The reap pass hands the walk its deadline; past it, the walk stops reading
    and the pass kills what it found, so the pass ends inside the deadline."""
    proc = procfs(_three_levels())
    monkeypatch.setattr(
        landlock_exec, "time", types.SimpleNamespace(monotonic=lambda: 10.0)
    )

    assert landlock_exec._descendants(until=5.0) == [11]
    assert _children_file(11, 11) not in proc.opened


def test_a_walk_inside_its_deadline_reads_the_whole_tree(procfs, monkeypatch):
    """Control: with time to spare, and with no deadline, every level is read."""
    procfs(_three_levels())
    monkeypatch.setattr(
        landlock_exec, "time", types.SimpleNamespace(monotonic=lambda: 10.0)
    )

    assert landlock_exec._descendants(until=20.0) == [11, 21, 31]
    assert landlock_exec._descendants() == [11, 21, 31]
