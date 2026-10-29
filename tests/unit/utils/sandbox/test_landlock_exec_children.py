# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Landlock wrapper's walk of its process tree is bounded, and its child ends
with the wrapper.

utils/sandbox/landlock_exec.py reaps what a scanner left behind by walking its
descendants through /proc. Before these tests, any failure to read a thread's
children file (a descendant that exited between the listing and the read, a file
this process may not read) fell back to a listing of every /proc entry, once per
descendant, with no bound, so one reap pass could outlast the quarter second a
stopped wrapper has before ASH kills it. And the forked child asked the kernel for
nothing on its parent's death, so a wrapper killed mid-reap left the scanner
running with no reaper, and it kept the SIGPIPE and SIGXFSZ dispositions the
interpreter ignores, unlike the same scanner started unwrapped.

Everything here runs in-process against a stand-in /proc: no fork, no sandbox.
"""

import errno
import io
import os
import signal
import sys
import types
from typing import Dict, List, Tuple, Union

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


class _Recording:
    """A module whose named functions record their calls and return ``returns``;
    every other attribute is the real module's."""

    def __init__(self, real, names, calls: List[Tuple[str, tuple]], returns=0):
        self._real = real
        self._names = frozenset(names)
        self._calls = calls
        self._returns = returns

    def __getattr__(self, name: str):
        if name in self._names:

            def record(*args):
                self._calls.append((name, args))
                return self._returns

            return record
        return getattr(self._real, name)


@pytest.fixture
def child_calls(monkeypatch):
    """Run the child's setup with its system calls recorded; return the calls."""

    def run(prctl_returns: int = 0) -> List[Tuple[str, tuple]]:
        calls: List[Tuple[str, tuple]] = []
        monkeypatch.setattr(landlock_exec, "os", _Recording(os, {"setsid"}, calls))
        monkeypatch.setattr(
            landlock_exec,
            "signal",
            _Recording(signal, {"pthread_sigmask", "signal"}, calls),
        )
        monkeypatch.setattr(
            landlock_exec,
            "libc",
            _Recording(None, {"prctl"}, calls, returns=prctl_returns),
        )
        landlock_exec._child_setup(lambda: calls.append(("restrict", ())))
        return calls

    return run


def test_the_child_asks_for_sigterm_on_its_parents_exit_between_setsid_and_restrict(
    child_calls,
):
    calls = child_calls()
    names = [name for name, _ in calls]

    assert names.index("setsid") < names.index("prctl") < names.index("restrict")
    (prctl_args,) = [args for name, args in calls if name == "prctl"]
    assert prctl_args == (landlock_exec.PR_SET_PDEATHSIG, int(signal.SIGTERM), 0, 0, 0)
    assert landlock_exec.PR_SET_PDEATHSIG == 1
    assert names[0] == "pthread_sigmask"
    assert calls[0][1][0] == signal.SIG_UNBLOCK
    assert set(calls[0][1][1]) == {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}


def test_the_child_restores_the_dispositions_the_interpreter_ignores(child_calls):
    """SIGPIPE and SIGXFSZ go back to their defaults before the exec, as
    subprocess does for every child it starts."""
    calls = child_calls()
    names = [name for name, _ in calls]
    restored = {args for name, args in calls if name == "signal"}

    assert restored == {
        (signal.SIGPIPE, signal.SIG_DFL),
        (signal.SIGXFSZ, signal.SIG_DFL),
    }
    assert max(i for i, name in enumerate(names) if name == "signal") < names.index(
        "restrict"
    )


def test_a_refused_parent_death_signal_is_noted_and_the_child_goes_on(
    child_calls, capsys
):
    """The parent-death signal is best effort: the child says so and is still
    restricted and exec'd."""
    calls = child_calls(prctl_returns=-1)

    assert ("restrict", ()) == calls[-1]
    noted = capsys.readouterr().err
    assert "prctl(PR_SET_PDEATHSIG)" in noted
    assert noted.startswith("ash-landlock: ")


def test_the_socket_filter_route_restores_the_dispositions_before_its_exec(
    monkeypatch,
):
    """The bwrap and firejail route execs in place, with no fork; it resets
    SIGPIPE and SIGXFSZ too, last before the exec."""
    calls: List[Tuple[str, tuple]] = []
    monkeypatch.setattr(landlock_exec, "os", _Recording(os, {"execvp"}, calls))
    monkeypatch.setattr(landlock_exec, "signal", _Recording(signal, {"signal"}, calls))
    monkeypatch.setattr(landlock_exec, "libc", _Recording(None, {"prctl"}, calls))
    monkeypatch.setattr(
        landlock_exec,
        "apply_socket_seccomp",
        lambda allow_ip: calls.append(("apply_socket_seccomp", (allow_ip,))),
    )

    landlock_exec.exec_with_socket_filter(True, ["/bin/true"])

    names = [name for name, _ in calls]
    assert names[-1] == "execvp"
    assert names[-3:-1] == ["signal", "signal"]
    assert {args for name, args in calls if name == "signal"} == {
        (signal.SIGPIPE, signal.SIG_DFL),
        (signal.SIGXFSZ, signal.SIG_DFL),
    }
    assert names.index("apply_socket_seccomp") < names.index("signal")


def test_a_late_pass_without_children_files_still_reads_the_direct_children(
    procfs, monkeypatch
):
    """The deadline is already behind when the walk starts and the kernel has no
    children files: the one listing of /proc still happens, so the scanner's own
    children are found and killed; only the deeper levels are left."""
    procfs(
        {
            _task("self"): ["7"],
            f"{_task('self')}/7": [],
            "/proc": ["1", str(ME), "101", "201", "self"],
            "/proc/1/stat": _stat(1, 0),
            f"/proc/{ME}/stat": _stat(ME, 1),
            "/proc/101/stat": _stat(101, ME),
            "/proc/201/stat": _stat(201, 101),
        }
    )
    monkeypatch.setattr(
        landlock_exec, "time", types.SimpleNamespace(monotonic=lambda: 10.0)
    )

    assert landlock_exec._descendants(until=5.0) == [101]
