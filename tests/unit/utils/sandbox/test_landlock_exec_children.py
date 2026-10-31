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
import json
import os
import signal
import sys
import types
from typing import Callable, Dict, List, Optional, Tuple, Union

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


#: The calls the stand-ins below never hand on to the real module. Their /proc is
#: made up, so a pid in it (4242, 21, 31) is the number of whatever process the host
#: happens to run under it: a test that reached one of these with such a pid would
#: signal or pin that process. A test that expects the call stubs it on the stand-in.
_SIGNALLING = {
    os: ("kill", "killpg", "pidfd_open", "pidfd_send_signal"),
    signal: ("pidfd_send_signal", "raise_signal", "pthread_kill"),
}


def _refuse_real_signalling(real: object, name: str) -> None:
    """Raise when ``name`` is a call that signals or pins a process of the host."""
    if name in _SIGNALLING.get(real, ()):
        raise AssertionError(
            f"{real.__name__}.{name} would reach the real module; stub it in the test"
        )


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
        assert mode == "rb", f"the stand-in /proc is read, not opened with {mode!r}"
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
        # A path with an entry exists, whatever reading it does.
        self.path = types.SimpleNamespace(
            isdir=proc.isdir, exists=lambda path: path in proc.files
        )

    @staticmethod
    def getpid() -> int:
        return ME

    def __getattr__(self, name: str):
        _refuse_real_signalling(os, name)
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


def test_a_thread_whose_children_file_cannot_be_read_is_skipped(procfs):
    """A permission error on one thread's file is not a reason to list /proc, and
    the threads after it still have their children read."""
    proc = procfs(
        {
            _task("self"): ["1", "2", "3"],
            _children_file("self", 1): b"11 12",
            _children_file("self", 2): PermissionError(errno.EACCES, "denied"),
            _children_file("self", 3): b"13",
        }
    )

    assert landlock_exec._children_files() == [11, 12, 13]
    assert "/proc" not in proc.listed


def test_a_thread_that_exited_between_the_listing_and_the_read_is_skipped(procfs):
    """The first thread's files are gone (no thread dir left) while a later
    thread has children: those are read, and the kernel is not taken to lack
    children files."""
    proc = procfs(
        {
            _task("self"): ["1", "2"],
            _children_file("self", 2): b"12",
        }
    )

    assert landlock_exec._children_files() == [12]
    assert "/proc" not in proc.listed


def test_a_descendant_that_exited_before_its_read_has_no_children(procfs):
    """The walk reaches a pid whose /proc entry is already gone: nothing to reap
    below it, and no listing of /proc to find out."""
    proc = procfs({_task(4242): FileNotFoundError(errno.ENOENT, "gone")})

    assert landlock_exec._children_files(4242) == []
    assert "/proc" not in proc.listed


def test_an_unreadable_task_list_of_the_wrapper_itself_falls_back_to_proc(
    procfs, capsys
):
    """The wrapper cannot be gone, so its own task list failing to read means
    /proc is not readable that way: it says so and the walk lists /proc, where
    the scanner's children are still found."""
    proc = procfs(
        {
            _task("self"): PermissionError(errno.EACCES, "denied"),
            "/proc": ["1", str(ME), "101", "self"],
            "/proc/1/stat": _stat(1, 0),
            f"/proc/{ME}/stat": _stat(ME, 1),
            "/proc/101/stat": _stat(101, ME),
        }
    )

    assert landlock_exec._children_files() is None
    assert landlock_exec._descendants() == [101]
    assert proc.listed.count("/proc") == 1
    noted = capsys.readouterr().err
    assert "ash-landlock: cannot read /proc/self/task" in noted


def test_an_unreadable_proc_is_said_rather_than_read_as_an_empty_tree(procfs, capsys):
    """With /proc itself unreadable the walk can find nothing, and it says so
    instead of reporting a tree with nothing left in it."""
    procfs(
        {
            _task("self"): PermissionError(errno.EACCES, "denied"),
            "/proc": PermissionError(errno.EACCES, "denied"),
        }
    )

    assert landlock_exec._descendants() == []
    noted = capsys.readouterr().err
    assert "cannot list /proc" in noted
    assert "nothing the scanner left can be found or ended" in noted


def test_a_kernel_without_children_files_lists_proc_up_to_the_cap(procfs, monkeypatch):
    """The thread is there and has no children file: the fallback lists /proc, and
    a walk with no deadline (the first reap pass) reads no more entries than
    PROC_SCAN_LIMIT allows."""
    monkeypatch.setattr(landlock_exec, "PROC_SCAN_LIMIT", 3)
    files: Dict[str, Entry] = {
        _task("self"): ["7"],
        f"{_task('self')}/7": [],
        "/proc": ["1", "2", "3", "4", "5", "6", "self", "meminfo"],
    }
    for pid in range(1, 7):
        files[f"/proc/{pid}/stat"] = _stat(pid, ME)
    proc = procfs(files)

    assert landlock_exec._descendants() == [1, 2, 3]
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


def test_descendants_with_the_highest_pids_are_read_before_the_cap_is_met(
    procfs, monkeypatch
):
    """The wrapper's descendants were forked after it and carry the highest pids;
    a bounded scan that read /proc in ascending order would spend its cap on
    older processes and find none of them. The scan starts just above this
    process and wraps around."""
    monkeypatch.setattr(landlock_exec, "PROC_SCAN_LIMIT", 3)
    files: Dict[str, Entry] = {
        _task("self"): ["7"],
        f"{_task('self')}/7": [],
        "/proc": ["1", "2", "3", "4", "5", str(ME), "1001", "2002", "self"],
        f"/proc/{ME}/stat": _stat(ME, 1),
        "/proc/1001/stat": _stat(1001, ME),
        "/proc/2002/stat": _stat(2002, 1001),
    }
    for pid in range(1, 6):
        files[f"/proc/{pid}/stat"] = _stat(pid, 1)
    proc = procfs(files)

    assert landlock_exec._descendants() == [1001, 2002]
    read = [path for path in proc.opened if path.endswith("/stat")]
    assert read == ["/proc/1001/stat", "/proc/2002/stat", "/proc/1/stat"]


def test_a_scan_with_a_deadline_is_bounded_by_the_deadline_not_the_cap(
    procfs, monkeypatch
):
    """With a deadline to honor, the entry cap is a floor, not a ceiling: a scan
    with time left reads every entry."""
    monkeypatch.setattr(landlock_exec, "PROC_SCAN_LIMIT", 1)
    monkeypatch.setattr(
        landlock_exec, "time", types.SimpleNamespace(monotonic=lambda: 10.0)
    )
    files: Dict[str, Entry] = {"/proc": ["1", "2", "3", "4", "self"]}
    for pid in range(1, 5):
        files[f"/proc/{pid}/stat"] = _stat(pid, ME)
    procfs(files)

    assert landlock_exec._parent_map(until=lambda: 20.0) == {ME: [1, 2, 3, 4]}


def test_a_walk_with_time_left_is_not_capped_on_a_kernel_without_children_files(
    procfs, monkeypatch
):
    """The whole walk on the fallback path reads the one listing it is handed:
    with time left, that listing goes past PROC_SCAN_LIMIT, so a descendant
    listed after the cap (a host with more processes than the cap, or a pid
    wraparound that put the tree below the wrapper's pid) is still found."""
    monkeypatch.setattr(landlock_exec, "PROC_SCAN_LIMIT", 2)
    monkeypatch.setattr(
        landlock_exec, "time", types.SimpleNamespace(monotonic=lambda: 10.0)
    )
    files: Dict[str, Entry] = {
        _task("self"): ["7"],
        f"{_task('self')}/7": [],
        "/proc": ["1", "2", "3", str(ME), "1001", "2002", "3003", "self"],
        f"/proc/{ME}/stat": _stat(ME, 1),
        "/proc/1001/stat": _stat(1001, ME),
        "/proc/2002/stat": _stat(2002, 1001),
        "/proc/3003/stat": _stat(3003, 2002),
    }
    for pid in range(1, 4):
        files[f"/proc/{pid}/stat"] = _stat(pid, 1)
    proc = procfs(files)

    assert landlock_exec._descendants(until=lambda: 20.0) == [1001, 2002, 3003]
    assert proc.listed.count("/proc") == 1
    # Control: with no deadline the same walk stops at the cap.
    assert landlock_exec._descendants() == [1001, 2002]


def test_a_live_descendant_whose_stat_cannot_be_read_is_left_alone_and_named(
    procfs, capsys
):
    """The kill first reads the pid's parent to be sure it is still the scanner's;
    a process that is there but whose stat cannot be read is not killed (the
    reused-pid guard) and one stderr line names it."""
    procfs(
        {
            "/proc/4242": [],
            "/proc/4242/stat": PermissionError(errno.EACCES, "denied"),
        }
    )

    assert landlock_exec._kill_descendant(4242, {ME}) is False
    noted = capsys.readouterr().err
    assert "4242" in noted
    assert noted.startswith("ash-landlock: could not read the parent of process")


@pytest.fixture
def pidfd_refused(monkeypatch):
    """Run ``_kill_descendant`` on a pid whose parent is the wrapper, with
    ``pidfd_open`` raising the given errno and the kill by number recorded."""

    def run(code: int) -> List[Tuple[str, tuple]]:
        calls: List[Tuple[str, tuple]] = []
        fake_os = _Recording(os, {"kill"}, calls)

        def refuse(pid):
            raise OSError(code, os.strerror(code))

        fake_os.pidfd_open = refuse
        monkeypatch.setattr(landlock_exec, "os", fake_os)
        monkeypatch.setattr(landlock_exec, "_parent_pid", lambda pid: ME)
        sent = landlock_exec._kill_descendant(4242, {ME})
        calls.append(("returned", (sent,)))
        return calls

    return run


def test_a_refused_pidfd_pin_falls_back_to_the_kill_by_number(pidfd_refused):
    """pidfd_open refused by the kernel (ENOSYS or EPERM under a seccomp profile,
    EMFILE) is not "the process is gone": the descendant is still the scanner's
    and is killed by number, as on a kernel without the call. Each refusal here
    is the stand-in raising the errno, the EMFILE row included: the wrapper is not
    run out of descriptors, and the parent read that follows is the stand-in's."""
    for code in (errno.ENOSYS, errno.EPERM, errno.EMFILE):
        calls = pidfd_refused(code)

        assert ("kill", (4242, signal.SIGKILL)) in calls
        assert calls[-1] == ("returned", (True,))


def test_a_pidfd_pin_of_a_gone_process_sends_nothing(pidfd_refused):
    """ESRCH from pidfd_open is the one answer that means gone: no kill."""
    calls = pidfd_refused(errno.ESRCH)

    assert calls == [("returned", (False,))]


def test_a_descendant_that_is_gone_is_skipped_in_silence(procfs, capsys):
    """The common case, a pid that exited between the listing and the kill, says
    nothing."""
    procfs({})

    assert landlock_exec._kill_descendant(4242, {ME}) is False
    assert capsys.readouterr().err == ""


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

    assert landlock_exec._descendants(until=lambda: 5.0) == [11]
    assert _children_file(11, 11) not in proc.opened


def test_a_stop_during_a_walk_moves_its_deadline(procfs, monkeypatch):
    """The deadline is asked again before every read, not once per pass: a stop
    that lands mid-walk (the deadline moves from far off to already past) ends the
    walk at the next read."""
    proc = procfs(_three_levels())
    monkeypatch.setattr(
        landlock_exec, "time", types.SimpleNamespace(monotonic=lambda: 10.0)
    )
    asked: List[int] = []

    def deadline() -> float:
        asked.append(1)
        return 20.0 if len(asked) == 1 else 5.0

    assert landlock_exec._descendants(until=deadline) == [11, 21]
    assert len(asked) >= 2
    assert _children_file(21, 21) not in proc.opened


def test_a_walk_inside_its_deadline_reads_the_whole_tree(procfs, monkeypatch):
    """Control: with time to spare, and with no deadline, every level is read."""
    procfs(_three_levels())
    monkeypatch.setattr(
        landlock_exec, "time", types.SimpleNamespace(monotonic=lambda: 10.0)
    )

    assert landlock_exec._descendants(until=lambda: 20.0) == [11, 21, 31]
    assert landlock_exec._descendants() == [11, 21, 31]


@pytest.fixture
def reap_calls(monkeypatch):
    """Run ``_reap_leftovers`` with the walk, the kills and the clock stood in for.

    The walk returns the given leftovers lists in turn, then empty lists; the
    arguments each walk was called with and every kill are recorded. The pids in
    ``still_present`` are the ones whose stat the survivors check still reads.
    """

    def run(deadline_value: float, leftovers: List[List[int]], still_present=()):
        walks: List[object] = []
        kills: List[int] = []
        remaining = list(leftovers)

        def walk(until=None):
            walks.append(until)
            return remaining.pop(0) if remaining else []

        def kill(pid, tree):
            kills.append(pid)
            return True

        fake_os = _Recording(os, set(), [])
        fake_os.waitpid = lambda pid, options: (0, 0)
        monkeypatch.setattr(landlock_exec, "_descendants", walk)
        monkeypatch.setattr(landlock_exec, "_kill_descendant", kill)
        monkeypatch.setattr(
            landlock_exec,
            "_parent_pid",
            lambda pid: ME if pid in still_present else None,
        )
        monkeypatch.setattr(landlock_exec, "os", fake_os)
        monkeypatch.setattr(
            landlock_exec,
            "time",
            types.SimpleNamespace(monotonic=lambda: 10.0, sleep=lambda seconds: None),
        )
        deadline = lambda: deadline_value  # noqa: E731 - the callable under test
        survivors = landlock_exec._reap_leftovers(deadline)
        return walks, kills, deadline, survivors

    return run


def test_the_first_reap_pass_walks_the_whole_tree_when_the_deadline_is_behind(
    reap_calls,
):
    """A stop that left the scanner's exit past the deadline still gets one
    complete pass: the walk is not given the deadline, and what it finds is
    killed; no second pass and no second walk follow. The survivors reported are
    the pids of that pass whose stat can still be read after its kills, here
    none, not the pids the pass already ended."""
    walks, kills, deadline, survivors = reap_calls(5.0, [[11, 21, 31]])

    assert walks == [None]
    assert kills == [11, 21, 31]
    assert survivors == []


def test_pids_still_present_after_the_last_kill_pass_are_the_survivors(reap_calls):
    """A pid of the last pass that is still there after its kills is reported,
    the ones the pass ended are not; the check reads each such pid's stat, never
    /proc as a whole, so it ends inside the stop's grace on any kernel."""
    walks, kills, deadline, survivors = reap_calls(5.0, [[11, 21]], still_present={21})

    assert walks == [None]
    assert kills == [11, 21]
    assert survivors == [21]


def test_later_reap_passes_carry_the_deadline(reap_calls):
    """With time left, the passes after the first are bounded by the deadline
    they are handed, and the loop ends once five passes find nothing."""
    walks, kills, deadline, survivors = reap_calls(20.0, [[11], [21]])

    assert walks[0] is None
    assert walks[1:] and all(until is deadline for until in walks[1:])
    assert kills == [11, 21]
    assert len(walks) == 2 + 5
    assert survivors == []


def test_a_child_reaped_only_after_the_last_pass_is_not_a_survivor(monkeypatch):
    """A SIGKILLed child becomes reapable a moment after the kill, so the pass's
    own sweep, run right after its kills, can miss it, and a zombie is still
    listed in /proc: the re-read that names the survivors is preceded by one
    more sweep, and a child collected there is not reported."""
    present = {11}
    signalled: List[int] = []
    reapable: List[int] = []

    def walk(until=None):
        return sorted(present)

    def kill(pid, tree):
        signalled.append(pid)
        return True

    def waitpid(pid, options):
        if reapable:
            reaped = reapable.pop(0)
            present.discard(reaped)
            return (reaped, 0)
        # The signal lands between two calls: reapable from the next one on.
        reapable.extend(signalled)
        signalled.clear()
        return (0, 0)

    fake_os = _Recording(os, set(), [])
    fake_os.waitpid = waitpid
    monkeypatch.setattr(landlock_exec, "_descendants", walk)
    monkeypatch.setattr(landlock_exec, "_kill_descendant", kill)
    monkeypatch.setattr(
        landlock_exec, "_parent_pid", lambda pid: ME if pid in present else None
    )
    monkeypatch.setattr(landlock_exec, "os", fake_os)
    monkeypatch.setattr(
        landlock_exec,
        "time",
        types.SimpleNamespace(monotonic=lambda: 10.0, sleep=lambda seconds: None),
    )

    assert landlock_exec._reap_leftovers(lambda: 5.0) == []
    assert present == set()


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
        _refuse_real_signalling(self._real, name)
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


@pytest.fixture
def child_run(monkeypatch):
    """Run ``_run_child`` with the setup, the exec and the exit stood in for.

    Returns the recorded calls: the setup's restrict, ``os.execve`` and
    ``os._exit`` in the order the child made them. ``parent`` is the wrapper's pid
    as the child would have read it before the fork. ``setup`` runs inside the
    stood-in setup and ``execve`` inside the stood-in exec, each after its call is
    recorded, so a test can make either raise.
    """

    def run(
        parent: Optional[int],
        setup: Optional[Callable[[], None]] = None,
        execve: Optional[Callable[[], None]] = None,
    ) -> List[Tuple[str, tuple]]:
        calls: List[Tuple[str, tuple]] = []

        def stood_in_setup(restrict) -> None:
            calls.append(("setup", ()))
            if setup is not None:
                setup()

        monkeypatch.setattr(landlock_exec, "_child_setup", stood_in_setup)
        fake_os = _Recording(os, {"execve", "_exit"}, calls)
        if execve is not None:

            def stood_in_execve(*args) -> None:
                calls.append(("execve", args))
                execve()

            fake_os.execve = stood_in_execve
        monkeypatch.setattr(landlock_exec, "os", fake_os)
        landlock_exec._run_child(["/bin/true"], lambda: None, parent)
        return calls

    return run


def _raise(exc: BaseException) -> Callable[[], None]:
    def raiser() -> None:
        raise exc

    return raiser


def test_an_exec_refused_for_its_environment_still_exits_126(child_run, capsys):
    """os.execve raises ValueError, not OSError, for an environment with an empty
    variable name (ASH's env dict holding ""): the child reports the failed exec
    with the scanner's path and exits 126, never with the interpreter's
    traceback and exit 1, which scanners use for "findings found"."""
    calls = child_run(
        parent=os.getppid(),
        execve=_raise(ValueError("illegal environment variable name")),
    )

    assert calls[-1] == ("_exit", (126,))
    noted = capsys.readouterr().err
    assert "ash-landlock: exec /bin/true: illegal environment variable name" in noted


def test_a_stop_that_lands_during_the_setup_is_reported_as_a_stop(child_run, capsys):
    """A stop signal forwarded to the child before its exec raises
    KeyboardInterrupt there: a stop, not a restriction that failed."""
    calls = child_run(parent=os.getppid(), setup=_raise(KeyboardInterrupt()))

    assert calls[-1] == ("_exit", (126,))
    noted = capsys.readouterr().err
    assert "stopped before the scanner started" in noted
    assert "restricting the scanner" not in noted


def test_a_stop_that_lands_before_the_exec_still_exits_126(child_run, capsys):
    """The same stop landing between the setup and the exec: reported, exit 126."""
    calls = child_run(parent=os.getppid(), execve=_raise(KeyboardInterrupt()))

    assert calls[-1] == ("_exit", (126,))
    assert "stopped before the scanner started" in capsys.readouterr().err


def test_a_child_whose_wrapper_died_before_the_prctl_exits(child_run, capsys):
    """The kernel sends the parent-death signal only for a parent that exits after
    the call, so a child reparented already runs nothing: it exits 126 as a
    failed setup does, instead of going on to exec, and says why."""
    # No process has a negative pid, so this never equals the real parent.
    calls = child_run(parent=-1)
    names = [name for name, _ in calls]

    assert names == ["setup", "_exit"]
    assert ("_exit", (126,)) in calls
    assert "the wrapper exited before the scanner started" in capsys.readouterr().err


def test_a_child_whose_wrapper_is_alive_execs_the_scanner(child_run):
    calls = child_run(parent=os.getppid())
    names = [name for name, _ in calls]

    assert names[:2] == ["setup", "execve"]


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
    subprocess does for every child it starts, and only after the restriction:
    while it runs, a failure line written to a closed stderr must be an error
    the child reports with exit 126, not a SIGPIPE that ends it with -13."""
    calls = child_calls()
    names = [name for name, _ in calls]
    restored = {args for name, args in calls if name == "signal"}

    assert restored == {
        (signal.SIGPIPE, signal.SIG_DFL),
        (signal.SIGXFSZ, signal.SIG_DFL),
    }
    assert min(i for i, name in enumerate(names) if name == "signal") > names.index(
        "restrict"
    )
    assert names[-2:] == ["signal", "signal"]


def test_a_refused_parent_death_signal_is_noted_and_the_child_goes_on(
    child_calls, capsys
):
    """The parent-death signal is best effort: the child says so and is still
    restricted and exec'd."""
    calls = child_calls(prctl_returns=-1)
    names = [name for name, _ in calls]

    assert names.index("prctl") < names.index("restrict")
    noted = capsys.readouterr().err
    assert "prctl(PR_SET_PDEATHSIG)" in noted
    assert noted.startswith("ash-landlock: ")


@pytest.fixture
def stop_calls(monkeypatch):
    """Run ``_forward_stop`` with the kill, the group lookup, the handler, the timer
    and the clock stood in for; return the calls and the list that records the
    first stop. The stand-in's ``getpgid`` answers 0, another group than the
    scanner's pid, the shape in which the pid is signalled as well as the group."""

    def run(signals: List[Tuple[int, bool]]) -> Tuple[List[Tuple[str, tuple]], List]:
        calls: List[Tuple[str, tuple]] = []
        monkeypatch.setattr(
            landlock_exec, "os", _Recording(os, {"kill", "killpg", "getpgid"}, calls)
        )
        monkeypatch.setattr(
            landlock_exec, "signal", _Recording(signal, {"signal", "setitimer"}, calls)
        )
        monkeypatch.setattr(
            landlock_exec, "time", types.SimpleNamespace(monotonic=lambda: 10.0)
        )
        stopped_at: List[float] = []
        for signum, running in signals:
            landlock_exec._forward_stop(42, signum, lambda: running, stopped_at)
        return calls, stopped_at

    return run


def test_repeated_stop_signals_arm_the_kill_timer_once(stop_calls):
    """Every stop signal is passed on to the scanner's group and, the scanner
    having left that group here, to its pid, but
    the SIGKILL timer counts from the first one, as the reap deadline does: a
    second signal inside the budget does not push the kill past that deadline.
    The timer is armed at half the budget, so the reap keeps the other half."""
    calls, stopped_at = stop_calls(
        [(signal.SIGINT, True), (signal.SIGTERM, True), (signal.SIGTERM, True)]
    )

    passed_on = [(42, signal.SIGINT), (42, signal.SIGTERM), (42, signal.SIGTERM)]
    assert [args for name, args in calls if name == "killpg"] == passed_on
    assert [args for name, args in calls if name == "kill"] == passed_on
    timers = [args for name, args in calls if name == "setitimer"]
    assert timers == [(signal.ITIMER_REAL, landlock_exec.STOP_KILL_DELAY_SECONDS)]
    assert (
        landlock_exec.STOP_KILL_DELAY_SECONDS < landlock_exec.STOP_REAP_DEADLINE_SECONDS
    )
    assert stopped_at == [10.0]


def test_a_stop_after_the_scanner_exited_is_recorded_and_sends_nothing(stop_calls):
    """The reap deadline still counts from the stop; the scanner's pid, reaped or
    about to be, is not signalled, and no timer is armed for it."""
    calls, stopped_at = stop_calls([(signal.SIGTERM, False)])

    assert calls == []
    assert stopped_at == [10.0]


def test_the_reap_after_a_stop_keeps_a_minimum_window_once_the_scanner_exited():
    """A scanner that takes the whole stop budget to exit (one that handles the
    signal slowly; one that ignores it is SIGKILLed halfway through) used to leave
    its tree one reap pass, since the reap ended with the budget: the reap now runs
    at least STOP_REAP_MINIMUM_SECONDS past the exit, and the two together stay
    inside the half second ASH gives a prompt stop."""
    stop, quarter = 10.0, landlock_exec.STOP_REAP_DEADLINE_SECONDS
    minimum = landlock_exec.STOP_REAP_MINIMUM_SECONDS

    # Exited at once on the signal: the deadline is the stop's, unchanged.
    assert landlock_exec._reap_deadline(stop + 0.05, stop) == stop + quarter
    # Exited only at the stop deadline: a minimum window follows the exit.
    assert landlock_exec._reap_deadline(stop + quarter, stop) == (
        stop + quarter + minimum
    )
    # No stop: the full reap after a clean exit.
    assert landlock_exec._reap_deadline(stop, None) == (
        stop + landlock_exec.REAP_DEADLINE_SECONDS
    )
    # A stop long before the exit: the exit-based bounds alone.
    assert landlock_exec._reap_deadline(stop, stop - 60.0) == stop + minimum
    assert quarter + minimum < 0.5


def test_a_policy_with_a_relative_path_is_refused(capsys):
    """The wrapper changes into the policy's cwd before the rules are applied and
    the command is run, so a relative path would resolve against that directory
    and a grant on a path that is then not found would go in silence: a relative
    path in any list, or as the cwd, is exit 126 with the key named."""
    base = {"read_only": ["/usr"], "writable": ["/var/out"], "network": False}

    for key, value in (
        ("read_only", ["usr"]),
        ("read_data", ["./data"]),
        ("writable", ["/var/out", "out"]),
        ("cwd", "work"),
    ):
        with pytest.raises(SystemExit) as refused:
            landlock_exec._parse_policy(json.dumps({**base, key: value}))
        assert refused.value.code == 126
        noted = capsys.readouterr().err
        assert (
            "absolute" in noted and key in noted and noted.startswith("ash-landlock: ")
        )

    # Control: absolute paths, and an empty cwd (none), pass as before.
    policy = landlock_exec._parse_policy(
        json.dumps({**base, "read_data": ["/srv/data"], "cwd": "/var/work"})
    )
    assert policy["cwd"] == "/var/work"
    assert landlock_exec._parse_policy(json.dumps({**base, "cwd": ""}))["cwd"] == ""


def test_an_optional_key_sent_as_null_is_the_key_left_out():
    """A producer that writes `"cwd": null` or `"read_data": null` for "none"
    is not refused: the key is dropped, and the required keys keep their types."""
    base = {"read_only": ["/usr"], "writable": ["/var/out"], "network": False}

    policy = landlock_exec._parse_policy(
        json.dumps({**base, "cwd": None, "read_data": None})
    )

    assert "cwd" not in policy and "read_data" not in policy
    assert policy["read_only"] == ["/usr"]
    with pytest.raises(SystemExit):
        landlock_exec._parse_policy(json.dumps({**base, "network": None}))


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

    assert landlock_exec._descendants(until=lambda: 5.0) == [101]


@pytest.mark.parametrize("name", ["kill", "killpg", "pidfd_open", "pidfd_send_signal"])
def test_the_stand_in_os_refuses_every_signalling_call_it_was_not_given(procfs, name):
    """The stand-in /proc names pids that are only numbers here; the real process
    under one of them must never be signalled or pinned by a test that forgot to
    stub the call."""
    procfs({})

    with pytest.raises(AssertionError, match=name):
        getattr(landlock_exec.os, name)


def test_a_recording_stand_in_refuses_the_signalling_calls_it_does_not_record():
    recording = _Recording(os, {"kill"}, [])

    recording.kill(4242, signal.SIGKILL)  # recorded, sent to no process
    assert recording.getpid() == os.getpid()
    for name in ("killpg", "pidfd_open", "pidfd_send_signal"):
        with pytest.raises(AssertionError, match=name):
            getattr(recording, name)
    for name in ("pidfd_send_signal", "raise_signal", "pthread_kill"):
        with pytest.raises(AssertionError, match=name):
            getattr(_Recording(signal, set(), []), name)


class _BrokenStderr:
    """A stderr whose reader has gone: every write raises BrokenPipeError."""

    def __init__(self) -> None:
        self.writes = 0

    def write(self, text: str) -> int:
        self.writes += 1
        raise BrokenPipeError(errno.EPIPE, "Broken pipe")

    def flush(self) -> None:
        pass


@pytest.fixture
def broken_stderr(monkeypatch):
    """Replace sys.stderr with one nobody reads. The wrapper repoints descriptor 2
    after a failed write, so each test stubs ``os.dup2``: this process's own
    descriptor 2 must not be."""
    stderr = _BrokenStderr()
    monkeypatch.setattr(sys, "stderr", stderr)
    return stderr


def test_a_note_to_a_stderr_nobody_reads_is_dropped_and_descriptor_2_given_up(
    broken_stderr, monkeypatch
):
    """The write raises BrokenPipeError because the interpreter ignores SIGPIPE;
    the note is dropped, and descriptor 2 is pointed at a descriptor of /dev/null
    so the interpreter's flush as it exits cannot fail and turn the wrapper's
    status into 120."""
    calls: List[Tuple[str, tuple]] = []
    monkeypatch.setattr(landlock_exec, "os", _Recording(os, {"dup2"}, calls))

    landlock_exec._note("a pass was cut short")

    assert broken_stderr.writes == 1
    assert [name for name, _ in calls] == ["dup2"]
    ((_, (_, target)),) = calls
    assert target == 2


def test_a_failure_to_a_stderr_nobody_reads_still_exits_126(broken_stderr, monkeypatch):
    monkeypatch.setattr(landlock_exec, "os", _Recording(os, {"dup2"}, []))

    with pytest.raises(SystemExit) as raised:
        landlock_exec.fail("exec /bin/true: gone")

    assert raised.value.code == 126
    assert broken_stderr.writes == 1


def test_a_reap_pass_goes_on_to_the_next_process_when_its_note_cannot_be_written(
    procfs, broken_stderr, monkeypatch
):
    """The note about a process whose stat cannot be read used to raise out of
    ``_kill_descendant`` and end the pass, so the processes after it in the
    list were never reached and outlived the wrapper."""
    proc = procfs(
        {
            "/proc/11": [],
            "/proc/11/stat": PermissionError(errno.EACCES, "denied"),
            "/proc/22": [],
            "/proc/22/stat": PermissionError(errno.EACCES, "denied"),
        }
    )
    landlock_exec.os.dup2 = lambda source, target: None
    landlock_exec.os.waitpid = lambda pid, options: (0, 0)
    walks = [[11, 22]]
    monkeypatch.setattr(
        landlock_exec, "_descendants", lambda until=None: walks.pop(0) if walks else []
    )
    monkeypatch.setattr(
        landlock_exec,
        "time",
        types.SimpleNamespace(monotonic=lambda: 10.0, sleep=lambda seconds: None),
    )

    landlock_exec._reap_leftovers(lambda: 20.0)

    assert "/proc/22/stat" in proc.opened


def test_the_stand_in_proc_is_only_opened_for_reading():
    proc = _Procfs({"/proc/1/stat": b"1 (init) S 0"})

    assert proc.open("/proc/1/stat", "rb").read() == b"1 (init) S 0"
    with pytest.raises(AssertionError):
        proc.open("/proc/1/stat", "wb")


class _RecordedStderr:
    """A stderr that records each write among the events of the run."""

    def __init__(self, events: List[Tuple[str, tuple]]) -> None:
        self._events = events

    def write(self, text: str) -> int:
        self._events.append(("write", (text,)))
        return len(text)

    def flush(self) -> None:
        pass


def _sigpipe_at_the_first_write(events: List[Tuple[str, tuple]]):
    """The disposition SIGPIPE was last given before the first stderr write."""
    disposition = None
    for name, args in events:
        if name == "signal" and args[0] == signal.SIGPIPE:
            disposition = args[1]
        if name == "write":
            return disposition
    raise AssertionError(f"nothing was written: {events}")


def _refused_exec(*args) -> None:
    raise OSError(errno.ENOENT, "No such file or directory", "/bin/true")


@pytest.mark.parametrize("wrapper_alive", [True, False])
def test_the_child_reports_a_failure_after_its_setup_with_sigpipe_ignored(
    monkeypatch, wrapper_alive
):
    """``_child_setup`` ends by giving SIGPIPE its default for the scanner. The
    report of an exec that failed, or of a wrapper that exited before the exec, is
    written after that, to a stderr that may be a closed pipe: with the default
    disposition the signal ends the child and ASH reads -13 where it owes 126."""
    events: List[Tuple[str, tuple]] = []

    def setup(restrict) -> None:
        events.append(("setup", ()))
        landlock_exec._restore_dispositions()

    fake_os = _Recording(os, {"_exit"}, events)
    fake_os.execve = _refused_exec
    monkeypatch.setattr(landlock_exec, "os", fake_os)
    monkeypatch.setattr(landlock_exec, "signal", _Recording(signal, {"signal"}, events))
    monkeypatch.setattr(landlock_exec, "_child_setup", setup)
    monkeypatch.setattr(sys, "stderr", _RecordedStderr(events))

    landlock_exec._run_child(
        ["/bin/true"], lambda: None, os.getppid() if wrapper_alive else -1
    )

    assert events[-1] == ("_exit", (126,))
    assert _sigpipe_at_the_first_write(events) == signal.SIG_IGN


def test_the_socket_filter_route_reports_a_failed_exec_with_sigpipe_ignored(
    monkeypatch,
):
    """The same for the route that execs in place: it restores the dispositions,
    and its exec failing is reported, with exit 126, after that."""
    events: List[Tuple[str, tuple]] = []
    fake_os = _Recording(os, set(), events)
    fake_os.execvp = _refused_exec
    monkeypatch.setattr(landlock_exec, "os", fake_os)
    monkeypatch.setattr(landlock_exec, "signal", _Recording(signal, {"signal"}, events))
    monkeypatch.setattr(landlock_exec, "libc", _Recording(None, {"prctl"}, events))
    monkeypatch.setattr(landlock_exec, "apply_socket_seccomp", lambda allow_ip: None)
    monkeypatch.setattr(sys, "stderr", _RecordedStderr(events))

    with pytest.raises(SystemExit) as raised:
        landlock_exec.exec_with_socket_filter(True, ["/bin/true"])

    assert raised.value.code == 126
    assert _sigpipe_at_the_first_write(events) == signal.SIG_IGN
