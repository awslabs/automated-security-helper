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
        # A path with an entry exists, whatever reading it does.
        self.path = types.SimpleNamespace(
            isdir=proc.isdir, exists=lambda path: path in proc.files
        )

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
    """With a deadline to honor, the entry cap does not apply: a scan with time
    left reads every entry."""
    monkeypatch.setattr(landlock_exec, "PROC_SCAN_LIMIT", 1)
    monkeypatch.setattr(
        landlock_exec, "time", types.SimpleNamespace(monotonic=lambda: 10.0)
    )
    files: Dict[str, Entry] = {"/proc": ["1", "2", "3", "4", "self"]}
    for pid in range(1, 5):
        files[f"/proc/{pid}/stat"] = _stat(pid, ME)
    procfs(files)

    assert landlock_exec._parent_map(until=lambda: 20.0) == {ME: [1, 2, 3, 4]}


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
    arguments each walk was called with and every kill are recorded.
    """

    def run(deadline_value: float, leftovers: List[List[int]]):
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
    killed; no second pass follows. The survivors reported are what one more
    deadline-bounded read still finds after that kill pass, here nothing, not
    the pids the pass already ended."""
    walks, kills, deadline, survivors = reap_calls(5.0, [[11, 21, 31]])

    assert walks == [None, deadline]
    assert kills == [11, 21, 31]
    assert survivors == []


def test_pids_still_present_after_the_last_kill_pass_are_the_survivors(reap_calls):
    """When the re-read after the deadline still finds a pid, that one is
    reported, the ones the pass ended are not."""
    walks, kills, deadline, survivors = reap_calls(5.0, [[11, 21], [21]])

    assert walks == [None, deadline]
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

    assert landlock_exec._descendants(until=lambda: 5.0) == [101]
