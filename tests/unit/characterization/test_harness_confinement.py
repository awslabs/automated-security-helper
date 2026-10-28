# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A characterization test cannot reach anything outside itself.

Each test drives one route out of the test (a process start, a signal, a write, a
socket, a C call, the account's home, a default bound at import) and asserts the
harness refuses it or keeps it inside the test. Every one is safe to run with its
guard removed: process starts run under ``no_new_processes()``, so a fork fails
with EAGAIN; the signals name pids no process can have or use signal 0; the writes
target a directory this module created for them, or raise an audit event by hand;
the C calls are getpid and getppid, and the landlock test asserts the refusing
stub is in place before it calls anything.
"""

from __future__ import annotations

import asyncio
import collections
import concurrent.futures
import contextlib
import ctypes
import dbm
import http.client
import inspect
import multiprocessing
import os
import posix
import pty
import shutil
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import types
import urllib.request
import warnings
from pathlib import Path

import _signal
import _socket
import boto3
import pytest
import requests
import urllib3

from tests.unit.characterization import _harness
from tests.unit.characterization._harness import Exit, Hang, LaunchViolation

NONEXISTENT = "/nonexistent-char-probe/x"

# By the build, not the platform: CPython leaves os.waitid out on some systems
# (macOS, Windows). The harness installs its refusing stub only where the function
# exists, so a test that calls os.waitid itself has nothing to run against there.
needs_waitid = pytest.mark.skipif(
    not hasattr(os, "waitid"), reason="this build of Python has no os.waitid"
)

# Bound at collection, before any guard is installed.
_THIRD_PARTY = types.ModuleType("char_third_party_probe")
_THIRD_PARTY.Popen = subprocess.Popen
_ASH_MODULE = types.ModuleType("automated_security_helper._char_probe")
_ASH_MODULE.Popen = subprocess.Popen
sys.modules["automated_security_helper._char_probe"] = _ASH_MODULE
from asyncio import create_subprocess_exec as _bound_create_subprocess_exec  # noqa: E402

from automated_security_helper.cli import dependencies as _dependencies  # noqa: E402
from automated_security_helper.utils.sandbox import landlock_exec as _landlock_exec  # noqa: E402

_PRELOADED_LIBC = ctypes.CDLL(None, use_errno=True)
_BOUND_OS_OPEN = os.open
_PRELOADED_GETPID = _PRELOADED_LIBC.getpid
#: The interpreter with its symlinks resolved, read here because a read inside a test
#: would lstat each link of a venv's chain under the probe guards.
_INTERPRETER_REAL_PATH = os.path.realpath(sys.executable)


class _SubPopen(subprocess.Popen):
    pass


def _noop() -> None:
    pass


@pytest.fixture(scope="session")
def outside(tmp_path_factory: pytest.TempPathFactory):
    """A directory outside pytest's basetemp, made before any guard is up.

    It holds the files the write tests try to change; each test checks they are
    exactly as made.
    """
    directory = Path(tempfile.mkdtemp(prefix="char-outside-")).resolve()
    if directory.is_relative_to(tmp_path_factory.getbasetemp().resolve()):
        pytest.fail(f"{directory} is inside pytest's basetemp")
    (directory / "victim.txt").write_text("victim\n", encoding="utf-8")
    (directory / "victim-dir").mkdir()
    (directory / "victim-dir" / "f").write_text("victim\n", encoding="utf-8")
    yield directory
    shutil.rmtree(directory, ignore_errors=True)


@pytest.fixture(scope="session", autouse=True)
def _name_the_process_cells_that_skipped():
    """One warning at the end of the session for the cells that skipped because the
    kernel would not hold the process limit, with the count and the switch that runs
    them. Without it each is a plain skip among the others."""
    yield
    summary = _harness.process_limit_skip_summary()
    if summary is not None:
        warnings.warn(summary, pytest.PytestWarning, stacklevel=2)


def _unchanged(outside: Path) -> None:
    entries = sorted(p.relative_to(outside).as_posix() for p in outside.rglob("*"))
    assert entries == ["victim-dir", "victim-dir/f", "victim.txt"]
    assert (outside / "victim.txt").read_text(encoding="utf-8") == "victim\n"


# -- process starts --------------------------------------------------------------


# Every test here that starts a process does it inside no_new_processes(), so with
# its guard removed the start fails with EAGAIN rather than forking the worker.


def _a_thread_can_start() -> bool:
    """Whether the kernel will make one more task for this worker. A thread is a task
    that counts against RLIMIT_NPROC, and one that does nothing harms nothing."""
    thread = threading.Thread(target=_noop)
    try:
        thread.start()
    except RuntimeError:
        return False
    thread.join()
    return True


def test_no_new_processes_holds_the_process_limit_at_one_and_restores_it():
    import resource

    # Asked of the kernel's rule directly, not through no_new_processes(): that one
    # runs its block on an exempt process when the opt-in variable is set, and the
    # limit this test asserts is not held there.
    exemption = _harness._process_limit_exemption(
        os.getuid(), _harness._process_status()
    )
    if exemption is not None:
        pytest.skip(f"RLIMIT_NPROC does not bind this process ({exemption})")
    before_soft, _ = resource.getrlimit(resource.RLIMIT_NPROC)
    with _harness.no_new_processes():
        # The hard limit is read here, not taken from before: the kernel may have
        # lowered it when the soft limit was set (macOS holds it to the per-user cap).
        held_soft, held_hard = resource.getrlimit(resource.RLIMIT_NPROC)
        assert held_soft == 1
        # Set is not held: the kernel must refuse the next task, as it refuses a fork.
        # macOS counts only processes, not threads, against RLIMIT_NPROC, so a thread
        # still starts there with the soft limit at one.
        if sys.platform != "darwin":
            assert not _a_thread_can_start()
    unlimited = resource.RLIM_INFINITY
    if held_hard != unlimited and (before_soft == unlimited or before_soft > held_hard):
        expected_soft = held_hard
    else:
        expected_soft = before_soft
    assert resource.getrlimit(resource.RLIMIT_NPROC) == (expected_soft, held_hard)


def test_a_process_limit_that_is_not_set_lets_a_thread_start(monkeypatch):
    """The check above fails when the limit does not bind: with the call that sets it
    made to do nothing, the worker can still start a task."""
    import resource

    monkeypatch.setattr(resource, "setrlimit", lambda *_: None)
    with _harness.no_new_processes():
        assert _a_thread_can_start()


@pytest.fixture
def clamped_process_limit(monkeypatch):
    """A process limit that behaves as macOS does, on every platform.

    It starts at (1000, 2000). A write that asks for a hard limit above 1333 gets 1333
    (the per-user cap), and a write that asks to raise the hard limit above its
    current value is refused. Yields the dict that holds the current pair.
    """
    import resource

    state = {"limit": (1000, 2000)}
    per_user_cap = 1333

    def getrlimit(which):
        assert which == resource.RLIMIT_NPROC
        return state["limit"]

    def setrlimit(which, limits):
        assert which == resource.RLIMIT_NPROC
        soft, hard = limits
        if hard > state["limit"][1]:
            raise ValueError("not allowed to raise maximum limit")
        if soft > hard:
            raise ValueError("current limit exceeds maximum limit")
        state["limit"] = (soft, min(hard, per_user_cap))

    monkeypatch.setattr(_harness, "require_process_limit", lambda: None)
    monkeypatch.setattr(resource, "getrlimit", getrlimit)
    monkeypatch.setattr(resource, "setrlimit", setrlimit)
    return state


def test_no_new_processes_restores_against_the_hard_limit_the_kernel_kept(
    clamped_process_limit,
):
    """With a hard limit that is clamped on the lowering write and cannot be raised
    back, the block still exits cleanly and leaves the soft limit as it was."""
    import resource

    with _harness.no_new_processes():
        assert resource.getrlimit(resource.RLIMIT_NPROC) == (1, 1333)
    assert resource.getrlimit(resource.RLIMIT_NPROC) == (1000, 1333)


def test_restoring_the_original_pair_fails_against_the_clamped_limit(
    clamped_process_limit,
):
    """Control for the test above: the restore this module used to make, the original
    pair written back, is refused by the same stand-in, so the stand-in can fail."""
    import resource

    soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
    resource.setrlimit(resource.RLIMIT_NPROC, (1, hard))
    assert resource.getrlimit(resource.RLIMIT_NPROC) == (1, 1333)
    with pytest.raises(ValueError, match="not allowed to raise maximum limit"):
        resource.setrlimit(resource.RLIMIT_NPROC, (soft, hard))


def test_the_restored_process_limit_never_asks_to_raise_the_hard_limit():
    """Infinity counts as larger than every number, on the soft and the hard limit; it
    reads as -1 on Linux, so a plain comparison would call it the smallest."""
    import resource

    unlimited = resource.RLIM_INFINITY
    cases = [
        ((1000, 1333), (1000, 1333)),
        ((2000, 1333), (1333, 1333)),
        ((unlimited, 1333), (1333, 1333)),
        ((1000, unlimited), (1000, unlimited)),
        ((unlimited, unlimited), (unlimited, unlimited)),
    ]
    for (original_soft, held_hard), expected in cases:
        restored = _harness._process_limit_to_restore(original_soft, held_hard)
        assert restored == expected, (original_soft, held_hard)


# The kernel ignores RLIMIT_NPROC for a process that is root or holds CAP_SYS_RESOURCE
# (capability 24) or CAP_SYS_ADMIN (21), and then a start with its guard removed would
# really fork the worker: no_new_processes() is not a safety net there.
_CAPEFF_SYS_RESOURCE = "Name:\tpython\nCapEff:\t0000000001000000\n"
_CAPEFF_SYS_ADMIN = "Name:\tpython\nCapEff:\t0000000000200000\n"
#: A container's default set (capabilities 0, 1, 3-8, 10, 13, 18, 27, 29 and 31): bits
#: 21 and 24 are clear.
_CAPEFF_NEITHER = "Name:\tpython\nCapEff:\t00000000a80425fb\n"


@pytest.mark.parametrize(
    "uid, status, exempt",
    [
        (0, _CAPEFF_NEITHER, True),
        (1000, _CAPEFF_SYS_RESOURCE, True),
        (1000, _CAPEFF_SYS_ADMIN, True),
        (1000, "Name:\tpython\nCapEff:\tffffffffffffffff\n", True),
        (1000, "Name:\tpython\nCapEff:\tnot-hex\n", True),
        (1000, _CAPEFF_NEITHER, False),
        (1000, "Name:\tpython\nCapEff:\t0000000000000000\n", False),
        (1000, "", False),
    ],
    ids=[
        "root",
        "cap-sys-resource",
        "cap-sys-admin",
        "all-caps",
        "unreadable-caps",
        "neither-bit",
        "no-caps",
        "no-procfs",
    ],
)
def test_the_process_limit_exemption_reads_the_uid_and_the_two_capabilities(
    uid, status, exempt
):
    reason = _harness._process_limit_exemption(uid, status)
    assert (reason is not None) is exempt


#: The processes the kernel does not hold RLIMIT_NPROC for, as (uid, /proc status text).
_NO_LIMIT_CASES = pytest.mark.parametrize(
    "uid, status",
    [(0, ""), (1000, _CAPEFF_SYS_RESOURCE), (1000, _CAPEFF_SYS_ADMIN)],
    ids=["root", "cap-sys-resource", "cap-sys-admin"],
)


@_NO_LIMIT_CASES
def test_no_new_processes_skips_where_the_kernel_would_not_hold_the_limit(
    monkeypatch, uid, status
):
    # The skips raised here are this test's own: they are not added to the count the
    # session reports, and the opt-in variable does not run the block they refuse.
    monkeypatch.setattr(_harness, "_PROCESS_LIMIT_SKIPS", [])
    monkeypatch.setattr(_harness, "_RUN_UNPROTECTED", False)
    monkeypatch.setattr(os, "getuid", lambda: uid)
    monkeypatch.setattr(_harness, "_process_status", lambda: status, raising=False)
    with pytest.raises(pytest.skip.Exception, match="RLIMIT_NPROC"):
        with _harness.no_new_processes():
            pytest.fail("the block ran although the limit would not hold")


@_NO_LIMIT_CASES
def test_a_skip_case_leaves_the_session_skip_count_alone(uid, status):
    """The skips a self-test provokes with a faked uid are not the run's: the count the
    session reports at its end is the same after as before."""
    before = list(_harness._PROCESS_LIMIT_SKIPS)
    summary = _harness.process_limit_skip_summary()
    with pytest.MonkeyPatch.context() as inner:
        test_no_new_processes_skips_where_the_kernel_would_not_hold_the_limit(
            inner, uid, status
        )
    assert _harness._PROCESS_LIMIT_SKIPS == before
    assert _harness.process_limit_skip_summary() == summary


@_NO_LIMIT_CASES
def test_a_skip_case_skips_although_the_opt_in_is_set(monkeypatch, uid, status):
    """With the opt-in variable set the run's other tests start their processes
    anyway, but this self-test is about the skip itself and holds either way."""
    monkeypatch.setattr(_harness, "_RUN_UNPROTECTED", True)
    with pytest.MonkeyPatch.context() as inner:
        test_no_new_processes_skips_where_the_kernel_would_not_hold_the_limit(
            inner, uid, status
        )


def test_the_limit_test_skips_on_an_exempt_process_although_the_opt_in_is_set(
    monkeypatch,
):
    """The kernel holds no limit for root, so the test that asserts it holds one has
    nothing to assert there, with the opt-in set or not. The limit is made inert here,
    as it is on such a process, and the test must skip instead of failing."""
    import resource

    monkeypatch.setattr(_harness, "_PROCESS_LIMIT_SKIPS", [])
    monkeypatch.setattr(_harness, "_RUN_UNPROTECTED", True)
    monkeypatch.setattr(os, "getuid", lambda: 0)
    monkeypatch.setattr(resource, "setrlimit", lambda *_: None)
    with pytest.raises(pytest.skip.Exception, match="RLIMIT_NPROC"):
        test_no_new_processes_holds_the_process_limit_at_one_and_restores_it()


def test_a_skipped_process_cell_is_counted_and_named_in_one_summary(monkeypatch):
    """Each cell that skips for want of the limit is counted, and one text names the
    count and the switch that runs them anyway."""
    monkeypatch.setattr(_harness, "_PROCESS_LIMIT_SKIPS", [])
    monkeypatch.setattr(_harness, "_RUN_UNPROTECTED", False)
    monkeypatch.setattr(os, "getuid", lambda: 0)
    assert _harness.process_limit_skip_summary() is None
    for _ in range(2):
        with pytest.raises(pytest.skip.Exception, match="RLIMIT_NPROC"):
            _harness.require_process_limit()
    summary = _harness.process_limit_skip_summary()
    assert summary is not None
    assert "2 characterization cells" in summary
    assert _harness.UNPROTECTED_PROCESS_LIMIT_ENV in summary


def test_the_opt_in_runs_a_process_cell_where_the_limit_does_not_hold(monkeypatch):
    """On a disposable run, the variable named in the summary runs the cells that
    would skip. The block here starts nothing."""
    monkeypatch.setattr(_harness, "_PROCESS_LIMIT_SKIPS", [])
    monkeypatch.setattr(_harness, "_RUN_UNPROTECTED", True)
    monkeypatch.setattr(os, "getuid", lambda: 0)
    ran = []
    try:
        with _harness.no_new_processes():
            ran.append(True)
    except pytest.skip.Exception:
        pytest.fail("the opt-in did not run the block")
    assert ran == [True]
    assert _harness.process_limit_skip_summary() is None


def test_a_module_that_bound_the_real_popen_cannot_start_a_process(char):
    assert _THIRD_PARTY.Popen is _harness.REAL_POPEN
    with _harness.no_new_processes():
        with pytest.raises(LaunchViolation, match="the real subprocess.Popen"):
            _THIRD_PARTY.Popen([NONEXISTENT])
    assert char.take_violations()


def test_an_ash_module_that_bound_popen_gets_the_fake(char):
    assert _ASH_MODULE.Popen is _harness.FakePopen
    with _harness.no_new_processes():
        with pytest.raises(FileNotFoundError):
            _ASH_MODULE.Popen(["not-a-tool"])
    assert char.launches[0].api == "subprocess.Popen"


def test_a_popen_subclass_cannot_start_a_process(char):
    with _harness.no_new_processes():
        with pytest.raises(LaunchViolation, match="the real subprocess.Popen"):
            _SubPopen([NONEXISTENT])
    assert char.take_violations()


def test_a_shell_command_runs_no_stand_in(char):
    with _harness.no_new_processes():
        with pytest.raises(LaunchViolation, match="not a characterization stand-in"):
            subprocess.getoutput("true")
    assert char.take_violations()


@pytest.mark.parametrize("name", _harness._OS_LAUNCHERS)
def test_every_os_launcher_is_guarded(char, name):
    if hasattr(os, name):
        assert getattr(os, name).__name__.startswith("guarded_"), name


@pytest.mark.parametrize(
    "call",
    [
        lambda: posix.execv(NONEXISTENT, ["x"]),
        lambda: posix.system("true"),
        lambda: posix.fork(),
        pytest.param(
            lambda: posix.forkpty(),
            marks=pytest.mark.skipif(
                not hasattr(posix, "forkpty"), reason="no posix.forkpty here"
            ),
        ),
        lambda: posix.posix_spawn(NONEXISTENT, ["x"], {}),
        lambda: posix.posix_spawnp("char-nonexistent-tool", ["x"], {}),
    ],
    ids=["execv", "system", "fork", "forkpty", "posix-spawn", "posix-spawnp"],
)
def test_the_posix_process_aliases_reach_the_audit_hook(char, call):
    """The posix names hold the unguarded functions; only the hook sees them."""
    with _harness.no_new_processes():
        with pytest.raises(LaunchViolation, match="never starts or signals"):
            call()
    assert len(char.take_violations()) == 1


def test_pty_spawn_is_refused(char):
    with _harness.no_new_processes():
        with pytest.raises(LaunchViolation):
            pty.spawn([NONEXISTENT])
    assert char.take_violations()


def test_asyncio_subprocess_routes_are_refused(char):
    async def main() -> None:
        with pytest.raises(LaunchViolation):
            await _bound_create_subprocess_exec(NONEXISTENT)
        with pytest.raises(LaunchViolation):
            await asyncio.create_subprocess_shell("true")
        loop = asyncio.get_running_loop()
        with pytest.raises(LaunchViolation):
            await loop.subprocess_exec(asyncio.SubprocessProtocol, NONEXISTENT)

    with _harness.no_new_processes():
        asyncio.run(main())
    assert len(char.take_violations()) == 3


@pytest.mark.parametrize("method", ["fork", "spawn", "forkserver"])
def test_multiprocessing_cannot_start_a_process(char, method):
    with _harness.no_new_processes():
        with pytest.raises(LaunchViolation):
            multiprocessing.get_context(method).Process(target=_noop).start()
    assert char.take_violations()


def test_pools_cannot_start_workers(char):
    with _harness.no_new_processes():
        with pytest.raises(LaunchViolation):
            multiprocessing.get_context("fork").Pool(1)
    char.take_violations()
    executor = concurrent.futures.ProcessPoolExecutor(
        1, mp_context=multiprocessing.get_context("fork")
    )
    with _harness.no_new_processes():
        with pytest.raises(LaunchViolation):
            executor.submit(_noop)
    assert char.take_violations()


def test_a_violation_swallowed_in_a_thread_still_fails_the_test(char):
    go = threading.Event()
    cancelled = threading.Event()

    def worker() -> None:
        go.wait()
        if cancelled.is_set():
            return  # the block never opened: its command is not safe to run
        try:
            subprocess.run([NONEXISTENT])
        except BaseException:  # noqa: BLE001 - product code that swallows everything
            pass

    # The skip comes before the thread, which waits with no timeout and would keep the
    # worker from exiting if the block never opened. A daemon, so nothing else can.
    _harness.require_process_limit()
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()  # before the limit, which would refuse the thread itself
    try:
        with _harness.no_new_processes():
            go.set()
            thread.join()
    finally:
        # Reached with the thread still waiting only when the block was not entered
        # (the limit could not be set): it then ends without starting anything.
        cancelled.set()
        go.set()
    with pytest.raises(pytest.fail.Exception, match="undeclared"):
        _harness.check_no_violations()


def test_a_thread_cell_skips_before_it_starts_a_thread_where_the_limit_does_not_hold(
    char, monkeypatch
):
    """The thread above waits with no timeout. Started before a skip, it would keep the
    worker from exiting, so the cell checks the limit first. Any thread started here is
    made a daemon, so this cell cannot hold the worker either."""
    started = []
    real_start = threading.Thread.start

    def start(self) -> None:
        self.daemon = True
        started.append(self)
        real_start(self)

    monkeypatch.setattr(_harness, "_PROCESS_LIMIT_SKIPS", [])
    monkeypatch.setattr(_harness, "_RUN_UNPROTECTED", False)
    monkeypatch.setattr(os, "getuid", lambda: 0)
    monkeypatch.setattr(threading.Thread, "start", start)
    with pytest.raises(pytest.skip.Exception, match="RLIMIT_NPROC"):
        test_a_violation_swallowed_in_a_thread_still_fails_the_test(char)
    assert started == []


def test_a_thread_cell_never_starts_its_work_when_the_limit_cannot_be_set(
    char, monkeypatch
):
    """If the limit cannot be set, the block is never entered, and the thread that waits
    for it must end without running its command: that command is only safe to run with
    the limit in place. The command is replaced here by a recorder."""
    import resource

    started, ran = [], []
    real_start = threading.Thread.start

    def start(self) -> None:
        self.daemon = True
        started.append(self)
        real_start(self)

    def refuse(*_args) -> None:
        raise OSError("the limit cannot be set")

    monkeypatch.setattr(_harness, "_process_limit_exemption", lambda uid, status: None)
    monkeypatch.setattr(resource, "setrlimit", refuse)
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: ran.append(args))
    monkeypatch.setattr(threading.Thread, "start", start)
    with pytest.raises(OSError, match="cannot be set"):
        test_a_violation_swallowed_in_a_thread_still_fails_the_test(char)
    assert len(started) == 1
    started[0].join(timeout=5)
    assert not started[0].is_alive()
    assert ran == []


# -- signals and reaping -----------------------------------------------------------


def test_fake_pids_cannot_name_a_real_process(char):
    char.tool("slow", lambda call: Hang())
    proc = subprocess.Popen(["slow"], start_new_session=True)
    assert proc.pid > 2**22
    pid_max = Path("/proc/sys/kernel/pid_max")
    if pid_max.exists():
        assert proc.pid > int(pid_max.read_text())
    proc.kill()
    proc.wait()


def test_a_group_signal_reaches_the_fake_that_leads_the_group(char):
    char.tool("slow", lambda call: Hang(ignores_sigterm=True))
    proc = subprocess.Popen(["slow"], start_new_session=True)
    os.killpg(proc.pid, signal.SIGTERM)
    assert proc.poll() is None
    os.killpg(proc.pid, signal.SIGKILL)
    assert proc.wait() == -signal.SIGKILL
    assert char.launches[0].calls == [
        {"os.killpg": {"signal": signal.SIGTERM}},
        {"os.killpg": {"signal": signal.SIGKILL}},
        {"wait": {"timeout": None}},
    ]


def test_a_group_signal_to_a_fake_that_leads_no_group_is_esrch(char):
    char.tool("slow", lambda call: Hang())
    proc = subprocess.Popen(["slow"])
    with pytest.raises(ProcessLookupError):
        os.killpg(proc.pid, signal.SIGTERM)
    proc.kill()
    proc.wait()
    assert char.launches[0].calls[0] == {
        "os.killpg": {"signal": signal.SIGTERM, "error": "ESRCH"}
    }


def test_terminate_after_the_exit_reaps_the_zombie_so_a_group_signal_finds_no_group(
    char,
):
    """``Popen.terminate`` polls first and sends nothing to a child that has exited;
    the poll reaps a zombie, so a group signal after it names a freed id (ESRCH)."""
    char.tool("slow", lambda call: Hang(leaves_zombie=True))
    proc = subprocess.Popen(["slow"], start_new_session=True)
    os.killpg(proc.pid, signal.SIGTERM)
    assert proc.returncode is None
    proc.terminate()
    assert proc.returncode == -signal.SIGTERM
    with pytest.raises(ProcessLookupError):
        os.killpg(proc.pid, signal.SIGKILL)
    assert char.launches[0].calls == [
        {"os.killpg": {"signal": signal.SIGTERM}},
        {"terminate": {}},
        {"os.killpg": {"signal": signal.SIGKILL, "error": "ESRCH"}},
    ]


def _zombie(char) -> subprocess.Popen:
    """A ``Hang(leaves_zombie=True)`` that a group SIGTERM has ended and nothing has
    waited for: it has exited, and its ``returncode`` is still None."""
    char.tool("slow", lambda call: Hang(leaves_zombie=True))
    proc = subprocess.Popen(["slow"], start_new_session=True)
    os.killpg(proc.pid, signal.SIGTERM)
    return proc


@needs_waitid
def test_a_hang_that_leaves_a_zombie_is_observed_unreaped_and_reachable(char):
    """``leaves_zombie``: the SIGTERM ends it with ``returncode`` still None;
    ``os.waitid`` with ``WNOWAIT`` reports the exit, every time, without reaping it;
    a later group signal still reaches it and changes nothing; the first ``poll``
    reaps it and sets the code."""
    proc = _zombie(char)
    assert proc.returncode is None
    observe = os.WEXITED | os.WNOHANG | os.WNOWAIT
    for _ in range(2):
        found = os.waitid(os.P_PID, proc.pid, observe)
        assert (found.si_pid, found.si_status, found.si_code) == (
            proc.pid,
            signal.SIGTERM,
            os.CLD_KILLED,
        )
    assert proc.returncode is None
    os.killpg(proc.pid, signal.SIGKILL)
    assert proc.returncode is None
    assert proc.poll() == -signal.SIGTERM
    assert char.launches[0].calls == [
        {"os.killpg": {"signal": signal.SIGTERM}},
        {"os.waitid": {"options": observe}},
        {"os.waitid": {"options": observe}},
        {"os.killpg": {"signal": signal.SIGKILL}},
    ]


@needs_waitid
@pytest.mark.parametrize("reap", ["poll", "wait", "communicate"])
def test_the_first_wait_of_a_zombie_reaps_it_and_sets_its_code(char, reap):
    proc = _zombie(char)
    reapers = {
        "poll": proc.poll,
        "wait": proc.wait,
        "communicate": proc.communicate,
    }
    reapers[reap]()
    assert proc.returncode == -signal.SIGTERM
    # Reaped: the group id is free and the child is no longer ours to wait for.
    with pytest.raises(ProcessLookupError):
        os.killpg(proc.pid, signal.SIGKILL)
    with pytest.raises(ChildProcessError):
        os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)


def _exited(char) -> subprocess.Popen:
    """An ``Exit(3)`` child in a session of its own that nothing has waited for."""
    char.tool("done", lambda call: Exit(3))
    return subprocess.Popen(["done"], start_new_session=True)


def _leave_the_with_block(proc: subprocess.Popen) -> None:
    with proc:
        pass


#: Every Popen call that waits for its child. In CPython they all end in ``wait`` or
#: ``poll``: ``communicate`` and ``__exit__`` call ``wait``, and ``kill``,
#: ``terminate`` and ``send_signal`` poll first (subprocess.py, Popen.send_signal).
_POPEN_WAITS = {
    "poll": lambda proc: proc.poll(),
    "wait": lambda proc: proc.wait(),
    "communicate": lambda proc: proc.communicate(),
    "kill": lambda proc: proc.kill(),
    "terminate": lambda proc: proc.terminate(),
    "send_signal": lambda proc: proc.send_signal(signal.SIGKILL),
    "__exit__": _leave_the_with_block,
}


def _reap_with_waitpid(pid: int) -> tuple[int, int]:
    """The pid and the exit code ``os.waitpid`` reports for ``pid``."""
    reaped, status = os.waitpid(pid, 0)
    return reaped, os.waitstatus_to_exitcode(status)


def _reap_with_waitid(pid: int) -> tuple[int, int]:
    """The pid and exit code ``os.waitid`` reports for ``pid``, without ``WNOWAIT``."""
    found = os.waitid(os.P_PID, pid, os.WEXITED)
    killed = found.si_code == os.CLD_KILLED
    return found.si_pid, -found.si_status if killed else found.si_status


#: The two ways to reap a child from outside its Popen. Both take the exit; neither
#: tells the Popen.
_OUTSIDE_REAPS = {"waitpid": _reap_with_waitpid, "waitid": _reap_with_waitid}


@needs_waitid
@pytest.mark.parametrize("wait", list(_POPEN_WAITS))
@pytest.mark.parametrize("child", ["zombie", "exited"])
@pytest.mark.parametrize("reap", list(_OUTSIDE_REAPS))
def test_an_outside_reap_takes_the_exit_and_every_popen_wait_then_records_0(
    char, reap, child, wait
):
    """A reap from outside the Popen, ``os.waitpid`` or ``os.waitid`` without
    ``WNOWAIT``, reports the exit itself but does not update the Popen object
    (bpo-15756): ``returncode`` stays None, whether the child is a zombie or a tool
    that exited with a code nobody has read, and the Popen's next wait, whichever call
    makes it, finds nothing to wait for and records 0, as CPython's do (``_try_wait``
    answers 0 on ECHILD; ``communicate`` and ``__exit__`` wait; ``kill``,
    ``terminate`` and ``send_signal`` poll first)."""
    proc = _zombie(char) if child == "zombie" else _exited(char)
    expected = -signal.SIGTERM if child == "zombie" else 3
    assert _OUTSIDE_REAPS[reap](proc.pid) == (proc.pid, expected)
    assert proc.returncode is None
    _POPEN_WAITS[wait](proc)
    assert proc.returncode == 0
    # Reaped: the group id is free and the child is no longer ours to wait for.
    with pytest.raises(ProcessLookupError):
        os.killpg(proc.pid, signal.SIGKILL)
    with pytest.raises(ChildProcessError):
        os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)


@needs_waitid
def test_an_exited_tool_looked_at_with_wnowait_is_not_waited_for(char):
    """``os.waitid`` with ``WNOWAIT`` reads the exit of a tool that has exited and
    waits for nothing, as it does for a zombie: the Popen is not told, so
    ``returncode`` stays None, a later group signal still reaches the child and
    changes nothing, and the first ``poll`` sets the code the tool exited with."""
    proc = _exited(char)
    observe = os.WEXITED | os.WNOHANG | os.WNOWAIT
    for _ in range(2):
        found = os.waitid(os.P_PID, proc.pid, observe)
        assert (found.si_pid, found.si_status, found.si_code) == (
            proc.pid,
            3,
            os.CLD_EXITED,
        )
        assert proc.returncode is None
    os.killpg(proc.pid, signal.SIGTERM)
    assert proc.returncode is None
    assert proc.poll() == 3
    assert char.launches[0].calls == [
        {"os.waitid": {"options": observe}},
        {"os.waitid": {"options": observe}},
        {"os.killpg": {"signal": signal.SIGTERM}},
    ]


@needs_waitid
def test_an_exited_leader_is_a_zombie_to_every_look_and_reaped_by_waitpid(char):
    """The questions a launcher puts to its leader, in its order: look without
    waiting, signal the group, look again, reap. A tool that has exited and that
    nothing has waited for is a zombie to each of them. Neither look sets
    ``returncode`` (a launcher that reads it first takes the leader for reaped and
    skips the signal and the reap), the signal is recorded, and the reap is a
    ``waitpid`` of the launcher's own, which the record shows."""
    proc = _exited(char)
    observe = os.WEXITED | os.WNOHANG | os.WNOWAIT
    assert os.waitid(os.P_PID, proc.pid, observe).si_pid == proc.pid
    assert proc.returncode is None
    os.killpg(proc.pid, signal.SIGTERM)
    assert os.waitid(os.P_PID, proc.pid, observe).si_pid == proc.pid
    assert proc.returncode is None
    assert os.waitpid(proc.pid, 0) == (proc.pid, 3 << 8)
    assert proc.returncode is None
    assert proc.poll() == 0
    assert char.launches[0].calls == [
        {"os.waitid": {"options": observe}},
        {"os.killpg": {"signal": signal.SIGTERM}},
        {"os.waitid": {"options": observe}},
        {"os.waitpid": {"options": 0}},
    ]


@pytest.mark.parametrize("send", ["killpg", "kill"])
def test_a_signal_before_the_first_look_finds_an_exited_tool_a_zombie(char, send):
    """The signal reaches a child that has exited and that nothing has waited for, so
    it changes nothing: ``returncode`` stays None, and the first ``poll`` answers with
    the code the tool exited with, not with the signal."""
    proc = _exited(char)
    {"killpg": os.killpg, "kill": os.kill}[send](proc.pid, signal.SIGTERM)
    assert proc.returncode is None
    assert proc.poll() == 3


@pytest.mark.parametrize("call", ["kill", "terminate", "send_signal"])
def test_a_signal_to_a_zombie_reaps_it_first_and_sends_nothing(char, call):
    """``Popen.send_signal`` (so ``kill`` and ``terminate``) polls first and sends
    nothing to a child that has exited; the poll reaps the zombie, so the code stays
    the one it exited with and a group signal after it finds no group."""
    proc = _zombie(char)
    if call == "send_signal":
        proc.send_signal(signal.SIGKILL)
        recorded = {"send_signal": {"signal": signal.SIGKILL}}
    else:
        getattr(proc, call)()
        recorded = {call: {}}
    assert proc.returncode == -signal.SIGTERM
    with pytest.raises(ProcessLookupError):
        os.killpg(proc.pid, signal.SIGKILL)
    assert char.launches[0].calls == [
        {"os.killpg": {"signal": signal.SIGTERM}},
        recorded,
        {"os.killpg": {"signal": signal.SIGKILL, "error": "ESRCH"}},
    ]


def test_a_signal_to_a_running_hang_ends_it_and_to_an_exited_tool_changes_nothing(
    char,
):
    """The same poll-first rule at its two ends: a hanging double that is running is
    ended by the signal (a zombie here, so its code arrives with the first poll), and
    a tool that has already exited keeps the code it exited with."""
    char.tool("slow", lambda call: Hang(leaves_zombie=True))
    char.tool("done", lambda call: Exit(3))
    running = subprocess.Popen(["slow"])
    running.terminate()
    assert running.returncode is None
    assert running.poll() == -signal.SIGTERM
    finished = subprocess.Popen(["done"])
    finished.kill()
    assert finished.returncode == 3


def test_kill_getpgid_getsid_and_waitpid_answer_for_the_fake(char):
    char.tool("tool", lambda call: Exit(3))
    leader = subprocess.Popen(["tool"], start_new_session=True)
    os.kill(leader.pid, 0)
    assert os.getpgid(leader.pid) == leader.pid
    assert os.getsid(leader.pid) == leader.pid
    assert os.waitpid(leader.pid, 0) == (leader.pid, 3 << 8)
    with pytest.raises(ProcessLookupError):
        os.kill(leader.pid, 0)
    with pytest.raises(ChildProcessError):
        os.waitpid(leader.pid, 0)
    member = subprocess.Popen(["tool"])
    assert os.getpgid(member.pid) == os.getpgrp()
    member.wait()
    assert [next(iter(call)) for call in char.launches[0].calls] == [
        "os.kill",
        "os.getpgid",
        "os.getsid",
        "os.waitpid",
        "os.kill",
        "os.waitpid",
    ]


@needs_waitid
def test_waitid_observes_a_fake_and_reaps_it_only_without_wnowait(char):
    char.tool("tool", lambda call: Exit(3))
    char.tool("slow", lambda call: Hang())
    done = subprocess.Popen(["tool"])
    observe = os.WEXITED | os.WNOHANG | os.WNOWAIT
    found = os.waitid(os.P_PID, done.pid, observe)
    assert (found.si_pid, found.si_status, found.si_code) == (
        done.pid,
        3,
        os.CLD_EXITED,
    )
    # Observed twice: WNOWAIT leaves the child to be reaped, and the Popen unwaited.
    assert os.waitid(os.P_PID, done.pid, observe) is not None
    assert done.returncode is None
    assert os.waitid(os.P_PID, done.pid, os.WEXITED).si_pid == done.pid
    # An outside reap too: the Popen is not told, and its next wait records 0.
    assert done.returncode is None
    assert done.poll() == 0
    with pytest.raises(ChildProcessError):
        os.waitid(os.P_PID, done.pid, os.WEXITED | os.WNOHANG)
    running = subprocess.Popen(["slow"])
    assert os.waitid(os.P_PID, running.pid, observe) is None
    running.kill()
    running.wait()
    assert char.take_violations() == []


_TASKS = Path("/proc/self/task")


def _children_of_the_worker(tasks: Path = _TASKS) -> list[int] | None:
    """The pids of the worker's children, from the ``children`` file of each of its
    threads (``/proc/self/task/<tid>/children``). None where the kernel lists none:
    no procfs, or one built without CONFIG_PROC_CHILDREN."""
    pids: list[int] = []
    listed = False
    try:
        for thread in tasks.iterdir():
            try:
                text = (thread / "children").read_text()
            except FileNotFoundError:
                continue
            listed = True
            pids += [int(pid) for pid in text.split()]
    except (OSError, ValueError):
        return None
    return pids if listed else None


def _require_no_children_to_reap(tasks: Path = _TASKS) -> None:
    """Skip unless the worker has no child. With its guard removed, ``wait`` and
    ``waitpid(-1)`` would reap another test's child, or block on a live one; with
    nothing to wait for they fail with ECHILD and do no harm."""
    children = _children_of_the_worker(tasks)
    if children is None:
        pytest.skip("this kernel does not list the worker's children")
    if children:
        pytest.skip(f"the worker has children ({children}) a wait could reap")


def _procfs(root: Path, children: dict[str, str | None]) -> Path:
    for tid, text in children.items():
        (root / tid).mkdir(parents=True)
        if text is not None:
            (root / tid / "children").write_text(text, encoding="utf-8")
    return root


def test_the_workers_children_are_read_from_every_thread(tmp_path):
    tasks = _procfs(tmp_path / "task", {"11": "", "12": "21 22 ", "13": "23 "})
    assert _children_of_the_worker(tasks) == [21, 22, 23]
    assert _children_of_the_worker(_procfs(tmp_path / "idle", {"11": ""})) == []
    assert _children_of_the_worker(tmp_path / "missing") is None
    assert _children_of_the_worker(_procfs(tmp_path / "blind", {"11": None})) is None


def test_a_wait_cell_is_skipped_unless_the_worker_has_no_child(tmp_path):
    _require_no_children_to_reap(_procfs(tmp_path / "idle", {"11": "", "12": ""}))
    with pytest.raises(pytest.skip.Exception, match="children"):
        _require_no_children_to_reap(_procfs(tmp_path / "busy", {"11": "31 "}))
    with pytest.raises(pytest.skip.Exception, match="does not list"):
        _require_no_children_to_reap(tmp_path / "missing")


# ``reaps`` marks the cells that, with their guard removed, could reap or wait for a
# child of the worker that another test started; only those need a worker with none.
@pytest.mark.parametrize(
    "call, reaps",
    [
        pytest.param(lambda: os.kill(os.getpid(), 0), False, id="kill-self"),
        pytest.param(lambda: os.kill(0, 0), False, id="kill-group-0"),
        pytest.param(lambda: os.killpg(os.getpgrp(), 0), False, id="killpg-own-group"),
        pytest.param(lambda: os.getpgid(os.getpid()), False, id="getpgid-self"),
        pytest.param(lambda: os.getsid(os.getpid()), False, id="getsid-self"),
        pytest.param(lambda: os.waitpid(-1, os.WNOHANG), True, id="waitpid-any"),
        pytest.param(lambda: os.wait(), True, id="wait"),
        pytest.param(
            lambda: os.waitid(os.P_PID, os.getpid(), os.WEXITED | os.WNOHANG),
            False,
            id="waitid-self",
            marks=needs_waitid,
        ),
        pytest.param(
            lambda: os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG),
            True,
            id="waitid-any",
            marks=needs_waitid,
        ),
        pytest.param(
            lambda: os.pidfd_open(1),
            False,
            id="pidfd-open",
            marks=pytest.mark.skipif(
                not hasattr(os, "pidfd_open"), reason="no os.pidfd_open here"
            ),
        ),
        pytest.param(
            lambda: signal.pidfd_send_signal(-1, 0),
            False,
            id="pidfd-send-signal",
            marks=pytest.mark.skipif(
                not hasattr(signal, "pidfd_send_signal"),
                reason="no signal.pidfd_send_signal here",
            ),
        ),
    ],
)
def test_signaling_querying_or_reaping_any_other_process_fails(char, call, reaps):
    if reaps:
        _require_no_children_to_reap()
    with pytest.raises(LaunchViolation, match="not a characterization fake"):
        call()
    assert len(char.take_violations()) == 1


@pytest.mark.parametrize(
    "call, reaps",
    [
        pytest.param(lambda: posix.waitpid(-1, os.WNOHANG), True, id="waitpid"),
        pytest.param(lambda: posix.wait(), True, id="wait"),
        pytest.param(lambda: posix.getpgid(os.getpid()), False, id="getpgid"),
        pytest.param(lambda: posix.getsid(os.getpid()), False, id="getsid"),
        pytest.param(
            lambda: posix.pidfd_open(os.getppid()),
            False,
            id="pidfd-open",
            marks=pytest.mark.skipif(
                not hasattr(posix, "pidfd_open"), reason="no posix.pidfd_open here"
            ),
        ),
        pytest.param(
            lambda: _signal.pidfd_send_signal(-1, 0),
            False,
            id="pidfd-send-signal",
            marks=pytest.mark.skipif(
                not hasattr(_signal, "pidfd_send_signal"),
                reason="no _signal.pidfd_send_signal here",
            ),
        ),
    ],
)
def test_the_c_module_aliases_are_guarded_too(char, call, reaps):
    """None of these raise an audit event, so the guard is the only line."""
    if reaps:
        _require_no_children_to_reap()
    with pytest.raises(LaunchViolation, match="not a characterization fake"):
        call()
    assert len(char.take_violations()) == 1


@pytest.mark.parametrize(
    "cell, refused",
    [
        pytest.param(
            test_signaling_querying_or_reaping_any_other_process_fails,
            lambda: os.kill(os.getpid(), 0),
            id="signal-guards",
        ),
        pytest.param(
            test_the_c_module_aliases_are_guarded_too,
            lambda: posix.getsid(os.getpid()),
            id="c-module-aliases",
        ),
    ],
)
@pytest.mark.parametrize("reaps", [False, True], ids=["cannot-reap", "can-reap"])
def test_only_a_cell_that_can_reap_needs_a_worker_without_children(
    char, monkeypatch, cell, refused, reaps
):
    """Where the worker's children cannot be listed, a cell that can reap one skips and
    every other cell runs."""
    monkeypatch.setattr(
        sys.modules[__name__], "_children_of_the_worker", lambda *_: None
    )
    if reaps:
        with pytest.raises(pytest.skip.Exception, match="does not list"):
            cell(char, refused, reaps)
    else:
        cell(char, refused, reaps)


def test_signal_state_is_put_back():
    state = _harness._signal_state()
    previous = signal.getsignal(signal.SIGUSR1)
    signal.signal(signal.SIGUSR1, lambda *_: None)
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})
    _harness._restore_signal_state(state)
    assert signal.getsignal(signal.SIGUSR1) is previous
    assert signal.SIGUSR2 not in signal.pthread_sigmask(signal.SIG_BLOCK, [])


def test_guarded_puts_the_signal_mask_and_handlers_back():
    """Through ``guarded`` itself, nested in this test's own guards."""
    guards, confine = _harness._GUARDS, _harness._CONFINE
    saved = (guards.installed, guards.harness, confine.active, confine.roots)
    previous = signal.getsignal(signal.SIGUSR1)
    try:
        with pytest.MonkeyPatch.context() as inner:
            with _harness.guarded(inner):
                signal.signal(signal.SIGUSR1, lambda *_: None)
                signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})
    finally:
        guards.installed, guards.harness, confine.active, confine.roots = saved
    assert signal.getsignal(signal.SIGUSR1) is previous
    assert signal.SIGUSR2 not in signal.pthread_sigmask(signal.SIG_BLOCK, [])


def test_guarded_puts_the_multiprocessing_start_method_back():
    """ASH's detect-secrets worker forces fork; a test that runs it must not leave
    that behind for the rest of the pytest worker."""
    guards, confine = _harness._GUARDS, _harness._CONFINE
    saved = (guards.installed, guards.harness, confine.active, confine.roots)
    previous = multiprocessing.get_start_method(allow_none=True)
    forced = "spawn" if previous == "fork" else "fork"
    try:
        with pytest.MonkeyPatch.context() as inner:
            with _harness.guarded(inner):
                multiprocessing.set_start_method(forced, force=True)
                assert multiprocessing.get_start_method(allow_none=True) == forced
    finally:
        guards.installed, guards.harness, confine.active, confine.roots = saved
    assert multiprocessing.get_start_method(allow_none=True) == previous


# -- the cache resets ----------------------------------------------------------------

_FS_GUARD = "automated_security_helper.utils.sandbox.fs_guard"


def _fs_guard_holding(**containers: object) -> types.ModuleType:
    """A stand-in for the sandbox fs_guard module: its lock and ``containers``."""
    module = types.ModuleType(_FS_GUARD)
    module._roots_lock = threading.Lock()
    for name, container in containers.items():
        setattr(module, name, container)
    return module


def test_the_sandbox_roots_reset_clears_the_containers_this_fs_guard_has():
    """The containers of the fs_guard this tree ships: the roots a write is confined
    below, and the releases queued for them."""
    roots = {Path("/char-stale-root"): 2}
    releases = collections.deque([Path("/char-stale-root")])
    module = _fs_guard_holding(_writable_roots=roots, _pending_releases=releases)
    with pytest.MonkeyPatch.context() as inner:
        inner.setitem(sys.modules, _FS_GUARD, module)
        _harness._forget_sandbox_writable_roots()
    assert roots == {}
    assert not releases


def test_a_cache_reset_against_this_fs_guard_records_no_violation():
    """What ran after every test that followed the first import of fs_guard: the reset
    named containers this fs_guard does not have, and the harness failed the test at
    teardown with ``the cache reset _forget_sandbox_writable_roots raised
    AttributeError``."""
    roots = {Path("/char-stale-root"): 1}
    module = _fs_guard_holding(
        _writable_roots=roots, _pending_releases=collections.deque()
    )
    with pytest.MonkeyPatch.context() as inner:
        inner.setitem(sys.modules, _FS_GUARD, module)
        _harness._clear_caches()
    assert _harness.take_violations() == []
    assert roots == {}


def test_the_sandbox_roots_reset_also_clears_the_containers_an_older_fs_guard_had():
    roots, permanent, blocks = {Path("/a"): 1}, {Path("/b")}, {Path("/c"): 3}
    module = _fs_guard_holding(
        _writable_roots=roots,
        _pending_releases=collections.deque(),
        _permanent_roots=permanent,
        _block_counts=blocks,
    )
    with pytest.MonkeyPatch.context() as inner:
        inner.setitem(sys.modules, _FS_GUARD, module)
        _harness._forget_sandbox_writable_roots()
    assert (roots, permanent, blocks) == ({}, set(), {})


def test_the_sandbox_roots_reset_still_refuses_an_fs_guard_without_its_roots():
    """A name every fs_guard has is not skipped when it is gone: the reset raises, and
    the harness records that as a violation."""
    with pytest.MonkeyPatch.context() as inner:
        inner.setitem(sys.modules, _FS_GUARD, _fs_guard_holding())
        with pytest.raises(AttributeError, match="_writable_roots"):
            _harness._forget_sandbox_writable_roots()


def test_the_sandbox_roots_reset_refuses_an_fs_guard_without_its_release_queue():
    """The release queue is one of the containers every fs_guard of this tree has. If it
    is renamed, the reset must say so, not leave the queue it no longer finds."""
    module = _fs_guard_holding(_writable_roots={Path("/char-stale-root"): 1})
    with pytest.MonkeyPatch.context() as inner:
        inner.setitem(sys.modules, _FS_GUARD, module)
        with pytest.raises(AttributeError, match="_pending_releases"):
            _harness._forget_sandbox_writable_roots()


@pytest.mark.parametrize(
    "container",
    [dict, set, list, collections.deque],
    ids=["dict", "set", "list", "deque"],
)
def test_the_sandbox_roots_reset_refuses_a_container_it_does_not_know(container):
    """A new module-level container in fs_guard would stay filled between tests, which
    is the leak the reset exists to prevent. The reset clears what it knows, then
    raises naming the one it does not."""
    roots = {Path("/char-stale-root"): 1}
    releases = collections.deque([Path("/char-stale-root")])
    unknown = container()
    module = _fs_guard_holding(
        _writable_roots=roots, _pending_releases=releases, _queued_for_later=unknown
    )
    with pytest.MonkeyPatch.context() as inner:
        inner.setitem(sys.modules, _FS_GUARD, module)
        with pytest.raises(AssertionError, match="_queued_for_later"):
            _harness._forget_sandbox_writable_roots()
    assert roots == {}
    assert not releases


def test_a_cache_reset_against_an_unknown_fs_guard_container_records_a_violation():
    module = _fs_guard_holding(
        _writable_roots={}, _pending_releases=collections.deque(), _queued_for_later=[]
    )
    with pytest.MonkeyPatch.context() as inner:
        inner.setitem(sys.modules, _FS_GUARD, module)
        _harness._clear_caches()
    found = _harness.take_violations()
    assert len(found) == 1
    assert "_queued_for_later" in found[0]


def test_the_sandbox_roots_reset_leaves_what_is_not_a_mutable_container_alone():
    """Control: a number, a tuple, a frozenset and the module's own dunder names are not
    state that grows, so none of them is refused."""
    module = _fs_guard_holding(
        _writable_roots={},
        _pending_releases=collections.deque(),
        _LIMIT=3,
        _NAMES=("a", "b"),
        _KINDS=frozenset({"c"}),
    )
    module.__all__ = ["x"]
    with pytest.MonkeyPatch.context() as inner:
        inner.setitem(sys.modules, _FS_GUARD, module)
        _harness._forget_sandbox_writable_roots()
    assert module._NAMES == ("a", "b")


# -- writes ------------------------------------------------------------------------


def _touch(path: Path) -> Path:
    path.write_text("x", encoding="utf-8")
    return path


def _tree(tmp: Path) -> Path:
    """A small directory inside the test, to copy or archive."""
    (tmp / "tree").mkdir(exist_ok=True)
    _touch(tmp / "tree" / "f")
    return tmp / "tree"


_WRITES = {
    "open-w": lambda out, tmp: open(out / "new.txt", "w"),
    "open-a": lambda out, tmp: open(out / "victim.txt", "a"),
    "write-text": lambda out, tmp: (out / "new.txt").write_text("x"),
    "os-open-creat": lambda out, tmp: os.open(
        out / "new.txt", os.O_WRONLY | os.O_CREAT
    ),
    "remove": lambda out, tmp: os.remove(out / "victim.txt"),
    "unlink": lambda out, tmp: os.unlink(out / "victim.txt"),
    "rename-from": lambda out, tmp: os.rename(out / "victim.txt", tmp / "moved"),
    "rename-to": lambda out, tmp: os.rename(_touch(tmp / "t"), out / "new.txt"),
    "replace-to": lambda out, tmp: os.replace(_touch(tmp / "t"), out / "victim.txt"),
    "mkdir": lambda out, tmp: os.mkdir(out / "new-dir"),
    "makedirs": lambda out, tmp: os.makedirs(out / "a" / "b"),
    "rmdir": lambda out, tmp: os.rmdir(out / "victim-dir"),
    "rmtree": lambda out, tmp: shutil.rmtree(out / "victim-dir"),
    "copyfile": lambda out, tmp: shutil.copyfile(_touch(tmp / "t"), out / "copy"),
    "copy": lambda out, tmp: shutil.copy(_touch(tmp / "t"), out),
    "move": lambda out, tmp: shutil.move(out / "victim.txt", tmp / "moved"),
    "symlink": lambda out, tmp: os.symlink(tmp, out / "link"),
    "link": lambda out, tmp: os.link(out / "victim.txt", tmp / "hard"),
    "truncate": lambda out, tmp: os.truncate(out / "victim.txt", 0),
    "chmod": lambda out, tmp: os.chmod(out / "victim.txt", 0o600),
    "utime": lambda out, tmp: os.utime(out / "victim.txt", None),
    "mkstemp": lambda out, tmp: tempfile.mkstemp(dir=out),
    "mkdtemp": lambda out, tmp: tempfile.mkdtemp(dir=out),
    "named-temporary-file": lambda out, tmp: tempfile.NamedTemporaryFile(dir=out),
    "sqlite3-connect": lambda out, tmp: sqlite3.connect(out / "new.db"),
    # The URI form dbm.sqlite3 builds, opened by URI only.
    "sqlite3-uri": lambda out, tmp: sqlite3.connect(
        f"file:{out / 'new.db'}?mode=rwc", uri=True
    ),
    "chown": lambda out, tmp: os.chown(out / "victim.txt", os.getuid(), os.getgid()),
    "mkfifo": lambda out, tmp: os.mkfifo(out / "fifo"),
    "mknod": lambda out, tmp: os.mknod(out / "node"),
    "setxattr": lambda out, tmp: os.setxattr(out / "victim.txt", "user.char", b"1"),
    "removexattr": lambda out, tmp: os.removexattr(out / "victim.txt", "user.char"),
    "copytree": lambda out, tmp: shutil.copytree(_tree(tmp), out / "tree"),
    "copystat": lambda out, tmp: shutil.copystat(_touch(tmp / "t"), out / "victim.txt"),
    "make-archive": lambda out, tmp: shutil.make_archive(
        str(out / "archive"), "zip", root_dir=_tree(tmp)
    ),
    "unpack-archive": lambda out, tmp: shutil.unpack_archive(
        shutil.make_archive(str(tmp / "a"), "zip", root_dir=_tree(tmp)),
        out / "unpacked",
    ),
    "dbm-open": lambda out, tmp: dbm.open(str(out / "new"), "c"),
    # The C backend itself, which raises no audit event.
    "dbm-ndbm-open": lambda out, tmp: pytest.importorskip("dbm.ndbm").open(
        str(out / "new"), "c"
    ),
}


@pytest.mark.parametrize("write", list(_WRITES.values()), ids=list(_WRITES))
def test_a_write_outside_the_test_is_refused(char, outside, tmp_path, write):
    with pytest.raises(LaunchViolation, match="outside the test's directory"):
        write(outside, tmp_path)
    _unchanged(outside)
    assert char.take_violations()


def test_a_symlink_cannot_carry_a_write_out_of_the_test(char, outside, tmp_path):
    link = tmp_path / "link"
    link.symlink_to(outside / "victim.txt")
    with pytest.raises(LaunchViolation, match="outside the test's directory"):
        open(link, "w")
    _unchanged(outside)
    assert char.take_violations()


def test_a_symlink_inside_the_test_can_be_removed_but_not_reached_through(
    char, outside
):
    """Unlinking or renaming a link acts on the link; a symlinked directory still
    cannot carry a delete out."""
    (char.work / "file-link").symlink_to(outside / "victim.txt")
    (char.work / "dir-link").symlink_to(outside / "victim-dir")
    with pytest.raises(LaunchViolation, match="outside the test's directory"):
        os.remove(char.work / "dir-link" / "f")
    with pytest.raises(LaunchViolation, match="outside the test's directory"):
        os.rename(char.work / "dir-link" / "f", char.work / "taken")
    os.rename(char.work / "file-link", char.work / "renamed-link")
    os.remove(char.work / "renamed-link")
    tree = char.work / "tree"
    tree.mkdir()
    (tree / "link").symlink_to(outside / "victim.txt")
    shutil.rmtree(tree)
    _unchanged(outside)
    assert len(char.take_violations()) == 2


def test_a_hard_link_cannot_be_made_to_a_file_a_symlink_names_outside(char, outside):
    """os.link follows its source by default, and writes through the new name
    would change the file outside."""
    (char.work / "file-link").symlink_to(outside / "victim.txt")
    with pytest.raises(LaunchViolation, match="outside the test's directory"):
        os.link(char.work / "file-link", char.work / "hard")
    assert not (char.work / "hard").exists()
    (char.work / "own.txt").write_text("x\n", encoding="utf-8")
    os.link(char.work / "own.txt", char.work / "own-hard")
    _unchanged(outside)
    assert len(char.take_violations()) == 1


def test_a_delete_relative_to_a_directory_descriptor_is_resolved(char, outside):
    fd = os.open(outside, os.O_RDONLY)
    try:
        with pytest.raises(LaunchViolation, match="outside the test's directory"):
            os.unlink("victim.txt", dir_fd=fd)
    finally:
        os.close(fd)
    _unchanged(outside)
    assert char.take_violations()


def test_a_write_relative_to_a_directory_descriptor_is_checked_there(char, outside):
    """os.open's audit event names no dir_fd, so the guard on os.open resolves it."""
    assert os.open.__name__ == "_guarded_os_open"
    flags = os.O_WRONLY | os.O_CREAT
    out_fd = os.open(outside, os.O_RDONLY | os.O_DIRECTORY)
    in_fd = os.open(char.tmp, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(LaunchViolation, match="outside the test's directory"):
            os.open("new.txt", flags, 0o600, dir_fd=out_fd)
        os.close(os.open("inside.txt", flags, 0o600, dir_fd=in_fd))
    finally:
        os.close(out_fd)
        os.close(in_fd)
    _unchanged(outside)
    assert (char.tmp / "inside.txt").is_file()
    assert len(char.take_violations()) == 1


class _IndexFlags:
    """Not an int, but os.open takes it, through ``__index__``."""

    def __init__(self, value):
        self.value = value

    def __index__(self):
        return self.value


def test_os_open_flags_that_are_not_an_int_are_checked_too(char, outside):
    flags = _IndexFlags(os.O_WRONLY | os.O_CREAT)
    out_fd = os.open(outside, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(LaunchViolation, match="outside the test's directory"):
            os.open("new.txt", flags, 0o600, dir_fd=out_fd)
    finally:
        os.close(out_fd)
    _unchanged(outside)
    assert len(char.take_violations()) == 1
    with pytest.raises(TypeError):
        os.open(char.tmp / "x", "w")


def test_metadata_changes_through_a_descriptor_are_checked(char, outside, tmp_path):
    """fchmod, futimens, ftruncate and fchown name an fd, which may be read-only."""
    victim, inside = outside / "victim.txt", _touch(tmp_path / "inside.txt")
    before = victim.stat()
    ids = (os.getuid(), os.getgid())
    out_fd, in_fd = os.open(victim, os.O_RDONLY), os.open(inside, os.O_RDWR)
    read_end, write_end = os.pipe()
    try:
        for change in (
            lambda fd: os.fchmod(fd, 0o600),
            lambda fd: os.utime(fd, (0, 0)),
            lambda fd: os.chown(fd, *ids),
            lambda fd: os.truncate(fd, 0),
        ):
            with pytest.raises(LaunchViolation, match="outside the test's directory"):
                change(out_fd)
            change(in_fd)
        os.fchmod(read_end, 0o600)  # a pipe names no file
    finally:
        for fd in (out_fd, in_fd, read_end, write_end):
            os.close(fd)
    _unchanged(outside)
    after = victim.stat()
    assert (after.st_mode, after.st_mtime_ns) == (before.st_mode, before.st_mtime_ns)
    assert len(char.take_violations()) == 4


def test_an_os_open_bound_before_the_guards_cannot_write_a_relative_name(char, outside):
    """Its audit event cannot say which directory the name is in: refused."""
    fd = os.open(outside, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(LaunchViolation, match="does not guard"):
            _BOUND_OS_OPEN("new.txt", os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=fd)
    finally:
        os.close(fd)
    os.close(_BOUND_OS_OPEN(str(char.tmp / "absolute.txt"), os.O_WRONLY | os.O_CREAT))
    _unchanged(outside)
    assert len(char.take_violations()) == 1


def test_the_sandbox_results_writer_cannot_write_outside_the_test(char, outside):
    """fs_guard.open_for_write writes through os.open, naming the directory by fd."""
    from automated_security_helper.utils.sandbox import fs_guard

    fs_guard.register_writable_root(outside)
    with pytest.raises(LaunchViolation, match="outside the test's directory"):
        with fs_guard.open_for_write(outside / "new.txt") as handle:
            handle.write("x")
    _unchanged(outside)
    assert char.take_violations()


def test_each_harness_starts_with_no_sandbox_writable_root(char_factory, tmp_path):
    """fs_guard keeps its roots as a dict (root -> number of holders), so the empty
    registry is ``{}``, and ``registered_roots()`` is the public view of it."""
    from automated_security_helper.utils.sandbox import fs_guard

    for name in ("first", "second"):
        harness = char_factory(tmp_path / name)
        with harness.active():
            assert fs_guard._writable_roots == {}
            assert fs_guard.registered_roots() == frozenset()
            fs_guard.register_writable_root(harness.out)
    assert fs_guard._writable_roots == {}
    assert fs_guard.registered_roots() == frozenset()


def test_os_capability_sets_still_list_the_guarded_functions(char):
    """scanned_tree chooses its walk by `os.open in os.supports_dir_fd`."""
    assert os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
    assert os.stat in os.supports_follow_symlinks


def test_writes_inside_the_test_and_bytecode_caches_are_allowed(
    char, outside, tmp_path
):
    (tmp_path / "d").mkdir()
    _touch(tmp_path / "d" / "f")
    fd, name = tempfile.mkstemp(dir=tmp_path)
    os.close(fd)
    os.replace(name, tmp_path / "d" / "g")
    shutil.rmtree(tmp_path / "d")
    sqlite3.connect(":memory:").close()
    sqlite3.connect(tmp_path / "inside.db").close()
    sqlite3.connect(f"file:{outside / 'victim.txt'}?mode=ro", uri=True).close()
    for backend in _harness._C_DBM_MODULES:
        backend.open(str(tmp_path / f"inside-{backend.__name__}"), "c").close()
    _unchanged(outside)
    assert char.take_violations() == []


@pytest.mark.parametrize(
    "statement",
    ["ATTACH DATABASE '{}' AS other", "VACUUM INTO '{}'"],
    ids=["attach", "vacuum-into"],
)
def test_sqlite_cannot_attach_or_vacuum_into_a_file_outside(
    char, outside, tmp_path, statement
):
    """SQLite opens these files in C, after a connect that wrote nothing."""
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE TABLE t (x)")
        with pytest.raises(sqlite3.DatabaseError, match="not authorized|denied"):
            connection.execute(statement.format(outside / "new.db"))
        connection.execute(statement.format(tmp_path / "inside.db"))
    finally:
        connection.close()
    _unchanged(outside)
    assert (tmp_path / "inside.db").is_file()
    assert len(char.take_violations()) == 1


def test_a_bytecode_cache_gets_no_exemption(char, outside, tmp_path):
    """Imports write no bytecode while guarded, so __pycache__ is an ordinary name:
    a host one cannot be made, and a symlink under the test's own carries nothing
    out."""
    assert sys.dont_write_bytecode
    with pytest.raises(LaunchViolation, match="outside the test's directory"):
        (outside / "__pycache__").mkdir()
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    (cache / "out").symlink_to(outside)
    with pytest.raises(LaunchViolation, match="outside the test's directory"):
        open(cache / "out" / "m.cpython-314.pyc", "w")
    (tmp_path / "fresh_char_module.py").write_text("VALUE = 1\n", encoding="utf-8")
    sys.path.insert(0, str(tmp_path))
    try:
        import fresh_char_module  # noqa: F401 - imported for its side effects

        assert sorted(p.name for p in cache.iterdir()) == ["out"]
    finally:
        sys.path.remove(str(tmp_path))
        sys.modules.pop("fresh_char_module", None)
    _unchanged(outside)
    assert len(char.take_violations()) == 2


def test_a_test_without_char_is_confined_too(outside, tmp_path, monkeypatch):
    # A relative socket path: an AF_UNIX address over 108 bytes fails before the
    # audit event is raised, and pytest's basetemp can be that long.
    monkeypatch.chdir(tmp_path)
    _touch(tmp_path / "allowed")
    with pytest.raises(LaunchViolation, match="outside the test's directory"):
        _touch(outside / "new.txt")
    sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    try:
        with pytest.raises(LaunchViolation, match="offline"):
            sock.bind("s")
    finally:
        sock.close()
    with pytest.raises(LaunchViolation, match="not a characterization fake"):
        os.kill(os.getpid(), 0)
    _unchanged(outside)
    assert len(_harness.take_violations()) == 3


def test_tool_and_write_source_refuse_a_directory_outside_the_test(char, outside):
    with pytest.raises(ValueError, match="outside the test's directory"):
        char.tool("planted", on=outside / "bin")
    with pytest.raises(ValueError, match="outside the test's directory"):
        char.write_source({"f.txt": "x\n"}, root=outside / "src")
    _unchanged(outside)


def test_a_double_cannot_write_where_argv_points_outside_the_test(char, outside):
    from tests.unit.characterization._bandit_double import BanditDouble

    char.tool("bandit", BanditDouble())
    char.write_source({"app.py": "x\n"})
    argv = ["bandit", "--recursive", "--format", "sarif", "--output"]
    with pytest.raises(LaunchViolation, match="was handed .*out.sarif"):
        subprocess.run([*argv, str(outside / "out.sarif"), str(char.src)])
    _unchanged(outside)
    assert char.take_violations()


def test_a_double_cannot_read_or_probe_a_path_outside_the_test(char, outside):
    seen = {}

    def double(call):
        seen["inside"] = call.read("inside.txt")
        seen["resolved"] = call.confined("inside.txt")
        for path in (outside / "victim.txt", "../../../../../../etc/hostname"):
            with pytest.raises(LaunchViolation, match="was handed"):
                call.confined(path)
        with pytest.raises(LaunchViolation, match="was handed"):
            call.read(outside / "victim.txt")
        return Exit(0)

    (char.work / "inside.txt").write_bytes(b"in\n")
    (char.work / "link").symlink_to(outside / "victim.txt")
    char.tool("reader", double)
    subprocess.run(["reader"], cwd=char.work, check=True)
    assert seen == {"inside": b"in\n", "resolved": char.work / "inside.txt"}
    char.tool("linker", lambda call: Exit(0, stdout=call.read("link").decode()))
    with pytest.raises(LaunchViolation, match="was handed"):
        subprocess.run(["linker"], cwd=char.work, capture_output=True)
    assert len(char.take_violations()) == 4


def test_call_write_writes_a_fixture_or_bytes_inside_the_test(
    char, tmp_path, monkeypatch
):
    """``write_fixture`` copies a file of the fixtures directory and refuses a name
    that leaves it. The directory is a stand-in made here, so the test pins that
    behavior whichever fixture files the tree it runs in carries."""
    fixtures = tmp_path / "fixtures"
    (fixtures / "bandit").mkdir(parents=True)
    content = b'{"version": "2.1.0", "runs": []}\n'
    (fixtures / "bandit" / "results.sarif").write_bytes(content)
    # A file the escaping name reaches, so only the check on the directory refuses it.
    (tmp_path / "conftest.py").write_bytes(b"")
    monkeypatch.setattr(_harness, "FIXTURES_DIR", fixtures)
    written = {}

    def double(call):
        written["fixture"] = call.write_fixture("bandit/results.sarif", call.args[0])
        written["bytes"] = call.write("relative.bin", b"\x00\x01")
        with pytest.raises(TypeError, match="write_fixture"):
            call.write("other.sarif", "bandit/results.sarif")
        with pytest.raises(ValueError, match="is not a file under"):
            call.write_fixture("../conftest.py", "escaped.py")
        return Exit(0)

    char.tool("emitter", double)
    subprocess.run(["emitter", str(char.out / "a.sarif")], cwd=char.work)
    assert written["fixture"].read_bytes() == content
    assert written["bytes"] == char.work / "relative.bin"
    assert written["bytes"].read_bytes() == b"\x00\x01"


# -- the interpreter, resolved before the guards ------------------------------------


def test_a_venv_interpreter_behind_a_chain_of_links_is_not_probed_during_a_test(
    tmp_path, monkeypatch
):
    """``<PYREAL>`` is the interpreter resolved once, at import. Resolving it inside a
    test would ``lstat`` each link of ``bin/python -> python3 -> /usr/bin/python3``,
    and a link in a host executable directory is a probe the guards refuse."""
    base = tmp_path / "base"
    base.mkdir()
    target = base / "python3.99"
    target.write_text("", encoding="utf-8")
    venv_bin = tmp_path / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python3").symlink_to(target)
    (venv_bin / "python").symlink_to("python3")
    monkeypatch.setattr(sys, "executable", str(venv_bin / "python"))
    monkeypatch.setattr(
        _harness,
        "HOST_EXEC_DIRS",
        _harness.HOST_EXEC_DIRS | {str(venv_bin), str(base)},
    )
    roots = _harness._interpreter_roots()
    assert roots["<PY>"] == str(venv_bin / "python")
    assert roots["<PYREAL>"] == _INTERPRETER_REAL_PATH
    assert _harness.take_violations() == []


# -- the files argv names ------------------------------------------------------------


def _argv_files(char, *argv, cwd=None) -> dict:
    """What the harness records of the files a launch's argv names."""
    char.tool("reader", lambda call: Exit(0))
    subprocess.run(["reader", *map(str, argv)], cwd=cwd or char.work, check=True)
    return char.launches[-1].files


def test_an_argv_path_with_dots_that_lands_outside_the_test_is_not_captured(
    char, outside
):
    """It is spelled inside the test's tree and resolves outside it."""
    file_path = char.work / os.path.relpath(outside / "victim.txt", char.work)
    directory = char.work / os.path.relpath(outside, char.work)
    assert _argv_files(char, file_path) == {}
    assert _argv_files(char, f"--input={file_path}") == {}
    assert _argv_files(char, directory) == {}


def test_an_argv_path_through_a_symlinked_directory_leading_outside_is_not_captured(
    char, outside
):
    (char.work / "dir-link").symlink_to(outside / "victim-dir")
    assert _argv_files(char, char.work / "dir-link" / "f") == {}
    assert _argv_files(char, char.work / "dir-link") == {
        str(char.work / "dir-link"): {"symlink": str(outside / "victim-dir")}
    }


@pytest.mark.parametrize("kind", ["host-file", "dangling"])
def test_a_symlink_in_argv_is_recorded_as_a_symlink_and_not_read_through(
    char, outside, kind
):
    link = char.work / "link"
    target = outside / "victim.txt" if kind == "host-file" else char.work / "missing"
    link.symlink_to(target)
    assert _argv_files(char, link) == {str(link): {"symlink": str(target)}}


def test_a_directory_in_argv_records_its_symlinks_as_symlinks(char, outside):
    handed = char.work / "handed"
    handed.mkdir()
    (handed / "own.txt").write_text("own\n", encoding="utf-8")
    (handed / "link").symlink_to(outside / "victim.txt")
    (handed / "dangling").symlink_to(char.work / "missing")
    (handed / "dir-link").symlink_to(outside / "victim-dir")
    listing = _argv_files(char, handed)[str(handed)]["dir"]
    assert sorted(listing) == [
        str(handed / "dangling"),
        str(handed / "dir-link"),
        str(handed / "link"),
        str(handed / "own.txt"),
    ]
    assert listing[str(handed / "link")] == {"symlink": str(outside / "victim.txt")}
    assert listing[str(handed / "dangling")] == {"symlink": str(char.work / "missing")}
    assert listing[str(handed / "dir-link")] == {"symlink": str(outside / "victim-dir")}
    assert listing[str(handed / "own.txt")].value == {"text": ["own\n"]}


def test_an_argv_path_through_a_link_into_a_host_directory_probes_no_host_path(char):
    """``<work>/bin-link/git`` lies inside the test's tree and resolves into a host
    executable directory. Judging it takes no step into that directory, so the test
    is not failed for a probe it did not make, and the file is not captured."""
    host = "/usr/bin"
    if not os.path.isdir(host):
        pytest.skip("this host has no /usr/bin")
    link = char.work / "bin-link"
    link.symlink_to(host)
    assert _argv_files(char, link / "git") == {}
    assert _argv_files(char, link) == {str(link): {"symlink": host}}
    assert char.take_violations() == []


def test_a_relative_argv_that_resolves_into_the_source_tree_is_a_fixture(char):
    """``../src/app.py`` from the work directory is the file under ``<SRC>``: unchanged
    since ``begin()`` it is a fixture, as it is when argv spells it directly."""
    char.write_source({"app.py": "x\n"})
    char.begin()
    assert _argv_files(char, "../src/app.py", cwd=char.work) == {}
    assert _argv_files(char, char.src / "app.py") == {}


def test_a_source_file_that_was_changed_is_captured_under_its_resolved_name(char):
    char.write_source({"app.py": "x\n"})
    char.begin()
    (char.src / "app.py").write_text("y\n", encoding="utf-8")
    direct = _argv_files(char, char.src / "app.py")
    relative = _argv_files(char, "../src/app.py", cwd=char.work)
    assert list(direct) == list(relative) == [str(char.src / "app.py")]
    assert relative[str(char.src / "app.py")].value == {"text": ["y\n"]}


def test_a_file_the_test_made_inside_its_tree_is_captured_as_before(char):
    made = char.work / "made.txt"
    made.write_text("made\n", encoding="utf-8")
    files = _argv_files(char, made, f"--out={made}")
    assert list(files) == [str(made)]
    assert files[str(made)].value == {"text": ["made\n"]}


def test_dots_after_a_link_in_argv_name_the_parent_of_the_links_target(char):
    """``<work>/link/../x`` is opened as ``<work>/deep/x`` when ``link`` leads to
    ``<work>/deep/target``. The file there is the one recorded, under that name, and
    ``<work>/x`` is left out."""
    (char.work / "deep" / "target").mkdir(parents=True)
    (char.work / "link").symlink_to(char.work / "deep" / "target")
    (char.work / "x").write_text("work\n", encoding="utf-8")
    (char.work / "deep" / "x").write_text("deep\n", encoding="utf-8")
    files = _argv_files(char, char.work / "link" / ".." / "x")
    assert list(files) == [str(char.work / "deep" / "x")]
    assert files[str(char.work / "deep" / "x")].value == {"text": ["deep\n"]}


def test_dots_after_a_link_that_leads_outside_are_not_judged_as_the_text_reads(
    char, outside
):
    """``<work>/out-link/../victim.txt`` is opened as ``<outside>/victim.txt``. A file
    of the same name in ``<work>``, which the text alone would name, is not what the
    process opens and is not recorded for it."""
    (char.work / "out-link").symlink_to(outside / "victim-dir")
    (char.work / "victim.txt").write_text("own\n", encoding="utf-8")
    assert _argv_files(char, char.work / "out-link" / ".." / "victim.txt") == {}
    assert (
        _argv_files(char, f"--input={char.work / 'out-link' / '..' / 'victim.txt'}")
        == {}
    )


def test_dots_after_a_plain_directory_in_argv_are_captured_under_the_resolved_name(
    char,
):
    """Control: with no link in front of the dots, the text and the kernel agree."""
    (char.work / "sub").mkdir()
    (char.work / "x").write_text("work\n", encoding="utf-8")
    files = _argv_files(char, char.work / "sub" / ".." / "x")
    assert list(files) == [str(char.work / "x")]
    assert files[str(char.work / "x")].value == {"text": ["work\n"]}


# -- every audit entry --------------------------------------------------------------


def _audit_cases(outside: Path, tmp: Path) -> dict:
    """Arguments for each event the hook checks, naming targets outside the test,
    in the order CPython raises them. Raising an event does nothing else."""
    victim, src = outside / "victim.txt", tmp / "src"
    ids = (os.getuid(), os.getgid())
    return {
        "open": (outside / "new.txt", "w", os.O_WRONLY | os.O_CREAT),
        "os.remove": (victim, None),
        "os.rmdir": (outside / "victim-dir", None),
        "os.mkdir": (outside / "d", 0o777, None),
        "os.rename": (victim, tmp / "moved", None, None),
        "os.link": (victim, tmp / "hard", None, None),
        "os.symlink": (tmp, outside / "link", None),
        "os.truncate": (victim, 0),
        "os.chmod": (victim, 0o600, None),
        "os.chown": (victim, *ids, None),
        "os.utime": (victim, None, None, None),
        "os.chflags": (victim, 0),
        "os.lchflags": (victim, 0),
        "os.setxattr": (victim, "user.x", b"1", 0),
        "os.removexattr": (victim, "user.x"),
        "shutil.rmtree": (outside / "victim-dir", None),
        "shutil.copyfile": (src, outside / "copy"),
        "shutil.copymode": (src, victim),
        "shutil.copystat": (src, victim),
        "shutil.copytree": (src, outside / "tree"),
        "shutil.move": (victim, tmp / "moved"),
        "shutil.chown": (victim, None, None),
        "shutil.make_archive": (outside / "archive", "zip", None, None),
        "shutil.unpack_archive": (tmp / "a.zip", outside / "unpacked", None),
        "tempfile.mkstemp": (outside / "tmpabcd",),
        "tempfile.mkdtemp": (outside / "tmpabcd",),
        "sqlite3.connect": (outside / "new.db",),
        "socket.connect": (None, ("127.0.0.1", 9)),
        "socket.bind": (None, ("127.0.0.1", 0)),
        "socket.sendto": (None, ("127.0.0.1", 9)),
        "socket.sendmsg": (None, ("127.0.0.1", 9)),
        "socket.getaddrinfo": ("localhost", 80, 0, 0, 0),
        "socket.getnameinfo": (("127.0.0.1", 80), 0),
        "socket.gethostbyname": ("localhost",),
        "socket.gethostbyaddr": ("127.0.0.1",),
        "socket.sethostname": (b"char",),
        "ctypes.dlopen": ("libc.so.6",),
        "ctypes.call_function": (0, ()),
        "ctypes.dlsym": (None, "getpid"),
        "os.system": (b"true",),
        "os.exec": (b"/bin/true", [b"true"], None),
        "os.fork": (),
        "os.forkpty": (),
        "os.posix_spawn": (b"/bin/true", [b"true"], None),
        "os.spawn": (0, b"/bin/true", [b"true"], None),
        "os.startfile": ("x", None),
        "subprocess.Popen": (b"/bin/true", [b"true"], None, None),
        "os.kill": (_harness.FAKE_PID_BASE - 1, 0),
        "os.killpg": (_harness.FAKE_PID_BASE - 1, 0),
        "_posixsubprocess.fork_exec": ([b"/bin/true"], [b"/bin/true"], None, None),
    }


def test_every_audit_entry_has_a_case():
    assert set(_audit_cases(Path("/o"), Path("/t"))) == set(_harness._AUDIT_CHECKS)


@pytest.mark.parametrize("event", sorted(_audit_cases(Path("/o"), Path("/t"))))
def test_every_audit_entry_refuses_its_event(char, outside, tmp_path, event):
    """Raised by hand: many entries are reachable only through an alias the
    function guards miss, so no other test would notice one went missing."""
    (tmp_path / "src").write_text("x\n", encoding="utf-8")
    with pytest.raises(LaunchViolation):
        sys.audit(event, *_audit_cases(outside, tmp_path)[event])
    _unchanged(outside)
    assert len(char.take_violations()) == 1


# -- sockets -----------------------------------------------------------------------


def test_raw_sockets_unix_sockets_and_name_lookups_are_refused(char):
    # Relative to the harness cwd: an AF_UNIX address over 108 bytes fails before
    # the audit event is raised, and pytest's basetemp can be that long.
    path = "s"
    server = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    client = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    try:
        with pytest.raises(LaunchViolation, match="offline"):
            server.bind(path)
        with pytest.raises(LaunchViolation, match="offline"):
            client.connect(path)
    finally:
        server.close()
        client.close()
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sender:
        with pytest.raises(LaunchViolation, match="offline"):
            sender.sendmsg([b"x"], [], 0, path)
    with pytest.raises(LaunchViolation, match="offline"):
        socket.getnameinfo(("127.0.0.1", 80), 0)
    with pytest.raises(LaunchViolation, match="offline"):
        _socket.getaddrinfo("localhost", 80)
    assert len(char.take_violations()) == 5


def _raw_sendto() -> None:
    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    try:
        sock.sendto(b"x", ("127.0.0.1", 9))
    finally:
        sock.close()


@pytest.mark.parametrize(
    "call",
    [
        _raw_sendto,
        lambda: _socket.gethostbyname("localhost"),
        lambda: _socket.gethostbyaddr("127.0.0.1"),
        lambda: _socket.sethostname("char"),
    ],
    ids=["sendto", "gethostbyname", "gethostbyaddr", "sethostname"],
)
def test_the_socket_aliases_reach_the_audit_hook(char, call):
    """_socket holds the functions socket's guards replace by name."""
    with pytest.raises(LaunchViolation, match="offline"):
        call()
    assert len(char.take_violations()) == 1


def test_stdlib_network_clients_are_refused(char):
    with pytest.raises(LaunchViolation):
        urllib.request.urlopen("http://127.0.0.1:9/", timeout=2)
    with pytest.raises(LaunchViolation):
        http.client.HTTPConnection("127.0.0.1", 9, timeout=2).request("GET", "/")
    context = ssl.create_default_context()
    with socket.socket() as raw:
        tls = context.wrap_socket(raw, server_hostname="example.invalid")
        with pytest.raises(LaunchViolation):
            tls.connect(("127.0.0.1", 9))
    with pytest.raises(LaunchViolation):
        asyncio.run(asyncio.open_connection("127.0.0.1", 9))
    assert char.take_violations()


def test_third_party_http_clients_are_refused(char):
    # Imported at collection, so urllib3's IPv6 probe ran there: what is refused
    # here is the request.
    with pytest.raises(LaunchViolation):
        urllib3.PoolManager(retries=False).request(
            "GET", "http://127.0.0.1:9/", timeout=2
        )
    with pytest.raises(LaunchViolation):
        requests.get("http://127.0.0.1:9/", timeout=2)
    client = boto3.client(
        "sts",
        endpoint_url="http://127.0.0.1:9",
        region_name="us-east-1",
        aws_access_key_id="AKIDEXAMPLE",
        aws_secret_access_key="example",
    )
    with pytest.raises(LaunchViolation):
        client.get_caller_identity()
    assert char.take_violations()


# -- imports at collection ---------------------------------------------------------


@pytest.fixture
def watch_only():
    """Leave the import watch as the only check listening, as during collection.

    The events below are raised with ``sys.audit``, so nothing they name happens.
    """
    confine = _harness._CONFINE
    active = confine.active
    confine.active = False
    try:
        yield
    finally:
        confine.active = active


@pytest.mark.parametrize(
    "event, args",
    [
        ("socket.__new__", (None, socket.AF_INET, socket.SOCK_STREAM, 0)),
        ("socket.connect", (None, ("192.0.2.1", 443))),
        ("socket.getaddrinfo", ("example.com", 443, 0, 0, 0)),
        ("subprocess.Popen", ("node", ["node"], None, None)),
        ("os.posix_spawn", ("/bin/true", ["true"], None)),
        ("_posixsubprocess.fork_exec", (["node"], [b"node"], None, None)),
        ("os.kill", (1, signal.SIGKILL)),
    ],
)
def test_an_import_may_not_start_a_process_signal_or_open_a_socket(
    watch_only, event, args
):
    with _harness.watched_imports("a probe module") as refused:
        with pytest.raises(LaunchViolation, match=f"^{event}.*importing a probe"):
            sys.audit(event, *args)
        sys.audit("open", "/etc/hostname", "r", 0)
        sys.audit("import", "json", None, None, None, None)
    assert len(refused) == 1


# -- urllib3's IPv6 probe, the one import-time effect allowed ------------------------

#: urllib3.util.connection as urllib3 2 lays it out: ``_has_ipv6`` makes an IPv6
#: socket and binds it to ("::1", 0), and the module body calls it once, so the probe
#: runs when urllib3 is first imported. The socket is made for real, so
#: ``socket.__new__`` comes from ``socket.socket.__init__`` as it does for urllib3;
#: the bind is raised by hand, so nothing binds.
_FAKE_CONNECTION_SOURCE = """\
import socket, sys, types

def _has_ipv6(host):
    try:
        sock = socket.socket(FAMILY)
    except OSError:  # a host with no sockets of this family at all
        sock = types.SimpleNamespace(
            family=FAMILY, type=socket.SOCK_STREAM, close=lambda: None
        )
    try:
        sys.audit(EVENT, sock, (host, PORT))
    finally:
        sock.close()
    return True

if AT_IMPORT:
    HAS_IPV6 = _has_ipv6(HOST)
"""

_URLLIB3_CONNECTION = "/venv/site-packages/urllib3/util/connection.py"


def _fake_urllib3_connection(
    *,
    host="::1",
    port=0,
    family=socket.AF_INET6,
    event="socket.bind",
    at_import=True,
    name="urllib3.util.connection",
    filename=_URLLIB3_CONNECTION,
):
    """Run the fake connection module's body, as importing it would; return its
    namespace."""
    namespace = {
        "__name__": name,
        "HOST": host,
        "PORT": port,
        "FAMILY": family,
        "EVENT": event,
        "AT_IMPORT": at_import,
    }
    exec(compile(_FAKE_CONNECTION_SOURCE, filename, "exec"), namespace)
    return namespace


@contextlib.contextmanager
def _when_urllib3_is_imported(when):
    """Check what follows as urllib3's first import is checked ``when`` it happens:
    at ``collection`` (the import watch, with the conftest's allowance) or inside a
    ``test`` (the per-test guards). Yields the refusals so far."""
    if when == "collection":
        confine = _harness._CONFINE
        active = confine.active
        confine.active = False
        try:
            with _harness.watched_imports(
                "a pre-import", allowed=[_harness.urllib3_ipv6_probe]
            ) as refused:
                yield refused
        finally:
            confine.active = active
    else:
        refused = []
        try:
            yield refused
        finally:
            refused.extend(_harness.take_violations())


@pytest.mark.parametrize("when", ["collection", "test"])
def test_urllib3s_ipv6_probe_is_allowed_whichever_import_comes_first(when):
    """ASH imports detect-secrets, and through it requests and urllib3, only when it
    builds that scanner: urllib3's first import in a worker can come at collection
    or inside whichever test builds one first."""
    with _when_urllib3_is_imported(when) as refused:
        namespace = _fake_urllib3_connection()
    assert namespace["HAS_IPV6"] is True
    assert refused == []


@pytest.mark.parametrize("when", ["collection", "test"])
def test_the_installed_urllib3s_own_probe_is_allowed(when):
    """The installed urllib3.util.connection, its module body run again as its first
    import runs it: its real socket, bound to ("::1", 0) and closed."""
    import urllib3.util.connection as connection

    try:
        socket.socket(socket.AF_INET6).close()
    except OSError:
        pytest.skip("this host makes no IPv6 socket, so urllib3's probe binds nothing")
    source = Path(connection.__file__).read_text(encoding="utf-8")
    namespace = {
        "__name__": connection.__name__,
        "__package__": connection.__package__,
        "__file__": connection.__file__,
    }
    with _when_urllib3_is_imported(when) as refused:
        exec(compile(source, connection.__file__, "exec"), namespace)
    assert refused == []
    assert namespace["HAS_IPV6"] == connection.HAS_IPV6


def _bind_from_the_test():
    stand_in = types.SimpleNamespace(family=socket.AF_INET6, type=socket.SOCK_STREAM)
    sys.audit("socket.bind", stand_in, ("::1", 0))


def _probe_called_after_the_import():
    namespace = _fake_urllib3_connection(at_import=False)
    namespace["_has_ipv6"]("::1")


@pytest.mark.parametrize("when", ["collection", "test"])
@pytest.mark.parametrize(
    "probe",
    [
        pytest.param(lambda: _fake_urllib3_connection(host="192.0.2.1"), id="address"),
        pytest.param(lambda: _fake_urllib3_connection(port=80), id="port"),
        pytest.param(
            lambda: _fake_urllib3_connection(family=socket.AF_INET), id="ipv4-socket"
        ),
        pytest.param(
            lambda: _fake_urllib3_connection(event="socket.connect"), id="connect"
        ),
        pytest.param(
            lambda: _fake_urllib3_connection(name="lookalike.util.connection"),
            id="another-module",
        ),
        pytest.param(
            lambda: _fake_urllib3_connection(
                filename="/venv/site-packages/lookalike/connection.py"
            ),
            id="another-file",
        ),
        pytest.param(_probe_called_after_the_import, id="after-the-import"),
        pytest.param(_bind_from_the_test, id="from-the-test"),
    ],
)
def test_no_other_bind_or_connect_passes_for_urllib3s_probe(when, probe):
    """Only urllib3's own probe, run by its module body, binding an IPv6 socket to
    port 0 on ::1, is allowed: a bind or connect any other way is refused."""
    with _when_urllib3_is_imported(when) as refused:
        with pytest.raises(LaunchViolation, match=r"socket\.(__new__|bind|connect)"):
            probe()
    assert len(refused) == 1


def test_a_module_whose_import_effect_was_swallowed_fails_to_collect(
    watch_only, request
):
    from tests.unit.characterization import conftest

    module = request.node.parent
    assert isinstance(module, pytest.Module)
    wrapper = conftest.pytest_make_collect_report(module)
    next(wrapper)
    try:
        sys.audit("socket.connect", None, ("192.0.2.1", 443))
    except LaunchViolation:
        pass
    report = types.SimpleNamespace(passed=True, outcome="passed", longrepr=None)
    with pytest.raises(StopIteration) as finished:
        wrapper.send(report)
    assert finished.value.value is report
    assert report.outcome == "failed"
    assert report.longrepr.startswith("socket.connect")
    assert _harness._CONFINE.import_watch is None


# -- C calls -----------------------------------------------------------------------


def test_ctypes_cannot_load_a_library_or_look_up_a_function(char):
    with pytest.raises(LaunchViolation, match="ctypes.dlopen"):
        ctypes.CDLL(None)
    with pytest.raises(LaunchViolation, match="ctypes.dlsym"):
        _PRELOADED_LIBC.getppid
    assert len(char.take_violations()) == 2


@pytest.mark.skipif(
    sys.version_info < (3, 14),
    reason="before Python 3.14 a call through a resolved symbol raises no audit event",
)
def test_ctypes_cannot_call_a_function_looked_up_earlier(char):
    with pytest.raises(LaunchViolation, match="ctypes.call_function"):
        _PRELOADED_GETPID()
    assert len(char.take_violations()) == 1


def _restrictions_in(status_text: str) -> dict[str, str]:
    """The ``Seccomp:``, ``Seccomp_filters:`` and ``NoNewPrivs:`` values in a
    /proc/<pid>/status text. A filter added to a worker that already has one changes
    only the count. Kernels before 5.9 print no ``Seccomp_filters:`` line."""
    found = {}
    for line in status_text.splitlines():
        name, _, value = line.partition(":")
        if name in ("Seccomp", "Seccomp_filters", "NoNewPrivs"):
            found[name] = value.strip()
    return found


def _worker_restrictions() -> dict[str, str] | None:
    """The worker's own, or None where there is no procfs."""
    status = Path("/proc/self/status")
    return _restrictions_in(status.read_text()) if status.exists() else None


def test_the_kernel_restrictions_read_from_a_status_text_name_a_change():
    default_container = (
        "Name:\tpython\nSeccomp:\t2\nSeccomp_filters:\t1\nNoNewPrivs:\t0\n"
    )
    assert _restrictions_in(default_container) == {
        "Seccomp": "2",
        "Seccomp_filters": "1",
        "NoNewPrivs": "0",
    }
    assert _restrictions_in(default_container) == _restrictions_in(default_container)
    tightened = default_container.replace("NoNewPrivs:\t0", "NoNewPrivs:\t1")
    assert _restrictions_in(tightened) != _restrictions_in(default_container)
    # A second filter changes the count and neither of the other two lines.
    filtered = default_container.replace("Seccomp_filters:\t1", "Seccomp_filters:\t2")
    assert _restrictions_in(filtered) != _restrictions_in(default_container)
    # Kernels before 5.9 print no Seccomp_filters line.
    older = "Name:\tpython\nSeccomp:\t2\nNoNewPrivs:\t0\n"
    assert _restrictions_in(older) == {"Seccomp": "2", "NoNewPrivs": "0"}
    assert _restrictions_in("Name:\tpython\n") == {}


def test_landlock_exec_cannot_restrict_the_test_worker(char):
    """A worker under a container's default seccomp profile reads ``Seccomp: 2`` before
    the call, so the lines are compared before and after it rather than with a fixed
    value."""
    before = _worker_restrictions()
    assert before is None or before, (
        "no Seccomp or NoNewPrivs line in /proc/self/status"
    )
    assert isinstance(_landlock_exec.libc, _harness._RefusingLibrary)
    with pytest.raises(LaunchViolation, match=r"landlock_exec\.libc\.prctl"):
        _landlock_exec.exec_with_socket_filter(True, ["anything"])
    assert _worker_restrictions() == before
    assert char.take_violations()


# -- the account's home and defaults bound at import ---------------------------------


def test_with_home_unset_the_account_home_is_the_harness_home(char):
    import getpass
    import pwd

    from automated_security_helper.utils import content_db_refresh, download_utils

    # grype's cache directory is $GRYPE_DB_CACHE_DIR or $XDG_CACHE_HOME when either is
    # set, and the harness sets XDG_CACHE_HOME, so both go too: the home is only
    # asked for when neither names a directory.
    char.set_env(HOME=None, XDG_CACHE_HOME=None, GRYPE_DB_CACHE_DIR=None)
    assert Path.home() == char.home
    assert os.path.expanduser("~/.ash") == str(char.home / ".ash")
    assert pwd.getpwuid(os.getuid()).pw_dir == str(char.home)
    assert getpass.getuser() == "char"
    assert download_utils.receipt_root().is_relative_to(char.home)
    assert content_db_refresh.default_cache_dir("grype").is_relative_to(char.home)


def test_the_dependencies_install_default_is_the_harness_default(char):
    """The option's default is the text of ASH_BIN_PATH, not the Path (a blank value
    must be no value), bound when the module is imported."""
    option = (
        inspect.signature(_dependencies.install_dependencies)
        .parameters["bin_path"]
        .default
    )
    assert option.default == str(char.ash_bin_default)


def test_a_write_to_the_real_ash_bin_directory_is_refused(char):
    target = _harness.REAL_ASH_BIN_PATH / "char-confinement-probe"
    with pytest.raises(LaunchViolation, match="outside the test's directory"):
        open(target, "w")
    assert char.take_violations()


def test_a_module_imported_during_a_test_keeps_nothing_of_it(char_factory, tmp_path):
    name = "automated_security_helper._char_leak_probe"
    module = types.ModuleType(name)
    harness = char_factory(tmp_path / "leak")
    try:
        with harness.active():
            sys.modules[name] = module
            exec(
                "import typer\n"
                "from automated_security_helper.core.constants import ASH_BIN_PATH\n"
                "from automated_security_helper.utils.subprocess_utils import (\n"
                "    path_independent_dirs,\n"
                ")\n"
                "def plain(bin_path=ASH_BIN_PATH):\n"
                "    return bin_path\n"
                "def command(bin_path=typer.Option(ASH_BIN_PATH)):\n"
                "    return bin_path\n",
                module.__dict__,
            )
            assert module.ASH_BIN_PATH == harness.ash_bin_default
            assert (
                module.path_independent_dirs is not _harness.REAL_PATH_INDEPENDENT_DIRS
            )
        real = _harness.REAL_ASH_BIN_PATH
        assert module.ASH_BIN_PATH is real
        assert module.path_independent_dirs is _harness.REAL_PATH_INDEPENDENT_DIRS
        assert module.plain() is real
        option = inspect.signature(module.command).parameters["bin_path"].default
        assert option.default is real
    finally:
        sys.modules.pop(name, None)


def test_a_text_default_of_a_module_imported_during_a_test_keeps_nothing_of_it(
    char_factory, tmp_path
):
    """A default made as ``str(ASH_BIN_PATH)`` at import is the harness home's text
    inside the test and the product's text again after it."""
    name = "automated_security_helper._char_text_leak_probe"
    module = types.ModuleType(name)
    harness = char_factory(tmp_path / "text-leak")
    try:
        with harness.active():
            sys.modules[name] = module
            exec(
                "import typer\n"
                "from automated_security_helper.core.constants import ASH_BIN_PATH\n"
                "def command(bin_path=typer.Option(str(ASH_BIN_PATH))):\n"
                "    return bin_path\n",
                module.__dict__,
            )
            option = inspect.signature(module.command).parameters["bin_path"].default
            assert option.default == str(harness.ash_bin_default)
        option = inspect.signature(module.command).parameters["bin_path"].default
        assert option.default == str(_harness.REAL_ASH_BIN_PATH)
    finally:
        sys.modules.pop(name, None)
