# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Landlock wrapper's own failures, its stop, its reap and its exit, in-process.

A malformed policy or a failed fork exits 126 with an ``ash-landlock:`` line, not
the interpreter's exit 1; a restriction step that raises in the child is reported
as such, not as a failed exec; a stop is passed to the scanner's process group as
the signal ASH sent, with a SIGKILL halfway through the stop budget only for a
scanner that lingers; the reap loop kills a pid only while it is still a
descendant and says which pids outlived the deadline; the wrapper turns core
dumps off before it dies of the scanner's signal; the scan's data is granted read
without exec; and the wrapper enters the policy's working directory. Nothing forks
or restricts: every system call that would is replaced, and the ``no_process_control``
fixture below makes sure of it for every test of this file.
"""

from __future__ import annotations

import errno
import json
import os
import signal
import sys
from types import SimpleNamespace

import pytest

if sys.platform != "linux":
    pytest.skip("the wrapper uses prctl and /proc, Linux only", allow_module_level=True)

# After the guard: the resource module does not exist on Windows, and an import
# above the skip would fail collection there instead of skipping the file.
import resource  # noqa: E402

from automated_security_helper.utils.sandbox import landlock_exec  # noqa: E402

pytestmark = pytest.mark.unit

VALID = json.dumps({"read_only": ["/usr"], "writable": [], "network": False})

#: Every call that would replace, fork, signal or abort the test process. The
#: wrapper's code runs here unforked, kept harmless only by the stubs each test
#: puts in place for the one call it expects; a refactor that reached for a
#: sibling (``execv`` for ``execve``, ``killpg`` or ``raise_signal`` for ``kill``)
#: would otherwise replace the test runner with the scanner's program, which exits
#: 0 and ends a run looking green with its tests unrun, or kill it with the
#: scanner's signal and dump its core. ``getpgid`` acts on nothing, but unstubbed
#: it reads whatever process happens to carry the made-up pid on the host, so the
#: stop's group lookup is stubbed by every test that reaches it too.
#:
#: The pinned kill is in the set as well (``pidfd_open`` and
#: ``signal.pidfd_send_signal`` would pin and kill the host process under the
#: made-up pid), and so are the other ways a process ends or replaces itself or
#: signals a thread (``os._exit``, ``pthread_kill``, ``posix_spawn``, ``forkpty``):
#: ``os._exit`` reached from ``main()`` ends the pytest worker with no report.
_PROCESS_CONTROL = (
    (os, "execv"),
    (os, "execve"),
    (os, "execvp"),
    (os, "execvpe"),
    (os, "execl"),
    (os, "execle"),
    (os, "execlp"),
    (os, "execlpe"),
    (os, "fork"),
    (os, "kill"),
    (os, "killpg"),
    (os, "getpgid"),
    (os, "abort"),
    (os, "_exit"),
    (os, "pidfd_open"),
    (os, "posix_spawn"),
    (os, "posix_spawnp"),
    (os, "forkpty"),
    (signal, "raise_signal"),
    (signal, "pidfd_send_signal"),
    (signal, "pthread_kill"),
    (resource, "setrlimit"),
)


@pytest.fixture(autouse=True)
def no_process_control(monkeypatch):
    """Fail the test at any process-control call it did not stub itself.

    The test's own ``monkeypatch.setattr`` on the one call it expects lands after
    this fixture's and wins; every other call of the set fails the test with the
    call's name instead of acting on the pytest process.

    The wrapper's ``libc`` is replaced too: its ``prctl`` and ``syscall`` set
    no_new_privs, restrict the process with Landlock and install the seccomp
    filter, none of which can be undone, so a main() that reached them (a step
    reordered ahead of the policy check) would restrict the pytest worker for
    every later test. ``resource.setrlimit`` is in the set for the same reason
    (RLIMIT_CORE). A test that needs one of them stubs it, as the fork test does.

    ``pytest.fail`` raises a BaseException, which code under test that wraps its
    work in ``except BaseException`` (the forked child does) turns into its own
    exit, leaving the test to pass on whatever that exit reports. So each refusal
    is also recorded, the fixture yields the list, and it asserts the list empty
    once the test is over. A test that provokes a refusal on purpose clears it.
    """
    reached = []

    def refuse(label):
        def refused(*args, **kwargs):
            reached.append(label)
            pytest.fail(f"{label} reached the test process; stub it in the test")

        return refused

    for module, name in _PROCESS_CONTROL:
        monkeypatch.setattr(
            module, name, refuse(f"{module.__name__}.{name}"), raising=False
        )
    monkeypatch.setattr(
        landlock_exec,
        "libc",
        SimpleNamespace(prctl=refuse("libc.prctl"), syscall=refuse("libc.syscall")),
    )
    yield reached
    assert not reached, f"reached the test process, and swallowed there: {reached}"


@pytest.mark.parametrize(
    "module, name",
    [
        (os, "_exit"),
        (os, "pidfd_open"),
        (os, "posix_spawn"),
        (os, "posix_spawnp"),
        (os, "forkpty"),
        (signal, "raise_signal"),
        (signal, "pidfd_send_signal"),
        (signal, "pthread_kill"),
    ],
)
def test_the_fixture_refuses_each_call_that_ends_or_signals_a_process(
    module, name, no_process_control
):
    """Called with more arguments than the real function takes, so that a call the
    fixture failed to replace raises TypeError and acts on nothing."""
    with pytest.raises(pytest.fail.Exception, match=f"{module.__name__}.{name} "):
        getattr(module, name)(1, 2, 3, 4, 5, 6, 7)
    no_process_control.clear()


def test_the_fixture_refuses_the_calls_that_restrict_the_process(no_process_control):
    """The calls are made with an option and a system call number the kernel
    refuses (EINVAL, ENOSYS) and with too many arguments, so that a call the
    fixture failed to replace restricts nothing."""
    with pytest.raises(pytest.fail.Exception, match="libc.prctl"):
        landlock_exec.libc.prctl(0, 0, 0, 0, 0)
    with pytest.raises(pytest.fail.Exception, match="libc.syscall"):
        landlock_exec.libc.syscall(-1)
    with pytest.raises(pytest.fail.Exception, match="resource.setrlimit"):
        resource.setrlimit(1, 2, 3)
    no_process_control.clear()


def test_a_refusal_the_code_under_test_swallows_is_still_recorded(no_process_control):
    """Too many arguments again, so that a call the fixture failed to replace is a
    TypeError and replaces nothing."""
    try:
        os.execv(1, 2, 3, 4, 5, 6, 7)
    except BaseException:  # noqa: BLE001 - what the forked child's reporting does
        pass

    assert no_process_control == ["os.execv"]
    no_process_control.clear()


class _Exit(BaseException):
    def __init__(self, code):
        self.code = code


@pytest.mark.parametrize(
    "document, said",
    [
        ("{not json", "JSON"),
        (json.dumps({"read_only": []}), "lacks"),
        (json.dumps({"read_only": "x", "writable": [], "network": False}), "list"),
        (json.dumps({"read_only": [], "writable": [], "network": 1}), "bool"),
        (
            json.dumps({"read_only": [], "writable": [], "network": False, "x": 1}),
            "unknown",
        ),
        (json.dumps([]), "object"),
    ],
)
def test_a_malformed_policy_exits_126_with_a_reason(document, said, capsys):
    with pytest.raises(SystemExit) as raised:
        landlock_exec.main(["--policy", document, "--", "/bin/true"])
    assert raised.value.code == 126
    err = capsys.readouterr().err
    assert err.startswith("ash-landlock: ")
    assert said in err


def test_a_fork_that_fails_exits_126(monkeypatch, capsys):
    monkeypatch.setattr(
        landlock_exec, "libc", SimpleNamespace(prctl=lambda *a: 0, syscall=lambda *a: 3)
    )
    monkeypatch.setattr(signal, "pthread_sigmask", lambda *a: None)

    def no_fork():
        raise OSError(errno.EAGAIN, "Resource temporarily unavailable")

    monkeypatch.setattr(os, "fork", no_fork)

    with pytest.raises(SystemExit) as raised:
        landlock_exec.main(["--policy", VALID, "--", "/bin/true"])
    assert raised.value.code == 126
    assert "fork" in capsys.readouterr().err


def test_a_restriction_error_in_the_child_is_reported_as_such(monkeypatch, capsys):
    def exit_(code):
        raise _Exit(code)

    monkeypatch.setattr(os, "_exit", exit_)

    def failing_setup(restrict):
        raise OSError(errno.EPERM, "landlock refused")

    monkeypatch.setattr(landlock_exec, "_child_setup", failing_setup)
    with pytest.raises(_Exit) as raised:
        landlock_exec._run_child(["/bin/true"], lambda: None)
    assert raised.value.code == 126
    err = capsys.readouterr().err
    assert "restricting the scanner" in err
    assert "exec /bin/true" not in err

    monkeypatch.setattr(landlock_exec, "_child_setup", lambda restrict: None)

    def no_exec(path, argv, env):
        raise OSError(errno.ENOENT, "No such file or directory", path)

    monkeypatch.setattr(os, "execve", no_exec)
    with pytest.raises(_Exit) as raised:
        landlock_exec._run_child(["/bin/true"], lambda: None)
    assert raised.value.code == 126
    assert "exec /bin/true" in capsys.readouterr().err


def test_a_pid_no_longer_in_the_tree_is_not_killed(monkeypatch):
    kills = []
    monkeypatch.setattr(os, "kill", lambda pid, sig: kills.append((pid, sig)))
    monkeypatch.setattr(os, "pidfd_open", None, raising=False)
    tree = {os.getpid()}

    monkeypatch.setattr(landlock_exec, "_parent_pid", lambda pid: 1)
    assert landlock_exec._kill_descendant(4242, tree) is False
    monkeypatch.setattr(landlock_exec, "_parent_pid", lambda pid: None)
    assert landlock_exec._kill_descendant(4242, tree) is False
    assert kills == []

    monkeypatch.setattr(landlock_exec, "_parent_pid", lambda pid: os.getpid())
    assert landlock_exec._kill_descendant(4242, tree) is True
    assert kills == [(4242, signal.SIGKILL)]


def test_a_descendant_is_killed_through_its_pinned_descriptor(monkeypatch):
    sent = []
    closed = []
    monkeypatch.setattr(os, "pidfd_open", lambda pid: 42, raising=False)
    monkeypatch.setattr(
        signal,
        "pidfd_send_signal",
        lambda fd, sig: sent.append((fd, sig)),
        raising=False,
    )
    monkeypatch.setattr(os, "close", lambda fd: closed.append(fd))
    monkeypatch.setattr(os, "kill", lambda pid, sig: pytest.fail("kill by number"))
    monkeypatch.setattr(landlock_exec, "_parent_pid", lambda pid: os.getpid())

    assert landlock_exec._kill_descendant(4242, {os.getpid()}) is True
    assert sent == [(42, signal.SIGKILL)]
    assert closed == [42]


def test_the_reap_loop_returns_what_outlived_the_deadline(monkeypatch):
    # The wrapper's own clock, not the process's: three reads inside the deadline,
    # then past it for every read after, however many there are.
    readings = [0.0, 0.0, 0.0]
    clock = SimpleNamespace(
        monotonic=lambda: readings.pop(0) if readings else 5.0,
        sleep=lambda seconds: None,
    )
    monkeypatch.setattr(landlock_exec, "time", clock)
    monkeypatch.setattr(landlock_exec, "_descendants", lambda until=None: [777])
    # The survivors check reads each pid of the last pass: 777 is still there.
    monkeypatch.setattr(landlock_exec, "_parent_pid", lambda pid: os.getpid())
    killed = []
    monkeypatch.setattr(
        landlock_exec,
        "_kill_descendant",
        lambda pid, tree: killed.append((pid, tree)) or False,
    )

    def no_children(pid, options):
        raise ChildProcessError

    monkeypatch.setattr(os, "waitpid", no_children)

    assert landlock_exec._reap_leftovers(lambda: 1.0) == [777]
    assert killed and killed[0][0] == 777 and os.getpid() in killed[0][1]

    monkeypatch.setattr(landlock_exec, "_descendants", lambda until=None: [])
    clock.monotonic = lambda: 0.0
    assert landlock_exec._reap_leftovers(lambda: 1.0) == []


def test_a_stop_is_passed_on_to_the_scanners_group_and_a_lingering_one_is_killed(
    monkeypatch,
):
    """The stop goes to the scanner's process group, as ASH's own stop reaches an
    unwrapped scanner's group, so what the scanner started in it gets the signal
    too; a scanner still leading that group got the signal with it and is not
    signalled a second time by pid; the SIGKILL for a scanner that lingers goes
    the same way, armed halfway through the stop budget so the reap keeps the
    other half."""
    sent = []
    handlers = {}
    timers = []
    monkeypatch.setattr(
        os, "killpg", lambda pgid, sig: sent.append(("group", pgid, sig))
    )
    monkeypatch.setattr(os, "kill", lambda pid, sig: sent.append(("pid", pid, sig)))
    monkeypatch.setattr(os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(
        signal, "signal", lambda signum, handler: handlers.__setitem__(signum, handler)
    )
    monkeypatch.setattr(
        signal, "setitimer", lambda which, seconds: timers.append((which, seconds))
    )
    running = [True]
    stopped_at = []

    landlock_exec._forward_stop(4242, signal.SIGTERM, lambda: running[0], stopped_at)

    assert len(stopped_at) == 1
    assert sent == [("group", 4242, signal.SIGTERM)]
    assert timers == [(signal.ITIMER_REAL, landlock_exec.STOP_KILL_DELAY_SECONDS)]
    assert landlock_exec.STOP_KILL_DELAY_SECONDS == (
        landlock_exec.STOP_REAP_DEADLINE_SECONDS / 2
    )
    handlers[signal.SIGALRM](signal.SIGALRM, None)
    assert sent[1:] == [("group", 4242, signal.SIGKILL)]
    running[0] = False
    handlers[signal.SIGALRM](signal.SIGALRM, None)
    assert len(sent) == 2


def test_a_scanner_that_leads_its_group_is_signalled_once(monkeypatch):
    """A scanner still leading group ``pid`` received the group signal as every
    member did; signalling its pid as well would deliver a handled SIGTERM twice
    (a handler that counts them, or escalates on the second, would see a sequence
    the unwrapped scanner never sees), so the pid is left alone."""
    sent = []
    monkeypatch.setattr(
        os, "killpg", lambda pgid, sig: sent.append(("group", pgid, sig))
    )
    monkeypatch.setattr(os, "kill", lambda pid, sig: sent.append(("pid", pid, sig)))
    monkeypatch.setattr(os, "getpgid", lambda pid: 4242)

    landlock_exec._signal_scanner(4242, signal.SIGTERM)

    assert sent == [("group", 4242, signal.SIGTERM)]


def test_a_scanner_that_left_its_group_is_still_signalled_by_pid(monkeypatch):
    """A scanner that moved itself to another group while its children stayed in
    group ``pid``: the group signal reaches the children (no ESRCH, the group is
    not empty) and would not reach the scanner, which the base always reached by
    pid; its group reads as another, so the pid is signalled as well."""
    sent = []
    monkeypatch.setattr(
        os, "killpg", lambda pgid, sig: sent.append(("group", pgid, sig))
    )
    monkeypatch.setattr(os, "kill", lambda pid, sig: sent.append(("pid", pid, sig)))
    monkeypatch.setattr(os, "getpgid", lambda pid: 4300)

    landlock_exec._signal_scanner(4242, signal.SIGTERM)

    assert sent == [("group", 4242, signal.SIGTERM), ("pid", 4242, signal.SIGTERM)]


def test_a_group_or_a_scanner_that_is_gone_is_passed_over(monkeypatch):
    """Until the child's setsid no process group carries its pid, and a scanner
    reaped between the check and the signal, or between the group signal and the
    group lookup, is gone too: ESRCH from any of the three calls is passed over
    and what can still be sent is sent. Any other refusal is the caller's to read,
    as before."""
    kills = []

    def no_such_group(pgid, sig):
        raise ProcessLookupError(errno.ESRCH, "No such process")

    monkeypatch.setattr(os, "killpg", no_such_group)
    monkeypatch.setattr(os, "getpgid", lambda pid: 4300)
    monkeypatch.setattr(os, "kill", lambda pid, sig: kills.append((pid, sig)))
    landlock_exec._signal_scanner(4242, signal.SIGTERM)
    assert kills == [(4242, signal.SIGTERM)]

    group_kills = []

    def no_such_process(*args):
        raise ProcessLookupError(errno.ESRCH, "No such process")

    monkeypatch.setattr(os, "killpg", lambda pgid, sig: group_kills.append((pgid, sig)))
    monkeypatch.setattr(os, "kill", no_such_process)
    landlock_exec._signal_scanner(4242, signal.SIGTERM)
    assert group_kills == [(4242, signal.SIGTERM)]

    # Reaped between the group signal and the group lookup: nothing more is sent.
    monkeypatch.setattr(os, "getpgid", no_such_process)
    monkeypatch.setattr(os, "kill", lambda pid, sig: pytest.fail("kill after ESRCH"))
    landlock_exec._signal_scanner(4242, signal.SIGTERM)
    assert group_kills == [(4242, signal.SIGTERM)] * 2

    def refused(pgid, sig):
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "killpg", refused)
    monkeypatch.setattr(os, "kill", lambda pid, sig: kills.append((pid, sig)))
    with pytest.raises(PermissionError):
        landlock_exec._signal_scanner(4242, signal.SIGTERM)
    assert kills == [(4242, signal.SIGTERM)], "nothing more was sent after EPERM"


def test_dying_of_the_scanners_signal_turns_core_dumps_off_first(monkeypatch):
    events = []
    monkeypatch.setattr(
        resource,
        "setrlimit",
        lambda which, limits: events.append(("rlimit", which, limits)),
    )
    monkeypatch.setattr(os, "kill", lambda pid, sig: events.append(("kill", pid, sig)))
    monkeypatch.setattr(signal, "signal", lambda signum, handler: None)
    monkeypatch.setattr(signal, "pthread_sigmask", lambda how, signals: None)

    assert landlock_exec._die_of(signal.SIGSEGV) == 128 + signal.SIGSEGV

    assert events[0] == ("rlimit", resource.RLIMIT_CORE, (0, 0))
    assert events[1] == ("kill", os.getpid(), signal.SIGSEGV)


def test_the_scans_data_is_granted_read_without_exec(monkeypatch):
    rules = []
    monkeypatch.setattr(
        landlock_exec,
        "add_path_rule",
        lambda fd, path, access: rules.append((path, access)),
    )

    class _Os:
        def __getattr__(self, name):
            return getattr(os, name)

        @staticmethod
        def close(fd):
            pass

    monkeypatch.setattr(landlock_exec, "os", _Os())
    monkeypatch.setattr(
        landlock_exec,
        "libc",
        SimpleNamespace(
            syscall=lambda nr, *a: (
                7 if nr == landlock_exec.SYS_LANDLOCK_CREATE_RULESET else 0
            )
        ),
    )

    landlock_exec.apply_landlock(
        {
            "read_only": ["/a"],
            "read_data": ["/b"],
            "writable": ["/c"],
            "network": False,
        },
        abi=3,
    )

    rights = dict(rules)
    read = landlock_exec.FS_READ_FILE | landlock_exec.FS_READ_DIR
    assert rights["/a"] == read | landlock_exec.FS_EXECUTE
    assert rights["/b"] == read
    assert rights["/c"] & landlock_exec.FS_WRITE_FILE


def test_the_wrapper_enters_the_policys_working_directory(monkeypatch, capsys):
    entered = []
    monkeypatch.setattr(os, "chdir", lambda path: entered.append(path))
    landlock_exec._enter_policy_cwd({"cwd": "/private/tmp"})
    landlock_exec._enter_policy_cwd({})
    assert entered == ["/private/tmp"]

    def refuse(path):
        raise OSError(errno.ENOENT, "gone", path)

    monkeypatch.setattr(os, "chdir", refuse)
    with pytest.raises(SystemExit) as raised:
        landlock_exec._enter_policy_cwd({"cwd": "/gone"})
    assert raised.value.code == 126
    assert "working directory" in capsys.readouterr().err
