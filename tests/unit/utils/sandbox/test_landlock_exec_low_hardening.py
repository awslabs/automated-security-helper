# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Landlock wrapper's own failures, its stop, its reap and its exit, in-process.

A malformed policy or a failed fork exits 126 with an ``ash-landlock:`` line, not
the interpreter's exit 1; a restriction step that raises in the child is reported
as such, not as a failed exec; a stop is passed to the scanner as the signal ASH
sent, with a SIGKILL only for a scanner that lingers; the reap loop kills a pid
only while it is still a descendant and says which pids outlived the deadline;
the wrapper turns core dumps off before it dies of the scanner's signal; the
scan's data is granted read without exec; and the wrapper enters the policy's
working directory. Nothing forks or restricts: every system call that would is
replaced.
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


def test_a_stop_is_passed_on_as_sent_and_a_lingering_scanner_is_killed(monkeypatch):
    kills = []
    handlers = {}
    timers = []
    monkeypatch.setattr(os, "kill", lambda pid, sig: kills.append((pid, sig)))
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
    assert kills == [(4242, signal.SIGTERM)]
    assert timers == [(signal.ITIMER_REAL, landlock_exec.STOP_REAP_DEADLINE_SECONDS)]
    handlers[signal.SIGALRM](signal.SIGALRM, None)
    assert kills == [(4242, signal.SIGTERM), (4242, signal.SIGKILL)]
    running[0] = False
    handlers[signal.SIGALRM](signal.SIGALRM, None)
    assert len(kills) == 2


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
