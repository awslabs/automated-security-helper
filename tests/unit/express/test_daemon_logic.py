# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The daemon's own decisions, tested as decisions: idle exit and scan refusals.

The serve loop, the fork and the sockets belong to the integration and e2e
tiers; what is unit-testable is the policy they consult -- when an idle daemon
retires (:func:`should_idle_exit`) and which requests it refuses with which
staleness (:meth:`ExpressDaemon._scan_refusal`), because the client's
restart-under---express choreography keys on exactly that staleness bit.
"""

import os

import pytest

from automated_security_helper.express import runtime
from automated_security_helper.express.daemon import (
    ExpressDaemon,
    concurrency_cap,
    should_idle_exit,
)

pytestmark = pytest.mark.unit

needs_posix = pytest.mark.skipif(
    not runtime.express_supported(), reason="express mode is unix-only"
)


class TestIdleExit:
    def test_a_daemon_with_a_running_scan_never_retires(self):
        assert not should_idle_exit(
            last_activity=0.0, active_children=1, now=10_000.0, idle_timeout=1.0
        )

    def test_an_idle_daemon_retires_at_the_timeout(self):
        assert should_idle_exit(
            last_activity=100.0,
            active_children=0,
            now=100.0 + 30 * 60,
            idle_timeout=30 * 60,
        )

    def test_an_idle_daemon_inside_the_window_stays(self):
        assert not should_idle_exit(
            last_activity=100.0,
            active_children=0,
            now=100.0 + 29 * 60,
            idle_timeout=30 * 60,
        )

    def test_the_default_window_is_thirty_minutes(self):
        assert runtime.DEFAULT_IDLE_SECONDS == 30 * 60


class TestConcurrencyCap:
    def test_the_cap_is_the_usable_cpu_count_and_at_least_one(self):
        getter = getattr(os, "sched_getaffinity", None)
        expected = len(getter(0)) if getter else max(os.cpu_count() or 1, 1)
        assert concurrency_cap() == max(expected, 1)
        assert concurrency_cap() >= 1

    def test_a_pinned_process_gets_the_pinned_count_not_the_machines(self, monkeypatch):
        """taskset, a cpuset or a container's pinning lowers what can run at
        once; the machine's CPU count would admit far more scans than that."""
        monkeypatch.setattr(os, "sched_getaffinity", lambda pid: {0, 1}, raising=False)
        monkeypatch.setattr(os, "cpu_count", lambda: 64)
        assert concurrency_cap() == 2

    def test_without_affinity_the_cpu_count_stands(self, monkeypatch):
        monkeypatch.delattr(os, "sched_getaffinity", raising=False)
        monkeypatch.setattr(os, "cpu_count", lambda: 6)
        assert concurrency_cap() == 6

    def test_an_unreadable_affinity_falls_back_to_the_cpu_count(self, monkeypatch):
        def refused(pid):
            raise OSError("not permitted")

        monkeypatch.setattr(os, "sched_getaffinity", refused, raising=False)
        monkeypatch.setattr(os, "cpu_count", lambda: 3)
        assert concurrency_cap() == 3


class TestBudgetConsistency:
    def test_the_two_sides_timeouts_nest(self):
        """A slow-but-healthy ok must never read as a dead daemon, and the
        daemon must never outwait a client that is still waiting for it. That
        holds only while the budgets nest: the daemon's whole-handshake stall
        bound under the client's connect budget, and both far under the
        handshake budget that covers the warm-import wall (the one stretch a
        healthy daemon legitimately spends not answering)."""
        from automated_security_helper.express import daemon as daemon_module

        assert (
            daemon_module.INLINE_HANDSHAKE_TIMEOUT_SECONDS
            < runtime.CONNECT_TIMEOUT_SECONDS
            < runtime.HANDSHAKE_TIMEOUT_SECONDS
        )


class _Connection:
    def __init__(self, fds=(10, 11, 12)):
        self.client_fds = list(fds)


@pytest.fixture
def daemon(monkeypatch):
    """A ExpressDaemon that never binds: only its refusal policy is consulted.

    The thread count is pinned to one: the test process itself may run threads
    (an xdist worker does), and the single-thread refusal has its own tests.
    """
    if not runtime.express_supported():
        pytest.skip("express mode is unix-only")
    from automated_security_helper.express import daemon as daemon_module

    monkeypatch.setattr(daemon_module, "_thread_count", lambda: 1)
    built = ExpressDaemon(idle_timeout=60.0)
    try:
        yield built
    finally:
        os.close(built._wakeup_read)
        os.close(built._wakeup_write)
        built.selector.close()


def _request(daemon_instance, **overrides):
    request = {
        "op": "scan",
        "protocol": runtime.PROTOCOL_VERSION,
        "version": daemon_instance.version,
        "fingerprint": daemon_instance.fingerprint,
        "argv": ["scan", "--source-dir", "."],
        "cwd": "/somewhere",
        "env": {"ASH_MODE": "local"},
        "config_hash": None,
    }
    request.update(overrides)
    return request


@needs_posix
class TestScanRefusals:
    def test_a_matching_request_is_not_refused(self, daemon):
        assert daemon._scan_refusal(_request(daemon), _Connection()) is None

    @pytest.mark.parametrize(
        "override",
        [
            {"protocol": 0},
            {"version": "0.0.0-not-this-one"},
            {"fingerprint": "f" * 64},
        ],
    )
    def test_every_staleness_mismatch_is_refused_as_stale(self, daemon, override):
        reason, stale = daemon._scan_refusal(
            _request(daemon, **override), _Connection()
        )
        assert stale is True, reason

    @pytest.mark.parametrize(
        "override",
        [
            {"argv": "scan"},
            {"argv": ["scan", 7]},
            {"cwd": None},
            {"env": ["not", "a", "dict"]},
            {"env": {"KEY": 5}},
        ],
    )
    def test_a_malformed_request_is_refused_and_is_not_stale(self, daemon, override):
        reason, stale = daemon._scan_refusal(
            _request(daemon, **override), _Connection()
        )
        assert stale is False, reason

    def test_missing_descriptors_are_refused_and_are_not_stale(self, daemon):
        reason, stale = daemon._scan_refusal(_request(daemon), _Connection(fds=()))
        assert "descriptors" in reason
        assert stale is False

    def test_the_concurrency_cap_refuses_busy_and_busy_is_not_stale(self, daemon):
        for fake_pid in range(concurrency_cap()):
            daemon.children[100_000 + fake_pid] = object()
        reason, stale = daemon._scan_refusal(_request(daemon), _Connection())
        assert reason.startswith("busy")
        assert stale is False

    def test_a_multi_threaded_daemon_refuses_to_fork_and_says_so(
        self, daemon, monkeypatch
    ):
        """The design is a single-threaded daemon: a warm import that started
        a thread would make every fork a fork of a multi-threaded process.
        Refused with a log line, never forked; the client runs the scan cold."""
        from automated_security_helper.express import daemon as daemon_module

        lines = []
        monkeypatch.setattr(daemon_module, "_thread_count", lambda: 3)
        monkeypatch.setattr(daemon_module, "_log", lines.append)
        reason, stale = daemon._scan_refusal(_request(daemon), _Connection())
        assert "single-threaded" in reason and "3 threads" in reason
        assert stale is False, "a restart would not cure a thread a module starts"
        assert any("refusing to fork" in line for line in lines), lines


@needs_posix
class TestRetiresWhenWarmImportsLeaveThreads:
    def test_the_loop_is_never_entered_and_the_socket_comes_down(
        self, daemon, monkeypatch, tmp_path
    ):
        """A daemon that cannot fork safely serves nobody; staying up would
        refuse every scan. It logs the cause once and exits through shutdown."""
        from automated_security_helper.express import daemon as daemon_module

        lines = []
        shutdowns = []
        monkeypatch.setattr(daemon_module, "warm_imports", list)
        monkeypatch.setattr(daemon_module, "_thread_count", lambda: 2)
        monkeypatch.setattr(daemon_module, "_log", lines.append)
        monkeypatch.setattr(runtime, "socket_path", lambda *a, **k: tmp_path / "x.sock")
        monkeypatch.setattr(daemon, "_shutdown", lambda: shutdowns.append(True))
        monkeypatch.setattr(
            daemon.selector,
            "select",
            lambda timeout=None: pytest.fail("the serve loop must not run"),
        )
        daemon._path = tmp_path / "x.sock"  # what bind() keeps
        daemon.run()
        assert shutdowns == [True]
        assert any("exiting so scans run cold" in line for line in lines), lines
        # The cause is readable beside the socket, for `start` and the backoff.
        assert runtime.recent_retirement(tmp_path / "x.sock") == "threads"

    def test_the_marker_lands_at_the_bound_path_not_a_recomputed_one(
        self, daemon, monkeypatch, tmp_path
    ):
        """socket_path() reads os.environ, which a warm import may have
        changed: recomputed at retirement time it would name a different
        socket, and the client's backoff would never see the marker."""
        from automated_security_helper.express import daemon as daemon_module

        bound = tmp_path / "bound.sock"
        monkeypatch.setattr(daemon_module, "warm_imports", list)
        monkeypatch.setattr(daemon_module, "_thread_count", lambda: 2)
        monkeypatch.setattr(daemon_module, "_log", lambda _m: None)
        monkeypatch.setattr(
            runtime, "socket_path", lambda *a, **k: tmp_path / "other.sock"
        )
        monkeypatch.setattr(daemon, "_shutdown", lambda: None)
        daemon._path = bound
        daemon.run()
        assert runtime.recent_retirement(bound) == "threads"
        assert runtime.recent_retirement(tmp_path / "other.sock") is None

    def test_a_refusing_socket_path_at_retirement_does_not_escape_run(
        self, daemon, monkeypatch, tmp_path
    ):
        from automated_security_helper.express import daemon as daemon_module

        def refuse(*_a, **_k):
            raise runtime.ExpressUnavailable("the runtime directory changed")

        monkeypatch.setattr(daemon_module, "warm_imports", list)
        monkeypatch.setattr(daemon_module, "_thread_count", lambda: 2)
        monkeypatch.setattr(daemon_module, "_log", lambda _m: None)
        monkeypatch.setattr(runtime, "socket_path", refuse)
        monkeypatch.setattr(daemon, "_shutdown", lambda: None)
        daemon._path = tmp_path / "bound.sock"
        daemon.run()  # must return, not raise
        assert runtime.recent_retirement(tmp_path / "bound.sock") == "threads"


class _TickingClock:
    """A monotonic clock that advances by a fixed step on every read."""

    def __init__(self, step):
        self.now = 0.0
        self.step = step

    def monotonic(self):
        self.now += self.step
        return self.now


class _DribblingSock:
    """A peer that returns one byte per recv and never finishes a frame."""

    def __init__(self):
        self.timeouts = []

    def settimeout(self, value):
        self.timeouts.append(value)

    def recv(self, size):
        return b"x"


@needs_posix
class TestWholeHandshakeDeadline:
    """The inline handshake blocks the single-threaded loop, so its bound is a
    deadline for the whole handshake: each read's timeout is shrunk to what
    remains of it, and a peer that dribbles one byte at a time cannot restart
    the clock with every read."""

    def _connection(self, monkeypatch, sock, deadline, step):
        import types

        from automated_security_helper.express import daemon as daemon_module

        # The daemon module's own clock, not the process-wide time.monotonic.
        clock = _TickingClock(step)
        monkeypatch.setattr(
            daemon_module, "time", types.SimpleNamespace(monotonic=clock.monotonic)
        )
        connection = daemon_module._Connection(sock)
        connection.handshake_deadline = deadline
        return connection

    def test_a_dribbling_peer_is_cut_off_at_the_deadline(self, monkeypatch):
        sock = _DribblingSock()
        connection = self._connection(monkeypatch, sock, deadline=1.0, step=0.3)
        with pytest.raises(TimeoutError):
            connection.reader.read_frame()
        # Every read before the cut-off ran on a timeout that only shrank.
        assert sock.timeouts == sorted(sock.timeouts, reverse=True)
        assert sock.timeouts and max(sock.timeouts) <= 1.0

    def test_each_read_gets_only_what_remains(self, monkeypatch):
        sock = _DribblingSock()
        connection = self._connection(monkeypatch, sock, deadline=10.0, step=1.0)
        connection.arm_read()
        connection.arm_read()
        assert sock.timeouts == pytest.approx([9.0, 8.0])

    def test_outside_the_handshake_nothing_is_armed(self, monkeypatch):
        sock = _DribblingSock()
        connection = self._connection(monkeypatch, sock, deadline=None, step=1.0)
        connection.arm_read()
        assert sock.timeouts == []

    def test_the_accept_path_arms_the_deadline_and_clears_it(self, daemon, monkeypatch):
        """_accept sets the deadline before the handshake reads and clears it
        after, so the established connection's non-blocking reads are never
        armed."""
        import socket as socket_module

        seen = {}
        first, second = socket_module.socketpair()
        try:

            class _Listener:
                def accept(self):
                    return first, None

            def fake_handshake(connection):
                seen["connection"] = connection
                seen["deadline"] = connection.handshake_deadline
                connection.close()

            monkeypatch.setattr(daemon, "_handshake", fake_handshake)
            monkeypatch.setattr(runtime, "peer_is_this_user", lambda _s: True)
            daemon._accept(_Listener())
            assert seen["deadline"] is not None
            # Cleared once the handshake returns, so later reads on the
            # established connection are never armed with a spent deadline.
            assert seen["connection"].handshake_deadline is None
        finally:
            second.close()
            first.close()


class _OrderSock:
    """Records sendall payloads, for the acknowledgement-ordering pin."""

    def __init__(self, log):
        self._log = log

    def sendall(self, data) -> None:
        self._log.append(("sent", bytes(data)))

    def fileno(self) -> int:
        return 97

    def close(self) -> None:
        self._log.append(("closed", b""))


class _ScriptedReader:
    """Answers the daemon's inline go read with the scripted frame."""

    def __init__(self, log, frame):
        self._log = log
        self._frame = frame

    def read_frame(self):
        self._log.append(("go-read", b""))
        if isinstance(self._frame, Exception):
            raise self._frame
        return self._frame


@needs_posix
class TestAcknowledgementOrdering:
    def test_ok_is_sent_and_go_is_read_before_the_fork(self, daemon, monkeypatch):
        """The client falls back to a cold run on anything before ok and
        commits by answering the ok with go, so a scan must never exist
        before the go is READ: a client whose handshake timed out mid-fork
        would otherwise run the same scan cold while the forked one wrote
        into its terminal -- the double scan. This pins the order: send ok,
        read go, fork."""
        events: list = []

        def fake_fork():
            events.append(("fork", b""))
            return 54321  # the parent's view; no child exists in this test

        monkeypatch.setattr(os, "fork", fake_fork)
        # Hermetic: the fake fork's pid is fake, so the real setpgid must not
        # run against it -- pid 54321 could be a real process of this user.
        monkeypatch.setattr(os, "setpgid", lambda *a: None)
        read_fd, write_fd = os.pipe()
        spare = os.dup(read_fd)
        connection = _Connection(fds=[read_fd, write_fd, spare])
        connection.child_pid = None
        connection.sock = _OrderSock(events)
        connection.reader = _ScriptedReader(events, {"op": "go"})
        daemon._start_scan(connection, _request(daemon))
        kinds = [kind for kind, _ in events]
        assert kinds.index("sent") < kinds.index("go-read") < kinds.index("fork"), kinds
        sent = next(data for kind, data in events if kind == "sent")
        assert b'"ok":true' in sent
        assert daemon.children.get(54321) is connection


@needs_posix
class TestNoForkForAGoneClient:
    def test_an_undeliverable_ok_means_no_fork(self, daemon, monkeypatch):
        """A client that timed out and fell back cold closed its socket, so
        the pre-fork ok send gets EPIPE -- and then nothing may fork: that
        client is already running the scan cold, and a forked twin would write
        into its terminal beside it."""

        class _GoneSock:
            def sendall(self, data) -> None:
                raise OSError(32, "Broken pipe")

            def fileno(self) -> int:
                return 98

            def close(self) -> None:
                pass

        monkeypatch.setattr(
            os, "fork", lambda: pytest.fail("a gone client must not fork a scan")
        )
        connection = _Connection(fds=[])
        connection.sock = _GoneSock()
        connection.close = lambda: None
        daemon.connections[98] = connection
        daemon._start_scan(connection, _request(daemon))
        assert daemon.children == {}
        assert 98 not in daemon.connections


@needs_posix
class TestNoForkWithoutGo:
    """The ok alone is not the client's commit: an ok delivered into the
    socket buffer in the same instant the client's handshake timeout fires is
    never read, and that client is already running cold. The daemon forks
    only after READING the go frame, so every other answer -- EOF, a timeout,
    a frame that is not the go -- must fork nothing."""

    @pytest.mark.parametrize(
        "go_answer",
        [
            None,  # the client closed without sending go (EOF)
            {"op": "signal", "signum": 15},  # some frame, but never the go
            TimeoutError("timed out"),  # the inline read's socket timeout
        ],
    )
    def test_anything_but_the_go_means_no_fork(self, daemon, monkeypatch, go_answer):
        monkeypatch.setattr(
            os, "fork", lambda: pytest.fail("no fork without the client's go")
        )
        events: list = []
        connection = _Connection(fds=[])
        connection.child_pid = None
        connection.sock = _OrderSock(events)
        connection.reader = _ScriptedReader(events, go_answer)
        connection.close = lambda: None
        daemon.connections[connection.sock.fileno()] = connection
        daemon._start_scan(connection, _request(daemon))
        assert daemon.children == {}
        assert connection.sock.fileno() not in daemon.connections


class TestKillDeadlines:
    """A scan that ignores the hangup's SIGTERM must not hold its concurrency
    slot (and the daemon's idle exit) forever: the discard records a SIGKILL
    deadline, and the run loop's enforcement kills the group past it."""

    def test_a_hangup_discard_records_a_kill_deadline(self, daemon, monkeypatch):
        import signal as signal_module
        import time as time_module

        from automated_security_helper.express import daemon as daemon_module

        signals = []
        monkeypatch.setattr(
            daemon_module, "_signal_scan", lambda pid, sig: signals.append((pid, sig))
        )

        class _DiscardableSock:
            def fileno(self):
                return 99

            def close(self):
                pass

        connection = _Connection(fds=[])
        connection.sock = _DiscardableSock()
        connection.child_pid = 4242
        connection.close = lambda: None
        daemon.connections[99] = connection
        daemon._discard(connection, kill=True)
        assert signals == [(4242, int(signal_module.SIGTERM))]
        assert 4242 in daemon._kill_deadlines
        assert daemon._kill_deadlines[4242] > time_module.monotonic()

    @staticmethod
    def _groups(monkeypatch, alive):
        """Stand-ins for the group probe and the group signal: ``alive`` names
        the group ids that still have a member; every signal is recorded."""
        import signal as signal_module

        from automated_security_helper.express import daemon as daemon_module

        signals = []

        def killpg(pgid, signum):
            if signum == 0:
                if pgid not in alive:
                    raise ProcessLookupError(pgid)
                return
            signals.append((pgid, signum))

        monkeypatch.setattr(os, "killpg", killpg)
        monkeypatch.setattr(
            os, "kill", lambda pid, signum: pytest.fail("no single-pid kill expected")
        )
        return signals, int(signal_module.SIGKILL), daemon_module

    def test_a_survivor_past_the_deadline_is_sigkilled_and_the_entry_dropped(
        self, daemon, monkeypatch
    ):
        signals, sigkill, _ = self._groups(monkeypatch, alive={4242})
        daemon.children[4242] = _Connection(fds=[])
        daemon._kill_deadlines[4242] = 0.0  # long past
        daemon._enforce_kill_deadlines()
        assert signals == [(4242, sigkill)]
        assert 4242 not in daemon._kill_deadlines

    def test_a_group_with_no_member_left_is_dropped_without_a_signal(
        self, daemon, monkeypatch
    ):
        signals, _, _ = self._groups(monkeypatch, alive=set())
        daemon._kill_deadlines[777] = 0.0
        daemon._enforce_kill_deadlines()
        assert signals == []
        assert daemon._kill_deadlines == {}

    def test_a_deadline_still_in_the_future_waits(self, daemon, monkeypatch):
        import time as time_module

        signals, _, _ = self._groups(monkeypatch, alive={4242})
        daemon.children[4242] = _Connection(fds=[])
        daemon._kill_deadlines[4242] = time_module.monotonic() + 60.0
        daemon._enforce_kill_deadlines()
        assert signals == []
        assert 4242 in daemon._kill_deadlines

    def test_the_deadline_outlives_the_leaders_reap_and_kills_the_group(
        self, daemon, monkeypatch
    ):
        """The scan child handled the hangup's SIGTERM and exited at once; a
        scanner subprocess in its group ignored it. The reap must keep the
        entry, and the deadline then SIGKILLs the GROUP (no single-pid
        fallback: the leader's pid number may be recycled)."""
        signals, sigkill, daemon_module = self._groups(monkeypatch, alive={4242})
        connection = _Connection(fds=[])

        class _Sock:
            def sendall(self, data):
                pass

            def fileno(self):
                return 55

            def close(self):
                pass

        connection.sock = _Sock()
        connection.close = lambda: None
        connection.child_pid = 4242
        daemon.children[4242] = connection
        daemon._kill_deadlines[4242] = 0.0
        reapable = [(4242, 0)]
        monkeypatch.setattr(
            os, "waitpid", lambda *_: reapable.pop(0) if reapable else (0, 0)
        )
        daemon._reap()
        assert 4242 not in daemon.children
        assert 4242 in daemon._kill_deadlines, "the reap must keep the group's entry"
        daemon._enforce_kill_deadlines()
        assert signals == [(4242, sigkill)]
        assert daemon._kill_deadlines == {}

    def test_a_new_scan_with_a_recycled_number_clears_the_stale_entry(
        self, daemon, monkeypatch
    ):
        """An old group's entry can outlive its leader's reap by a loop pass;
        a fork that is handed the same number must not inherit its deadline."""
        monkeypatch.setattr(os, "fork", lambda: 4242)
        monkeypatch.setattr(os, "setpgid", lambda *a: None)
        events: list = []
        connection = _Connection(fds=[])
        connection.child_pid = None
        connection.sock = _OrderSock(events)
        connection.reader = _ScriptedReader(events, {"op": "go"})
        daemon._kill_deadlines[4242] = 0.0
        daemon._start_scan(connection, _request(daemon))
        assert daemon.children.get(4242) is connection
        assert 4242 not in daemon._kill_deadlines


@needs_posix
class TestShutdownExitCodes:
    """The shutdown's SIGKILL escalation must never rewrite a real exit: the
    grace loop can end right after a child exited on its own (its deadline is
    checked before another reap would run), and that child's code -- 0, or 1
    with findings, or its own SIGTERM handling -- is the scan's result. Only
    a child the shutdown actually SIGKILLed reports the uniform 143."""

    class _FrameSock:
        def __init__(self, fd):
            self.frames = []
            self._fd = fd

        def sendall(self, data) -> None:
            import json as json_module

            self.frames.append(json_module.loads(bytes(data)))

        def fileno(self) -> int:
            return self._fd

        def close(self) -> None:
            pass

    @pytest.fixture(autouse=True)
    def _hermetic_shutdown(self, monkeypatch, tmp_path):
        """_shutdown re-reads the socket path, which would otherwise mkdir and
        chmod the REAL runtime directory of whoever runs the tests (and raise
        ExpressUnavailable out of a test on a host whose directory is refused);
        the group signal stand-in keeps every fake pid away from a real killpg."""
        from automated_security_helper.express import daemon as daemon_module

        monkeypatch.setattr(runtime, "socket_path", lambda *a, **k: tmp_path / "x.sock")
        self.group_signals = []
        monkeypatch.setattr(
            daemon_module,
            "_signal_group",
            lambda pgid, sig: self.group_signals.append((pgid, sig)),
        )

    def test_a_natural_exit_at_the_deadline_keeps_its_code(self, daemon, monkeypatch):
        import signal as signal_module

        from automated_security_helper.express import daemon as daemon_module

        # The grace window is over the moment it starts: the shape under test
        # is the loop ending between a child's exit and its reap.
        monkeypatch.setattr(runtime, "STOP_GRACE_SECONDS", 0.0)
        exited, sigkilled = _Connection(fds=[]), _Connection(fds=[])
        for fd, connection in ((91, exited), (92, sigkilled)):
            connection.sock = self._FrameSock(fd)
            connection.close = lambda: None
            connection.child_pid = None
        daemon.children[100] = exited
        daemon.children[200] = sigkilled

        # pid 100 already exited 0 on its own; pid 200 dies only of the
        # escalation's SIGKILL (waitstatus 9 = killed by signal 9), which the
        # recorder makes reapable the moment the SIGKILL is actually sent.
        reapable = [(100, 0)]
        signals = []

        def record_signal(pid, sig):
            signals.append((pid, sig))
            if sig == int(signal_module.SIGKILL):
                reapable.append((pid, 9))

        monkeypatch.setattr(daemon_module, "_signal_scan", record_signal)
        monkeypatch.setattr(
            os, "waitpid", lambda *_: reapable.pop(0) if reapable else (0, 0)
        )
        daemon._shutdown()

        assert exited.sock.frames == [{"exit": 0}]
        assert sigkilled.sock.frames == [{"exit": 143}]
        # The exited child was never SIGKILLed as a scan: the pre-escalation
        # reap had already taken it out of children. Its GROUP is still swept
        # (see the next tests), which signals no pid and reports no code.
        assert (100, int(signal_module.SIGKILL)) not in signals
        assert daemon.children == {}

    def test_a_group_whose_leader_exited_in_the_grace_still_gets_the_sigkill(
        self, daemon, monkeypatch
    ):
        """The scan child handled SIGTERM and exited inside the grace; a scanner
        subprocess in its group ignored it. Only unreaped leaders used to be
        SIGKILLed, so that subprocess outlived the daemon."""
        import signal as signal_module

        from automated_security_helper.express import daemon as daemon_module

        connection = _Connection(fds=[])
        connection.sock = self._FrameSock(94)
        connection.close = lambda: None
        connection.child_pid = None
        daemon.children[400] = connection
        reapable = []
        signals = []

        def record_signal(pid, sig):
            signals.append((pid, sig))
            if sig == int(signal_module.SIGTERM):
                reapable.append((400, 0))  # exits on the SIGTERM, inside the grace

        monkeypatch.setattr(daemon_module, "_signal_scan", record_signal)
        monkeypatch.setattr(
            os, "waitpid", lambda *_: reapable.pop(0) if reapable else (0, 0)
        )
        daemon._shutdown()
        assert signals == [(400, int(signal_module.SIGTERM))]
        assert self.group_signals == [(400, int(signal_module.SIGKILL))]
        assert connection.sock.frames == [{"exit": 0}]

    def test_a_pending_hangup_deadline_group_is_killed_at_shutdown(
        self, daemon, monkeypatch
    ):
        """A group a client's hangup already SIGTERMed has its SIGKILL
        deadline pending, with its leader reaped and no entry in children:
        the shutdown must not leave it to a loop that is no longer running."""
        import signal as signal_module

        from automated_security_helper.express import daemon as daemon_module

        monkeypatch.setattr(runtime, "STOP_GRACE_SECONDS", 0.0)
        monkeypatch.setattr(
            daemon_module,
            "_signal_scan",
            lambda pid, sig: pytest.fail("no unreaped child in this test"),
        )
        monkeypatch.setattr(os, "waitpid", lambda *_: (0, 0))
        daemon._kill_deadlines[500] = 1e12
        daemon._shutdown()
        assert self.group_signals == [(500, int(signal_module.SIGKILL))]

    def test_an_unusable_runtime_directory_does_not_abort_the_shutdown(
        self, daemon, monkeypatch
    ):
        """socket_path() re-checks the runtime directory; a refusal there must
        not stop the shutdown that SIGTERMs the running scans."""
        import signal as signal_module

        from automated_security_helper.express import daemon as daemon_module

        def refused(*_a, **_k):
            raise runtime.ExpressUnavailable("the directory became a symlink")

        monkeypatch.setattr(runtime, "socket_path", refused)
        monkeypatch.setattr(runtime, "STOP_GRACE_SECONDS", 0.0)
        signals = []
        monkeypatch.setattr(
            daemon_module, "_signal_scan", lambda pid, sig: signals.append((pid, sig))
        )
        monkeypatch.setattr(os, "waitpid", lambda *_: (0, 0))
        connection = _Connection(fds=[])
        connection.sock = self._FrameSock(95)
        connection.close = lambda: None
        connection.child_pid = None
        daemon.children[600] = connection
        daemon._shutdown()
        assert (600, int(signal_module.SIGTERM)) in signals

    def test_a_child_killed_by_a_signal_reports_128_plus_the_signal(
        self, daemon, monkeypatch
    ):
        """The shell's own convention, outside any shutdown override: an
        express scan whose child dies of SIGKILL reports the 137 a cold run's
        caller would have seen, so the exit code is one more thing warm and
        cold runs cannot disagree on."""
        connection = _Connection(fds=[])
        connection.sock = self._FrameSock(93)
        connection.close = lambda: None
        connection.child_pid = None
        daemon.children[300] = connection
        reapable = [(300, 9)]  # waitstatus 9 = killed by signal 9
        monkeypatch.setattr(
            os, "waitpid", lambda *_: reapable.pop(0) if reapable else (0, 0)
        )
        daemon._reap()
        assert connection.sock.frames == [{"exit": 137}]


class TestAutostartReadiness:
    def test_a_loser_bind_still_tells_the_client_a_daemon_serves(self, monkeypatch):
        """A concurrent autostart loser (pre-commit fires parallel batches, so
        the first commit starts several daemons at once) writes the
        another-daemon-owns-it byte instead of dying silently: its client then
        connects to the winner rather than running cold with a warning."""
        from automated_security_helper.express import daemon as daemon_module

        class _Loser:
            def __init__(self, idle_timeout):
                self.idle_timeout = idle_timeout

            def bind(self):
                # Another daemon holds the socket's lock: the loser answer.
                return False

            def run(self):  # pragma: no cover - the loser must never serve
                raise AssertionError("a loser daemon must not enter the loop")

        monkeypatch.setattr(daemon_module, "ExpressDaemon", _Loser)
        read_fd, write_fd = os.pipe()
        try:
            daemon_module.serve(idle_timeout=1.0, ready_fd=write_fd)
            assert os.read(read_fd, 2) == b"\x02"
        finally:
            os.close(read_fd)
            try:
                os.close(write_fd)
            except OSError:
                pass  # serve closed it, as it must
