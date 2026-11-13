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
    def test_the_cap_is_the_cpu_count_and_at_least_one(self):
        assert concurrency_cap() == max(os.cpu_count() or 1, 1)
        assert concurrency_cap() >= 1


class TestBudgetConsistency:
    def test_the_two_sides_timeouts_nest(self):
        """A slow-but-healthy ok must never read as a dead daemon, and the
        daemon must never outwait a client that is still waiting for it. That
        holds only while the budgets nest: the daemon's inline per-read stall
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
def daemon():
    """A ExpressDaemon that never binds: only its refusal policy is consulted."""
    if not runtime.express_supported():
        pytest.skip("express mode is unix-only")
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

    def test_a_survivor_past_the_deadline_is_sigkilled_and_the_entry_dropped(
        self, daemon, monkeypatch
    ):
        import signal as signal_module

        from automated_security_helper.express import daemon as daemon_module

        signals = []
        monkeypatch.setattr(
            daemon_module, "_signal_scan", lambda pid, sig: signals.append((pid, sig))
        )
        connection = _Connection(fds=[])
        daemon.children[4242] = connection
        daemon._kill_deadlines[4242] = 0.0  # long past
        daemon._enforce_kill_deadlines()
        assert signals == [(4242, int(signal_module.SIGKILL))]
        assert 4242 not in daemon._kill_deadlines

    def test_a_reaped_pid_is_dropped_without_a_signal(self, daemon, monkeypatch):
        from automated_security_helper.express import daemon as daemon_module

        monkeypatch.setattr(
            daemon_module,
            "_signal_scan",
            lambda pid, sig: pytest.fail("a reaped pid must not be signalled"),
        )
        daemon._kill_deadlines[777] = 0.0  # pid no longer in children
        daemon._enforce_kill_deadlines()
        assert daemon._kill_deadlines == {}

    def test_a_deadline_still_in_the_future_waits(self, daemon, monkeypatch):
        import time as time_module

        from automated_security_helper.express import daemon as daemon_module

        monkeypatch.setattr(
            daemon_module,
            "_signal_scan",
            lambda pid, sig: pytest.fail("the grace is not over yet"),
        )
        connection = _Connection(fds=[])
        daemon.children[4242] = connection
        daemon._kill_deadlines[4242] = time_module.monotonic() + 60.0
        daemon._enforce_kill_deadlines()
        assert 4242 in daemon._kill_deadlines


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
        # The exited child was never SIGKILLed: the pre-escalation reap had
        # already taken it out of children.
        assert (100, int(signal_module.SIGKILL)) not in signals
        assert daemon.children == {}

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
