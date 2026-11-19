# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The client against a real unix socket, without a real daemon.

Integration tier (this opens sockets): a scripted server thread speaks the
daemon's side of the protocol at a real socket path, so what is measured is
the client's actual wire behaviour -- the descriptor pass, the request frame,
and each road back to the cold run -- with the daemon's policy replaced by the
script. The real daemon end to end is the e2e tier's job
(test_express_e2e.py).
"""

import json
import os
import socket
import threading

import pytest

from automated_security_helper.express import client, runtime

pytestmark = pytest.mark.integration

if not runtime.express_supported():
    pytest.skip("express mode is unix-only", allow_module_level=True)


#: Every scripted daemon a test started, so the autouse fixture below can join
#: each one and fail the test on anything its thread raised: a script that
#: died early would otherwise leave a client that fell back "correctly" for the
#: wrong reason.
_STARTED: list["_ScriptedDaemon"] = []


class _ScriptedDaemon:
    """Accepts one connection and answers with the scripted frames."""

    def __init__(self, path, answers):
        self.path = path
        self.answers = answers
        self.request = None
        self.go_frame = None
        self.received_fds = []
        self.peer_uid = None
        self.error = None
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # Bounded accept: a test whose client never connects must leave a
        # thread that ends on its own, not one blocked in accept forever.
        self._server.settimeout(10.0)
        self._server.bind(os.fspath(path))
        self._server.listen(1)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        _STARTED.append(self)
        self.thread.start()

    def _serve(self):
        conn = None
        try:
            conn, _ = self._server.accept()
            self._converse(conn)
        except BaseException as exc:  # noqa: BLE001 - recorded, asserted by the fixture
            self.error = exc
        finally:
            for fd in self.received_fds:
                os.close(fd)
            if conn is not None:
                conn.close()
            self._close_listener()

    def _close_listener(self):
        # shutdown first: close alone leaves a thread blocked in accept() on
        # Linux, and its descriptor number free for reuse underneath it.
        try:
            self._server.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._server.close()

    def _read_request(self, conn):
        self.peer_uid = runtime.peer_uid(conn)
        _, fds, _, _ = socket.recv_fds(conn, 1, 3)
        self.received_fds = list(fds)
        reader = runtime.FrameReader(conn)
        self.request = reader.read_frame()
        return reader

    def _converse(self, conn):
        reader = self._read_request(conn)
        for frame in self.answers:
            runtime.send_frame(conn, frame)
            if (
                self.go_frame is None
                and self.request.get("op") == "scan"
                and frame.get("ok")
            ):
                # Protocol 2: the real daemon forks only after reading the
                # client's go, so the script reads it where the daemon
                # would -- right after its scan ok.
                self.go_frame = reader.read_frame()


@pytest.fixture(autouse=True)
def _join_scripted_daemons():
    """Every scripted daemon ends within a timeout and raised nothing."""
    _STARTED.clear()
    yield
    started = list(_STARTED)
    _STARTED.clear()
    for daemon in started:
        daemon.thread.join(timeout=10)
        assert not daemon.thread.is_alive(), "a scripted daemon thread hung"
        assert daemon.error is None, f"the scripted daemon raised: {daemon.error!r}"


@pytest.fixture
def socket_dir():
    """A private socket path of this test's own, short enough for AF_UNIX.

    pytest's tmp_path can be longer than the AF_UNIX name limit (about 104
    bytes), so the socket goes under a short mkdtemp of its own and the path
    length is asserted rather than hoped about. Every test hands this path to
    the client call under test explicitly; nothing here resolves it through
    ``runtime.socket_path``.
    """
    import shutil
    import tempfile

    base = tempfile.mkdtemp(prefix="ash-t")
    if len(base) > 90:
        # A long TMPDIR (a CI lane's, say) overflows the AF_UNIX name cap.
        shutil.rmtree(base, ignore_errors=True)
        base = tempfile.mkdtemp(prefix="ash-t", dir="/tmp")  # nosec B108 - mkdtemp makes a private 0700 dir; the fixed parent keeps the socket path under the AF_UNIX cap
    path = os.path.join(base, "d.sock")
    assert len(path) < 100, path
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass
    try:
        os.unlink(path + ".lock")
    except OSError:
        pass
    os.rmdir(base)


class TestTheWire:
    def test_a_scan_request_carries_fds_argv_cwd_and_the_env_subset(self, socket_dir):
        daemon = _ScriptedDaemon(
            socket_dir, answers=[{"ok": True, "pid": 1}, {"exit": 3}]
        )
        sock = client._connect(socket_dir)
        outcome = client._run_on_daemon(
            sock,
            ["scan", "--source-dir", "."],
            {
                "ASH_MODE": "local",
                "UNRELATED": "carried",
                runtime.CHILD_ENV: "denied",
            },
            explicit=False,
        )
        daemon.thread.join(timeout=10)
        assert outcome == ("exit", 3)
        assert len(daemon.received_fds) == 3
        assert daemon.peer_uid == os.getuid()
        assert daemon.request["op"] == "scan"
        assert daemon.request["argv"] == ["scan", "--source-dir", "."]
        assert daemon.request["cwd"] == os.getcwd()
        # Asserted by names and the one named value, never the mapping itself:
        # a failed assertion prints its operands (tests/utils/env_assertions.py).
        # The request carries the client's whole environment minus the
        # denylist: a name no allowlist would have listed travels too.
        carried_names = sorted(daemon.request["env"])
        assert carried_names == ["ASH_MODE", "UNRELATED"]
        carried_mode = daemon.request["env"].get("ASH_MODE")
        assert carried_mode == "local"
        assert daemon.request["version"] == runtime.ash_version()
        assert daemon.request["fingerprint"] == runtime.runtime_fingerprint()
        assert daemon.request["protocol"] == runtime.PROTOCOL_VERSION
        # The client's commit: the go answered the ok before anything else,
        # which is what lets the daemon fork nothing for a client that fell
        # back cold on a handshake timeout.
        assert daemon.go_frame == {"op": "go"}

    def test_a_stale_refusal_reads_as_stale(self, socket_dir):
        _ScriptedDaemon(
            socket_dir,
            answers=[{"ok": False, "reason": "the daemon is stale", "stale": True}],
        )
        sock = client._connect(socket_dir)
        assert client._run_on_daemon(sock, ["scan"], {}, explicit=False) == (
            "stale",
            None,
        )

    def test_a_busy_refusal_reads_as_plain_fallback(self, socket_dir):
        _ScriptedDaemon(
            socket_dir,
            answers=[{"ok": False, "reason": "busy: 8 scans already running"}],
        )
        sock = client._connect(socket_dir)
        assert client._run_on_daemon(sock, ["scan"], {}, explicit=False) == (
            "fallback",
            None,
        )

    def test_a_daemon_that_hangs_up_before_answering_is_a_fallback(self, socket_dir):
        _ScriptedDaemon(socket_dir, answers=[])
        sock = client._connect(socket_dir)
        assert client._run_on_daemon(sock, ["scan"], {}, explicit=False) == (
            "fallback",
            None,
        )

    def test_a_connection_lost_after_start_is_exit_1_never_a_rerun(
        self, socket_dir, capsys
    ):
        """Once the daemon said started, the scan is running against our own
        streams; a fallback would run it twice. The lost connection is reported
        and read as exit 1."""
        _ScriptedDaemon(socket_dir, answers=[{"ok": True, "pid": 12345}])
        sock = client._connect(socket_dir)
        assert client._run_on_daemon(sock, ["scan"], {}, explicit=False) == ("exit", 1)
        assert "exit code" in capsys.readouterr().err

    def test_a_dead_socket_file_is_removed_and_read_as_no_daemon(self, socket_dir):
        # Bind and close without listening serving: connect gets ECONNREFUSED.
        leftover = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        leftover.bind(os.fspath(socket_dir))
        leftover.close()
        assert client._connect(socket_dir) is None
        assert not os.path.exists(socket_dir)

    def test_control_request_speaks_the_hello_byte_protocol(self, socket_dir):
        daemon = _ScriptedDaemon(
            socket_dir, answers=[{"ok": True, "pid": 7, "active_scans": 0}]
        )
        answer = client.control_request(socket_dir, {"op": "status"})
        daemon.thread.join(timeout=10)
        assert answer == {"ok": True, "pid": 7, "active_scans": 0}
        assert daemon.request == {"op": "status"}
        assert daemon.received_fds == [], "a control request carries no descriptors"

    def test_a_sigterm_after_start_is_forwarded_and_the_exit_is_143(self, socket_dir):
        """The CI-timeout shape: the runner SIGTERMs the client while the scan
        runs on the daemon. The client's handler writes a signal frame (never
        dies itself), the daemon-side script answers with the exit code the
        signalled scan died with, and the client reports exactly that code."""

        class _SignalAwareDaemon(_ScriptedDaemon):
            def __init__(self, path):
                self.signal_frame = None
                # Set once the go frame is read: from then on the client's
                # forwarding handler is installed and stays installed until it
                # has read the exit frame, so a signal sent after this point
                # can only land inside the window under test.
                self.go_read = threading.Event()
                super().__init__(path, answers=[])

            def _converse(self, conn):
                reader = self._read_request(conn)
                runtime.send_frame(conn, {"ok": True, "pid": 4242})
                # The go answers the ok first (protocol 2), then the
                # client blocks on the scan as a real daemon's client
                # does; the next frame is the forwarded signal.
                self.go_frame = reader.read_frame()
                self.go_read.set()
                self.signal_frame = reader.read_frame()
                runtime.send_frame(conn, {"exit": 143})

        daemon = _SignalAwareDaemon(socket_dir)
        sock = client._connect(socket_dir)
        import signal as signal_module

        def deliver_after_the_go():
            # A bounded wait: if the go never arrives the test fails on its
            # outcome below, and nothing is signalled outside the window.
            if daemon.go_read.wait(timeout=10):
                os.kill(os.getpid(), signal_module.SIGTERM)

        # An inherited SIG_IGN (nohup, a background job) would make the client
        # leave SIGTERM ignored: the default disposition is set for the run.
        previous = signal_module.signal(signal_module.SIGTERM, signal_module.SIG_DFL)
        sender = threading.Thread(target=deliver_after_the_go, daemon=True)
        sender.start()
        try:
            outcome = client._run_on_daemon(sock, ["scan"], {}, explicit=False)
        finally:
            signal_module.signal(signal_module.SIGTERM, previous)
        sender.join(timeout=10)
        assert not sender.is_alive()
        daemon.thread.join(timeout=10)
        assert outcome == ("exit", 143)
        assert daemon.signal_frame == {
            "op": "signal",
            "signum": int(signal_module.SIGTERM),
        }

    @pytest.mark.parametrize(
        ("name", "code"), [("SIGINT", 130), ("SIGTERM", 143)], ids=["ctrl-c", "term"]
    )
    def test_a_signal_during_the_handshake_ends_the_run_before_the_go(
        self, socket_dir, name, code
    ):
        """The daemon's ok can take seconds (its warm imports). A Ctrl-C that
        landed meanwhile is only recorded; the client must end with the
        signal's code instead of sending the go, which would have the daemon
        fork a whole scan for the forwarded signal to kill."""
        import signal as signal_module

        signum = getattr(signal_module, name)
        # A background job, nohup or a CI step inherits some of these as
        # SIG_IGN, and the client then leaves them ignored (a cold run would
        # have survived them): the test needs the forwarder installed, so the
        # disposition is made the default for the run and restored after.
        previous_disposition = signal_module.signal(signum, signal_module.SIG_DFL)

        class _InterruptedHandshake(_ScriptedDaemon):
            def _converse(self, conn):
                reader = self._read_request(conn)
                # The request is read, so the client's forwarding handler is
                # installed. Calling it here records the signal exactly as a
                # delivery during the wait would, with no timing to race.
                handler = signal_module.getsignal(signum)
                assert getattr(handler, "__name__", "") == "forward", handler
                handler(int(signum), None)
                runtime.send_frame(conn, {"ok": True, "pid": 4242})
                # The client closes without a go: EOF, not a frame.
                self.go_frame = reader.read_frame()

        daemon = _InterruptedHandshake(socket_dir, answers=[])
        sock = client._connect(socket_dir)
        try:
            outcome = client._run_on_daemon(sock, ["scan"], {}, explicit=False)
        finally:
            signal_module.signal(signum, previous_disposition)
        daemon.thread.join(timeout=10)
        assert outcome == ("exit", code)
        assert daemon.go_frame is None, "no go may follow a recorded signal"

    def test_frames_survive_json_with_non_ascii_values(self, socket_dir):
        argv = ["scan", "--source-dir", "précis"]
        daemon = _ScriptedDaemon(
            socket_dir, answers=[{"ok": True, "pid": 1}, {"exit": 0}]
        )
        sock = client._connect(socket_dir)
        client._run_on_daemon(sock, argv, {}, explicit=False)
        daemon.thread.join(timeout=10)
        assert daemon.request["argv"] == argv
        assert json.dumps(daemon.request)  # round-trippable, not mojibake
