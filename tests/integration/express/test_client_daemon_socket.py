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


class _ScriptedDaemon:
    """Accepts one connection and answers with the scripted frames."""

    def __init__(self, path, answers):
        self.path = path
        self.answers = answers
        self.request = None
        self.go_frame = None
        self.received_fds = []
        self.peer_uid = None
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # Bounded accept: a test whose client never connects must leave a
        # thread that ends on its own, not one blocked in accept forever.
        self._server.settimeout(10.0)
        self._server.bind(os.fspath(path))
        self._server.listen(1)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        conn, _ = self._server.accept()
        try:
            self.peer_uid = runtime.peer_uid(conn)
            data, fds, _, _ = socket.recv_fds(conn, 1, 3)
            self.received_fds = list(fds)
            reader = runtime.FrameReader(conn)
            self.request = reader.read_frame()
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
        finally:
            for fd in self.received_fds:
                os.close(fd)
            conn.close()
            self._server.close()


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
        base = tempfile.mkdtemp(prefix="ash-t", dir="/tmp")
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
            {"ASH_MODE": "local", "UNRELATED": "carried", "LD_PRELOAD": "denied"},
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
                super().__init__(path, answers=[])

            def _serve(self):
                conn, _ = self._server.accept()
                try:
                    data, fds, _, _ = socket.recv_fds(conn, 1, 3)
                    self.received_fds = list(fds)
                    reader = runtime.FrameReader(conn)
                    self.request = reader.read_frame()
                    runtime.send_frame(conn, {"ok": True, "pid": 4242})
                    # The go answers the ok first (protocol 2), then the
                    # client blocks on the scan as a real daemon's client
                    # does; the next frame is the forwarded signal.
                    self.go_frame = reader.read_frame()
                    self.signal_frame = reader.read_frame()
                    runtime.send_frame(conn, {"exit": 143})
                finally:
                    for fd in self.received_fds:
                        os.close(fd)
                    conn.close()
                    self._server.close()

        daemon = _SignalAwareDaemon(socket_dir)
        sock = client._connect(socket_dir)
        import signal as signal_module

        timer = threading.Timer(0.2, os.kill, args=(os.getpid(), signal_module.SIGTERM))
        timer.start()
        try:
            outcome = client._run_on_daemon(sock, ["scan"], {}, explicit=False)
        finally:
            timer.cancel()
        daemon.thread.join(timeout=10)
        assert outcome == ("exit", 143)
        assert daemon.signal_frame == {
            "op": "signal",
            "signum": int(signal_module.SIGTERM),
        }

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
