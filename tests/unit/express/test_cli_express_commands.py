# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ``ash express`` command layer's own judgments, driven through typer.

Unit tier (no real daemon): ``client`` and ``runtime`` are monkeypatched at
their modules, which the commands import lazily, so what is measured is the
command layer itself -- how ``stop`` and ``status`` tell "no daemon" from
"something holds the socket and did not answer", and which launch path
``start`` takes. The wire and the real daemon belong to the integration and
e2e tiers.
"""

import json
import os

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.express import express_app
from automated_security_helper.express import client, runtime

pytestmark = pytest.mark.unit

needs_posix = pytest.mark.skipif(
    not runtime.express_supported(), reason="express mode is unix-only"
)

runner = CliRunner()


def _all_output(result) -> str:
    """stdout plus stderr, across click versions that split or mix them."""
    try:
        return result.output + result.stderr
    except ValueError:
        return result.output


@pytest.fixture
def socket_path(tmp_path, monkeypatch):
    path = tmp_path / "d.sock"
    monkeypatch.setattr(runtime, "socket_path", lambda: path)
    return path


@needs_posix
class TestWedgedSocketReporting:
    """``control_request``'s None means nothing ANSWERED, which is "no daemon"
    only when nothing holds the socket either. A wedged daemon (stuck imports,
    SIGSTOP, a foreign holder) leaves the socket file -- or, wedged between
    taking its lock and binding, only the lock -- in place, every implicit
    scan pays the connect timeout against it, and "no express daemon is
    running" would be a lie a script acts on."""

    def test_status_on_a_silent_but_held_socket_exits_nonzero(
        self, socket_path, monkeypatch
    ):
        socket_path.touch()
        monkeypatch.setattr(client, "control_request", lambda *_: None)
        result = runner.invoke(express_app, ["status"])
        assert result.exit_code == 1
        assert "did not answer" in _all_output(result)

    def test_status_json_distinguishes_unanswered_from_not_running(
        self, socket_path, monkeypatch
    ):
        socket_path.touch()
        monkeypatch.setattr(client, "control_request", lambda *_: None)
        result = runner.invoke(express_app, ["status", "--json"])
        assert result.exit_code == 1
        assert json.loads(result.output) == {
            "running": False,
            "answered": False,
            "socket_exists": True,
            "socket": os.fspath(socket_path),
        }

    def test_a_held_lock_with_no_socket_file_still_reads_as_wedged(
        self, socket_path, monkeypatch
    ):
        """A daemon wedged between taking its lock and binding leaves no
        socket file; the lock is the only trace, and it is enough. The holder
        here is a real flock: flock locks belong to the open file description,
        so a second open in this same process genuinely contends."""
        import fcntl

        monkeypatch.setattr(client, "control_request", lambda *_: None)
        holder = os.open(
            os.fspath(socket_path) + ".lock", os.O_WRONLY | os.O_CREAT, 0o600
        )
        try:
            fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = runner.invoke(express_app, ["status", "--json"])
        finally:
            os.close(holder)
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["answered"] is False
        assert payload["socket_exists"] is False

    def test_a_truly_absent_daemon_reads_as_not_running(self, socket_path, monkeypatch):
        """No socket file, no held lock: plain not-running, with no wedged
        wording for an operator to chase."""
        monkeypatch.setattr(client, "control_request", lambda *_: None)
        result = runner.invoke(express_app, ["status", "--json"])
        assert result.exit_code == 1
        assert json.loads(result.output) == {
            "running": False,
            "socket": os.fspath(socket_path),
        }

    def test_stop_on_a_silent_but_held_socket_exits_nonzero(
        self, socket_path, monkeypatch
    ):
        socket_path.touch()
        monkeypatch.setattr(client, "control_request", lambda *_: None)
        result = runner.invoke(express_app, ["stop"])
        assert result.exit_code == 1
        assert "did not answer the stop" in _all_output(result)

    def test_stop_with_no_daemon_at_all_succeeds_quietly(
        self, socket_path, monkeypatch
    ):
        monkeypatch.setattr(client, "control_request", lambda *_: None)
        result = runner.invoke(express_app, ["stop"])
        assert result.exit_code == 0
        assert "no express daemon is running" in _all_output(result)


@needs_posix
class TestStartLaunchPath:
    def test_start_spawns_a_fresh_interpreter_never_a_bare_fork(
        self, socket_path, tmp_path, monkeypatch
    ):
        """``ash express start`` runs after the whole CLI import, with typer,
        rich, the logging stack and main's signal handlers live, so a bare
        fork would carry all of that (and any lock an import holds) into the
        daemon. This path must launch a fresh interpreter; autostart's double
        fork stays the implicit scan path's, which runs before the heavy
        import (see cli/entrypoint.py)."""
        calls = []
        # Nothing answers before the spawn; after it, the new daemon does.
        monkeypatch.setattr(
            client,
            "control_request",
            lambda *_, **__: _matching_status() if "spawn" in calls else None,
        )
        monkeypatch.setattr(
            client,
            "autostart",
            lambda *_: pytest.fail("start must not bare-fork the daemon"),
        )
        monkeypatch.setattr(
            client,
            "spawn_daemon_process",
            lambda environ: calls.append("spawn") or True,
        )

        class _Sock:
            def close(self):
                calls.append("closed")

        monkeypatch.setattr(client, "await_daemon", lambda path: _Sock())
        monkeypatch.setattr(runtime, "log_path", lambda: tmp_path / "express.log")
        result = runner.invoke(express_app, ["start"])
        assert result.exit_code == 0, _all_output(result)
        assert calls == ["spawn", "closed"]
        assert "express daemon started" in _all_output(result)

    def test_a_spawn_that_never_serves_is_reported_with_the_log_path(
        self, socket_path, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(client, "control_request", lambda *_: None)
        monkeypatch.setattr(client, "spawn_daemon_process", lambda environ: False)
        monkeypatch.setattr(
            client,
            "await_daemon",
            lambda path: pytest.fail("a failed spawn must not be awaited"),
        )
        monkeypatch.setattr(runtime, "log_path", lambda: tmp_path / "express.log")
        result = runner.invoke(express_app, ["start"])
        assert result.exit_code == 1
        assert "did not come up" in _all_output(result)


def _matching_status(**overrides):
    """A healthy daemon's status answer for THIS installation."""
    status = {
        "ok": True,
        "pid": 4242,
        "fingerprint": runtime.runtime_fingerprint(),
        "protocol": runtime.PROTOCOL_VERSION,
        "active_scans": 0,
        "scans_served": 0,
    }
    status.update(overrides)
    return status


def _stale_status(**overrides):
    return _matching_status(fingerprint="f" * 64, **overrides)


class _Closable:
    def close(self):
        pass


@needs_posix
class TestStartVerifiesWhatItClaims:
    """``start`` may print "started" only for a daemon this installation's
    scans can use, and may replace a stale one only once it is really gone:
    ``stop_daemon`` returns quietly on no answer and on timeout, and the
    readiness probe accepts a concurrent winner's byte, so success could
    otherwise be printed while the old daemon still served."""

    def _wire(self, monkeypatch, tmp_path, answers):
        """control_request answers from ``answers`` in order, then repeats the
        last; the spawn and the stop are recorded."""
        calls = []
        queue = list(answers)

        def control(path, frame, timeout=None):
            calls.append(("control", frame["op"]))
            self.timeouts.append(timeout)
            return queue.pop(0) if len(queue) > 1 else queue[0]

        self.timeouts = []

        monkeypatch.setattr(client, "control_request", control)
        monkeypatch.setattr(client, "stop_daemon", lambda path: calls.append("stop"))
        monkeypatch.setattr(
            client,
            "spawn_daemon_process",
            lambda environ: calls.append("spawn") or True,
        )
        monkeypatch.setattr(client, "await_daemon", lambda path: _Closable())
        monkeypatch.setattr(client, "daemon_lock_is_held", lambda path: False)
        monkeypatch.setattr(runtime, "log_path", lambda: tmp_path / "express.log")
        return calls

    def test_the_post_start_status_query_waits_the_handshake_budget(
        self, socket_path, tmp_path, monkeypatch
    ):
        """A fresh daemon answers only after its warm imports (the handshake
        budget, 30 s), so the query that decides "started" must not use the
        connect probe's few seconds. A hermetic slow-import daemon is not
        feasible in the unit tier; this pins the timeout the start path asks
        for, and the client test below pins that control_request applies it."""
        self._wire(monkeypatch, tmp_path, [None, _matching_status()])
        result = runner.invoke(express_app, ["start"])
        assert result.exit_code == 0, _all_output(result)
        # The first query is the pre-start probe (default timeout); the one
        # after the spawn carries the handshake budget.
        assert self.timeouts[0] is None
        assert self.timeouts[-1] == runtime.HANDSHAKE_TIMEOUT_SECONDS
        assert runtime.HANDSHAKE_TIMEOUT_SECONDS > runtime.CONNECT_TIMEOUT_SECONDS

    def test_a_daemon_that_retired_over_threads_is_named_as_the_cause(
        self, socket_path, tmp_path, monkeypatch
    ):
        self._wire(monkeypatch, tmp_path, [None, None])
        runtime.mark_retired_for_threads(socket_path)
        result = runner.invoke(express_app, ["start"])
        assert result.exit_code == 1, _all_output(result)
        output = _all_output(result)
        assert "retired itself" in output and "extra threads" in output
        assert "fingerprint" not in output
        assert "express daemon started" not in output

    def test_a_stale_daemon_that_survives_the_stop_is_a_failure_not_a_start(
        self, socket_path, tmp_path, monkeypatch
    ):
        # status -> stale idle daemon; after the stop it STILL answers.
        calls = self._wire(monkeypatch, tmp_path, [_stale_status(), _stale_status()])
        result = runner.invoke(express_app, ["start"])
        assert result.exit_code == 1, _all_output(result)
        assert "still there after the stop" in _all_output(result)
        assert "spawn" not in calls, "nothing may be spawned over a live daemon"
        assert "express daemon started" not in _all_output(result)

    def test_a_stale_daemon_whose_lock_is_still_held_is_a_failure(
        self, socket_path, tmp_path, monkeypatch
    ):
        calls = self._wire(monkeypatch, tmp_path, [_stale_status(), None])
        monkeypatch.setattr(client, "daemon_lock_is_held", lambda path: True)
        result = runner.invoke(express_app, ["start"])
        assert result.exit_code == 1, _all_output(result)
        assert "spawn" not in calls

    def test_a_stale_daemon_that_is_gone_is_replaced_and_verified(
        self, socket_path, tmp_path, monkeypatch
    ):
        # stale daemon; gone after the stop; the spawned one answers matching.
        calls = self._wire(
            monkeypatch, tmp_path, [_stale_status(), None, _matching_status()]
        )
        result = runner.invoke(express_app, ["start"])
        assert result.exit_code == 0, _all_output(result)
        assert calls.index("stop") < calls.index("spawn")
        assert "express daemon started" in _all_output(result)

    @pytest.mark.parametrize(
        "after",
        [
            _stale_status(),
            _matching_status(protocol=runtime.PROTOCOL_VERSION + 1),
            {"ok": False, "reason": "not a daemon"},
            None,
        ],
        ids=["old-fingerprint", "old-protocol", "not-ok", "silent"],
    )
    def test_a_start_that_ends_with_the_wrong_daemon_is_not_reported_started(
        self, socket_path, tmp_path, monkeypatch, after
    ):
        """The socket answered the readiness probe, but what answers a status
        query afterwards is not a daemon this installation's scans can use."""
        self._wire(monkeypatch, tmp_path, [None, after])
        result = runner.invoke(express_app, ["start"])
        assert result.exit_code == 1, _all_output(result)
        assert "express daemon started" not in _all_output(result)
        assert "not one this installation's scans can use" in _all_output(result)


@needs_posix
class TestForegroundStartsAsADaemonWould:
    def test_the_environment_is_scrubbed_and_signal_handlers_are_reset(
        self, socket_path, monkeypatch
    ):
        import signal

        from automated_security_helper.express import daemon as daemon_module
        from automated_security_helper.utils.process_env import snapshot_environ

        monkeypatch.setattr(client, "control_request", lambda *_: None)
        monkeypatch.setenv("GIT_INDEX_FILE", ".git/index.hook")
        monkeypatch.setenv("AWS_PROFILE", "prod")
        monkeypatch.setenv(runtime.IDLE_ENV, "120")
        seen = {}

        def fake_serve(idle_timeout=None, ready_fd=None):
            env = snapshot_environ()
            seen["names"] = sorted(env)
            seen["idle"] = idle_timeout
            seen["sigint"] = signal.getsignal(signal.SIGINT)
            seen["sigterm"] = signal.getsignal(signal.SIGTERM)

        monkeypatch.setattr(daemon_module, "serve", fake_serve)
        previous = {
            number: signal.getsignal(number)
            for number in (signal.SIGINT, signal.SIGTERM)
        }
        # What the CLI's own startup leaves installed.
        signal.signal(signal.SIGINT, lambda *_: None)
        signal.signal(signal.SIGTERM, lambda *_: None)
        # The command mutates the real process environment (its job); the
        # fixture-restored copy puts it back for the tests after this one.
        saved = dict(os.environ)
        try:
            result = runner.invoke(express_app, ["start", "--foreground"])
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)
            os.environ.clear()
            os.environ.update(saved)
        assert result.exit_code == 0, _all_output(result)
        assert "GIT_INDEX_FILE" not in seen["names"]
        assert "AWS_PROFILE" not in seen["names"]
        assert runtime.IDLE_ENV in seen["names"]
        assert seen["idle"] == 120
        assert seen["sigint"] is signal.SIG_DFL
        assert seen["sigterm"] is signal.SIG_DFL
