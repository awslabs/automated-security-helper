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
        monkeypatch.setattr(client, "control_request", lambda *_: None)
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
