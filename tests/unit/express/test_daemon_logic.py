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

    def close(self) -> None:
        self._log.append(("closed", b""))


@needs_posix
class TestAcknowledgementOrdering:
    def test_the_ok_frame_is_on_the_wire_before_the_fork(self, daemon, monkeypatch):
        """The client falls back to a cold run on anything before ok and
        commits on ok, so a scan must never exist before the ok is sent: a
        client whose handshake timed out mid-fork would otherwise run the same
        scan cold while the forked one wrote into its terminal -- the double
        scan. This pins the order: send ok, then fork."""
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
        daemon._start_scan(connection, _request(daemon))
        kinds = [kind for kind, _ in events]
        assert kinds.index("sent") < kinds.index("fork"), kinds
        sent = next(data for kind, data in events if kind == "sent")
        assert b'"ok":true' in sent
        assert daemon.children.get(54321) is connection
