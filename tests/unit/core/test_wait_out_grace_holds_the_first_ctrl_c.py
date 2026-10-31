# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The grace wait a shutdown runs is the one ``stop_grace_in_progress`` guards.

Why these tests exist
---------------------
``cancellation.stop_grace_in_progress`` makes a first Ctrl-C latch the
registered scans' cancel instead of raising ``KeyboardInterrupt``, so the
shutdown that is waiting out a tool's grace can finish its SIGKILL. Its own tests entered
the context manager by hand. Nothing in production entered it: the subprocess
layer's ``_wait_out_grace`` never used it, the branch in the SIGINT handler that
reads the count was dead, and a first Ctrl-C during a grace still aborted the
wait before the SIGKILL.

These tests drive the real ``_wait_out_grace`` with a stand-in child whose
``poll`` delivers the Ctrl-C, so the count the handler reads is the one the wait
sets. No signal is raised and no process is started.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

import os
import signal
from typing import List, Optional

import pytest

from automated_security_helper.core import cancellation
from automated_security_helper.core.cancellation import CancelEvent
from automated_security_helper.utils import subprocess_utils

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX"),
]


class _Child:
    """A child that is still running for ``polls_running`` polls, then exits.

    ``on_poll`` runs at the start of each poll, with the count the SIGINT
    handler reads.
    """

    pid = 424242

    def __init__(self, polls_running: int, on_poll=None):
        self._left = polls_running
        self._on_poll = on_poll
        self.returncode: Optional[int] = None
        self.counts: List[int] = []

    def poll(self) -> Optional[int]:
        self.counts.append(cancellation._GRACE_WAITS)
        if self._on_poll is not None:
            self._on_poll()
        if self._left > 0:
            self._left -= 1
            return None
        self.returncode = 0
        return 0


@pytest.fixture
def quiet_handler_state(monkeypatch):
    monkeypatch.setattr(cancellation, "_SIGINT_SEEN", False)
    monkeypatch.setattr(cancellation, "_SIGTERM_SEEN", False)
    monkeypatch.setattr(cancellation, "_SHUTDOWN_REQUESTED", False)
    monkeypatch.setattr(cancellation, "_GRACE_WAITS", 0)


class TestTheGraceWaitCountsItself:
    def test_the_count_is_one_while_it_waits_and_zero_after(self, quiet_handler_state):
        child = _Child(polls_running=2)

        subprocess_utils._wait_out_grace(child, None, 5.0)

        # Red at the base: every read was 0, the wait never entered the context.
        assert child.counts and set(child.counts) == {1}
        assert cancellation._GRACE_WAITS == 0

    def test_the_count_returns_to_zero_when_the_wait_is_interrupted(
        self, quiet_handler_state
    ):
        def interrupted():
            raise KeyboardInterrupt

        child = _Child(polls_running=2, on_poll=interrupted)

        with pytest.raises(KeyboardInterrupt):
            subprocess_utils._wait_out_grace(child, None, 5.0)

        assert cancellation._GRACE_WAITS == 0


class TestAFirstCtrlCInsideTheGraceWaitDoesNotEndIt:
    def test_the_wait_goes_on_and_the_scan_is_latched(
        self, monkeypatch, quiet_handler_state
    ):
        scan = CancelEvent()
        monkeypatch.setattr(cancellation, "_SHUTDOWN_SCOPES", (scan,))

        def chain_default(signum, frame):
            raise KeyboardInterrupt

        monkeypatch.setattr(cancellation, "_PREVIOUS_SIGINT", chain_default)
        delivered = []

        def deliver_once():
            if not delivered:
                delivered.append(True)
                cancellation._handle_sigint(signal.SIGINT, None)

        child = _Child(polls_running=2, on_poll=deliver_once)
        interrupted = False
        try:
            subprocess_utils._wait_out_grace(child, None, 5.0)
        except KeyboardInterrupt:
            interrupted = True

        # Red at the base: the handler chained the default handler from inside
        # the wait, and KeyboardInterrupt ended it before the SIGKILL.
        assert interrupted is False
        assert child.returncode == 0
        assert scan._signalled is True

    def test_with_no_scan_registered_the_first_ctrl_c_still_interrupts(
        self, monkeypatch, quiet_handler_state
    ):
        """The control: nothing reads the latch with no scan registered, so the
        Ctrl-C stays an interrupt even inside the wait."""
        monkeypatch.setattr(cancellation, "_SHUTDOWN_SCOPES", ())

        def chain_default(signum, frame):
            raise KeyboardInterrupt

        monkeypatch.setattr(cancellation, "_PREVIOUS_SIGINT", chain_default)

        child = _Child(
            polls_running=2,
            on_poll=lambda: cancellation._handle_sigint(signal.SIGINT, None),
        )

        with pytest.raises(KeyboardInterrupt):
            subprocess_utils._wait_out_grace(child, None, 5.0)
