# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The die-now kill reaches only a live child, and a first Ctrl-C does not abort
a stop that is waiting out a tool's grace.

* ``_kill_recorded_groups`` falls back from ``killpg`` to ``os.kill`` on the
  recorded id, for a child recorded before its setsid. A group id left recorded
  after its child was reaped is a pid another process can hold by now, and the
  fallback kill landed on it. The fallback now asks ``waitpid(WNOHANG)`` first.
* A stop a timeout began (SIGTERM sent, grace being waited out, SIGKILL to
  follow) is not a signal, so a first Ctrl-C found neither latch set and chained
  the default handler, which raised KeyboardInterrupt inside the grace wait and
  aborted the escalation. Inside ``stop_grace_in_progress`` the first Ctrl-C
  latches the cancel and returns.

No signal is raised and no child is started: the kill function and the handler
are called directly with the module's records patched.
"""

from __future__ import annotations

import os
import signal

import pytest

from automated_security_helper.core import cancellation

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX"),
]


class TestTheDieNowFallbackKillsOnlyALiveChild:
    def test_a_reaped_pid_is_not_killed(self, monkeypatch):
        killed = []
        monkeypatch.setattr(
            os, "killpg", lambda pgid, sig: (_ for _ in ()).throw(ProcessLookupError())
        )
        monkeypatch.setattr(os, "kill", lambda pid, sig: killed.append((pid, sig)))

        def not_our_child(pid, flags):
            raise ChildProcessError

        monkeypatch.setattr(os, "waitpid", not_our_child)
        monkeypatch.setattr(cancellation, "_TOOL_GROUPS", (424242,))
        monkeypatch.setattr(cancellation, "_TOOL_PIDS", ())

        cancellation._kill_recorded_groups()

        # Red at the base: the fallback killed whatever held the pid.
        assert killed == []

    def test_a_live_child_that_leads_no_group_is_still_killed(self, monkeypatch):
        """The control: the fallback the launcher child relies on still fires."""
        killed = []
        monkeypatch.setattr(
            os, "killpg", lambda pgid, sig: (_ for _ in ()).throw(ProcessLookupError())
        )
        monkeypatch.setattr(os, "kill", lambda pid, sig: killed.append((pid, sig)))
        monkeypatch.setattr(os, "waitpid", lambda pid, flags: (0, 0))
        monkeypatch.setattr(cancellation, "_TOOL_GROUPS", (424242,))
        monkeypatch.setattr(cancellation, "_TOOL_PIDS", ())

        cancellation._kill_recorded_groups()

        assert killed == [(424242, signal.SIGKILL)]


class TestAFirstCtrlCDuringAGraceWaitLatchesWithoutInterrupting:
    def test_the_previous_handler_is_not_chained_inside_a_grace_wait(self, monkeypatch):
        chained = []
        monkeypatch.setattr(cancellation, "_SIGINT_SEEN", False)
        monkeypatch.setattr(cancellation, "_SIGTERM_SEEN", False)
        monkeypatch.setattr(cancellation, "_SHUTDOWN_REQUESTED", False)
        monkeypatch.setattr(cancellation, "_SHUTDOWN_SCOPES", ())
        monkeypatch.setattr(
            cancellation, "_PREVIOUS_SIGINT", lambda s, f: chained.append(s)
        )
        monkeypatch.setattr(cancellation, "_GRACE_WAITS", 0)

        with cancellation.stop_grace_in_progress():
            assert cancellation.grace_wait_in_progress() is True
            cancellation._handle_sigint(signal.SIGINT, None)

        # Red at the base: the context manager did not exist; the handler
        # chained the default handler, which raises KeyboardInterrupt.
        assert chained == []
        assert cancellation._SIGINT_SEEN is True
        assert cancellation.grace_wait_in_progress() is False

    def test_outside_a_grace_wait_the_first_ctrl_c_still_interrupts(self, monkeypatch):
        """The control: the interrupt arm of a command still runs."""
        chained = []
        monkeypatch.setattr(cancellation, "_SIGINT_SEEN", False)
        monkeypatch.setattr(cancellation, "_SIGTERM_SEEN", False)
        monkeypatch.setattr(cancellation, "_SHUTDOWN_REQUESTED", False)
        monkeypatch.setattr(cancellation, "_SHUTDOWN_SCOPES", ())
        monkeypatch.setattr(
            cancellation, "_PREVIOUS_SIGINT", lambda s, f: chained.append(s)
        )
        monkeypatch.setattr(cancellation, "_GRACE_WAITS", 0)

        cancellation._handle_sigint(signal.SIGINT, None)

        assert chained == [signal.SIGINT]
