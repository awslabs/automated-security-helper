# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The die-now kill reaches only a live child, and a first Ctrl-C does not abort
a stop that is waiting out a tool's grace.

* ``_kill_recorded_groups`` falls back from ``killpg`` to ``os.kill`` on the
  recorded id, for a child recorded before its setsid. A group id left recorded
  after its child was reaped is a pid another process can hold by now, and the
  fallback kill landed on it. The fallback now asks ``waitid(WNOWAIT)`` first,
  which leaves an exited child unreaped for the ``Popen`` that owns it (a reap
  here made that ``Popen`` read a lost wait, ECHILD, as a return code of 0 when
  this process is its container's init); a build with no ``waitid`` asks
  ``waitpid(WNOHANG)``.
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
from automated_security_helper.core.cancellation import CancelEvent

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

        def not_our_child(idtype, pid, flags):
            raise ChildProcessError

        def never_reap(pid, flags):
            raise AssertionError("the probe must not reap with waitpid")

        monkeypatch.setattr(os, "waitid", not_our_child)
        monkeypatch.setattr(os, "waitpid", never_reap)
        monkeypatch.setattr(cancellation, "_TOOL_GROUPS", (424242,))
        monkeypatch.setattr(cancellation, "_TOOL_PIDS", ())

        cancellation._kill_recorded_groups()

        # Red at the base: the fallback killed whatever held the pid.
        assert killed == []

    def test_an_exited_child_is_not_killed_and_not_reaped(self, monkeypatch):
        """``waitid`` answering a result: the child had exited. Its pid may be
        free for reuse once its owner reaps it, so the fallback kill must not
        follow, and the probe must leave the child for that owner to reap: a
        reap here left the owner a wait that failed with ECHILD, read as a
        return code of 0."""
        killed = []
        seen = []
        monkeypatch.setattr(
            os, "killpg", lambda pgid, sig: (_ for _ in ()).throw(ProcessLookupError())
        )
        monkeypatch.setattr(os, "kill", lambda pid, sig: killed.append((pid, sig)))

        def exited(idtype, pid, flags):
            seen.append((idtype, pid, flags))
            return object()

        def never_reap(pid, flags):
            raise AssertionError("the probe must not reap with waitpid")

        monkeypatch.setattr(os, "waitid", exited)
        monkeypatch.setattr(os, "waitpid", never_reap)
        monkeypatch.setattr(cancellation, "_TOOL_GROUPS", (424242,))
        monkeypatch.setattr(cancellation, "_TOOL_PIDS", ())

        cancellation._kill_recorded_groups()

        assert killed == []
        # Red at the base: waitid was never asked, waitpid reaped the child.
        wanted = os.WEXITED | os.WNOHANG | os.WNOWAIT
        assert seen == [(os.P_PID, 424242, wanted)]

    def test_a_live_child_that_leads_no_group_is_still_killed(self, monkeypatch):
        """The control: the fallback the launcher child relies on still fires."""
        killed = []
        monkeypatch.setattr(
            os, "killpg", lambda pgid, sig: (_ for _ in ()).throw(ProcessLookupError())
        )
        monkeypatch.setattr(os, "kill", lambda pid, sig: killed.append((pid, sig)))
        monkeypatch.setattr(os, "waitid", lambda idtype, pid, flags: None)
        monkeypatch.setattr(
            os,
            "waitpid",
            lambda pid, flags: (_ for _ in ()).throw(
                AssertionError("the probe must not reap with waitpid")
            ),
        )
        monkeypatch.setattr(cancellation, "_TOOL_GROUPS", (424242,))
        monkeypatch.setattr(cancellation, "_TOOL_PIDS", ())

        cancellation._kill_recorded_groups()

        assert killed == [(424242, signal.SIGKILL)]


class TestWithoutWaitidTheProbeFallsBackToWaitpid:
    """A build with no ``os.waitid`` (CPython leaves it out on macOS)."""

    @pytest.fixture(autouse=True)
    def _no_waitid(self, monkeypatch):
        monkeypatch.delattr(os, "waitid", raising=False)

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

        assert killed == []

    def test_a_child_the_probe_reaped_is_not_killed(self, monkeypatch):
        """``waitpid`` answering ``(pid, status)``: the child had exited and the
        probe reaped it. Its pid is free for reuse from that moment, so the
        fallback kill must not follow."""
        killed = []
        seen_flags = []
        monkeypatch.setattr(
            os, "killpg", lambda pgid, sig: (_ for _ in ()).throw(ProcessLookupError())
        )
        monkeypatch.setattr(os, "kill", lambda pid, sig: killed.append((pid, sig)))

        def reaped(pid, flags):
            seen_flags.append(flags)
            return (pid, 0)

        monkeypatch.setattr(os, "waitpid", reaped)
        monkeypatch.setattr(cancellation, "_TOOL_GROUPS", (424242,))
        monkeypatch.setattr(cancellation, "_TOOL_PIDS", ())

        cancellation._kill_recorded_groups()

        assert killed == []
        assert seen_flags == [os.WNOHANG]

    def test_a_live_child_that_leads_no_group_is_still_killed(self, monkeypatch):
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
        scan = CancelEvent()
        monkeypatch.setattr(cancellation, "_SIGINT_SEEN", False)
        monkeypatch.setattr(cancellation, "_SIGTERM_SEEN", False)
        monkeypatch.setattr(cancellation, "_SHUTDOWN_REQUESTED", False)
        # A scan is registered to unwind on the latch (shutdown_cancels).
        monkeypatch.setattr(cancellation, "_SHUTDOWN_SCOPES", (scan,))
        monkeypatch.setattr(
            cancellation, "_PREVIOUS_SIGINT", lambda s, f: chained.append(s)
        )
        monkeypatch.setattr(cancellation, "_GRACE_WAITS", 0)

        with cancellation.stop_grace_in_progress():
            assert cancellation._GRACE_WAITS == 1
            cancellation._handle_sigint(signal.SIGINT, None)

        # Red at the base: the context manager did not exist; the handler
        # chained the default handler, which raises KeyboardInterrupt.
        assert chained == []
        assert cancellation._SIGINT_SEEN is True
        assert scan._signalled is True
        assert cancellation._GRACE_WAITS == 0

    def test_with_no_scan_registered_the_first_ctrl_c_still_interrupts(
        self, monkeypatch
    ):
        """Nothing reads the latch when no scan is registered, so holding the
        interrupt back inside a grace wait would leave the Ctrl-C without any
        effect: the interrupt is chained as it is outside a grace wait."""
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
            cancellation._handle_sigint(signal.SIGINT, None)

        # Red at the previous tip: the grace wait alone held the interrupt back.
        assert chained == [signal.SIGINT]
        assert cancellation._SIGINT_SEEN is True

    def test_a_second_ctrl_c_inside_a_grace_wait_dies_now(self, monkeypatch):
        """The second interrupt is the operator's "gone now": the recorded tool
        groups are killed and the process re-raises SIGINT under the default
        disposition, grace wait or not. No signal is raised here: the two
        signal calls are recorded."""
        killed = []
        dispositions = []
        raised = []
        monkeypatch.setattr(cancellation, "_SIGINT_SEEN", True)
        monkeypatch.setattr(cancellation, "_SIGTERM_SEEN", False)
        monkeypatch.setattr(cancellation, "_SHUTDOWN_REQUESTED", True)
        monkeypatch.setattr(cancellation, "_SHUTDOWN_SCOPES", ())
        monkeypatch.setattr(cancellation, "_TOOL_GROUPS", (424242,))
        monkeypatch.setattr(cancellation, "_TOOL_PIDS", ())
        monkeypatch.setattr(cancellation, "_remove_die_now_cleanups", lambda: None)
        monkeypatch.setattr(os, "killpg", lambda pgid, sig: killed.append((pgid, sig)))

        # pid 424242 can be a live process on a host with a large pid_max, so a
        # path that fell back to a kill or a wait by pid would signal or reap an
        # unrelated process. Both are recorded, not run, and neither may be
        # reached. (Recorded rather than raising: a Popen collected meanwhile
        # waits through the same function, and an exception there is only
        # printed.)
        by_pid = []
        monkeypatch.setattr(os, "kill", lambda pid, sig: by_pid.append(("kill", pid)))
        monkeypatch.setattr(
            os, "waitpid", lambda pid, flags: by_pid.append(("waitpid", pid)) or (0, 0)
        )
        monkeypatch.setattr(
            os,
            "waitid",
            lambda idtype, pid, flags: by_pid.append(("waitid", pid)),
            raising=False,
        )
        monkeypatch.setattr(
            signal, "signal", lambda signum, handler: dispositions.append(handler)
        )
        monkeypatch.setattr(
            signal, "raise_signal", lambda signum: raised.append(signum)
        )
        monkeypatch.setattr(cancellation, "_GRACE_WAITS", 0)

        with cancellation.stop_grace_in_progress():
            cancellation._handle_sigint(signal.SIGINT, None)

        assert killed == [(424242, signal.SIGKILL)]
        assert [call for call in by_pid if call[1] == 424242] == []
        assert dispositions == [signal.SIG_DFL]
        assert raised == [signal.SIGINT]

    def test_outside_a_grace_wait_the_first_ctrl_c_still_interrupts(self, monkeypatch):
        """The control: with a scan registered, so that a handler which ignored
        the grace-wait count and held the interrupt back whenever any scan was
        registered would fail here, the interrupt arm of a command still runs."""
        chained = []
        scan = CancelEvent()
        monkeypatch.setattr(cancellation, "_SIGINT_SEEN", False)
        monkeypatch.setattr(cancellation, "_SIGTERM_SEEN", False)
        monkeypatch.setattr(cancellation, "_SHUTDOWN_REQUESTED", False)
        monkeypatch.setattr(cancellation, "_SHUTDOWN_SCOPES", (scan,))
        monkeypatch.setattr(
            cancellation, "_PREVIOUS_SIGINT", lambda s, f: chained.append(s)
        )
        monkeypatch.setattr(cancellation, "_GRACE_WAITS", 0)

        cancellation._handle_sigint(signal.SIGINT, None)

        assert cancellation._GRACE_WAITS == 0
        assert chained == [signal.SIGINT]

    def test_the_count_goes_back_down_when_the_wait_is_interrupted(self, monkeypatch):
        """The previous handler raises KeyboardInterrupt, inside the block, when no
        scan is registered. A count that stayed raised would hold back every first
        Ctrl-C of the process from then on."""

        def interrupt(signum, frame):
            raise KeyboardInterrupt

        monkeypatch.setattr(cancellation, "_SIGINT_SEEN", False)
        monkeypatch.setattr(cancellation, "_SIGTERM_SEEN", False)
        monkeypatch.setattr(cancellation, "_SHUTDOWN_REQUESTED", False)
        monkeypatch.setattr(cancellation, "_SHUTDOWN_SCOPES", ())
        monkeypatch.setattr(cancellation, "_PREVIOUS_SIGINT", interrupt)
        monkeypatch.setattr(cancellation, "_GRACE_WAITS", 0)

        with pytest.raises(KeyboardInterrupt):
            with cancellation.stop_grace_in_progress():
                assert cancellation._GRACE_WAITS == 1
                cancellation._handle_sigint(signal.SIGINT, None)

        # Red with a count that is raised and lowered without a try/finally.
        assert cancellation._GRACE_WAITS == 0

    def test_grace_waits_nest(self, monkeypatch):
        monkeypatch.setattr(cancellation, "_GRACE_WAITS", 0)

        with cancellation.stop_grace_in_progress():
            with cancellation.stop_grace_in_progress():
                assert cancellation._GRACE_WAITS == 2
            assert cancellation._GRACE_WAITS == 1

        assert cancellation._GRACE_WAITS == 0
