"""A refused kill inside stop_after_interrupt must not replace the stop's own cause.

``Popen.kill`` raises PermissionError on a child this process may not signal
(a setuid program the tool became). Raised from the stop arms it replaced the
KeyboardInterrupt the caller re-raises, or the TimeoutExpired the grace arm
swallows, with an unexplained OSError.

The same holds for the Ctrl-C escalations inside ``_stop`` and ``_stop_tree``:
the SIGKILL that follows an interrupt during the grace is still attempted, and
a kernel that refuses it leaves the interrupt as what the caller handles.
"""

import os
import signal
import subprocess  # nosec B404 - the module under test wraps subprocess
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.utils import subprocess_utils

pytestmark = pytest.mark.unit

POSIX_ONLY = pytest.mark.skipif(
    os.name == "nt", reason="process groups are the POSIX arm of _stop_tree"
)

#: Outside any real pid range this test could collide with.
_NO_SUCH_PGID = 2**30 + 4343
#: Outside any real pid range: stop_after_interrupt runs for real on these
#: stand-ins, and a small number can name a live process on the test host.
_NO_SUCH_PID = 2**30 + 4242


def test_an_interrupt_during_the_plain_stops_grace_survives_a_refused_kill():
    process = _child_the_kernel_will_not_kill()
    process.poll.return_value = None
    with patch.object(
        subprocess_utils, "_wait_out_grace", side_effect=KeyboardInterrupt
    ):
        with pytest.raises(KeyboardInterrupt):
            subprocess_utils._stop(process, grace=0.01)
    process.terminate.assert_called_once()
    # The escalation was attempted; the refusal did not become the error raised.
    process.kill.assert_called_once()


@POSIX_ONLY
def test_an_interrupt_during_the_tree_stops_grace_survives_a_refused_kill():
    process = MagicMock(spec=subprocess.Popen)
    process.pid = _NO_SUCH_PGID
    process.returncode = None
    process.poll.return_value = None
    process.args = ["tool"]
    sent = []

    def signal_group(pgid, signum):
        sent.append(signum)
        if signum == signal.SIGKILL:
            raise PermissionError(1, "Operation not permitted")
        return True

    with (
        patch.object(subprocess_utils, "_group_survives", return_value=True),
        patch.object(subprocess_utils, "_signal_group", side_effect=signal_group),
        patch.object(
            subprocess_utils, "_wait_out_grace", side_effect=KeyboardInterrupt
        ),
    ):
        with pytest.raises(KeyboardInterrupt):
            subprocess_utils._stop_tree(process, grace=0.01)
    assert sent == [signal.SIGTERM, signal.SIGKILL]


def test_a_refused_kill_after_an_interrupt_in_the_plain_stop_marks_the_record(
    monkeypatch, caplog
):
    """The interrupt still propagates, and the spawn's record says the stop was
    refused, as it does for the ordinary stop's refusal; the refusal is a
    WARNING, not a debug line."""
    process = _child_the_kernel_will_not_kill()
    process.poll.return_value = None
    process.args = ["tool"]
    monkeypatch.setattr(subprocess_utils, "_has_exited", lambda child: False)
    started = subprocess_utils._StartedChild()
    with (
        patch.object(
            subprocess_utils, "_wait_out_grace", side_effect=KeyboardInterrupt
        ),
        caplog.at_level("WARNING"),
        started.recording(),
    ):
        started.process = process
        with pytest.raises(KeyboardInterrupt):
            subprocess_utils._stop(process, grace=0.01)
    assert started.stop_refused is True
    assert any(
        "Could not stop" in r.getMessage() and r.levelname == "WARNING"
        for r in caplog.records
    )


@POSIX_ONLY
def test_a_refused_kill_after_an_interrupt_in_the_tree_stop_marks_the_record(
    monkeypatch, caplog
):
    process = MagicMock(spec=subprocess.Popen)
    process.pid = _NO_SUCH_PGID
    process.returncode = None
    process.poll.return_value = None
    process.args = ["tool"]

    def signal_group(pgid, signum):
        if signum == signal.SIGKILL:
            raise PermissionError(1, "Operation not permitted")
        return True

    monkeypatch.setattr(subprocess_utils, "_has_exited", lambda child: False)
    started = subprocess_utils._StartedChild()
    with (
        patch.object(subprocess_utils, "_group_survives", return_value=True),
        patch.object(subprocess_utils, "_signal_group", side_effect=signal_group),
        patch.object(
            subprocess_utils, "_wait_out_grace", side_effect=KeyboardInterrupt
        ),
        caplog.at_level("WARNING"),
        started.recording(),
    ):
        started.process = process
        with pytest.raises(KeyboardInterrupt):
            subprocess_utils._stop_tree(process, grace=0.01)
    assert started.stop_refused is True
    assert any(
        "Could not stop" in r.getMessage() and r.levelname == "WARNING"
        for r in caplog.records
    )


def _child_the_kernel_will_not_kill() -> MagicMock:
    process = MagicMock(spec=subprocess.Popen)
    process.pid = _NO_SUCH_PID
    process.returncode = None
    # `args` is set on a real Popen in __init__, not on the class, so a spec'd
    # mock lacks it; the refusal's WARNING names the program through it.
    process.args = ["tool"]
    # An unset method of a spec'd mock answers with a (truthy) mock, which every
    # read of the child's exit status takes for an exit: the stand-in is still
    # running, as Popen.poll says for a child with no exit code.
    process.poll.return_value = process.returncode
    process.kill.side_effect = PermissionError(1, "Operation not permitted")
    return process


class _OsWithoutWaitid:
    """``os`` as a build without ``waitid`` has it (CPython on macOS, Windows)."""

    def __getattr__(self, attribute: str):
        if attribute == "waitid":
            raise AttributeError(attribute)
        return getattr(os, attribute)


def test_the_stand_in_the_kernel_will_not_kill_reads_as_running_without_waitid(
    monkeypatch,
):
    """Where the build has no waitid the exit is read from ``poll``: the stand-in
    answers None, so its exit is not observed and its record is kept. Left
    unset, the poll answered a truthy mock and the stand-in read as an exit."""
    monkeypatch.setattr(subprocess_utils, "os", _OsWithoutWaitid())
    process = _child_the_kernel_will_not_kill()
    with patch.object(subprocess_utils, "discard_tool_pid") as discard:
        assert subprocess_utils.discard_tool_pid_once_exited(process) is False
    discard.assert_not_called()


def test_a_second_interrupt_still_raises_keyboard_interrupt_when_kill_is_refused(
    caplog,
):
    process = _child_the_kernel_will_not_kill()
    with (
        patch.object(subprocess_utils, "_wait_out", side_effect=KeyboardInterrupt),
        caplog.at_level("WARNING"),
    ):
        with pytest.raises(KeyboardInterrupt):
            subprocess_utils.stop_after_interrupt(
                process, grace=0.01, child_got_the_interrupt=True
            )
    process.kill.assert_called_once()
    # A child the kernel would not kill is not waited for: the wait would
    # block on a process that is still running.
    process.wait.assert_not_called()
    # The refusal is logged, not swallowed: it is the only record that the
    # child may still run.
    _assert_the_refusal_was_logged(caplog)


def test_an_outlived_grace_returns_false_when_kill_is_refused(caplog):
    """The caller learns that the child may still run, and can say so in its
    cancel, as the cancellable runner does for a stop the kernel refused."""
    process = _child_the_kernel_will_not_kill()
    timed_out = subprocess.TimeoutExpired(["tool"], 0.01)
    with (
        patch.object(subprocess_utils, "_wait_out", side_effect=timed_out),
        caplog.at_level("WARNING"),
    ):
        stopped = subprocess_utils.stop_after_interrupt(
            process, grace=0.01, child_got_the_interrupt=True
        )
    assert stopped is False
    process.kill.assert_called_once()
    process.wait.assert_not_called()
    _assert_the_refusal_was_logged(caplog)


def _assert_the_refusal_was_logged(caplog) -> None:
    """The WARNING naming the pid and the kernel's refusal."""
    assert any(
        r.levelname == "WARNING"
        and f"Could not kill pid {_NO_SUCH_PID}" in r.getMessage()
        and "Operation not permitted" in r.getMessage()
        for r in caplog.records
    ), [r.getMessage() for r in caplog.records]


@POSIX_ONLY
def test_an_eperm_on_the_group_read_and_the_kill_after_an_interrupt_keeps_it(
    monkeypatch, caplog
):
    """A group holding a process the server may not signal answers EPERM to the
    existence probe (signal 0) as well as to the kill. The probe reads the group
    as still there, so the kill is attempted, the refusal is marked, and the
    interrupt, not the OSError, is what propagates. The real group read runs
    here, unlike the cases above, which pin it to True."""
    process = MagicMock(spec=subprocess.Popen)
    process.pid = _NO_SUCH_PGID
    # Reaped: the kill's guard then depends on the group read alone.
    process.returncode = 0
    process.poll.return_value = 0
    process.args = ["tool"]
    sent = []

    def signal_group(pgid, signum):
        sent.append(signum)
        if signum in (0, signal.SIGKILL):
            raise PermissionError(1, "Operation not permitted")
        return True

    monkeypatch.setattr(subprocess_utils, "_this_process_is_init", lambda: False)
    monkeypatch.setattr(
        subprocess_utils, "_pid_names_a_live_process", lambda pid: False
    )
    monkeypatch.setattr(subprocess_utils, "_has_exited", lambda child: True)
    started = subprocess_utils._StartedChild()
    with (
        patch.object(subprocess_utils, "_signal_group", side_effect=signal_group),
        patch.object(
            subprocess_utils, "_wait_out_grace", side_effect=KeyboardInterrupt
        ),
        caplog.at_level("WARNING"),
        started.recording(),
    ):
        started.process = process
        with pytest.raises(KeyboardInterrupt):
            subprocess_utils._stop_tree(process, grace=0.01)
    assert sent.count(0) >= 2, "the group was not read before the kill, twice"
    assert signal.SIGKILL in sent, sent
    assert started.stop_refused is True
    assert any(
        f"(process group {_NO_SUCH_PGID}) after an interrupt" in r.getMessage()
        and r.levelname == "WARNING"
        for r in caplog.records
    )


def test_an_outlived_grace_whose_kill_is_accepted_returns_true():
    process = MagicMock(spec=subprocess.Popen)
    process.pid = _NO_SUCH_PID
    process.returncode = None
    process.poll.return_value = None
    timed_out = subprocess.TimeoutExpired(["tool"], 0.01)
    with (
        patch.object(subprocess_utils, "_wait_out", side_effect=timed_out),
        patch.object(subprocess_utils, "discard_tool_pid_before_reap"),
    ):
        stopped = subprocess_utils.stop_after_interrupt(
            process, grace=0.01, child_got_the_interrupt=True
        )
    assert stopped is True
    process.kill.assert_called_once()


def test_a_child_that_stops_within_the_grace_returns_true():
    process = MagicMock(spec=subprocess.Popen)
    process.pid = _NO_SUCH_PID
    process.returncode = 0
    process.poll.return_value = 0
    with patch.object(subprocess_utils, "_wait_out", return_value=None):
        stopped = subprocess_utils.stop_after_interrupt(
            process, grace=0.01, child_got_the_interrupt=True
        )
    assert stopped is True
    process.kill.assert_not_called()


def test_a_kill_the_kernel_accepts_is_still_followed_by_the_reap():
    process = MagicMock(spec=subprocess.Popen)
    process.pid = _NO_SUCH_PID
    process.returncode = None
    process.poll.return_value = None
    with (
        patch.object(subprocess_utils, "_wait_out", side_effect=KeyboardInterrupt),
        patch.object(subprocess_utils, "discard_tool_pid_before_reap") as discard,
    ):
        with pytest.raises(KeyboardInterrupt):
            subprocess_utils.stop_after_interrupt(
                process, grace=0.01, child_got_the_interrupt=True
            )
    process.kill.assert_called_once()
    discard.assert_called_once_with(process)
    process.wait.assert_called_once()
