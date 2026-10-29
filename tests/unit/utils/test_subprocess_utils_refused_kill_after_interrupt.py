"""A refused kill inside stop_after_interrupt must not replace the stop's own cause.

``Popen.kill`` raises PermissionError on a child this process may not signal
(a setuid program the tool became). Raised from the stop arms it replaced the
KeyboardInterrupt the caller re-raises, or the TimeoutExpired the grace arm
swallows, with an unexplained OSError.
"""

import subprocess  # nosec B404 - the module under test wraps subprocess
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.utils import subprocess_utils

pytestmark = pytest.mark.unit


def _child_the_kernel_will_not_kill() -> MagicMock:
    process = MagicMock(spec=subprocess.Popen)
    process.pid = 4242
    process.returncode = None
    process.kill.side_effect = PermissionError(1, "Operation not permitted")
    return process


def test_a_second_interrupt_still_raises_keyboard_interrupt_when_kill_is_refused():
    process = _child_the_kernel_will_not_kill()
    with patch.object(subprocess_utils, "_wait_out", side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            subprocess_utils.stop_after_interrupt(
                process, grace=0.01, child_got_the_interrupt=True
            )
    process.kill.assert_called_once()
    # A child the kernel would not kill is not waited for: the wait would
    # block on a process that is still running.
    process.wait.assert_not_called()


def test_an_outlived_grace_returns_quietly_when_kill_is_refused():
    process = _child_the_kernel_will_not_kill()
    timed_out = subprocess.TimeoutExpired(["tool"], 0.01)
    with patch.object(subprocess_utils, "_wait_out", side_effect=timed_out):
        subprocess_utils.stop_after_interrupt(
            process, grace=0.01, child_got_the_interrupt=True
        )
    process.kill.assert_called_once()
    process.wait.assert_not_called()


def test_a_kill_the_kernel_accepts_is_still_followed_by_the_reap():
    process = MagicMock(spec=subprocess.Popen)
    process.pid = 4242
    process.returncode = None
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
