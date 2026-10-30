"""The plain runner's timeout stops the child's whole process group.

Outside a sandbox and outside a cancel scope a spawn runs through _run_plain,
whose timeout killed the child alone. A scanner run through uv is uv's child:
killing uv left the tool running, holding its pipes, while the TimeoutExpired
reported the stop as done. With a timeout the child now leads a process group of
its own, registered as a cancellable spawn's is, and the timeout stops the group.
Without a timeout the child stays in ASH's own session and group, as
subprocess.run leaves it: a session of its own would cost the child its
controlling terminal and the terminal's job-control signals for nothing.
"""

import os
import subprocess  # nosec B404 - the module under test wraps subprocess
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.utils import subprocess_utils

pytestmark = pytest.mark.unit

#: Outside any real pid range this test could collide with.
_NO_SUCH_PID = 2**30 + 4242


def _child_that_outlives_its_timeout(error: BaseException) -> MagicMock:
    process = MagicMock(spec=subprocess.Popen)
    process.pid = _NO_SUCH_PID
    process.args = ["uv", "run", "tool"]
    process.returncode = None
    process.poll.return_value = None
    process.communicate.side_effect = error
    return process


def _led_its_own_group(popen: MagicMock) -> bool:
    kwargs = popen.call_args.kwargs
    if os.name == "nt":
        flag = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        return bool(kwargs.get("creationflags", 0) & flag)
    return kwargs.get("start_new_session") is True


def test_a_timeout_stops_the_tree_the_child_leads():
    expired = subprocess.TimeoutExpired(["uv", "run", "tool"], 1)
    process = _child_that_outlives_its_timeout(expired)
    with (
        patch.object(
            subprocess_utils.subprocess, "Popen", return_value=process
        ) as popen,
        patch.object(subprocess_utils, "_note_start", return_value=None),
        patch.object(subprocess_utils, "_register_group") as register,
        patch.object(subprocess_utils, "_stop_tree") as stop_tree,
        patch.object(subprocess_utils, "_output_after_stop", return_value=(b"", b"")),
        patch.object(subprocess_utils, "_reap"),
    ):
        with pytest.raises(subprocess.TimeoutExpired) as raised:
            subprocess_utils._run_plain(["uv", "run", "tool"], timeout=1)
    assert raised.value is expired
    stop_tree.assert_called_once_with(process, 0.0, None)
    process.kill.assert_not_called()
    assert _led_its_own_group(popen)
    register.assert_called_once_with(process)


def test_a_failed_wait_with_a_timeout_stops_the_tree_the_child_leads():
    process = _child_that_outlives_its_timeout(KeyboardInterrupt())
    with (
        patch.object(subprocess_utils.subprocess, "Popen", return_value=process),
        patch.object(subprocess_utils, "_note_start", return_value=None),
        patch.object(subprocess_utils, "_register_group"),
        patch.object(subprocess_utils, "_claim_started", return_value=None),
        patch.object(subprocess_utils, "_note_failed_wait"),
        patch.object(subprocess_utils, "_stop_tree") as stop_tree,
        patch.object(subprocess_utils, "_reap"),
    ):
        with pytest.raises(KeyboardInterrupt):
            subprocess_utils._run_plain(["uv", "run", "tool"], timeout=1)
    stop_tree.assert_called_once_with(process, 0.0, None)
    process.kill.assert_not_called()


def test_without_a_timeout_the_child_keeps_the_session_and_is_killed_alone():
    """No bound to enforce: the child shares ASH's session and terminal, nothing
    is registered, and a failed wait kills the child as subprocess.run does."""
    process = _child_that_outlives_its_timeout(KeyboardInterrupt())
    with (
        patch.object(
            subprocess_utils.subprocess, "Popen", return_value=process
        ) as popen,
        patch.object(subprocess_utils, "_note_start", return_value=None),
        patch.object(subprocess_utils, "_register_group") as register,
        patch.object(subprocess_utils, "_leads_its_own_group", return_value=False),
        patch.object(subprocess_utils, "_claim_started", return_value=None),
        patch.object(subprocess_utils, "_note_failed_wait"),
        patch.object(subprocess_utils, "_stop_tree") as stop_tree,
        patch.object(subprocess_utils, "_reap"),
    ):
        with pytest.raises(KeyboardInterrupt):
            subprocess_utils._run_plain(["tool"])
    assert not _led_its_own_group(popen)
    assert "start_new_session" not in popen.call_args.kwargs
    register.assert_not_called()
    stop_tree.assert_not_called()
    process.kill.assert_called_once()


def test_a_child_a_caller_put_in_its_own_group_is_still_stopped_as_a_group():
    """A caller's own start_new_session: the stop reaches the group it leads."""
    process = _child_that_outlives_its_timeout(KeyboardInterrupt())
    with (
        patch.object(subprocess_utils.subprocess, "Popen", return_value=process),
        patch.object(subprocess_utils, "_note_start", return_value=None),
        patch.object(subprocess_utils, "_leads_its_own_group", return_value=True),
        patch.object(subprocess_utils, "_claim_started", return_value=None),
        patch.object(subprocess_utils, "_note_failed_wait"),
        patch.object(subprocess_utils, "_stop_tree") as stop_tree,
        patch.object(subprocess_utils, "_reap"),
    ):
        with pytest.raises(KeyboardInterrupt):
            subprocess_utils._run_plain(["tool"], start_new_session=True)
    stop_tree.assert_called_once_with(process, 0.0, None)
    process.kill.assert_not_called()


def test_a_caller_that_names_the_session_flag_keeps_its_value():
    process = _child_that_outlives_its_timeout(KeyboardInterrupt())
    with (
        patch.object(
            subprocess_utils.subprocess, "Popen", return_value=process
        ) as popen,
        patch.object(subprocess_utils, "_note_start", return_value=None),
        patch.object(subprocess_utils, "_register_group"),
        patch.object(subprocess_utils, "_claim_started", return_value=None),
        patch.object(subprocess_utils, "_note_failed_wait"),
        patch.object(subprocess_utils, "_stop_tree"),
        patch.object(subprocess_utils, "_reap"),
    ):
        with pytest.raises(KeyboardInterrupt):
            subprocess_utils._run_plain(["tool"], timeout=1, start_new_session=False)
    if os.name != "nt":
        assert popen.call_args.kwargs["start_new_session"] is False
