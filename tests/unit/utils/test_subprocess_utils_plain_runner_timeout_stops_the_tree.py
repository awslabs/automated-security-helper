"""The plain runner's timeout stops the child's whole process group.

Outside a sandbox and outside a cancel scope a spawn runs through _run_plain,
whose timeout killed the child alone. A scanner run through uv is uv's child:
killing uv left the tool running, holding its pipes, while the TimeoutExpired
reported the stop as done. The child now leads a process group of its own, as
every unsandboxed spawn in a cancel scope does, and the timeout stops the group.
"""

import os
import subprocess  # nosec B404 - the module under test wraps subprocess
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.utils import subprocess_utils

pytestmark = pytest.mark.unit


def _child_that_outlives_its_timeout(error: BaseException) -> MagicMock:
    process = MagicMock(spec=subprocess.Popen)
    process.pid = 4242
    process.args = ["uv", "run", "tool"]
    process.returncode = None
    process.poll.return_value = None
    process.communicate.side_effect = error
    return process


def test_a_timeout_stops_the_tree_the_child_leads():
    expired = subprocess.TimeoutExpired(["uv", "run", "tool"], 1)
    process = _child_that_outlives_its_timeout(expired)
    with (
        patch.object(
            subprocess_utils.subprocess, "Popen", return_value=process
        ) as popen,
        patch.object(subprocess_utils, "_note_start", return_value=None),
        patch.object(subprocess_utils, "_stop_tree") as stop_tree,
        patch.object(subprocess_utils, "_output_after_stop", return_value=(b"", b"")),
        patch.object(subprocess_utils, "_reap"),
    ):
        with pytest.raises(subprocess.TimeoutExpired) as raised:
            subprocess_utils._run_plain(["uv", "run", "tool"], timeout=1)
    assert raised.value is expired
    stop_tree.assert_called_once_with(process, 0.0, None)
    process.kill.assert_not_called()
    if os.name == "nt":
        flag = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        assert popen.call_args.kwargs["creationflags"] & flag
    else:
        assert popen.call_args.kwargs["start_new_session"] is True


def test_a_failed_wait_stops_the_tree_the_child_leads():
    process = _child_that_outlives_its_timeout(KeyboardInterrupt())
    with (
        patch.object(subprocess_utils.subprocess, "Popen", return_value=process),
        patch.object(subprocess_utils, "_note_start", return_value=None),
        patch.object(subprocess_utils, "_claim_started", return_value=None),
        patch.object(subprocess_utils, "_note_failed_wait"),
        patch.object(subprocess_utils, "_stop_tree") as stop_tree,
        patch.object(subprocess_utils, "_reap"),
    ):
        with pytest.raises(KeyboardInterrupt):
            subprocess_utils._run_plain(["uv", "run", "tool"], timeout=1)
    stop_tree.assert_called_once_with(process, 0.0, None)
    process.kill.assert_not_called()


def test_a_caller_that_names_the_session_flag_keeps_its_value():
    process = _child_that_outlives_its_timeout(KeyboardInterrupt())
    with (
        patch.object(
            subprocess_utils.subprocess, "Popen", return_value=process
        ) as popen,
        patch.object(subprocess_utils, "_note_start", return_value=None),
        patch.object(subprocess_utils, "_claim_started", return_value=None),
        patch.object(subprocess_utils, "_note_failed_wait"),
        patch.object(subprocess_utils, "_stop_tree"),
        patch.object(subprocess_utils, "_reap"),
    ):
        with pytest.raises(KeyboardInterrupt):
            subprocess_utils._run_plain(["tool"], start_new_session=False)
    if os.name != "nt":
        assert popen.call_args.kwargs["start_new_session"] is False
