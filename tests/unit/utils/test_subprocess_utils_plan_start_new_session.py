"""A sandbox plan that asks for its own session gets ``start_new_session=True`` at Popen.

The sandboxed runners do not set the flag themselves: the wrappers that call
setsid (bwrap's ``--new-session``, the sandbox-exec plan) make it redundant, and
firejail does not call it, so its plan carries the request and the spawner passes
it to Popen. A plan without the request changes nothing about the Popen call.
"""

from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.sandbox.backends import SpawnPlan

pytestmark = pytest.mark.unit


def test_a_plan_asks_for_no_new_session_by_default():
    assert SpawnPlan(argv=["tool"], env={}).start_new_session is False


@patch("subprocess.Popen")
@patch("automated_security_helper.utils.subprocess_utils.find_executable")
def test_a_plan_with_the_flag_starts_the_child_in_a_new_session(
    mock_find_executable, mock_popen
):
    mock_find_executable.return_value = "/usr/bin/tool"
    mock_popen.return_value = MagicMock()
    plan = SpawnPlan(
        argv=["wrapper", "tool"], env={}, cleanup=[], start_new_session=True
    )
    with patch.object(subprocess_utils, "_prepare_spawn", return_value=plan):
        subprocess_utils.create_process_with_pipes(["tool"])
    mock_popen.assert_called_once()
    args, kwargs = mock_popen.call_args
    assert args[0] == ["wrapper", "tool"]
    assert kwargs["start_new_session"] is True


@patch("subprocess.Popen")
@patch("automated_security_helper.utils.subprocess_utils.find_executable")
def test_a_plan_without_the_flag_leaves_the_popen_call_as_it_was(
    mock_find_executable, mock_popen
):
    mock_find_executable.return_value = "/usr/bin/tool"
    mock_popen.return_value = MagicMock()
    plan = SpawnPlan(argv=["wrapper", "tool"], env={}, cleanup=[])
    with patch.object(subprocess_utils, "_prepare_spawn", return_value=plan):
        subprocess_utils.create_process_with_pipes(["tool"])
    mock_popen.assert_called_once()
    _, kwargs = mock_popen.call_args
    assert "start_new_session" not in kwargs


def test_the_popen_kwargs_helper_reads_the_plan():
    assert subprocess_utils._plan_popen_kwargs(None) == {}
    assert subprocess_utils._plan_popen_kwargs(SpawnPlan(argv=[], env={})) == {}
    assert subprocess_utils._plan_popen_kwargs(
        SpawnPlan(argv=[], env={}, start_new_session=True)
    ) == {"start_new_session": True}
