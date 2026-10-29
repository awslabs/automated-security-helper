"""A sandbox plan's cleanup never runs inside the Popen finalizer's own thread.

create_process_with_pipes hands the caller the Popen and ties the plan's cleanup
to its collection with weakref.finalize. The cleanup releases the spawn's
writable roots through fs_guard, which takes the registry's non-re-entrant lock;
a collection can be triggered by an allocation this thread makes while it holds
that lock, so the finalizer ran the release on the thread that was blocking it.
"""

import gc
import threading
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.sandbox.backends import SpawnPlan

pytestmark = pytest.mark.unit


def _plan_recording_its_thread(seen: dict, done: threading.Event) -> SpawnPlan:
    def cleanup() -> None:
        seen["thread"] = threading.get_ident()
        done.set()

    return SpawnPlan(argv=["tool"], env={}, cleanup=[cleanup])


def test_with_the_collector_on_the_cleanup_runs_on_a_thread_of_its_own():
    seen: dict = {}
    done = threading.Event()
    plan = _plan_recording_its_thread(seen, done)
    assert gc.isenabled()

    subprocess_utils._run_cleanup_off_the_finalizer(plan)

    assert done.wait(5), "the cleanup never ran"
    assert seen["thread"] != threading.get_ident()
    assert plan.cleanup == []


def test_with_the_collector_off_the_cleanup_runs_inline():
    """weakref.finalize's exit pass runs with the collector disabled."""
    seen: dict = {}
    done = threading.Event()
    plan = _plan_recording_its_thread(seen, done)
    gc.disable()
    try:
        subprocess_utils._run_cleanup_off_the_finalizer(plan)
    finally:
        gc.enable()
    assert done.is_set()
    assert seen["thread"] == threading.get_ident()


@patch("subprocess.Popen")
@patch("automated_security_helper.utils.subprocess_utils.find_executable")
def test_the_popen_finalizer_runs_the_cleanup_off_its_own_thread(
    mock_find_executable, mock_popen
):
    mock_find_executable.return_value = "/usr/bin/tool"
    mock_popen.return_value = MagicMock()
    plan = SpawnPlan(argv=["wrapper", "tool"], env={}, cleanup=[])
    with (
        patch.object(subprocess_utils, "_prepare_spawn", return_value=plan),
        patch.object(subprocess_utils.weakref, "finalize") as finalize,
    ):
        process = subprocess_utils.create_process_with_pipes(["tool"])
    finalize.assert_called_once_with(
        process, subprocess_utils._run_cleanup_off_the_finalizer, plan
    )
