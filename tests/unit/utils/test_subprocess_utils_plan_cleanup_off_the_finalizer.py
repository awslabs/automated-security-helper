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


def _with_the_collector_on() -> None:
    """The thread arm is taken only with the collector on; a session that runs
    with it off (a plugin, an earlier test) cannot measure it, so skip there
    rather than fail on the session's state."""
    if not gc.isenabled():
        pytest.skip("the garbage collector is off in this session")


def test_with_the_collector_on_the_cleanup_runs_on_a_thread_of_its_own():
    seen: dict = {}
    done = threading.Event()
    plan = _plan_recording_its_thread(seen, done)
    _with_the_collector_on()

    subprocess_utils._run_cleanup_off_the_finalizer(plan)

    assert done.wait(5), "the cleanup never ran"
    assert seen["thread"] != threading.get_ident()
    assert plan.cleanup == []


def test_with_the_collector_off_the_cleanup_runs_inline():
    """weakref.finalize's exit pass runs with the collector disabled."""
    seen: dict = {}
    done = threading.Event()
    plan = _plan_recording_its_thread(seen, done)
    # The collector is put back as it was found, never turned on for the rest
    # of a session that ran with it off.
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        subprocess_utils._run_cleanup_off_the_finalizer(plan)
    finally:
        if was_enabled:
            gc.enable()
    assert done.is_set()
    assert seen["thread"] == threading.get_ident()


def test_a_thread_that_cannot_start_while_finalizing_runs_the_cleanup_inline():
    """Thread.start raises RuntimeError once the interpreter is finalizing with
    gc still on; no registry call of this thread can be in progress then."""
    seen: dict = {}
    done = threading.Event()
    plan = _plan_recording_its_thread(seen, done)
    _with_the_collector_on()
    with (
        patch.object(
            threading.Thread,
            "start",
            side_effect=RuntimeError("can't create new thread at interpreter shutdown"),
        ),
        patch.object(subprocess_utils.sys, "is_finalizing", return_value=True),
    ):
        subprocess_utils._run_cleanup_off_the_finalizer(plan)
    assert done.is_set()
    assert seen["thread"] == threading.get_ident()
    assert plan.cleanup == []


def test_a_thread_that_cannot_start_after_threadings_shutdown_runs_inline():
    """threading's shutdown runs before atexit and before the finalizing flag,
    the one that makes Thread.start refuse, is set. A start that fails inside
    the atexit pass for another reason cannot leave the cleanup to atexit (a
    callback registered during the pass never runs), so the main thread being
    dead is read as shutdown and the cleanup runs inline."""
    seen: dict = {}
    done = threading.Event()
    plan = _plan_recording_its_thread(seen, done)
    _with_the_collector_on()
    with (
        patch.object(
            threading.Thread,
            "start",
            side_effect=RuntimeError("can't create new thread at interpreter shutdown"),
        ),
        patch.object(subprocess_utils.sys, "is_finalizing", return_value=False),
        patch.object(threading.main_thread(), "is_alive", return_value=False),
        patch.object(subprocess_utils.atexit, "register") as register,
    ):
        subprocess_utils._run_cleanup_off_the_finalizer(plan)
    assert done.is_set()
    assert seen["thread"] == threading.get_ident()
    assert plan.cleanup == []
    register.assert_not_called()


def test_a_thread_that_cannot_start_mid_run_leaves_the_cleanup_to_the_exit_pass():
    """Thread.start also raises RuntimeError when the process is out of threads.
    Running the cleanup inline then would bring back the self-deadlock the
    thread exists to avoid, so the cleanup is left to the interpreter's exit
    pass instead."""
    seen: dict = {}
    done = threading.Event()
    plan = _plan_recording_its_thread(seen, done)
    _with_the_collector_on()
    with (
        patch.object(
            threading.Thread,
            "start",
            side_effect=RuntimeError("can't start new thread"),
        ),
        patch.object(subprocess_utils.sys, "is_finalizing", return_value=False),
        patch.object(subprocess_utils.atexit, "register") as register,
    ):
        subprocess_utils._run_cleanup_off_the_finalizer(plan)
    assert not done.is_set(), "the cleanup ran on the finalizer's own thread"
    assert plan.cleanup, "the plan's cleanup was consumed without running"
    register.assert_called_once_with(plan.run_cleanup)


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
