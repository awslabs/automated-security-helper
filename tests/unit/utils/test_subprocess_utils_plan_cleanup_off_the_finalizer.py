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


def test_with_the_collector_on_the_cleanup_runs_on_a_thread_of_its_own(monkeypatch):
    seen: dict = {}
    done = threading.Event()
    plan = _plan_recording_its_thread(seen, done)
    _with_the_collector_on()
    # The worker is kept so it can be joined: the callback sets ``done`` itself,
    # while ``SpawnPlan.run_cleanup`` is still running on the worker, so reading
    # the plan's list right after ``done`` raced a thread nobody had joined.
    made: list = []
    make_thread = subprocess_utils.ash_thread

    def recording_thread(*args, **kwargs):
        worker = make_thread(*args, **kwargs)
        made.append(worker)
        return worker

    monkeypatch.setattr(subprocess_utils, "ash_thread", recording_thread)

    subprocess_utils._run_cleanup_off_the_finalizer(plan)

    assert done.wait(5), "the cleanup never ran"
    (worker,) = made
    worker.join(5)
    assert not worker.is_alive(), "the cleanup thread did not finish"
    assert seen["thread"] == worker.ident
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
    gc still on (``sys.is_finalizing()`` reads True, and is patched to here); no
    registry call of this thread can be in progress then."""
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
    """threading's shutdown runs before atexit, and before the interpreter is
    marked finalizing (the state ``sys.is_finalizing()`` reports, and the one
    that makes Thread.start refuse). A start that fails inside the atexit pass
    for another reason cannot leave the cleanup to atexit (a callback registered
    during the pass never runs), so the main thread being dead is read as
    shutdown and the cleanup runs inline: ``sys.is_finalizing()`` is patched to
    False here, as it reads during that pass."""
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


class _Collectable:
    """A process stand-in a weak reference can follow."""


@patch("automated_security_helper.utils.subprocess_utils.find_executable")
def test_a_collected_popen_runs_the_plans_cleanup_on_a_thread_of_its_own(
    mock_find_executable,
):
    """End to end: the registration above is not the behavior. Dropping the
    last reference to the process runs the finalizer, and the plan's cleanup
    runs on a thread other than the one that dropped it."""
    mock_find_executable.return_value = "/usr/bin/tool"
    _with_the_collector_on()
    seen: dict = {}
    done = threading.Event()
    plan = _plan_recording_its_thread(seen, done)
    # Held in a list the Popen stand-in empties, so the only reference left after
    # the call is the caller's own.
    holder = [_Collectable()]
    with (
        patch.object(
            subprocess_utils.subprocess,
            "Popen",
            side_effect=lambda *args, **kwargs: holder.pop(),
        ),
        patch.object(subprocess_utils, "_prepare_spawn", return_value=plan),
    ):
        process = subprocess_utils.create_process_with_pipes(["tool"])
    assert not done.is_set(), "the cleanup ran before the process was dropped"
    del process
    gc.collect()
    assert done.wait(5), "the cleanup never ran after the process was dropped"
    assert seen["thread"] != threading.get_ident()
