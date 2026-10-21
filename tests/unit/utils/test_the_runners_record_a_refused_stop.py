# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The runners PRODUCE the could-not-stop state for a real refused stop.

Built on the EPERM helpers of
test_a_failure_while_waiting_on_a_started_child_keeps_its_code.py: a child
whose stop the kernel refuses stays alive, and each producer records
``could_not_stop`` on its own result shape -- the response dict, the typed
timeout and failed-wait results, and the late StartWatch response.
"""

import contextlib
import os
import subprocess
import sys

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import (
    StartWatch,
    run_command,
    run_command_with_output_handling,
    spawn_run,
    spawn_run_failure_after_the_start,
    watched_launch,
)

from utils.test_a_failure_while_waiting_on_a_started_child_keeps_its_code import (
    _DIAGNOSES_THEN_SLEEPS_MARKED,
    _POPEN_STOPPED,
    _runner,
    _the_kernel_refuses_the_stop,
    _waiting_fails_once_the_stderr_was_read,
)


@pytest.mark.skipif(os.name != "posix", reason="EPERM on a stop is POSIX's case")
@pytest.mark.parametrize("kind", _POPEN_STOPPED)
def test_a_failed_wait_whose_stop_was_refused_carries_the_state(tmp_path, kind):
    with _the_kernel_refuses_the_stop() as children:
        with _runner(kind), _waiting_fails_once_the_stderr_was_read():
            response = run_command_with_output_handling(
                list(_DIAGNOSES_THEN_SLEEPS_MARKED), results_dir=tmp_path
            )
        alive = [child for child in children if child.poll() is None]
    assert children and alive, "the cell shows nothing"
    assert response.get("post_run_error") is True, response
    assert response.get("could_not_stop") is True, response


@pytest.mark.skipif(os.name != "posix", reason="EPERM on a stop is POSIX's case")
@pytest.mark.parametrize("kind", _POPEN_STOPPED)
def test_a_timeout_whose_stop_was_refused_carries_the_state(tmp_path, kind):
    with _the_kernel_refuses_the_stop() as children:
        with _runner(kind):
            response = run_command_with_output_handling(
                list(_DIAGNOSES_THEN_SLEEPS_MARKED), results_dir=tmp_path, timeout=1
            )
        alive = [child for child in children if child.poll() is None]
    assert children and alive, "the cell shows nothing"
    assert response.get("timed_out") is True, response
    assert response.get("could_not_stop") is True, response


@pytest.mark.skipif(os.name != "posix", reason="EPERM on a stop is POSIX's case")
@pytest.mark.parametrize("kind", _POPEN_STOPPED)
def test_run_command_timeout_whose_stop_was_refused_carries_the_state(kind):
    with _the_kernel_refuses_the_stop() as children:
        with _runner(kind):
            result = run_command(list(_DIAGNOSES_THEN_SLEEPS_MARKED), timeout=1)
        alive = [child for child in children if child.poll() is None]
    assert children and alive, "the cell shows nothing"
    assert type(result).__name__ == "TimedOutProcess", result
    assert result.could_not_stop is True, result


@pytest.mark.skipif(os.name != "posix", reason="EPERM on a stop is POSIX's case")
@pytest.mark.parametrize("kind", _POPEN_STOPPED)
def test_run_command_failed_wait_whose_stop_was_refused_carries_the_state(kind):
    with _the_kernel_refuses_the_stop() as children:
        with _runner(kind), _waiting_fails_once_the_stderr_was_read():
            result = run_command(list(_DIAGNOSES_THEN_SLEEPS_MARKED))
        alive = [child for child in children if child.poll() is None]
    assert children and alive, "the cell shows nothing"
    assert type(result).__name__ == "PostRunErrorProcess", result
    assert result.could_not_stop is True, result


@pytest.mark.skipif(os.name != "posix", reason="EPERM on a stop is POSIX's case")
@pytest.mark.parametrize("kind", _POPEN_STOPPED)
def test_spawn_run_failed_wait_whose_stop_was_refused_carries_the_state(kind):
    args = list(_DIAGNOSES_THEN_SLEEPS_MARKED)
    watch = StartWatch()
    raised = None
    with _the_kernel_refuses_the_stop() as children:
        with _runner(kind), _waiting_fails_once_the_stderr_was_read():
            with watch.watching():
                try:
                    # Under watched_launch, as the uv runner holds it around
                    # the launch's own spawn: only such a record answers for
                    # the launch.
                    with watched_launch():
                        spawn_run(args, capture_output=True)
                except Exception as error:  # the wait's own failure
                    raised = error
        alive = [child for child in children if child.poll() is None]
    assert children and alive, "the cell shows nothing"
    assert raised is not None, "spawn_run returned"
    after = spawn_run_failure_after_the_start(args, raised)
    assert after is not None and after.could_not_stop is True, after
    response = watch.failure_after_the_start(raised)
    assert response is not None and response.get("could_not_stop") is True, response


def _the_kernel_refuses() -> None:
    raise PermissionError(1, "Operation not permitted")


def test_a_refusal_after_the_child_exited_is_not_a_failed_stop():
    """A stop can be refused about a child that already finished on its own:
    _stop_tree signals the group even when the child has exited, and a leftover
    group member the server may not signal raises EPERM. The record is marked
    for a child still running at the refusal, or for a group that still exists
    (the cell below); this plain child leads no group, so its own exit clears
    the mark. Its pipes are still open here (they close only in _reap), so a
    poll showing an exit is the child's own, not the pipe-close ending the
    mark exists for."""
    record = subprocess_utils._StartedChild()
    with record.recording():
        process = subprocess.Popen([sys.executable, "-c", "pass"])
        subprocess_utils._note_start(process)
        process.wait(timeout=10)
        delivered = subprocess_utils._send_stop(process, _the_kernel_refuses)
    assert delivered is False, "the cell shows nothing: the stop was not refused"
    assert record.stop_refused is False, "an exited child was marked stop-refused"
    assert record.not_stopped() is None, record.not_stopped()


def test_a_refusal_while_the_child_runs_is_a_failed_stop():
    """The control: the same refusal about a child still running keeps the mark,
    and the reason names the pid."""
    record = subprocess_utils._StartedChild()
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        with record.recording():
            subprocess_utils._note_start(process)
            delivered = subprocess_utils._send_stop(process, _the_kernel_refuses)
        assert delivered is False
        assert record.stop_refused is True
        reason = record.not_stopped()
        assert reason is not None and str(process.pid) in reason, reason
    finally:
        process.kill()
        process.wait(timeout=10)


#: Leads its own group, starts a same-group survivor, writes its pid, and exits:
#: the group outlives the leader, which is the state a tree stop then meets.
_LEADER_EXITS_SURVIVOR_STAYS = (
    "import pathlib, subprocess, sys, time; "
    "survivor = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
    "pathlib.Path(sys.argv[1]).write_text(str(survivor.pid))"
)


def _survivor_pid(pid_file, timeout=20.0) -> int:
    import time as _time

    deadline = _time.monotonic() + timeout
    while _time.monotonic() < deadline:
        text = pid_file.read_text() if pid_file.exists() else ""
        if text:
            return int(text)
        _time.sleep(0.02)
    raise AssertionError("the leader never wrote the survivor's pid")


@pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX's case")
def test_a_group_refusal_after_the_leader_exited_is_a_failed_stop(
    tmp_path, monkeypatch
):
    """Through the real tree stop: the leader exited, a same-group survivor
    keeps the group alive, and the kernel refuses the group signal. The leader's
    exit is not the stop having worked -- the survivor can still write into the
    output directory -- so the record must say ASH could not stop it. Gated on
    the leader's poll() alone, the refusal was swallowed and the run could
    exit 0 with the process still running. Only the kernel's EPERM is injected
    (a member the server may not signal needs root to create); the group's
    existence is read for real, and the whole _stop_tree -> _stop_child ->
    _note_stop_refused chain is the production one."""
    pid_file = tmp_path / "survivor.pid"
    record = subprocess_utils._StartedChild()
    leader = subprocess.Popen(
        [sys.executable, "-c", _LEADER_EXITS_SURVIVOR_STAYS, str(pid_file)],
        start_new_session=True,
    )
    survivor = None
    try:
        survivor = _survivor_pid(pid_file)
        leader.wait(timeout=20)

        real_signal_group = subprocess_utils._signal_group

        def the_kernel_refuses_real_signals(pgid, signum):
            if signum == 0:
                return real_signal_group(pgid, signum)
            raise PermissionError(1, "Operation not permitted")

        monkeypatch.setattr(
            subprocess_utils, "_signal_group", the_kernel_refuses_real_signals
        )
        with record.recording():
            subprocess_utils._note_start(leader)
            subprocess_utils._stop_child(
                leader.args, leader, subprocess_utils._stop_tree, 0.0, None
            )
        monkeypatch.setattr(subprocess_utils, "_signal_group", real_signal_group)

        assert leader.poll() is not None, "the cell shows nothing: the leader runs"
        import automated_security_helper.utils.subprocess_utils as su

        assert su._group_exists(leader.pid), (
            "the cell shows nothing: no survivor kept the group alive"
        )
        reason = record.not_stopped()
        assert record.stop_refused is True, (
            "a refused group stop with a live survivor was not marked"
        )
        assert reason is not None and str(leader.pid) in reason, reason
    finally:
        if survivor is not None:
            with contextlib.suppress(OSError):
                os.kill(survivor, 9)
        with contextlib.suppress(Exception):
            leader.kill()
            leader.wait(timeout=10)


#: Leads a group, starts a child that outlives it, and keeps running itself, so
#: the tree stop meets a live leader. Writes the child's pid first.
_LEADER_RUNS_WITH_SURVIVOR = (
    "import subprocess, sys, time\n"
    "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
    "open(sys.argv[1], 'w').write(str(child.pid))\n"
    "time.sleep(60)\n"
)


def test_a_kill_the_kernel_reports_done_with_a_survivor_is_a_failed_stop(
    tmp_path, monkeypatch
):
    """The kernel reports a group kill as a success when it signalled ANY
    member, so a member ASH may not signal survives with no EPERM raised:
    the settle sees the zombie leader, the reap takes it, and the run read
    as a plain stop that worked. The partial success is simulated below
    _signal_group -- os.killpg delivers to the leader alone and returns
    success, exactly the kernel's shape -- never by forcing EPERM at
    _signal_group, which the refusal cells already cover. After the reap the
    leader is gone, so a group that still exists is a survivor, and the
    record must say ASH could not stop the tool."""
    pid_file = tmp_path / "survivor.pid"
    record = subprocess_utils._StartedChild()
    leader = subprocess.Popen(
        [sys.executable, "-c", _LEADER_RUNS_WITH_SURVIVOR, str(pid_file)],
        start_new_session=True,
    )
    survivor = None
    try:
        survivor = _survivor_pid(pid_file)
        real_killpg = os.killpg

        def killpg_signals_the_leader_alone(pgid, signum):
            if signum == 0:
                return real_killpg(pgid, 0)
            # The kernel's partial success: one member signalled, no error.
            os.kill(leader.pid, signum)
            return None

        monkeypatch.setattr(os, "killpg", killpg_signals_the_leader_alone)
        with record.recording():
            subprocess_utils._note_start(leader)
            subprocess_utils._stop_child(
                leader.args, leader, subprocess_utils._stop_tree, 0.0, None
            )
        monkeypatch.setattr(os, "killpg", real_killpg)

        assert leader.poll() is not None, "the cell shows nothing: the leader runs"
        assert os.kill(survivor, 0) is None, (
            "the cell shows nothing: the survivor is gone"
        )
        assert record.stop_refused is True, (
            "a kill the kernel reported done left a survivor unreported"
        )
        reason = record.not_stopped()
        assert reason is not None and str(leader.pid) in reason, reason
        assert record.exit_code() is None, record.exit_code()
    finally:
        if survivor is not None:
            with contextlib.suppress(OSError):
                os.kill(survivor, 9)
        with contextlib.suppress(Exception):
            leader.kill()
            leader.wait(timeout=10)


def test_a_refused_stop_reports_no_exit_code(tmp_path, monkeypatch):
    """A tool ASH could not stop has no exit code to report (error_after's own
    contract): the leader's exit code is the leader's alone, and a survivor may
    still write into the output directory, so the run never reads as one that
    finished. The response for a failure after such a refusal carries no code,
    as a could-not-stop timeout carries none -- it carried the exited leader's
    0 beside "may still be running"."""
    pid_file = tmp_path / "survivor.pid"
    record = subprocess_utils._StartedChild()
    leader = subprocess.Popen(
        [sys.executable, "-c", _LEADER_EXITS_SURVIVOR_STAYS, str(pid_file)],
        start_new_session=True,
    )
    survivor = None
    try:
        survivor = _survivor_pid(pid_file)
        leader.wait(timeout=20)
        real_signal_group = subprocess_utils._signal_group

        def the_kernel_refuses_real_signals(pgid, signum):
            if signum == 0:
                return real_signal_group(pgid, signum)
            raise PermissionError(1, "Operation not permitted")

        monkeypatch.setattr(
            subprocess_utils, "_signal_group", the_kernel_refuses_real_signals
        )
        with record.recording():
            subprocess_utils._note_start(leader)
            subprocess_utils._stop_child(
                leader.args, leader, subprocess_utils._stop_tree, 0.0, None
            )
        monkeypatch.setattr(subprocess_utils, "_signal_group", real_signal_group)

        assert record.stop_refused is True, "the cell shows nothing: no refusal"
        assert record.exit_code() is None, (
            f"a tool ASH could not stop reported an exit code: {record.exit_code()!r}"
        )
        watch = subprocess_utils.StartWatch()
        watch.started = record
        response = watch.failure_after_the_start(RuntimeError("the wait broke"))
        assert response is not None
        assert response.get("could_not_stop") is True, response
        assert response.get("could_not_stop_pid") == leader.pid, response
        assert response.get("returncode") is None, response
    finally:
        if survivor is not None:
            with contextlib.suppress(OSError):
                os.kill(survivor, 9)
        with contextlib.suppress(Exception):
            leader.kill()
            leader.wait(timeout=10)
