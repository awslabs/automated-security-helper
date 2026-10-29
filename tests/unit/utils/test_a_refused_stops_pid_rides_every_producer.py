# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every producer of a could-not-stop result carries the refused stop's pid.

The pid rides as data beside the ``could_not_stop`` flag (``could_not_stop_pid``)
so a reason whose text is lost can still name the process ASH left running.
These cells drive each producer the way the EPERM cells of
``test_a_failure_while_waiting_on_a_started_child_keeps_its_code`` do: a real
child whose stop the kernel refuses, read back from the spawn record, never from
any text. The uv runner's two conversion branches are covered with the response
shape run_command_with_output_handling gives such an ending, plus the control
that a value which is not a real pid (a bool) is dropped rather than carried.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import (
    _STARTED_CHILD_ATTRIBUTE,
    COULD_NOT_STOP_MARKER,
    StartWatch,
    _StartedChild,
    run_command,
    run_command_with_output_handling,
    spawn_run,
    spawn_run_failure_after_the_start,
    watched_launch,
)
from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    _reset_uv_tool_runner_caches,
)

from utils.test_a_failure_while_waiting_on_a_started_child_keeps_its_code import (
    _DIAGNOSES_THEN_SLEEPS_MARKED,
    _POPEN_STOPPED,
    _runner,
    _the_kernel_refuses_the_stop,
    _waiting_fails_once_the_stderr_was_read,
)

_RCWOH = (
    "automated_security_helper.utils.subprocess_utils.run_command_with_output_handling"
)
_POSIX = pytest.mark.skipif(os.name != "posix", reason="a refused stop is POSIX's case")


def _refused_child_pid(children) -> int:
    """The pid of the child the refused stop left running."""
    alive = [child for child in children if child.poll() is None]
    assert children and alive, "no child outlived the stop, so the cell shows nothing"
    return children[0].pid


@pytest.mark.integration
@_POSIX
@pytest.mark.parametrize("kind", _POPEN_STOPPED)
def test_a_failed_wait_response_carries_the_refused_stops_pid(tmp_path, kind):
    """run_command_with_output_handling's failure-while-waiting response."""
    with _the_kernel_refuses_the_stop() as children:
        with _runner(kind), _waiting_fails_once_the_stderr_was_read():
            response = run_command_with_output_handling(
                list(_DIAGNOSES_THEN_SLEEPS_MARKED), results_dir=tmp_path
            )
        pid = _refused_child_pid(children)
    assert response.get("could_not_stop") is True, response
    assert response.get("could_not_stop_pid") == pid, (pid, response)


@pytest.mark.integration
@_POSIX
@pytest.mark.parametrize("kind", _POPEN_STOPPED)
def test_a_timeout_response_carries_the_refused_stops_pid(tmp_path, kind):
    """run_command_with_output_handling's timeout response."""
    with _the_kernel_refuses_the_stop() as children:
        with _runner(kind):
            response = run_command_with_output_handling(
                list(_DIAGNOSES_THEN_SLEEPS_MARKED), results_dir=tmp_path, timeout=1
            )
        pid = _refused_child_pid(children)
    assert response.get("could_not_stop") is True, response
    assert response.get("could_not_stop_pid") == pid, (pid, response)


@pytest.mark.integration
@_POSIX
@pytest.mark.parametrize("kind", _POPEN_STOPPED)
def test_run_commands_timeout_result_carries_the_pid(kind):
    """run_command's TimedOutProcess."""
    with _the_kernel_refuses_the_stop() as children:
        with _runner(kind):
            result = run_command(list(_DIAGNOSES_THEN_SLEEPS_MARKED), timeout=1)
        pid = _refused_child_pid(children)
    assert result.could_not_stop is True, result
    assert result.could_not_stop_pid == pid, (pid, result)


@pytest.mark.integration
@_POSIX
@pytest.mark.parametrize("kind", _POPEN_STOPPED)
def test_run_commands_failed_wait_result_carries_the_pid(kind):
    """run_command's PostRunErrorProcess for a failure while the child ran."""
    with _the_kernel_refuses_the_stop() as children:
        with _runner(kind), _waiting_fails_once_the_stderr_was_read():
            result = run_command(list(_DIAGNOSES_THEN_SLEEPS_MARKED))
        pid = _refused_child_pid(children)
    assert result.could_not_stop is True, result
    assert result.could_not_stop_pid == pid, (pid, result)


@pytest.mark.integration
@_POSIX
@pytest.mark.parametrize("kind", _POPEN_STOPPED)
def test_spawn_run_failure_and_the_start_watch_carry_the_pid(kind):
    """The two failure-after-the-start builders, off one refused stop."""
    args = list(_DIAGNOSES_THEN_SLEEPS_MARKED)
    watch = StartWatch()
    raised = None
    with _the_kernel_refuses_the_stop() as children:
        with _runner(kind), _waiting_fails_once_the_stderr_was_read():
            with watch.watching():
                try:
                    # Under watched_launch, as the real runner holds it around
                    # the launch's own spawn: only such a record answers for
                    # the launch.
                    with watched_launch():
                        spawn_run(args, capture_output=True)
                except Exception as error:  # the wait's own failure
                    raised = error
        pid = _refused_child_pid(children)
    assert raised is not None, "spawn_run returned, so the cell shows nothing"
    after = spawn_run_failure_after_the_start(args, raised)
    assert after is not None and after.could_not_stop_pid == pid, (pid, after)
    response = watch.failure_after_the_start(raised)
    assert response is not None and response.get("could_not_stop_pid") == pid, (
        pid,
        response,
    )


class _ExitsBetweenReads:
    """A child alive at one poll and exited at the next.

    The window a failure's two readers can straddle: a child that ignored the
    stop and then exited on its own. One read must decide both the reason's
    text and the recorded flag, or they describe two different children.
    """

    pid = 4242

    def __init__(self) -> None:
        self._polls = 0
        self.returncode = None

    def poll(self):
        self._polls += 1
        if self._polls >= 2:
            self.returncode = 0
            return 0
        return None


def _record_exiting_between_reads() -> _StartedChild:
    started = _StartedChild()
    started.process = _ExitsBetweenReads()
    return started


def _agrees(text, flagged: bool):
    """The reason's words and the recorded flag describe the same child."""
    return (COULD_NOT_STOP_MARKER in str(text or "")) == flagged


@pytest.mark.unit
def test_text_and_flag_agree_when_the_child_exits_between_reads():
    """The failure-after-the-start builders read the stop's outcome once: a
    child that exits right after the read cannot leave a reason saying it may
    still be running beside a flag saying the stop worked."""
    watch = StartWatch()
    watch.started = _record_exiting_between_reads()
    response = watch.failure_after_the_start(RuntimeError("reading output failed"))
    assert response is not None
    assert _agrees(response.get("error"), response.get("could_not_stop") is True), (
        response
    )

    raised = RuntimeError("the wait failed")
    setattr(raised, _STARTED_CHILD_ATTRIBUTE, _record_exiting_between_reads())
    after = spawn_run_failure_after_the_start(["tool"], raised)
    assert after is not None
    assert _agrees(after.error, after.could_not_stop is True), (
        after.error,
        after.could_not_stop,
    )


@pytest.mark.integration
@_POSIX
@pytest.mark.parametrize("kind", _POPEN_STOPPED[:1])
def test_the_stop_outcome_is_read_once_per_failure(tmp_path, monkeypatch, kind):
    """The in-function producers make one read of ``not_stopped()`` per failure,
    so the reason and the flag come from the same answer."""
    reads = []
    original = _StartedChild.not_stopped

    def counting(self):
        reads.append(self)
        return original(self)

    monkeypatch.setattr(subprocess_utils._StartedChild, "not_stopped", counting)

    with _the_kernel_refuses_the_stop():
        with _runner(kind), _waiting_fails_once_the_stderr_was_read():
            run_command_with_output_handling(
                list(_DIAGNOSES_THEN_SLEEPS_MARKED), results_dir=tmp_path
            )
    assert len(reads) == 1, f"{len(reads)} reads for one failed wait"

    reads.clear()
    with _the_kernel_refuses_the_stop():
        with _runner(kind), _waiting_fails_once_the_stderr_was_read():
            run_command(list(_DIAGNOSES_THEN_SLEEPS_MARKED))
    assert len(reads) == 1, f"{len(reads)} reads for one failed wait"


class _ScriptedPolls:
    """A stand-in child whose poll() answers from a script, one answer per call.

    After the script runs out, the last recorded exit code answers, as a real
    Popen keeps answering once the child was reaped.
    """

    pid = 5151

    def __init__(self, answers) -> None:
        self._answers = list(answers)
        self.polls = 0
        self.returncode = None

    def poll(self):
        self.polls += 1
        answer = self._answers.pop(0) if self._answers else self.returncode
        if answer is not None:
            self.returncode = answer
        return answer


def _scripted_record(answers) -> _StartedChild:
    started = _StartedChild()
    started.process = _ScriptedPolls(answers)
    return started


@pytest.fixture
def counted_reads(monkeypatch):
    """Counts every ``not_stopped()`` read made while a cell runs."""
    reads = []
    original = _StartedChild.not_stopped

    def counting(self):
        reads.append(self)
        return original(self)

    monkeypatch.setattr(subprocess_utils._StartedChild, "not_stopped", counting)
    return reads


def _start_watch_failure(started):
    watch = StartWatch()
    watch.started = started
    return watch.failure_after_the_start(RuntimeError("reading output failed"))


def _spawn_run_failure(started):
    raised = RuntimeError("the wait failed")
    setattr(raised, _STARTED_CHILD_ATTRIBUTE, started)
    return spawn_run_failure_after_the_start(["tool"], raised)


@pytest.mark.unit
def test_the_start_watch_builder_reads_the_stop_outcome_once(counted_reads):
    """One ``not_stopped()`` read, and one poll, per StartWatch failure."""
    started = _scripted_record([None, 0])
    response = _start_watch_failure(started)
    assert len(counted_reads) == 1, f"{len(counted_reads)} reads for one failure"
    assert started.process.polls == 1, started.process.polls
    assert response is not None and response.get("could_not_stop") is True, response


@pytest.mark.unit
def test_the_spawn_run_builder_reads_the_stop_outcome_once(counted_reads):
    """One ``not_stopped()`` read, and one poll, per spawn_run failure."""
    started = _scripted_record([None, 0])
    after = _spawn_run_failure(started)
    assert len(counted_reads) == 1, f"{len(counted_reads)} reads for one failure"
    assert started.process.polls == 1, started.process.polls
    assert after is not None and after.could_not_stop is True, after


@pytest.mark.unit
@pytest.mark.parametrize(
    "build", [_start_watch_failure, _spawn_run_failure], ids=["watch", "spawn_run"]
)
def test_alive_at_the_read_then_exiting_stays_could_not_stop_in_both(build):
    """A child alive at the single read that exits right after it: the flag and
    the reason's words both say could-not-stop, and nothing re-reads."""
    started = _scripted_record([None, 0, 0])
    out = build(started)
    assert out is not None
    error = out.get("error") if isinstance(out, dict) else out.error
    flagged = (
        out.get("could_not_stop") is True
        if isinstance(out, dict)
        else out.could_not_stop is True
    )
    assert flagged, (flagged, error)
    assert COULD_NOT_STOP_MARKER in str(error), error
    # The exit lands after the read; a later poll sees it, and nothing re-read.
    assert started.process.poll() == 0


@pytest.mark.integration
@_POSIX
def test_a_cancel_whose_stop_fails_keeps_the_record_saying_so():
    """A cancel ends the scan, so no per-scanner response exists for it; the
    spawn record is the recorded state there, and it still says the stop failed,
    with the pid, while the cancel's own words stay a cancel. The exception's
    text is reporting; nothing parses it."""
    import threading

    from automated_security_helper.core.cancellation import ScanCancelled

    cancel = threading.Event()
    cancel.set()
    record = _StartedChild()
    with _the_kernel_refuses_the_stop() as children:
        with record.recording():
            with pytest.raises(ScanCancelled) as info:
                subprocess_utils._run_cancellable(
                    list(_DIAGNOSES_THEN_SLEEPS_MARKED),
                    cancel_event=cancel,
                    graceful_timeout=False,
                    capture_output=True,
                )
        pid = _refused_child_pid(children)
    assert "may still be running" in str(info.value), info.value
    not_stopped = record.not_stopped()
    assert not_stopped is not None and COULD_NOT_STOP_MARKER in not_stopped, not_stopped
    assert record.not_stopped_pid() == pid, (pid, record.not_stopped_pid())


class _Unprintable:
    def __str__(self):
        raise RuntimeError("the error cannot be shown")


@pytest.fixture
def uv_runner():
    _reset_uv_tool_runner_caches()
    runner = UVToolRunner(uv_executable="uv")
    runner._uv_available_cache = True
    yield runner
    _reset_uv_tool_runner_caches()


def _uv_result_for(uv_runner, tmp_path, response):
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    with patch(_RCWOH) as mock_run:
        mock_run.return_value = response
        return uv_runner.run_tool("bandit", args=[], results_dir=results_dir)


#: A readable error exercises the straight conversion; one whose str() raises
#: sends the conversion into its rebuilt (kept) branch.
_CONVERSION_ERRORS = pytest.mark.parametrize(
    "error", ["the run's reason", _Unprintable()], ids=["converted", "rebuilt"]
)


@pytest.mark.unit
@_CONVERSION_ERRORS
def test_the_uv_runner_copies_the_pid_through_both_conversions(
    uv_runner, tmp_path, error
):
    result = _uv_result_for(
        uv_runner,
        tmp_path,
        {
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "timed_out": True,
            "could_not_stop": True,
            "could_not_stop_pid": 4242,
            "error": error,
        },
    )
    assert getattr(result, "could_not_stop", False) is True, result
    assert getattr(result, "could_not_stop_pid", None) == 4242, result


@pytest.mark.unit
@_CONVERSION_ERRORS
def test_the_uv_runner_drops_a_bool_pid(uv_runner, tmp_path, error):
    """The control: True is not a pid, and no number is invented from it."""
    result = _uv_result_for(
        uv_runner,
        tmp_path,
        {
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "timed_out": True,
            "could_not_stop": True,
            "could_not_stop_pid": True,
            "error": error,
        },
    )
    assert getattr(result, "could_not_stop_pid", None) is None, result
