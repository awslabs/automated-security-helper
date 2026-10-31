# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A failure while ASH waited on a child that had started is no failure to start.

Why this file exists
--------------------
Were run_command and run_command_with_output_handling to put every exception
their runner raised down to a command that never started, exit code 127 and
``spawn_failed``, then since the runner starts the child and then waits on it, an
error reading its pipes after it started, raised from ``communicate()``, would be
reported as "never started" too: the scan would end ERROR, but name the wrong
cause.

So an exception raised inside a started child's own methods (communicate, wait,
the exit of its with-block) is a failure after the start: ``post_run_error``,
``spawn_failed`` False and the error. A child that had exited on its own keeps its
exit code. A child still running when the read fails is stopped by ASH, and the
signal ASH sent is not the tool's code: the response has returncode None, and the
error says "ASH stopped the tool after: <error>". Either way the stderr read
before the failure is kept. A failure in the constructor, or before it, stays 127.
"""

from __future__ import annotations

import contextlib
import errno
import functools
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from typing import Iterator, Optional
from unittest.mock import patch

import pytest

from automated_security_helper.core.cancellation import cancel_scope
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import (
    SPAWN_FAILURE_RETURNCODE,
    PostRunErrorProcess,
    run_command,
    run_command_with_output_handling,
)

#: A child that is still running when ASH's read of its pipes fails.
SLEEPER = [sys.executable, "-c", "import time; time.sleep(60)"]

#: What every response for a child ASH stopped says, before the error.
ASH_STOPPED = "ASH stopped the tool after"

#: Writes a diagnostic to stderr at once, then runs until something stops it.
_DIAGNOSE = "import sys, time; sys.stderr.write('diag before the failure\\n')"
DIAGNOSES_THEN_SLEEPS = [
    sys.executable,
    "-c",
    f"{_DIAGNOSE}; sys.stderr.flush(); time.sleep(60)",
]

#: Writes a diagnostic to stderr and exits 3 on its own.
DIAGNOSES_THEN_EXITS_3 = [sys.executable, "-c", f"{_DIAGNOSE}; sys.exit(3)"]

#: subprocess.run; the cancellable runner a scan's children go through; and the
#: runner a sandboxed spawn uses, which stops its child with SIGTERM first.
RUNNERS = [
    pytest.param(None, id="plain"),
    pytest.param("cancel-scope", id="in-a-cancel-scope"),
    pytest.param("stoppable", id="sandboxed-runner"),
]


@contextlib.contextmanager
def _runner(kind: Optional[str]) -> Iterator[None]:
    if kind == "cancel-scope":
        with cancel_scope(threading.Event()):
            yield
    elif kind == "stoppable":
        with patch.object(
            subprocess_utils,
            "_runner",
            lambda sandboxed: subprocess_utils._run_stoppable,
        ):
            yield
    else:
        yield


def _reading_the_pipes_fails():
    return patch.object(
        subprocess.Popen,
        "_communicate",
        side_effect=RuntimeError("reading the pipes failed"),
    )


def _tool_that_exits_3(marker) -> list:
    """A child that writes ``marker``, so the test can tell it started, and exits 3."""
    program = f"import pathlib, sys; pathlib.Path({str(marker)!r}).touch(); sys.exit(3)"
    return [sys.executable, "-c", program]


def _communicate_returns_then_raises():
    """communicate() reads the child's output and waits for it, then raises."""
    real = subprocess.Popen.communicate

    def communicate(self, *args, **kwargs):
        real(self, *args, **kwargs)
        raise RuntimeError("handling the output failed")

    return patch.object(subprocess.Popen, "communicate", communicate)


@pytest.mark.integration
@pytest.mark.parametrize("kind", RUNNERS)
def test_run_command_keeps_the_exit_code_of_a_child_that_exited(tmp_path, kind):
    marker = tmp_path / "started"

    with _runner(kind), _communicate_returns_then_raises():
        result = run_command(_tool_that_exits_3(marker))

    assert marker.exists(), "the child never started, so the cell shows nothing"
    assert isinstance(result, PostRunErrorProcess), result
    assert result.returncode == 3, result
    assert "never ran" not in (result.stderr or ""), result


@pytest.mark.integration
@pytest.mark.parametrize("kind", RUNNERS)
def test_run_command_with_output_handling_keeps_the_exit_code_of_a_child_that_exited(
    tmp_path, kind
):
    marker = tmp_path / "started"
    results = tmp_path / "results"

    with _runner(kind), _communicate_returns_then_raises():
        response = run_command_with_output_handling(
            _tool_that_exits_3(marker), results_dir=results, class_name="Tool"
        )

    assert marker.exists(), "the child never started, so the cell shows nothing"
    assert response["returncode"] == 3, response
    assert response["post_run_error"] is True, response
    assert response["spawn_failed"] is False, response
    assert "never ran" not in str(response), response
    # The "never ran" text a spawn failure writes there would replace the log.
    assert not (results / "Tool.stderr.log").exists()


@pytest.mark.integration
@pytest.mark.parametrize("kind", RUNNERS)
def test_run_command_reports_no_code_for_a_child_ash_stopped(kind):
    """The child was still running when waiting on it failed, so ASH stopped it.
    The signal ASH sent is ASH's own: returncode None, never -9, -15 or 1."""
    with _runner(kind), _reading_the_pipes_fails():
        result = run_command(SLEEPER)

    assert isinstance(result, PostRunErrorProcess), result
    assert result.returncode is None, result.returncode
    assert f"{ASH_STOPPED}: reading the pipes failed" in result.error, result.error
    assert not getattr(result, "spawn_failed", False), result


@pytest.mark.integration
@pytest.mark.parametrize("kind", RUNNERS)
def test_run_command_with_output_handling_reports_no_code_for_a_child_ash_stopped(
    tmp_path, kind
):
    with _runner(kind), _reading_the_pipes_fails():
        response = run_command_with_output_handling(SLEEPER, results_dir=tmp_path)

    assert response["returncode"] is None, response
    assert response["post_run_error"] is True, response
    assert response["spawn_failed"] is False, response
    assert f"{ASH_STOPPED}: reading the pipes failed" in response["error"], response


def _waiting_fails_once_the_stderr_was_read(
    failure: str = "reading the output failed", after_exit: bool = False
):
    """For each child, its first communicate() reads until the child's stderr holds
    its diagnostic, or the child exits, and then raises: a failure while waiting,
    after some output was read. Every later call on that child is the real one, so
    what was read can still be collected.

    With ``after_exit``, it raises only once the real communicate() has returned:
    both pipes at EOF and the child waited on, so it has exited and been reaped,
    and its own code is the only right answer. Without it, the raise can come
    while the child is still exiting, and stopping it is then right too.
    """
    real = subprocess.Popen.communicate
    failed: list = []

    def communicate(self, *args, **kwargs):
        if any(process is self for process in failed):
            return real(self, *args, **kwargs)
        failed.append(self)
        to_send = args[0] if args else kwargs.get("input")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                real(self, to_send, timeout=0.2)
            except subprocess.TimeoutExpired as partial:
                to_send = None
                if not after_exit and b"diag before the failure" in (
                    partial.stderr or b""
                ):
                    break
            else:
                break
        raise RuntimeError(failure)

    return patch.object(subprocess.Popen, "communicate", communicate)


@pytest.mark.integration
@pytest.mark.parametrize("kind", RUNNERS)
def test_a_child_ash_stopped_keeps_the_stderr_read_before_the_failure(tmp_path, kind):
    """The tool's diagnostics are what explain ASH's own failure."""
    with _runner(kind), _waiting_fails_once_the_stderr_was_read():
        result = run_command(DIAGNOSES_THEN_SLEEPS)
        response = run_command_with_output_handling(
            DIAGNOSES_THEN_SLEEPS, results_dir=tmp_path
        )

    assert getattr(result, "post_run_error", False) is True, result
    assert result.returncode is None, result
    assert "diag before the failure" in (result.stderr or ""), result
    assert response["post_run_error"] is True, response
    assert response["returncode"] is None, response
    assert "diag before the failure" in response.get("stderr", ""), response


@pytest.mark.integration
@pytest.mark.parametrize("kind", RUNNERS)
def test_a_child_that_exited_keeps_its_code_and_the_stderr_read_before_the_failure(
    tmp_path, kind
):
    """The failure comes only after the child exited and was reaped, so its code
    is known: 3, with the stderr it wrote."""
    with _runner(kind), _waiting_fails_once_the_stderr_was_read(after_exit=True):
        result = run_command(DIAGNOSES_THEN_EXITS_3)
        response = run_command_with_output_handling(
            DIAGNOSES_THEN_EXITS_3, results_dir=tmp_path
        )

    assert getattr(result, "post_run_error", False) is True, result
    assert result.returncode == 3, result
    assert "diag before the failure" in (result.stderr or ""), result
    assert response["post_run_error"] is True, response
    assert response["returncode"] == 3, response
    assert "diag before the failure" in response.get("stderr", ""), response


#: Starts a grandchild that inherits the pipes and outlives the child, writes the
#: grandchild's pid to the file named by its argument, then writes the diagnostic
#: and runs until something stops it. The grandchild gets a session of its own, so
#: a stop of the tool's process group does not reach it and the pipes stay held;
#: _kill_the_grandchild ends it by pid.
_DIAGNOSES_WITH_A_GRANDCHILD = (
    "import pathlib, subprocess, sys, time; "
    "g = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], "
    "start_new_session=True); "
    "pathlib.Path(sys.argv[1]).write_text(str(g.pid)); "
    "sys.stderr.write('diag before the failure\\n'); sys.stderr.flush(); "
    "time.sleep(60)"
)


def _kill_the_grandchild(pid_file) -> None:
    try:
        pid = int(pid_file.read_text())
    except (OSError, ValueError):
        return
    with contextlib.suppress(OSError):
        os.kill(pid, signal.SIGKILL)


@pytest.mark.integration
@pytest.mark.skipif(os.name != "posix", reason="the grandchild is POSIX's case")
@pytest.mark.parametrize("kind", RUNNERS)
def test_the_stderr_read_before_the_failure_is_collected_within_a_bound(tmp_path, kind):
    """A process the tool left holding its pipes doesn't hold up collecting what
    the tool wrote before ASH's failure: ASH stops the tool and reads what is left
    for a bounded time, well short of the grandchild's 60 s."""
    pid_file = tmp_path / "grandchild.pid"
    command = [sys.executable, "-c", _DIAGNOSES_WITH_A_GRANDCHILD, str(pid_file)]
    started = time.monotonic()
    try:
        with _runner(kind), _waiting_fails_once_the_stderr_was_read():
            response = run_command_with_output_handling(
                command, results_dir=tmp_path / "results"
            )
        elapsed = time.monotonic() - started

        assert pid_file.exists(), "no grandchild started, so the cell shows nothing"
        assert response["post_run_error"] is True, response
        assert response["returncode"] is None, response
        assert "diag before the failure" in response.get("stderr", ""), response
        assert elapsed < 20, f"collecting the stderr took {elapsed:.1f}s"
    finally:
        _kill_the_grandchild(pid_file)


def _tool_that_ends_by_its_own_signal(marker, signum=None) -> list:
    """A child that writes ``marker`` and then sends itself ``signum`` (SIGUSR1
    when none is given). SIGKILL and SIGTERM are the signals ASH's own stop
    sends, so a design that reads them as its stop is caught. The default is
    resolved here, not in the signature: a POSIX-only signal name evaluated at
    import would fail Windows collection for the whole module."""
    if signum is None:
        signum = signal.SIGUSR1
    # A signal that can be caught gets its default action back first, so an
    # ignored disposition the child inherited (nohup, a CI harness ignoring
    # SIGHUP or SIGTERM) can't keep it alive; SIGKILL can't be caught, ignored
    # or reset.
    restore = (
        ""
        if signum == signal.SIGKILL
        else f"signal.signal({int(signum)}, signal.SIG_DFL); "
    )
    program = (
        f"import os, pathlib, signal; {restore}"
        f"pathlib.Path({str(marker)!r}).touch(); "
        f"os.kill(os.getpid(), {int(signum)})"
    )
    return [sys.executable, "-c", program]


@pytest.mark.integration
@pytest.mark.skipif(os.name != "posix", reason="a signal death is POSIX's case")
@pytest.mark.parametrize("signal_name", ["SIGUSR1", "SIGKILL", "SIGTERM"])
@pytest.mark.parametrize("kind", RUNNERS)
def test_a_tool_that_ended_by_its_own_signal_keeps_that_code(
    tmp_path, kind, signal_name
):
    """The tool ended itself by a signal, and then ASH's handling failed. The
    negative code is the tool's own, so it is kept, the run is flagged as
    signaled, and nothing says ASH stopped the tool: only a child ASH stopped
    has no code. Parametrized by NAME, resolved here: SIGUSR1 and SIGKILL do not
    exist on Windows, and a parametrize list is evaluated at collection."""
    signum = getattr(signal, signal_name)
    first, second = tmp_path / "first", tmp_path / "second"
    third = tmp_path / "third"

    with _runner(kind), _communicate_returns_then_raises():
        result = run_command(_tool_that_ends_by_its_own_signal(first, signum))
        response = run_command_with_output_handling(
            _tool_that_ends_by_its_own_signal(second, signum),
            results_dir=tmp_path / "results",
        )
        with pytest.raises(subprocess_utils.PostRunError) as info:
            run_command(_tool_that_ends_by_its_own_signal(third, signum), check=True)

    assert first.exists() and second.exists(), "the tool never started"
    assert result.returncode == -signum, result
    assert getattr(result, "post_run_error", False) is True, result
    assert getattr(result, "signaled", False) is True, result
    assert getattr(result, "signal", None) == int(signum), result
    assert ASH_STOPPED not in (getattr(result, "error", "") or ""), result
    assert response["returncode"] == -signum, response
    assert response["post_run_error"] is True, response
    assert response.get("signaled") is True, response
    assert response.get("signal") == int(signum), response
    assert ASH_STOPPED not in response["error"], response
    # check=True raises the exception counterpart with the same three facts.
    assert third.exists(), "the tool never started"
    assert info.value.returncode == -signum, info.value
    assert info.value.signaled is True, info.value
    assert info.value.signal == int(signum), info.value
    assert ASH_STOPPED not in str(info.value), info.value


@pytest.mark.integration
def test_a_failure_right_after_popen_returned_is_after_the_start(monkeypatch):
    """The child counts as started once Popen returns. A step that fails between
    that and the first wait, here the cancellable runner's own record of the
    spawn, is a failure after the start: never 127, and the child is stopped, not
    left running."""
    started: list = []

    class _Recorded(subprocess.Popen):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            started.append(self)

    real_record = subprocess_utils._record_spawn

    def recording_fails(process):
        real_record(process)
        raise RuntimeError("recording the spawn failed")

    monkeypatch.setattr(subprocess, "Popen", _Recorded)
    monkeypatch.setattr(subprocess_utils, "_record_spawn", recording_fails)
    try:
        with cancel_scope(threading.Event()):
            result = run_command(SLEEPER)

        assert started, "no child started, so the cell shows nothing"
        assert result.returncode != SPAWN_FAILURE_RETURNCODE, result
        assert not getattr(result, "spawn_failed", False), result
        assert getattr(result, "post_run_error", False) is True, result
        assert result.returncode is None, result
        assert f"{ASH_STOPPED}: recording the spawn failed" in result.error, result
        try:
            started[0].wait(timeout=5)
        except subprocess.TimeoutExpired:
            pytest.fail("the child was left running after ASH's failure")
    finally:
        for process in started:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=30)


class _RefusesAttributes(Exception):
    """An exception whose type refuses attributes set on it, as a frozen one does.
    The interpreter's own (``__traceback__``, ``__context__`` and the rest) are let
    through: contextlib sets ``__traceback__`` as the exception leaves a block."""

    def __setattr__(self, name, value):
        if name.startswith("__") and name.endswith("__"):
            super().__setattr__(name, value)
            return
        raise AttributeError(f"{type(self).__name__} is frozen")


def _the_runner_raises(monkeypatch, error: BaseException) -> None:
    """Both runners a spawn outside a cancel scope can get raise ``error``, before
    they start anything."""

    def runner(args, **kwargs):
        raise error

    monkeypatch.setattr(subprocess_utils, "_run_plain", runner)
    monkeypatch.setattr(subprocess_utils, "_run_stoppable", runner)


@pytest.mark.unit
def test_a_runner_error_that_refuses_attributes_reaches_spawn_runs_caller(
    monkeypatch,
):
    """spawn_run notes its record of the start on the exception its runner raised.
    For an exception that refuses attributes, that note raised AttributeError in its
    place, and the runner's own error was lost. It reaches the caller unchanged."""
    raised = _RefusesAttributes("the runner's own error")
    _the_runner_raises(monkeypatch, raised)

    with pytest.raises(_RefusesAttributes) as excinfo:
        subprocess_utils.spawn_run([sys.executable, "-c", "pass"], capture_output=True)

    assert excinfo.value is raised


@pytest.mark.unit
def test_a_runner_error_that_refuses_attributes_reaches_the_uv_runners_caller(
    tmp_path, monkeypatch
):
    """The same through the uv runner's run without a results directory, which
    spawns through spawn_run. run_tool wraps what its spawn raised in
    UVToolRunnerError, as it types every other failure for its callers, so the
    caller gets the typed error with the runner's own error as its cause: the
    failure that ended the wait keeps its identity through the chain."""
    from automated_security_helper.utils.uv_tool_runner import (
        UVToolRunner,
        UVToolRunnerError,
    )

    raised = _RefusesAttributes("the runner's own error")
    _the_runner_raises(monkeypatch, raised)
    monkeypatch.setattr(UVToolRunner, "is_uv_available", lambda self: True)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(UVToolRunnerError) as excinfo:
        UVToolRunner(uv_executable=sys.executable).run_tool("semgrep", args=["scan"])

    assert excinfo.value.__cause__ is raised


#: What the runners' record of the start raises in the cell below.
_NOTING_FAILED = "noting the start failed"


@pytest.mark.integration
@pytest.mark.parametrize("kind", RUNNERS)
def test_a_raise_while_noting_the_start_stops_the_child(tmp_path, monkeypatch, kind):
    """Popen returned, so the child has started, and the runner's own note of the
    start raised before it noted anything. That is a failure after the start, on
    each runner: the child is stopped, not left running, and the result is
    post_run_error with no code, never 127 or spawn_failed."""
    started: list = []

    class _Recorded(subprocess.Popen):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            started.append(self)

    monkeypatch.setattr(subprocess, "Popen", _Recorded)
    # Put back afterwards: a cancellable spawn that raised here may have left its
    # start counted, and the server's stop waits for every counted start.
    monkeypatch.setattr(
        subprocess_utils, "_SPAWNS_STARTING", subprocess_utils._SPAWNS_STARTING
    )
    try:
        with (
            _runner(kind),
            patch.object(
                subprocess_utils,
                "_note_start",
                side_effect=RuntimeError(_NOTING_FAILED),
            ),
        ):
            result = run_command(SLEEPER)
            response = run_command_with_output_handling(SLEEPER, results_dir=tmp_path)

        assert len(started) == 2, "the children never started, so this shows nothing"
        for outcome in (
            {
                "returncode": result.returncode,
                "spawn_failed": getattr(result, "spawn_failed", False),
                "post_run_error": getattr(result, "post_run_error", False),
                "error": getattr(result, "error", None) or "",
            },
            response,
        ):
            assert outcome["returncode"] != SPAWN_FAILURE_RETURNCODE, outcome
            assert outcome.get("spawn_failed") is not True, outcome
            assert outcome.get("post_run_error") is True, outcome
            assert outcome["returncode"] is None, outcome
            assert f"{ASH_STOPPED}: {_NOTING_FAILED}" in outcome["error"], outcome
        for process in started:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pytest.fail(f"the child (pid {process.pid}) was left running")
    finally:
        for process in started:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=30)


@pytest.mark.integration
def test_a_noting_failure_leaves_no_spawn_counted(monkeypatch):
    """A cancellable spawn is counted before its child starts, and uncounted when
    the child is recorded or the spawn gives up. A raise in the runner's note of
    the start must not leave it counted: the count never drains, so every later
    server stop waits its full settle bound for a spawn that ended long ago, and
    the child is in no group the stop can reach."""
    started: list = []

    class _Recorded(subprocess.Popen):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            started.append(self)

    monkeypatch.setattr(subprocess, "Popen", _Recorded)
    # Put back afterwards whatever happens, so a red here cannot poison the
    # worker's later server-stop tests.
    monkeypatch.setattr(
        subprocess_utils, "_SPAWNS_STARTING", subprocess_utils._SPAWNS_STARTING
    )
    before = subprocess_utils._SPAWNS_STARTING
    # A count, so the comparison below is by value: a mutable counter object
    # would compare equal to itself whatever happened to it.
    assert isinstance(before, int), type(before)
    try:
        with (
            cancel_scope(threading.Event()),
            patch.object(
                subprocess_utils,
                "_note_start",
                side_effect=RuntimeError(_NOTING_FAILED),
            ),
        ):
            run_command(SLEEPER)

        assert started, "no child started, so the cell shows nothing"
        assert subprocess_utils._SPAWNS_STARTING == before, (
            "the spawn stayed counted after its noting failure: "
            f"{subprocess_utils._SPAWNS_STARTING} counted, {before} before"
        )
    finally:
        for process in started:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=30)


# -- a stop the kernel refuses -------------------------------------------------------

#: Marks the tool's child, so the stop is refused for that process and no other.
_MARK = "ASH-STOP-REFUSED-TOOL"

#: Writes its diagnostic to stderr at once, then runs until the test's process
#: is gone, so no suite load can outwait it: a fixed sleep here was outlived by
#: a loaded run's machinery, and the child's own exit broke the cells' premise
#: that a child outlives the refused stop. The kill in the fixture's cleanup
#: still ends it; the 600 s cap only bounds a leak if the watch ever fails.
_DIAGNOSES_THEN_SLEEPS_MARKED = [
    sys.executable,
    "-c",
    (
        f"{_DIAGNOSE}; sys.stderr.flush()\n"
        "import os\n"
        "parent = os.getppid()\n"
        "deadline = time.monotonic() + 600\n"
        "while os.getppid() == parent and time.monotonic() < deadline:\n"
        "    time.sleep(0.2)"
    ),
    _MARK,
]

#: The runners whose own stop calls Popen's: the plain one and the sandboxed one.
_POPEN_STOPPED = [
    pytest.param(None, id="plain"),
    pytest.param("stoppable", id="sandboxed-runner"),
]


@contextlib.contextmanager
def _the_kernel_refuses_the_stop() -> Iterator[list]:
    """Every signal ASH sends the tool's child raises EPERM, as for a setuid
    program the tool started, and the child keeps running: the ones sent through
    Popen (send_signal) and the ones sent to the child's own process group
    (os.killpg, the plain runner's stop of a timed-out child, which leads a group
    of its own so the kill reaches what it started). A probe of the group (signal
    0) is answered for real, so the stop paths read the group as it is. Yields
    the children started; each is killed for real afterwards."""
    children: list = []
    real_init = subprocess.Popen.__init__
    real_send_signal = subprocess.Popen.send_signal
    real_killpg = os.killpg

    def recording(self, *args, **kwargs):
        real_init(self, *args, **kwargs)
        if _MARK in [str(part) for part in (self.args or [])]:
            children.append(self)

    def refused(self, sig):
        if any(child is self for child in children):
            raise PermissionError(errno.EPERM, "Operation not permitted")
        return real_send_signal(self, sig)

    def group_refused(pgid, signum):
        if signum != 0 and any(child.pid == pgid for child in children):
            raise PermissionError(errno.EPERM, "Operation not permitted")
        return real_killpg(pgid, signum)

    try:
        with (
            patch.object(subprocess.Popen, "__init__", recording),
            patch.object(subprocess.Popen, "send_signal", refused),
            patch.object(os, "killpg", group_refused),
        ):
            yield children
    finally:
        for child in children:
            with contextlib.suppress(OSError):
                os.kill(child.pid, signal.SIGKILL)
            with contextlib.suppress(subprocess.TimeoutExpired):
                child.wait(timeout=30)


@pytest.mark.integration
@pytest.mark.skipif(os.name != "posix", reason="EPERM on a stop is POSIX's case")
@pytest.mark.parametrize("kind", _POPEN_STOPPED)
def test_a_failed_wait_whose_stop_the_kernel_refused_says_so(tmp_path, kind):
    """Waiting on the tool failed, and the stop that followed raised EPERM. Nothing
    stopped the tool, so the response says ASH could not stop it, which may still
    be running, with its pid. It keeps the wait's own error and the stderr read
    before it, has no code, and never says ASH stopped the tool."""
    started = time.monotonic()
    with _the_kernel_refuses_the_stop() as children:
        with _runner(kind), _waiting_fails_once_the_stderr_was_read():
            response = run_command_with_output_handling(
                list(_DIAGNOSES_THEN_SLEEPS_MARKED), results_dir=tmp_path
            )
        elapsed = time.monotonic() - started
        alive = [child for child in children if child.poll() is None]

    # First: the child never exits on its own, so a wait without a bound ends
    # only when the mocked read's own 30 s deadline raises.
    assert elapsed < 25, f"the refused stop took {elapsed:.1f}s"
    assert children, "the tool's child never started, so the cell shows nothing"
    assert alive, "the stop worked after all, so the cell shows nothing"
    error = response.get("error") or ""
    assert response.get("post_run_error") is True, response
    assert response["returncode"] is None, response
    assert "could not stop" in error.lower(), error
    assert str(children[0].pid) in error, error
    assert "reading the output failed" in error, error
    assert ASH_STOPPED not in error, error
    assert "diag before the failure" in response.get("stderr", ""), response


@pytest.mark.integration
@pytest.mark.skipif(os.name != "posix", reason="EPERM on a stop is POSIX's case")
@pytest.mark.parametrize("kind", _POPEN_STOPPED)
def test_a_timeout_whose_stop_the_kernel_refused_is_still_a_timeout(tmp_path, kind):
    """The tool timed out, and its stop raised EPERM. The run is still a timeout,
    never post_run_error: timed_out, no code (not 124, and not a 0 the child happened
    to exit with later), and the reason says ASH could not stop it, with its pid."""
    started = time.monotonic()
    with _the_kernel_refuses_the_stop() as children:
        with _runner(kind):
            response = run_command_with_output_handling(
                list(_DIAGNOSES_THEN_SLEEPS_MARKED), results_dir=tmp_path, timeout=1
            )
        elapsed = time.monotonic() - started
        alive = [child for child in children if child.poll() is None]

    # First: the child never exits on its own, so the timeout path returning
    # promptly is the only way the run ends inside this bound.
    assert elapsed < 25, f"the refused stop took {elapsed:.1f}s"
    assert children, "the tool's child never started, so the cell shows nothing"
    assert alive, "the stop worked after all, so the cell shows nothing"
    error = response.get("error") or ""
    assert response.get("timed_out") is True, response
    assert response.get("post_run_error") is not True, response
    assert response["returncode"] is None, response
    assert "timed out" in error, error
    assert "could not stop" in error.lower(), error
    assert str(children[0].pid) in error, error


#: The marked child, writing on to stderr until something ends it, with SIGPIPE's
#: default action back (Python ignores it). Once ASH closes the pipes it stopped
#: reading, its next write ends it on SIGPIPE: a code ASH caused, not the tool's.
_KEEPS_WRITING_PROGRAM = (
    "import signal, sys, time\n"
    "signal.signal(signal.SIGPIPE, signal.SIG_DFL)\n"
    "sys.stderr.write('diag before the failure\\n')\n"
    "sys.stderr.flush()\n"
    "deadline = time.monotonic() + 30\n"
    "while time.monotonic() < deadline:\n"
    "    time.sleep(0.05)\n"
    "    sys.stderr.write('.')\n"
    "    sys.stderr.flush()\n"
)
_KEEPS_WRITING_MARKED = [sys.executable, "-c", _KEEPS_WRITING_PROGRAM, _MARK]


@pytest.mark.integration
@pytest.mark.skipif(os.name != "posix", reason="EPERM on a stop is POSIX's case")
@pytest.mark.parametrize("kind", _POPEN_STOPPED)
def test_a_failed_wait_whose_stop_was_refused_never_reports_the_sigpipe_ash_caused(
    tmp_path, kind
):
    """As above, with a tool that goes on writing. The refused stop left it running,
    and closing the pipes ended it on SIGPIPE. That -13 is ASH's doing, so the
    response has no code, keeps the wait's own error and the stderr read before it,
    and is a failure after the start."""
    with _the_kernel_refuses_the_stop() as children:
        with _runner(kind), _waiting_fails_once_the_stderr_was_read():
            response = run_command_with_output_handling(
                list(_KEEPS_WRITING_MARKED), results_dir=tmp_path
            )

    assert children, "the tool's child never started, so the cell shows nothing"
    error = response.get("error") or ""
    assert response.get("post_run_error") is True, response
    assert response["returncode"] is None, response
    assert "reading the output failed" in error, error
    assert "diag before the failure" in response.get("stderr", ""), response


@pytest.mark.integration
@pytest.mark.skipif(os.name != "posix", reason="EPERM on a stop is POSIX's case")
@pytest.mark.parametrize("kind", _POPEN_STOPPED)
def test_a_timeout_whose_stop_was_refused_never_reports_the_sigpipe_ash_caused(
    tmp_path, kind
):
    """The timeout's case of the cell above: still a timeout, never post_run_error,
    and never the -13 that closing the pipes caused. The kill was refused, so the
    tool never finished on its own and the code is none, as a could-not-stop run's
    code always is."""
    with _the_kernel_refuses_the_stop() as children:
        with _runner(kind):
            response = run_command_with_output_handling(
                list(_KEEPS_WRITING_MARKED), results_dir=tmp_path, timeout=1
            )

    assert children, "the tool's child never started, so the cell shows nothing"
    error = response.get("error") or ""
    assert response.get("timed_out") is True, response
    assert response.get("post_run_error") is not True, response
    assert response["returncode"] is None, response
    assert "timed out" in error, error


@pytest.mark.integration
def test_a_reused_exception_instance_carries_no_start_from_an_earlier_run(
    tmp_path, monkeypatch
):
    """One exception instance is raised twice: first after the tool started, then by
    a step before the next spawn, which starts nothing. The second run is a tool
    that never started. The first run's start is not read back from the instance."""
    from automated_security_helper.utils.uv_tool_runner import (
        UVToolRunner,
        UVToolRunnerError,
    )

    shared = RuntimeError("the same error instance")
    monkeypatch.setattr(UVToolRunner, "is_uv_available", lambda self: True)
    monkeypatch.chdir(tmp_path)
    runner = UVToolRunner(uv_executable=sys.executable)
    real_communicate = subprocess.Popen.communicate

    def communicate(self, *args, **kwargs):
        real_communicate(self, *args, **kwargs)
        raise shared

    with patch.object(subprocess.Popen, "communicate", communicate):
        first = runner.run_tool("semgrep", args=["scan"])

    assert getattr(first, "post_run_error", False) is True, first
    assert first.returncode == 2, first

    # One refusal shape: the runner's own error type. The raised instance
    # reaching the caller as itself would hand a caller that catches only
    # UVToolRunnerError an unhandled error. What may never come back is a
    # RESULT built from the first run's stale record.
    second = None
    with patch.object(subprocess_utils, "_prepare_spawn", side_effect=shared):
        try:
            second = runner.run_tool("semgrep", args=["scan"])
        except UVToolRunnerError:
            second = None

    assert not getattr(second, "post_run_error", False), second
    assert second is None or second.returncode == SPAWN_FAILURE_RETURNCODE, second


# -- the stderr a failure after the start carries -------------------------------------

#: Writes a line to each stream, then exits with the named code.
_WRITES_BOTH = (
    "import sys; sys.stdout.write('out-line\\n'); sys.stderr.write('err-line\\n')"
)
WRITES_BOTH_THEN_EXITS_0 = [sys.executable, "-c", f"{_WRITES_BOTH}; sys.exit(0)"]
WRITES_BOTH_THEN_EXITS_3 = [sys.executable, "-c", f"{_WRITES_BOTH}; sys.exit(3)"]


@contextlib.contextmanager
def _logging_the_result_fails(message_start: str) -> Iterator[None]:
    """The log line run_command writes about a run that returned raises, once: a
    failure after the tool exited, with its result in hand."""
    logger = subprocess_utils.ASH_LOGGER
    real = {name: getattr(logger, name) for name in ("debug", "warning")}

    def failing(name):
        def call(msg, *args, **kwargs):
            if str(msg).startswith(message_start):
                raise RuntimeError("logging the result failed")
            return real[name](msg, *args, **kwargs)

        return call

    with (
        patch.object(logger, "debug", failing("debug")),
        patch.object(logger, "warning", failing("warning")),
    ):
        yield


@pytest.mark.integration
def test_run_command_after_its_run_returned_keeps_that_runs_stderr():
    """The tool exited 3 and its result was in hand when ASH failed: the post-run
    result keeps the code and the stderr the run wrote."""
    with _logging_the_result_fails("Command failed with return code"):
        result = run_command(WRITES_BOTH_THEN_EXITS_3)

    assert isinstance(result, PostRunErrorProcess), result
    assert result.returncode == 3, result
    assert "err-line" in (result.stderr or ""), result


@pytest.mark.integration
def test_run_command_check_after_its_run_returned_raises_with_that_runs_stderr():
    with (
        _logging_the_result_fails("Command succeeded with return code"),
        pytest.raises(Exception) as info,
    ):
        run_command(WRITES_BOTH_THEN_EXITS_0, check=True)

    raised = info.value
    assert getattr(raised, "post_run_error", False) is True, repr(raised)
    assert "err-line" in (getattr(raised, "stderr", "") or ""), repr(raised)


@pytest.mark.integration
def test_run_command_check_after_a_failed_wait_raises_with_the_stderr_read():
    """check=True after a failure while waiting: the raised error carries the
    stderr read before the failure, as the returned result would."""
    with (
        _waiting_fails_once_the_stderr_was_read(),
        pytest.raises(Exception) as info,
    ):
        run_command(DIAGNOSES_THEN_SLEEPS, check=True)

    raised = info.value
    assert getattr(raised, "post_run_error", False) is True, repr(raised)
    assert "diag before the failure" in (getattr(raised, "stderr", "") or ""), repr(
        raised
    )


@pytest.mark.integration
@pytest.mark.skipif(sys.platform == "win32", reason="the stand-in uv is a shell script")
def test_a_uv_run_whose_wait_failed_keeps_the_stderr_read(tmp_path, monkeypatch):
    """run_tool without a results directory runs through spawn_run. Waiting on the
    uv child failed after it wrote a diagnostic; the post-run result carries it."""
    from automated_security_helper.utils.uv_tool_runner import UVToolRunner

    uv = tmp_path / "fake-uv"
    uv.write_text(
        '#!/bin/sh\ncase " $* " in *" run "*) '
        "echo 'diag before the failure' >&2; exec sleep 30;; esac\nexit 0\n",
        encoding="utf-8",
    )
    uv.chmod(0o755)
    monkeypatch.setattr(UVToolRunner, "is_uv_available", lambda self: True)
    monkeypatch.chdir(tmp_path)

    with _waiting_fails_once_the_stderr_was_read():
        result = UVToolRunner(uv_executable=str(uv)).run_tool("semgrep", args=["scan"])

    assert getattr(result, "post_run_error", False) is True, result
    assert result.returncode is None, result
    assert "diag before the failure" in (result.stderr or ""), result


@pytest.mark.integration
def test_the_log_line_names_the_failure_after_the_start(caplog):
    with _reading_the_pipes_fails(), caplog.at_level("ERROR", logger="ash"):
        run_command(SLEEPER)

    logged = [r.getMessage() for r in caplog.records]
    assert any("could not record the output" in m for m in logged), logged
    assert not any("Could not start" in m for m in logged), logged


@pytest.mark.integration
@pytest.mark.parametrize(
    "preference, carried",
    [("write", False), ("return", True)],
    ids=["write", "return"],
)
def test_a_raising_handler_keeps_the_refused_stop_and_the_stderr_read(
    monkeypatch, tmp_path, preference, carried
):
    """A failure after the start whose own handling raised falls back to the
    outer handler. That fallback carries what was already set on the record by
    then -- a refused stop, and the streams read -- as the first handler does.
    Dropped there, a run ASH could not stop read as one that merely could not
    be recorded, and the stderr read before the failure was gone. Nothing is
    probed in the fallback: with ``stop_refused`` set, ``not_stopped()`` reads
    no process state.

    The stdout body honors the call's preference here as everywhere else: the
    fallback used to return it unconditionally, so exactly the run whose
    handler raised handed a "write" caller the body it asked to keep on disk.
    The stderr is kept whatever the preference says. And the reason composes
    in the one order the first handler uses: the wait's own failure first,
    then the could-not-stop sentence around the handler's crash."""
    from automated_security_helper.utils import subprocess_utils as spu

    first_handling = []
    real_signaled = spu._signaled_failure

    def signaled_breaks_once(*args, **kwargs):
        if not first_handling:
            first_handling.append(True)
            raise RuntimeError("the failure's own handling broke")
        return real_signaled(*args, **kwargs)

    monkeypatch.setattr(spu, "_signaled_failure", signaled_breaks_once)

    children: list = []

    def runner_wait_breaks(sandboxed):
        def run(*args, **kwargs):
            process = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"]
            )
            children.append(process)
            record = spu._note_start(process)
            assert record is not None, "the cell shows nothing: no record held"
            # The state the stop path records when the kernel refuses a stop,
            # already set by the time the wait's failure reaches the handlers.
            record.stop_refused = True
            record.stdout = "stdout before the stop"
            record.stderr = "diag before the stop"
            raise RuntimeError("waiting on the child broke")

        return run

    monkeypatch.setattr(spu, "_runner", runner_wait_breaks)
    try:
        response = spu.run_command_with_output_handling(
            [sys.executable, "-c", "pass"],
            results_dir=tmp_path / "results",
            stdout_preference=preference,
        )
    finally:
        for child in children:
            child.kill()
            child.wait()

    assert first_handling, "the cell shows nothing: the first handler never raised"
    assert response.get("post_run_error") is True, response
    assert response.get("returncode") is None, response
    assert response.get("could_not_stop") is True, response
    assert response.get("could_not_stop_pid") == children[0].pid, response
    assert "diag before the stop" in (response.get("stderr") or ""), response
    has_stdout = "stdout before the stop" in (response.get("stdout") or "")
    assert has_stdout is carried, response
    # The reason itself says the tool may still be running and names the pid,
    # as the first handler's reason does, and it keeps the wait's own failure
    # (the handler's __context__) beside the handler's crash: a reader of the
    # text alone sees the process left running and what broke the wait, not
    # only what broke the handler. One order at both builders: the wait's
    # failure leads, then the could-not-stop sentence around the handler's
    # crash, as StartWatch.failure_after_the_start composes it.
    reason = response.get("error") or ""
    assert spu.COULD_NOT_STOP_MARKER in reason, response
    assert str(children[0].pid) in reason, response
    assert "waiting on the child broke" in reason, response
    assert "the failure's own handling broke" in reason, response
    assert reason.index("waiting on the child broke") < reason.index(
        spu.COULD_NOT_STOP_MARKER
    ), reason


@pytest.mark.integration
@pytest.mark.parametrize(
    ("preference", "written", "carried"),
    [
        pytest.param("write", True, False, id="write"),
        pytest.param("both", True, True, id="both"),
        pytest.param("return", False, True, id="return"),
        pytest.param("none", False, False, id="none"),
    ],
)
def test_a_failed_waits_stdout_reaches_the_stream_log_under_the_preference(
    monkeypatch, tmp_path, preference, written, carried
):
    """What the tool printed before the wait broke is usually the only clue to
    why it failed, and scanners default to "write": the body's destination
    there is the stream log, as for a completed run and a timeout's partial
    read, while the response carries it only when the preference returns it.
    It used to reach no file and no response under "write"."""
    from automated_security_helper.utils import subprocess_utils as spu

    children: list = []

    def runner_wait_breaks(sandboxed):
        def run(*args, **kwargs):
            process = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"]
            )
            children.append(process)
            record = spu._note_start(process)
            assert record is not None, "the cell shows nothing: no record held"
            record.stop_refused = True
            record.stdout = "stdout before the stop"
            record.stderr = "diag before the stop"
            raise RuntimeError("waiting on the child broke")

        return run

    monkeypatch.setattr(spu, "_runner", runner_wait_breaks)
    results = tmp_path / "results"
    try:
        response = spu.run_command_with_output_handling(
            [sys.executable, "-c", "pass"],
            results_dir=results,
            stdout_preference=preference,
        )
    finally:
        for child in children:
            child.kill()
            child.wait()

    assert response.get("post_run_error") is True, response
    log = results / "stdout.log"
    if written:
        assert log.read_text(encoding="utf-8") == "stdout before the stop", response
    else:
        assert not log.exists(), response
    # The stderr log is written too, as the timeout path and the spawn-failure
    # answer write it: scanners read <class>.stderr.log to explain a failure,
    # and stderr_preference defaults to "write" here.
    stderr_log = results / "stderr.log"
    assert stderr_log.read_text(encoding="utf-8") == "diag before the stop", response
    has_body = "stdout before the stop" in (response.get("stdout") or "")
    assert has_body is carried, response


@pytest.mark.integration
def test_the_fallbacks_failed_wait_streams_reach_the_stream_logs(monkeypatch, tmp_path):
    """The outer fallback answers when the wait failure's own handler raised,
    and the streams the wait had read go to the stream logs there under the
    same gates. The first handler fails BEFORE its own write (its reason
    build, ``error_after``, comes first), so the files this cell reads can
    only have been written by the fallback: with the handler's write reached
    first, as an earlier shape of this cell had it, deleting the fallback's
    write block left the cell green."""
    from automated_security_helper.utils import subprocess_utils as spu

    first_handling = []

    def error_after_breaks(self, error, not_stopped=None):
        first_handling.append(True)
        raise RuntimeError("the failure's own handling broke")

    monkeypatch.setattr(spu._StartedChild, "error_after", error_after_breaks)

    children: list = []

    def runner_wait_breaks(sandboxed):
        def run(*args, **kwargs):
            process = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"]
            )
            children.append(process)
            record = spu._note_start(process)
            assert record is not None, "the cell shows nothing: no record held"
            record.stop_refused = True
            record.stdout = "stdout before the stop"
            record.stderr = "diag before the stop"
            raise RuntimeError("waiting on the child broke")

        return run

    monkeypatch.setattr(spu, "_runner", runner_wait_breaks)
    results = tmp_path / "results"
    try:
        response = spu.run_command_with_output_handling(
            [sys.executable, "-c", "pass"], results_dir=results
        )
    finally:
        for child in children:
            child.kill()
            child.wait()

    assert first_handling, "the cell shows nothing: the first handler never raised"
    assert response.get("post_run_error") is True, response
    assert "stdout" not in response, response
    log = results / "stdout.log"
    assert log.read_text(encoding="utf-8") == "stdout before the stop", response
    stderr_log = results / "stderr.log"
    assert stderr_log.read_text(encoding="utf-8") == "diag before the stop", response


@pytest.mark.integration
@pytest.mark.parametrize("which_handler", ["first-handler", "fallback"])
def test_the_sandbox_cleanup_runs_before_a_failed_waits_stream_writes(
    monkeypatch, tmp_path, which_handler
):
    """The sandbox cleanup's first step is sweep_writable over the writable
    dirs (inserted by scope.prepare_spawn), which removes a link a scanner
    left at a log's name: a failed wait must run the cleanup before it writes
    there, as the completed-run and timeout paths do, or the first link
    defense comes too late. open_for_write below the registered root is the
    second defense (the planted-link cell below), and the plan's own private
    directories go in the same cleanup. The plan's cleanup runs each step
    once, so the repeat in the ``finally`` stays a no-op."""
    from automated_security_helper.utils import subprocess_utils as spu
    from automated_security_helper.utils.sandbox.backends import SpawnPlan

    events: list = []

    def plan_with_recording(command, env, cwd, shell):
        return SpawnPlan(
            argv=list(command),
            env=dict(env or {}),
            cleanup=[lambda: events.append("cleanup")],
        )

    monkeypatch.setattr(spu, "_prepare_spawn", plan_with_recording)

    def recording_write(results_dir, class_name, stream_name, preference, text):
        events.append(("write", stream_name))

    monkeypatch.setattr(spu, "_write_stream_log", recording_write)

    if which_handler == "fallback":

        def error_after_breaks(self, error, not_stopped=None):
            raise RuntimeError("the failure's own handling broke")

        monkeypatch.setattr(spu._StartedChild, "error_after", error_after_breaks)

    children: list = []

    def runner_wait_breaks(sandboxed):
        def run(*args, **kwargs):
            process = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"]
            )
            children.append(process)
            record = spu._note_start(process)
            assert record is not None, "the cell shows nothing: no record held"
            record.stop_refused = True
            record.stdout = "stdout before the stop"
            record.stderr = "diag before the stop"
            raise RuntimeError("waiting on the child broke")

        return run

    monkeypatch.setattr(spu, "_runner", runner_wait_breaks)
    try:
        response = spu.run_command_with_output_handling(
            [sys.executable, "-c", "pass"], results_dir=tmp_path / "results"
        )
    finally:
        for child in children:
            child.kill()
            child.wait()

    assert response.get("post_run_error") is True, response
    writes = [event for event in events if event != "cleanup"]
    assert ("write", "stdout") in writes, events
    assert ("write", "stderr") in writes, events
    assert events[0] == "cleanup", (
        "the sandbox cleanup must run before the first stream write",
        events,
    )
    # Exactly once: the plan drains its steps on the first call, which is what
    # makes the repeats in the finally (and in a handler that already ran) safe.
    # A plan that re-ran its steps on every call would still order correctly
    # and silently clean up two or three times.
    assert events.count("cleanup") == 1, events
    # Which handler answered: the fallback's reason leads with the wait's
    # failure ("..., then: ..."), the first handler's never does, so each
    # variant proves ITS builder did the writes rather than the other one.
    reason = response.get("error") or ""
    if which_handler == "fallback":
        assert ", then: " in reason, response
    else:
        assert ", then: " not in reason, response


@pytest.mark.integration
def test_a_completed_run_whose_stdout_write_breaks_keeps_its_stderr_log(
    monkeypatch, tmp_path
):
    """A completed run writes its stream logs per stream: a stdout log that
    cannot be written must not cost the stderr log, which scanners read to
    explain a failure, and every failed write's clause reaches the post-run
    handler as one raise after both writes were attempted."""
    from automated_security_helper.utils import subprocess_utils as spu

    results = tmp_path / "results"
    original = spu._write_stream_log

    def stdout_write_fails(results_dir, class_name, stream_name, preference, text):
        if stream_name == "stdout":
            raise OSError("the stdout log could not be written")
        return original(results_dir, class_name, stream_name, preference, text)

    monkeypatch.setattr(spu, "_write_stream_log", stdout_write_fails)
    script = (
        "import sys\n"
        "sys.stdout.write('stdout of the tool')\n"
        "sys.stderr.write('diag from the tool')\n"
    )
    response = spu.run_command_with_output_handling(
        [sys.executable, "-c", script],
        results_dir=results,
        class_name="ProbeScanner",
    )
    assert response.get("post_run_error") is True, (
        "the cell shows nothing: the stdout write failure never surfaced",
        response,
    )
    assert "stdout log could not be written" in str(response.get("error")), response
    log = results / "ProbeScanner.stderr.log"
    assert log.is_file(), ("the stderr log was lost to the stdout failure", response)
    assert log.read_text(encoding="utf-8") == "diag from the tool", response


@pytest.mark.integration
def test_a_failed_stdout_write_under_both_keeps_the_body_in_the_response(
    monkeypatch, tmp_path
):
    """Under ``stdout_preference="both"`` the preference's "return" half did
    not fail when the disk write did, so the body must still ride in the
    response: the old loop's ``continue`` after a failed write skipped the
    response field too, and the stdout was then neither on disk nor in the
    response."""
    from automated_security_helper.utils import subprocess_utils as spu

    results = tmp_path / "results"
    original = spu._write_stream_log

    def stdout_write_fails(results_dir, class_name, stream_name, preference, text):
        if stream_name == "stdout":
            raise OSError("the stdout log could not be written")
        return original(results_dir, class_name, stream_name, preference, text)

    monkeypatch.setattr(spu, "_write_stream_log", stdout_write_fails)
    script = (
        "import sys\n"
        "sys.stdout.write('stdout of the tool')\n"
        "sys.stderr.write('diag from the tool')\n"
    )
    response = spu.run_command_with_output_handling(
        [sys.executable, "-c", script],
        results_dir=results,
        class_name="ProbeScanner",
        stdout_preference="both",
    )
    assert response.get("post_run_error") is True, (
        "the cell shows nothing: the stdout write failure never surfaced",
        response,
    )
    assert response.get("stdout") == "stdout of the tool", response
    assert (results / "ProbeScanner.stderr.log").is_file(), response


@pytest.mark.integration
def test_every_failed_completed_run_write_is_named_in_the_reason(
    monkeypatch, tmp_path, caplog
):
    """When both stream writes fail, the reason names both: keeping
    only the first failure left the second with no log line and no clause,
    where the failed-wait and timeout paths list every failed write. Each
    clause carries the shared "ASH could not write its X log" lead -- the
    completed path goes through the same _write_stream_logs as the other
    paths, so the wordings cannot drift apart -- and the one ash.log ERROR
    record names both failures too."""
    from automated_security_helper.utils import subprocess_utils as spu

    def every_write_fails(results_dir, class_name, stream_name, preference, text):
        raise OSError(f"the {stream_name} log could not be written")

    monkeypatch.setattr(spu, "_write_stream_log", every_write_fails)
    script = (
        "import sys\n"
        "sys.stdout.write('stdout of the tool')\n"
        "sys.stderr.write('diag from the tool')\n"
    )
    with caplog.at_level(logging.ERROR, logger="ash"):
        response = spu.run_command_with_output_handling(
            [sys.executable, "-c", script],
            results_dir=tmp_path / "results",
            class_name="ProbeScanner",
        )
    assert response.get("post_run_error") is True, response
    reason = str(response.get("error"))
    assert (
        "ASH could not write its stdout log: the stdout log could not be written"
        in reason
    ), reason
    assert (
        "ASH could not write its stderr log: the stderr log could not be written"
        in reason
    ), reason
    recorded = [
        record.getMessage()
        for record in caplog.records
        if "could not record the output" in record.getMessage()
    ]
    assert recorded, "the cell shows nothing: no ash.log record of the failure"
    assert any(
        "stdout log could not be written" in message
        and "stderr log could not be written" in message
        for message in recorded
    ), recorded


# The child for the completed-run path of the two-defense cells: it leaves a
# link at the stderr log's name (as a sandboxed scanner can), writes its
# stderr, and exits. The timeout path plants its own link and arms the
# TimeoutExpired through a fake runner instead of sleeping one out.
_LINKING_CHILD = (
    "import os, sys\n"
    "os.symlink(sys.argv[2], os.path.join(sys.argv[1], 'stderr.log'))\n"
    "sys.stderr.write(sys.argv[3]); sys.stderr.flush()\n"
)

_LINK_PATHS = ["completed", "first-handler", "fallback", "timeout"]


def _scanner_scope(layout, steps):
    """A real SandboxScope over a passthrough backend: prepare_spawn then
    builds the plan the production path builds, sweep step included."""
    from automated_security_helper.utils.sandbox import SandboxRequirements
    from automated_security_helper.utils.sandbox import scope as scope_module
    from automated_security_helper.utils.sandbox.backends import SpawnPlan

    class _PassThrough:
        """A backend whose plan runs the argv as given, with the steps handed."""

        name = "passthrough"

        def __init__(self, extra_steps):
            self.extra_steps = extra_steps

        def plan(self, argv, env, policy):
            return SpawnPlan(
                argv=list(argv), env=dict(env), cleanup=list(self.extra_steps)
            )

    source, output, results, _outside = layout
    return scope_module.SandboxScope(
        backend=_PassThrough(list(steps)),  # type: ignore[arg-type]
        scanner_name="grype",
        requirements=SandboxRequirements(),
        source_dir=source,
        output_dir=output,
        results_dir=results,
        scan_target=source,
        offline=True,
    )


@pytest.fixture
def link_layout(tmp_path, monkeypatch):
    from automated_security_helper.utils.sandbox import fs_guard

    source = tmp_path / "src"
    output = source / ".ash" / "ash_output"
    results = output / "scanners" / "grype"
    results.mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("untouched", encoding="utf-8")
    # A fresh registry: prepare_spawn registers the results dir, and this
    # test's root must not reach other tests; monkeypatch restores the
    # module's own counted registry (a dict of root to holder count).
    monkeypatch.setattr(fs_guard, "_writable_roots", {})
    return source, output, results, outside


def _run_linked_path(path, layout, monkeypatch, steps=()):
    """Run one path inside the real scope; returns the response."""
    from automated_security_helper.utils import subprocess_utils as spu
    from automated_security_helper.utils.sandbox import sandbox_scope

    _source, _output, results, outside = layout
    children: list = []
    scope = _scanner_scope(layout, steps)
    if path == "completed":
        command = [
            sys.executable,
            "-c",
            _LINKING_CHILD,
            str(results),
            str(outside),
            "diag from the tool",
        ]
        kwargs = {}
    elif path == "timeout":
        # The armed shape, not a real clock: the fake runner notes a real
        # (already exited) child and raises the TimeoutExpired the real
        # runner would, partial stderr attached, so the cell neither sleeps
        # out a timeout nor flakes when Python starts slowly under load.
        (results / "stderr.log").symlink_to(outside)

        def runner_times_out(sandboxed):
            def run(*args, **kwargs):
                process = subprocess.Popen([sys.executable, "-c", "pass"])
                children.append(process)
                record = spu._note_start(process)
                assert record is not None, "the cell shows nothing: no record held"
                process.wait()
                raise subprocess.TimeoutExpired(
                    list(args[0]) if args else ["x"],
                    3,
                    stderr="diag from the tool",
                )

            return run

        monkeypatch.setattr(spu, "_runner", runner_times_out)
        command = [sys.executable, "-c", "pass"]
        kwargs = {"timeout": 3}
    else:
        # The link a scanner left before the wait broke.
        (results / "stderr.log").symlink_to(outside)
        if path == "fallback":

            def error_after_breaks(self, error, not_stopped=None):
                raise RuntimeError("the failure's own handling broke")

            monkeypatch.setattr(spu._StartedChild, "error_after", error_after_breaks)

        def runner_wait_breaks(sandboxed):
            def run(*args, **kwargs):
                process = subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(30)"]
                )
                children.append(process)
                record = spu._note_start(process)
                assert record is not None, "the cell shows nothing: no record held"
                record.stop_refused = True
                record.stderr = "diag from the tool"
                raise RuntimeError("waiting on the child broke")

            return run

        monkeypatch.setattr(spu, "_runner", runner_wait_breaks)
        command = [sys.executable, "-c", "pass"]
        kwargs = {}
    try:
        with sandbox_scope(scope):
            response = spu.run_command_with_output_handling(
                command, results_dir=results, **kwargs
            )
    finally:
        for child in children:
            child.kill()
            child.wait()
    return response


@pytest.mark.integration
@pytest.mark.skipif(os.name != "posix", reason="links and the sandbox are POSIX's case")
def test_the_sandbox_debug_line_hides_the_scopes_values(
    link_layout, monkeypatch, caplog
):
    """prepare_spawn logs the planned argv at DEBUG, and an argv is
    plugin-built text that can carry an env-read value: the record is
    redacted with the scope's environment values, like every other line the
    runner logs about a run."""
    import dataclasses

    from automated_security_helper.utils import subprocess_utils as spu
    from automated_security_helper.utils.sandbox import sandbox_scope

    value = "ARGSECRET" + "77421"
    scope = dataclasses.replace(
        _scanner_scope(link_layout, ()), environment_values=(value,)
    )
    _source, _output, results, _outside = link_layout
    with (
        caplog.at_level(logging.DEBUG, logger="ash"),
        sandbox_scope(scope),
    ):
        spu.run_command_with_output_handling(
            [sys.executable, "-c", "pass", f"--token={value}"],
            results_dir=results,
        )
    lines = [
        record.getMessage()
        for record in caplog.records
        if "Scanner sandbox" in record.getMessage()
    ]
    assert lines, "the cell shows nothing: no sandbox debug line"
    assert any("--token=" in line for line in lines), lines
    assert all(value not in line for line in lines), lines


@pytest.mark.integration
@pytest.mark.skipif(os.name != "posix", reason="links and the sandbox are POSIX's case")
@pytest.mark.parametrize("mode", ["as-built", "plain-open", "plain-open-no-sweep"])
@pytest.mark.parametrize("path", _LINK_PATHS)
def test_the_plans_cleanup_removes_a_planted_link_before_the_write(
    link_layout, monkeypatch, caplog, path, mode
):
    """The two link defenses, each measured alone. scope.prepare_spawn inserts
    sweep_writable over the policy's writable dirs as the plan's FIRST cleanup
    step, so on the real path the cleanup removes a link a scanner left at a
    log's name before ASH writes; open_for_write below the registered root is
    the second defense, and it refuses a link instead of replacing it (the
    tests after this one). "plain-open" removes the second defense and the
    sweep alone keeps the write off the link; the plain-open-no-sweep control
    removes both and asserts the hazard ITSELF -- the stderr write lands in the
    link's target and the link survives -- which is what makes the other
    columns measurements. An ordinary assertion, not an xfail: an xfail is
    satisfied by ANY failure (a changed sweep signature raising TypeError in the
    stub, say), so only the specific outside read proves the write FOLLOWED the
    link."""
    from automated_security_helper.utils import subprocess_utils as spu
    from automated_security_helper.utils.sandbox import scope as scope_module

    _source, _output, results, outside = link_layout
    if mode in ("plain-open", "plain-open-no-sweep"):
        # The production call's signature, ``root`` included: a stub without it
        # raises TypeError, the write never happens, and the control stops
        # measuring the hazard.
        def _plain_open(
            path, encoding="utf-8", errors="strict", mode=0o666, root=None, **kwargs
        ):
            return open(path, "w", encoding=encoding, errors=errors)

        monkeypatch.setattr(spu, "open_for_write", _plain_open)
    if mode == "plain-open-no-sweep":
        monkeypatch.setattr(
            scope_module, "sweep_writable", lambda roots, values=(), **kwargs: 0
        )
    with caplog.at_level(logging.DEBUG, logger="ash"):
        response = _run_linked_path(path, link_layout, monkeypatch)
    log = results / "stderr.log"
    assert os.path.lexists(log), ("the cell shows nothing: no stderr log", response)
    # The stub must be a clean no-op, not a swallowed crash: run_cleanup eats
    # any exception at DEBUG, so a stub whose signature drifted from the
    # production call would "remove the sweep" by TypeError and this cell
    # would stop measuring what it claims to.
    crashed = [
        record.getMessage()
        for record in caplog.records
        if "Sandbox cleanup failed" in record.getMessage()
    ]
    assert not crashed, crashed
    if path == "timeout":
        assert response.get("timed_out") is True, response
    elif path != "completed":
        assert response.get("post_run_error") is True, response
    swept = [
        record.getMessage()
        for record in caplog.records
        if "removed 1 symlink" in record.getMessage()
    ]
    if mode == "plain-open-no-sweep":
        assert outside.read_text(encoding="utf-8") == "diag from the tool", (
            (
                "with both defenses removed the write must follow the link; "
                "anything else means the control stopped measuring the hazard"
            ),
            response,
        )
        assert log.is_symlink(), "the planted link should have survived"
        assert not swept, "no sweep ran, so no sweep record can exist"
        return
    assert outside.read_text(encoding="utf-8") == "untouched", (
        "the write followed the planted link",
        response,
    )
    assert not log.is_symlink(), "the planted link is still there"
    assert log.read_text(encoding="utf-8") == "diag from the tool", response
    assert swept, "no sweep record: the cleanup did not remove the link"


#: What fs_guard's refusal says, whichever path met the link.
_LINK_REFUSAL = (
    "is a symlink, and ASH does not write through a symlink below its output directory"
)


@pytest.mark.integration
@pytest.mark.skipif(os.name != "posix", reason="links and the sandbox are POSIX's case")
@pytest.mark.parametrize("path", _LINK_PATHS)
def test_without_the_sweep_the_write_refuses_a_planted_link(
    link_layout, monkeypatch, caplog, path
):
    """The second link defense alone. With the plan's sweep removed, the link a
    scanner left at the stderr log's name is still there when ASH writes, and
    open_for_write below the registered root refuses it (fs_guard.py: a link at
    the file name raises OutputLinkRefused and is left where it is, as
    tests/integration/sandbox/test_fs_guard.py and TestStreamLogs in
    test_output_dir_links_are_refused.py pin). The link's target is never
    written, the link survives, and the run's reason names the refusal. An
    earlier version of this test asserted the link was replaced in place; that
    contradicted the refusal those tests pin."""
    from automated_security_helper.utils.sandbox import scope as scope_module

    _source, _output, results, outside = link_layout
    monkeypatch.setattr(
        scope_module, "sweep_writable", lambda roots, values=(), **kwargs: 0
    )
    with caplog.at_level(logging.DEBUG, logger="ash"):
        response = _run_linked_path(path, link_layout, monkeypatch)
    log = results / "stderr.log"
    assert os.path.lexists(log), ("no stderr log, so this shows nothing", response)
    crashed = [
        record.getMessage()
        for record in caplog.records
        if "Sandbox cleanup failed" in record.getMessage()
    ]
    assert not crashed, crashed
    swept = [
        record.getMessage()
        for record in caplog.records
        if "removed 1 symlink" in record.getMessage()
    ]
    assert not swept, "no sweep ran, so no sweep record can exist"
    if path == "timeout":
        assert response.get("timed_out") is True, response
    elif path != "completed":
        assert response.get("post_run_error") is True, response
    assert outside.read_text(encoding="utf-8") == "untouched", (
        "the write followed the planted link",
        response,
    )
    assert log.is_symlink(), "the refusal leaves the link where it was"
    assert _LINK_REFUSAL in str(response.get("error")), response


@pytest.mark.integration
@pytest.mark.skipif(os.name != "posix", reason="links and the sandbox are POSIX's case")
@pytest.mark.parametrize("path", _LINK_PATHS)
def test_the_cleanup_runs_once_and_before_the_stderr_write(
    link_layout, monkeypatch, path
):
    """Every path, the timeout's included, runs the plan's cleanup exactly
    once and before the stderr write: a backend step planted in the plan sees
    no stderr log yet. Since the timeout path's own entry cleanup was removed,
    its cleanup-before-write rests on the call inside _write_stream_logs, and
    nothing else pinned that."""
    _source, _output, results, _outside = link_layout
    seen: list = []

    def step():
        seen.append(os.path.lexists(results / "stderr.log"))

    _run_linked_path(path, link_layout, monkeypatch, steps=[step])
    log = results / "stderr.log"
    assert log.is_file(), "the cell shows nothing: no stderr log"
    # is_file() follows a symlink to a regular file, so alone it would pass
    # on step order even with the planted link still in place.
    assert not log.is_symlink(), "the planted link is still there"
    assert seen == [False], "the plan's step ran %d times; before the write: %r" % (
        len(seen),
        seen,
    )


@pytest.mark.integration
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="symlink creation needs a privilege on Windows, and fs_guard's "
    "write guard is fwalk-gated (_guarded_write_fd returns None without "
    "os.fwalk), so the guarded path under test does not exist there",
)
@pytest.mark.parametrize("which_handler", ["first-handler", "fallback"])
def test_a_failed_waits_write_refuses_a_link_a_scanner_planted(
    monkeypatch, tmp_path, which_handler
):
    """A sandboxed scanner can leave a symlink at the stderr log's name, and
    ASH is not sandboxed, so a plain write there would land wherever the link
    points. The first defense is the cleanup's sweep_writable step
    (scope.prepare_spawn inserts it; the two-defense cells above); this cell
    runs with NO plan, so it measures the SECOND defense alone: open_for_write
    below the registered writable root refuses the link (OutputLinkRefused,
    fs_guard.py) and leaves it where it was, so the link's target is never
    touched and the run's reason names the refusal. An earlier version of this
    test asserted that the link was replaced by a regular file; that contradicted
    the refusal fs_guard documents and tests/integration/sandbox/test_fs_guard.py
    and TestStreamLogs pin. Parametrized over both failed-wait builders, as the
    cleanup-order test is."""
    from automated_security_helper.utils import subprocess_utils as spu
    from automated_security_helper.utils.sandbox import fs_guard

    results = tmp_path / "results"
    results.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("untouched", encoding="utf-8")
    (results / "stderr.log").symlink_to(outside)
    # A fresh registry so this cell's root does not leak into other tests;
    # monkeypatch restores the module's own registry afterwards. The assert
    # below proves fs_guard reads the module-level registry at CALL time: were
    # it rebound at import or moved elsewhere, this patch would no longer reach
    # it and the test would measure a plain open.
    monkeypatch.setattr(fs_guard, "_writable_roots", {})
    fs_guard.register_writable_root(results)
    assert fs_guard._writable_root_for(results / "stderr.log") is not None, (
        "the fresh registry is not the one fs_guard reads at call time"
    )

    if which_handler == "fallback":

        def error_after_breaks(self, error, not_stopped=None):
            raise RuntimeError("the failure's own handling broke")

        monkeypatch.setattr(spu._StartedChild, "error_after", error_after_breaks)

    children: list = []

    def runner_wait_breaks(sandboxed):
        def run(*args, **kwargs):
            process = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"]
            )
            children.append(process)
            record = spu._note_start(process)
            assert record is not None, "the cell shows nothing: no record held"
            record.stop_refused = True
            record.stderr = "diag before the stop"
            raise RuntimeError("waiting on the child broke")

        return run

    monkeypatch.setattr(spu, "_runner", runner_wait_breaks)
    try:
        response = spu.run_command_with_output_handling(
            [sys.executable, "-c", "pass"], results_dir=results
        )
    finally:
        for child in children:
            child.kill()
            child.wait()

    assert response.get("post_run_error") is True, response
    # Which builder answered: the fallback's reason leads with the wait's
    # failure (", then: "), the first handler's never does, so each variant
    # proves ITS builder did the guarded write rather than the other one.
    reason = response.get("error") or ""
    if which_handler == "fallback":
        assert ", then: " in reason, response
    else:
        assert ", then: " not in reason, response
    log = results / "stderr.log"
    assert log.is_symlink(), "the refusal leaves the link where it was"
    assert _LINK_REFUSAL in reason, response
    assert outside.read_text(encoding="utf-8") == "untouched", (
        "the write escaped the results directory through the planted link"
    )


@pytest.mark.integration
@pytest.mark.parametrize(
    ("stderr_preference", "written"),
    [
        pytest.param("write", True, id="write"),
        pytest.param("both", True, id="both"),
        pytest.param("return", False, id="return"),
        pytest.param("none", False, id="none"),
    ],
)
@pytest.mark.parametrize("which_handler", ["first-handler", "fallback"])
def test_a_failed_waits_stderr_log_honors_its_own_preference(
    monkeypatch, tmp_path, stderr_preference, written, which_handler
):
    """The stderr log exists exactly when stderr_preference writes it; the
    response's stderr field is carried whatever the preference says, the bound
    every builder honors. Only the default "write" was pinned before, so a
    change that wrote stderr regardless of its preference went unmeasured.
    Parametrized over both failed-wait builders, as the cleanup cell is, so a
    fallback that ignored the preference fails a test too."""
    from automated_security_helper.utils import subprocess_utils as spu

    if which_handler == "fallback":

        def error_after_breaks(self, error, not_stopped=None):
            raise RuntimeError("the failure's own handling broke")

        monkeypatch.setattr(spu._StartedChild, "error_after", error_after_breaks)

    children: list = []

    def runner_wait_breaks(sandboxed):
        def run(*args, **kwargs):
            process = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"]
            )
            children.append(process)
            record = spu._note_start(process)
            assert record is not None, "the cell shows nothing: no record held"
            record.stop_refused = True
            record.stdout = "stdout before the stop"
            record.stderr = "diag before the stop"
            raise RuntimeError("waiting on the child broke")

        return run

    monkeypatch.setattr(spu, "_runner", runner_wait_breaks)
    results = tmp_path / "results"
    try:
        response = spu.run_command_with_output_handling(
            [sys.executable, "-c", "pass"],
            results_dir=results,
            stderr_preference=stderr_preference,
        )
    finally:
        for child in children:
            child.kill()
            child.wait()

    assert response.get("post_run_error") is True, response
    # Which builder answered: the fallback's reason leads with the wait's
    # failure (", then: "), the first handler's never does, so each variant
    # proves ITS builder honored the preference rather than the other one.
    reason = response.get("error") or ""
    if which_handler == "fallback":
        assert ", then: " in reason, response
    else:
        assert ", then: " not in reason, response
    stderr_log = results / "stderr.log"
    if written:
        assert stderr_log.read_text(encoding="utf-8") == "diag before the stop", (
            response
        )
    else:
        assert not stderr_log.exists(), response
    assert response.get("stderr") == "diag before the stop", response


@pytest.mark.integration
def test_a_failed_wait_whose_stdout_log_cannot_be_written_says_so(
    monkeypatch, tmp_path
):
    """A stdout log that cannot be written is added to the reason, as the
    timeout path adds its own: the run is still a failure after the start,
    never one that did not start, and the original failure stays named."""
    from automated_security_helper.utils import subprocess_utils as spu

    blocked = tmp_path / "blocked"
    blocked.write_text("a file where the results directory should be")

    children: list = []

    def runner_wait_breaks(sandboxed):
        def run(*args, **kwargs):
            process = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"]
            )
            children.append(process)
            record = spu._note_start(process)
            assert record is not None, "the cell shows nothing: no record held"
            record.stop_refused = True
            record.stdout = "stdout before the stop"
            raise RuntimeError("waiting on the child broke")

        return run

    monkeypatch.setattr(spu, "_runner", runner_wait_breaks)
    try:
        response = spu.run_command_with_output_handling(
            [sys.executable, "-c", "pass"], results_dir=blocked
        )
    finally:
        for child in children:
            child.kill()
            child.wait()

    assert response.get("post_run_error") is True, response
    reason = response.get("error") or ""
    assert "waiting on the child broke" in reason, response
    assert "could not write its stdout log" in reason, response


@pytest.mark.integration
def test_a_handlers_nested_except_does_not_lose_the_wait_failure(monkeypatch, tmp_path):
    """The first handler's own raise can happen inside its own try/except -- a
    log write that failed, say -- and the raise's ``__context__`` is then that
    inner error, not the wait's failure the handler was handling. The outer
    handler reads the failure the inner one caught, held as a local, so the
    reason still leads with what broke the wait."""
    from automated_security_helper.utils import subprocess_utils as spu

    first_handling = []
    real_signaled = spu._signaled_failure

    def breaks_inside_its_own_except(*args, **kwargs):
        if not first_handling:
            first_handling.append(True)
            try:
                raise ValueError("an inner log write failed")
            except ValueError:
                raise RuntimeError("the failure's own handling broke")
        return real_signaled(*args, **kwargs)

    monkeypatch.setattr(spu, "_signaled_failure", breaks_inside_its_own_except)

    children: list = []

    def runner_wait_breaks(sandboxed):
        def run(*args, **kwargs):
            process = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"]
            )
            children.append(process)
            record = spu._note_start(process)
            assert record is not None, "the cell shows nothing: no record held"
            record.stop_refused = True
            record.stderr = "diag before the stop"
            raise RuntimeError("waiting on the child broke")

        return run

    monkeypatch.setattr(spu, "_runner", runner_wait_breaks)
    try:
        response = spu.run_command_with_output_handling(
            [sys.executable, "-c", "pass"], results_dir=tmp_path / "results"
        )
    finally:
        for child in children:
            child.kill()
            child.wait()

    assert first_handling, "the cell shows nothing: the first handler never raised"
    assert response.get("post_run_error") is True, response
    reason = response.get("error") or ""
    assert "waiting on the child broke" in reason, response
    assert reason.index("waiting on the child broke") < reason.index(
        spu.COULD_NOT_STOP_MARKER
    ), reason


@pytest.mark.integration
def test_a_disavowing_handler_keeps_the_wait_failure_out_of_the_reason(
    monkeypatch, tmp_path
):
    """A handler that raises ``from None`` disavows what it was handling, and
    the env-blind refusals rely on that: the wait's failure can quote an
    environment-read value. The outer handler holds that failure as a local,
    so the disavowal must beat the local, not only the __context__ chain."""
    from automated_security_helper.utils import subprocess_utils as spu

    first_handling = []
    real_signaled = spu._signaled_failure

    def refuses_blind(*args, **kwargs):
        if not first_handling:
            first_handling.append(True)
            raise RuntimeError("the failure's own handling broke") from None
        return real_signaled(*args, **kwargs)

    monkeypatch.setattr(spu, "_signaled_failure", refuses_blind)

    children: list = []

    def runner_wait_breaks(sandboxed):
        def run(*args, **kwargs):
            process = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"]
            )
            children.append(process)
            record = spu._note_start(process)
            assert record is not None, "the cell shows nothing: no record held"
            record.stop_refused = True
            raise RuntimeError("read ENV-VALUE-7421 from the environment")

        return run

    monkeypatch.setattr(spu, "_runner", runner_wait_breaks)
    try:
        response = spu.run_command_with_output_handling(
            [sys.executable, "-c", "pass"], results_dir=tmp_path / "results"
        )
    finally:
        for child in children:
            child.kill()
            child.wait()

    assert first_handling, "the cell shows nothing: the first handler never raised"
    assert response.get("post_run_error") is True, response
    reason = response.get("error") or ""
    assert "ENV-VALUE-7421" not in reason, response
    assert "the failure's own handling broke" in reason, response


@pytest.mark.integration
def test_a_handler_crash_chained_from_a_cause_keeps_the_wait_failure_leading(
    monkeypatch, tmp_path
):
    """A ``from cause`` on a raise inside the handler describes that raise's
    own chain, not a decision about the wait's failure: the raise can come
    from a helper frames below the handler (here ``_signaled_failure``), and
    letting it beat the local dropped what broke the wait from the reason and
    from every log, since the first handler's own log line comes after the
    helper that crashed. Only ``raise ... from None`` disavows the local; an
    environment-read value a led failure can quote is the printers' job to
    redact, not the chain shape's."""
    from automated_security_helper.utils import subprocess_utils as spu

    first_handling = []
    real_signaled = spu._signaled_failure

    def crashes_with_its_own_chain(*args, **kwargs):
        if not first_handling:
            first_handling.append(True)
            raise RuntimeError("the failure's own handling broke") from ValueError(
                "the helper's own cause"
            )
        return real_signaled(*args, **kwargs)

    monkeypatch.setattr(spu, "_signaled_failure", crashes_with_its_own_chain)

    children: list = []

    def runner_wait_breaks(sandboxed):
        def run(*args, **kwargs):
            process = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"]
            )
            children.append(process)
            record = spu._note_start(process)
            assert record is not None, "the cell shows nothing: no record held"
            record.stop_refused = True
            raise RuntimeError("waiting on the child broke")

        return run

    monkeypatch.setattr(spu, "_runner", runner_wait_breaks)
    try:
        response = spu.run_command_with_output_handling(
            [sys.executable, "-c", "pass"], results_dir=tmp_path / "results"
        )
    finally:
        for child in children:
            child.kill()
            child.wait()

    assert first_handling, "the cell shows nothing: the first handler never raised"
    assert response.get("post_run_error") is True, response
    reason = response.get("error") or ""
    assert "waiting on the child broke" in reason, response
    assert "the failure's own handling broke" in reason, response
    assert reason.index("waiting on the child broke") < reason.index(
        "the failure's own handling broke"
    ), reason
    assert "the helper's own cause" not in reason, response


class _FakeChild:
    """A recorded child for cells that need a specific recorded state: its pid,
    the code poll() reports, and returncode. Nothing runs."""

    pid = 2**22 + 31

    def __init__(self, code):
        self.returncode = code
        self._code = code
        self.stdout = None
        self.stderr = None

    def poll(self):
        return self._code


@pytest.mark.unit
@pytest.mark.parametrize(
    ("preference", "carried"),
    [
        pytest.param("write", False, id="write"),
        pytest.param("none", False, id="none"),
        pytest.param("return", True, id="return"),
        pytest.param("both", True, id="both"),
    ],
)
def test_the_timeouts_partial_stdout_honors_the_preference(
    monkeypatch, tmp_path, preference, carried
):
    """What a timed-out tool printed before it was killed is written to the
    stream log when the preference writes it ("write" or "both",
    _write_stream_log's own gate), since it is usually the only clue to why
    the tool hung -- and the RESPONSE carries the body only when the
    preference returns it, the bound every other builder honors. It used to
    ride the response under every preference, "none" included. The partial
    stderr stays merged into the response's stderr whatever the preference
    says, as a returned stderr always is."""
    from automated_security_helper.utils import subprocess_utils as spu

    def runner(sandboxed):
        def run(args, **kwargs):
            raise subprocess.TimeoutExpired(
                args, 5, output="partial stdout body", stderr="partial err"
            )

        return run

    monkeypatch.setattr(spu, "find_executable", lambda name: None)
    monkeypatch.setattr(spu, "_runner", runner)

    response = spu.run_command_with_output_handling(
        ["stub-tool"],
        results_dir=tmp_path / "results",
        stdout_preference=preference,
    )

    assert response.get("timed_out") is True, response
    has_stdout = "partial stdout body" in (response.get("stdout") or "")
    assert has_stdout is carried, response
    assert "partial err" in (response.get("stderr") or ""), response
    written = sorted(p.name for p in (tmp_path / "results").rglob("*") if p.is_file())
    # The stdout log exists exactly when the preference writes it; a bare
    # non-empty check was satisfied by stderr.log alone (stderr_preference
    # defaults to "write" here) and could not catch a stdout-write regression.
    if preference in ("write", "both"):
        assert "stdout.log" in written, written
    else:
        assert "stdout.log" not in written, written
    assert "stderr.log" in written, written


@pytest.mark.unit
def test_an_empty_stderr_read_is_carried_by_every_builder(monkeypatch, tmp_path):
    """A record whose stderr is the empty string was read: the tool wrote
    nothing. The fallback and the watch carried that "" while the first
    handler dropped the key, so one state read two ways. One bound for the
    field: a read stderr is carried, empty or not, at all three builders."""
    from automated_security_helper.utils import subprocess_utils as spu

    # The first handler: the wait raised, its own handling held.
    def runner_wait_breaks(sandboxed):
        def run(*args, **kwargs):
            record = spu._note_start(_FakeChild(3))
            assert record is not None, "the cell shows nothing: no record held"
            record.stderr = ""
            raise RuntimeError("waiting on the child broke")

        return run

    monkeypatch.setattr(spu, "find_executable", lambda name: None)
    monkeypatch.setattr(spu, "_runner", runner_wait_breaks)
    handled = spu.run_command_with_output_handling(["stub-tool"])
    assert handled.get("post_run_error") is True, handled
    assert handled.get("stderr") == "", handled

    # The fallback: the first handler itself raised.
    first_handling = []
    real_signaled = spu._signaled_failure

    def signaled_breaks_once(*args, **kwargs):
        if not first_handling:
            first_handling.append(True)
            raise RuntimeError("the failure's own handling broke")
        return real_signaled(*args, **kwargs)

    monkeypatch.setattr(spu, "_signaled_failure", signaled_breaks_once)
    fallback = spu.run_command_with_output_handling(["stub-tool"])
    monkeypatch.setattr(spu, "_signaled_failure", real_signaled)
    assert first_handling, "the cell shows nothing: the first handler never raised"
    assert fallback.get("stderr") == "", fallback

    # The watch, answering for the same record state.
    record = spu._StartedChild()
    record.process = _FakeChild(3)
    record.watched_launch = True
    record.stderr = ""
    watch = spu.StartWatch()
    watch.started = record
    watched = watch.failure_after_the_start(RuntimeError("a later layer raised"))
    assert watched is not None
    assert watched.get("stderr") == "", watched


@pytest.mark.unit
def test_the_fallback_and_the_watch_compose_one_reason_for_an_ash_stopped_child(
    monkeypatch,
):
    """The one arm where the two compositions read differently: a child ASH
    stopped has no exit code, so the reason carries the "ASH stopped the tool
    after:" wrap -- composed around the handler's crash, with the wait's own
    failure leading the whole, at BOTH builders. The committed order cells sit
    in the exited arm, where either composition reads alike."""
    from automated_security_helper.utils import subprocess_utils as spu

    first_handling = []
    real_signaled = spu._signaled_failure

    def signaled_breaks_once(*args, **kwargs):
        if not first_handling:
            first_handling.append(True)
            raise RuntimeError("the failure's own handling broke")
        return real_signaled(*args, **kwargs)

    def runner_wait_breaks(sandboxed):
        def run(*args, **kwargs):
            record = spu._note_start(_FakeChild(-15))
            assert record is not None, "the cell shows nothing: no record held"
            record.stopped = True
            raise RuntimeError("waiting on the child broke")

        return run

    monkeypatch.setattr(spu, "find_executable", lambda name: None)
    monkeypatch.setattr(spu, "_runner", runner_wait_breaks)
    monkeypatch.setattr(spu, "_signaled_failure", signaled_breaks_once)
    fallback = spu.run_command_with_output_handling(["stub-tool"])
    monkeypatch.setattr(spu, "_signaled_failure", real_signaled)
    assert first_handling, "the cell shows nothing: the first handler never raised"

    record = spu._StartedChild()
    record.process = _FakeChild(-15)
    record.watched_launch = True
    record.stopped = True
    watch = spu.StartWatch()
    watch.started = record
    try:
        try:
            raise RuntimeError("waiting on the child broke")
        except RuntimeError:
            raise RuntimeError("the failure's own handling broke")
    except RuntimeError as crash:
        watched = watch.failure_after_the_start(crash)

    a, b = fallback.get("error") or "", (watched or {}).get("error") or ""
    assert a == b, (a, b)
    assert "ASH stopped the tool after:" in a, a
    assert a.index("waiting on the child broke") < a.index(
        "ASH stopped the tool after:"
    ), a
    assert fallback.get("returncode") is None, fallback
    assert (watched or {}).get("returncode") is None, watched


@pytest.mark.integration
def test_control_check_true_raises_the_error():
    """check=True keeps its documented contract: the caller gets an exception, not
    a response. It carries the flag and ASH's reason, and no exit code, since ASH
    stopped the tool and saw none."""
    with _reading_the_pipes_fails(), pytest.raises(Exception) as info:
        run_command(SLEEPER, check=True)

    raised = info.value
    assert getattr(raised, "post_run_error", False) is True, repr(raised)
    assert f"{ASH_STOPPED}: reading the pipes failed" in str(raised), repr(raised)
    assert getattr(raised, "returncode", None) is None, repr(raised)


@pytest.mark.integration
@pytest.mark.parametrize("kind", RUNNERS)
def test_control_a_command_that_cannot_start_is_127(tmp_path, kind):
    missing = [str(tmp_path / "no-such-tool")]

    with _runner(kind):
        result = run_command(list(missing))
        response = run_command_with_output_handling(list(missing), results_dir=tmp_path)

    assert result.returncode == SPAWN_FAILURE_RETURNCODE, result
    assert getattr(result, "spawn_failed", False) is True, result
    assert response["returncode"] == SPAWN_FAILURE_RETURNCODE, response
    assert response["spawn_failed"] is True, response
    assert not response.get("post_run_error"), response


# -- only the spawn's own runner counts ----------------------------------------


def _a_step_before_the_spawn_starts_a_child_that_fails(monkeypatch):
    """_prepare_spawn runs a child of its own, as the sandbox's plan can
    (backends.py's trust-root lookup), and that child starts, then fails."""

    def prepare(*args, **kwargs):
        subprocess.run([sys.executable, "-c", "pass"], capture_output=True)
        return None

    monkeypatch.setattr(subprocess_utils, "_prepare_spawn", prepare)


@pytest.mark.integration
@pytest.mark.parametrize("kind", RUNNERS)
def test_a_child_a_step_before_the_spawn_started_is_not_the_tools(
    tmp_path, monkeypatch, kind
):
    """The tool never started: 127 and spawn_failed, not post_run_error with the
    code of the step's own child (exit code 0). Only a child the spawn's own
    runner call recorded is the tool's."""
    _a_step_before_the_spawn_starts_a_child_that_fails(monkeypatch)

    with _runner(kind), _communicate_returns_then_raises():
        result = run_command(SLEEPER)
        response = run_command_with_output_handling(SLEEPER, results_dir=tmp_path)

    assert result.returncode == SPAWN_FAILURE_RETURNCODE, result
    assert getattr(result, "spawn_failed", False) is True, result
    assert not getattr(result, "post_run_error", False), result
    assert response["returncode"] == SPAWN_FAILURE_RETURNCODE, response
    assert response["spawn_failed"] is True, response
    assert not response.get("post_run_error"), response


# -- the start is the runner's own record, not a reading of frames ---------------


@contextlib.contextmanager
def _runner_behind_a_shim(kind: Optional[str]) -> Iterator[None]:
    """The runner ``kind`` chooses, called through a decorator.

    A wrapper, a decorator or a renamed alias around the runner changes which frame
    a traceback shows below the caller. A start known from the runner's own record
    of its child, set right after Popen returns, doesn't depend on that frame.
    """
    chosen_by = subprocess_utils._runner
    if kind == "stoppable":

        def chosen_by(sandboxed):
            return subprocess_utils._run_stoppable

    def shimmed(sandboxed):
        runner = chosen_by(sandboxed)

        @functools.wraps(runner)
        def shim(*args, **kwargs):
            return runner(*args, **kwargs)

        return shim

    scope = (
        cancel_scope(threading.Event())
        if kind == "cancel-scope"
        else contextlib.nullcontext()
    )
    with scope, patch.object(subprocess_utils, "_runner", shimmed):
        yield


@pytest.mark.integration
@pytest.mark.parametrize("kind", RUNNERS)
def test_run_command_behind_a_shim_keeps_the_exit_code_of_a_child_that_exited(
    tmp_path, kind
):
    marker = tmp_path / "started"

    with _runner_behind_a_shim(kind), _communicate_returns_then_raises():
        result = run_command(_tool_that_exits_3(marker))

    assert marker.exists(), "the child never started, so the cell shows nothing"
    assert isinstance(result, PostRunErrorProcess), result
    assert result.returncode == 3, result
    assert not getattr(result, "spawn_failed", False), result


@pytest.mark.integration
@pytest.mark.parametrize("kind", RUNNERS)
def test_run_command_with_output_handling_behind_a_shim_keeps_the_exit_code(
    tmp_path, kind
):
    marker = tmp_path / "started"

    with _runner_behind_a_shim(kind), _communicate_returns_then_raises():
        response = run_command_with_output_handling(
            _tool_that_exits_3(marker), results_dir=tmp_path / "results"
        )

    assert marker.exists(), "the child never started, so the cell shows nothing"
    assert response["returncode"] == 3, response
    assert response["post_run_error"] is True, response
    assert response["spawn_failed"] is False, response


@pytest.mark.integration
@pytest.mark.parametrize(
    "kind", [None, "cancel-scope"], ids=["plain", "in-a-cancel-scope"]
)
def test_spawn_run_behind_a_shim_keeps_the_exit_code_of_a_child_that_exited(
    tmp_path, monkeypatch, kind
):
    """spawn_run's caller (run_tool without a results_dir) reads the same record.
    The stand-in uv is this Python, which exits 2 on the missing script 'tool'."""
    from automated_security_helper.utils.uv_tool_runner import UVToolRunner

    monkeypatch.setattr(UVToolRunner, "is_uv_available", lambda self: True)
    monkeypatch.chdir(tmp_path)

    with _runner_behind_a_shim(kind), _communicate_returns_then_raises():
        result = UVToolRunner(uv_executable=sys.executable).run_tool(
            "semgrep", args=["scan"]
        )

    assert getattr(result, "post_run_error", False) is True, result
    assert result.returncode == 2, result
    assert "handling the output failed" in result.error, result


@pytest.mark.integration
@pytest.mark.parametrize("kind", RUNNERS)
def test_a_child_that_never_started_behind_a_shim_is_still_127(tmp_path, kind):
    missing = [str(tmp_path / "no-such-tool")]

    with _runner_behind_a_shim(kind):
        result = run_command(list(missing))
        response = run_command_with_output_handling(list(missing), results_dir=tmp_path)

    assert result.returncode == SPAWN_FAILURE_RETURNCODE, result
    assert getattr(result, "spawn_failed", False) is True, result
    assert response["returncode"] == SPAWN_FAILURE_RETURNCODE, response
    assert response["spawn_failed"] is True, response


@contextlib.contextmanager
def _runner_behind_a_shim_that_drops_the_traceback(
    kind: Optional[str],
) -> Iterator[None]:
    """The runner ``kind`` chooses, behind a shim that raises a fresh error of its
    own after its except block. The error the caller sees has no frame below the
    shim and no __context__, so nothing read from a traceback, its frames or
    their locals can tell the child started: only the runner's own record can.
    """
    chosen_by = subprocess_utils._runner
    if kind == "stoppable":

        def chosen_by(sandboxed):
            return subprocess_utils._run_stoppable

    def shimmed(sandboxed):
        runner = chosen_by(sandboxed)

        @functools.wraps(runner)
        def shim(*args, **kwargs):
            message = None
            try:
                return runner(*args, **kwargs)
            except Exception as caught:
                message = str(caught)
            raise RuntimeError(message)

        return shim

    scope = (
        cancel_scope(threading.Event())
        if kind == "cancel-scope"
        else contextlib.nullcontext()
    )
    with scope, patch.object(subprocess_utils, "_runner", shimmed):
        yield


@pytest.mark.integration
@pytest.mark.parametrize("kind", RUNNERS)
def test_run_command_behind_a_shim_that_drops_the_traceback_keeps_the_exit_code(
    tmp_path, kind
):
    marker = tmp_path / "started"

    with (
        _runner_behind_a_shim_that_drops_the_traceback(kind),
        _communicate_returns_then_raises(),
    ):
        result = run_command(_tool_that_exits_3(marker))

    assert marker.exists(), "the child never started, so the cell shows nothing"
    assert isinstance(result, PostRunErrorProcess), result
    assert result.returncode == 3, result
    assert not getattr(result, "spawn_failed", False), result


@pytest.mark.integration
@pytest.mark.parametrize("kind", RUNNERS)
def test_output_handling_behind_a_shim_that_drops_the_traceback_keeps_the_exit_code(
    tmp_path, kind
):
    marker = tmp_path / "started"

    with (
        _runner_behind_a_shim_that_drops_the_traceback(kind),
        _communicate_returns_then_raises(),
    ):
        response = run_command_with_output_handling(
            _tool_that_exits_3(marker), results_dir=tmp_path / "results"
        )

    assert marker.exists(), "the child never started, so the cell shows nothing"
    assert response["returncode"] == 3, response
    assert response["post_run_error"] is True, response
    assert response["spawn_failed"] is False, response


@pytest.mark.integration
@pytest.mark.parametrize(
    "kind", [None, "cancel-scope"], ids=["plain", "in-a-cancel-scope"]
)
def test_spawn_run_behind_a_shim_that_drops_the_traceback_keeps_the_exit_code(
    tmp_path, monkeypatch, kind
):
    """The stand-in uv is this Python, which exits 2 on the missing script 'tool'."""
    from automated_security_helper.utils.uv_tool_runner import UVToolRunner

    monkeypatch.setattr(UVToolRunner, "is_uv_available", lambda self: True)
    monkeypatch.chdir(tmp_path)

    with (
        _runner_behind_a_shim_that_drops_the_traceback(kind),
        _communicate_returns_then_raises(),
    ):
        result = UVToolRunner(uv_executable=sys.executable).run_tool(
            "semgrep", args=["scan"]
        )

    assert getattr(result, "post_run_error", False) is True, result
    assert result.returncode == 2, result
    assert "handling the output failed" in result.error, result


@pytest.mark.integration
@pytest.mark.parametrize("kind", RUNNERS)
def test_control_never_started_behind_a_shim_that_drops_the_traceback_is_127(
    tmp_path, kind
):
    missing = [str(tmp_path / "no-such-tool")]

    with _runner_behind_a_shim_that_drops_the_traceback(kind):
        result = run_command(list(missing))
        response = run_command_with_output_handling(list(missing), results_dir=tmp_path)

    assert result.returncode == SPAWN_FAILURE_RETURNCODE, result
    assert getattr(result, "spawn_failed", False) is True, result
    assert response["returncode"] == SPAWN_FAILURE_RETURNCODE, response
    assert response["spawn_failed"] is True, response


@pytest.mark.unit
@pytest.mark.parametrize("kind", RUNNERS)
def test_a_popen_that_refuses_its_arguments_is_still_127(tmp_path, kind):
    """Popen raising anything, not only an OSError, is a start that never happened:
    an argument that is no string is a TypeError from Popen itself. (Not a null
    byte, which would put a NUL into every log of the run.)"""
    with _runner(kind):
        result = run_command([sys.executable, "-c", "pass", object()])
        response = run_command_with_output_handling(
            [sys.executable, "-c", "pass", object()], results_dir=tmp_path
        )

    assert result.returncode == SPAWN_FAILURE_RETURNCODE, result
    assert getattr(result, "spawn_failed", False) is True, result
    assert response["returncode"] == SPAWN_FAILURE_RETURNCODE, response
    assert response["spawn_failed"] is True, response


def _a_step_before_the_spawn_runs_a_child_through_an_ash_runner(monkeypatch):
    """_prepare_spawn runs a child of its own through ASH's own runner, as the
    sandbox's plan can. The child exits 0, unless the test makes waiting on it
    raise. The runner records that child, and it is not the tool's."""

    def prepare(*args, **kwargs):
        subprocess_utils._runner(sandboxed=False)(
            [sys.executable, "-c", "pass"], capture_output=True
        )
        return None

    monkeypatch.setattr(subprocess_utils, "_prepare_spawn", prepare)


@pytest.mark.integration
@pytest.mark.parametrize("kind", RUNNERS)
def test_a_child_a_step_ran_through_an_ash_runner_is_not_the_tools(
    tmp_path, monkeypatch, kind
):
    """The step's child started and exited 0; then the tool's own start failed. The
    tool never started: 127, not post_run_error with the step child's code 0."""
    _a_step_before_the_spawn_runs_a_child_through_an_ash_runner(monkeypatch)
    missing = [str(tmp_path / "no-such-tool")]

    with _runner(kind):
        result = run_command(list(missing))
        response = run_command_with_output_handling(list(missing), results_dir=tmp_path)

    assert result.returncode == SPAWN_FAILURE_RETURNCODE, result
    assert getattr(result, "spawn_failed", False) is True, result
    assert not getattr(result, "post_run_error", False), result
    assert response["returncode"] == SPAWN_FAILURE_RETURNCODE, response
    assert response["spawn_failed"] is True, response
    assert not response.get("post_run_error"), response


@pytest.mark.integration
@pytest.mark.parametrize("kind", RUNNERS)
def test_a_step_child_that_failed_after_its_start_is_not_the_tools(
    tmp_path, monkeypatch, kind
):
    """Waiting on the step's own child raises after it started, and the step lets
    the error go, before the tool's spawn: still a tool that never started."""
    _a_step_before_the_spawn_runs_a_child_through_an_ash_runner(monkeypatch)

    with _runner(kind), _communicate_returns_then_raises():
        result = run_command(SLEEPER)
        response = run_command_with_output_handling(SLEEPER, results_dir=tmp_path)

    assert result.returncode == SPAWN_FAILURE_RETURNCODE, result
    assert getattr(result, "spawn_failed", False) is True, result
    assert not getattr(result, "post_run_error", False), result
    assert response["returncode"] == SPAWN_FAILURE_RETURNCODE, response
    assert response["spawn_failed"] is True, response
    assert not response.get("post_run_error"), response


@pytest.mark.unit
def test_a_response_with_no_code_grades_by_its_flag_without_raising():
    """A scanner reads the response before post_run_error grades its scan; a code
    of None raised there ('<' between None and int), and the TypeError took the
    place of the error the run had. The None never reaches the comparison:
    judging reads the flag's own conventional code instead (125 for a
    post-run failure), and the stderr line is still recorded. The stub carries
    the kept-cause attribute the response seam reads before the exit-code fold."""
    import types

    from automated_security_helper.base.plugin_base import PluginBase

    scanner = types.SimpleNamespace(
        output=[],
        errors=[],
        exit_code=None,
        _scan_kept_flag=None,
        _values_to_redact=lambda: (),
    )

    PluginBase._process_command_response(
        scanner, {"returncode": None, "stderr": "warning\n", "post_run_error": True}
    )

    assert scanner.exit_code == 125, scanner.exit_code
    assert scanner.errors == ["warning"]


@pytest.mark.integration
def test_the_module_imports_while_subprocess_run_is_a_stand_in():
    """Nothing reads subprocess.run at import: a test that patches it with a
    MagicMock before ASH is imported raised there."""
    from tests.utils.helpers import importing_this_checkout

    driver = (
        "import subprocess\n"
        "from unittest import mock\n"
        "subprocess.run = mock.MagicMock()\n"
        "import automated_security_helper.utils.subprocess_utils\n"
    )
    child = subprocess.run(
        [sys.executable, "-I", "-c", importing_this_checkout(driver)],
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert child.returncode == 0, child.stderr


@pytest.mark.integration
def test_a_watch_sees_a_start_whose_noting_raised(tmp_path, monkeypatch):
    """A raise while noting the start does not blind a held watch. The child
    started when Popen returned, whatever noting it managed: the runner recovers
    the spawn's record itself, and a watch held around the launch is told of it
    too, so a later layer's raise answers as a failure after the start, never a
    tool that could not start."""

    def noting_fails(process):
        raise RuntimeError("noting the start failed")

    monkeypatch.setattr(subprocess_utils, "_note_start", noting_fails)
    watch = subprocess_utils.StartWatch()
    started: list = []

    class _Recorded(subprocess.Popen):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            started.append(self)

    monkeypatch.setattr(subprocess, "Popen", _Recorded)
    try:
        # watched_launch as the launching layer holds it: only the launch's
        # own spawn tells a watch.
        with watch.watching(), subprocess_utils.watched_launch():
            response = run_command_with_output_handling(
                list(SLEEPER), results_dir=tmp_path / "results"
            )
    finally:
        for child in started:
            if child.poll() is None:
                with contextlib.suppress(OSError):
                    child.kill()
                with contextlib.suppress(Exception):
                    child.wait(timeout=10)

    assert started, "no child started, so the cell shows nothing"
    assert response.get("post_run_error") is True, response
    assert watch.started is not None, "the watch missed a start whose noting raised"
    answered = watch.failure_after_the_start(RuntimeError("a later layer raised"))
    assert answered is not None, "the failure read as a tool that could not start"
    assert answered.get("post_run_error") is True, answered
    assert answered.get("spawn_failed") is False, answered


#: Writes a marker on each stream, then exits 0.
_WRITES_BOTH_STREAMS = [
    sys.executable,
    "-c",
    (
        "import sys; sys.stdout.write('stdout-body-7421'); "
        "sys.stderr.write('stderr-body-7421')"
    ),
]


@pytest.mark.integration
@pytest.mark.parametrize(
    "preference, carried",
    [("write", False), ("return", True)],
    ids=["write", "return"],
)
def test_a_watch_answers_the_streams_the_preference_returned(
    tmp_path, preference, carried
):
    """A failure after a completed run carries the run's stderr whatever the
    preference said, and its stdout body only when stdout_preference returned
    it: under "write" the body went to the results file, and answering it again
    would hand a later layer output the caller asked to keep on disk. The same
    bound rcwoh's own failure-after-the-start branch already honors."""
    watch = subprocess_utils.StartWatch()

    # watched_launch as the launching layer holds it: only the launch's own
    # spawn tells a watch.
    with watch.watching(), subprocess_utils.watched_launch():
        response = run_command_with_output_handling(
            list(_WRITES_BOTH_STREAMS),
            results_dir=tmp_path / "results",
            stdout_preference=preference,
        )

    assert response.get("returncode") == 0, response
    assert watch.started is not None, "the spawn never told the watch"
    # The answering layer passes the call's own preference, as the uv mixin
    # does: the watch applies the same bound to what the record carries.
    answered = watch.failure_after_the_start(
        RuntimeError("a later layer raised"), stdout_preference=preference
    )
    assert answered is not None, answered
    assert "stderr-body-7421" in (answered.get("stderr") or ""), answered
    has_stdout = "stdout-body-7421" in (answered.get("stdout") or "")
    assert has_stdout is carried, answered


# -- a kept signal death stays signaled, with its number, at every builder ----------


def _shown_raises_once(monkeypatch) -> list:
    """subprocess_utils.shown_on_one_line raises on its first call and passes
    through afterwards: the first post-run log line fails, and the handler's own
    logging still works."""
    fired: list = []
    real = subprocess_utils.shown_on_one_line

    def wrapper(text):
        if not fired:
            fired.append(True)
            raise OSError("logging the result failed")
        return real(text)

    monkeypatch.setattr(subprocess_utils, "shown_on_one_line", wrapper)
    return fired


@pytest.mark.integration
@pytest.mark.skipif(os.name != "posix", reason="a signal death is POSIX's case")
@pytest.mark.parametrize("signal_name", ["SIGKILL", "SIGHUP"])
def test_a_kept_signal_death_stays_signaled_after_the_run_returned(
    tmp_path, monkeypatch, caplog, signal_name
):
    """run_command's run returned a signal death, through a real spawn, and
    logging it then failed. The post-run result keeps the tool's own ending: the
    negative code, signaled, and the signal's own number. Two signals, so a
    builder stamping one hardcoded number is caught; by name, since the names do
    not exist on Windows and parametrize evaluates at collection. check=True is
    not pinned here: a real runner raises CalledProcessError for any non-zero
    code before this path, and that raise's shape is pinned by
    test_a_signal_death_under_check_raises_the_stock_error. The death is logged
    once: by the handler's failure line, which carries it."""
    import logging

    signum = getattr(signal, signal_name)
    marker = tmp_path / "ran"
    fired = _shown_raises_once(monkeypatch)

    with caplog.at_level(logging.DEBUG, logger="ash"):
        result = run_command(_tool_that_ends_by_its_own_signal(marker, signum))

    assert marker.exists(), "the tool never started, so the cell shows nothing"
    assert fired, "the log line never fired, so the cell shows nothing"
    assert getattr(result, "post_run_error", False) is True, result
    assert result.returncode == -int(signum), result
    assert getattr(result, "signaled", False) is True, result
    assert getattr(result, "signal", None) == int(signum), result
    deaths = [
        r.getMessage()
        for r in caplog.records
        if "a signal ASH did not send" in r.getMessage()
    ]
    assert len(deaths) == 1, deaths


@pytest.mark.integration
@pytest.mark.skipif(os.name != "posix", reason="a signal death is POSIX's case")
def test_a_signal_death_under_check_raises_the_stock_error(tmp_path):
    """A plain signal death on a check=True path keeps the stock
    CalledProcessError. The negative code already names the signal, and no
    signaled attribute is added: the flag belongs to ASH's recorded response,
    not an exception type ASH does not own. A wrapper that adds or loses either
    goes red here."""
    marker = tmp_path / "ran"

    with pytest.raises(subprocess.CalledProcessError) as caught:
        run_command(
            _tool_that_ends_by_its_own_signal(marker, signal.SIGKILL), check=True
        )

    assert marker.exists(), "the tool never started, so the cell shows nothing"
    error = caught.value
    assert error.returncode == -signal.SIGKILL, error
    assert not hasattr(error, "signaled"), vars(error)


@pytest.mark.integration
@pytest.mark.skipif(os.name != "posix", reason="a signal death is POSIX's case")
def test_a_kept_signal_death_stays_signaled_on_the_waited_check_raise(
    tmp_path, monkeypatch
):
    """The waited-child form of the cell above, through a real spawn: the tool
    ended itself, reading its output then raised, and check=True raises the
    post-run error with the tool's own ending kept: signaled, with the number."""
    marker = tmp_path / "ran"

    with _communicate_returns_then_raises():
        with pytest.raises(subprocess_utils.PostRunError) as caught:
            run_command(
                _tool_that_ends_by_its_own_signal(marker, signal.SIGKILL), check=True
            )

    assert marker.exists(), "the tool never started, so the cell shows nothing"
    error = caught.value
    assert getattr(error, "post_run_error", False) is True, error
    assert error.returncode == -signal.SIGKILL, error
    assert getattr(error, "signaled", False) is True, error
    assert getattr(error, "signal", None) == int(signal.SIGKILL), error


@pytest.mark.integration
@pytest.mark.skipif(os.name != "posix", reason="a signal death is POSIX's case")
def test_a_kept_signal_death_stays_signaled_in_the_late_response(tmp_path, monkeypatch):
    """run_command_with_output_handling's run returned a signal death, and ASH
    failed BEFORE building any response: the sandbox's cleanup, which runs right
    after the run returns, raises once. The late post-run response still keeps the
    tool's own ending — the negative code, signaled, and the signal's number — so
    the flags come from the late handler itself, whatever order the response's
    own build or its logging takes."""
    marker = tmp_path / "ran"
    fired: list = []

    class _CleanupFailsOnce:
        def __init__(self, argv, env):
            self.argv = argv
            self.env = env

        def run_cleanup(self) -> None:
            if not fired:
                fired.append(True)
                raise OSError("the sandbox's cleanup failed")

    monkeypatch.setattr(
        subprocess_utils,
        "_prepare_spawn",
        lambda command, env, cwd, shell: _CleanupFailsOnce(list(command), env),
    )

    response = run_command_with_output_handling(
        _tool_that_ends_by_its_own_signal(marker, signal.SIGHUP),
        results_dir=tmp_path / "results",
    )

    assert marker.exists(), "the tool never started, so the cell shows nothing"
    assert fired, "the cleanup never raised, so the cell shows nothing"
    assert response.get("post_run_error") is True, response
    assert response.get("returncode") == -signal.SIGHUP, response
    assert response.get("signaled") is True, response
    assert response.get("signal") == int(signal.SIGHUP), response


class _Unprintable(Exception):
    """An error whose text cannot be formatted."""

    def __str__(self) -> str:
        raise RuntimeError("the error's text cannot be formatted")


def _child_whose_handling_fails(shape: str, code: int):
    """A runner that records a child that exited with ``code`` and then
    raises, in a way that makes the handler for a failure after the start raise
    too: the child's poll() raises (``poll-raises``), or the runner's error
    cannot be formatted (``unprintable``)."""

    class _Exited:
        pid = 2**22 + 23
        returncode = code
        stdout = None
        stderr = None

        def poll(self):
            if shape == "poll-raises":
                raise ValueError("poll failed")
            return code

    def run(args, **kwargs):
        subprocess_utils._note_start(_Exited())
        if shape == "unprintable":
            raise _Unprintable
        raise RuntimeError("reading its output failed")

    return run


HANDLING_FAILS = [
    pytest.param("poll-raises", 3, id="poll-raises"),
    pytest.param("unprintable", 3, id="unprintable-error"),
    pytest.param(
        "poll-raises",
        -9,
        id="poll-raises-after-sigkill",
        marks=pytest.mark.skipif(
            os.name != "posix", reason="a signal death is POSIX's case"
        ),
    ),
]


@pytest.mark.unit
@pytest.mark.parametrize("shape,code", HANDLING_FAILS)
def test_a_started_child_whose_failure_handling_raises_is_still_after_the_start(
    monkeypatch, shape, code
):
    """run_command_with_output_handling's handler for a failure after the
    start can itself raise. The child was recorded, so the answer is still a
    post-run error with the child's own code (signaled for a signal death),
    never 127 "the command never ran"."""
    monkeypatch.setattr(
        subprocess_utils,
        "_runner",
        lambda sandboxed: _child_whose_handling_fails(shape, code),
    )
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)

    response = run_command_with_output_handling(["stub-tool"])

    assert response.get("post_run_error") is True, response
    assert response.get("spawn_failed") is False, response
    assert response.get("returncode") == code, response
    assert response.get("signaled", False) is (code < 0), response
    assert "never ran" not in str(response.get("stderr", "")), response
    assert "never ran" not in str(response.get("error", "")), response


@pytest.mark.unit
@pytest.mark.parametrize("shape,code", HANDLING_FAILS)
def test_run_command_lets_the_failure_of_its_own_handling_raise(
    monkeypatch, shape, code
):
    """run_command has no outer handler: when its handler for a failure after
    the start raises, that error reaches the caller as raised. Deliberately
    unlike run_command_with_output_handling, which answers a post-run error;
    run_command's callers get its raise as it is."""
    monkeypatch.setattr(
        subprocess_utils,
        "_runner",
        lambda sandboxed: _child_whose_handling_fails(shape, code),
    )
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)

    expected = ValueError if shape == "poll-raises" else RuntimeError
    with pytest.raises(expected):
        run_command(["stub-tool"])


class _RecordedChild:
    """A child the runner recorded, which exited with code 3. Its poll()
    raises ``poll_error`` when one is given."""

    pid = 2**22 + 29
    returncode = 3
    stdout = None
    stderr = None

    def __init__(self, poll_error: Optional[BaseException] = None) -> None:
        self._poll_error = poll_error

    def poll(self):
        if self._poll_error is not None:
            raise self._poll_error
        return self.returncode


def _runner_after_the_start(
    child: _RecordedChild,
    error: BaseException,
    *,
    stop_refused: bool = False,
    stderr: Optional[str] = None,
    stdout: Optional[str] = None,
):
    """A runner that records *child*, sets what a runner records of it (a
    refused stop, the streams a failed wait read), and raises *error*."""

    def run(args, **kwargs):
        record = subprocess_utils._note_start(child)
        if record is None:
            raise AssertionError("control: the child was not recorded")
        record.stop_refused = stop_refused
        record.stderr = stderr
        record.stdout = stdout
        raise error

    return run


@pytest.mark.unit
def test_a_poll_error_whose_text_cannot_be_formatted_is_still_an_answer(monkeypatch):
    """The child's poll() raises an error whose text cannot be formatted, inside
    the handler for a failure after the start. The fallback that answers for
    that handler formats the error it receives under a guard: the answer is a
    post-run error with the child's own code, never a raise out of
    run_command_with_output_handling."""
    child = _RecordedChild(poll_error=_Unprintable())
    monkeypatch.setattr(
        subprocess_utils,
        "_runner",
        lambda sandboxed: _runner_after_the_start(
            child, RuntimeError("reading its output failed")
        ),
    )
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)

    response = run_command_with_output_handling(["stub-tool"])

    assert response.get("post_run_error") is True, response
    assert response.get("spawn_failed") is False, response
    assert response.get("returncode") == 3, response


@pytest.mark.unit
def test_a_refused_stop_is_still_said_when_the_failure_handling_raises(monkeypatch):
    """ASH's stop of the recorded child was refused, and the handler for the
    failure after the start then raised (on an error whose text cannot be
    formatted). The answer is the one every other producer gives a refused
    stop: no code, could_not_stop with the child's pid, and a reason saying it
    may still be running. The control: a post-run error, never "never ran"."""
    child = _RecordedChild()
    monkeypatch.setattr(
        subprocess_utils,
        "_runner",
        lambda sandboxed: _runner_after_the_start(
            child, _Unprintable(), stop_refused=True
        ),
    )
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)

    response = run_command_with_output_handling(["stub-tool"])

    assert response.get("post_run_error") is True, response
    assert "never ran" not in str(response.get("error", "")), response
    assert response.get("returncode") is None, response
    assert response.get("could_not_stop") is True, response
    assert response.get("could_not_stop_pid") == child.pid, response
    assert "may still be running" in str(response.get("error", "")), response


@pytest.mark.unit
def test_the_output_a_failed_wait_read_is_kept_when_the_failure_handling_raises(
    monkeypatch,
):
    """The record holds the stderr the failed wait read before the handler
    raised. The answer carries it, as the handler's own answer would: it is
    usually the only clue to the failure."""
    child = _RecordedChild()
    monkeypatch.setattr(
        subprocess_utils,
        "_runner",
        lambda sandboxed: _runner_after_the_start(
            child, _Unprintable(), stderr="diag before the failure\n"
        ),
    )
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)

    response = run_command_with_output_handling(["stub-tool"])

    # The control: the fallback answered, a post-run error with the code.
    assert response.get("post_run_error") is True, response
    assert response.get("returncode") == 3, response
    assert "diag before the failure" in str(response.get("stderr", "")), response


class _FormatRaises(str):
    """Text whose formatting raises, as a str subclass's own __format__ can."""

    __slots__ = ()

    def __format__(self, spec: str) -> str:
        raise RuntimeError("the text's formatting raised")


class _TextIsAStrSubclass(Exception):
    """An error whose text is a str subclass that cannot be formatted."""

    def __str__(self) -> str:
        return _FormatRaises("poll failed")


@pytest.mark.unit
def test_a_poll_error_whose_text_is_a_str_subclass_is_still_an_answer(monkeypatch):
    """The child's poll() raises an error whose str() is a str subclass whose
    formatting raises, inside the handler for a failure after the start. The
    fallback that answers for that handler takes the error's text as a plain
    str before it builds a message from it: the answer is a post-run error with
    the child's own code and the error's words, never a raise out of
    run_command_with_output_handling."""
    child = _RecordedChild(poll_error=_TextIsAStrSubclass())
    monkeypatch.setattr(
        subprocess_utils,
        "_runner",
        lambda sandboxed: _runner_after_the_start(
            child, RuntimeError("reading its output failed")
        ),
    )
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)

    response = run_command_with_output_handling(["stub-tool"])

    assert response.get("post_run_error") is True, response
    assert response.get("spawn_failed") is False, response
    assert response.get("returncode") == 3, response
    assert "poll failed" in str(response.get("error", "")), response


@pytest.mark.unit
def test_the_stdout_a_failed_wait_read_follows_the_callers_preference(monkeypatch):
    """Under the scanners' default "write" the stdout body went to the results
    file, and the handler's own answer returns it only when the preference
    asks for it; the fallback that answers when that handler raises honors
    the same bound, so the body the caller asked to keep on disk is not also
    in the response."""
    child = _RecordedChild()
    monkeypatch.setattr(
        subprocess_utils,
        "_runner",
        lambda sandboxed: _runner_after_the_start(
            child, _Unprintable(), stdout="the whole stdout body\n"
        ),
    )
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)

    response = run_command_with_output_handling(["stub-tool"])

    assert response.get("post_run_error") is True, response
    assert "stdout" not in response, response


@pytest.mark.unit
def test_the_stdout_a_failed_wait_read_is_returned_when_asked(monkeypatch):
    """The admit side of the preference bound: with "return" the fallback
    carries the stdout the record holds, as the handler's answer would."""
    child = _RecordedChild()
    monkeypatch.setattr(
        subprocess_utils,
        "_runner",
        lambda sandboxed: _runner_after_the_start(
            child, _Unprintable(), stdout="the whole stdout body\n"
        ),
    )
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)

    response = run_command_with_output_handling(
        ["stub-tool"], stdout_preference="return"
    )

    assert response.get("post_run_error") is True, response
    assert response.get("stdout") == "the whole stdout body\n", response


@pytest.mark.unit
def test_the_handlers_own_failure_keeps_the_original_on_the_answer(monkeypatch):
    """The handler for a failure after the start raised while answering the
    runner's original failure, which its raise chains (``__context__``). That
    original failure is usually the only clue to what went wrong, so the
    answer's reason leads with it and adds the handler's own error after."""
    child = _RecordedChild(poll_error=ValueError("the poll exploded"))
    monkeypatch.setattr(
        subprocess_utils,
        "_runner",
        lambda sandboxed: _runner_after_the_start(
            child, RuntimeError("reading its output failed")
        ),
    )
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)

    response = run_command_with_output_handling(["stub-tool"])

    assert response.get("post_run_error") is True, response
    error_text = str(response.get("error", ""))
    assert "reading its output failed" in error_text, response
    assert "the poll exploded" in error_text, response
    # The order is part of the contract: the wait's own failure leads, the
    # handler's crash follows. Both-present alone passes with the order
    # reversed.
    assert error_text.index("reading its output failed") < error_text.index(
        "the poll exploded"
    ), error_text


@pytest.mark.unit
@pytest.mark.parametrize(
    "stdout", ["the whole stdout body\n", ""], ids=["body", "empty"]
)
@pytest.mark.parametrize("preference", ["write", "return", "both", "none"])
def test_the_fallbacks_stdout_parity_with_the_handler(monkeypatch, preference, stdout):
    """Across every preference and an empty body, the fallback's answer
    carries stdout exactly when the handler's own answer would, and the same
    body: one bound, not two. The write and return cells above pin the two
    named arms; this matrix pins "both", "none", and the empty body, which an
    is-not-None bound would carry and a truthiness bound must not."""
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)
    monkeypatch.setattr(
        subprocess_utils,
        "_runner",
        lambda sandboxed: _runner_after_the_start(
            _RecordedChild(), RuntimeError("reading its output failed"), stdout=stdout
        ),
    )
    handler = run_command_with_output_handling(
        ["stub-tool"], stdout_preference=preference
    )
    monkeypatch.setattr(
        subprocess_utils,
        "_runner",
        lambda sandboxed: _runner_after_the_start(
            _RecordedChild(), _Unprintable(), stdout=stdout
        ),
    )
    fallback = run_command_with_output_handling(
        ["stub-tool"], stdout_preference=preference
    )
    # The controls: each answer came from the arm it was meant to.
    assert "be formatted" in str(fallback.get("error", "")), fallback
    assert "reading its output failed" in str(handler.get("error", "")), handler
    assert ("stdout" in fallback) == ("stdout" in handler), (handler, fallback)
    assert fallback.get("stdout") == handler.get("stdout"), (handler, fallback)


#: A value the caller's config read from the environment, which the poll
#: error's text quotes.
_ENV_READ_VALUE = "/nonexistent/ENVCANARY-91bd/settings.yaml"


@pytest.mark.unit
def test_the_fallbacks_log_line_carries_no_value_its_caller_hands_it(monkeypatch):
    """The fallback that answers when the handler for a failure after the
    start raised logs one line of its own, built from the error's text. It is
    redacted with the values the caller handed run_command_with_output_handling,
    as every line the runner logs itself is. What it returns stays as it is:
    the caller redacts where it keeps it, which is the control that the value
    reached the line at all."""
    child = _RecordedChild(poll_error=ValueError(f"poll failed on {_ENV_READ_VALUE}"))
    monkeypatch.setattr(
        subprocess_utils,
        "_runner",
        lambda sandboxed: _runner_after_the_start(
            child, RuntimeError("reading its output failed")
        ),
    )
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)
    records = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    handler = _Collect(level=logging.DEBUG)
    level = subprocess_utils.ASH_LOGGER.level
    subprocess_utils.ASH_LOGGER.setLevel(logging.DEBUG)
    subprocess_utils.ASH_LOGGER.addHandler(handler)
    try:
        response = run_command_with_output_handling(
            ["stub-tool"], values=[_ENV_READ_VALUE]
        )
    finally:
        subprocess_utils.ASH_LOGGER.removeHandler(handler)
        subprocess_utils.ASH_LOGGER.setLevel(level)

    # The controls: the fallback answered, its error holds the value, and it
    # logged its line.
    assert response.get("post_run_error") is True, response
    assert _ENV_READ_VALUE in str(response.get("error", "")), response
    fallback_lines = [r for r in records if "ASH could not record the output of" in r]
    assert fallback_lines, records
    for record in records:
        assert "ENVCANARY-91bd" not in record, record
