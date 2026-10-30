# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH's plain runner is subprocess.run, with the start held where ASH can see it.

Why this file exists
--------------------
A spawn outside a sandbox and outside a cancel scope went through subprocess.run,
which starts the child and waits on it in one call. When the wait raised, ASH
could tell whether the child had started only by reading the traceback's frames:
matching their code objects, reading the runner's ``process`` local, and finding
a closure by name. A shim, a decorator or a rename around the runner turned a
started child into "never started" (127).

Now the plain runner is ASH's own, ``subprocess_utils._run_plain``: Popen, then
communicate, with the child recorded right after Popen returns. These cells hold
it to everything subprocess.run does, case by case and as a differential against
subprocess.run itself:

- capture_output sets PIPE for both streams, and is a ValueError with stdout or
  stderr also given (None is allowed, as subprocess.run allows it);
- input is written to the child's stdin, and is a ValueError with stdin given;
- a timeout kills the child, reaps it, keeps the output read so far, and raises
  the TimeoutExpired communicate raised, the same object. On POSIX it reaps with
  wait(), not another read: a process the tool left holding the pipes doesn't
  stretch the timeout;
- check=True raises CalledProcessError with the code, the args and the output;
- any other error while waiting kills and reaps the child and raises the same
  object, KeyboardInterrupt included, without an unbounded wait: on an interrupt
  it waits only briefly for a child the kill did not stop;
- no pipe or process object is left for the garbage collector to warn about.

What is out of scope: Windows' second communicate() after the kill can't run on
a POSIX host, so only its outcome (the output read so far is kept) is held here.
"""

from __future__ import annotations

import contextlib
import gc
import os
import signal
import subprocess
import sys
import time
import warnings
from types import SimpleNamespace
from typing import Any, Iterator, List, Optional, Tuple
from unittest.mock import patch

import pytest

from automated_security_helper.utils import subprocess_utils

PY = sys.executable

#: Writes a line to each stream and exits 3.
WRITES_AND_EXITS_3 = [
    PY,
    "-c",
    "import sys; sys.stdout.write('out\\n'); sys.stderr.write('err\\n'); sys.exit(3)",
]

#: Writes what its stdin holds to its stdout.
ECHOES_STDIN = [PY, "-c", "import sys; sys.stdout.write(sys.stdin.read())"]

#: Writes a line to each stream at once, then runs well past any timeout here.
_PARTIAL_PROGRAM = (
    "import sys, time; sys.stdout.write('partial\\n'); sys.stdout.flush(); "
    "sys.stderr.write('diag\\n'); sys.stderr.flush(); time.sleep(60)"
)
PARTIAL_THEN_SLEEPS = [PY, "-c", _PARTIAL_PROGRAM]

#: A wait that ended in a kill is far shorter than the child's own 60 s.
WELL_SHORT_OF_THE_CHILD = 30.0

#: Starts a grandchild that inherits the pipes and outlives the child, writes the
#: grandchild's pid to the file named by its argument, then writes a line and
#: runs past any timeout here.
_GRANDCHILD_PROGRAM = (
    "import pathlib, subprocess, sys, time; "
    "g = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
    "pathlib.Path(sys.argv[1]).write_text(str(g.pid)); "
    "sys.stdout.write('partial\\n'); sys.stdout.flush(); time.sleep(60)"
)


def _kill_quietly(pid_file: Any) -> None:
    """SIGKILL the grandchild whose pid ``pid_file`` holds, if it got one."""
    try:
        pid = int(pid_file.read_text())
    except (OSError, ValueError):
        return
    with contextlib.suppress(OSError):
        os.kill(pid, signal.SIGKILL)


def _plain() -> Any:
    """The runner under test. An AttributeError here means it doesn't exist yet."""
    return subprocess_utils._run_plain


def _text(captured: Any) -> str:
    if isinstance(captured, bytes):
        return captured.decode("utf-8", errors="replace")
    return captured or ""


@contextlib.contextmanager
def _watched_communicate(fail_with: Optional[BaseException] = None) -> Iterator[Any]:
    """Record every Popen communicate() is called on, and what it raised.

    With ``fail_with``, the first call raises it instead of reading anything, as a
    failure while waiting on a child that is still running.
    """
    real = subprocess.Popen.communicate
    seen = SimpleNamespace(processes=[], raised=[])

    def communicate(self, *args, **kwargs):
        seen.processes.append(self)
        if fail_with is not None and len(seen.processes) == 1:
            raise fail_with
        try:
            return real(self, *args, **kwargs)
        except BaseException as error:
            seen.raised.append(error)
            raise

    with patch.object(subprocess.Popen, "communicate", communicate):
        yield seen


@pytest.mark.unit
def test_the_plain_branch_is_ashs_own_runner():
    """Outside a sandbox and a cancel scope, _runner hands out _run_plain."""
    assert subprocess_utils._runner(sandboxed=False) is _plain()


# -- capture_output, input and stdin -------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_capture_output_with_a_stream_given_is_a_value_error(stream):
    with pytest.raises(ValueError, match="may not be used with capture_output"):
        _plain()(WRITES_AND_EXITS_3, capture_output=True, **{stream: subprocess.PIPE})


@pytest.mark.integration
def test_capture_output_with_a_stream_given_as_none_is_allowed():
    """subprocess.run checks ``is not None``, so stdout=None is no conflict."""
    result = _plain()(WRITES_AND_EXITS_3, capture_output=True, text=True, stdout=None)

    assert result.stdout == "out\n", result
    assert result.stderr == "err\n", result


@pytest.mark.integration
def test_input_is_written_to_the_childs_stdin():
    result = _plain()(ECHOES_STDIN, input="hello\n", capture_output=True, text=True)

    assert result.stdout == "hello\n", result


@pytest.mark.unit
def test_input_with_stdin_given_is_a_value_error():
    with pytest.raises(ValueError, match="stdin and input arguments may not both"):
        _plain()(ECHOES_STDIN, input="x", stdin=subprocess.DEVNULL)


# -- a timeout ------------------------------------------------------------------


@pytest.mark.integration
def test_a_timeout_kills_reaps_and_raises_the_same_timeout_expired():
    started = time.monotonic()
    with (
        _watched_communicate() as seen,
        pytest.raises(subprocess.TimeoutExpired) as info,
    ):
        _plain()(PARTIAL_THEN_SLEEPS, capture_output=True, text=True, timeout=3.0)

    assert time.monotonic() - started < WELL_SHORT_OF_THE_CHILD
    assert seen.raised, "communicate() never raised, so the cell shows nothing"
    assert info.value is seen.raised[0], (info.value, seen.raised)
    assert info.value.cmd == PARTIAL_THEN_SLEEPS
    assert info.value.timeout == 3.0
    (process,) = seen.processes[:1]
    assert process.returncode not in (None, 0), process.returncode


@pytest.mark.integration
def test_a_timeout_keeps_the_output_read_before_it():
    with pytest.raises(subprocess.TimeoutExpired) as info:
        _plain()(PARTIAL_THEN_SLEEPS, capture_output=True, text=True, timeout=3.0)

    assert "partial" in _text(info.value.output), info.value.output
    assert "diag" in _text(info.value.stderr), info.value.stderr


@pytest.mark.integration
@pytest.mark.skipif(os.name != "posix", reason="wait() after the kill is POSIX's path")
def test_a_timeout_does_not_wait_for_a_grandchild_holding_the_pipes(tmp_path):
    """subprocess.run kills the child, then wait()s for it. A read of the pipes
    after the kill would last until every process holding them exits, so a tool
    that left a process behind would turn the 2 s timeout into 60 s."""
    pid_file = tmp_path / "grandchild.pid"
    started = time.monotonic()
    try:
        with pytest.raises(subprocess.TimeoutExpired) as info:
            _plain()(
                [PY, "-c", _GRANDCHILD_PROGRAM, str(pid_file)],
                capture_output=True,
                text=True,
                timeout=2.0,
            )
        elapsed = time.monotonic() - started

        assert pid_file.exists(), "no grandchild started, so the cell shows nothing"
        assert "partial" in _text(info.value.output), info.value.output
        assert elapsed < 20, f"the timeout took {elapsed:.1f}s"
    finally:
        _kill_quietly(pid_file)


# -- check=True -------------------------------------------------------------------


@pytest.mark.integration
def test_check_raises_called_process_error_with_the_output():
    with pytest.raises(subprocess.CalledProcessError) as info:
        _plain()(WRITES_AND_EXITS_3, capture_output=True, text=True, check=True)

    assert info.value.returncode == 3
    assert info.value.cmd == WRITES_AND_EXITS_3
    assert info.value.output == "out\n"
    assert info.value.stderr == "err\n"


@pytest.mark.integration
def test_control_check_with_a_clean_exit_returns_the_result():
    result = _plain()([PY, "-c", "pass"], capture_output=True, check=True)

    assert isinstance(result, subprocess.CompletedProcess), result
    assert result.returncode == 0


# -- any other error while waiting ----------------------------------------------


@pytest.mark.integration
def test_an_error_while_waiting_kills_reaps_and_raises_the_same_object():
    raised = RuntimeError("reading the pipes failed")
    started = time.monotonic()

    with (
        _watched_communicate(fail_with=raised) as seen,
        pytest.raises(RuntimeError) as info,
    ):
        _plain()(PARTIAL_THEN_SLEEPS, capture_output=True, text=True)

    assert info.value is raised, info.value
    assert time.monotonic() - started < WELL_SHORT_OF_THE_CHILD
    process = seen.processes[0]
    assert process.returncode not in (None, 0), "the child was left running"


@pytest.mark.integration
def test_an_interrupt_while_waiting_is_raised_without_an_unbounded_wait():
    interrupt = KeyboardInterrupt()
    started = time.monotonic()

    with (
        _watched_communicate(fail_with=interrupt) as seen,
        pytest.raises(KeyboardInterrupt) as info,
    ):
        _plain()(PARTIAL_THEN_SLEEPS, capture_output=True, text=True)

    assert info.value is interrupt, info.value
    assert time.monotonic() - started < WELL_SHORT_OF_THE_CHILD
    process = seen.processes[0]
    # Killed: it ends well before its own 60 s, though the runner may not wait.
    assert process.wait(timeout=WELL_SHORT_OF_THE_CHILD) != 0


@pytest.mark.integration
def test_an_interrupt_waits_only_briefly_for_a_child_the_kill_did_not_stop():
    """On KeyboardInterrupt subprocess.run kills the child, and Popen's exit then
    waits at most a quarter second for it, never without a bound. With the kill a
    no-op the child keeps running, so a wait without a bound shows as one.

    With a timeout the plain runner stops the child's own process group, so the
    kill it sends is the group signal rather than Popen.kill; without one, as
    here, it kills the child alone, as subprocess.run does. The kill is made a
    no-op so the child keeps running, as the case under test requires, and the
    group signal is recorded apart from it: a stop that reached for the group
    in this no-timeout case would show as a group signal, not as a kill."""
    interrupt = KeyboardInterrupt()
    real_kill = subprocess.Popen.kill
    real_communicate = subprocess.Popen.communicate
    seen = SimpleNamespace(processes=[], kills=0, group_signals=0)

    def communicate(self, *args, **kwargs):
        seen.processes.append(self)
        if len(seen.processes) == 1:
            raise interrupt
        return real_communicate(self, *args, **kwargs)

    def kill(self):
        seen.kills += 1

    def signal_group(pgid, signum):
        # Signal 0 is the existence probe, which keeps answering that the group
        # lives on; a real signal is a group stop, counted on its own and
        # swallowed so the child keeps running as the case under test requires.
        if signum != 0:
            seen.group_signals += 1
        return True

    started = time.monotonic()
    try:
        with (
            patch.object(subprocess.Popen, "communicate", communicate),
            patch.object(subprocess.Popen, "kill", kill),
            patch.object(subprocess_utils, "_signal_group", signal_group),
            pytest.raises(KeyboardInterrupt) as info,
        ):
            _plain()(PARTIAL_THEN_SLEEPS, capture_output=True, text=True)
        elapsed = time.monotonic() - started

        assert info.value is interrupt, info.value
        assert seen.kills >= 1, "the runner never tried to stop the child"
        assert seen.group_signals == 0, "without a timeout the child is killed alone"
        assert elapsed < 10, f"the interrupt took {elapsed:.1f}s"
    finally:
        for process in seen.processes:
            with contextlib.suppress(OSError):
                real_kill(process)
            process.wait(timeout=WELL_SHORT_OF_THE_CHILD)


# -- nothing is left for the garbage collector ----------------------------------


@contextlib.contextmanager
def _resource_warnings() -> Iterator[List[warnings.WarningMessage]]:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ResourceWarning)
        yield caught
        gc.collect()


def _of_resources(caught: List[warnings.WarningMessage]) -> List[str]:
    return [str(w.message) for w in caught if issubclass(w.category, ResourceWarning)]


@pytest.mark.integration
def test_no_pipe_or_process_is_left_unclosed():
    with _resource_warnings() as caught:
        _plain()(WRITES_AND_EXITS_3, capture_output=True, text=True)
        _plain()(ECHOES_STDIN, input="x", capture_output=True, text=True)
        with pytest.raises(subprocess.CalledProcessError):
            _plain()(WRITES_AND_EXITS_3, capture_output=True, check=True)
        with pytest.raises(subprocess.TimeoutExpired):
            _plain()(PARTIAL_THEN_SLEEPS, capture_output=True, timeout=1.0)
        with (
            _watched_communicate(fail_with=RuntimeError("x")),
            pytest.raises(RuntimeError),
        ):
            _plain()(PARTIAL_THEN_SLEEPS, capture_output=True)

    assert not _of_resources(caught), _of_resources(caught)


@pytest.mark.unit
def test_control_an_unclosed_pipe_is_seen():
    """The detector above is not vacuous: a pipe dropped unclosed is reported."""
    with _resource_warnings() as caught:
        read_end, write_end = os.pipe()
        os.close(write_end)
        leaked = os.fdopen(read_end, "rb")
        del leaked

    assert _of_resources(caught), "an unclosed pipe went unreported"


# -- the differential: subprocess.run against _run_plain -------------------------


def _outcome(runner: Any, args: List[str], **kwargs: Any) -> Tuple[Any, ...]:
    """What a call answered, in a form two runners' answers compare in."""
    try:
        result = runner(args, **kwargs)
    except subprocess.CalledProcessError as error:
        return (
            "CalledProcessError",
            error.returncode,
            error.cmd,
            error.output,
            error.stderr,
        )
    except subprocess.TimeoutExpired as error:
        # How much was read before the kill depends on timing; that something was
        # read does not, nor its type (bytes on POSIX, even in text mode).
        return (
            "TimeoutExpired",
            error.cmd,
            error.timeout,
            "partial" in _text(error.output),
            type(error.output).__name__,
        )
    except ValueError as error:
        return ("ValueError", str(error))
    return (
        type(result).__name__,
        result.args,
        result.returncode,
        result.stdout,
        result.stderr,
    )


_INVALID_UTF8 = [PY, "-c", "import sys; sys.stdout.buffer.write(b'a\\xffb\\n')"]
_PRINTS_ITS_VARIABLE = [
    PY,
    "-c",
    "import os, sys; sys.stdout.write(os.environ.get('ASH_PARITY', 'unset'))",
]
#: The child's whole environment: one variable, plus what Windows needs to start.
_ONE_VARIABLE = {
    "ASH_PARITY": "1",
    **({"SYSTEMROOT": os.environ["SYSTEMROOT"]} if "SYSTEMROOT" in os.environ else {}),
}

DIFFERENTIAL = [
    pytest.param(
        WRITES_AND_EXITS_3, {"capture_output": True, "text": True}, id="exits-3-text"
    ),
    pytest.param(WRITES_AND_EXITS_3, {"capture_output": True}, id="exits-3-bytes"),
    pytest.param([PY, "-c", "pass"], {}, id="exits-0-nothing-captured"),
    pytest.param(
        WRITES_AND_EXITS_3,
        {"stdout": subprocess.PIPE, "text": True},
        id="stdout-piped-alone",
    ),
    pytest.param(
        WRITES_AND_EXITS_3,
        {"capture_output": True, "text": True, "check": True},
        id="check-raises",
    ),
    pytest.param(
        [PY, "-c", "pass"], {"capture_output": True, "check": True}, id="check-clean"
    ),
    pytest.param(
        ECHOES_STDIN,
        {"input": "hello\n", "capture_output": True, "text": True},
        id="input-text",
    ),
    pytest.param(
        ECHOES_STDIN, {"input": b"hi", "capture_output": True}, id="input-bytes"
    ),
    pytest.param(
        ECHOES_STDIN,
        {"input": "x", "stdin": subprocess.DEVNULL},
        id="input-and-stdin",
    ),
    pytest.param(
        ECHOES_STDIN,
        {"input": "x", "stdin": None, "capture_output": True, "text": True},
        id="input-and-stdin-none",
    ),
    pytest.param(
        WRITES_AND_EXITS_3,
        {"capture_output": True, "stdout": subprocess.PIPE},
        id="capture-and-stdout",
    ),
    pytest.param(
        WRITES_AND_EXITS_3,
        {"capture_output": True, "stderr": subprocess.PIPE},
        id="capture-and-stderr",
    ),
    pytest.param(
        WRITES_AND_EXITS_3,
        {"capture_output": True, "text": True, "stdout": None},
        id="capture-and-stdout-none",
    ),
    pytest.param(
        _INVALID_UTF8,
        {"capture_output": True, "encoding": "utf-8", "errors": "replace"},
        id="undecodable-replaced",
    ),
    pytest.param(
        _PRINTS_ITS_VARIABLE,
        {"capture_output": True, "text": True, "env": _ONE_VARIABLE},
        id="env",
    ),
    pytest.param(
        PARTIAL_THEN_SLEEPS,
        {"capture_output": True, "text": True, "timeout": 2.0},
        id="timeout",
    ),
]


@pytest.mark.integration
@pytest.mark.parametrize("args, kwargs", DIFFERENTIAL)
def test_the_plain_runner_answers_as_subprocess_run(args, kwargs):
    expected = _outcome(subprocess.run, args, **kwargs)

    assert _outcome(_plain(), args, **kwargs) == expected


@pytest.mark.integration
def test_the_plain_runner_answers_as_subprocess_run_in_a_cwd(tmp_path):
    prints_cwd = [PY, "-c", "import os, sys; sys.stdout.write(os.getcwd())"]
    kwargs = {"capture_output": True, "text": True, "cwd": str(tmp_path)}

    assert _outcome(_plain(), prints_cwd, **kwargs) == _outcome(
        subprocess.run, prints_cwd, **kwargs
    )
