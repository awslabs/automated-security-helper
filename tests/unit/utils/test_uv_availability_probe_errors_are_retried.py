# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``is_uv_available`` memoizes answers; costly failures wait out a window.

The probe runs ``uv --version`` once and caches the answer on the runner. A
long-lived process (the MCP server) keeps one global runner, so a cache
entry written for a failure that is not uv's own answer -- a timeout, a
child killed by a signal, a transient OS error -- would mark uv unavailable
for the life of the process while uv works fine. So only uv's definite
answers are memoized for the process: the probe exited 0 (present), or the
executable is not there to run (absent).

Only the failures whose retry is expensive take the retry window: a timed
out probe (retrying costs the probe timeout again) and one killed by a
signal (an OOM kill or a stop aimed at its group tends to repeat). Every
cheap failure -- a transient OS error from the spawn, a completed exit
that is not uv's answer (75 means "try again"; a sandbox wrapper's own
exit is not uv's) -- answers False for that call only and is probed again
on the next one, so one EAGAIN during a parallel spawn burst does not
answer "unavailable" for a minute. A window answer logs a warning naming
the window, so it does not read as "uv is not installed", and concurrent
callers share one probe behind a lock instead of each starting their own.
A sandbox scope's refusal is the scope's answer, not uv's: it touches
neither the cache nor the window.

Both answers are keyed to what was asked. The memo and the window belong
to the executable that was probed: the getter re-resolves uv on every
call, so a uv that appears after a miss (or disappears after a hit) is a
different question and is probed, never answered from the other
executable's memory. The window is kept per active sandbox scope: the
probe runs inside the scanner's scope, so a wrapper that hangs or is
killed is that scope's weather, and must not answer False for a caller
probing outside it.

The window cells rewind ``_uv_probe_retry_windows`` instead of waiting it
out; the window-length cell moves the module's clock instead, so the
length itself is measured.
"""

import subprocess
import sys
import time as real_time
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.core.cancellation import (
    CancelEvent,
    ScanCancelled,
    cancel_scope,
)
from automated_security_helper.utils import subprocess_utils, uv_tool_runner
from automated_security_helper.utils.sandbox import scope as sandbox_scope
from automated_security_helper.utils.sandbox.backends import SpawnPlan


def _counting(monkeypatch, outcomes):
    """spawn_run stand-in: one scripted outcome per call, the last repeated."""
    calls = []

    def _spawn_run(command, **kwargs):
        calls.append(list(command))
        outcome = outcomes[min(len(calls), len(outcomes)) - 1]
        if isinstance(outcome, BaseException):
            raise outcome
        return subprocess.CompletedProcess(command, outcome, "uv 0.0.0", "")

    monkeypatch.setattr(uv_tool_runner, "spawn_run", _spawn_run)
    return calls


def _rewind(runner) -> None:
    """Make every open retry window read as already passed (monotonic time
    is >= 0), keeping each window's remembered failure beside it."""
    runner._uv_probe_retry_windows = {
        key: (0.0, window[1]) for key, window in runner._uv_probe_retry_windows.items()
    }


@pytest.mark.unit
def test_a_timed_out_probe_waits_out_the_retry_window(monkeypatch):
    """A hung uv is probed once per window, not once per call, and a
    recovered uv is noticed once the window passes."""
    calls = _counting(
        monkeypatch, [subprocess.TimeoutExpired(["uv", "--version"], 10), 0]
    )
    runner = uv_tool_runner.UVToolRunner(uv_executable="uv")

    assert runner.is_uv_available() is False
    assert runner.is_uv_available() is False
    assert len(calls) == 1, (
        "a second probe inside the window pays the full probe timeout "
        "on every call while uv hangs"
    )

    _rewind(runner)
    assert runner.is_uv_available() is True
    assert len(calls) == 2, calls


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(
            BlockingIOError(11, "Resource temporarily unavailable"), id="eagain"
        ),
        pytest.param(InterruptedError(4, "Interrupted system call"), id="eintr"),
        pytest.param(PermissionError(13, "Permission denied"), id="permission"),
        pytest.param(OSError(8, "Exec format error"), id="enoexec"),
    ],
)
@pytest.mark.unit
def test_a_transient_os_error_is_probed_again_next_call(monkeypatch, error):
    """An OS error that is not absence answers False for this call only.
    A failed spawn costs microseconds to retry, so it takes no window: one
    EAGAIN while scanners spawn in parallel must not answer "unavailable"
    to every uv-backed scanner for the window's length."""
    calls = _counting(monkeypatch, [error, 0])
    runner = uv_tool_runner.UVToolRunner(uv_executable="uv")

    assert runner.is_uv_available() is False
    assert runner.is_uv_available() is True
    assert len(calls) == 2, calls


@pytest.mark.unit
def test_a_probe_killed_by_a_signal_is_probed_again_after_the_window(monkeypatch):
    """A negative returncode is the signal's, not uv's answer: never
    memoized for the process, answered from the window instead."""
    calls = _counting(monkeypatch, [-9, 0])
    runner = uv_tool_runner.UVToolRunner(uv_executable="uv")

    assert runner.is_uv_available() is False
    assert runner.is_uv_available() is False
    assert len(calls) == 1, calls

    _rewind(runner)
    assert runner.is_uv_available() is True, (
        "the signal-killed probe was memoized as absent for the life of the process"
    )
    assert len(calls) == 2, calls


class _Collector:
    """Collects the ash logger's WARNINGs: ASH_LOGGER sets propagate=False,
    so caplog never sees its records; attach a handler directly, as the
    converter log tests do."""

    def __init__(self):
        import logging

        self.records: list = []
        collector = self

        class _Handler(logging.Handler):
            def emit(self, record):
                collector.records.append(record)

        self._handler = _Handler(level=logging.WARNING)
        self._logger = logging.getLogger("ash")

    def __enter__(self):
        self._logger.addHandler(self._handler)
        return self

    def __exit__(self, *exc):
        self._logger.removeHandler(self._handler)

    def window_warnings(self):
        """Only the window-ANSWER warnings: the failing probe's own warning
        also mentions the window, so the filter takes the answer message's
        distinctive opening."""
        import logging

        return [
            r.getMessage()
            for r in self.records
            if r.levelno == logging.WARNING
            and "answered False from the retry window" in r.getMessage()
        ]


@pytest.mark.unit
def test_an_answer_from_the_window_names_itself(monkeypatch):
    """Inside the window the refusal is not silent: without a line saying
    the answer comes from the window after a failed probe, "UV is not
    available" reads as "uv is not installed"."""
    calls = _counting(
        monkeypatch, [subprocess.TimeoutExpired(["uv", "--version"], 10), 0]
    )
    runner = uv_tool_runner.UVToolRunner(uv_executable="uv")
    assert runner.is_uv_available() is False

    with _Collector() as warned:
        assert runner.is_uv_available() is False
    assert len(calls) == 1, calls
    assert warned.window_warnings(), "the window's False was silent"


@pytest.mark.unit
def test_the_window_warns_once_not_on_every_answer(monkeypatch, clock):
    """One hung uv is one line, not a line per call: every uv-backed
    scanner asks is_uv_available, so a per-answer warning prints dozens of
    identical lines across a parallel scan. The window warns on its first
    answer; a window re-armed by the next failed probe warns again."""
    calls = _counting(
        monkeypatch,
        [
            subprocess.TimeoutExpired(["uv", "--version"], 10),
            subprocess.TimeoutExpired(["uv", "--version"], 10),
            0,
        ],
    )
    runner = uv_tool_runner.UVToolRunner(uv_executable="uv")
    with _Collector() as warned:
        assert runner.is_uv_available() is False  # probe 1: arms the window
        assert runner.is_uv_available() is False  # first answer: warns
        assert runner.is_uv_available() is False  # second answer: silent
        assert len(warned.window_warnings()) == 1, warned.records
        clock.advance(61.0)
        assert runner.is_uv_available() is False  # probe 2: re-arms
        assert runner.is_uv_available() is False  # the new window warns once
        assert len(warned.window_warnings()) == 2, warned.records
    assert len(calls) == 2, calls


@pytest.mark.unit
def test_concurrent_callers_wait_for_one_probe(monkeypatch):
    """Two threads probing at once run ONE uv --version: the second waits
    for the first's answer instead of starting its own probe. Without the
    lock, every thread arriving while uv hangs starts its own hung probe,
    and each pays the full probe timeout."""
    import threading

    both_probes_arrived = threading.Barrier(2)
    calls = []

    def _spawn_run(command, **kwargs):
        calls.append(list(command))
        try:
            # Give a concurrent second probe (the defect) time to arrive.
            # With the probe lock no other thread can get here, and this
            # wait ends at its timeout.
            both_probes_arrived.wait(2)
        except threading.BrokenBarrierError:
            pass
        return subprocess.CompletedProcess(command, 0, "uv 0.0.0", "")

    monkeypatch.setattr(uv_tool_runner, "spawn_run", _spawn_run)
    runner = uv_tool_runner.UVToolRunner(uv_executable="uv")
    answers = []
    threads = [
        threading.Thread(target=lambda: answers.append(runner.is_uv_available()))
        for _ in range(2)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert (answers, len(calls)) == ([True, True], 1), calls


@pytest.mark.unit
def test_a_probe_error_that_is_no_os_error_is_retried_next_call(monkeypatch):
    """An unforeseen error outside the named classes keeps the old shape:
    False for this call, probed again on the next one."""
    calls = _counting(monkeypatch, [MemoryError(), 0])
    runner = uv_tool_runner.UVToolRunner(uv_executable="uv")

    assert runner.is_uv_available() is False
    assert runner.is_uv_available() is True
    assert len(calls) == 2, calls


@pytest.mark.unit
def test_a_cancel_propagates_and_is_not_memoized(monkeypatch):
    # Constructed with its message: ScanCancelled requires one wherever the
    # could_not_stop records exist, and the message form constructs on both
    # sides of that change.
    calls = _counting(
        monkeypatch, [ScanCancelled("the scan was cancelled while uv was running"), 0]
    )
    runner = uv_tool_runner.UVToolRunner(uv_executable="uv")

    with pytest.raises(ScanCancelled):
        runner.is_uv_available()
    assert runner.is_uv_available() is True
    assert len(calls) == 2, calls


@pytest.mark.unit
def test_a_missing_uv_executable_is_memoized_as_absent(monkeypatch):
    """No executable is a definite answer: cached, not re-probed."""
    calls = []

    def _spawn_run(command, **kwargs):
        calls.append(list(command))
        raise FileNotFoundError(command[0])

    monkeypatch.setattr(uv_tool_runner, "spawn_run", _spawn_run)
    runner = uv_tool_runner.UVToolRunner(uv_executable="uv")

    assert runner.is_uv_available() is False
    assert runner.is_uv_available() is False
    assert len(calls) == 1, calls


@pytest.mark.unit
def test_a_probe_that_answered_present_is_memoized(monkeypatch):
    """Exit 0 is uv's definite answer: one probe, cached for the process."""
    calls = _counting(monkeypatch, [0])
    runner = uv_tool_runner.UVToolRunner(uv_executable="uv")

    assert runner.is_uv_available() is True
    assert runner.is_uv_available() is True
    assert len(calls) == 1, calls


@pytest.mark.unit
def test_a_completed_nonzero_exit_is_probed_again_next_call(monkeypatch):
    """A completed nonzero exit is not memoized and takes no window: 75
    means "try again", and a sandbox wrapper's own exit code is not uv's
    answer. Retrying a completed probe costs microseconds, so a working uv
    is noticed on the very next call."""
    calls = _counting(monkeypatch, [75, 0])
    runner = uv_tool_runner.UVToolRunner(uv_executable="uv")

    assert runner.is_uv_available() is False
    assert runner.is_uv_available() is True
    assert len(calls) == 2, calls


# End to end through the real spawn_run, with stand-in executables (never uv).

pytestmark_posix = pytest.mark.skipif(sys.platform == "win32", reason="POSIX stand-ins")


def _script(tmp_path, name: str, body: str) -> str:
    path = tmp_path / name
    path.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


@pytestmark_posix
@pytest.mark.parametrize("signal_name", ["KILL", "TERM", "SEGV"])
@pytest.mark.integration
def test_end_to_end_a_probe_killed_by_a_signal_is_probed_again(
    tmp_path, clock, attempts, signal_name
):
    """The stand-in dies by a signal before it answers (an OOM kill, a stop
    sent to its group). That is no answer from uv, so once the window
    passes the probe runs again and a working uv is noticed. One
    executable, recovering by a rewrite in place: swapping executables
    would reset the window and leave the expiry itself untested."""
    flaky = tmp_path / "zz-recovers"
    flaky.write_text(f"#!/bin/sh\nkill -{signal_name} $$\n", encoding="utf-8")
    flaky.chmod(0o755)
    runner = uv_tool_runner.UVToolRunner(uv_executable=str(flaky))
    if runner.is_uv_available() is not False:
        raise RuntimeError("the dying stand-in answered available")
    flaky.write_text("#!/bin/sh\necho 'uv 0.0.0'\n", encoding="utf-8")
    inside = runner.is_uv_available()
    clock.advance(61.0)
    after = runner.is_uv_available()
    assert (inside, after, len(attempts.log)) == (False, True, 2), attempts.log


@pytestmark_posix
@pytest.mark.integration
def test_end_to_end_a_real_timeout_is_probed_again_after_the_window(
    tmp_path, clock, attempts
):
    """Same shape through a real hang: the stopped stand-in times out, the
    window answers until it passes, and the recovered (rewritten in place)
    executable is probed again."""
    attempts.timeout = 0.5
    flaky = tmp_path / "zz-recovers"
    flaky.write_text("#!/bin/sh\nkill -STOP $$\n", encoding="utf-8")
    flaky.chmod(0o755)
    runner = uv_tool_runner.UVToolRunner(uv_executable=str(flaky))
    assert runner.is_uv_available() is False
    flaky.write_text("#!/bin/sh\necho 'uv 0.0.0'\n", encoding="utf-8")
    inside = runner.is_uv_available()
    clock.advance(61.0)
    after = runner.is_uv_available()
    assert (inside, after, len(attempts.log)) == (False, True, 2), attempts.log


class _Clock:
    """The runner module's ``time``: monotonic moved by advance(), the rest real."""

    def __init__(self):
        self.offset = 0.0

    def monotonic(self):
        return real_time.monotonic() + self.offset

    def advance(self, seconds):
        self.offset += seconds

    def __getattr__(self, name):
        return getattr(real_time, name)


@pytest.fixture
def clock(monkeypatch):
    moved = _Clock()
    monkeypatch.setattr(uv_tool_runner, "time", moved)
    return moved


class _Attempts:
    """Every probe attempt through the real spawn_run, with its outcome, and
    an optional shorter probe timeout for cells that force a real hang."""

    def __init__(self):
        self.log = []
        self.timeout = None


@pytest.fixture
def attempts(monkeypatch):
    seen = _Attempts()
    real = uv_tool_runner.spawn_run

    def _spawn_run(command, **kwargs):
        entry = {"argv": list(command)}
        seen.log.append(entry)
        if seen.timeout is not None:
            kwargs["timeout"] = seen.timeout
        try:
            result = real(command, **kwargs)
        except BaseException as exc:
            entry["raised"] = type(exc).__name__
            raise
        entry["rc"] = result.returncode
        return result

    monkeypatch.setattr(uv_tool_runner, "spawn_run", _spawn_run)
    return seen


@pytestmark_posix
@pytest.mark.integration
def test_the_retry_window_is_sixty_seconds_measured_by_the_clock(
    tmp_path, clock, attempts
):
    """The window's length itself: 59 s after a no-answer failure the probe
    still waits (no new attempt); 61 s after it, the probe runs again and a
    working uv is noticed. Rewinding the deadline cannot measure this. The
    stand-in recovers by rewriting the one script in place: assigning a new
    executable would reset the window and make the expiry vacuous."""
    flaky = tmp_path / "zz-recovers"
    flaky.write_text("#!/bin/sh\nkill -KILL $$\n", encoding="utf-8")
    flaky.chmod(0o755)
    runner = uv_tool_runner.UVToolRunner(uv_executable=str(flaky))
    first = runner.is_uv_available()
    if first is not False or len(attempts.log) != 1:
        raise RuntimeError(("premise: one failed probe", first, attempts.log))
    clock.advance(59.0)
    inside = runner.is_uv_available()
    inside_attempts = len(attempts.log)
    flaky.write_text("#!/bin/sh\necho 'uv 0.0.0'\n", encoding="utf-8")
    clock.advance(2.0)
    after = runner.is_uv_available()
    assert (inside, inside_attempts, after, len(attempts.log)) == (
        False,
        1,
        True,
        2,
    ), attempts.log


@pytestmark_posix
@pytest.mark.integration
def test_an_exit_code_meaning_try_again_is_probed_next_call(tmp_path, attempts):
    """End to end: a stand-in that exits 75 (EX_TEMPFAIL) is not memoized
    and takes no window; the very next call probes the SAME executable
    again (rewritten in place, so no swap or setter is involved)."""
    flaky = tmp_path / "zz-recovers"
    flaky.write_text("#!/bin/sh\nexit 75\n", encoding="utf-8")
    flaky.chmod(0o755)
    runner = uv_tool_runner.UVToolRunner(uv_executable=str(flaky))
    first = runner.is_uv_available()
    if first is not False or attempts.log[0].get("rc") != 75:
        raise RuntimeError(("premise: exit 75", first, attempts.log))
    flaky.write_text("#!/bin/sh\necho 'uv 0.0.0'\n", encoding="utf-8")
    assert runner.is_uv_available() is True, attempts.log


@pytestmark_posix
@pytest.mark.integration
def test_a_refusal_of_one_scope_does_not_answer_for_a_call_outside_it(
    tmp_path, clock, attempts
):
    """A scanner that cannot be sandboxed probes under a RefusingScope
    (plugin_probe_scope), so its spawn raises SandboxUnavailable, an OSError,
    before anything starts. That says nothing about uv; a call outside that
    scope (another scan of the same server process) must still probe."""
    answers = _script(tmp_path, "zz-answers", "echo 'uv 0.0.0'")
    runner = uv_tool_runner.UVToolRunner(uv_executable=answers)
    token = sandbox_scope._ACTIVE.set(
        sandbox_scope.RefusingScope("zz-scanner", "no sandbox backend")
    )
    try:
        inside = runner.is_uv_available()
    finally:
        sandbox_scope._ACTIVE.reset(token)
    if inside is not False or attempts.log[0].get("raised") != "SandboxUnavailable":
        raise RuntimeError(
            ("premise: the refusing scope did not refuse", inside, attempts.log)
        )
    outside = runner.is_uv_available()
    assert (outside, len(attempts.log)) == (True, 2), attempts.log


@pytestmark_posix
@pytest.mark.integration
def test_a_sandbox_wrappers_failure_is_not_uvs_answer(tmp_path, monkeypatch, attempts):
    """A backend wrapper that runs and fails before the tool starts exits
    non-zero itself. Outside the scope, the very next call probes uv."""
    wrapper = _script(tmp_path, "zz-wrapper", "exit 1")
    answers = _script(tmp_path, "zz-answers", "echo 'uv 0.0.0'")
    sandboxed = {"on": True}
    real_prepare = subprocess_utils._prepare_spawn

    def prepare(args, env, cwd, shell):
        if sandboxed["on"]:
            return SpawnPlan(argv=[wrapper, *args], env=dict(env or {}))
        return real_prepare(args, env, cwd, shell)

    monkeypatch.setattr(subprocess_utils, "_prepare_spawn", prepare)
    runner = uv_tool_runner.UVToolRunner(uv_executable=answers)
    first = runner.is_uv_available()
    if first is not False or attempts.log[0].get("rc") != 1:
        raise RuntimeError(("premise: the wrapper's exit", first, attempts.log))
    sandboxed["on"] = False
    assert runner.is_uv_available() is True, attempts.log


def _zz_sandbox_scope(tmp_path):
    """A SandboxScope whose only part these cells read is the backend's
    name: _prepare_spawn is replaced wholesale, so the policy fields are
    never consulted."""
    return sandbox_scope.SandboxScope(
        backend=SimpleNamespace(name="zz-backend"),
        scanner_name="zz-scanner",
        requirements=None,
        source_dir=Path(tmp_path),
        output_dir=Path(tmp_path),
        results_dir=Path(tmp_path),
        scan_target=None,
        offline=False,
    )


@pytestmark_posix
@pytest.mark.parametrize(
    "body,premise_key,premise_value",
    [
        pytest.param("kill -KILL $$", "rc", -9, id="wrapper-killed"),
        pytest.param("exec sleep 30", "raised", "TimeoutExpired", id="wrapper-hung"),
    ],
)
@pytest.mark.integration
def test_one_scopes_wrapper_window_does_not_answer_outside_the_scope(
    tmp_path, monkeypatch, attempts, body, premise_key, premise_value
):
    """The probe runs inside the scanner's sandbox scope, so a wrapper that
    hangs or is killed opens the retry window. That window is the scope's
    weather, not uv's: inside the same scope it answers (one probe timeout
    per window, not per call), and a caller outside the scope right after
    probes instead of reading False for the window's length."""
    answers = _script(tmp_path, "zz-answers", "echo 'uv 0.0.0'")
    wrapper = _script(tmp_path, "zz-wrapper", body)
    attempts.timeout = 0.5
    state = {"on": True}
    real_prepare = subprocess_utils._prepare_spawn

    def prepare(args, env, cwd, shell):
        if state["on"]:
            return SpawnPlan(argv=[wrapper, *args], env=dict(env or {}))
        return real_prepare(args, env, cwd, shell)

    monkeypatch.setattr(subprocess_utils, "_prepare_spawn", prepare)
    runner = uv_tool_runner.UVToolRunner(uv_executable=answers)
    scope = _zz_sandbox_scope(tmp_path)
    token = sandbox_scope._ACTIVE.set(scope)
    try:
        inside = runner.is_uv_available()
        inside_again = runner.is_uv_available()
    finally:
        sandbox_scope._ACTIVE.reset(token)
    if inside is not False or attempts.log[0].get(premise_key) != premise_value:
        raise RuntimeError(("premise: the wrapper's failure", inside, attempts.log))
    assert (inside_again, len(attempts.log)) == (False, 1), (
        "the window stopped answering inside its own scope",
        attempts.log,
    )
    state["on"] = False
    outside = runner.is_uv_available()
    assert (outside, len(attempts.log)) == (True, 2), attempts.log


# The failing call names its failure ------------------------------------------


def _runner_warnings(collector):
    """The collected WARNINGs that uv_tool_runner.py itself logged."""
    return [
        r.getMessage()
        for r in collector.records
        if r.pathname.endswith("uv_tool_runner.py")
    ]


@pytestmark_posix
@pytest.mark.parametrize(
    "body, premise_key, premise_value, names",
    [
        pytest.param(
            "exec sleep 30",
            "raised",
            "TimeoutExpired",
            "timed out after 0.5 seconds",
            id="timeout",
        ),
        pytest.param("kill -KILL $$", "rc", -9, "signal SIGKILL", id="signal-kill"),
        pytest.param("exit 75", "rc", 75, "exited 75", id="exit-75"),
    ],
)
@pytest.mark.integration
def test_a_failed_probe_names_its_cause_on_the_failing_call(
    tmp_path, attempts, body, premise_key, premise_value, names
):
    """The call whose probe failed says what happened, in its own warning
    and in the failure ``uv_availability`` returns: a bare False surfaces
    downstream as "uv is not available", which reads as "uv is not installed"
    when the real cause was a timeout, a signal, or an exit that is not uv's
    answer."""
    exe = _script(tmp_path, "zz-fails", body)
    attempts.timeout = 0.5
    runner = uv_tool_runner.UVToolRunner(uv_executable=exe)

    with _Collector() as warned:
        answer, failure = runner.uv_availability()

    if attempts.log[0].get(premise_key) != premise_value:
        raise RuntimeError(("premise: the forced failure", attempts.log))
    assert answer is False
    named = [line for line in _runner_warnings(warned) if names in line]
    assert named, (names, [r.getMessage() for r in warned.records])
    assert names in (failure or ""), failure


@pytestmark_posix
@pytest.mark.unit
def test_a_refused_spawns_warning_names_the_refusal(tmp_path, attempts):
    """A sandbox scope's refusal is named as the spawn failure it is, so the
    scanner's "uv is not available" can say the scope refused, not that uv
    is missing."""
    answers = _script(tmp_path, "zz-answers", "echo 'uv 0.0.0'")
    runner = uv_tool_runner.UVToolRunner(uv_executable=answers)
    token = sandbox_scope._ACTIVE.set(
        sandbox_scope.RefusingScope("zz-scanner", "no sandbox backend")
    )
    try:
        with _Collector() as warned:
            answer, failure = runner.uv_availability()
    finally:
        sandbox_scope._ACTIVE.reset(token)

    if attempts.log[0].get("raised") != "SandboxUnavailable":
        raise RuntimeError(("premise: the refusal", attempts.log))
    assert answer is False
    assert "SandboxUnavailable" in (failure or ""), failure
    assert any("SandboxUnavailable" in line for line in _runner_warnings(warned)), [
        r.getMessage() for r in warned.records
    ]


@pytest.mark.unit
def test_a_transient_os_errors_warning_names_the_error_and_a_success_clears_it(
    monkeypatch,
):
    """The OS-error arm names the error class, and the next successful probe
    clears the remembered failure, so a later "not available" cannot carry a
    stale cause."""
    calls = _counting(
        monkeypatch, [BlockingIOError(11, "Resource temporarily unavailable"), 0]
    )
    runner = uv_tool_runner.UVToolRunner(uv_executable="uv")

    with _Collector() as warned:
        answer, failure = runner.uv_availability()
    assert answer is False
    assert "BlockingIOError" in (failure or ""), failure
    assert any("BlockingIOError" in line for line in _runner_warnings(warned))

    answer, failure = runner.uv_availability()
    assert answer is True, calls
    assert failure is None, failure


@pytest.mark.unit
def test_a_missing_uv_adds_no_failure_detail(monkeypatch):
    """The must-not-flag control: an absent executable is uv genuinely not
    available, so the probe stays silent and remembers no failure -- the
    plain sentence downstream is the whole truth."""
    _counting(monkeypatch, [FileNotFoundError(2, "No such file or directory")])
    runner = uv_tool_runner.UVToolRunner(uv_executable="uv")

    with _Collector() as warned:
        answer, failure = runner.uv_availability()
    assert answer is False
    assert failure is None, failure
    assert not _runner_warnings(warned), [r.getMessage() for r in warned.records]


@pytest.mark.unit
def test_the_window_warning_carries_the_remembered_failure(monkeypatch):
    """A caller answered from the window sees the failing probe's cause in
    the window's own warning, not only the caller whose probe failed."""
    _counting(monkeypatch, [subprocess.TimeoutExpired(["uv", "--version"], 10), 0])
    runner = uv_tool_runner.UVToolRunner(uv_executable="uv")
    assert runner.is_uv_available() is False

    with _Collector() as warned:
        assert runner.is_uv_available() is False
    window_lines = warned.window_warnings()
    assert window_lines, "the window's False was silent"
    # The REMEMBERED failure, not the generic sentence (which also says
    # "timed out"): the specific text proves the carry.
    assert (
        "The failing probe: the probe timed out after 10 seconds" in (window_lines[0])
    ), window_lines


# Waiting behind another caller's probe --------------------------------------


def _parallel(count, target):
    """Run target() on *count* threads released together; [(answer or
    exception name, seconds)] per thread."""
    import threading

    start = threading.Barrier(count)
    results = [None] * count

    def call(index):
        start.wait(10)
        t0 = real_time.monotonic()
        try:
            got = target()
        except BaseException as exc:  # noqa: BLE001 -- recorded, asserted below
            got = type(exc).__name__
        results[index] = (got, real_time.monotonic() - t0)

    threads = [threading.Thread(target=call, args=(i,)) for i in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(90)
    return results


@pytestmark_posix
@pytest.mark.integration
def test_threads_arriving_during_a_hung_probe_share_its_one_timeout(tmp_path, attempts):
    """Four callers behind one hung uv cost one probe timeout: the prober
    pays it, the waiters answer from the window it opened (which warns
    once), and nobody starts a second probe."""
    hangs = _script(tmp_path, "zz-hangs", "exec sleep 30")
    attempts.timeout = 1.0
    runner = uv_tool_runner.UVToolRunner(uv_executable=hangs)
    with _Collector() as warned:
        results = _parallel(4, runner.is_uv_available)
    answers = [r[0] for r in results]
    longest = max(r[1] for r in results)
    assert attempts.log and attempts.log[0].get("raised") == "TimeoutExpired", (
        attempts.log
    )
    assert (answers, len(attempts.log), len(warned.window_warnings())) == (
        [False] * 4,
        1,
        1,
    ), (results, warned.records)
    assert longest < 5.0, results


@pytestmark_posix
@pytest.mark.integration
def test_waiters_behind_a_slow_unanswered_probe_pay_for_one_probe(tmp_path, attempts):
    """A probe whose outcome is neither memoized nor windowed (a wrapper
    that fails slowly) must still answer its waiters: without the probe
    generation, each waiter re-probes in turn under the lock, so the k-th
    caller waits k probes."""
    slow_fail = _script(tmp_path, "zz-slow-fail", "sleep 1\nexit 1")
    runner = uv_tool_runner.UVToolRunner(uv_executable=slow_fail)
    results = _parallel(4, runner.is_uv_available)
    assert [r[0] for r in results] == [False] * 4, results
    longest = max(r[1] for r in results)
    assert longest < 2.5, (results, len(attempts.log))
    assert len(attempts.log) == 1, attempts.log


@pytestmark_posix
@pytest.mark.integration
def test_a_waiters_own_scope_does_not_take_another_scopes_answer(
    tmp_path, monkeypatch, attempts
):
    """The generation answer is shared only between callers asking the same
    question: a waiter under a different sandbox scope probes itself, since
    the prober's per-call failure may be that scope's weather."""
    import threading

    answers_exe = _script(tmp_path, "zz-answers", "echo 'uv 0.0.0'")
    wrapper = _script(tmp_path, "zz-wrapper", "sleep 1\nexit 1")
    in_probe = threading.Event()
    state = {"wrap": True}
    real_prepare = subprocess_utils._prepare_spawn

    def prepare(args, env, cwd, shell):
        if state["wrap"]:
            in_probe.set()
            return SpawnPlan(argv=[wrapper, *args], env=dict(env or {}))
        return real_prepare(args, env, cwd, shell)

    monkeypatch.setattr(subprocess_utils, "_prepare_spawn", prepare)
    runner = uv_tool_runner.UVToolRunner(uv_executable=answers_exe)
    scope = _zz_sandbox_scope(tmp_path)

    def scoped_probe():
        token = sandbox_scope._ACTIVE.set(scope)
        try:
            return runner.is_uv_available()
        finally:
            sandbox_scope._ACTIVE.reset(token)

    prober = threading.Thread(target=scoped_probe)
    prober.start()
    assert in_probe.wait(5), "premise: the scoped probe started"
    state["wrap"] = False
    # Arrives while the scoped probe holds the lock; outside any scope.
    outside = runner.is_uv_available()
    prober.join(10)
    assert outside is True, attempts.log
    assert len(attempts.log) == 2, attempts.log


@pytest.mark.integration
def test_a_cancel_reaches_a_thread_waiting_on_another_callers_probe(tmp_path, attempts):
    """A scan cancelled while its thread is parked on the probe lock stops
    within the poll interval and raises ScanCancelled; it does not wait out
    the other caller's probe and answer False from the window."""
    import threading

    hangs = _script(tmp_path, "zz-hangs", "exec sleep 30")
    attempts.timeout = 3.0
    runner = uv_tool_runner.UVToolRunner(uv_executable=hangs)
    other = threading.Thread(target=runner.is_uv_available)
    other.start()
    assert attempts.log or _wait_for(lambda: attempts.log, 5), (
        "premise: the other caller's probe started"
    )
    event = CancelEvent()
    result = {}

    def scanned():
        with cancel_scope(event):
            try:
                result["answer"] = runner.is_uv_available()
            except ScanCancelled:
                result["answer"] = "ScanCancelled"
            result["t_end"] = real_time.monotonic()

    waiting = threading.Thread(target=scanned)
    waiting.start()
    waiting.join(0.3)
    cancelled_at = real_time.monotonic()
    event.set()
    waiting.join(15)
    other.join(15)
    lag = result["t_end"] - cancelled_at
    assert (result["answer"], lag < 1.0) == ("ScanCancelled", True), (
        result,
        lag,
        attempts.log,
    )


def _wait_for(condition, seconds):
    deadline = real_time.monotonic() + seconds
    while real_time.monotonic() < deadline:
        if condition():
            return True
        real_time.sleep(0.02)
    return False


@pytest.mark.unit
def test_a_new_executable_waits_for_the_in_flight_probe_of_the_old(monkeypatch):
    """Forced interleaving: the old executable's probe is in flight when the
    setter runs. Its answer (present) must not land after the reset; the new
    executable (missing) is probed and answers absent."""
    import threading

    gate = threading.Event()
    entered = threading.Event()
    calls = []

    def _spawn_run(command, **kwargs):
        calls.append(command[0])
        if command[0] == "zz-old":
            entered.set()
            gate.wait(10)
            return subprocess.CompletedProcess(command, 0, "uv 0.0.0", "")
        raise FileNotFoundError(command[0])

    monkeypatch.setattr(uv_tool_runner, "spawn_run", _spawn_run)
    runner = uv_tool_runner.UVToolRunner(uv_executable="zz-old")
    answers = []
    probe = threading.Thread(target=lambda: answers.append(runner.is_uv_available()))
    probe.start()
    assert entered.wait(5), "premise: the old probe started"
    setter = threading.Thread(target=lambda: setattr(runner, "uv_executable", "zz-new"))
    setter.start()
    setter.join(0.5)
    blocked = setter.is_alive()
    gate.set()
    probe.join(5)
    setter.join(5)
    after = runner.is_uv_available()
    assert (answers, blocked, after, calls) == (
        [True],
        True,
        False,
        ["zz-old", "zz-new"],
    )
