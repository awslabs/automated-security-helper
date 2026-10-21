# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The failure text a caller reads belongs to its own call's probe.

The failure ``uv_availability`` returns beside its answer is the detail a
caller quotes when uv did not run ("uv is not available (<failure>)"), and
the retry window's warning repeats it. One runner serves every scope and
thread, so a runner-wide slot would hold whatever probe failed LAST,
anywhere: a window answer would then name another scope's refusal instead of
the timeout that opened the window, and a caller that reads the slot after
its call could quote a failure that happened on another thread in between.
The window must remember its own opening failure beside its deadline, and
each call must be answered with its own probe's failure, returned with the
answer so no later read is needed.

The cells: a window answer names the window's own cause after another
scope's probe failed in between; a caller's failure is not rewritten by
another thread's later probe; a waiter that takes a finished probe's shared
answer receives that probe's failure (the control pinning the share's text
travels with its answer); and a call made on a worker thread returns its
failure to the thread that awaits it.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils import subprocess_utils, uv_tool_runner
from automated_security_helper.utils.sandbox import scope as sandbox_scope
from automated_security_helper.utils.sandbox.backends import SpawnPlan

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX stand-ins")


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


class _Collector(logging.Handler):
    """The WARNINGs uv_tool_runner.py logs while the block runs."""

    def __init__(self):
        super().__init__(level=logging.WARNING)
        self.records = []

    def emit(self, record):
        if record.pathname.endswith("uv_tool_runner.py"):
            self.records.append(record.getMessage())

    def __enter__(self):
        from automated_security_helper.utils.log import ASH_LOGGER

        self._logger = ASH_LOGGER
        self._logger.addHandler(self)
        return self

    def __exit__(self, *exc):
        self._logger.removeHandler(self)


def _script(tmp_path, name: str, body: str) -> str:
    path = tmp_path / name
    path.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def _zz_scope(tmp_path):
    """A SandboxScope whose backend only lends its name: the probe under it
    goes through the wrapped prepare, never the policy fields."""
    return sandbox_scope.SandboxScope(
        backend=SimpleNamespace(name="zz-x"),
        scanner_name="zz-scanner",
        requirements=None,
        source_dir=Path(tmp_path),
        output_dir=Path(tmp_path),
        results_dir=Path(tmp_path),
        scan_target=None,
        offline=False,
    )


def test_a_window_answer_names_the_windows_own_cause(tmp_path, monkeypatch, attempts):
    """Scope X's window was opened by a timeout. Another scope's probe then
    fails per call. X's next call answers from X's window and must name the
    timeout, not the other scope's refusal."""
    answers_exe = _script(tmp_path, "zz-answers", "echo 'uv 0.0.0'")
    hung = _script(tmp_path, "zz-hung", "exec sleep 30")
    attempts.timeout = 0.5
    state = {"wrap": True}
    real_prepare = subprocess_utils._prepare_spawn

    def prepare(args, env, cwd, shell):
        if state["wrap"]:
            return SpawnPlan(argv=[hung, *args], env=dict(env or {}))
        return real_prepare(args, env, cwd, shell)

    monkeypatch.setattr(subprocess_utils, "_prepare_spawn", prepare)
    runner = uv_tool_runner.UVToolRunner(uv_executable=answers_exe)
    scope_x = _zz_scope(tmp_path)
    token = sandbox_scope._ACTIVE.set(scope_x)
    try:
        opened = runner.is_uv_available()
    finally:
        sandbox_scope._ACTIVE.reset(token)
    if opened is not False or attempts.log[0].get("raised") != "TimeoutExpired":
        raise RuntimeError(("premise: the window opened on a timeout", attempts.log))
    state["wrap"] = False
    # Another scope's probe fails per call and leaves its own text behind.
    token = sandbox_scope._ACTIVE.set(
        sandbox_scope.RefusingScope("zz-other", "no sandbox backend")
    )
    try:
        refused = runner.is_uv_available()
    finally:
        sandbox_scope._ACTIVE.reset(token)
    if refused is not False or attempts.log[-1].get("raised") != "SandboxUnavailable":
        raise RuntimeError(("premise: the other scope's refusal", attempts.log))
    token = sandbox_scope._ACTIVE.set(scope_x)
    try:
        with _Collector() as warned:
            answered, failure = runner.uv_availability()
    finally:
        sandbox_scope._ACTIVE.reset(token)
    assert answered is False, attempts.log
    window_lines = [r for r in warned.records if "retry window" in r]
    assert window_lines, ("the window answer logged no warning", warned.records)
    # The carrier first: a warning with no remembered text at all would
    # pass the foreign-text assertions below with nothing named.
    assert "timed out" in window_lines[0], window_lines
    assert "zz-other" not in window_lines[0], window_lines
    assert failure is not None and "timed out" in failure, failure
    assert "zz-other" not in failure, (
        "the window answer quoted another scope's refusal",
        failure,
    )


def test_a_callers_failure_is_not_rewritten_by_another_threads_probe(
    tmp_path, attempts
):
    """Thread A's call failed with A's own cause. Thread B's probe then fails
    differently. A must still hold A's, and B must hold B's."""
    flaky = tmp_path / "zz-flaky"
    flaky.write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
    flaky.chmod(0o755)
    runner = uv_tool_runner.UVToolRunner(uv_executable=str(flaky))
    a_called = threading.Event()
    b_done = threading.Event()
    seen = {}

    def caller_a():
        seen["answer"], seen["failure"] = runner.uv_availability()
        a_called.set()
        assert b_done.wait(10), "premise: B's probe ran"

    thread_a = threading.Thread(target=caller_a)
    thread_a.start()
    assert a_called.wait(10), "premise: A's call finished"
    # B's probe, same runner, fails with a different completed exit.
    flaky.write_text("#!/bin/sh\nexit 75\n", encoding="utf-8")
    answer_b, failure_b = runner.uv_availability()
    b_done.set()
    thread_a.join(10)
    if seen.get("answer") is not False or answer_b is not False:
        raise RuntimeError(("premise: both calls failed per call", seen, answer_b))
    # The carrier first: an empty failure would pass the foreign-text check.
    assert seen.get("failure") and "exited 2" in seen["failure"], seen
    assert "exited 75" not in seen["failure"], (
        "A holds the failure B's probe wrote",
        seen,
    )
    assert failure_b and "exited 75" in failure_b, failure_b


def test_a_shared_answers_waiter_reads_the_probes_failure(
    tmp_path, monkeypatch, attempts
):
    """The control: a waiter that takes a finished probe's per-call answer
    (same scope, same executable: both outside any scope here) reads that
    probe's failure beside it."""
    slow_fail = _script(tmp_path, "zz-slow-fail", "sleep 1\nexit 1")
    runner = uv_tool_runner.UVToolRunner(uv_executable=slow_fail)
    in_probe = threading.Event()
    real_spawn = uv_tool_runner.spawn_run

    def noticing_spawn(command, **kwargs):
        in_probe.set()
        return real_spawn(command, **kwargs)

    monkeypatch.setattr(uv_tool_runner, "spawn_run", noticing_spawn)
    prober = threading.Thread(target=runner.uv_availability)
    prober.start()
    assert in_probe.wait(5), "premise: the slow probe started"
    answer, failure = runner.uv_availability()
    prober.join(10)
    assert answer is False, attempts.log
    assert failure is not None and "exited 1" in failure, (
        "the shared answer arrived without its probe's failure",
        failure,
    )


def test_a_check_made_on_a_worker_thread_returns_its_failure(tmp_path, attempts):
    """An async caller checks availability through ``asyncio.to_thread``. The
    probe, and any per-thread state it left, belong to the worker thread, so
    the failure has to come back with the answer to reach the awaiting
    thread."""
    flaky = tmp_path / "zz-flaky"
    flaky.write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
    flaky.chmod(0o755)
    runner = uv_tool_runner.UVToolRunner(uv_executable=str(flaky))

    answer, failure = asyncio.run(asyncio.to_thread(runner.uv_availability))

    assert answer is False, attempts.log
    assert failure is not None and "exited 2" in failure, failure


def test_the_bool_wrapper_probes_once_per_check(tmp_path, attempts):
    """``is_uv_available`` is the tuple function's first element, not a second
    probe: a failing probe is not memoized, so each extra probe the wrapper
    made would show as another attempt."""
    flaky = tmp_path / "zz-flaky"
    flaky.write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
    flaky.chmod(0o755)
    runner = uv_tool_runner.UVToolRunner(uv_executable=str(flaky))

    assert runner.is_uv_available() is False
    assert len(attempts.log) == 1, attempts.log

    assert runner.uv_availability()[0] is False
    assert len(attempts.log) == 2, attempts.log
