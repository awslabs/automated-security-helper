# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A finished probe's per-call answer is shared only within its own scope.

A thread that waited on the probe lock while another caller probed takes
that probe's answer when it asked the same question. The retry window is
deliberately keyed by backend -- a wrapper's hang is that backend's
weather -- but a PER-CALL failure is often one scanner's own: a sandbox
refusal names that scanner's results and output directories. So the
question's identity for sharing is the scope itself (the same object, or
both callers outside any scope) plus the executable, not merely the same
backend: scanner b parked behind scanner a's refused probe must probe its
own call, not report a's refusal as its availability.

The cells park a second caller behind a slow per-call-failing probe and
vary one side of the question: another scanner's scope on the same backend
(must probe its own), the same scope (must share), and another executable
(must probe its own). The last cell pins the cancel pre-check: a cancelled
scope is answered with ScanCancelled even when the memo already holds True.
"""

from __future__ import annotations

import sys
import threading
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

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX stand-ins")


class _Attempts:
    """Every probe attempt through the real spawn_run, with its outcome."""

    def __init__(self):
        self.log = []


@pytest.fixture
def attempts(monkeypatch):
    seen = _Attempts()
    real = uv_tool_runner.spawn_run

    def _spawn_run(command, **kwargs):
        entry = {"argv": list(command)}
        seen.log.append(entry)
        try:
            result = real(command, **kwargs)
        except BaseException as exc:
            entry["raised"] = type(exc).__name__
            raise
        entry["rc"] = result.returncode
        return result

    monkeypatch.setattr(uv_tool_runner, "spawn_run", _spawn_run)
    return seen


def _script(tmp_path, name: str, body: str) -> str:
    path = tmp_path / name
    path.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def _zz_scope(tmp_path, scanner_name: str):
    """A SandboxScope whose only parts these cells read are the backend's
    name and its identity: _prepare_spawn is replaced wholesale, so the
    policy fields are never consulted. Both scopes name ONE backend."""
    return sandbox_scope.SandboxScope(
        backend=SimpleNamespace(name="zz-backend"),
        scanner_name=scanner_name,
        requirements=None,
        source_dir=Path(tmp_path),
        output_dir=Path(tmp_path),
        results_dir=Path(tmp_path),
        scan_target=None,
        offline=False,
    )


def _park_behind_slow_probe(tmp_path, monkeypatch, prober_scope, waiter):
    """Thread a probes under *prober_scope* through a slow per-call-failing
    wrapper (exit 1: neither memoized nor windowed); once that probe is in
    flight the wrapper is turned off and *waiter* runs on this thread.
    Returns the waiter's answer."""
    answers_exe = _script(tmp_path, "zz-answers", "echo 'uv 0.0.0'")
    wrapper = _script(tmp_path, "zz-wrapper", "sleep 1\nexit 1")
    in_probe = threading.Event()
    state = {"wrap": True}

    def prepare(args, env, cwd, shell):
        # Replaced wholesale (never falling back to the real one), because
        # the fake scopes' policy fields must not be consulted on either
        # phase: the prober goes through the slow wrapper, the waiter runs
        # the command as given.
        if state["wrap"]:
            in_probe.set()
            return SpawnPlan(argv=[wrapper, *args], env=dict(env or {}))
        return SpawnPlan(argv=list(args), env=dict(env or {}))

    monkeypatch.setattr(subprocess_utils, "_prepare_spawn", prepare)
    runner = uv_tool_runner.UVToolRunner(uv_executable=answers_exe)

    def scoped_probe():
        token = sandbox_scope._ACTIVE.set(prober_scope)
        try:
            runner.is_uv_available()
        finally:
            sandbox_scope._ACTIVE.reset(token)

    prober = threading.Thread(target=scoped_probe)
    prober.start()
    assert in_probe.wait(5), "premise: the scoped probe started"
    state["wrap"] = False
    answer = waiter(runner)
    prober.join(10)
    return answer


def test_another_scanner_on_the_same_backend_probes_its_own(
    tmp_path, monkeypatch, attempts
):
    """Scanner b's scope shares a's backend but is not a's scope: a's
    per-call failure may be a's own weather (a refusal naming a's
    directories), so b must probe its own call."""
    scope_a = _zz_scope(tmp_path, "zz-a")
    scope_b = _zz_scope(tmp_path, "zz-b")

    def waiter(runner):
        token = sandbox_scope._ACTIVE.set(scope_b)
        try:
            return runner.is_uv_available()
        finally:
            sandbox_scope._ACTIVE.reset(token)

    answer = _park_behind_slow_probe(tmp_path, monkeypatch, scope_a, waiter)
    assert (answer, len(attempts.log)) == (True, 2), (
        "the waiter took the other scanner's per-call answer",
        attempts.log,
    )


def test_the_same_scope_takes_the_finished_probes_answer(
    tmp_path, monkeypatch, attempts
):
    """The control: inside ONE scope the k-th of k waiters still pays for
    one probe, not k -- the share holds where the question is the same."""
    scope_a = _zz_scope(tmp_path, "zz-a")

    def waiter(runner):
        token = sandbox_scope._ACTIVE.set(scope_a)
        try:
            return runner.is_uv_available()
        finally:
            sandbox_scope._ACTIVE.reset(token)

    answer = _park_behind_slow_probe(tmp_path, monkeypatch, scope_a, waiter)
    assert (answer, len(attempts.log)) == (False, 1), attempts.log


def test_a_waiter_resolving_another_uv_probes_its_own(tmp_path, monkeypatch, attempts):
    """The executable half of the question: a waiter whose getter resolved
    a DIFFERENT uv than the finished probe's must probe its own, even
    though the generation moved while it waited."""
    slow_fail = _script(tmp_path, "zz-slow-fail", "sleep 1\nexit 1")
    answers_exe = _script(tmp_path, "zz-answers", "echo 'uv 0.0.0'")
    resolved = {"path": slow_fail}
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: resolved["path"])
    runner = uv_tool_runner.UVToolRunner()
    in_probe = threading.Event()
    real_spawn = uv_tool_runner.spawn_run

    def noticing_spawn(command, **kwargs):
        in_probe.set()
        return real_spawn(command, **kwargs)

    monkeypatch.setattr(uv_tool_runner, "spawn_run", noticing_spawn)
    prober = threading.Thread(target=runner.is_uv_available)
    prober.start()
    assert in_probe.wait(5), "premise: the slow probe started"
    resolved["path"] = answers_exe
    answer = runner.is_uv_available()
    prober.join(10)
    assert (answer, len(attempts.log)) == (True, 2), (
        "the waiter took the other executable's answer",
        attempts.log,
    )


def test_a_cancelled_scope_with_a_memoized_answer_still_raises(tmp_path, attempts):
    """The cancel pre-check runs before the memo is read: a cancelled scan
    gets ScanCancelled, never a memoized True that lets it start work."""
    answers_exe = _script(tmp_path, "zz-answers", "echo 'uv 0.0.0'")
    runner = uv_tool_runner.UVToolRunner(uv_executable=answers_exe)
    if runner.is_uv_available() is not True:
        raise RuntimeError(("premise: the memo holds True", attempts.log))
    event = CancelEvent()
    event.set()
    with cancel_scope(event):
        with pytest.raises(ScanCancelled):
            runner.is_uv_available()
    assert len(attempts.log) == 1, ("the cancelled call probed", attempts.log)
