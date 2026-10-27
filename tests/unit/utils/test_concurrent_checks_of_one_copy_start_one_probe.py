# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Checks of one copy that run at the same time start one probe between them.

``verify_pre_installed_tool`` answers from its memo and otherwise probes the copy:
``<copy> --version`` and, with uv, a dry run. A probe takes up to
``_VERSION_PROBE_TIMEOUT`` seconds. Several scanners (the project instances of one
tool in a workspace scan) check the same copy at once, so the memo is read again
after taking a per-key probe lock, the shape ``get_uv_tool_command`` has. The checks
that waited see what the first one stored, and no waiter probes.

Every launch is a recorded stand-in and every thread is the cell's own. The first
probe is held until every other thread is parked at the per-key lock, or one of them
has started a probe of its own; the wait is bounded, so a cell that fails does not
hang. No real tool starts.

Controls: two different copies do not wait for each other, a check the sandbox
refused leaves the lock free, and the lock's key spells no env-read value. A check
whose scan is cancelled while it waits behind another's probe stops there instead
of waiting the probe out.
"""

from __future__ import annotations

import contextlib
import subprocess
import threading
from pathlib import Path
from typing import Any, Callable, List

import pytest

from automated_security_helper.core.cancellation import (
    CancelEvent,
    ScanCancelled,
    cancel_scope,
)
from automated_security_helper.utils import pre_installed_tool, uv_tool_runner
from automated_security_helper.utils.sandbox.policy import SandboxUnavailable

_TOOL = "sampletool"
_THREADS = 4
#: Upper bound, in seconds, on every wait in this module.
_BOUND = 10.0


def _failed_version_probe(command: List[str]) -> "subprocess.CompletedProcess[str]":
    """A ``--version`` probe that exited 1: the verdict is ``unsatisfied``, and it
    is the memoized kind."""
    return subprocess.CompletedProcess(command, 1, "", "no sarif\n")


@pytest.fixture(autouse=True)
def _fresh_memo():
    pre_installed_tool.reset_pre_installed_tool_cache()
    yield
    pre_installed_tool.reset_pre_installed_tool_cache()


def _copy(directory: Path) -> Path:
    directory.mkdir()
    executable = directory / _TOOL
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    return executable


class _HeldProbe:
    """Records every probe; holds the first until the others are parked or probing.

    ``parked`` counts the threads that reached the per-key probe lock, the first one
    included. With the lock in place the first probe is released when all of the
    threads are parked. Without it nobody parks, a second probe starts, and the
    first is released by that.
    """

    def __init__(self, process: Any) -> None:
        self.process = process
        self.runs: List[List[str]] = []
        self.parked = 0
        self._condition = threading.Condition()

    def run(self, command: List[str], timeout: int) -> Any:
        with self._condition:
            self.runs.append(list(command))
            first = len(self.runs) == 1
            self._condition.notify_all()
            if first:
                self._condition.wait_for(
                    lambda: self.parked >= _THREADS or len(self.runs) > 1,
                    timeout=_BOUND,
                )
        return self.process

    def counting(self, real: Callable[..., Any]) -> Callable[..., Any]:
        """``_probe_lock_held`` with a count of the threads that reach it."""

        @contextlib.contextmanager
        def held(probe_lock: Any):
            with self._condition:
                self.parked += 1
                self._condition.notify_all()
            with real(probe_lock):
                yield

        return held


def _check_at_once(executable: Path) -> List[Any]:
    """``_THREADS`` threads call ``verify_pre_installed_tool`` on one copy together."""
    results: List[Any] = [None] * _THREADS
    errors: List[BaseException] = []
    together = threading.Barrier(_THREADS)

    def check(index: int) -> None:
        try:
            together.wait(timeout=_BOUND)
            results[index] = pre_installed_tool.verify_pre_installed_tool(
                str(executable), _TOOL
            )
        except BaseException as error:  # reported by the cell
            errors.append(error)

    threads = [
        threading.Thread(target=check, args=(index,), name=f"check-{index}")
        for index in range(_THREADS)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=3 * _BOUND)
    assert not any(thread.is_alive() for thread in threads), "a check never returned"
    assert errors == [], errors
    return results


def _hold_the_first_probe(monkeypatch, process: Any) -> _HeldProbe:
    held = _HeldProbe(process)
    real_lock = uv_tool_runner._probe_lock_held
    monkeypatch.setattr(pre_installed_tool, "_run", held.run)
    monkeypatch.setattr(uv_tool_runner, "_probe_lock_held", held.counting(real_lock))
    return held


def test_concurrent_checks_of_one_copy_start_one_probe(monkeypatch, tmp_path):
    executable = _copy(tmp_path / "bin")
    held = _hold_the_first_probe(
        monkeypatch, _failed_version_probe([str(executable), "--version"])
    )

    results = _check_at_once(executable)

    assert held.parked == _THREADS, "a check never reached the per-key lock"
    assert len(held.runs) == 1, f"a check beside the first started a probe: {held.runs}"
    assert {result.status for result in results} == {"unsatisfied"}, results
    assert all(result == results[0] for result in results), results
    with pre_installed_tool._verdict_cache_lock:
        assert len(pre_installed_tool._verdict_cache) == 1


def test_two_copies_are_probed_without_waiting_for_each_other(monkeypatch, tmp_path):
    """Control: the lock is per copy. The first copy's probe is held until the
    second copy's check has returned."""
    first = _copy(tmp_path / "first")
    second = _copy(tmp_path / "second")
    first_probing = threading.Event()
    second_done = threading.Event()
    first_saw_second_done: List[bool] = []

    def run(command: List[str], timeout: int) -> Any:
        if command[0] == str(first):
            first_probing.set()
            first_saw_second_done.append(second_done.wait(timeout=_BOUND))
        return _failed_version_probe(list(command))

    monkeypatch.setattr(pre_installed_tool, "_run", run)
    waiter = threading.Thread(
        target=pre_installed_tool.verify_pre_installed_tool,
        args=(str(first), _TOOL),
        name="first-copy",
    )
    waiter.start()
    assert first_probing.wait(timeout=_BOUND), "the first copy was never probed"

    other = pre_installed_tool.verify_pre_installed_tool(str(second), _TOOL)
    second_done.set()
    waiter.join(timeout=3 * _BOUND)

    assert other.status == "unsatisfied", other
    assert first_saw_second_done == [True], "the second copy waited for the first"
    assert not waiter.is_alive()


def test_a_check_the_sandbox_refused_leaves_the_lock_free(monkeypatch, tmp_path):
    """Control: a refusal is answered, not remembered, and the next check probes."""
    executable = _copy(tmp_path / "bin")
    outcomes: List[Any] = [SandboxUnavailable("the backend cannot plan here")]

    def run(command: List[str], timeout: int) -> Any:
        outcome = outcomes.pop(0) if outcomes else None
        if isinstance(outcome, BaseException):
            raise outcome
        return _failed_version_probe(list(command))

    monkeypatch.setattr(pre_installed_tool, "_run", run)

    refused = pre_installed_tool.verify_pre_installed_tool(str(executable), _TOOL)
    after = pre_installed_tool.verify_pre_installed_tool(str(executable), _TOOL)

    assert refused.status == "unverifiable", refused
    assert "sandbox refused" in refused.detail, refused
    assert after.status == "unsatisfied", after


def test_the_probe_lock_key_spells_no_env_read_value(monkeypatch, tmp_path):
    """Control: the key is read while the probe holds the lock. It names the lock
    by the hash of the memo key, so the env-read value that is part of the memo key
    is not spelled in the table's keys."""
    value = "Zq7Kx9LmPw4Nv2Rt"
    executable = _copy(tmp_path / "bin")
    keys_during_the_probe: List[str] = []

    def run(command: List[str], timeout: int) -> Any:
        keys_during_the_probe.extend(uv_tool_runner._uv_tool_probe_locks.keys())
        return _failed_version_probe(list(command))

    monkeypatch.setattr(pre_installed_tool, "_run", run)

    verdict = pre_installed_tool.verify_pre_installed_tool(
        str(executable), _TOOL, values=(value,)
    )

    assert verdict.status == "unsatisfied", verdict
    # The carrier first: a check that took no lock would pass the leak assertion
    # with nothing in the table at all.
    assert any(key.startswith("verdict::") for key in keys_during_the_probe), (
        keys_during_the_probe
    )
    assert not any(value in key for key in keys_during_the_probe), keys_during_the_probe


def test_a_cancelled_check_parked_behind_a_probe_stops(monkeypatch, tmp_path):
    """Control: the wait for the first probe is the runner's polling wait, so a
    check whose scan is cancelled while it is parked stops with the cancellation.
    The first probe stays held until the cell has decided, so a check that sat the
    probe out would still be alive at the bound."""
    executable = _copy(tmp_path / "bin")
    in_probe = threading.Event()
    release = threading.Event()
    reached_the_lock = threading.Event()
    entries: List[None] = []
    real_lock = uv_tool_runner._probe_lock_held

    def run(command: List[str], timeout: int) -> Any:
        in_probe.set()
        release.wait(timeout=3 * _BOUND)
        return _failed_version_probe(list(command))

    @contextlib.contextmanager
    def held(probe_lock: Any):
        entries.append(None)
        if len(entries) > 1:
            reached_the_lock.set()
        with real_lock(probe_lock):
            yield

    monkeypatch.setattr(pre_installed_tool, "_run", run)
    monkeypatch.setattr(uv_tool_runner, "_probe_lock_held", held)

    holder = threading.Thread(
        target=pre_installed_tool.verify_pre_installed_tool,
        args=(str(executable), _TOOL),
        name="first-probe",
    )
    holder.start()
    assert in_probe.wait(timeout=_BOUND), "the first probe never started"

    event = CancelEvent()
    outcome: dict = {}

    def waiter() -> None:
        with cancel_scope(event):
            try:
                outcome["answer"] = pre_installed_tool.verify_pre_installed_tool(
                    str(executable), _TOOL
                )
            except ScanCancelled as cancelled:
                outcome["raised"] = cancelled

    parked = threading.Thread(target=waiter, name="parked-check")
    try:
        parked.start()
        assert reached_the_lock.wait(timeout=_BOUND), "the check never reached the lock"
        event.set()
        parked.join(timeout=_BOUND)
        stopped = not parked.is_alive()
    finally:
        release.set()
        holder.join(timeout=3 * _BOUND)
        parked.join(timeout=3 * _BOUND)

    assert stopped, "the cancelled check sat the other check's probe out"
    assert "raised" in outcome, outcome
    assert "answer" not in outcome, outcome
    assert not holder.is_alive(), "the first probe never returned"
