# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The spawn helpers stop what they started, resolve what they were given, and
record what happened, at the edges nothing else pins.

Properties of ``utils/subprocess_utils.py``:

- a returncode of False is no success, as every exit-code reader says;
- a usable copy found later clears a command's recorded in-tree refusal;
- the terminal probe asks every standard stream, not stdin alone;
- the just-killed wait before a reap is bounded on a build with waitid too;
- stop_after_interrupt observes the exit before it signals, and reaps with a
  bound after its kill;
- an interrupt during a stop's SIGTERM grace still escalates to SIGKILL, in
  the plain stop, the tree stop and the stoppable runner;
- the server's last stop signals no group id a reaped pid no longer names, and
  ends a groupless child through SIGTERM before SIGKILL;
- a Python without ctypes still names the Windows system directory;
- only a SIGKILL or SIGTERM death while the server stops is the server's;
- a child another thread reaped reads as exited;
- the timeout arms mark the record stopped;
- an empty stream truncates a stale log and creates none;
- a run logged below INFO logs its failure below INFO too;
- a string command is the program's name, a tuple is copied, and a failure of
  the resolution itself is a spawn failure;
- the child's own PATH is searched when the caller gave one;
- a refused stop reaps a leader that has ended before it reads the leader's
  group, so the zombie's own group id is not read as a survivor;
- the lookup cache is bounded and keeps no miss;
- a shell command refused under a sandbox scope is counted;
- a streamed run stops its child on the scan's cancel, a child silent since
  the cancel included, and starts none in a cancelled scan;
- a process with pipes that fails to start runs its plan's cleanup, and bytes
  mode passes no encoding.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess  # nosec B404 - the module under test wraps subprocess
import sys
import threading
import time
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from automated_security_helper.core import cancellation
from automated_security_helper.core.cancellation import CancelEvent, ScanCancelled
from automated_security_helper.utils import subprocess_utils as spu
from automated_security_helper.utils.sandbox import scope as sandbox_scope

pytestmark = pytest.mark.unit

POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="POSIX signals and groups")

#: Above the kernel's pid space, so no live process shares it.
_FAKE_PID = 2**30 + 47


class _FakeChild:
    """The members the stop paths use, recorded."""

    def __init__(self, *, returncode=None, leads_group=False):
        self.pid = _FAKE_PID
        self.returncode = returncode
        self.calls: List[Any] = []
        self.args = ["tool"]
        self.stdout = self.stderr = self.stdin = None
        self.leads_group = leads_group

    def poll(self):
        return self.returncode

    def terminate(self):
        self.calls.append("terminate")

    def kill(self):
        self.calls.append("kill")
        self.returncode = -9

    def send_signal(self, signum):
        self.calls.append(("send_signal", signum))

    def wait(self, timeout=None):
        self.calls.append(("wait", timeout))
        if self.returncode is None:
            raise subprocess.TimeoutExpired(self.args, timeout or 0)
        return self.returncode


@pytest.fixture(autouse=True)
def _fresh_lookup_cache():
    spu.clear_find_executable_cache()
    yield
    spu.clear_find_executable_cache()


# --- exit codes -------------------------------------------------------------------


def test_a_returncode_of_false_is_no_success():
    assert spu.run_succeeded({"returncode": False}) is False
    assert spu.run_succeeded(SimpleNamespace(returncode=False)) is False
    # The control.
    assert spu.run_succeeded({"returncode": 0}) is True
    assert spu.run_succeeded(SimpleNamespace(returncode=0)) is True


# --- the lookup under a scan ------------------------------------------------------


def test_a_usable_copy_found_later_clears_the_recorded_refusal(monkeypatch, tmp_path):
    answers = {"n": 0}

    def first_usable(command, candidates, scope, sandbox=False):
        answers["n"] += 1
        if answers["n"] == 1:
            return None, str(tmp_path / "repo" / "tool")
        return "/opt/bin/tool", None

    monkeypatch.setattr(spu, "_first_usable", first_usable)
    monkeypatch.setattr(spu, "_executable_candidates", lambda command: iter(()))
    with spu.scanning_tree(str(tmp_path / "repo")):
        assert spu.find_executable("tool") is None
        assert "tool" in spu.in_tree_refusals()
        assert spu.find_executable("tool") == "/opt/bin/tool"
        assert "tool" not in spu.in_tree_refusals()


def test_the_lookup_cache_is_bounded_and_keeps_no_miss(monkeypatch):
    monkeypatch.setattr(spu, "_FIND_EXECUTABLE_CACHE_LIMIT", 2)
    found = {"a": "/opt/a", "b": "/opt/b", "c": "/opt/c", "missing": None}
    monkeypatch.setattr(
        spu,
        "_first_usable",
        lambda command, candidates, scope, sandbox=False: (found[command], None),
    )
    monkeypatch.setattr(spu, "_executable_candidates", lambda command: iter(()))
    monkeypatch.setattr(spu, "_is_executable_file", lambda path: True)
    for name in ("a", "b", "c", "missing"):
        spu.find_executable(name)
    keys = [key[0] for key in spu._find_executable_cache]
    assert len(keys) <= 2
    assert "missing" not in keys
    assert "c" in keys


class _EndedLeader:
    """A child that has exited and is not yet reaped: a zombie leading its group."""

    pid = _FAKE_PID
    returncode = None

    def __init__(self) -> None:
        self.events: List[str] = []

    def poll(self):
        self.events.append("poll")
        self.returncode = 0
        return 0


@POSIX_ONLY
def test_a_refused_stop_reaps_an_ended_leader_before_reading_its_group(monkeypatch):
    """A zombie leader keeps its group id alive by itself, so read before the reap
    the group of a tool that had ended before the stop looked like one the stop
    could not end, and the record kept the refusal instead of the exit code."""
    process = _EndedLeader()
    monkeypatch.setattr(spu, "_has_exited", lambda child: True)

    def group_survives(pgid):
        process.events.append("group")
        # The kernel keeps the id while the leader is a zombie, and releases it
        # once the leader is reaped.
        return "poll" not in process.events

    monkeypatch.setattr(spu, "_group_survives", group_survives)
    started = spu._StartedChild()
    with started.recording():
        started.process = process
        spu._note_stop_refused(process)
    assert process.events == ["poll", "group"]
    assert started.stop_refused is False


def test_the_childs_own_path_is_searched_when_the_caller_gave_one(
    monkeypatch, tmp_path
):
    tool_dir = tmp_path / "bin"
    tool_dir.mkdir()
    tool = tool_dir / "ash-u26-own-path-tool"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    tool.chmod(0o755)
    monkeypatch.setattr(spu, "find_executable", lambda name: None)
    env = {"PATH": str(tool_dir)}
    args = ["ash-u26-own-path-tool", "--version"]
    assert spu._resolve_for_spawn(args, None, env) is None
    assert args[0] == str(tool)
    # The control: with no PATH of its own the name stays unresolved.
    other = ["ash-u26-own-path-tool"]
    spu._resolve_for_spawn(other, None, None)
    assert other[0] == "ash-u26-own-path-tool"


# --- the terminal probe -------------------------------------------------------------


@POSIX_ONLY
def test_the_terminal_probe_asks_every_standard_stream(monkeypatch):
    monkeypatch.setattr(spu.sys, "stdin", SimpleNamespace(fileno=lambda: 0))
    monkeypatch.setattr(spu.sys, "stdout", SimpleNamespace(fileno=lambda: 1))
    monkeypatch.setattr(spu.sys, "stderr", SimpleNamespace(fileno=lambda: 2))

    def tcgetpgrp(fd):
        if fd == 0:
            raise OSError(25, "not a tty")  # stdin redirected
        return os.getpgrp()

    monkeypatch.setattr(spu.os, "tcgetpgrp", tcgetpgrp)
    assert spu._child_got_the_terminals_interrupt() is True


# --- waits that are bounded ----------------------------------------------------------


@POSIX_ONLY
def test_the_just_killed_wait_before_a_reap_is_bounded_with_waitid(monkeypatch):
    monkeypatch.setattr(spu, "_REAP_POLL_BOUND_SECONDS", 0.01)
    monkeypatch.setattr(spu, "INTERRUPT_WAIT_SLICE_SECONDS", 0.001)
    monkeypatch.setattr(spu.os, "waitid", lambda *a, **k: None)  # never exits
    discarded = []
    monkeypatch.setattr(spu, "discard_tool_pid", discarded.append)
    spu.discard_tool_pid_before_reap(_FakeChild())
    assert discarded == [_FAKE_PID]


@POSIX_ONLY
def test_stop_after_interrupt_observes_before_it_signals_and_reaps_with_a_bound(
    monkeypatch,
):
    order: List[str] = []
    monkeypatch.setattr(
        spu, "discard_tool_pid_once_exited", lambda p: order.append("observe") or False
    )
    monkeypatch.setattr(spu, "discard_tool_pid_before_reap", lambda p: None)
    monkeypatch.setattr(
        spu, "_wait_out", lambda p, g: (_ for _ in ()).throw(KeyboardInterrupt())
    )
    child = _FakeChild()
    real_kill = child.kill

    def kill():
        order.append("kill")
        real_kill()

    child.kill = kill
    with pytest.raises(KeyboardInterrupt):
        spu.stop_after_interrupt(child, grace=0.01, child_got_the_interrupt=False)
    assert order[:2] == ["observe", ("send_signal", signal.SIGINT)] or order[0] == (
        "observe"
    )
    assert order.index("observe") < order.index("kill")
    assert ("wait", spu._REAP_SECONDS) in child.calls
    assert ("wait", None) not in child.calls


# --- an interrupt during a grace still escalates ----------------------------------------


def test_an_interrupt_during_the_plain_stops_grace_still_kills(monkeypatch):
    monkeypatch.setattr(
        spu,
        "_wait_out_grace",
        lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    child = _FakeChild()
    with pytest.raises(KeyboardInterrupt):
        spu._stop(child, grace=1.0)
    assert child.calls[:2] == ["terminate", "kill"]


@POSIX_ONLY
def test_an_interrupt_during_the_tree_stops_grace_still_kills_the_group(monkeypatch):
    sent: List[Any] = []
    monkeypatch.setattr(spu, "_group_exists", lambda pgid: True)
    monkeypatch.setattr(spu, "_pid_names_a_live_process", lambda pid: False)
    monkeypatch.setattr(
        spu, "_signal_group", lambda pgid, signum: sent.append((pgid, signum)) or True
    )
    monkeypatch.setattr(
        spu,
        "_wait_out_grace",
        lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    with pytest.raises(KeyboardInterrupt):
        spu._stop_tree(_FakeChild(), grace=1.0)
    assert (_FAKE_PID, signal.SIGTERM) in sent
    assert (_FAKE_PID, signal.SIGKILL) in sent


class _TimingOutPopen(_FakeChild):
    """communicate times out, then the grace wait is interrupted."""

    instances: List["_TimingOutPopen"] = []

    def __init__(self, args, **kwargs):
        super().__init__()
        self.args = list(args)
        self.kwargs = kwargs
        self.communicates = 0
        _TimingOutPopen.instances.append(self)

    def communicate(self, *_input, timeout=None):
        self.communicates += 1
        if self.communicates == 1:
            raise subprocess.TimeoutExpired(self.args, timeout or 0)
        raise KeyboardInterrupt


def test_an_interrupt_during_the_stoppable_runners_grace_still_kills(monkeypatch):
    _TimingOutPopen.instances.clear()
    monkeypatch.setattr(spu.subprocess, "Popen", _TimingOutPopen)
    monkeypatch.setattr(spu, "_reap", lambda args, process: None)
    with pytest.raises(KeyboardInterrupt):
        spu._run_stoppable(["tool"], timeout=0.01)
    (child,) = _TimingOutPopen.instances
    assert "terminate" in child.calls and "kill" in child.calls
    assert child.calls.index("terminate") < child.calls.index("kill")


# --- the server's last stop ------------------------------------------------------------------


@POSIX_ONLY
def test_the_last_stop_signals_no_group_a_reaped_pid_no_longer_names(monkeypatch):
    sent: List[Any] = []
    monkeypatch.setattr(spu, "_pid_names_a_live_process", lambda pid: True)
    monkeypatch.setattr(
        spu, "_signal_group", lambda pgid, signum: sent.append((pgid, signum)) or True
    )
    assert spu._kill_group(_FakeChild(returncode=0)) is False
    assert sent == []


@POSIX_ONLY
def test_the_last_stop_ends_a_groupless_child_through_sigterm_first(monkeypatch):
    monkeypatch.setattr(spu, "_leads_its_own_group", lambda process: False)
    monkeypatch.setattr(spu, "_KILLED_GROUP_SETTLE_SECONDS", 0.01)
    child = _FakeChild()
    assert spu._kill_group(child) is True
    assert child.calls == ["terminate", ("wait", 0.01), "kill"]


def test_a_python_without_ctypes_still_names_the_system_directory(monkeypatch):
    monkeypatch.setitem(sys.modules, "ctypes", None)
    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    assert spu._windows_system_directory() == "C:\\Windows\\System32"
    monkeypatch.delenv("SystemRoot")
    monkeypatch.delenv("SYSTEMROOT", raising=False)
    assert spu._windows_system_directory() is None


@POSIX_ONLY
def test_only_a_kill_or_term_death_while_stopping_is_the_servers(monkeypatch):
    monkeypatch.setattr(spu, "_server_stopping", lambda: True)
    assert spu._stopped_by_the_server(-signal.SIGKILL) is True
    assert spu._stopped_by_the_server(-signal.SIGTERM) is True
    assert spu._stopped_by_the_server(-signal.SIGSEGV) is False
    assert spu._stopped_by_the_server(0) is False
    assert spu._stopped_by_the_server(None) is False
    monkeypatch.setattr(spu, "_server_stopping", lambda: False)
    assert spu._stopped_by_the_server(-signal.SIGKILL) is False


# --- the record -------------------------------------------------------------------------------


class _ReapedUnderTheLock(_FakeChild):
    """A child another thread reaped: that thread set the code under Popen's
    reaping lock, and this thread's poll, asked while the lock was held, read
    nothing, as ``Popen.poll`` does then."""

    def __init__(self) -> None:
        super().__init__(returncode=0)

    def poll(self):
        return None


@POSIX_ONLY
def test_a_child_another_thread_reaped_reads_as_exited(monkeypatch):
    """The kernel no longer knows the pid (``waitid`` raises ChildProcessError)
    and the reaper set the code, so the child has ended."""

    def reaped_elsewhere(*args, **kwargs):
        raise ChildProcessError

    monkeypatch.setattr(spu.os, "waitid", reaped_elsewhere)
    assert spu._has_exited(_ReapedUnderTheLock()) is True
    # A pid the kernel does not know with NO code set is not a reaped child:
    # it is a recorded child that was never spawned (a stand-in with a pid of
    # its own), and the kernel is not asked to decide for it.
    assert spu._has_exited(_FakeChild()) is False
    # The control: a child the kernel reads as running is running.
    monkeypatch.setattr(spu.os, "waitid", lambda *a, **k: None)
    assert spu._has_exited(_FakeChild()) is False


class _TimingOutOncePopen(_FakeChild):
    def __init__(self, args, **kwargs):
        super().__init__()
        self.args = list(args)

    def communicate(self, *_input, timeout=None):
        raise subprocess.TimeoutExpired(self.args, timeout or 0, output=b"partial")


def test_the_plain_runners_timeout_marks_the_record_stopped(monkeypatch):
    monkeypatch.setattr(spu.subprocess, "Popen", _TimingOutOncePopen)
    monkeypatch.setattr(spu, "_start_in_own_group", lambda kwargs: None)
    # A timed-out spawn registers its group; the stand-in stays out of the
    # registry, which no later test should find it in.
    monkeypatch.setattr(spu, "_register_group", lambda process: None)
    monkeypatch.setattr(spu, "_stop_child", lambda *a, **k: None)
    monkeypatch.setattr(spu, "_reap", lambda args, process: None)
    started = spu._StartedChild()
    with started.recording():
        with pytest.raises(subprocess.TimeoutExpired):
            spu._run_plain(["tool"], timeout=0.01)
    assert started.process is not None
    assert started.stopped is True
    assert started.exit_code() is None


# --- the stream logs ---------------------------------------------------------------------------


def test_an_empty_stream_truncates_a_stale_log_and_creates_none(tmp_path):
    stale = tmp_path / "Cls.stdout.log"
    stale.write_text("the previous command's output", encoding="utf-8")
    clauses = spu._write_stream_logs(
        None,
        tmp_path,
        "Cls",
        (("stdout", "write", ""), ("stderr", "write", None)),
    )
    assert clauses == []
    assert stale.read_text(encoding="utf-8") == ""
    assert not (tmp_path / "Cls.stderr.log").exists()


# --- run_command ----------------------------------------------------------------------------------


def _fake_runner(returncode=0, seen: Dict[str, Any] | None = None):
    def runner(sandboxed):
        def run(args, **kwargs):
            if seen is not None:
                seen["args"] = args
                seen["kwargs"] = kwargs
            return subprocess.CompletedProcess(args, returncode, "", "")

        return run

    return runner


def test_a_run_logged_below_info_logs_its_failure_below_info_too(monkeypatch, caplog):
    monkeypatch.setattr(spu, "_runner", _fake_runner(returncode=1))
    monkeypatch.setattr(spu, "_resolved_or_refused", lambda *a: None)
    with caplog.at_level(logging.DEBUG):
        spu.run_command(["ash-u26-no-such-tool"], log_level=logging.DEBUG)
        quiet = [r for r in caplog.records if "Command failed" in r.getMessage()]
        caplog.clear()
        spu.run_command(["ash-u26-no-such-tool"])
        loud = [r for r in caplog.records if "Command failed" in r.getMessage()]
    assert [r.levelno for r in quiet] == [logging.DEBUG]
    assert [r.levelno for r in loud] == [logging.WARNING]


def test_a_string_command_is_the_programs_name_and_a_tuple_is_copied(monkeypatch):
    seen: Dict[str, Any] = {}
    monkeypatch.setattr(spu, "_runner", _fake_runner(seen=seen))
    monkeypatch.setattr(spu, "_resolved_or_refused", lambda *a: None)
    spu.run_command("ash-u26-no-such-tool")
    assert seen["args"] == ["ash-u26-no-such-tool"]
    given = ("ash-u26-no-such-tool", "--x")
    spu.run_command(given)
    assert seen["args"] == ["ash-u26-no-such-tool", "--x"]
    assert given == ("ash-u26-no-such-tool", "--x")


def test_a_failure_of_the_resolution_itself_is_a_spawn_failure(monkeypatch):
    def resolution_fails(*args):
        raise FileNotFoundError(2, "the working directory is gone")

    monkeypatch.setattr(spu, "_resolve_for_spawn", resolution_fails)
    monkeypatch.setattr(spu, "_runner", _fake_runner())
    result = spu.run_command(["ash-u26-no-such-tool"])
    assert isinstance(result, spu.SpawnFailedProcess)
    assert result.returncode == spu.SPAWN_FAILURE_RETURNCODE
    response = spu.run_command_with_output_handling(["ash-u26-no-such-tool"])
    assert response["spawn_failed"] is True


def test_bytes_mode_passes_no_encoding_and_no_error_handler(monkeypatch):
    seen: Dict[str, Any] = {}
    monkeypatch.setattr(spu, "_runner", _fake_runner(seen=seen))
    monkeypatch.setattr(spu, "_resolved_or_refused", lambda *a: None)
    spu.run_command(["ash-u26-no-such-tool"], text=False)
    assert seen["kwargs"]["encoding"] is None
    assert seen["kwargs"]["errors"] is None
    spu.run_command(["ash-u26-no-such-tool"], text=True)
    assert seen["kwargs"]["errors"] == "replace"


# --- the sandbox scope ---------------------------------------------------------------------------


def test_a_shell_command_refused_under_a_scope_is_counted():
    scope = sandbox_scope.RefusingScope(scanner_name="x", reason="no sandbox")
    token = sandbox_scope._ACTIVE.set(scope)
    try:
        with pytest.raises(sandbox_scope.SandboxUnavailable):
            spu._prepare_spawn("tool --x", None, None, shell=True)
    finally:
        sandbox_scope._ACTIVE.reset(token)
    assert scope.refused_spawns == 1
    assert "shell" in (scope.last_refusal or "")


# --- the streamed run ------------------------------------------------------------------------------


class _StreamingPopen(_FakeChild):
    instances: List["_StreamingPopen"] = []

    def __init__(self, args, **kwargs):
        super().__init__()
        self.args = list(args)
        self.event = _StreamingPopen.event
        _StreamingPopen.instances.append(self)
        self.stdout = self._lines()

    def _lines(self):
        yield "line one\n"
        self.event.set()
        yield "line two\n"

    def terminate(self):
        super().terminate()
        self.returncode = -15

    def wait(self, timeout=None):
        self.calls.append(("wait", timeout))
        return self.returncode if self.returncode is not None else 0


def test_a_streamed_run_stops_its_child_on_the_scans_cancel(monkeypatch):
    event = CancelEvent()
    _StreamingPopen.event = event
    _StreamingPopen.instances.clear()
    monkeypatch.setattr(spu.subprocess, "Popen", _StreamingPopen)
    monkeypatch.setattr(spu, "_resolved_or_refused", lambda *a: None)
    monkeypatch.setattr(spu, "_prepare_spawn", lambda *a, **k: None)
    with cancellation.cancel_scope(event):
        with pytest.raises(ScanCancelled):
            spu.run_command_stream_output(["ash-u26-no-such-tool"])
    (child,) = _StreamingPopen.instances
    assert "terminate" in child.calls


#: Longer than the stop should take by far, shorter than a test may hang.
_SILENT_BOUND = 5.0


class _SilentPopen(_FakeChild):
    """A child that prints nothing and runs until it is stopped."""

    instances: List["_SilentPopen"] = []

    def __init__(self, args, **kwargs):
        super().__init__()
        self.args = list(args)
        self.ended = threading.Event()
        _SilentPopen.instances.append(self)
        self.stdout = self._lines()

    def _lines(self):
        # The read blocks, as a pipe read does, until the child ends.
        self.ended.wait(_SILENT_BOUND)
        return
        yield  # pragma: no cover - makes this a generator

    def terminate(self):
        super().terminate()
        self.returncode = -15
        self.ended.set()

    def kill(self):
        super().kill()
        self.ended.set()

    def wait(self, timeout=None):
        self.calls.append(("wait", timeout))
        if not self.ended.wait(_SILENT_BOUND):
            raise subprocess.TimeoutExpired(self.args, _SILENT_BOUND)
        return self.returncode if self.returncode is not None else 0


def test_a_streamed_run_stops_a_child_silent_since_the_cancel(monkeypatch):
    """Read between output lines alone, the cancel never reached a tool that
    printed nothing more, and the wait on it had no bound."""
    event = CancelEvent()
    _SilentPopen.instances.clear()
    monkeypatch.setattr(spu.subprocess, "Popen", _SilentPopen)
    monkeypatch.setattr(spu, "_resolved_or_refused", lambda *a: None)
    monkeypatch.setattr(spu, "_prepare_spawn", lambda *a, **k: None)
    monkeypatch.setattr(spu, "_leads_its_own_group", lambda process: False)
    cancel = threading.Timer(0.1, event.set)
    began = time.monotonic()
    with cancellation.cancel_scope(event):
        cancel.start()
        try:
            with pytest.raises(ScanCancelled):
                spu.run_command_stream_output(["ash-u26-no-such-tool"])
        finally:
            cancel.cancel()
    took = time.monotonic() - began
    (child,) = _SilentPopen.instances
    assert "terminate" in child.calls
    assert took < _SILENT_BOUND / 2, f"the cancel took {took:.2f}s to stop the tool"


def test_a_streamed_run_starts_nothing_in_a_cancelled_scan(monkeypatch):
    _StreamingPopen.instances.clear()
    monkeypatch.setattr(spu.subprocess, "Popen", _StreamingPopen)
    monkeypatch.setattr(spu, "_resolved_or_refused", lambda *a: None)
    event = CancelEvent()
    event.set()
    with cancellation.cancel_scope(event):
        with pytest.raises(ScanCancelled):
            spu.run_command_stream_output(["ash-u26-no-such-tool"])
    assert _StreamingPopen.instances == []


# --- a process with pipes ----------------------------------------------------------------------------


def test_a_process_with_pipes_that_fails_to_start_runs_its_plans_cleanup(
    monkeypatch, caplog
):
    cleaned = []
    plan = SimpleNamespace(
        argv=["tool"], env={}, run_cleanup=lambda: cleaned.append("cleanup")
    )
    monkeypatch.setattr(spu, "_resolved_or_refused", lambda *a: None)
    monkeypatch.setattr(spu, "_prepare_spawn", lambda *a, **k: plan)
    monkeypatch.setattr(spu, "_plan_popen_kwargs", lambda plan: {})

    def failing_popen(*args, **kwargs):
        raise OSError(2, "no such program")

    monkeypatch.setattr(spu.subprocess, "Popen", failing_popen)
    with caplog.at_level(logging.ERROR):
        with pytest.raises(OSError):
            spu.create_process_with_pipes(["tool"])
    assert cleaned == ["cleanup"]
    assert any("Error creating process" in r.getMessage() for r in caplog.records)


def test_a_process_with_pipes_in_bytes_mode_passes_no_encoding(monkeypatch):
    seen: Dict[str, Any] = {}

    def recording_popen(args, **kwargs):
        seen.update(kwargs)
        return _FakeChild()

    monkeypatch.setattr(spu, "_resolved_or_refused", lambda *a: None)
    monkeypatch.setattr(spu, "_prepare_spawn", lambda *a, **k: None)
    monkeypatch.setattr(spu.subprocess, "Popen", recording_popen)
    spu.create_process_with_pipes(["tool"], text=False)
    assert seen["text"] is False
    assert seen["encoding"] is None and seen["errors"] is None
