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
#: The waitid probe exists on Linux and the BSDs but not on every POSIX build
#: (macOS has no os.waitid), so a test that stands it in skips where it is absent.
NEEDS_WAITID = pytest.mark.skipif(
    not hasattr(os, "waitid"), reason="this Python has no os.waitid"
)

#: Above the kernel's pid space, so no live process shares it.
_FAKE_PID = 2**30 + 47


@pytest.fixture(autouse=True)
def _no_state_carried_between_tests(monkeypatch):
    """Each test starts with the module's registries and every stand-in's
    class-level records empty, and puts the originals back after it.

    The fake pid rides several spawn paths here with ``_reap`` patched out, so
    a registration or a recorded kill one test left would be read by the next.
    Every stand-in that keeps ``instances`` is reset, and every one that is
    given a cancel ``event`` has it cleared: the event a test hands the
    interrupt-raising stand-in is read on the main thread, so one left over
    would raise KeyboardInterrupt in a later test, outside ``pytest.raises``,
    and pytest takes that as a user abort that ends the whole session."""
    monkeypatch.setattr(cancellation, "_TOOL_PIDS", ())
    monkeypatch.setattr(cancellation, "_TOOL_GROUPS", ())
    monkeypatch.setattr(spu, "_SERVER_KILLED", set())
    monkeypatch.setattr(spu, "_RUNNING_GROUPS", {})
    monkeypatch.setattr(spu, "_SPAWNS_STARTING", 0)
    for stand_in in _STAND_INS_WITH_INSTANCES:
        monkeypatch.setattr(stand_in, "instances", [])
    for stand_in in _STAND_INS_WITH_AN_EVENT:
        monkeypatch.setattr(stand_in, "event", None)


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


@POSIX_ONLY
def test_the_childs_own_path_is_searched_before_ashs(monkeypatch, tmp_path):
    """A tool's bin directory put first on the child's PATH names the copy the
    child runs; ASH's own PATH may hold another copy, which must not shadow it."""
    tool_dir = tmp_path / "bin"
    tool_dir.mkdir()
    tool = tool_dir / "ash-u26-two-copies-tool"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    tool.chmod(0o755)
    monkeypatch.setattr(spu, "find_executable", lambda name: "/opt/elsewhere/tool")
    env = {"PATH": str(tool_dir)}
    args = ["ash-u26-two-copies-tool"]
    assert spu._resolve_for_spawn(args, None, env) is None
    assert args[0] == str(tool), "ASH's PATH shadowed the child's own copy"


@POSIX_ONLY
def test_an_in_tree_copy_on_the_childs_path_is_a_refusal_not_a_miss(
    monkeypatch, tmp_path
):
    """The only copy the child's PATH names sits inside the scanned tree: the
    resolution reports the refusal, naming that copy, instead of falling through
    to the not-found branches as if nothing had been named."""
    repo = tmp_path / "repo"
    tool_dir = repo / "bin"
    tool_dir.mkdir(parents=True)
    tool = tool_dir / "ash-u26-in-tree-tool"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    tool.chmod(0o755)
    monkeypatch.setattr(spu, "find_executable", lambda name: None)
    env = {"PATH": str(tool_dir)}
    args = ["ash-u26-in-tree-tool"]
    with spu.scanning_tree(str(repo)):
        refusal = spu._resolve_for_spawn(args, None, env)
    assert isinstance(refusal, FileNotFoundError)
    assert "resolves on the child's PATH to" in str(refusal)
    assert str(tool) in str(refusal)
    assert args[0] == "ash-u26-in-tree-tool"


def _executable_tool(directory, name):
    """A `#!/bin/sh` file made executable by its mode, in ``directory``."""
    directory.mkdir(parents=True, exist_ok=True)
    tool = directory / name
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    tool.chmod(0o755)
    return tool


@POSIX_ONLY
def test_a_copy_in_the_trees_node_modules_bin_on_the_childs_path_is_refused(
    monkeypatch, tmp_path
):
    """The case the in-tree refusal exists for: a repository ships
    ``node_modules/.bin/<tool>`` and the child's PATH names that directory. The
    copy is refused by its exact path, and the program the caller gave is not
    rewritten to it."""
    repo = tmp_path / "repo"
    tool = _executable_tool(repo / "node_modules" / ".bin", "ash-u26-in-tree-tool")
    monkeypatch.setattr(spu, "find_executable", lambda name: None)
    monkeypatch.delenv(spu.ALLOW_IN_TREE_TOOLS_ENV, raising=False)
    args = ["ash-u26-in-tree-tool", "--version"]
    with spu.scanning_tree(str(repo)):
        refusal = spu._resolve_for_spawn(args, None, {"PATH": str(tool.parent)})
    assert isinstance(refusal, FileNotFoundError)
    assert f"resolves on the child's PATH to {tool}, inside the scanned tree" in str(
        refusal
    )
    assert args == ["ash-u26-in-tree-tool", "--version"]


@POSIX_ONLY
@pytest.mark.parametrize(
    "in_tree_first", [True, False], ids=["in-tree-first", "outside-first"]
)
def test_a_mixed_child_path_runs_the_copy_outside_the_tree(
    in_tree_first, monkeypatch, tmp_path
):
    """The child's PATH names both an in-tree directory and one outside it, each
    with the tool: whichever comes first, the program is the copy outside the
    tree, and the in-tree copy is never the one it is pointed at."""
    repo = tmp_path / "repo"
    in_tree = _executable_tool(repo / "node_modules" / ".bin", "ash-u26-in-tree-tool")
    outside = _executable_tool(tmp_path / "system", "ash-u26-in-tree-tool")
    directories = [in_tree.parent, outside.parent]
    if not in_tree_first:
        directories.reverse()
    monkeypatch.setattr(spu, "find_executable", lambda name: None)
    monkeypatch.delenv(spu.ALLOW_IN_TREE_TOOLS_ENV, raising=False)
    args = ["ash-u26-in-tree-tool", "--version"]
    path = os.pathsep.join(str(directory) for directory in directories)
    with spu.scanning_tree(str(repo)):
        refusal = spu._resolve_for_spawn(args, None, {"PATH": path})
    assert refusal is None
    assert args == [str(outside), "--version"]


@POSIX_ONLY
def test_the_childs_own_path_is_searched_when_the_caller_gave_one(
    monkeypatch, tmp_path
):
    # POSIX: an extensionless `#!/bin/sh` file made executable by its mode.
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
@pytest.mark.parametrize("terminal_fd", [0, 1, 2], ids=["stdin", "stdout", "stderr"])
def test_the_terminal_probe_asks_every_standard_stream(monkeypatch, terminal_fd):
    """Each stream in turn is the only one at the terminal, the other two
    redirected (``< inputs``, ``> out.log``, ``2> err.log``): a probe that left
    one of the three out would read "no terminal" for that case alone."""
    monkeypatch.setattr(spu.sys, "stdin", SimpleNamespace(fileno=lambda: 0))
    monkeypatch.setattr(spu.sys, "stdout", SimpleNamespace(fileno=lambda: 1))
    monkeypatch.setattr(spu.sys, "stderr", SimpleNamespace(fileno=lambda: 2))

    def tcgetpgrp(fd):
        if fd != terminal_fd:
            raise OSError(25, "not a tty")  # redirected
        return os.getpgrp()

    monkeypatch.setattr(spu.os, "tcgetpgrp", tcgetpgrp)
    assert spu._child_got_the_terminals_interrupt() is True


@POSIX_ONLY
def test_the_terminal_probe_reads_no_terminal_when_every_stream_is_redirected(
    monkeypatch,
):
    """The control for the case above: with all three redirected there is no
    terminal to have sent the Ctrl-C, as in CI."""
    monkeypatch.setattr(spu.sys, "stdin", SimpleNamespace(fileno=lambda: 0))
    monkeypatch.setattr(spu.sys, "stdout", SimpleNamespace(fileno=lambda: 1))
    monkeypatch.setattr(spu.sys, "stderr", SimpleNamespace(fileno=lambda: 2))

    def tcgetpgrp(fd):
        raise OSError(25, "not a tty")

    monkeypatch.setattr(spu.os, "tcgetpgrp", tcgetpgrp)
    assert spu._child_got_the_terminals_interrupt() is False


@POSIX_ONLY
def test_the_terminal_probe_reads_a_foreign_foreground_group_as_no_interrupt(
    monkeypatch,
):
    """The negative case: every standard stream is a terminal whose foreground
    group is not ours, so the child did not get the terminal's Ctrl-C."""
    monkeypatch.setattr(spu.sys, "stdin", SimpleNamespace(fileno=lambda: 0))
    monkeypatch.setattr(spu.sys, "stdout", SimpleNamespace(fileno=lambda: 1))
    monkeypatch.setattr(spu.sys, "stderr", SimpleNamespace(fileno=lambda: 2))
    monkeypatch.setattr(spu.os, "tcgetpgrp", lambda fd: os.getpgrp() + 1)
    assert spu._child_got_the_terminals_interrupt() is False


# --- waits that are bounded ----------------------------------------------------------


@POSIX_ONLY
@NEEDS_WAITID
def test_the_just_killed_wait_before_a_reap_is_bounded_with_waitid(monkeypatch):
    monkeypatch.setattr(spu, "_REAP_POLL_BOUND_SECONDS", 0.01)
    monkeypatch.setattr(spu, "INTERRUPT_WAIT_SLICE_SECONDS", 0.001)
    monkeypatch.setattr(spu.os, "waitid", lambda *a, **k: None)  # never exits
    discarded = []
    monkeypatch.setattr(spu, "discard_tool_pid", discarded.append)
    # On its own thread with a bounded join: a wait that lost its bound would
    # otherwise hang the test run instead of failing it.
    waiter = threading.Thread(
        target=spu.discard_tool_pid_before_reap, args=(_FakeChild(),), daemon=True
    )
    waiter.start()
    waiter.join(timeout=2.0)
    assert not waiter.is_alive(), "the just-killed wait did not return"
    assert discarded == [_FAKE_PID]


@POSIX_ONLY
def test_stop_after_interrupt_observes_before_it_signals_and_reaps_with_a_bound(
    monkeypatch,
):
    order: List[Any] = []
    monkeypatch.setattr(
        spu, "discard_tool_pid_once_exited", lambda p: order.append("observe") or False
    )
    monkeypatch.setattr(spu, "discard_tool_pid_before_reap", lambda p: None)
    monkeypatch.setattr(
        spu, "_wait_out", lambda p, g: (_ for _ in ()).throw(KeyboardInterrupt())
    )
    child = _FakeChild()
    real_kill = child.kill
    real_send_signal = child.send_signal

    def kill():
        order.append("kill")
        real_kill()

    def send_signal(signum):
        # Into the same record as the observe and the kill, so the order of all
        # three is what is asserted; the stand-in's own calls list keeps the
        # signal number as before.
        order.append("sigint" if signum == signal.SIGINT else ("send_signal", signum))
        real_send_signal(signum)

    child.kill = kill
    child.send_signal = send_signal
    with pytest.raises(KeyboardInterrupt):
        spu.stop_after_interrupt(child, grace=0.01, child_got_the_interrupt=False)
    # The exit is observed before the SIGINT is sent, and observed again when
    # the second Ctrl-C arrives, before the kill: the interrupt arm's own
    # observe-discard-reap step (stop_after_interrupt's documented order). The
    # first shape of this assertion named three steps and was red by reading.
    assert order == ["observe", "sigint", "observe", "kill"]
    assert ("wait", spu._REAP_SECONDS) in child.calls
    assert ("wait", None) not in child.calls


# --- the grace wait holds a first Ctrl-C --------------------------------------------


def test_the_grace_wait_runs_inside_the_stop_grace_context(monkeypatch):
    """While a stop waits out a tool's grace, a first Ctrl-C latches the scans'
    cancel and does not interrupt the wait (cancellation.stop_grace_in_progress);
    the wait had never entered that context."""
    child = _FakeChild()
    seen: List[int] = []

    def sleep(step):
        seen.append(cancellation._GRACE_WAITS)
        child.returncode = 0

    monkeypatch.setattr(spu.time, "sleep", sleep)
    before = cancellation._GRACE_WAITS
    spu._wait_out_grace(child, None, grace=1.0, prompt=None)
    assert seen == [before + 1], "the grace wait ran outside the context"
    assert cancellation._GRACE_WAITS == before


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
    refused: List[Any] = []
    # The group read that ending a tree makes is _group_survives, replaced here
    # as the sibling modules replace it, with the post-kill wait and the refusal
    # mark, so nothing reads the host's process table: patching the lower-level
    # existence probe left the zombie-aware read, the wait and the mark real.
    monkeypatch.setattr(spu, "_group_survives", lambda pgid: True)
    monkeypatch.setattr(spu, "_pid_names_a_live_process", lambda pid: False)
    monkeypatch.setattr(spu, "_wait_after_kill", lambda process: None)
    monkeypatch.setattr(spu, "_note_stop_refused", refused.append)
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
    # SIGTERM first, then the SIGKILL the interrupt escalates to, in the order
    # the plain runner's case asserts: SIGKILL first would leave no grace.
    assert sent == [(_FAKE_PID, signal.SIGTERM), (_FAKE_PID, signal.SIGKILL)], sent
    assert refused == [], "an accepted kill was marked as refused"


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
    monkeypatch.setattr(spu.subprocess, "Popen", _TimingOutPopen)
    # The reap that would forget a record is replaced, so a record made here is
    # left to the test's own registry (the autouse reset above).
    monkeypatch.setattr(spu, "_reap", lambda args, process: None)
    with pytest.raises(KeyboardInterrupt):
        spu._run_stoppable(["tool"], timeout=0.01)
    (child,) = _TimingOutPopen.instances
    assert "terminate" in child.calls and "kill" in child.calls
    assert child.calls.index("terminate") < child.calls.index("kill")
    # The sandboxed runner records no group of its own: the wrapper's setsid
    # makes the group, and the stop paths ask the child about it at stop time.
    assert spu._RUNNING_GROUPS == {}


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
    monkeypatch.setattr(spu, "_SERVER_KILLED", set())
    assert spu._stopped_by_the_server(-signal.SIGKILL) is True
    assert spu._stopped_by_the_server(-signal.SIGTERM) is True
    assert spu._stopped_by_the_server(-signal.SIGSEGV) is False
    assert spu._stopped_by_the_server(0) is False
    assert spu._stopped_by_the_server(None) is False
    # A child the stop did not signal is read by its code alone.
    assert spu._stopped_by_the_server(143, _FakeChild(returncode=143)) is False
    monkeypatch.setattr(spu, "_server_stopping", lambda: False)
    assert spu._stopped_by_the_server(-signal.SIGKILL) is False


class _WrapperThatEndsItsTreeOnSigterm(_FakeChild):
    """A wrapper that handles the SIGTERM it is sent first, ends its tree and
    exits with a code of its own within the settle."""

    def wait(self, timeout=None):
        self.calls.append(("wait", timeout))
        self.returncode = 143
        return self.returncode


@POSIX_ONLY
def test_a_child_the_servers_stop_signalled_is_the_servers_whatever_its_code(
    monkeypatch,
):
    monkeypatch.setattr(spu, "_server_stopping", lambda: True)
    monkeypatch.setattr(spu, "_SERVER_KILLED", set())
    monkeypatch.setattr(spu, "_leads_its_own_group", lambda process: False)
    monkeypatch.setattr(spu, "_KILLED_GROUP_SETTLE_SECONDS", 0.01)
    child = _WrapperThatEndsItsTreeOnSigterm()
    assert spu._kill_group(child) is True
    assert child.calls == ["terminate", ("wait", 0.01)], child.calls
    # Signalled by the stop and exited 143: the server's stop, not a run that
    # returned normally while the server stopped.
    assert spu._stopped_by_the_server(child.returncode, child) is True
    # The code alone, with no process, still reads 143 as the tool's own.
    assert spu._stopped_by_the_server(143) is False
    # Once the server is not stopping, nothing is the server's.
    monkeypatch.setattr(spu, "_server_stopping", lambda: False)
    assert spu._stopped_by_the_server(child.returncode, child) is False


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
@NEEDS_WAITID
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
    # And the other way: a result from the kernel is an exit the poll has not
    # reaped yet (a zombie), so the child has ended. The control above could
    # not fail on its own, since "running" is also what a read that never
    # asked the kernel would answer.
    monkeypatch.setattr(
        spu.os, "waitid", lambda *a, **k: SimpleNamespace(si_pid=_FAKE_PID)
    )
    assert spu._has_exited(_FakeChild()) is True


class _TimingOutOncePopen(_FakeChild):
    def __init__(self, args, **kwargs):
        super().__init__()
        self.args = list(args)

    def communicate(self, *_input, timeout=None):
        raise subprocess.TimeoutExpired(self.args, timeout or 0, output=b"partial")


def test_the_plain_runners_timeout_marks_the_record_stopped(monkeypatch):
    monkeypatch.setattr(spu.subprocess, "Popen", _TimingOutOncePopen)
    monkeypatch.setattr(spu, "_start_in_own_group", lambda kwargs: None)
    # A spawn with a timeout counts and records its group (_begin_spawn,
    # _record_spawn); the stand-in stays out of the module's count and
    # registry, which no later test should find it in.
    monkeypatch.setattr(spu, "_begin_spawn", lambda args: None)
    monkeypatch.setattr(spu, "_record_spawn", lambda process: spu._SpawnRecord.GOES_ON)
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


def test_an_empty_stream_with_no_log_to_truncate_creates_none(tmp_path):
    """The other half: an empty text, with no log from an earlier run to
    truncate, writes nothing and reports no failure."""
    clauses = spu._write_stream_logs(
        None,
        tmp_path,
        "Cls",
        (("stdout", "write", ""), ("stderr", "both", "")),
    )
    assert clauses == []
    assert not (tmp_path / "Cls.stdout.log").exists()
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


def test_a_string_command_is_the_programs_name_and_the_callers_list_is_copied(
    monkeypatch,
):
    seen: Dict[str, Any] = {}
    monkeypatch.setattr(spu, "_runner", _fake_runner(seen=seen))
    seen_by_resolution: List[Any] = []

    def resolve_into(args, *rest):
        # The resolution writes the program's path into the list it is given,
        # as the real one does; the caller's own list must not be that list.
        seen_by_resolution.append(list(args))
        args[0] = "/opt/bin/tool"
        return None

    monkeypatch.setattr(spu, "_resolved_or_refused", resolve_into)
    # The whole string is the program's name, spaces included: a split on
    # whitespace would hand the resolution three words.
    spu.run_command("ash-u26 no such tool")
    assert seen_by_resolution == [["ash-u26 no such tool"]]
    assert seen["args"] == ["/opt/bin/tool"]
    given = ["ash-u26-no-such-tool", "--x"]
    spu.run_command(given)
    assert seen["args"] == ["/opt/bin/tool", "--x"]
    assert given == ["ash-u26-no-such-tool", "--x"], "the caller's list was written"
    spu.run_command(("ash-u26-no-such-tool", "--y"))
    assert seen["args"] == ["/opt/bin/tool", "--y"]


def test_a_failure_of_the_resolution_itself_is_a_spawn_failure(monkeypatch):
    calls: List[Any] = []

    def resolution_fails(*args, **kwargs):
        calls.append(args[0])
        raise FileNotFoundError(2, "the working directory is gone")

    monkeypatch.setattr(spu, "_resolve_for_spawn", resolution_fails)
    monkeypatch.setattr(spu, "_runner", _fake_runner())
    # A name the lookup would resolve: the failure asserted below is the stand-in's,
    # not an earlier refusal of an unknown program.
    result = spu.run_command([sys.executable, "--version"])
    assert isinstance(result, spu.SpawnFailedProcess)
    assert result.returncode == spu.SPAWN_FAILURE_RETURNCODE
    response = spu.run_command_with_output_handling([sys.executable, "--version"])
    assert response["spawn_failed"] is True
    assert len(calls) == 2, "the resolution stand-in was not reached"
    # The failure reported is the resolution's own, carried as the error text.
    assert "the working directory is gone" in result.error
    assert "the working directory is gone" in response["error"]


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
    #: The scan's cancel event the stand-in sets between its two lines; given by
    #: the test that uses it (the autouse fixture clears it again).
    event: Any = None

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
    monkeypatch.setattr(_StreamingPopen, "event", event)
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


class _LingeringPopen(_FakeChild):
    """A child that ignores SIGTERM and prints one more line after it: the stop
    the watcher began must wait out its grace before anything kills the child."""

    instances: List["_LingeringPopen"] = []
    #: The scan's cancel event, given by the test that uses it (the autouse
    #: fixture clears it again).
    event: Any = None

    def __init__(self, args, **kwargs):
        super().__init__()
        self.args = list(args)
        self.event = _LingeringPopen.event
        self.terminated = threading.Event()
        self.ended = threading.Event()
        self.times: Dict[str, float] = {}
        _LingeringPopen.instances.append(self)
        self.stdout = self._lines()

    def _lines(self):
        yield "line one\n"
        self.event.set()
        # The read blocks until the SIGTERM, then one more line comes out.
        self.terminated.wait(_SILENT_BOUND)
        yield "line two\n"
        self.ended.wait(_SILENT_BOUND)

    def terminate(self):
        super().terminate()
        self.times["terminate"] = time.monotonic()
        self.terminated.set()  # the signal is ignored: no exit

    def kill(self):
        super().kill()
        self.times["kill"] = time.monotonic()
        self.ended.set()

    def wait(self, timeout=None):
        self.calls.append(("wait", timeout))
        if not self.ended.wait(_SILENT_BOUND):
            raise subprocess.TimeoutExpired(self.args, _SILENT_BOUND)
        return self.returncode if self.returncode is not None else 0


def test_a_line_printed_after_the_watchers_sigterm_does_not_cut_its_grace(
    monkeypatch,
):
    """The watcher sent SIGTERM and waits out the grace; the tool prints once
    more; the loop reads the cancel, and the cancel it raises must not put the
    finally's kill in front of the grace the watcher is still waiting out."""
    grace = 0.4
    event = CancelEvent()
    monkeypatch.setattr(_LingeringPopen, "event", event)
    monkeypatch.setattr(spu.subprocess, "Popen", _LingeringPopen)
    monkeypatch.setattr(spu, "_resolved_or_refused", lambda *a: None)
    monkeypatch.setattr(spu, "_prepare_spawn", lambda *a, **k: None)
    monkeypatch.setattr(spu, "_leads_its_own_group", lambda process: False)
    monkeypatch.setattr(spu, "_stop_grace", lambda cancel_event: grace)
    with cancellation.cancel_scope(event):
        with pytest.raises(ScanCancelled):
            spu.run_command_stream_output(["ash-u26-no-such-tool"])
    (child,) = _LingeringPopen.instances
    assert "terminate" in child.calls and "kill" in child.calls
    waited = child.times["kill"] - child.times["terminate"]
    assert waited >= grace * 0.8, f"the kill came {waited:.2f}s after the SIGTERM"


class _ReadFailsPopen(_FakeChild):
    """A child that ignores SIGTERM and whose output pipe then fails to read:
    the runner reaches its finally while the watcher still waits out the grace."""

    instances: List["_ReadFailsPopen"] = []
    event: Any = None

    def __init__(self, args, **kwargs):
        super().__init__()
        self.args = list(args)
        self.event = _ReadFailsPopen.event
        self.terminated = threading.Event()
        self.ended = threading.Event()
        self.closed = False
        _ReadFailsPopen.instances.append(self)
        self.stdout = self

    def __iter__(self):
        yield "line one\n"
        self.event.set()
        # The read blocks until the SIGTERM, then the pipe read fails.
        self.terminated.wait(_SILENT_BOUND)
        raise OSError(5, "read failed")

    def close(self):
        self.closed = True

    def terminate(self):
        super().terminate()
        self.terminated.set()  # the signal is ignored: no exit

    def kill(self):
        super().kill()
        self.ended.set()

    def wait(self, timeout=None):
        self.calls.append(("wait", timeout))
        if not self.ended.wait(_SILENT_BOUND):
            raise subprocess.TimeoutExpired(self.args, _SILENT_BOUND)
        return self.returncode if self.returncode is not None else 0


class _InterruptedEvent(CancelEvent):
    """A scan's cancel event that models a second Ctrl-C landing on the main
    thread while the finally waits out the grace the watcher's stop began: the
    grace read that the wait makes there raises, as an interrupt delivered at
    that point would. The watcher's own reads, on its thread, answer as usual."""

    def __init__(self):
        super().__init__()
        self.stop_began = threading.Event()

    @property
    def stop_promptly(self) -> bool:
        if (
            threading.current_thread() is threading.main_thread()
            and self.stop_began.is_set()
        ):
            raise KeyboardInterrupt
        return False


def test_a_second_interrupt_during_the_grace_wait_still_kills_the_child(
    monkeypatch,
):
    """The watcher's stop holds the grace; the runner is in its finally waiting
    for it; a second interrupt lands there. The child is still killed, reaped
    and its pipe closed before the interrupt leaves the runner: a wait that put
    those behind it skipped them all on the second Ctrl-C."""
    event = _InterruptedEvent()
    monkeypatch.setattr(_ReadFailsPopen, "event", event)
    monkeypatch.setattr(spu.subprocess, "Popen", _ReadFailsPopen)
    monkeypatch.setattr(spu, "_resolved_or_refused", lambda *a: None)
    monkeypatch.setattr(spu, "_prepare_spawn", lambda *a, **k: None)
    monkeypatch.setattr(spu, "_leads_its_own_group", lambda process: False)
    stop_child = spu._stop_child

    def stop_child_noting_the_start(*args, **kwargs):
        event.stop_began.set()
        return stop_child(*args, **kwargs)

    monkeypatch.setattr(spu, "_stop_child", stop_child_noting_the_start)
    with cancellation.cancel_scope(event):
        with pytest.raises(KeyboardInterrupt):
            spu.run_command_stream_output(["ash-u26-no-such-tool"])
    (child,) = _ReadFailsPopen.instances
    assert "kill" in child.calls, "the second interrupt skipped the kill"
    assert ("wait", None) in child.calls, "the killed child was not reaped"
    assert child.closed, "the output pipe was left open"


#: Every stand-in that records its instances at class level, and every one that is
#: handed a cancel event, for the autouse reset above.
_STAND_INS_WITH_INSTANCES = (
    _TimingOutPopen,
    _StreamingPopen,
    _SilentPopen,
    _LingeringPopen,
    _ReadFailsPopen,
)
_STAND_INS_WITH_AN_EVENT = (_StreamingPopen, _LingeringPopen, _ReadFailsPopen)


class _OneLinePopen(_FakeChild):
    """A child that prints one line and exits, for runs that never cancel."""

    def __init__(self, args, **kwargs):
        super().__init__()
        self.args = list(args)
        self.stdout = iter(["line one\n"])

    def wait(self, timeout=None):
        self.calls.append(("wait", timeout))
        self.returncode = 0 if self.returncode is None else self.returncode
        return self.returncode


def test_a_watcher_whose_start_raised_is_not_joined(monkeypatch):
    """ash_thread built the watcher, start() raised: the run is unrecorded and
    the child is killed and reaped, and the finally does not join a thread that
    never started (that join raises, and would hide the code behind it)."""
    children: List[_OneLinePopen] = []

    def popen(args, **kwargs):
        children.append(_OneLinePopen(args, **kwargs))
        return children[-1]

    monkeypatch.setattr(spu.subprocess, "Popen", popen)
    monkeypatch.setattr(spu, "_resolved_or_refused", lambda *a: None)
    monkeypatch.setattr(spu, "_prepare_spawn", lambda *a, **k: None)
    # The fake pid leads no group: asked of the host, the probe's answer for a
    # pid that is not a process depends on what the host is running.
    monkeypatch.setattr(spu, "_leads_its_own_group", lambda process: False)
    made: List[threading.Thread] = []

    def thread_that_cannot_start(target, *args, **kwargs):
        thread = threading.Thread(target=target, daemon=True)

        def start():
            raise RuntimeError("can't start new thread")

        thread.start = start  # type: ignore[method-assign]
        made.append(thread)
        return thread

    monkeypatch.setattr(spu, "ash_thread", thread_that_cannot_start)
    with cancellation.cancel_scope(CancelEvent()):
        code = spu.run_command_stream_output(["ash-u26-no-such-tool"])
    assert code == spu.UNRECORDED_RUN_RETURNCODE
    (thread,) = made
    # A thread that never started is not alive whatever the run did, so that
    # alone proves nothing: the child is what the run has to end and reap.
    assert not thread.is_alive()
    (child,) = children
    assert child.calls == ["kill", ("wait", None)], child.calls


def test_a_streamed_run_starts_nothing_in_a_cancelled_scan(monkeypatch):
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


# --- what an earlier test leaves behind ------------------------------------------------------


def test_a_test_starts_with_nothing_the_earlier_ones_left_behind():
    """Kept last in the file, after every test that fills a stand-in's class-level
    record, hands a stand-in a cancel event, or ends a child against the module's
    registries. The autouse reset must have emptied all of them again: an event
    left on the interrupt-raising stand-in would raise KeyboardInterrupt into
    whichever test reads it next, outside ``pytest.raises``, and a fake pid left
    in the registries would be read by the next test that ends a child."""
    for stand_in in _STAND_INS_WITH_INSTANCES:
        assert stand_in.instances == [], stand_in.__name__
    for stand_in in _STAND_INS_WITH_AN_EVENT:
        assert stand_in.event is None, stand_in.__name__
    assert spu._SERVER_KILLED == set()
    assert spu._RUNNING_GROUPS == {}
    assert spu._SPAWNS_STARTING == 0
    assert cancellation._TOOL_GROUPS == ()
