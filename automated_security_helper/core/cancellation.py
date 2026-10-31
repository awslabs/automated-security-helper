# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Stopping an in-process scan from outside it.

Why this exists
---------------
The MCP server runs each scan as ``run_ash_scan`` in a thread of its own process,
so ``cancel_scan`` has nothing to signal: there is no scan process to kill, and a
thread cannot be stopped from outside. Marking the scan cancelled in the registry
alone would leave the thread running every scanner to the end and writing the
results and reports of a scan the client had been told was cancelled.

So cancellation is cooperative. The runner sets a ``threading.Event`` as the
scan's cancel event with :func:`cancel_scope`, and the scan checks it at the
points where stopping is safe and worth it:

- before each phase (``ScanExecutionEngine.execute_phases``), so a scan cancelled
  during the scan phase writes no reports;
- before each scanner starts (``_safe_execute_scanner``), so queued scanners do
  not run;
- before each reporter runs and before what it returned is written
  (``ReportPhase``), which then removes the reports it had written, so a scan
  cancelled during the report phase leaves none of its reports;
- while waiting on a child process (``subprocess_utils``), so the scanner running
  at that moment is stopped, SIGTERM first and SIGKILL after a grace period, the
  way a timeout stops a sandboxed one;
- before the aggregated results file is written, by the scan phase and by
  ``run_ash_scan``'s rewrite after the last phase.

At each of them :func:`raise_if_cancelled` raises :class:`ScanCancelled`.

Why a context variable
----------------------
The event has to reach code several layers below the runner, through plugins
written against an API that has no place for it. A ``ContextVar`` reaches it
without changing that API, and it is scoped to the scan that set it: two
sessions' scans run in two threads of one process, and each sees only its own
event. A thread does not inherit context, so the scanner thread pools submit
each task with ``contextvars.copy_context().run``; without that, the scanners of
a parallel scan would never see the cancel.

Outside a scope (a CLI command that is not ``ash scan``, or a scan the MCP
server did not start) the variable is unset, every check is a no-op, and
subprocesses run with no cancel event. The CLI's ``ash scan`` enters a scope of
its own (cli/scan.py) so that a SIGTERM to the ASH process stops the scan the
way a timeout stops an MCP one; see the next section.

SIGTERM on the CLI
------------------
Without a handler, a SIGTERM to the ASH process is the default kill: no
``raise_if_cancelled`` ever fires, so no executor stop runs, and a scanner's
tool, its process group and its sandbox are left to their own ends.
:func:`install_sigterm_shutdown`, called by the console-script entry point
(cli/entrypoint.py) and nothing else, points SIGTERM at a handler that only
latches a lock-free flag on each scan event registered through
:func:`shutdown_cancels` (read as cancel and as ``stop_promptly`` both, so a
running tool gets the short grace a stdio shutdown gets), and returns. The
scan then unwinds through the same checks a timeout uses, and the subprocess
layer stops the running tool. The handler calls no stop and takes no lock:
every stop on that path can block (a runtime ``rm``, a grace wait,
``waitpid``) or takes locks the interrupted main thread may hold (logging
handlers, the executor's bookkeeping), and even an event's own ``set``
acquires a condition that thread holds whenever the signal lands inside the
event's ``wait`` -- a signal frame blocking on any of those deadlocks the
process.

The handler keeps SIGTERM's kill semantics where cooperation has no object:
with no registered scan, and on a second SIGTERM while the first is being
honored, it restores ``SIG_DFL`` and re-raises, so the process dies as it
would have without the handler instead of becoming unkillable. Those
branches first SIGKILL the recorded tool process groups (``os.killpg``, one
syscall, no lock, with one ``os.kill`` at the recorded pid when the kernel
refuses the group) and interrupt the launcher children recorded by plain pid --
the container runtime and the Nix shell share this process's group, so the
group kill cannot name them, and a kill would end the runtime client without
the container, or the inner ASH without its tools. The interrupt is the inner
ASH's second, so it takes its own die-now branch. A container that outlives
the die-now is removed by the next container-mode or nix-mode start
(``interactions/container_leftovers``, called from ``run_ash_scan``). The default kill ends this process alone and a
scanner's tool leads a session of its own: without those kills, the operator's
second SIGTERM orphaned the tool the first stop was still waiting out. A process
started with SIGTERM ignored keeps it ignored, for the reason
``cli.SIGINT_IGNORED_AT_START`` documents for SIGINT. The server paths are
unaffected: uvicorn and the stdio server install their own SIGTERM handling
over this one (cli/mcp), and the MCP runner's scans are stopped through their
registry entries, which this module's registry never touches. On Windows the
installer does nothing, deliberately: ``TerminateProcess`` ends a process
without running Python signal handlers, so a handler there would be dead code
pretending otherwise.

Limits
------
- A child process started by something other than ``subprocess_utils``
  (``jupyter_converter`` runs nbconvert directly) is waited for; the scan stops at
  the next check after it exits.
- Work under way in Python when the cancel comes finishes before the next check:
  a scanner reading its tool's output still writes its files under
  ``scanners/``, and a converter under ``converted/``. Nothing removes those but
  putting the previous results back, which replaces every result the scan wrote;
  its logs (``ash.log``, ``ash.log.jsonl``) stay, as they are not among
  ``previous_results.RESULT_ENTRIES``.
- The report phase removes the reports it wrote, by path. A reporter that
  writes a file of its own (``unused_suppressions_reporter`` writes its markdown
  beside the JSON the phase writes) leaves that file behind, unless previous
  results are put back over it.
- A workspace scan has an event per project, which its project's worker sets as
  its scope, and one for the run (workspace/execution.py). The run checks its own
  before writing the unified results and before the workspace reports, not while
  doing either, so a stop that arrives during one takes effect after it.
"""

from __future__ import annotations

import contextlib
import contextvars
import os
import signal
import threading
import time
from typing import Iterator, Optional, Tuple


class ScanCancelled(BaseException):
    """Raised inside a scan whose cancel event was set.

    A ``BaseException``, as ``asyncio.CancelledError`` is. ASH's phases, scanners
    and orchestrator catch ``Exception`` to record a failure and carry on, which
    is right for a scanner that broke and wrong for a cancel: caught there, the
    cancel would become one scanner's error and the scan would continue with the
    next one.

    ``could_not_stop`` carries the tools a stop could not end, as
    ``(tool, pid)`` pairs: data for the exit line, which names each one
    instead of matching the cancel's text. Raise sites that know the scan's
    event pass its accumulated records
    (:meth:`CancelEvent.could_not_stop_records`); others leave it empty.
    """

    def __init__(
        self,
        message: str,
        *,
        could_not_stop: Tuple[Tuple[str, int], ...] = (),
    ) -> None:
        super().__init__(message)
        self.could_not_stop = tuple(could_not_stop)


#: One slice of a cancel-event wait. The ``wait`` overrides below re-read the
#: chained state between slices, so a cause the underlying event cannot see
#: ends the wait at most one slice late.
_WAIT_SLICE_SECONDS = 0.05


def _poll_wait(event: threading.Event, timeout: Optional[float]) -> bool:
    """Wait like ``threading.Event.wait``, re-reading ``is_set`` every slice.

    ``event.is_set`` here is the subclass's chained read, so the wait ends
    for every cause the per-tick polls see: the local flag, an ancestor's
    cancel, and the SIGTERM handler's plain-store latch. None of those touch
    this event's own condition, so a plain ``Event.wait`` slept through them;
    entered one slice at a time, it can be late by at most one slice.
    """
    deadline = None if timeout is None else time.monotonic() + timeout
    while True:
        if event.is_set():
            return True
        if deadline is None:
            slice_seconds = _WAIT_SLICE_SECONDS
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return event.is_set()
            slice_seconds = min(_WAIT_SLICE_SECONDS, remaining)
        threading.Event.wait(event, slice_seconds)


class _ChainedPrompt(threading.Event):
    """A CancelEvent's prompt, answering for the event's ancestors too.

    ``is_set`` reads this event's own flag OR the SIGTERM handler's lock-free
    latch on the owner OR the owner's parent's ``stop_promptly``, so the grace
    wait's per-tick ``prompt.is_set()`` read
    (utils/subprocess_utils._wait_out_grace) sees any of them within one grace
    poll tick. ``wait`` polls the same read in slices (:func:`_poll_wait`):
    the plain event's wait blocked on the OWN flag only, so a wait already in
    flight was blind to a parent's prompt and to the handler's latch for its
    whole step. ``set`` and ``clear`` stay local, like the cancel flag's.
    """

    def __init__(self, owner: "CancelEvent") -> None:
        super().__init__()
        self._owner = owner

    def is_set(self) -> bool:
        if super().is_set() or self._owner._signalled:
            return True
        # Walk the ancestors here, with the seen set CancelEvent.is_set keeps,
        # and not by reading each parent's stop_promptly: that read recurses up
        # the chain, and two links made at once can close a cycle that the
        # unlocked cycle checks missed, which made it a RecursionError.
        seen = {id(self._owner)}
        parent = self._owner._parent
        while parent is not None and id(parent) not in seen:
            seen.add(id(parent))
            prompt = getattr(parent, "prompt", None)
            if not isinstance(prompt, _ChainedPrompt):
                # Not a CancelEvent: its own answer ends the climb.
                return bool(getattr(parent, "stop_promptly", False))
            if threading.Event.is_set(prompt) or parent._signalled:
                return True
            parent = parent._parent
        return False

    def wait(self, timeout: Optional[float] = None) -> bool:
        return _poll_wait(self, timeout)


class CancelEvent(threading.Event):
    """A scan's cancel event, with how quickly a cancel must take effect.

    ``stop_promptly`` is set when the process itself is going away (a stdio
    client closed the connection, or the server got SIGTERM): the scanner tool
    running then gets PROMPT_STOP_GRACE_SECONDS after SIGTERM instead of the usual
    grace, because the client that started the server kills it two seconds
    later (utils/subprocess_utils._stop_grace).

    It is backed by an event of its own, ``prompt``, so a stop already waiting out
    the usual grace when it is set wakes at once and shortens the wait
    (utils/subprocess_utils._wait_out_grace): SIGTERM can arrive in the middle of a
    stop a cancel began.

    Events nest through ``parent``: a workspace run holds one event for the
    run and one per project, and the project's checks run under the project
    event's scope, so without a link a cancel of the RUN was invisible there.
    ``is_set`` and ``stop_promptly`` answer for this event OR any ancestor,
    while ``set`` stays local, so cancelling one project never stops its
    siblings or the run. The parent is given at construction (a per-project
    event is built on the main thread, since the pool worker that enters its
    scope has no ambient context to link from) or recorded by
    :func:`cancel_scope` at entry when the event has none yet. A link is
    never removed: a cancel chain is one-shot, and unlinking at scope exit
    would race the grace wait still reading it. Pollers see a parent's
    cancel at their next check; ``wait`` polls the same chained read in
    slices (:func:`_poll_wait`), so what ``is_set`` reports ends a blocking
    wait at most one slice late instead of never.
    """

    #: Written by the SIGTERM handler instead of ``set``: a plain store takes
    #: no lock, where ``Event.set`` acquires a condition the interrupted main
    #: thread may hold inside this event's own ``wait``. One-shot, never
    #: cleared. Read by ``is_set`` and the prompt; pollers see it at their
    #: next check, the polling waits within a slice.
    _signalled = False

    def __init__(self, parent: Optional[threading.Event] = None) -> None:
        super().__init__()
        self._parent = parent
        self._signalled = False
        self._could_not_stop: Tuple[Tuple[str, int], ...] = ()
        self.prompt = _ChainedPrompt(self)

    def _record_root(self) -> "CancelEvent":
        """The chain's topmost CancelEvent, where could-not-stop records live.

        The scan-wide scope the CLI registered is an ancestor of a pool
        project's event, so recording on the root is what lets the exit line
        see a project's record. A parent that is a plain Event ends the climb.
        """
        seen = {id(self)}
        node = self
        parent = node._parent
        while isinstance(parent, CancelEvent) and id(parent) not in seen:
            node = parent
            seen.add(id(node))
            parent = node._parent
        return node

    def note_could_not_stop(self, tool: str, pid: int) -> None:
        """Record a tool a stop could not end, on the chain's root.

        Written by the subprocess layer on a normal thread frame, under a
        writer lock with whole-tuple replacement, so readers never take the
        lock and the signal handler's no-lock rules are untouched (it never
        writes here).
        """
        root = self._record_root()
        with _COULD_NOT_STOP_WRITE_LOCK:
            root._could_not_stop = root._could_not_stop + ((str(tool), int(pid)),)

    def could_not_stop_records(self) -> Tuple[Tuple[str, int], ...]:
        """The chain's recorded ``(tool, pid)`` pairs, read from the root."""
        return self._record_root()._could_not_stop

    def is_set(self) -> bool:
        seen = set()
        node: Optional[threading.Event] = self
        while node is not None and id(node) not in seen:
            if threading.Event.is_set(node) or getattr(node, "_signalled", False):
                return True
            seen.add(id(node))
            node = getattr(node, "_parent", None)
        return False

    def wait(self, timeout: Optional[float] = None) -> bool:
        return _poll_wait(self, timeout)

    @property
    def stop_promptly(self) -> bool:
        return self.prompt.is_set()

    @stop_promptly.setter
    def stop_promptly(self, value: bool) -> None:
        if value:
            self.prompt.set()
        else:
            self.prompt.clear()


#: Orders concurrent could-not-stop writers (two scanners' stops refused at
#: once); readers never take it, they read one tuple reference.
_COULD_NOT_STOP_WRITE_LOCK = threading.Lock()


def _chains_to(event: threading.Event, target: threading.Event) -> bool:
    """Whether *target* is *event* or one of its ancestors."""
    seen = set()
    node: Optional[threading.Event] = event
    while node is not None and id(node) not in seen:
        if node is target:
            return True
        seen.add(id(node))
        node = getattr(node, "_parent", None)
    return False


#: Orders the cycle check and the parent store of the two linking paths
#: (:func:`cancel_scope`, :func:`link_parent`). Unlocked, two threads linking
#: two events to each other each saw no cycle and each stored its link, closing
#: one. Only normal thread frames take it; the signal handlers never do.
_PARENT_LINK_LOCK = threading.Lock()


def _link_if_unlinked(event: "CancelEvent", parent: threading.Event) -> None:
    """Chain *event* to *parent* when it has no parent and no cycle would close."""
    with _PARENT_LINK_LOCK:
        if event._parent is None and not _chains_to(parent, event):
            event._parent = parent


_CANCEL_EVENT: contextvars.ContextVar[Optional[threading.Event]] = (
    contextvars.ContextVar("ash_scan_cancel_event", default=None)
)


@contextlib.contextmanager
def cancel_scope(event: threading.Event) -> Iterator[None]:
    """Run the enclosed code as a scan that ``event`` cancels.

    A :class:`CancelEvent` entering a scope with no parent of its own takes
    the ambient event as its parent, so a cancel of the enclosing scan
    reaches checks made under this one. An event already chained to (or
    being) the ambient one is left alone, so no chain can become a cycle.
    """
    if isinstance(event, CancelEvent) and event._parent is None:
        ambient = _CANCEL_EVENT.get()
        if ambient is not None:
            _link_if_unlinked(event, ambient)
    token = _CANCEL_EVENT.set(event)
    try:
        yield
    finally:
        _CANCEL_EVENT.reset(token)


def link_parent(event: threading.Event, parent: Optional[threading.Event]) -> None:
    """Chain *event* to *parent*, under :func:`cancel_scope`'s exact guards.

    For events constructed where their parent is not in scope: the workspace
    pool's per-project events are built on the submitting thread (by the
    caller, or by the pool itself), and the pool worker that enters their
    scope has no ambient context for :func:`cancel_scope`'s own linking to
    read, so without this call a cancel of the whole scan never reached
    them. The submitting thread, which does see the scan-wide event, links
    them here instead.

    The guards are :func:`cancel_scope`'s: only a :class:`CancelEvent` that
    has no parent yet is linked, a parent of None links nothing, and a link
    that would close a cycle (*parent* already chains to *event*) is
    refused. A link is never removed (see :class:`CancelEvent`).
    """
    if not isinstance(event, CancelEvent) or parent is None:
        return
    _link_if_unlinked(event, parent)


def current_cancel_event() -> Optional[threading.Event]:
    """The cancel event of the scan running in this context, or None outside one."""
    return _CANCEL_EVENT.get()


def raise_if_cancelled() -> None:
    """Raise :class:`ScanCancelled` if this context's scan has been cancelled.

    The raise carries the chain's could-not-stop records, so the cancel that
    reaches the CLI names the tools a stop could not end even when the
    exception that first said so was handled on the way.
    """
    event = _CANCEL_EVENT.get()
    if event is not None and event.is_set():
        records = (
            event.could_not_stop_records() if isinstance(event, CancelEvent) else ()
        )
        raise ScanCancelled("the scan was cancelled", could_not_stop=records)


#: Latched by the SIGTERM handler before anything else. Read on re-entry: a
#: second SIGTERM finds it set and takes the default-kill branch, so an
#: operator who asks twice gets the process gone rather than the cooperative
#: path again.
_SIGTERM_SEEN = False

#: The scan events a SIGTERM cancels. Replaced as a whole tuple, never mutated,
#: so the handler reads a consistent snapshot without taking a lock.
_SHUTDOWN_SCOPES: Tuple[CancelEvent, ...] = ()

#: Set once the handler has cancelled the registered scopes: a plain bool,
#: not an Event, because the handler writes it with the interrupted frame's
#: locks unknowable and ``Event.set`` takes one. Read by
#: :func:`shutdown_requested` and by :func:`shutdown_cancels`, so a scope
#: that registers after the signal (a worker thread entering while the main
#: thread handles it) is cancelled at once rather than running a scan nobody
#: can stop again.
_SHUTDOWN_REQUESTED = False

#: The disposition :func:`install_sigterm_shutdown` replaced. Chained when it is
#: a Python handler; ``SIG_DFL`` and a C-level handler (``getsignal``'s None) are
#: not callable and are covered by the default-kill branches instead.
_PREVIOUS_SIGTERM: object = None

#: Latched by the SIGINT handler before anything else, as
#: :data:`_SIGTERM_SEEN` is: a second Ctrl-C finds it set and takes the
#: die-now branch, so an operator who asks twice gets the process gone --
#: recorded tools along -- rather than another interrupt that aborts the
#: grace wait and leaves the tool running.
_SIGINT_SEEN = False

#: The disposition :func:`install_sigint_shutdown` replaced: normally the
#: interpreter's ``default_int_handler``, whose ``KeyboardInterrupt`` the
#: first-interrupt branch chains to, so Ctrl-C keeps driving the command's
#: own interrupt arm.
_PREVIOUS_SIGINT: object = None

#: The process groups of the scanner tools running now. The handler's
#: default-kill branches take them along: ``SIG_DFL`` ends this process alone,
#: and each tool leads a session and group of its own, so an operator's "die
#: now" would otherwise orphan the tool a cooperative stop was still waiting
#: out. Written by the subprocess layer beside its own lock-guarded registry
#: (utils/subprocess_utils), as a whole-tuple replacement under a writer lock;
#: the handler reads the reference without any lock, as it must.
_TOOL_GROUPS: Tuple[int, ...] = ()
_TOOL_GROUPS_WRITE_LOCK = threading.Lock()

#: Launcher children that lead no process group of their own (the direct and
#: shell launchers' children share this process's group), recorded by plain
#: pid for the same die-now branches: ``killpg`` on a non-leader's pid is
#: ESRCH or the wrong group, so these are interrupted one ``os.kill`` at a time.
#: Same idiom and the same writer lock as :data:`_TOOL_GROUPS`: whole-tuple
#: replacement under the lock, lock-free reads in the handler. The reuse
#: hazard is sharper here, since a single pid is reused faster than a pgid.
_TOOL_PIDS: Tuple[int, ...] = ()


def record_tool_group(pgid: int) -> None:
    """Mirror a running tool's process group for the handler's die-now kill.

    For the subprocess layer only, beside its own registry: the handler cannot
    take that registry's lock, so it reads this tuple instead. The writer lock
    orders concurrent spawns; readers never take it.
    """
    global _TOOL_GROUPS
    with _TOOL_GROUPS_WRITE_LOCK:
        if pgid not in _TOOL_GROUPS:
            _TOOL_GROUPS = _TOOL_GROUPS + (pgid,)


def discard_tool_group(pgid: int) -> None:
    """Forget a tool group once its child is reaped or forgotten.

    A reaped child's pid can be reused, so a group must not stay recorded past
    the registry forgetting its child: a stale entry would aim the die-now
    SIGKILL at whatever process group holds that id next.
    """
    global _TOOL_GROUPS
    with _TOOL_GROUPS_WRITE_LOCK:
        if pgid in _TOOL_GROUPS:
            _TOOL_GROUPS = tuple(g for g in _TOOL_GROUPS if g != pgid)


def record_tool_pid(pid: int) -> None:
    """Mirror a launcher child that leads no group of its own.

    For the subprocess layer only, as :func:`record_tool_group`: the handler
    cannot take the registry's lock, so it reads this tuple instead.
    """
    global _TOOL_PIDS
    with _TOOL_GROUPS_WRITE_LOCK:
        if pid not in _TOOL_PIDS:
            _TOOL_PIDS = _TOOL_PIDS + (pid,)


def discard_tool_pid(pid: int) -> None:
    """Forget a recorded child the moment its exit is observed, BEFORE the reap.

    A reaped pid is reused faster than a pgid, so a stale entry here aims the
    die-now SIGINT at whatever process holds that pid next -- an interrupt that
    process did not ask for, which it may ignore -- and so does an entry
    discarded after the reap, for the window between the two. The
    callers observe the exit without reaping (``os.waitid`` with ``WNOWAIT``,
    utils/subprocess_utils.discard_tool_pid_once_exited), discard, then reap.
    """
    global _TOOL_PIDS
    with _TOOL_GROUPS_WRITE_LOCK:
        if pid in _TOOL_PIDS:
            _TOOL_PIDS = tuple(p for p in _TOOL_PIDS if p != pid)


#: Files the die-now endings must remove before the default kill: each entry
#: is a file a launcher wrote the operator's environment values into, inside
#: a private temp directory of its own, both normally removed by the run
#: step's ``finally``. The die-now endings re-raise under ``SIG_DFL``, so no
#: ``finally`` runs and the values would stay on disk. Same idiom and the
#: same writer lock as :data:`_TOOL_GROUPS`: whole-tuple replacement under
#: the lock, lock-free reads in the handler.
_CLEANUP_FILES: Tuple[str, ...] = ()


def record_die_now_cleanup(path: "str | os.PathLike[str]") -> None:
    """Record a values-holding temp file the die-now endings must remove.

    For a launcher that writes environment values to disk for its child (the
    container runtime's env file) while its run step is active. The recorded
    path's parent directory is removed with it, because the launcher makes a
    private directory per file; the walk's ``rmdir`` refuses a directory
    holding anything else, so a shared parent is never swept.
    """
    global _CLEANUP_FILES
    name = os.fspath(path)
    with _TOOL_GROUPS_WRITE_LOCK:
        if name not in _CLEANUP_FILES:
            _CLEANUP_FILES = _CLEANUP_FILES + (name,)


def discard_die_now_cleanup(path: "str | os.PathLike[str]") -> None:
    """Forget a recorded cleanup file once the launcher's own removal ran.

    After the run step's ``finally`` the path may be reused by someone else,
    so a stale entry would aim the die-now removal at a file this process no
    longer owns.
    """
    global _CLEANUP_FILES
    name = os.fspath(path)
    with _TOOL_GROUPS_WRITE_LOCK:
        if name in _CLEANUP_FILES:
            _CLEANUP_FILES = tuple(p for p in _CLEANUP_FILES if p != name)


def _remove_die_now_cleanups() -> None:
    """Remove the recorded values-holding files, for the default-kill endings.

    ``os.unlink`` and ``os.rmdir`` are one syscall each and the tuple one
    reference load, all safe in the signal frame, like the kills beside this
    walk: no lock, no logger, no context manager (an interrupted frame may
    hold any of those). A removal the OS refuses -- the file already gone,
    the directory holding something else -- is left as it is: the process is
    about to die either way, and a raise here would replace the default kill
    with a traceback.
    """
    for name in _CLEANUP_FILES:
        try:
            os.unlink(name)
        except OSError:
            pass
        try:
            os.rmdir(os.path.dirname(name))
        except OSError:
            pass


def _is_live_child(pid: int) -> bool:
    """Whether *pid* is a child of this process that has not exited.

    ``waitpid(pid, WNOHANG)`` answers in one syscall: ``(0, 0)`` for a running
    child, the pid for one that exited (it is reaped here, which the die-now
    path can afford: the process is about to die), and ECHILD for a pid that
    is not this process's child, which is what a reaped child's pid becomes
    once another process holds it. Anything else, including a platform with
    no ``WNOHANG``, reads as not a live child, so no signal is sent on a guess.
    """
    flag = getattr(os, "WNOHANG", None)
    if flag is None:
        return False
    try:
        reaped, _status = os.waitpid(pid, flag)
    except OSError:
        return False
    return reaped == 0


def _kill_recorded_groups() -> None:
    """SIGKILL every recorded tool group, and interrupt every recorded pid.

    The groups are scanner tools that lead a session of their own, and the
    kill is right for them. The pids are launcher children that share this
    process's group: a container runtime client, or the inner ASH a Nix shell
    runs. A kill would end the runtime client alone and leave the container
    running, and would land on the inner ASH in the middle of its own stop and
    orphan the tools it was stopping. An interrupt is the inner ASH's second
    one, so it takes its own die-now branch and ends its tools, and a runtime
    client hands it on to the container. That is one interrupt with no
    escalation after it: a handler can do one syscall per pid and has no place
    to wait, so a child that ignores the interrupt is left running, and a
    container it was running is removed by the next container-mode or nix-mode
    start.

    ``os.killpg`` and ``os.kill`` are one syscall each and the tuple reads one
    reference load, all safe in the signal frame. A group or pid already gone,
    or one the kernel refuses, is left to its end: the process is about to die
    either way, and a raise here would replace the default kill with a
    traceback.
    """
    for pgid in _TOOL_GROUPS:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except OSError:
            # The recorded id is the child's pid. A child recorded before its
            # setsid leads no group of its own, so the group kill is ESRCH
            # while the child lives; one os.kill at the pid reaches it, as
            # the subprocess layer's _kill_group falls back for that child.
            # Only while that pid is still a live child of this process: a
            # group id left recorded after its child was reaped (the discard
            # never ran) is a pid another process can hold by now, and the
            # fallback kill landed on it. One waitpid(WNOHANG) tells the two
            # apart in one syscall, as the signal frame allows.
            if _is_live_child(pgid):
                try:
                    os.kill(pgid, signal.SIGKILL)
                except OSError:
                    pass
    for pid in _TOOL_PIDS:
        try:
            os.kill(pid, signal.SIGINT)
        except OSError:
            pass


#: How many stops are waiting out a tool's grace period right now (SIGTERM sent,
#: SIGKILL to follow when the grace ends). Written under its lock by
#: :func:`stop_grace_in_progress` on normal thread frames; read without the lock
#: by the SIGINT handler, one integer load, as the signal frame allows.
_GRACE_WAITS = 0
_GRACE_WAITS_WRITE_LOCK = threading.Lock()


@contextlib.contextmanager
def stop_grace_in_progress() -> Iterator[None]:
    """While inside, a first Ctrl-C latches the cancel but does not interrupt.

    For the subprocess layer's grace wait (``utils/subprocess_utils
    ._wait_out_grace``): a stop a TIMEOUT began (SIGTERM sent, the grace being
    waited out, SIGKILL to follow) is not a signal, so a first Ctrl-C during it
    found neither latch set and chained the default handler, which raised
    KeyboardInterrupt in the main thread's grace wait and aborted the SIGKILL
    escalation the second-signal branch protects: a SIGTERM-ignoring tool then
    outlived the exit. Inside this context the first Ctrl-C still latches every
    registered scan's cancel (the scan unwinds through the same checks a cancel
    uses once the stop returns), and the stop completes its escalation. The
    interrupt is held back only while a scan is registered
    (``shutdown_cancels``): with none, nothing would unwind on the latch, so the
    first Ctrl-C stays an interrupt. The count is process-wide, as the handler
    is.
    """
    global _GRACE_WAITS
    entered = False
    # The count is raised inside the try, so an interrupt that lands after the
    # increment still reaches the finally, which lowers it only if it was raised.
    try:
        with _GRACE_WAITS_WRITE_LOCK:
            _GRACE_WAITS += 1
            entered = True
        yield
    finally:
        if entered:
            with _GRACE_WAITS_WRITE_LOCK:
                _GRACE_WAITS -= 1


def shutdown_requested() -> bool:
    """Whether a shutdown signal has asked this process's registered scans to stop.

    Set by the SIGTERM handler and by the SIGINT handler's first interrupt:
    either way the process is unwinding, so a scope that registers after the
    signal is cancelled at once (:func:`shutdown_cancels`).
    """
    return _SHUTDOWN_REQUESTED


def shutdown_scopes_registered() -> bool:
    """Whether any scan is registered for the shutdown handlers to stop.

    The SIGTERM handler cooperates only while :func:`shutdown_cancels` holds a
    registration; with none it keeps SIGTERM's kill semantics and dies at
    once. A wrapper deciding whether to leave the handler in charge must read
    this same condition rather than a stand-in such as the ambient cancel
    event: :func:`cancel_scope` has a different owner (see
    :func:`shutdown_cancels`), so a scope can be active with nothing
    registered, and gating on the event there keeps a handler whose first
    signal takes the no-scan die-now.
    """
    return bool(_SHUTDOWN_SCOPES)


def _handle_sigterm(signum: int, frame: object) -> None:
    """Stop the registered scans the way a timeout stops them, then return.

    Runs on the main thread between two of its bytecodes, so it takes no lock
    at all: every real stop (the runtime ``rm``, the grace waits, ``waitpid``)
    blocks, and the interrupted frame may hold the locks those stops and the
    logger take -- including each event's own condition, when the signal lands
    while the main thread is inside that event's ``wait`` (the grace wait,
    utils/subprocess_utils._wait_out_grace). ``Event.set`` there deadlocks the
    process under its own interrupted frame, so the latch is one plain store
    per event (``_signalled``), which ``is_set``, ``stop_promptly`` and the
    polling waits all read. The subprocess layer's cancel polling and the
    phase checks see it within their poll interval and unwind in their own
    frames.
    """
    global _SIGTERM_SEEN, _SHUTDOWN_REQUESTED
    if _SIGTERM_SEEN or _SIGINT_SEEN:
        # The operator asked twice -- with two SIGTERMs or with a Ctrl-C and
        # then a SIGTERM; the second shutdown signal of either kind means
        # they want the process gone more than they want the cleanup. Die as
        # SIG_DFL would have, taking the recorded tool groups along: the
        # default kill ends this process alone, and the tool the first stop
        # was still waiting out leads a session of its own, with nobody left
        # to stop it once this process is gone. The recorded values-holding
        # temp files go the same way: no finally runs after SIG_DFL, so the
        # launcher's own removal never would.
        _kill_recorded_groups()
        _remove_die_now_cleanups()
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.raise_signal(signal.SIGTERM)
        return
    _SIGTERM_SEEN = True
    # Published BEFORE the scopes are read. shutdown_cancels appends its event
    # and then reads this flag, so with the flag first, a registration is seen
    # by one side or the other: either the append is in the snapshot below, or
    # the registrar's read finds the flag set. Read in the other order, an
    # append between the snapshot and the store was seen by neither.
    _SHUTDOWN_REQUESTED = True
    scopes = _SHUTDOWN_SCOPES
    if not scopes:
        # No scan to stop cooperatively: keep SIGTERM's kill semantics rather
        # than leave a hung non-scan command unkillable. Any recorded tool
        # goes along for the same reason as above, and so does any recorded
        # values-holding temp file.
        _kill_recorded_groups()
        _remove_die_now_cleanups()
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.raise_signal(signal.SIGTERM)
        return
    for event in scopes:
        # The process is going away: the running tool gets the short grace a
        # stdio shutdown gets (subprocess_utils._stop_grace). The flag covers
        # cancel and prompt both: a plain store, never ``set``.
        event._signalled = True
    previous = _PREVIOUS_SIGTERM
    if callable(previous):
        previous(signum, frame)


def _handle_sigint(signum: int, frame: object) -> None:
    """Latch the registered scans on the first Ctrl-C; die now on the second.

    The same no-lock rules as :func:`_handle_sigterm`: the latch is one plain
    store per event, and the die-now kills are one syscall each. The first
    interrupt stays an interrupt -- the chained default handler raises
    ``KeyboardInterrupt``, which drives the command's own interrupt arm and
    its cleanup -- while the latch lets a cancellable spawn polling in
    another thread stop within its poll interval instead of waiting for that
    arm's unwinding. Unlike SIGTERM's no-scan branch, a first Ctrl-C with no
    scan registered kills nothing: ``KeyboardInterrupt`` unwinds and the
    cleanup runs.

    A second shutdown signal of either kind -- another Ctrl-C, or a Ctrl-C
    after a SIGTERM already started the cooperative stop -- means the
    operator wants the process gone more than they want the cleanup. The recorded
    tool groups are killed -- each scanner tool leads a session and group of
    its own, so another interrupt alone would orphan the tool the first stop
    was still waiting out -- and the recorded launcher children are
    interrupted, which is the second interrupt of the inner ASH they run and
    so ends its own tools. The process then dies as an interrupted process
    does, by SIGINT under the default disposition, which a shell reports as
    130.
    """
    global _SIGINT_SEEN, _SHUTDOWN_REQUESTED
    if _SIGINT_SEEN or _SIGTERM_SEEN:
        # Either latch: a Ctrl-C inside a SIGTERM stop's grace is the
        # operator's second shutdown signal, and chaining the interrupt
        # instead would land KeyboardInterrupt in the main thread's grace
        # wait, aborting the stop before its own escalation -- a
        # SIGTERM-ignoring tool then outlives the 130 exit. The recorded
        # values-holding temp files go along too: no finally runs after
        # SIG_DFL, so the launcher's own removal never would.
        _kill_recorded_groups()
        _remove_die_now_cleanups()
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.raise_signal(signal.SIGINT)
        return
    _SIGINT_SEEN = True
    # Published before the scopes are read and whether or not any is
    # registered, as shutdown_requested() promises: a scope that registers
    # after this Ctrl-C is cancelled at once, and one that registers while
    # this runs is seen by the snapshot or by its own read of the flag (see
    # _handle_sigterm).
    _SHUTDOWN_REQUESTED = True
    scopes = _SHUTDOWN_SCOPES
    for event in scopes:
        # The same plain store as the SIGTERM handler's, for the same
        # deadlock reason; it covers cancel and prompt both.
        event._signalled = True
    if _GRACE_WAITS > 0 and scopes:
        # A stop is waiting out a tool's grace (stop_grace_in_progress) and a
        # scan is registered to unwind on the latch above: the latch is what
        # this Ctrl-C asks for, and chaining the default handler would raise
        # KeyboardInterrupt inside that wait and abort the SIGKILL escalation.
        # The stop completes; the scan unwinds after it. With no scan
        # registered nothing reads the latch, so swallowing the interrupt
        # here would leave the Ctrl-C without any effect: it stays an
        # interrupt, as below.
        return
    # The first interrupt stays an interrupt. A previous disposition that is
    # not a Python callable (SIG_DFL, or a handler set in C) has nothing to
    # chain to, and skipping it left the Ctrl-C without any effect, so the
    # interpreter's own handler raises KeyboardInterrupt in its place.
    previous = _PREVIOUS_SIGINT
    if not callable(previous):
        previous = signal.default_int_handler
    previous(signum, frame)


@contextlib.contextmanager
def shutdown_cancels(event: CancelEvent) -> Iterator[None]:
    """While inside, a SIGTERM to this process cancels *event*.

    Registration is its own context manager rather than part of
    :func:`cancel_scope` because the two have different owners: the MCP runner
    enters ``cancel_scope`` with an event its registry stops, and registering
    that one here would hand the CLI handler a scan the server owns.

    Only a :class:`CancelEvent` registers. The handler and the die-now walk
    read CancelEvent's own state (``stop_promptly``, the latch), so a plain
    ``threading.Event`` would register, satisfy nothing the handler sets,
    and silently miss the shutdown's cancellation mechanics.
    """
    if not isinstance(event, CancelEvent):
        raise TypeError(
            f"shutdown_cancels registers only CancelEvent, not {type(event).__name__}"
        )
    global _SHUTDOWN_SCOPES
    # The same writer discipline as the registry helpers above: the tuple is
    # rebuilt and swapped under the writer lock, because two threads
    # rebuilding it at once each read the same old tuple and the second
    # store erases the first thread's registration. The handlers keep
    # reading the tuple lock-free, so a signal landing while the lock is
    # held cannot deadlock on it.
    registered = False
    try:
        # The append sits inside the try so an interrupt delivered at the
        # lock's exit, after the store has landed, still reaches the finally
        # and unregisters the event. The same event can be registered more than
        # once (an inner scope around an outer one), so the finally removes one
        # copy, and only if this call reached the store: the flag is set just
        # before it, so an interrupt in between removes a copy at worst and
        # never leaves a registration behind.
        with _TOOL_GROUPS_WRITE_LOCK:
            registered = True
            _SHUTDOWN_SCOPES = _SHUTDOWN_SCOPES + (event,)
        # After the append, so a signal between the two lines is seen by one
        # side or the other, never neither. This arm runs on a normal thread
        # frame, so real ``set`` calls are safe here where the handler's are
        # not.
        if _SHUTDOWN_REQUESTED:
            event.stop_promptly = True
            event.set()
        yield
    finally:
        if registered:
            with _TOOL_GROUPS_WRITE_LOCK:
                scopes = list(_SHUTDOWN_SCOPES)
                for index in range(len(scopes) - 1, -1, -1):
                    if scopes[index] is event:
                        del scopes[index]
                        break
                _SHUTDOWN_SCOPES = tuple(scopes)


def install_sigterm_shutdown() -> None:
    """Point SIGTERM at :func:`_handle_sigterm`. The CLI entry point calls this.

    Nothing else does, and never at import time: a library import that installed
    a handler would hand every embedder (the MCP server, pytest, an in-process
    caller) a changed signal disposition it did not ask for. The module
    docstring's "SIGTERM on the CLI" section is the contract. Idempotent, and a
    no-op on Windows and for a process that started with SIGTERM ignored.
    """
    global _PREVIOUS_SIGTERM
    if os.name != "posix":
        return
    current = signal.getsignal(signal.SIGTERM)
    if current == signal.SIG_IGN or current is _handle_sigterm:
        return
    _PREVIOUS_SIGTERM = current
    signal.signal(signal.SIGTERM, _handle_sigterm)


def install_sigint_shutdown() -> None:
    """Point SIGINT at :func:`_handle_sigint`. The CLI entry point calls this.

    The same contract as :func:`install_sigterm_shutdown`: never at import
    time, idempotent, a no-op on Windows and for a process that started with
    SIGINT ignored (a shell's background job, the reason
    ``cli.SIGINT_IGNORED_AT_START`` documents). The server paths install
    their own SIGINT handling over this one once they start.
    """
    global _PREVIOUS_SIGINT
    if os.name != "posix":
        return
    current = signal.getsignal(signal.SIGINT)
    if current == signal.SIG_IGN or current is _handle_sigint:
        return
    _PREVIOUS_SIGINT = current
    signal.signal(signal.SIGINT, _handle_sigint)
