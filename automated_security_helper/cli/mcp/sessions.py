# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Per-connection MCP session lifecycle and registry.

A *session* is the slice of state the MCP server holds for a single client
connection: its workspace scratch directory, and the locks, claims and counts
that keep a scan, a change to the delivered tree, a write and the TTL sweep from
running over one another. What a client bound to the session lives in two other
stores, both keyed by the session id: the delivered source directory in
``source_delivery`` and the selected profile, its config and its patch ops in
``profile_registry``. Those stores are the only source of truth for a binding;
the ``MCPSession`` object holds none of it. Sessions are NEVER serialized (they
hold a live ``threading.Lock``) and are NEVER shared across clients (the
workspace_root is per-connection scratch).

The module exposes:

* ``MCPSession`` — Pydantic model describing the per-connection slice of state,
  with a ``PrivateAttr`` lock that serializes scans within a single session.
* ``MCPSessionRegistry`` — process-local map of ``connection_id -> MCPSession``
  guarded by an ``RLock``, plus ``disconnect()`` which rmtrees the workspace
  and drops the entry.
* ``get_default_registry`` — module-level singleton getter.
* :func:`end_session` — remove everything the server holds for a session that
  has ended, and :func:`sweep_stale_workspaces`, the TTL sweep for sessions
  whose end the server never sees.

Cross-session scans don't share locks, so two distinct sessions can scan in
parallel; same-session scans serialize on the per-session lock.

When a session ends
-------------------
The MCP SDK exposes no stable session-end callback, so the ends are observed
where ASH can see them: ``http_sessions.SessionBoundary`` calls
:func:`end_session` when a stateful session's ``DELETE`` is answered, when the
SDK answers 404 on its session path for a session this app issued (it discarded
the session, after its idle timeout for one, and a client asked about it
again), when an sse event stream closes, and for every session an app issued
when the app shuts down; ``mcp_server.run_mcp_server`` ends the stdio session
when the last stdio server sharing the root exits (``StdioServerPresence``). A
stateless server sees no end at all, and a stateful session the SDK closed for
being idle that no client asks about again sends nothing ASH could see, so
:func:`sweep_stale_workspaces` removes workspaces nobody used for longer than a
TTL, on every HTTP transport.

The registry's workspace directory is the session's sandbox under
``source_delivery.resolve_workspace_root()``, the directory source delivery
writes, so ending a session removes the tree that was delivered to it.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Set

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr
from typing_extensions import Self

from automated_security_helper.cli.mcp.session_paths import (
    SESSION_MARKER,
    mark_session_workspace,
    session_directory,
    validated_path_component,
)


class ScanCount:
    """Scans counted against the per-session limit and not yet returned.

    Each session has one (:meth:`MCPSession.try_start_scan`), and every caller
    with no session shares one more (:func:`sessionless_scan_count`).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._running = 0

    def try_start_scan(self, limit: Optional[int]) -> bool:
        """Count a scan as running, unless ``limit`` already are.

        Counted and checked under one lock, so two calls at once can't both take
        the last place. ``None`` is no limit. Each True is paired with one
        :meth:`scan_returned`, once nothing of that scan runs any more.
        """
        with self._lock:
            if limit is not None and self._running >= limit:
                return False
            self._running += 1
            return True

    def scan_returned(self) -> None:
        """Uncount a scan :meth:`try_start_scan` counted."""
        with self._lock:
            self._running = max(0, self._running - 1)

    def is_running(self) -> bool:
        """Whether a counted scan has not returned yet."""
        with self._lock:
            return self._running > 0


#: Why :meth:`MCPSession.try_begin_write` refused: the TTL sweep is removing the
#: session, so its state is gone once it is done.
WRITE_REFUSED_BY_SWEEP = "sweep"

#: Why :meth:`MCPSession.try_begin_write` refused: a change that deletes the
#: session's directory (``clear_source`` or the end of the session) holds it.
#: Its removal may or may not have reached the upload's files yet.
WRITE_REFUSED_BY_CHANGE = "change"

#: Why :meth:`MCPSession.try_begin_change` refused: a scan of the session holds
#: its lock, or has started and not yet returned (``try_claim_scan``).
CHANGE_REFUSED_BY_SCAN = "scan"

#: Why :meth:`MCPSession.try_begin_change` refused: another change holds the
#: session (a delivery, a clear, the end of the session, or the removal of an
#: idle session).
CHANGE_REFUSED_BY_CHANGE = "other-change"

#: Why :meth:`MCPSession.try_begin_change` refused: the change would delete the
#: session's directory while a chunk of an upload or a profile binding is
#: being written into it.
CHANGE_REFUSED_BY_WRITE = "write"


#: Why :meth:`MCPSession.try_begin_write` refused: the TTL sweep is removing the
#: session, so its state is gone once it is done.
WRITE_REFUSED_BY_SWEEP = "sweep"

#: Why :meth:`MCPSession.try_begin_write` refused: a change that deletes the
#: session's directory (``clear_source`` or the end of the session) holds it.
#: Its removal may or may not have reached the upload's files yet.
WRITE_REFUSED_BY_CHANGE = "change"


class MCPSession(BaseModel):
    """Per-connection state for an MCP client.

    Fields:
        id: Stable connection identifier provided by the transport.
        workspace_root: Per-session scratch directory. The disconnect hook
            rmtrees this path; do NOT place shared state here.
        created_at: UTC timestamp the session was created.

    A client's binding is not a field of this model. The directory it delivered
    is recorded by ``source_delivery`` (``get_session_source_dir``) and the profile
    it selected, with that profile's config and patch ops, by ``profile_registry``
    (``get_session_state``); both are keyed by ``id`` and are the source of truth.

    The ``_lock`` private attribute serializes scans within a single session.
    Two threads scanning the *same* session must contend on this lock; two
    threads scanning *different* sessions never touch each other's lock and
    so run in parallel.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: str = Field(description="Stable per-connection identifier.")
    workspace_root: Path = Field(
        description="Per-session scratch dir; disconnect rmtrees this.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp the session was created.",
    )

    # Per-session scan serialization. PrivateAttr keeps it off the schema and
    # off any serialization path — locks must never leave the process.
    _lock: threading.Lock = PrivateAttr(default_factory=threading.Lock)
    # Scans started and not yet returned, and whether a change to the delivered
    # tree holds the session; both guarded by _state_lock. See try_claim_scan.
    _state_lock: threading.Lock = PrivateAttr(default_factory=threading.Lock)
    _claimed_scans: int = PrivateAttr(default=0)
    _changing: bool = PrivateAttr(default=False)
    # Whether the change in progress deletes the session's directory, and so
    # excludes writes. See try_begin_change.
    _change_removes_workspace: bool = PrivateAttr(default=False)
    # Requests writing the session's state outside a change, and whether the TTL
    # sweep holds the session; both guarded by _state_lock. See try_begin_write.
    _writes: int = PrivateAttr(default=0)
    _sweeping: bool = PrivateAttr(default=False)
    # Scans counted against the per-session limit and not yet returned. See
    # try_start_scan.
    _scan_count: ScanCount = PrivateAttr(default_factory=ScanCount)
    # time.monotonic() when the registry last handed this session out. See
    # is_idle_since.
    _last_handed_out: float = PrivateAttr(default_factory=time.monotonic)

    @property
    def lock(self) -> threading.Lock:
        """Public accessor for the per-session lock.

        Callers running a scan should acquire this for the duration of the
        scan so that the same session never runs two scans concurrently.
        """
        return self._lock

    def try_claim_scan(self) -> bool:
        """Claim the session's tree for a scan that is about to start.

        A scan takes :attr:`lock` on a worker thread, after its scan id has been
        returned; the claim covers that gap, from before the id is returned until
        :meth:`release_scan`. While any claim is held,
        :meth:`try_begin_change` refuses.

        Returns:
            False, claiming nothing, while a change to the tree is in progress.
        """
        with self._state_lock:
            if self._changing:
                return False
            self._claimed_scans += 1
            return True

    def release_scan(self) -> None:
        """Release a claim :meth:`try_claim_scan` took, once its scan returned."""
        with self._state_lock:
            self._claimed_scans = max(0, self._claimed_scans - 1)

    def try_begin_change(self, *, removes_workspace: bool = True) -> Optional[str]:
        """Take the session for a change to its delivered tree, without waiting.

        Args:
            removes_workspace: True for a change that deletes the session's
                directory (``clear_source``, :func:`end_session`, the TTL sweep).
                It excludes writes (:meth:`try_begin_write`) both ways: it is
                refused while one is in progress, and refuses one that comes
                meanwhile, so the removal never runs under an append or a
                profile binding. False for a change that never deletes the
                session's directory (a clone, a finalize): a chunk lands in
                ``incoming/`` and a profile binding in ``config/`` and
                ``client-config/``, so neither is excluded. A clone touches
                only ``source/`` and its staging sibling; a finalize also
                reads and removes its own upload's ``incoming/<id>.zip``,
                under the upload's lock, which a chunk of that upload shares.

        Returns:
            None when the change began, holding :attr:`lock` until
            :meth:`end_change`. Otherwise why it was refused, as
            :meth:`try_begin_write` answers: :data:`CHANGE_REFUSED_BY_SCAN`
            while a scan of the session holds :attr:`lock` or is claimed and
            not yet returned; :data:`CHANGE_REFUSED_BY_CHANGE` while another
            change holds it; :data:`CHANGE_REFUSED_BY_WRITE`, for a change
            that removes the workspace, while a write is in progress. The
            holder named for a lock another thread holds is read beside the
            acquire, not under it, so by the time a caller words a message the
            holder can have moved on; the reason says what refused this
            attempt, never what is still running.
        """
        if not self._lock.acquire(blocking=False):
            with self._state_lock:
                changing = self._changing
            return CHANGE_REFUSED_BY_CHANGE if changing else CHANGE_REFUSED_BY_SCAN
        with self._state_lock:
            if self._claimed_scans or (removes_workspace and self._writes):
                self._lock.release()
                return CHANGE_REFUSED_BY_SCAN
            if removes_workspace and self._writes:
                self._lock.release()
                return CHANGE_REFUSED_BY_WRITE
            self._changing = True
            self._change_removes_workspace = removes_workspace
        return None

    def end_change(self) -> None:
        """End a change :meth:`try_begin_change` began."""
        with self._state_lock:
            self._changing = False
            self._change_removes_workspace = False
        self._lock.release()

    def try_begin_write(self) -> Optional[str]:
        """Hold the session against the TTL sweep for a request writing its state.

        A chunk of an upload and a profile binding write the session's state
        without taking its change (:meth:`try_begin_change`), which a running
        scan refuses: neither touches the tree a scan reads, so neither waits
        for one. The sweep runs on a worker thread and holds the session
        (:meth:`try_begin_sweep`) from its last look at the session's age until
        the removal is done, and a write that comes meanwhile is refused rather
        than accepted and then removed with the session. A change that removes
        the session's directory (clear, end of session; see
        :meth:`try_begin_change`) is refused while a write is in progress, and
        a write is refused while such a change holds the session, so a removal
        of the workspace never runs under an append. A clone or a finalize
        replaces ``source/`` only, and a write alongside it is not refused.
        Writes do not exclude each other.

        The hold is this process's: it is on the in-memory session, so it keeps
        this server's sweep off the session. Another server sharing the
        workspace root sweeps by the session's age and its scan presence entry
        (:class:`ScanPresence`), and does not see a write in progress here.

        Returns:
            None when the write began, until :meth:`end_write`. Otherwise why it
            was refused: :data:`WRITE_REFUSED_BY_SWEEP` while the sweep holds the
            session, :data:`WRITE_REFUSED_BY_CHANGE` while a change that removes
            the session's directory does. Either hold can end without removing
            the upload's files, so :func:`writing_session_state` raises one
            error with one retry rule for both.
        """
        with self._state_lock:
            if self._sweeping:
                return WRITE_REFUSED_BY_SWEEP
            if self._changing and self._change_removes_workspace:
                return WRITE_REFUSED_BY_CHANGE
            self._writes += 1
            return None

    def end_write(self) -> None:
        """End a write :meth:`try_begin_write` began."""
        with self._state_lock:
            self._writes = max(0, self._writes - 1)

    def try_begin_sweep(self) -> bool:
        """Hold the session for the TTL sweep's last check and its removal.

        Returns:
            False while a write (:meth:`try_begin_write`) is in progress, which
            keeps the session; otherwise True, until :meth:`end_sweep`.
        """
        with self._state_lock:
            if self._writes or self._sweeping:
                return False
            self._sweeping = True
            return True

    def end_sweep(self) -> None:
        """End what :meth:`try_begin_sweep` began."""
        with self._state_lock:
            self._sweeping = False

    def try_start_scan(self, limit: Optional[int]) -> bool:
        """Count a scan of this session as running, unless ``limit`` already are.

        See :meth:`ScanCount.try_start_scan`.
        """
        return self._scan_count.try_start_scan(limit)

    def scan_returned(self) -> None:
        """Uncount a scan :meth:`try_start_scan` counted."""
        self._scan_count.scan_returned()

    def is_idle_since(
        self, cutoff: float, holds_binding: Callable[[str], bool]
    ) -> bool:
        """Whether the registry can forget this session without anyone noticing.

        True when the session was last handed out before ``cutoff`` (a
        ``time.monotonic()`` reading), holds nothing a client bound to it, and
        nothing runs or is claimed on it: no scan, no change, no write, no sweep.
        A caller still holding the session from an earlier hand-out would have
        refreshed it, or holds a claim, so a session this returns True for is
        recreated empty by its next ``session_for``.

        What a client bound to the session lives outside this object: a delivered
        tree in ``source_delivery`` and a selected profile in ``profile_registry``,
        both keyed by the session id. ``holds_binding`` answers for those two
        stores (:func:`_session_holds_a_binding`); the caller passes it in so that
        a loop over many sessions imports them once.
        """
        if self._last_handed_out > cutoff:
            return False
        if holds_binding(self.id):
            return False
        if self._scan_count.is_running() or not self._lock.acquire(blocking=False):
            return False
        try:
            # _changing and _sweeping cannot be set while the lock is held today:
            # try_begin_change sets _changing only after taking _lock and end_change
            # clears it before releasing it, and the one sweeper,
            # _remove_if_still_stale, takes the change before try_begin_sweep. The
            # terms stay so that a later caller that sets either without the lock
            # still keeps its session.
            with self._state_lock:
                return not (
                    self._claimed_scans
                    or self._changing
                    or self._writes
                    or self._sweeping
                )
        finally:
            self._lock.release()


#: Sessions the registry holds before it looks for idle ones to forget. A stateless
#: server with ``--trust-upstream-session-id`` sees one new id per client, and no
#: end of session, so without this the map only grows (a session that never
#: delivered anything has no workspace directory for the TTL sweep to find).
SESSION_MAP_EVICT_ABOVE = 1024

#: How long a session must have gone unrequested, and idle, to be forgotten.
IDLE_SESSION_SECONDS = 300.0


def _session_holds_a_binding() -> Callable[[str], bool]:
    """The test ``MCPSession.is_idle_since`` uses for what a client bound.

    Looks up the delivered source directory and the selected profile by session
    id. Returned as a function so the two imports happen once per caller and not
    once per session.
    """
    from automated_security_helper.cli.mcp.profile_registry import (
        session_has_binding,
    )
    from automated_security_helper.cli.mcp.source_delivery import (
        get_session_source_dir,
    )

    def holds_binding(session_id: str) -> bool:
        return get_session_source_dir(session_id) is not None or session_has_binding(
            session_id
        )

    return holds_binding


class MCPSessionRegistry:
    """Process-local registry of MCP sessions keyed by connection id.

    The registry guards its internal dict with an ``RLock`` so that
    ``get_or_create`` and ``disconnect`` are safe to call from multiple
    threads. Per-session scan serialization is the *session's* job; the
    registry just owns the map.
    """

    def __init__(self, workspace_parent: Optional[Path] = None) -> None:
        """Initialize the registry.

        Args:
            workspace_parent: Optional parent directory for per-session
                workspace_roots. When None, each session's workspace is its
                sandbox under ``source_delivery.resolve_workspace_root()``,
                resolved when the session is created, so the registry and
                source delivery name one directory.
        """
        self._sessions: Dict[str, MCPSession] = {}
        self._lock = threading.RLock()
        #: The scans of every caller with no session, counted as one session's.
        #: See per_session_scan_limit.
        self.sessionless_scans = ScanCount()
        self._explicit_parent = workspace_parent
        if workspace_parent is not None:
            workspace_parent.mkdir(parents=True, exist_ok=True)

    @property
    def _workspace_parent(self) -> Path:
        if self._explicit_parent is not None:
            return self._explicit_parent
        from automated_security_helper.cli.mcp.source_delivery import (
            resolve_workspace_root,
        )

        return resolve_workspace_root()

    def session_for(self, session_id: str) -> MCPSession:
        """Return the session for ``session_id``, adding it to the map if needed.

        Creates nothing on disk. This is the call for a caller that needs the
        session's claim or lock and not its directory: a scan, and a change to
        the delivered tree, whose functions create and mark the directory
        themselves when they write there. A scan of a directory the operator
        granted therefore starts even when the workspace root can't be created.

        Repeated calls with the same id return the same instance, so the lock
        and the claim are shared by every caller of one session.

        Raises:
            ValueError: if ``session_id`` is not usable as a single path
                component. The id names a directory that ``get_or_create``
                creates and ``disconnect`` removes, so it is validated here
                rather than trusted from the caller; ``cli/mcp/session_paths.py``
                holds the rule, shared with the other surfaces that build a
                per-session path.

        Validated before the map lookup, not after. Checking only on the
        create branch would admit the id for the lifetime of the process the
        moment a first call had registered it.
        """
        from automated_security_helper.cli.mcp.session_identity import (
            UNIDENTIFIED_SESSION_ID,
        )

        if session_id == UNIDENTIFIED_SESSION_ID:
            raise ValueError(
                "this caller has no session the server issued, so it has no "
                "session state"
            )
        session_id = validated_path_component(session_id)
        with self._lock:
            existing = self._sessions.get(session_id)
            if existing is not None:
                existing._last_handed_out = time.monotonic()
                return existing
            if len(self._sessions) >= SESSION_MAP_EVICT_ABOVE:
                self._forget_idle_sessions()
            workspace = session_directory(self._workspace_parent, session_id)
            session = MCPSession(id=session_id, workspace_root=workspace)
            self._sessions[session_id] = session
            return session

    def _forget_idle_sessions(self) -> None:
        """Drop entries nobody has asked for lately and nothing runs on.

        Called with the registry lock held. Only the map entry goes: the
        session's directory, if it has one, is the TTL sweep's, and a later
        :meth:`session_for` of the same id makes a fresh entry.
        """
        cutoff = time.monotonic() - IDLE_SESSION_SECONDS
        holds_binding = _session_holds_a_binding()
        idle = [
            sid
            for sid, s in self._sessions.items()
            if s.is_idle_since(cutoff, holds_binding)
        ]
        for sid in idle:
            del self._sessions[sid]

    def get_or_create(self, session_id: str) -> MCPSession:
        """Return the session for ``session_id`` with its workspace directory.

        :meth:`session_for`, plus the session's directory and its marker,
        created when missing.

        Raises:
            ValueError: as :meth:`session_for`.
            OSError: when the directory can't be created.
        """
        session = self.session_for(session_id)
        if not session.workspace_root.is_dir():
            mark_session_workspace(session.workspace_root)
        return session

    def get(self, session_id: str) -> Optional[MCPSession]:
        """Return the session for ``session_id`` or None if unknown."""
        with self._lock:
            return self._sessions.get(session_id)

    def disconnect(self, session_id: str) -> None:
        """Drop the session and rmtree its workspace.

        Idempotent: calling on an unknown id is a no-op. The rmtree uses
        ``ignore_errors=True`` so a partially-deleted workspace doesn't
        wedge the registry.
        """
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is None:
            return
        self._cleanup(session)

    def forget(self, session_id: str) -> None:
        """Drop the entry for ``session_id`` and leave its workspace on disk.

        Idempotent. For a caller that can't remove the directory yet (the TTL
        sweep removes it later); :meth:`disconnect` removes both.
        """
        with self._lock:
            self._sessions.pop(session_id, None)

    def _cleanup(self, session: MCPSession) -> None:
        """Remove a session's workspace from disk."""
        workspace = session.workspace_root
        if workspace and workspace.exists():
            shutil.rmtree(workspace, ignore_errors=True)

    def __contains__(self, session_id: object) -> bool:
        with self._lock:
            return session_id in self._sessions

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)


_default_registry: Optional[MCPSessionRegistry] = None
_default_registry_lock = threading.Lock()

#: Sessions that ended while a scan or a write (a chunk, a profile binding) of
#: theirs held the session. Their removal waits for the scan or the write, so a
#: tree a scan is reading and a file a request is appending to are never removed
#: under it. A session is marked here before its removal is tried, and unmarked
#: once the removal is done.
_ended_while_scanning: Set[str] = set()
_ended_lock = threading.Lock()


def get_default_registry() -> MCPSessionRegistry:
    """Return the process-wide default ``MCPSessionRegistry``.

    Constructed lazily on first call so that importing this module does not
    create a workspace-parent directory on disk.
    """
    global _default_registry
    with _default_registry_lock:
        if _default_registry is None:
            _default_registry = MCPSessionRegistry()
        return _default_registry


def reset_default_registry_for_tests() -> None:
    """Drop the module-level singleton — for test isolation only."""
    global _default_registry
    with _default_registry_lock:
        _default_registry = None


def _remove_session_state(session_id: str) -> None:
    """Remove the workspace, delivered-source record, bound profile and entry."""
    from automated_security_helper.cli.mcp.profile_registry import (
        clear_session_state,
    )
    from automated_security_helper.cli.mcp.source_delivery import (
        remove_session_workspace,
    )

    try:
        # end_session holds the session's lock already.
        remove_session_workspace(session_id)
    except ValueError:
        # An id that cannot name a directory never had a workspace.
        pass
    clear_session_state(session_id)
    get_default_registry().disconnect(session_id)


def end_session(session_id: str) -> bool:
    """Remove everything the server holds for ``session_id``, which has ended.

    The session's sandbox (``<workspace root>/<session id>``: the delivered
    tree, uploads in progress, the config ``select_profile`` materialized), its
    delivered-source record, its bound profile, and its registry entry. If a
    scan of the session is running, the removal waits until that scan returns
    (:func:`finish_ended_session`), because removing the tree a scan is reading
    can turn its result into a clean one. It waits the same way for a write in
    progress (a chunk of an upload, a profile binding), which the removal would
    race.

    - A scan in this process: the removal waits until that scan returns, and
      :func:`finish_ended_session` completes it, called as the scan's claim is
      released.
    - A scan in another server sharing the workspace root: nothing in this
      process learns when that scan returns, so :func:`finish_ended_session` is
      not called for it. The tree, the profile binding and the delivered-source
      record stay until :func:`sweep_stale_workspaces` finds the workspace older
      than its TTL with no scan holding it, which is the only collector.

    Idempotent. The session is taken with ``session_for`` and not ``get``: the
    registry may have forgotten the id, and a scan can recreate and claim it right
    after a lookup that found nothing, which would leave the claim unseen by the
    change guard. Ending an id that never existed makes an empty entry that the
    removal drops at once, so it is still a no-op; an id that cannot name a session
    has no entry and no state to remove.

    If the scan presence lock can't be taken (a filesystem that refuses file
    locks), nothing proves that no scan elsewhere holds the session: the tree
    stays on disk, and the bound profile, the delivered-source record and the
    registry entry are cleared now, with one warning naming the lock. The TTL
    sweep needs the same lock, so nothing removes the tree until the root's
    filesystem supports file locks.

    Returns:
        True when everything was removed now, False when it waits for a scan or
        a write.
    """
    try:
        session = get_default_registry().session_for(session_id)
    except ValueError:
        # An id that cannot name a session has no entry and no state to remove.
        session = None
    # Pending before the change is tried, and dropped once the removal is done.
    # A scan or a write that ends between a refused try_begin_change and a later
    # add would run finish_ended_session before the session was pending, and
    # nothing would remove it after that. With the add first, whichever of the
    # two finishes second finds the session pending and removes it.
    with _ended_lock:
        _ended_while_scanning.add(session_id)
    if session is not None and session.try_begin_change() is not None:
        return False
    try:
        outcome = _remove_unless_a_scan_elsewhere_holds(session_id)
    finally:
        if session is not None:
            session.end_change()
    with _ended_lock:
        if outcome is False:
            _ended_while_scanning.add(session_id)
        else:
            _ended_while_scanning.discard(session_id)
    return outcome is True


def _remove_unless_a_scan_elsewhere_holds(session_id: str) -> Optional[bool]:
    """Remove the session's state unless a scan in any server sharing the root holds it.

    Run with the session's change held, which covers scans of this process. A scan
    in another server holds a locked entry under ``<root>/.ash-mcp-scans/<id>/``
    (:class:`ScanPresence`); removing the tree under it can turn its result into a
    clean one. Entries of scans that died, and the empty directory that held them,
    are dropped with the workspace, as the TTL sweep does.

    A session with no workspace directory has nothing a scan could be reading, and
    no registry is opened for it. A reserved id (stdio's ``__default__``) never has
    a presence entry, so it is removed without opening the registry: ending it
    creates nothing under ``.ash-mcp-scans``.

    If the presence lock cannot be taken, nothing proves that no scan holds the
    session, so the tree stays on disk. The TTL sweep needs the same lock, so
    on a root whose filesystem refuses it outright nothing removes the tree
    until the filesystem supports file locks; the sweep warns once about that.
    The server's own memory of the session (its bound profile, delivered-source
    record and registry entry) is cleared now, and one warning names the lock
    path, so such a root does not build up state for the life of the process.

    Returns:
        True when the state was removed, False when the removal must wait for a
        scan, None when the lock could not be taken and only the in-memory state
        was cleared.
    """
    from automated_security_helper.cli.mcp.session_identity import (
        is_reserved_session_id,
    )

    try:
        root = _workspace_root()
        has_workspace = session_directory(root, session_id).is_dir()
    except (OSError, RuntimeError, ValueError):
        has_workspace = False
    if not has_workspace or is_reserved_session_id(session_id):
        _remove_session_state(session_id)
        return True
    holder = root / SCAN_PRESENCE_DIR / session_id
    try:
        with contextlib.ExitStack() as stack:
            try:
                stack.enter_context(_scan_presence_guard(root))
            except OSError as exc:
                _forget_session_in_memory(session_id)
                from automated_security_helper.utils.log import ASH_LOGGER

                ASH_LOGGER.warning(
                    "Could not take the scan presence lock %s (%s). The "
                    "workspace of session %r stays on disk, and nothing "
                    "removes it until the root's filesystem supports file "
                    "locks: the TTL sweep needs this same lock.",
                    root / SCAN_PRESENCE_DIR / _SCAN_PRESENCE_LOCK,
                    exc,
                    session_id,
                )
                return None
            if _a_scan_holds(holder):
                return False
            _remove_session_state(session_id)
            with contextlib.suppress(OSError):
                holder.rmdir()
            return True
    except OSError:
        return False


def _forget_session_in_memory(session_id: str) -> None:
    """Drop the session's in-memory state, leaving the workspace on disk.

    The bound profile, the delivered-source record and the registry entry all
    go. The TTL sweep's lookup re-creates a registry entry, so a
    delivered-source record left behind would make ``holds_binding`` read that
    entry as bound: it would never be evicted, ``delivered_session_count``
    would stay inflated by ended sessions, and the forget would be undone at
    the next sweep.
    """
    from automated_security_helper.cli.mcp.profile_registry import (
        clear_session_state,
    )
    from automated_security_helper.cli.mcp.source_delivery import (
        _drop_session_source_dir,
    )

    clear_session_state(session_id)
    _drop_session_source_dir(session_id)
    get_default_registry().forget(session_id)


def finish_ended_session(session_id: Optional[str]) -> None:
    """Complete the removal of a session that ended while its scan or write ran."""
    if session_id is None:
        return
    with _ended_lock:
        pending = session_id in _ended_while_scanning
    if pending:
        end_session(session_id)


#: ``error_type`` the MCP tools return for :class:`SessionWorkspaceBusyError`.
SESSION_WORKSPACE_BUSY = "session_workspace_busy"


class SessionWorkspaceBusyError(RuntimeError):
    """A write to a session's state was refused: another request holds its workspace.

    The holder is the TTL sweep removing an idle session, a ``clear_source``,
    or the end of the session. Any of them can end without removing the
    upload's files -- the sweep re-reads the session's age while it holds it
    and keeps a session used meanwhile, steps back while a scan on another
    server holds the session, and stops on a read error -- so no refusal of
    this type means the upload is gone. The one retry rule that is right in
    every case: send the request again as it is once the hold ends. A chunk
    keeps its sequence number, and only an out-of-order answer means the
    upload was removed; the upload is then sent again from its first chunk.
    """

    error_type = SESSION_WORKSPACE_BUSY


@contextlib.contextmanager
def writing_session_state(session_id: Optional[str]) -> Iterator[None]:
    """Hold ``session_id`` against the TTL sweep while a request writes its state.

    For a write outside the session's change: a chunk of an upload, a profile
    binding (``MCPSession.try_begin_write``). ``None`` is the stdio session. A
    caller with no session state, or an id that can't name one, is not held:
    the write itself refuses those. The hold is this process's; see
    ``MCPSession.try_begin_write``.

    Raises:
        SessionWorkspaceBusyError: while another request holds the session's
            workspace: the TTL sweep removing an idle session, a
            ``clear_source``, or the end of the session. Any of them can end
            without removing the upload's files, so the request is sent again
            as it is once the hold ends; a chunk keeps its sequence number,
            and only an out-of-order answer means the upload was removed and
            is sent again from its first chunk. A clone or a finalize does
            not refuse a write.
    """
    from automated_security_helper.cli.mcp.profile_registry import DEFAULT_SESSION_ID

    session: Optional[MCPSession]
    try:
        session = get_default_registry().session_for(session_id or DEFAULT_SESSION_ID)
    except ValueError:
        session = None
    if session is None:
        yield
        return
    if session.try_begin_write() is not None:
        raise SessionWorkspaceBusyError(
            "another request holds this session's workspace (the removal of "
            "an idle session, a clear, or the end of the session), and the "
            "hold can end without removing an upload; send this request "
            "again as it is once it has finished. Only if the answer to a "
            "chunk is an out-of-order chunk was the upload removed, and then "
            "it is sent again from its first chunk"
        )
    try:
        yield
    finally:
        session.end_write()
        # A session that ended while this write ran was left in place by
        # end_session; it is removed now that nothing writes.
        finish_ended_session(session_id or DEFAULT_SESSION_ID)


#: ``error_type`` of a scan refused because its session is at the per-session limit.
SESSION_SCAN_LIMIT = "session_scan_limit"


def per_session_scan_limit(session_id: Optional[str]) -> Optional[int]:
    """How many scans ``session_id`` may run at once, or None for no limit.

    The operator's ``mcp-resource-management.max_concurrent_scans_per_session``,
    read from ``ASH_CONFIG`` (``get_default_config``), never from the config a
    scan resolves: that can be the scanned tree's own or one a client delivered,
    and a limit the limited party can raise is no limit. Read per scan, so a
    changed ``ASH_CONFIG`` applies to the next one; a file that no longer loads
    leaves the default. 0 is no limit.

    Only a caller of a network transport is limited. stdio has one session, the
    local client's, and nobody to share the host with.

    A limited caller with no session counts against :func:`sessionless_scan_count`,
    one count all such callers share, under the same limit. Over the network that
    is a caller with no session the server issued
    (``session_identity.UNIDENTIFIED_SESSION_ID``): every caller of a stateless
    streamable-HTTP server run without ``--trust-upstream-session-id``, and a
    request on sse or stateful streamable-HTTP that names no issued session. With
    ``ASH_MCP_TRANSPORT`` set it is also an in-process caller that passes no
    session id. Shared rather than uncounted, because these callers can't be told
    apart, and leaving them uncounted would let any of them start as many scans
    as it liked.
    """
    from automated_security_helper.cli.mcp.sandbox import caller_is_remote
    from automated_security_helper.config.ash_config import (
        MCPResourceManagementConfig,
    )
    from automated_security_helper.config.default_config import get_default_config

    if not caller_is_remote(session_id):
        return None
    try:
        settings = get_default_config().mcp_resource_management
    except Exception:  # noqa: BLE001 -- an unloadable ASH_CONFIG keeps the default
        settings = MCPResourceManagementConfig()
    return settings.max_concurrent_scans_per_session or None


def sessionless_scan_count() -> ScanCount:
    """The count every limited caller with no session shares; see per_session_scan_limit."""
    return get_default_registry().sessionless_scans


def session_scan_limit_refusal(
    operation: str, limit: int, *, shared: bool = False
) -> Dict[str, Any]:
    """The response for a scan refused because its session is at its limit.

    ``shared``: the caller has no session and counted on
    :func:`sessionless_scan_count`. Such a caller can't use cancel_scan, so the
    message doesn't suggest it.
    """
    if shared:
        error = (
            f"callers with no session the server issued share one count, and "
            f"{limit} scan(s) of theirs are already running, which is the "
            f"server's per-session limit (mcp-resource-management."
            f"max_concurrent_scans_per_session); start another once one has "
            f"finished"
        )
    else:
        error = (
            f"this session is already running {limit} scan(s), which is the "
            f"server's per-session limit (mcp-resource-management."
            f"max_concurrent_scans_per_session); start another once one has "
            f"finished, or cancel one with cancel_scan"
        )
    return {
        "success": False,
        "operation": operation,
        "error_type": SESSION_SCAN_LIMIT,
        "error": error,
    }


#: Directory under the workspace root holding one entry per live stdio server.
#: Not a session workspace: it carries no session marker, and
#: ``session_identity.is_reserved_session_id`` refuses it as a session id in any
#: letter case.
STDIO_SERVERS_DIR = ".stdio-servers"
_STDIO_SERVERS_LOCK = ".lock"


class PresenceLockError(Exception):
    """A stdio server or a scan could not lock its own presence entry.

    Not an ``OSError``: the presence classes treat an ``OSError`` as "no registry
    on this root" and carry on unregistered, and this is the one failure they
    refuse to carry on from.
    """


def _lock_own_entry(handle: Any, entry: Path, what: str) -> None:
    """Lock a presence entry this process just created, or refuse to go on.

    The entry is a new file named for this process, so no other process holds a
    lock on it; a refusal comes from the filesystem refusing the lock on this
    entry after it granted the one on the registry's guard file, and asking
    again gets the same answer, so there is no retry. On a root whose
    filesystem refuses locks outright the guard's own blocking lock fails
    first, and the presence classes then run unregistered with a warning
    instead of reaching this. A server or scan that went on without a locked entry would read as dead
    to every other server sharing the root, which would remove the workspace under
    it. The entry is removed and nothing stays registered.

    Raises:
        PresenceLockError: naming the entry's path.
    """
    if _try_lock(handle):
        return
    handle.close()
    with contextlib.suppress(OSError):
        entry.unlink()
    raise PresenceLockError(
        f"could not take the lock on {what} {entry}: the filesystem refused it. "
        "Without the lock other servers sharing the workspace root would read "
        "this process as dead and remove the workspace it is using, so it does "
        "not start. Set ASH_MCP_WORKSPACE_ROOT to a directory on a filesystem "
        "that supports file locks."
    )


def _try_lock(handle: Any) -> bool:
    """Take an exclusive lock on ``handle`` without waiting; True if taken."""
    try:
        # sys.platform rather than os.name: it is the check mypy reads, so the
        # Windows-only msvcrt names are checked on Windows alone.
        if sys.platform == "win32":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def _lock_blocking(handle: Any) -> None:
    if sys.platform == "win32":
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)


class StdioServerPresence:
    """Marks this process as a live stdio server sharing the default workspace.

    Every stdio server of one user resolves the same
    ``<workspace root>/__default__``, so it is removed only when the last of
    them exits. Each server holds an exclusive lock on its own entry under
    ``<workspace root>/.stdio-servers`` for its lifetime. On exit it drops its
    entry and removes the default workspace only if no other entry is still
    locked; an entry whose lock can be taken belongs to a server that died, and
    is removed, at registration as well as at exit. Registration and the exit
    check both run under one lock file, so a server starting while another exits
    is either counted or starts after the removal. A server that cannot lock its
    own entry does not start: ``__enter__`` raises :class:`PresenceLockError`
    naming the entry's path.

    Limits: a server on another host sharing the root through a network
    filesystem may not see this process's locks, and a root where the registry
    cannot be created or its lock file cannot be locked leaves the default
    workspace in place (no server can register there, so none is removed
    under).
    """

    def __init__(self) -> None:
        self._entry: Optional[Path] = None
        self._handle: Any = None

    @staticmethod
    def _registry() -> Path:
        from automated_security_helper.cli.mcp.source_delivery import (
            resolve_workspace_root,
        )

        return resolve_workspace_root() / STDIO_SERVERS_DIR

    def __enter__(self) -> Self:
        import uuid

        try:
            registry = self._registry()
            registry.mkdir(parents=True, exist_ok=True)
            with open(registry / _STDIO_SERVERS_LOCK, "a+b") as guard:
                _lock_blocking(guard)
                # Entries of servers that were killed are dropped here as well as
                # on exit, so a root that only sees killed servers does not keep
                # them. Under the guard, as the exit check is.
                self._drop_dead_entries(registry)
                entry = registry / f"{os.getpid()}-{uuid.uuid4().hex}"
                handle = open(entry, "a+b")
                # A file nobody else has opened, so only the filesystem can refuse
                # the lock, and asking again would get the same answer. The server
                # then does not start: running unregistered, it would read as dead
                # to an exiting sibling, which would remove the default workspace
                # under it. PresenceLockError is not caught below.
                _lock_own_entry(handle, entry, "this server's presence entry")
                self._entry, self._handle = entry, handle
        except (OSError, RuntimeError) as exc:
            # No registry: this server is not counted, and on exit it leaves the
            # default workspace alone rather than guess. Nothing can have
            # registered there either, as the registry's own lock was refused or
            # the directory cannot be created. Said out loud: silence here would
            # leave an operator on such a root with no sign the registry is out
            # of use.
            from automated_security_helper.utils.log import ASH_LOGGER

            ASH_LOGGER.warning(
                "Could not use the stdio server presence registry (%s): this "
                "server runs unregistered, and on exit it leaves the default "
                "workspace in place.",
                exc,
            )
            self._entry = self._handle = None
        return self

    def __exit__(self, *exc_info: object) -> None:
        from automated_security_helper.cli.mcp.profile_registry import (
            DEFAULT_SESSION_ID,
        )

        if self._entry is None:
            return
        registry = self._entry.parent
        try:
            with open(registry / _STDIO_SERVERS_LOCK, "a+b") as guard:
                _lock_blocking(guard)
                self._release()
                if not self._another_server_is_live(registry):
                    end_session(DEFAULT_SESSION_ID)
        except OSError:
            self._release()

    def _release(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None
        if self._entry is not None:
            try:
                self._entry.unlink()
            except OSError:
                pass
            self._entry = None

    @staticmethod
    def _drop_dead_entries(registry: Path) -> None:
        """Remove the entries of servers that died, keeping the live ones.

        Called under the registry's lock file, for its effect only.
        """
        StdioServerPresence._another_server_is_live(registry)

    @staticmethod
    def _another_server_is_live(registry: Path) -> bool:
        """True if another server's entry is locked; drops entries of dead ones."""
        live = False
        for entry in registry.iterdir():
            if entry.name == _STDIO_SERVERS_LOCK or not entry.is_file():
                continue
            try:
                with open(entry, "a+b") as handle:
                    taken = _try_lock(handle)
            except OSError:
                # Windows refuses to open a file another process holds.
                live = True
                continue
            if not taken:
                live = True
                continue
            try:
                entry.unlink()  # its server died without exiting
            except OSError:
                live = True
        return live

    def abandon_for_tests(self) -> None:
        """Drop the lock but keep the entry, as a server that died would."""
        if self._handle is not None:
            self._handle.close()
            self._handle = None
        self._entry = None


#: Directory under the workspace root holding, per session, one locked entry for
#: each running scan of that session, in any server process sharing the root.
#: Not a session workspace: it carries no session marker, and
#: ``session_identity.is_reserved_session_id`` refuses it as a session id.
SCAN_PRESENCE_DIR = ".ash-mcp-scans"
_SCAN_PRESENCE_LOCK = ".lock"


def _workspace_root() -> Path:
    from automated_security_helper.cli.mcp.source_delivery import (
        resolve_workspace_root,
    )

    return resolve_workspace_root()


@contextlib.contextmanager
def _scan_presence_guard(root: Path) -> Iterator[None]:
    """Hold the lock that registering a scan and the sweep's check-and-remove share."""
    registry = root / SCAN_PRESENCE_DIR
    registry.mkdir(exist_ok=True)
    with open(registry / _SCAN_PRESENCE_LOCK, "a+b") as guard:
        _lock_blocking(guard)
        yield


class ScanPresence:
    """Marks a running scan of ``session_id`` for every server sharing the root.

    A scan's claim and lock on its ``MCPSession`` hold the session's tree in this
    process only. Another server process sharing the workspace root (replicas
    behind a load balancer, with one root on a network filesystem) can't see
    them, so a running scan also holds an exclusive lock on its own entry under
    ``<root>/.ash-mcp-scans/<session id>/``. The TTL sweep of every server skips
    a session with a live entry. Registering and the sweep's check-and-remove run
    under one lock file, so a scan that starts while a sweep removes its
    session's workspace either is seen by it or finds the workspace gone.

    Nothing is registered for a session with no workspace on disk: nothing of
    the session's is there to protect, and a scan of a directory the operator
    granted creates nothing under the root. A root where the entry can't be
    created leaves the scan unregistered rather than failing it. A scan whose
    entry exists but can't be locked does not start: ``__enter__`` raises
    :class:`PresenceLockError`.

    Limits: as ``StdioServerPresence``, a server on another host sharing the root
    through a filesystem that does not share these locks can't see them.
    """

    def __init__(self, session_id: Optional[str]) -> None:
        self._session_id = session_id
        self._entry: Optional[Path] = None
        self._handle: Any = None

    def __enter__(self) -> Self:
        import uuid

        from automated_security_helper.cli.mcp.session_identity import (
            is_reserved_session_id,
        )

        session_id = self._session_id
        if not session_id or is_reserved_session_id(session_id):
            return self
        try:
            root = _workspace_root()
            sandbox = session_directory(root, session_id)
            if not sandbox.is_dir():
                return self
            with _scan_presence_guard(root):
                # Under the guard: a sweep that removed the workspace meanwhile
                # has finished, and its marker is gone.
                if not (sandbox / SESSION_MARKER).is_file():
                    return self
                holder = root / SCAN_PRESENCE_DIR / session_id
                holder.mkdir(exist_ok=True)
                entry = holder / f"{os.getpid()}-{uuid.uuid4().hex}"
                handle = open(entry, "a+b")
                # A file nobody else has opened, so only the filesystem can refuse
                # the lock. The scan then does not start, as an unlocked entry
                # reads as dead to every other server's sweep.
                try:
                    _lock_own_entry(handle, entry, "this scan's presence entry")
                except PresenceLockError:
                    with contextlib.suppress(OSError):
                        holder.rmdir()
                    raise
                self._entry, self._handle = entry, handle
        except (OSError, ValueError, RuntimeError) as exc:
            # The registry or its guard lock is out of reach: the scan runs
            # unregistered rather than failing, and the warning is the one
            # sign of it an operator gets.
            from automated_security_helper.utils.log import ASH_LOGGER

            ASH_LOGGER.warning(
                "Could not use the scan presence registry (%s): this scan of "
                "session %r runs unregistered, so another server sharing the "
                "root cannot see it.",
                exc,
                session_id,
            )
            self._entry = self._handle = None
        return self

    def __exit__(self, *exc_info: object) -> None:
        if self._entry is None:
            return
        entry, handle = self._entry, self._handle
        self._entry = self._handle = None
        try:
            with _scan_presence_guard(entry.parent.parent.parent):
                handle.close()
                with contextlib.suppress(OSError):
                    entry.unlink()
                with contextlib.suppress(OSError):
                    entry.parent.rmdir()  # only when no other scan's entry is left
        except OSError:
            handle.close()


def _a_scan_holds(holder: Path) -> bool:
    """True if a live scan of any server holds an entry in ``holder``.

    Run under the presence guard. An entry whose lock can be taken belongs to a
    scan whose server died, and is removed.
    """
    try:
        entries = list(holder.iterdir())
    except FileNotFoundError:
        return False
    live = False
    for entry in entries:
        if not entry.is_file():
            continue
        try:
            with open(entry, "a+b") as handle:
                taken = _try_lock(handle)
        except OSError:
            # Windows refuses to open a file another process holds.
            live = True
            continue
        if not taken:
            live = True
            continue
        try:
            entry.unlink()  # its server died without releasing it
        except OSError:
            live = True
    return live


def scan_presence_held(session_id: str) -> bool:
    """True if a running scan of ``session_id`` in any server holds its presence.

    Fails open: when the presence guard can't be taken (``OSError``) the answer
    is False, "no scan held". The answer only reports. No code in this package
    removes or clears anything on it; the sweep takes the guard itself and keeps
    the session when that fails (:func:`_remove_if_still_stale`). A caller that
    gates a deletion on this answer must not read False as permission.
    """

    root = _workspace_root()
    try:
        with _scan_presence_guard(root):
            return _a_scan_holds(root / SCAN_PRESENCE_DIR / session_id)
    except OSError:
        return False


def _last_used(sandbox: Path) -> float:
    """The newest mtime of the sandbox directory and its direct children."""
    newest = sandbox.lstat().st_mtime
    for child in sandbox.iterdir():
        try:
            newest = max(newest, child.lstat().st_mtime)
        except OSError:
            continue
    return newest


def touch_session_workspace(session_id: str) -> None:
    """Record that ``session_id`` was used now, for :func:`sweep_stale_workspaces`."""
    from automated_security_helper.cli.mcp.source_delivery import (
        resolve_workspace_root,
    )

    try:
        sandbox = session_directory(resolve_workspace_root(), session_id)
        if sandbox.is_dir() and not sandbox.is_symlink():
            os.utime(sandbox)
    except (OSError, ValueError, RuntimeError):
        pass


def sweep_stale_workspaces(
    ttl_seconds: float, now: Optional[float] = None
) -> List[str]:
    """Remove session workspaces nobody used for longer than ``ttl_seconds``.

    Only directories ASH created as session workspaces are considered: each
    carries ``session_paths.SESSION_MARKER``, and anything else under the root
    (an operator's notes, a ``.git`` directory) is never removed.

    "Used" is the newest modification time of the sandbox directory and its
    direct children; every HTTP request that names a session refreshes it
    (:func:`touch_session_workspace`), and every delivery writes there. Skipped,
    and never queued for later:

    - a session whose scan runs in this process (its claim or lock is held) or
      whose tree is being changed, because the sweep takes the session's change
      (``MCPSession.try_begin_change``) and that is refused. Queuing the removal
      would remove the tree, and the results the scan wrote under it, the moment
      the scan returned;
    - a session used after its age was read: the age is read again while the
      sweep holds the session;
    - a session whose state a request in this process is writing outside a
      change (``MCPSession.try_begin_write``). A write that comes while the
      sweep holds the session is refused instead (:func:`writing_session_state`);
    - a session a running scan in another server sharing the root holds
      (:class:`ScanPresence`);
    - every name ``session_identity.is_reserved_session_id`` reserves: the stdio
      session, which the last stdio server removes when it exits, and the two
      presence registries.

    Entries that are not directories, are symlinks, or do not name a single
    directory are left alone, and so is a name the session registry refuses
    (``MCPSessionRegistry.session_for``): the sweep goes on to the next entry.

    This is also what removes a session whose end :func:`end_session` deferred
    for a scan in another server: that scan's end is not seen here.

    Returns:
        The session ids whose workspaces were removed.
    """
    import time

    from automated_security_helper.cli.mcp.session_identity import (
        is_reserved_session_id,
    )

    try:
        root = _workspace_root()
        entries = list(root.iterdir()) if root.is_dir() else []
    except (OSError, RuntimeError):
        return []
    cutoff = (time.time() if now is None else now) - ttl_seconds
    removed: List[str] = []
    for entry in entries:
        session_id = entry.name
        if is_reserved_session_id(session_id):
            continue
        try:
            validated_path_component(session_id)
            if not _is_stale_workspace(entry, cutoff):
                continue
        except (OSError, ValueError):
            continue
        try:
            if _remove_if_still_stale(root, session_id, entry, cutoff):
                removed.append(session_id)
        except ValueError:
            # A name the session registry refuses is left alone, and the rest of
            # the root is still swept.
            continue
    return removed


def _is_stale_workspace(entry: Path, cutoff: float) -> bool:
    if entry.is_symlink() or not entry.is_dir():
        return False
    marker = entry / SESSION_MARKER
    if marker.is_symlink() or not marker.is_file():
        return False
    return _last_used(entry) < cutoff


#: Whether this process already warned that the sweep's presence guard was
#: refused. On a root whose filesystem refuses the lock every sweep is refused
#: the same way, so one warning tells the operator; one per sweep per session
#: would repeat for the life of the process.
_sweep_guard_warned = False


def _warn_once_sweep_guard_refused(root: Path, exc: OSError) -> None:
    """Log one warning per process when the sweep's presence guard is refused."""
    global _sweep_guard_warned
    if _sweep_guard_warned:
        return
    _sweep_guard_warned = True
    from automated_security_helper.utils.log import ASH_LOGGER

    ASH_LOGGER.warning(
        "The TTL sweep could not take the scan presence lock %s (%s). No "
        "session workspace on this root is removed until its filesystem "
        "supports file locks.",
        root / SCAN_PRESENCE_DIR / _SCAN_PRESENCE_LOCK,
        exc,
    )


def _remove_if_still_stale(
    root: Path, session_id: str, sandbox: Path, cutoff: float
) -> bool:
    """Remove a stale session's state, unless anything holds it now.

    A presence guard the filesystem refuses skips the removal and warns once
    per process (:func:`_warn_once_sweep_guard_refused`).
    """

    session = get_default_registry().session_for(session_id)
    if session.try_begin_change() is not None:
        return False
    try:
        # A request writing the session's state now keeps it, and one that comes
        # before the removal is done is refused (MCPSession.try_begin_write).
        if not session.try_begin_sweep():
            return False
        try:
            if not _is_stale_workspace(sandbox, cutoff):
                return False
            with contextlib.ExitStack() as stack:
                try:
                    stack.enter_context(_scan_presence_guard(root))
                except OSError as exc:
                    _warn_once_sweep_guard_refused(root, exc)
                    return False
                if _a_scan_holds(root / SCAN_PRESENCE_DIR / session_id):
                    return False
                _remove_session_state(session_id)
                with contextlib.suppress(OSError):
                    (root / SCAN_PRESENCE_DIR / session_id).rmdir()
        except OSError:
            return False
        finally:
            session.end_sweep()
    finally:
        session.end_change()
    with _ended_lock:
        _ended_while_scanning.discard(session_id)
    return True


__all__ = [
    "MCPSession",
    "MCPSessionRegistry",
    "PresenceLockError",
    "SESSION_SCAN_LIMIT",
    "SESSION_WORKSPACE_BUSY",
    "ScanCount",
    "SessionWorkspaceBusyError",
    "StdioServerPresence",
    "end_session",
    "finish_ended_session",
    "get_default_registry",
    "per_session_scan_limit",
    "session_scan_limit_refusal",
    "sessionless_scan_count",
    "reset_default_registry_for_tests",
    "sweep_stale_workspaces",
    "touch_session_workspace",
    "writing_session_state",
]
