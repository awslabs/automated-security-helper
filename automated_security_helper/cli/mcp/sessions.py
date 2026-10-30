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
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Collection, Dict, Iterator, List, Optional, Set

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr
from typing_extensions import Self

from automated_security_helper.cli.mcp.session_paths import (
    SESSION_MARKER,
    hidden_deleting_name,
    is_a_deleting_name,
    make_private_dir,
    mark_session_workspace,
    session_directory,
    validated_path_component,
)
from automated_security_helper.utils.terminal_text import raw_controls_on_one_line


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


class MCPSession(BaseModel):
    """Per-connection state for an MCP client.

    Fields:
        id: Stable connection identifier provided by the transport.
        workspace_root: Per-session scratch directory. The disconnect hook
            rmtrees this path; do NOT place shared state here. None while the
            workspace root cannot be resolved (no home directory and no
            ``ASH_MCP_WORKSPACE_ROOT``, say): ``MCPSessionRegistry.session_for``
            hands the session out anyway, since a scan needs its claim and lock
            and not its directory, and ``get_or_create`` fills the path in once
            the root resolves.
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
    workspace_root: Optional[Path] = Field(
        default=None,
        description=(
            "Per-session scratch dir; disconnect rmtrees this. None until the "
            "workspace root resolves."
        ),
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
            if self._claimed_scans:
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
            # Private from the moment each level exists, as the default root
            # the session paths make is: this parent's listing is the live
            # session ids. Made under the umask it was 0o755, and every session
            # directory created beneath it warned of a listable parent.
            make_private_dir(workspace_parent)

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

        Creates nothing on disk, and resolves nothing it has to: this is the
        call for a caller that needs the session's claim or lock and not its
        directory: a scan, and a change to the delivered tree, whose functions
        create and mark the directory themselves when they write there. A scan
        of a directory the operator granted therefore starts even when the
        workspace root can't be resolved (no home directory and no
        ``ASH_MCP_WORKSPACE_ROOT``) or created; the session's
        ``workspace_root`` is then None until :meth:`get_or_create` resolves it
        (:meth:`_workspace_for`).

        Repeated calls with the same id return the same instance, so the lock
        and the claim are shared by every caller of one session.

        Raises:
            ValueError: if ``session_id`` is not usable as a single path
                component, or names a directory the server keeps under the
                workspace root for itself: the presence registries
                (``.stdio-servers``, ``.ash-mcp-scans``), their guard file
                (``.lock``, :data:`PRESENCE_LOCK_NAME`) and any spelling of a
                reserved name that opens the same directory on a
                case-insensitive filesystem
                (``session_identity.is_reserved_session_id``). The stdio
                session's own id is admitted: its workspace is a session's. The
                id names a directory that ``get_or_create`` creates and
                ``disconnect`` removes, so it is validated here rather than
                trusted from the caller; ``cli/mcp/session_paths.py`` holds the
                component rule, shared with the other surfaces that build a
                per-session path.

        Validated before the map lookup, not after. Checking only on the
        create branch would admit the id for the lifetime of the process the
        moment a first call had registered it.
        """
        from automated_security_helper.cli.mcp.session_identity import (
            UNIDENTIFIED_SESSION_ID,
            is_reserved_session_id,
        )

        if session_id == UNIDENTIFIED_SESSION_ID:
            raise ValueError(
                "this caller has no session the server issued, so it has no "
                "session state"
            )
        session_id = validated_path_component(session_id)
        if not _is_the_stdio_session(session_id) and is_reserved_session_id(session_id):
            raise ValueError(
                f"session_id {session_id!r} names a directory the server keeps "
                "under its workspace root for itself, so it cannot name a session"
            )
        with self._lock:
            existing = self._sessions.get(session_id)
            if existing is not None:
                existing._last_handed_out = time.monotonic()
                return existing
            if len(self._sessions) >= SESSION_MAP_EVICT_ABOVE:
                self._forget_idle_sessions()
            session = MCPSession(
                id=session_id, workspace_root=self._workspace_for(session_id)
            )
            self._sessions[session_id] = session
            return session

    def _workspace_for(self, session_id: str) -> Optional[Path]:
        """The session's directory under the workspace root, or None for now.

        ``resolve_workspace_root`` raises ``RuntimeError`` when no home directory
        can be determined, and joining the id under the root can raise ``OSError``
        resolving the parent. Neither refuses the session: :meth:`session_for`
        creates nothing on disk, and :meth:`get_or_create`, which does, resolves
        the path again and lets that error out to the caller that needs the
        directory. :meth:`disconnect` resolves it again too, so a session handed
        out with no path still has its directory removed when it ends.
        """
        try:
            return session_directory(self._workspace_parent, session_id)
        except (RuntimeError, OSError):
            return None

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
        created when missing. A session handed out while the workspace root
        could not be resolved has no ``workspace_root`` yet; it is resolved
        here, and the error is this caller's, since it needs the directory.

        Raises:
            ValueError: as :meth:`session_for`.
            RuntimeError: when the workspace root can't be resolved (no home
                directory and no ``ASH_MCP_WORKSPACE_ROOT``).
            OSError: when the directory can't be created.
        """
        session = self.session_for(session_id)
        workspace = session.workspace_root
        if workspace is None:
            workspace = session_directory(self._workspace_parent, session_id)
            with self._lock:
                if session.workspace_root is None:
                    session.workspace_root = workspace
                else:
                    workspace = session.workspace_root
        if not workspace.is_dir():
            mark_session_workspace(workspace)
        return session

    def get(self, session_id: str) -> Optional[MCPSession]:
        """Return the session for ``session_id`` or None if unknown."""
        with self._lock:
            return self._sessions.get(session_id)

    def disconnect(self, session_id: str) -> None:
        """Drop the session and remove its workspace from disk.

        The workspace is renamed to a hidden sibling
        (``.<session_id>.deleting-<uuid4>``) while the registry lock is held, in
        the same hold that drops the map entry; the rmtree of the renamed
        directory runs after the lock is released. A ``get_or_create`` of the same
        id that arrives during the (possibly long) rmtree therefore finds nothing
        at the session's path and builds a fresh, empty directory, never a
        session over a tree that is being deleted -- and no other registry call
        waits behind the deletion.

        Disconnect is what ends a session, so it also drops the session's other
        records: the profile binding (``profile_registry.clear_session_state``)
        and the delivered-source record
        (``source_delivery._drop_session_source_dir``), each for this one id.
        The delivered source tree itself lives inside the workspace directory
        and goes with it.

        Idempotent: calling on an unknown id is a no-op. The removal is best
        effort (:meth:`_remove_workspace`): what it cannot remove stays on disk,
        named in one warning, and never wedges the registry.
        """
        # Lazy imports: both modules belong to this package's import web, and a
        # module-level import here would be a cycle.
        from automated_security_helper.cli.mcp.profile_registry import (
            clear_session_state,
        )
        from automated_security_helper.cli.mcp.source_delivery import (
            _drop_session_source_dir,
        )

        if session_id is not None:
            # Always this session's id: clear_session_state(None) drops the stdio
            # session's binding, which is not this session's.
            clear_session_state(session_id)
            _drop_session_source_dir(session_id)
        with self._lock:
            session = self._sessions.pop(session_id, None)
            if session is None:
                return
            workspace = session.workspace_root
            if workspace is None:
                # Handed out while the root could not be resolved
                # (_workspace_for answered None for a passing failure), and no
                # get_or_create resolved it since. The source-delivery tools
                # resolve the root themselves and may have built the directory
                # meanwhile, so it is resolved again here, as get_or_create
                # does, and removed with the session; a root that still cannot
                # be resolved leaves nothing to remove.
                workspace = self._workspace_for(session.id)
            doomed = self._rename_for_removal_locked(session.id, workspace)
        if doomed is not None:
            self._remove_workspace(doomed)

    def forget(self, session_id: str) -> None:
        """Drop the entry for ``session_id`` and leave its workspace on disk.

        Idempotent. For a caller that can't remove the directory yet (the TTL
        sweep removes it later); :meth:`disconnect` removes both.
        """
        with self._lock:
            self._sessions.pop(session_id, None)

    def _rename_for_removal_locked(
        self, session_id: str, workspace: Optional[Path]
    ) -> Optional[Path]:
        """Move ``workspace`` aside for deletion; for a caller holding ``self._lock``.

        Renames the directory to a hidden sibling, ``.<session_id>.deleting-<uuid4>``
        in the same parent, and returns the renamed path for the caller to rmtree
        after releasing the lock. Returns None when nothing is on disk. A rename
        that fails (the directory vanished between the check and the rename, or
        the filesystem refused it) returns the workspace itself, so the caller's
        best-effort rmtree still runs; only that failure path removes at the
        original name.
        """
        if workspace is None or not workspace.exists():
            return None
        doomed = workspace.parent / hidden_deleting_name(session_id)
        try:
            os.rename(workspace, doomed)
        except OSError:
            return workspace
        # See source_delivery._set_aside_for_removal: the rename leaves the
        # directory's modification time as it was.
        with contextlib.suppress(OSError):
            os.utime(doomed)
        return doomed

    def _remove_workspace(self, workspace: Path) -> None:
        """Delete ``workspace``, and say so when some of it could not be removed.

        ``source_delivery._remove_tree`` clears the read-only bit of an entry the
        delete refuses and tries again, as the removal of an ended session does;
        what it still cannot remove stays on disk, and a silent return would
        report that as removed. Under its hidden delete name
        (``.<session id>.deleting-<uuid4>``) the leftover is cleared by the TTL
        sweep once it is older than the TTL, marker or no marker
        (:func:`sweep_stale_workspaces`); one left at the session's own path
        (the rename aside was refused) may have lost its marker to the delete,
        and the sweep never removes an unmarked directory, so the warning says
        it stays until removed by hand.
        """
        from automated_security_helper.cli.mcp.source_delivery import _remove_tree

        if not workspace.exists():
            return
        if _remove_tree(workspace):
            return
        from automated_security_helper.utils.log import ASH_LOGGER

        if is_a_deleting_name(workspace.name):
            outlook = (
                "The TTL sweep removes what is left once it is older than the TTL."
            )
        else:
            outlook = (
                "It could not be renamed aside first, so what is left stands at "
                "the session's own path, may have lost its session marker, and "
                "stays until it is removed by hand."
            )
        ASH_LOGGER.warning(
            "Could not remove all of %s, the workspace of a session that "
            "disconnected: some entry in it cannot be removed by this account. %s",
            workspace,
            outlook,
        )

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
    """Remove the workspace, delivered-source record, bound profile and entry.

    The workspace is deleted under a hidden name (``remove_session_workspace``),
    so the session's own path is free while the delete runs. The registry entry is
    then dropped with ``forget``, which never touches the disk: a request for the
    same id that built a fresh workspace during the delete keeps it. (``disconnect``
    would rename and delete whatever stands at the session's path.)
    """
    from automated_security_helper.cli.mcp.profile_registry import (
        clear_session_state,
    )
    from automated_security_helper.cli.mcp.source_delivery import (
        remove_session_workspace,
    )

    try:
        # end_session holds the session's lock already.
        remove_session_workspace(session_id)
    except (ValueError, RuntimeError):
        # An id that cannot name a directory never had a workspace, and with no
        # workspace root (no home directory, RuntimeError) there is none to
        # remove; the bound profile and the entry are the server's own and are
        # cleared either way.
        pass
    clear_session_state(session_id)
    get_default_registry().forget(session_id)


def end_session(session_id: str) -> bool:
    """Remove everything the server holds for ``session_id``, which has ended.

    The session's sandbox (``<workspace root>/<session id>``: the delivered
    tree, uploads in progress, the config ``select_profile`` materialized), its
    delivered-source record, its bound profile, and its registry entry. Removing
    the tree a scan is reading can turn its result into a clean one, so a scan
    that holds the session defers the removal:

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

    If the scan presence lock can't be taken, nothing proves that no scan
    elsewhere holds the session: the tree stays on disk, and the bound profile,
    the delivered-source record and the registry entry are cleared now, with one
    warning naming the lock and the error. The TTL sweep needs the same lock, so
    it removes the tree at the first pass that can take the lock once the
    workspace is past its TTL; every request that names the session refreshes
    that clock (:func:`touch_session_workspace`).

    Returns:
        True when everything was removed now, False when it waits for a scan or
        the tree stays for the sweep.
    """
    try:
        session: Optional[MCPSession] = get_default_registry().session_for(session_id)
    except ValueError:
        session = None
    # Marked before the change is tried: a scan or a write that releases the
    # session right after the refusal below must already find the removal pending.
    with _ended_lock:
        _ended_while_scanning.add(session_id)
    # try_begin_change answers None when the change began, and why it was refused
    # otherwise.
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
    no registry is opened for it. A reserved name other than the stdio session's
    (``session_identity.is_reserved_session_id``: a presence registry, the
    registries' guard file :data:`PRESENCE_LOCK_NAME`, the unidentified sentinel,
    a spelling of the stdio id that opens its directory on a case-insensitive
    filesystem) never has a presence entry and has no workspace of its own: what
    stands at the name under the root is the server's, so only the in-memory
    state is cleared for it and nothing on disk is touched. The stdio session is
    shared by every stdio server of one user, and a scan of it in a sibling
    server holds a presence entry like a replica's scan of a session
    (:func:`_publishes_scan_presence`), so ending it reads the registry as for
    any session. Only ``ValueError`` and ``RuntimeError`` (an id that names no
    directory, no workspace root) mean there is no workspace: an ``OSError``
    from the stat of the directory says nothing about whether it exists, so
    that case takes the guarded path like a session whose directory is there.

    If the presence lock cannot be taken, nothing proves that no scan holds the
    session, so the tree stays on disk. The TTL sweep needs the same lock, so
    while the lock stays refused nothing removes the tree; one warning per run
    of refusals says so (:func:`_warn_guard_refused_once`, shared with the sweep
    and ``ScanPresence``) names the lock path and the error, and the sweep
    removes the tree at the first pass that can take the lock once the workspace
    is past its TTL (every request that names the session refreshes it,
    :func:`touch_session_workspace`). The server's own
    memory of the session (its bound profile, delivered-source record and
    registry entry) is cleared now, so such a root does not build up state for
    the life of the process.

    The stdio session is the exception to a refused lock: its workspace is removed
    as it was before the registry covered it. Nothing registers a scan on a root
    whose registry is refused, and the TTL sweep never collects the stdio
    workspace (a reserved name), so a tree left for it would stay for good.

    An ``OSError`` after the lock was taken (the check for a scan, the removal) is
    logged with one warning and ends the call as a refused lock does.

    Returns:
        True when the state was removed, False when the removal must wait for a
        scan, None when the lock could not be taken or the check or removal
        failed, and only the in-memory state was cleared.
    """
    from automated_security_helper.cli.mcp.session_identity import (
        is_reserved_session_id,
    )

    if is_reserved_session_id(session_id) and not _is_the_stdio_session(session_id):
        # A presence registry, the unidentified sentinel, or an alias of the
        # stdio id: the directory of that name is the server's, not a
        # session's, so it is never removed as one.
        _forget_session_in_memory(session_id)
        return True
    try:
        root = _workspace_root()
        sandbox = session_directory(root, session_id)
    except (RuntimeError, ValueError):
        # No workspace root, or an id that names no directory under it.
        _remove_session_state(session_id)
        return True
    try:
        has_workspace = sandbox.is_dir()
    except OSError:
        # ``Path.is_dir()`` re-raises EACCES, EIO and ESTALE on Python <= 3.13
        # instead of answering False. The workspace may exist, so the removal
        # takes the guarded path below, as ``ScanPresence`` registers for it.
        has_workspace = True
    if not has_workspace or not _publishes_scan_presence(session_id):
        _remove_session_state(session_id)
        return True
    holder = root / SCAN_PRESENCE_DIR / session_id
    try:
        with contextlib.ExitStack() as stack:
            try:
                stack.enter_context(_scan_presence_guard(root))
            except OSError as exc:
                if _is_the_stdio_session(session_id):
                    # Nothing registers a scan on a root whose registry is
                    # refused, and the TTL sweep never collects the stdio
                    # workspace, so a tree left for it would stay for good:
                    # it is removed as before the registry covered it.
                    _remove_session_state(session_id)
                    return True
                _forget_session_in_memory(session_id)
                _warn_guard_refused_once(root, exc, f"ending session {session_id!r}")
                return None
            if _a_scan_holds(holder):
                return False
            _remove_session_state(session_id)
            with contextlib.suppress(OSError):
                holder.rmdir()
            return True
    except OSError as exc:
        # The check for a scan or the removal failed after the lock was taken.
        # Nothing proves that no scan holds the session, so the tree stays for
        # the TTL sweep and the server's own state is cleared, as for a refused
        # lock. The id is not recorded as held by a scan, which it is not known
        # to be.
        from automated_security_helper.utils.log import ASH_LOGGER

        _forget_session_in_memory(session_id)
        ASH_LOGGER.warning(
            "Could not finish ending session %r (%s): its workspace stays on "
            "disk for the TTL sweep, and the server's own state for it is "
            "cleared.",
            session_id,
            _describe_os_error(exc),
        )
        return None


def _forget_session_in_memory(session_id: str) -> None:
    """Drop the session's in-memory state, leaving the workspace on disk.

    The bound profile, the delivered-source record and the registry entry all
    go. The sweep opens no registry entry while its presence guard is refused
    (:func:`sweep_stale_workspaces`), so the forget stands until a later request
    names the id. A delivered-source record left behind would keep
    ``delivered_session_count`` inflated by the ended session, and would make
    ``holds_binding`` read any later entry for the id as bound, so it would not
    be evicted.
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
    """Complete the removal of a session that ended while its scan or write ran.

    The stdio session is shared by every stdio server of one user, and its end
    is decided by the exiting server under the presence registry's lock, when no
    other server is live (:meth:`StdioServerPresence.__exit__`). A scan that
    outlived that decision completes it here, later, when a server started
    since may be using the workspace, so the question is asked again: another
    live server keeps the workspace, and its removal falls to the last one out.
    """
    if session_id is None:
        return
    with _ended_lock:
        pending = session_id in _ended_while_scanning
    if not pending:
        return
    if not _is_the_stdio_session(session_id):
        end_session(session_id)
        return
    # The end runs under the registry's lock, where the question is answered,
    # so a server registering between the answer and the removal is counted or
    # starts after it; a registry that cannot be read keeps the workspace.
    if StdioServerPresence.a_server_is_live(if_none=lambda: end_session(session_id)):
        # The workspace stays for the live server (or for the last one out,
        # when the registry could not be read), but this server's own memory
        # of the session ended with it: its bound profile, delivered-source
        # record and registry entry are the exiting server's, not the
        # sibling's, so they are dropped as end_session would have dropped them.
        _forget_session_in_memory(session_id)
        with _ended_lock:
            _ended_while_scanning.discard(session_id)


def _is_the_stdio_session(session_id: str) -> bool:
    from automated_security_helper.cli.mcp.profile_registry import (
        DEFAULT_SESSION_ID,
    )

    return session_id == DEFAULT_SESSION_ID


def _publishes_scan_presence(session_id: Optional[str]) -> bool:
    """Whether a scan of ``session_id`` is marked for the other servers sharing the root.

    Every session with a workspace is, the stdio session included: every stdio
    server of one user resolves the same ``<root>/__default__``, so a scan of it
    in one server is as invisible to a sibling server's change as a replica's
    scan of a session is to another replica's, and the sibling would replace or
    remove the tree under it. The other reserved names (the unidentified
    sentinel, the two registries; ``session_identity.is_reserved_session_id``)
    name no session and never have a workspace.
    """
    from automated_security_helper.cli.mcp.session_identity import (
        is_reserved_session_id,
    )

    if not session_id:
        return False
    return _is_the_stdio_session(session_id) or not is_reserved_session_id(session_id)


#: ``error_type`` the MCP tools return for :class:`SessionWorkspaceBusyError`.
SESSION_WORKSPACE_BUSY = "session_workspace_busy"

#: ``error_type`` the MCP tools return for :class:`SessionChangeInProgressError`.
SESSION_CHANGE_IN_PROGRESS = "session_change_in_progress"


class SessionWorkspaceBusyError(RuntimeError):
    """A write to a session's state was refused: the TTL sweep is removing it.

    The session's state is gone once the removal is done, so the request is sent
    again from the start, an upload from its first chunk.
    """

    error_type = SESSION_WORKSPACE_BUSY


class SessionChangeInProgressError(SessionWorkspaceBusyError):
    """A write to a session's state was refused: a change that deletes its directory holds it.

    The change is ``clear_source`` or the end of the session. The request is sent
    again as it is once the change is done. A chunk is sent with the same
    sequence number; only an out-of-order answer then means that the upload was
    removed, and the upload is sent again from its first chunk.
    """

    error_type = SESSION_CHANGE_IN_PROGRESS


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
        session = get_default_registry().session_for(
            DEFAULT_SESSION_ID if session_id is None else session_id
        )
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
    read from ``ASH_CONFIG``, never from the config a scan resolves: that can be
    the scanned tree's own or one a client delivered, and a limit the limited
    party can raise is no limit. Read as the server's other limits are
    (``mcp_tools._resource_limits``, ``default_config_for_tree``): loaded as a
    scan rooted at the server's working directory loads it, so what an
    ``ASH_CONFIG`` file inside this checkout writes for an operator-only option
    is left out and does not make the file unloadable for this read while the
    scan itself reads past it; the two reads of one file then agree on its
    limits. Read per scan, so a changed ``ASH_CONFIG`` applies to the next one;
    a file that no longer loads leaves the default. 0 is no limit.

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
    from automated_security_helper.config.default_config import (
        default_config_for_tree,
    )

    if not caller_is_remote(session_id):
        return None
    try:
        settings = default_config_for_tree().mcp_resource_management
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
        "error": raw_controls_on_one_line(error),
    }


#: Directory under the workspace root holding one entry per live stdio server.
#: Not a session workspace: it carries no session marker, and
#: ``session_identity.is_reserved_session_id`` refuses it as a session id in any
#: letter case.
STDIO_SERVERS_DIR = ".stdio-servers"

#: The guard file of each presence registry, locked around every change to the
#: registry. Not a session id either (``session_identity.is_reserved_session_id``
#: refuses it in any letter case, trailing periods and spaces dropped): under
#: ``SCAN_PRESENCE_DIR`` a session's holder directory and the guard file share
#: one parent, so a session of this name would have its holder where the file
#: is, could register no scan, and could never be swept.
PRESENCE_LOCK_NAME = ".lock"
_STDIO_SERVERS_LOCK = PRESENCE_LOCK_NAME


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
    instead of reaching this. A server or scan that went on without a locked
    entry would read as dead to every other server sharing the root, which would
    remove the workspace under it. The entry is removed and nothing stays
    registered.

    Raises:
        PresenceLockError: naming the entry's path and the error that refused
            the lock.
    """
    taken = _try_lock(handle)
    if taken:
        return
    reason = getattr(taken, "error", None)
    detail = (
        _describe_os_error(reason)
        if isinstance(reason, OSError)
        else "no error was reported"
    )
    handle.close()
    with contextlib.suppress(OSError):
        entry.unlink()
    raise PresenceLockError(
        f"could not take the lock on {what} {entry}: the filesystem refused it "
        f"({detail}). The lock on the registry's guard file under the same "
        "workspace root was granted, so the filesystem does lock files there; "
        "the error says what refused this one. Without this lock other servers "
        "sharing the workspace root would read this process as dead and remove "
        "the workspace it is using, so it does not start. Set "
        "ASH_MCP_WORKSPACE_ROOT to another directory to start on a different "
        "root."
    )


class _LockOutcome:
    """The result of ``_try_lock``: true when the lock was taken.

    A refusal is false and carries the ``OSError`` that refused it in
    ``error``, so a caller that turns a refusal into a message can say why.
    """

    __slots__ = ("error",)

    def __init__(self, error: Optional[OSError] = None) -> None:
        self.error = error

    def __bool__(self) -> bool:
        return self.error is None


def _try_lock(handle: Any) -> _LockOutcome:
    """Take an exclusive lock on ``handle`` without waiting.

    The result is true if the lock was taken; a refusal is false and carries the
    ``OSError`` (:class:`_LockOutcome`).
    """
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
        return _LockOutcome()
    except OSError as exc:
        return _LockOutcome(exc)


def _lock_blocking(handle: Any) -> None:
    """Take an exclusive lock on ``handle``, waiting for as long as it takes.

    On POSIX ``flock`` waits. On Windows ``msvcrt.locking`` with ``LK_LOCK``
    tries once a second for ten seconds and then raises ``OSError``, so a
    server that waits behind a sibling's registration or exit for longer than
    that would read the refusal as "no registry", run uncounted, and have the
    default workspace removed under it by the next server to exit. The lock is
    asked for again until it is granted; only an error that is not the lock's
    refusal (a closed handle, say) is raised.
    """
    if sys.platform == "win32":
        import errno
        import msvcrt

        handle.seek(0)
        while True:
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                return
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EDEADLK):
                    raise
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
            # Private from the moment each level exists (the workspace root among
            # them when it is made here), as a session workspace is.
            make_private_dir(registry)
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

    @staticmethod
    def a_server_is_live(*, if_none: Optional[Callable[[], None]] = None) -> bool:
        """Whether any stdio server holds a locked entry in the presence registry.

        Read under the registry's lock file, as the exit check is, and
        ``if_none`` runs there, before the lock is dropped, when no server is
        live: a server registering meanwhile is either counted or starts after
        ``if_none`` ran, the promise the class makes for the exit check. The
        answer is True as well when the registry cannot be made, read or
        locked: a passing failure (a file table full, a directory read that
        fails) must not read as "no server is live" and remove the default
        workspace under a live sibling, so nothing runs on its account, the
        way the exit check keeps the workspace on an error. Said out loud,
        since the workspace then stays until the last server out removes it.
        """
        from automated_security_helper.utils.log import ASH_LOGGER

        try:
            registry = StdioServerPresence._registry()
            if not registry.parent.is_dir():
                # No workspace root: nothing of the default workspace exists to
                # remove, and a deferred end does not make the root to say so.
                raise FileNotFoundError(str(registry.parent))
            make_private_dir(registry)
            guard = open(registry / _STDIO_SERVERS_LOCK, "a+b")
        except (OSError, RuntimeError) as exc:
            ASH_LOGGER.warning(
                "Could not read the stdio server presence registry (%s): the "
                "default workspace is kept as if a server were live.",
                exc,
            )
            return True
        with guard:
            try:
                _lock_blocking(guard)
                live = StdioServerPresence._another_server_is_live(registry)
            except (OSError, RuntimeError) as exc:
                ASH_LOGGER.warning(
                    "Could not read the stdio server presence registry (%s): "
                    "the default workspace is kept as if a server were live.",
                    exc,
                )
                return True
            if live:
                return True
            if if_none is not None:
                if_none()
            return False

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
_SCAN_PRESENCE_LOCK = PRESENCE_LOCK_NAME

#: How long a TTL sweep waits for the scan presence lock another server holds,
#: in seconds: "about a second", as the MCP page puts it. A sweep that cannot
#: take the lock within it removes nothing more and leaves the remaining
#: sessions to its next sweep, so another server cannot hold up the request
#: that set the sweep off, or an interrupt, for as long as it keeps the lock.
#: Registering a scan still waits for as long as it takes (``_lock_blocking``):
#: a scan that ran unregistered could have its tree removed under it.
_SWEEP_LOCK_WAIT_SECONDS = 1.0

#: How long the busy gate of a change to a session's tree
#: (:func:`a_scan_in_another_server_holds`) waits for the scan presence lock
#: another server holds, in seconds. The gate runs on one of the server's few
#: delivery threads while it holds the session's change, so a wait as long as
#: the holder keeps the lock (another server's sweep deleting a tree, or its
#: shutdown ending every session in turn) would hold that thread and refuse
#: this server's own scans of the session meanwhile. A lock still held at the
#: end of the wait is answered as "busy", which the caller reports as the
#: retryable refusal it reports for a scan.
_BUSY_GATE_LOCK_WAIT_SECONDS = _SWEEP_LOCK_WAIT_SECONDS

#: How often a bounded wait asks for the lock again.
_LOCK_POLL_SECONDS = 0.05


class _PresenceLockHeld(Exception):
    """Another process held the scan presence lock for the whole bounded wait."""


def _is_lock_held_refusal(exc: OSError) -> bool:
    """True if ``exc`` is a non-blocking lock call's "someone else holds it"."""
    import errno

    names = ("EACCES", "EAGAIN", "EWOULDBLOCK", "EDEADLK")
    codes = {getattr(errno, name, None) for name in names}
    return exc.errno is not None and exc.errno in codes


def _lock_within(handle: Any, seconds: float) -> None:
    """Take an exclusive lock on ``handle``, asking for up to ``seconds``.

    The lock is asked for without waiting (``_try_lock``) every
    ``_LOCK_POLL_SECONDS`` until it is granted or the time is up, which raises
    :class:`_PresenceLockHeld`. A refusal that is not "another holder has it"
    (a filesystem without locks, a closed handle) is raised as the ``OSError``
    it is, so the caller reports it as the guard refusals are reported.
    """
    import time

    deadline = time.monotonic() + seconds
    while True:
        error = _try_lock(handle).error
        if error is None:
            return
        if not _is_lock_held_refusal(error):
            raise error
        if time.monotonic() >= deadline:
            raise _PresenceLockHeld
        time.sleep(_LOCK_POLL_SECONDS)


def _workspace_root() -> Path:
    from automated_security_helper.cli.mcp.source_delivery import (
        resolve_workspace_root,
    )

    return resolve_workspace_root()


@contextlib.contextmanager
def _scan_presence_guard(root: Path, *, wait: Optional[float] = None) -> Iterator[None]:
    """Hold the lock that registering a scan and the sweep's check-and-remove share.

    ``wait`` is None to wait for as long as it takes (registering a scan), or the
    seconds to ask for the lock before giving up with :class:`_PresenceLockHeld`
    (the TTL sweep, ``_SWEEP_LOCK_WAIT_SECONDS``; the busy gate of a change to a
    session's tree, ``_BUSY_GATE_LOCK_WAIT_SECONDS``).
    """
    registry = root / SCAN_PRESENCE_DIR
    make_private_dir(registry)
    with open(registry / _SCAN_PRESENCE_LOCK, "a+b") as guard:
        if wait is None:
            _lock_blocking(guard)
        else:
            _lock_within(guard, wait)
        _forget_guard_refusal_warning()
        yield


def _note_sweep_left_the_lock(root: Path) -> None:
    """Say, at info level, that a sweep gave the lock up to another server."""
    from automated_security_helper.utils.log import ASH_LOGGER

    ASH_LOGGER.info(
        "The TTL sweep could not take the scan presence lock %s within %.0f s "
        "because another server holds it; it removed nothing more this pass and "
        "leaves the remaining sessions to its next sweep.",
        root / SCAN_PRESENCE_DIR / _SCAN_PRESENCE_LOCK,
        _SWEEP_LOCK_WAIT_SECONDS,
    )


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

    The stdio session registers like any other: every stdio server of one user
    shares its workspace, so a sibling server's change has to see a scan of it
    (:func:`_publishes_scan_presence`), and the busy gate of a change reads the
    registry (:func:`a_scan_in_another_server_holds`). Nothing is registered,
    and nothing is reported, for a session with no workspace on disk or no
    resolvable workspace root: nothing of the session's
    is there to protect, and a scan of a directory the operator granted creates
    nothing under the root. Nothing is registered for a reserved name either
    (``session_identity.is_reserved_session_id``), the registries' guard file's
    among them: a session of that name would have its holder directory where the
    guard file is. A root whose registry can't be used leaves the scan
    unregistered rather than failing it, with a warning: a refused guard shares
    the process-wide warn-once latch (:func:`_warn_guard_refused_once`) with the
    TTL sweep and ``end_session``. A scan whose entry exists but can't be locked
    does not start: ``__enter__`` raises :class:`PresenceLockError`.

    The scan's end is a use of the workspace: ``__exit__`` sets the workspace's
    modification time to now, registered or not, before the entry is dropped.
    The TTL sweep reads liveness from that time, and a scan that ran longer than
    the TTL on a workspace nothing else touched would otherwise leave it older
    than the cutoff the moment the entry went, so the next pass would remove
    the tree and the results the scan had just written under it.

    Limits: as ``StdioServerPresence``, a server on another host sharing the root
    through a filesystem that does not share these locks can't see them.
    """

    def __init__(self, session_id: Optional[str]) -> None:
        self._session_id = session_id
        self._entry: Optional[Path] = None
        self._handle: Any = None
        # The workspace found on entry, touched on exit; None when none was.
        self._sandbox: Optional[Path] = None

    def __enter__(self) -> Self:
        import uuid

        session_id = self._session_id
        if not _publishes_scan_presence(session_id):
            return self
        try:
            root = _workspace_root()
            sandbox = session_directory(root, session_id)
            has_workspace = sandbox.is_dir()
        except (ValueError, RuntimeError):
            # No workspace root, or an id that names no directory under it: a
            # scan of a directory the operator granted registers nothing, so
            # there is no registry to report on.
            return self
        except OSError as exc:
            # ``Path.is_dir()`` re-raises EACCES, EIO and ESTALE on
            # Python <= 3.13 instead of answering False, and the stat is the
            # one statement here that raises ``OSError`` (``_workspace_root``
            # and ``session_directory`` are environment reads and path math).
            # The workspace may exist, so the scan runs unregistered rather
            # than returning in silence, and the warning is the one sign of
            # it an operator gets. It is its own warning for this scan: the
            # presence lock was not tried, so it does not use the guard's
            # warn-once text or set its latch, which a real refusal of the
            # guard still needs.
            from automated_security_helper.utils.log import ASH_LOGGER

            ASH_LOGGER.warning(
                "Could not examine the workspace of session %r (%s): the scan "
                "runs unregistered, so another server sharing the root cannot "
                "see it.",
                session_id,
                _describe_os_error(exc),
            )
            return self
        if not has_workspace:
            return self
        self._sandbox = sandbox
        guarded = False
        try:
            with _scan_presence_guard(root):
                guarded = True
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
        except OSError as exc:
            # The registry is out of reach: the scan runs unregistered rather
            # than failing, and the warning is the one sign of it an operator
            # gets. A refused guard is reported through the process-wide latch;
            # a failure after the guard was taken (the scan's own entry could
            # not be created) is a different condition, reported for this scan.
            self._entry = self._handle = None
            if not guarded:
                _warn_guard_refused_once(
                    root, exc, f"registering a scan of session {session_id!r}"
                )
            else:
                from automated_security_helper.utils.log import ASH_LOGGER

                ASH_LOGGER.warning(
                    "Could not create this scan's presence entry (%s): the "
                    "scan of session %r runs unregistered, so another server "
                    "sharing the root cannot see it.",
                    _describe_os_error(exc),
                    session_id,
                )
        return self

    def __exit__(self, *exc_info: object) -> None:
        sandbox, self._sandbox = self._sandbox, None
        if sandbox is not None:
            # Before the entry goes: while it is held no sweep removes the
            # workspace, and once it is gone the workspace's age is what keeps
            # it. Whatever ended the scan, its end was a use.
            _touch_workspace(sandbox)
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


def a_scan_in_another_server_holds(session_id: str) -> bool:
    """True while a scan of ``session_id`` in another server sharing the root holds its presence.

    For the busy gate of a change to the session's tree
    (``source_delivery._no_scan_running``), which holds the session's change when
    it asks: that excludes every scan of this process, and a scan of this process
    holds its presence entry only while it holds the session, so a live entry
    under ``<root>/.ash-mcp-scans/<session id>/`` is another server's. A replica
    behind a load balancer and a sibling stdio server of the same user are the
    two: the stdio session is shared by every stdio server of one user, and a
    scan of it registers like any other (:func:`_publishes_scan_presence`).
    Entries of scans whose server died are dropped on the way, as everywhere the
    registry is read.

    No guard is taken for a session with no workspace on disk: no scan of it can
    be registered (:class:`ScanPresence` registers a session with a workspace
    only), and the first delivery into a fresh root creates the workspace itself,
    under a root that may not exist yet.

    Fails open, with one warning: when the guard can't be taken (``OSError``) the
    answer is False. A root whose registry is refused is one where
    :class:`ScanPresence` runs unregistered too, so there is nothing there to
    read, and the change goes on as it did before the registry existed; the
    process-wide latch (:func:`_warn_guard_refused_once`) reports the refusal
    once. As :func:`scan_presence_held` says, False is "no scan is known to
    hold", not permission; what holds the session for the change is the
    session's change.

    Bounded: the guard is asked for ``_BUSY_GATE_LOCK_WAIT_SECONDS``, not for
    as long as another server keeps it. The gate runs on a delivery thread
    while it holds the session's change, so a wait as long as another server's
    sweep (a whole tree removal under the guard) or shutdown (every session
    ended in turn) would hold that thread and refuse this server's own scans
    of the session meanwhile. A lock still held at the end of the wait answers
    True: "busy", not "a scan was seen", which the caller reports as the same
    retryable refusal, so the client asks again rather than the thread waits.
    """
    try:
        root = _workspace_root()
        sandbox = session_directory(root, session_id)
        has_workspace = sandbox.is_dir()
    except (RuntimeError, ValueError):
        # No workspace root, or an id that names no directory under it: no
        # scan of it registered anything.
        return False
    except OSError:
        # ``Path.is_dir()`` re-raises EACCES, EIO and ESTALE on Python <= 3.13
        # instead of answering False. The workspace may exist, so the registry
        # is read.
        has_workspace = True
    if not has_workspace:
        return False
    try:
        with _scan_presence_guard(root, wait=_BUSY_GATE_LOCK_WAIT_SECONDS):
            return _a_scan_holds(root / SCAN_PRESENCE_DIR / session_id)
    except _PresenceLockHeld:
        # Another server kept the lock for the whole wait: whatever it is doing
        # under it (a sweep's removal, a shutdown's ends), the registry cannot
        # be read now, and a change that went on regardless could replace the
        # tree under a scan that holds an entry behind that lock.
        return True
    except OSError as exc:
        _warn_guard_refused_once(
            root,
            exc,
            f"checking for a scan of session {session_id!r} in another server",
        )
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
    except (OSError, ValueError, RuntimeError):
        return
    _touch_workspace(sandbox)


def _touch_workspace(sandbox: Path) -> None:
    """Set ``sandbox``'s modification time to now, if it is a directory of its own.

    A symlink is left alone: the sweep never follows one, and touching it would
    touch what it points at. A workspace that is gone, or that cannot be touched,
    is left as it is.
    """
    try:
        if sandbox.is_dir() and not sandbox.is_symlink():
            os.utime(sandbox)
    except OSError:
        pass


def sweep_stale_workspaces(
    ttl_seconds: float,
    now: Optional[float] = None,
    *,
    in_use: Optional[Collection[str]] = None,
) -> List[str]:
    """Remove session workspaces nobody used for longer than ``ttl_seconds``.

    ``in_use`` names the sessions the caller knows to be live (the HTTP
    boundary's: the sessions whose sse event stream is open right now). Those
    are kept whatever their age: an open stream that has sent no message for
    longer than the TTL is idle, not ended, and its workspace, bound profile and
    delivered-source record end with the stream (``end_session``), not with the
    sweep. The keep is this process's knowledge only; a caller that shares the
    root with other servers also marks those workspaces used
    (``touch_session_workspace``), since another server's sweep reads age alone.

    Only directories ASH created are considered. A session workspace carries
    ``session_paths.SESSION_MARKER``, and anything else under the root (an
    operator's notes, a ``.git`` directory) is never removed. The one entry
    removed without the marker is the leftover of a delete that could not finish:
    a directory named ``.<session id>.deleting-<uuid4>`` (the hidden name an ended
    session's workspace is renamed to, ``session_paths.hidden_deleting_name``),
    which may have lost its marker to the delete itself. It is removed once its
    own modification time, set at the rename, is older than the TTL, and only when
    nothing owns the name: no registry entry of this process and no scan-presence
    directory (:func:`_remove_stale_leftover`). One that cannot be deleted is
    logged once.

    "Used" is the newest modification time of the sandbox directory and its
    direct children; every HTTP request that names a session refreshes it
    (:func:`touch_session_workspace`), every delivery writes there, and the end
    of every scan of the session refreshes it (:class:`ScanPresence`), so a scan
    that ran longer than the TTL does not leave its workspace stale the moment
    it returns. Skipped, and never queued for later:

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
    (``MCPSessionRegistry.session_for``), or a workspace whose removal raises
    (an ``OSError``, ``RuntimeError`` or ``ValueError`` out of the registry or
    the removal): that one is logged with its id and left for the next pass, and
    the sweep goes on to the next entry rather than ending the pass with every
    later entry unread. (The registry's refusal of the unidentified sentinel is
    defensive here: a reserved name is skipped before the registry is asked.)

    This is also what removes a session whose end :func:`end_session` deferred
    for a scan in another server: that scan's end is not seen here.

    The presence guard is tried once, after the stale workspaces are listed and
    before any session is looked up. If the filesystem refuses it, no removal
    can be proven safe: the sweep reports it through the process-wide latch
    (:func:`_warn_guard_refused_once`) and returns ``[]`` without opening
    a registry entry for any workspace. A per-workspace lookup would create the
    entry that :func:`end_session` forgot, and refresh its idle time on every
    pass. The guard is asked for for about a second (``_SWEEP_LOCK_WAIT_SECONDS``),
    here and again before each removal: a sweep that cannot take it, because
    another server sharing the root holds it, removes nothing more and leaves
    the remaining sessions to its next sweep (:func:`_note_sweep_left_the_lock`),
    so another server cannot hold up the request that set the sweep off, or an
    interrupt, for as long as it keeps the lock.

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
    stale: List[Path] = []
    for entry in entries:
        session_id = entry.name
        if is_a_deleting_name(session_id):
            # What an ended session's delete could not finish. It is no session
            # and may have lost its marker, so it is cleared on its age alone,
            # unless something owns the name (_remove_stale_leftover).
            _remove_stale_leftover(root, entry, cutoff)
            continue
        if is_reserved_session_id(session_id):
            continue
        if in_use is not None and session_id in in_use:
            # Still issued by the caller: its end comes through end_session.
            continue
        try:
            validated_path_component(session_id)
            if not _is_stale_workspace(entry, cutoff):
                continue
        except (OSError, ValueError):
            continue
        stale.append(entry)
    if not stale:
        return []
    try:
        with _scan_presence_guard(root, wait=_SWEEP_LOCK_WAIT_SECONDS):
            pass
    except _PresenceLockHeld:
        # Another server holds the lock: this pass removes nothing and the
        # request that set it off is answered; the next sweep tries again.
        _note_sweep_left_the_lock(root)
        return []
    except OSError as exc:
        _warn_guard_refused_once(root, exc, "running the TTL sweep")
        return []
    removed: List[str] = []
    for entry in stale:
        try:
            if _remove_if_still_stale(root, entry.name, entry, cutoff):
                removed.append(entry.name)
        except _PresenceLockHeld:
            # The lock was taken by another server between two workspaces:
            # nothing more is removed this pass (the page's promise), and the
            # remaining stale workspaces are left to the next sweep.
            _note_sweep_left_the_lock(root)
            break
        except (OSError, RuntimeError, ValueError) as exc:
            # One workspace's failure (a registry refusal, a removal that
            # raised past its own handling) is that workspace's: it is named
            # and left for the next pass, and the sweep goes on to the rest
            # instead of ending the pass with every later entry unread.
            _warn_sweep_failure_once(
                entry.name,
                _describe_os_error(exc) if isinstance(exc, OSError) else str(exc),
            )
    return removed


#: Session ids whose removal the sweep has already reported as failing, so a
#: workspace that keeps failing (a file another account owns) is named once for
#: the life of the process, not on every pass, as a leftover is
#: (``_warn_leftover_once``). A session the sweep later removes leaves the set,
#: so a new failure of a reused id is reported again.
_sweep_failures_warned: Set[str] = set()


def _warn_sweep_failure_once(session_id: str, detail: str) -> None:
    """Log once per session id that the sweep could not remove its workspace."""
    from automated_security_helper.utils.log import ASH_LOGGER

    with _leftovers_warned_lock:
        if session_id in _sweep_failures_warned:
            return
        _sweep_failures_warned.add(session_id)
    ASH_LOGGER.warning(
        "The TTL sweep could not remove session %r (%s); its workspace stays "
        "for the next pass. This is the only warning for it until a pass "
        "removes it.",
        session_id,
        detail,
    )


def _forget_sweep_failure(session_id: str) -> None:
    """A removal worked: a later failure of the same id is reported as new."""
    with _leftovers_warned_lock:
        _sweep_failures_warned.discard(session_id)


def _remove_stale_leftover(root: Path, entry: Path, cutoff: float) -> None:
    """Delete a hidden delete-name directory older than the cutoff, best effort.

    A session workspace is renamed to ``.<session id>.deleting-<uuid4>`` before it
    is deleted (:func:`~automated_security_helper.cli.mcp.source_delivery.remove_session_workspace`),
    and what that delete could not remove stays under the name. The age is the
    directory's own mtime: the entries inside may be unreadable to this process.
    The rename sets the mtime to the time of the rename, so a delete that has just
    started is younger than any TTL. A symlink or a file of that name is left
    alone.

    The entry is a leftover only if nothing owns the name. A registry entry of this
    process, or a scan-presence directory (a scan of another server), means the
    name is a session's: an id of this shape is refused where ids are validated
    (``session_paths.validated_path_component``), but one admitted by an older
    server, or put on disk some other way, names a live tree, and the sweep leaves
    it alone whatever its age.

    A leftover whose delete failed is reported once (:func:`_warn_leftover_once`) and
    then not attempted again by this process. Each attempt is two full delete passes
    with chmod retries, and a leftover that holds files another account owns costs
    that on every sweep. The tree stays on disk until it is removed by hand or the
    server restarts, which is what the one warning says.
    """
    from automated_security_helper.cli.mcp.source_delivery import _remove_tree

    try:
        if entry.is_symlink() or not entry.is_dir():
            return
        if entry.lstat().st_mtime >= cutoff:
            return
        if get_default_registry().get(entry.name) is not None:
            return
        if (root / SCAN_PRESENCE_DIR / entry.name).exists():
            return
    except OSError:
        return
    with _leftovers_warned_lock:
        if entry.name in _leftovers_warned:
            return
    if not _remove_tree(entry):
        _warn_leftover_once(entry)


#: Names of leftovers already reported as not deletable, so the sweep says so once
#: per name for the life of the process and not on every pass.
_leftovers_warned: Set[str] = set()
_leftovers_warned_lock = threading.Lock()


def _warn_leftover_once(entry: Path) -> None:
    """Log once per name that a hidden delete-name directory could not be removed."""
    from automated_security_helper.utils.log import ASH_LOGGER

    with _leftovers_warned_lock:
        if entry.name in _leftovers_warned:
            return
        _leftovers_warned.add(entry.name)
    ASH_LOGGER.warning(
        "The TTL sweep could not delete %s, what is left of a session workspace "
        "that was being deleted. Some entry in it cannot be removed by this "
        "account. It stays on disk until it is removed by hand; this is the only "
        "warning for it.",
        entry,
    )


def _is_stale_workspace(entry: Path, cutoff: float) -> bool:
    if entry.is_symlink() or not entry.is_dir():
        return False
    marker = entry / SESSION_MARKER
    if marker.is_symlink() or not marker.is_file():
        return False
    return _last_used(entry) < cutoff


#: Whether this process already warned that the scan presence guard was
#: refused. One latch serves every place that takes the guard and reports a
#: refusal (the TTL sweep, ``end_session`` and ``ScanPresence``): while the guard
#: stays refused each of them is refused the same way, so one warning tells the
#: operator, and one per sweep, per ended session (``_end_all_on_shutdown`` ends
#: them all at once) or per scan would repeat for the life of the process. A
#: guard that is taken clears it (:func:`_forget_guard_refusal_warning`), so a
#: refusal after that is reported again, whatever the first one was.
_guard_refusal_warned = False
_guard_refusal_warned_lock = threading.Lock()


def _forget_guard_refusal_warning() -> None:
    """Clear the warn-once latch: the presence guard was just taken."""
    global _guard_refusal_warned
    with _guard_refusal_warned_lock:
        _guard_refusal_warned = False


def reset_guard_refusal_warning_for_tests() -> None:
    """Clear the warn-once latch — for test isolation only.

    The latch is process state, like the default registry
    (:func:`reset_default_registry_for_tests`): a test that meets a refused guard
    leaves it set for every later test in the process.
    """
    _forget_guard_refusal_warning()


def _is_lock_refusal(exc: OSError) -> bool:
    """True if ``exc`` says the filesystem cannot lock files at all.

    ENOLCK (no locks available), EOPNOTSUPP/ENOTSUP and ENOSYS are the errnos a
    locking call returns when the filesystem or kernel has no file locks. Every
    other failure of the guard (mkdir or open refused, too many open files, a
    Windows lock that timed out) says nothing about lock support.
    """
    import errno

    names = ("ENOLCK", "EOPNOTSUPP", "ENOTSUP", "ENOSYS")
    codes = {getattr(errno, name, None) for name in names}
    return exc.errno is not None and exc.errno in codes


def _describe_os_error(exc: OSError) -> str:
    """The errno, its name, its text and the file that failed, for a warning:
    ``errno 13 EACCES: Permission denied: /root/.ash-mcp-scans``.

    Naming the file matters because one guard warning stands for several
    operations: the registry mkdir, the lock file's open and the lock call
    (:func:`_scan_presence_guard`), and the sandbox stat in
    :class:`ScanPresence`. The exception's own ``filename`` says which one
    failed; the lock call carries none, and the warning's fixed lock path
    already names it.
    """
    import errno

    if exc.errno is None:
        described = f"{type(exc).__name__}: {exc}"
    else:
        name = errno.errorcode.get(exc.errno, "unnamed")
        described = f"errno {exc.errno} {name}: {exc.strerror or exc}"
    if exc.filename:
        described += f": {exc.filename}"
        if exc.filename2:
            described += f" -> {exc.filename2}"
    return described


def _guard_refusal_outlook(exc: OSError) -> str:
    """What a refusal means for the next pass, from the failure's own errno."""
    if _is_lock_refusal(exc):
        return (
            "The filesystem reports that it cannot lock files, so this repeats "
            "on every pass until ASH_MCP_WORKSPACE_ROOT names a directory where "
            "locks work, or the filesystem's lock service recovers; a pass that "
            "takes the lock clears the warning latch, so a refusal after that "
            "is reported again."
        )
    return (
        "The failure is not a report that locks are unsupported, and it may "
        "clear: the next pass tries the lock again, and a refusal after a "
        "successful pass is reported again."
    )


def _warn_guard_refused_once(root: Path, exc: OSError, during: str) -> None:
    """Log one warning per run of refusals when the scan presence guard is refused.

    ``during`` names what was being done ("ending session 'x'"), so the one
    warning says where the refusal was first seen. A refusal while the latch is
    set is logged at debug level with the same detail.
    """
    global _guard_refusal_warned
    from automated_security_helper.utils.log import ASH_LOGGER

    lock_path = root / SCAN_PRESENCE_DIR / _SCAN_PRESENCE_LOCK
    with _guard_refusal_warned_lock:
        already_warned = _guard_refusal_warned
        _guard_refusal_warned = True
    if already_warned:
        ASH_LOGGER.debug(
            "The scan presence lock %s was refused again while %s (%s).",
            lock_path,
            during,
            _describe_os_error(exc),
        )
        return
    ASH_LOGGER.warning(
        "Could not take the scan presence lock %s while %s (%s). While it "
        "cannot be taken, a session workspace on this root stays on disk after "
        "it ends or goes idle, and a scan runs unregistered, so another server "
        "sharing the root cannot see it. This is the one warning for this run "
        "of refusals: any pass that takes the lock clears it, and a refusal "
        "after that is reported again. %s",
        lock_path,
        during,
        _describe_os_error(exc),
        _guard_refusal_outlook(exc),
    )


def _remove_if_still_stale(
    root: Path, session_id: str, sandbox: Path, cutoff: float
) -> bool:
    """Remove a stale session's state, unless anything holds it now.

    :func:`sweep_stale_workspaces` has already taken the presence guard once for
    the pass. A guard the filesystem refuses after that (a lock that fails
    between two workspaces) skips this removal and is reported through the
    process-wide latch (:func:`_warn_guard_refused_once`). A guard another server
    holds for the whole bounded wait raises :class:`_PresenceLockHeld`, which the
    sweep takes as the end of its pass.
    """

    if _remove_stale_session_state(root, session_id, sandbox, cutoff):
        return True
    finish_ended_session(session_id)
    return False


def _remove_stale_session_state(
    root: Path, session_id: str, sandbox: Path, cutoff: float
) -> bool:
    """:func:`_remove_if_still_stale`, up to the release of the sweep's change."""

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
                    stack.enter_context(
                        _scan_presence_guard(root, wait=_SWEEP_LOCK_WAIT_SECONDS)
                    )
                except OSError as exc:
                    _warn_guard_refused_once(root, exc, "running the TTL sweep")
                    return False
                if _a_scan_holds(root / SCAN_PRESENCE_DIR / session_id):
                    return False
                # The age read before the guard is not the age now: a scan in
                # another server that ended meanwhile touched the workspace and
                # then took this guard to drop its entry (ScanPresence.__exit__,
                # in that order), so this sweep, let in right after it, sees no
                # entry and a fresh mtime. Re-read under the guard, where that
                # order guarantees the touch is visible before the entry is gone.
                if not _is_stale_workspace(sandbox, cutoff):
                    return False
                _remove_session_state(session_id)
                _forget_sweep_failure(session_id)
                with contextlib.suppress(OSError):
                    (root / SCAN_PRESENCE_DIR / session_id).rmdir()
        except OSError as exc:
            # The check for a scan, or the removal, failed after the guard was
            # taken: the workspace stays for the next pass, and the failure is
            # named rather than swallowed, because a removal that keeps failing
            # is the one an operator has to see (a file another account owns,
            # a filesystem error). Named once per session, not on every pass
            # (at most every five minutes) for as long as it keeps failing.
            _warn_sweep_failure_once(session_id, _describe_os_error(exc))
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
    "PRESENCE_LOCK_NAME",
    "PresenceLockError",
    "SESSION_SCAN_LIMIT",
    "SESSION_CHANGE_IN_PROGRESS",
    "SESSION_WORKSPACE_BUSY",
    "SessionChangeInProgressError",
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
    "reset_guard_refusal_warning_for_tests",
    "sweep_stale_workspaces",
    "touch_session_workspace",
    "writing_session_state",
]
