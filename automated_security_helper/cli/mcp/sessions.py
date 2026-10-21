# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Per-connection MCP session lifecycle and registry.

A *session* is the slice of state the MCP server holds for a single client
connection — the working source directory, the resolved profile, the patch
ops a client supplied at bind time, and the workspace scratch directory the
server uses to materialize that state for a scan. Sessions are NEVER
serialized (they hold a live ``threading.Lock``) and are NEVER shared across
clients (the workspace_root is per-connection scratch).

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
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Set

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr
from typing_extensions import Self

from automated_security_helper.cli.mcp.session_paths import (
    SESSION_MARKER,
    mark_session_workspace,
    session_directory,
    validated_path_component,
)

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig


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


class MCPSession(BaseModel):
    """Per-connection state for an MCP client.

    Fields:
        id: Stable connection identifier provided by the transport.
        source_dir: Directory the client asked us to scan, if bound.
        config: Resolved ``AshConfig`` for this session, if bound.
        profile_name: Name of the profile that produced ``config``.
        patch_ops: JSON-Patch ops the client supplied at bind time, if any.
        workspace_root: Per-session scratch directory. The disconnect hook
            rmtrees this path; do NOT place shared state here.
        created_at: UTC timestamp the session was created.

    The ``_lock`` private attribute serializes scans within a single session.
    Two threads scanning the *same* session must contend on this lock; two
    threads scanning *different* sessions never touch each other's lock and
    so run in parallel.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: str = Field(description="Stable per-connection identifier.")
    source_dir: Optional[Path] = Field(
        default=None,
        description="Directory the client asked us to scan, set at bind time.",
    )
    config: Optional["AshConfig"] = Field(
        default=None,
        description="Resolved AshConfig for this session, set at bind time.",
    )
    profile_name: Optional[str] = Field(
        default=None,
        description="Name of the profile that produced config.",
    )
    patch_ops: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="JSON-Patch ops the client supplied at bind time.",
    )
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
    # Requests writing the session's state outside a change, and whether the TTL
    # sweep holds the session; both guarded by _state_lock. See try_begin_write.
    _writes: int = PrivateAttr(default=0)
    _sweeping: bool = PrivateAttr(default=False)
    # Scans counted against the per-session limit and not yet returned. See
    # try_start_scan.
    _scan_count: ScanCount = PrivateAttr(default_factory=ScanCount)

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

    def try_begin_change(self) -> bool:
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
            False while a scan of the session holds :attr:`lock` or is claimed
            and not yet returned; otherwise True, holding :attr:`lock` until
            :meth:`end_change`.
        """
        if not self._lock.acquire(blocking=False):
            return False
        with self._state_lock:
            if self._claimed_scans:
                self._lock.release()
                return False
            self._changing = True
        return True

    def end_change(self) -> None:
        """End a change :meth:`try_begin_change` began."""
        with self._state_lock:
            self._changing = False
        self._lock.release()

    def try_begin_write(self) -> bool:
        """Hold the session against the TTL sweep for a request writing its state.

        A chunk of an upload and a profile binding write the session's state
        without taking its change (:meth:`try_begin_change`), which a running
        scan refuses: neither touches the tree a scan reads, so neither waits
        for one. The sweep runs on a worker thread and holds the session
        (:meth:`try_begin_sweep`) from its last look at the session's age until
        the removal is done, and a write that comes meanwhile is refused rather
        than accepted and then removed with the session. Writes do not exclude
        each other.

        The hold is this process's: it is on the in-memory session, so it keeps
        this server's sweep off the session. Another server sharing the
        workspace root sweeps by the session's age and its scan presence entry
        (:class:`ScanPresence`), and does not see a write in progress here.

        Returns:
            False while the sweep holds the session; otherwise True, until
            :meth:`end_write`.
        """
        with self._state_lock:
            if self._sweeping:
                return False
            self._writes += 1
            return True

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


# Resolve the ``AshConfig`` forward reference. Pydantic v2 refuses to
# instantiate a model with an unresolved string annotation, so we rebuild at
# import time. The bare ``AshConfig`` name must be available in this
# module's globals so ``model_rebuild`` can resolve the string form.
from automated_security_helper.config.ash_config import (  # noqa: E402,F401
    AshConfig,
)

MCPSession.model_rebuild()


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
                return existing
            workspace = session_directory(self._workspace_parent, session_id)
            session = MCPSession(id=session_id, workspace_root=workspace)
            self._sessions[session_id] = session
            return session

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

#: Sessions that ended while a scan of theirs held the session lock. Their
#: removal waits for the scan, so a scan's tree is never removed under it.
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
    can turn its result into a clean one.

    Idempotent.

    Returns:
        True when everything was removed now, False when it waits for a scan.
    """
    session = get_default_registry().get(session_id)
    if session is not None and not session.try_begin_change():
        with _ended_lock:
            _ended_while_scanning.add(session_id)
        return False
    try:
        _remove_session_state(session_id)
    finally:
        if session is not None:
            session.end_change()
    with _ended_lock:
        _ended_while_scanning.discard(session_id)
    return True


def finish_ended_session(session_id: Optional[str]) -> None:
    """Complete the removal of a session that ended while its scan ran."""
    if session_id is None:
        return
    with _ended_lock:
        pending = session_id in _ended_while_scanning
    if pending:
        end_session(session_id)


class SessionWorkspaceBusyError(RuntimeError):
    """A write to a session's state was refused: the TTL sweep is removing it."""


#: ``error_type`` the MCP tools return for :class:`SessionWorkspaceBusyError`.
SESSION_WORKSPACE_BUSY = "session_workspace_busy"


@contextlib.contextmanager
def writing_session_state(session_id: Optional[str]) -> Iterator[None]:
    """Hold ``session_id`` against the TTL sweep while a request writes its state.

    For a write outside the session's change: a chunk of an upload, a profile
    binding (``MCPSession.try_begin_write``). ``None`` is the stdio session. A
    caller with no session state, or an id that can't name one, is not held:
    the write itself refuses those. The hold is this process's; see
    ``MCPSession.try_begin_write``.

    Raises:
        SessionWorkspaceBusyError: while the sweep is removing the session, whose
            workspace nobody used for longer than the TTL. Its state is gone once
            the removal is done, so the request is sent again from the start: an
            upload from its first chunk.
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
    if not session.try_begin_write():
        raise SessionWorkspaceBusyError(
            "the server is removing this session's workspace, which nobody used "
            "for longer than its time to live; send the request again, and an "
            "upload from its first chunk"
        )
    try:
        yield
    finally:
        session.end_write()


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
    is removed. Registration and the exit check both run under one lock file,
    so a server starting while another exits is either counted or starts after
    the removal.

    Limits: a server on another host sharing the root through a network
    filesystem may not see this process's locks, and a root that cannot be
    created leaves the default workspace in place.
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
                entry = registry / f"{os.getpid()}-{uuid.uuid4().hex}"
                handle = open(entry, "a+b")
                # A file nobody else has opened: the lock is always free.
                _try_lock(handle)
                self._entry, self._handle = entry, handle
        except (OSError, RuntimeError):
            # No registry: this server is not counted, and on exit it leaves the
            # default workspace alone rather than guess.
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
    def _another_server_is_live(registry: Path) -> bool:
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
    created leaves the scan unregistered rather than failing it.

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
                # A file nobody else has opened: the lock is always free.
                _try_lock(handle)
                self._entry, self._handle = entry, handle
        except (OSError, ValueError, RuntimeError):
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
    """True if a running scan of ``session_id`` in any server holds its presence."""

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
    directory are left alone.

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
        if _remove_if_still_stale(root, session_id, entry, cutoff):
            removed.append(session_id)
    return removed


def _is_stale_workspace(entry: Path, cutoff: float) -> bool:
    if entry.is_symlink() or not entry.is_dir():
        return False
    marker = entry / SESSION_MARKER
    if marker.is_symlink() or not marker.is_file():
        return False
    return _last_used(entry) < cutoff


def _remove_if_still_stale(
    root: Path, session_id: str, sandbox: Path, cutoff: float
) -> bool:
    """Remove a stale session's state, unless anything holds it now."""

    session = get_default_registry().session_for(session_id)
    if not session.try_begin_change():
        return False
    try:
        # A request writing the session's state now keeps it, and one that comes
        # before the removal is done is refused (MCPSession.try_begin_write).
        if not session.try_begin_sweep():
            return False
        try:
            if not _is_stale_workspace(sandbox, cutoff):
                return False
            with _scan_presence_guard(root):
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
