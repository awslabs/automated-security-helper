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
SDK answers 404 for a session this app issued (it discarded it), when an sse
event stream closes, and for every session an app issued when the app shuts
down; ``mcp_server.run_mcp_server`` calls it for the stdio session when the
server exits. A stateless server sees no end at all, and a stateful session the
SDK closed for being idle sends no request that ASH could see, so
:func:`sweep_stale_workspaces` removes workspaces nobody used for longer than a
TTL, on every HTTP transport.

The registry's workspace directory is the session's sandbox under
``source_delivery.resolve_workspace_root()``, the directory source delivery
writes, so ending a session removes the tree that was delivered to it.
"""

from __future__ import annotations

import os
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from automated_security_helper.cli.mcp.session_paths import (
    session_directory,
    validated_path_component,
)

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig


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

    @property
    def lock(self) -> threading.Lock:
        """Public accessor for the per-session lock.

        Callers running a scan should acquire this for the duration of the
        scan so that the same session never runs two scans concurrently.
        """
        return self._lock


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

    def get_or_create(self, session_id: str) -> MCPSession:
        """Return the session for ``session_id``, creating one if needed.

        Repeated calls with the same id return the same instance — the lock
        identity is preserved so per-session serialization works.

        Raises:
            ValueError: if ``session_id`` is not usable as a single path
                component. The id becomes a directory this method creates and
                ``disconnect`` removes, so it is validated here rather than
                trusted from the caller; ``cli/mcp/session_paths.py`` holds the
                rule, shared with the other surfaces that build a per-session
                path.

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
            workspace.mkdir(parents=True, exist_ok=True)
            session = MCPSession(id=session_id, workspace_root=workspace)
            self._sessions[session_id] = session
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
    if session is not None and not session.lock.acquire(blocking=False):
        with _ended_lock:
            _ended_while_scanning.add(session_id)
        return False
    try:
        _remove_session_state(session_id)
    finally:
        if session is not None:
            session.lock.release()
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

    "Used" is the newest modification time of the sandbox directory and its
    direct children; every HTTP request that names a session refreshes it
    (:func:`touch_session_workspace`), and every delivery writes there. A
    session whose scan is running is skipped, and so is the stdio session,
    which its own server removes when it exits. Entries that are not
    directories, are symlinks, or do not name a single directory are left
    alone.

    Returns:
        The session ids whose workspaces were removed.
    """
    import time

    from automated_security_helper.cli.mcp.profile_registry import (
        DEFAULT_SESSION_ID,
    )
    from automated_security_helper.cli.mcp.source_delivery import (
        resolve_workspace_root,
    )

    try:
        root = resolve_workspace_root()
        entries = list(root.iterdir()) if root.is_dir() else []
    except (OSError, RuntimeError):
        return []
    cutoff = (time.time() if now is None else now) - ttl_seconds
    removed: List[str] = []
    for entry in entries:
        session_id = entry.name
        if session_id == DEFAULT_SESSION_ID:
            continue
        try:
            validated_path_component(session_id)
            if entry.is_symlink() or not entry.is_dir():
                continue
            if _last_used(entry) >= cutoff:
                continue
        except (OSError, ValueError):
            continue
        if end_session(session_id):
            removed.append(session_id)
    return removed


__all__ = [
    "MCPSession",
    "MCPSessionRegistry",
    "end_session",
    "finish_ended_session",
    "get_default_registry",
    "reset_default_registry_for_tests",
    "sweep_stale_workspaces",
    "touch_session_workspace",
]
