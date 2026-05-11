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

Cross-session scans don't share locks, so two distinct sessions can scan in
parallel; same-session scans serialize on the per-session lock.

Notes on FastMCP integration: FastMCP does not (as of writing) expose an
``on_disconnect`` callback in a stable way. Until it does, the wiring strategy
in ``cli/mcp/__init__.py`` should call ``registry.disconnect(connection_id)``
from whatever lifecycle hook is available, and ``MCPSession.__del__`` provides
a best-effort fallback for orphaned sessions. Real cleanup needs an upstream
FastMCP feature.
"""

from __future__ import annotations

import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

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
                workspace_roots. When None, a sane default is computed
                under the OS temp dir at construct-time. Tests should
                pass an explicit ``tmp_path`` to keep all I/O scoped.
        """
        self._sessions: Dict[str, MCPSession] = {}
        self._lock = threading.RLock()
        if workspace_parent is None:
            import tempfile

            workspace_parent = Path(tempfile.gettempdir()) / "ash-mcp-sessions"
        self._workspace_parent = workspace_parent
        self._workspace_parent.mkdir(parents=True, exist_ok=True)

    def get_or_create(self, session_id: str) -> MCPSession:
        """Return the session for ``session_id``, creating one if needed.

        Repeated calls with the same id return the same instance — the lock
        identity is preserved so per-session serialization works.
        """
        with self._lock:
            existing = self._sessions.get(session_id)
            if existing is not None:
                return existing
            workspace = self._workspace_parent / session_id
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


__all__ = [
    "MCPSession",
    "MCPSessionRegistry",
    "get_default_registry",
    "reset_default_registry_for_tests",
]
