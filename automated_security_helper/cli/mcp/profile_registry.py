# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Config profile registry + minimal per-session state for the MCP server.

Track 10.3 introduces a startup-time *profile registry* and three per-session
selection modes:

* **Static** — bind a registered profile as-is.
* **Inherit-and-patch** — bind a registered profile, then apply a JSON-Patch
  through the Track 10.4 allowlist via :mod:`runtime_patch`.
* **Full override** — replace the resolved config with a YAML string, still
  validated through :class:`AshConfig`.

The session state object here is intentionally minimal — Track 10.5 (#63) owns
the full ``MCPSession`` lifecycle and disconnect cleanup. We expose enough
surface (``bound_config``, ``profile_name``, ``patch_ops``, ``override_yaml``)
for downstream tools (``run_ash_scan``, ``mcp_validate_config``, etc.) to
prefer a session-bound config over an explicit ``config_path``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Dict, List, Optional, Tuple

import yaml

from automated_security_helper.config.ash_config import AshConfig


class ProfileRegistryError(ValueError):
    """Raised when a ``--profile`` spec cannot be parsed, loaded, or validated.

    Subclassing ``ValueError`` keeps the typer error path simple — the CLI
    layer turns a single ``ValueError`` into ``Validation Error: ...`` and
    exits with code 3.
    """


@dataclass(frozen=True)
class ProfileEntry:
    """A single registered profile.

    Frozen so the registry can be safely shared across threads without a
    caller mutating the bound :class:`AshConfig` in place. ``path_sha256``
    is computed over the absolute path string (not the file content) — the
    point is to surface "did the operator point a profile at a different
    file" without leaking the file contents.
    """

    name: str
    path: Path
    config: AshConfig
    path_sha256: str


def parse_profile_spec(spec: str) -> Tuple[str, Path]:
    """Split a ``--profile NAME=path`` spec into ``(name, path)``.

    Whitespace is stripped from both halves. The path is NOT resolved here —
    callers do that during loading so the error message can include the
    original literal the operator typed.
    """
    if "=" not in spec:
        raise ProfileRegistryError(
            f"--profile spec must be of the form NAME=path/to/ash.yaml, got {spec!r}"
        )
    name, _, raw_path = spec.partition("=")
    name = name.strip()
    raw_path = raw_path.strip()
    if not name:
        raise ProfileRegistryError(
            f"--profile spec missing name before '=': {spec!r}"
        )
    if not raw_path:
        raise ProfileRegistryError(
            f"--profile spec missing path after '=': {spec!r}"
        )
    return name, Path(raw_path)


def _sha256_of_path(path: Path) -> str:
    """Hash the absolute path string (not file content). Surfaces *which*
    file is registered under each name without exposing the content.
    """
    return hashlib.sha256(str(path.resolve()).encode("utf-8")).hexdigest()


def register_profiles(specs: List[str]) -> Dict[str, ProfileEntry]:
    """Parse + load every ``--profile`` spec into a registry dict.

    Each profile is loaded via :meth:`AshConfig.from_file`, so the same
    YAML/JSON/!ENV resolution path the regular CLI uses is in effect here.

    Raises:
        ProfileRegistryError: on duplicate name, missing file, malformed
            YAML, or AshConfig validation failure.
    """
    registry: Dict[str, ProfileEntry] = {}
    for spec in specs:
        name, path = parse_profile_spec(spec)
        if name in registry:
            raise ProfileRegistryError(
                f"duplicate --profile name {name!r} (already registered from "
                f"{registry[name].path})"
            )
        if not path.exists():
            raise ProfileRegistryError(
                f"--profile {name!r} points at missing file: {path}"
            )
        try:
            cfg = AshConfig.from_file(path)
        except yaml.YAMLError as exc:
            raise ProfileRegistryError(
                f"--profile {name!r} failed to parse {path}: {exc}"
            ) from exc
        except Exception as exc:
            # Pydantic ValidationError, JSON decode errors, OSError, etc.
            raise ProfileRegistryError(
                f"--profile {name!r} failed to load {path}: {exc}"
            ) from exc
        # Re-validate the *raw* YAML/JSON against AshConfig with extra='forbid'
        # so operator typos in profile YAML fail at MCP boot rather than at
        # silently-ignored runtime. AshConfig.model_config has extra='ignore'
        # for end-user-config back-compat — operator-controlled profiles are
        # deployment artifacts and should be strict.
        try:
            with open(path, mode="r", encoding="utf-8") as f:
                if str(path).endswith(".json"):
                    import json as _json

                    raw = _json.load(f)
                else:
                    raw = yaml.safe_load(f)
            allowed = set(AshConfig.model_fields.keys())
            for fname, finfo in AshConfig.model_fields.items():
                if finfo.alias:
                    allowed.add(finfo.alias)
            unknown = sorted(set(raw or {}) - allowed)
            if unknown:
                raise ProfileRegistryError(
                    f"--profile {name!r} has unknown top-level field(s): "
                    f"{', '.join(unknown)}"
                )
        except ProfileRegistryError:
            raise
        except Exception as exc:
            raise ProfileRegistryError(
                f"--profile {name!r} re-validation against schema failed: {exc}"
            ) from exc
        registry[name] = ProfileEntry(
            name=name,
            path=path,
            config=cfg,
            path_sha256=_sha256_of_path(path),
        )
    return registry


# ---------------------------------------------------------------------------
# Process-local registry singleton
# ---------------------------------------------------------------------------

_lock = RLock()
_profile_registry: Dict[str, ProfileEntry] = {}


def set_profile_registry(registry: Dict[str, ProfileEntry]) -> None:
    """Install ``registry`` as the active process-local profile registry.

    Called once from ``mcp_command`` after parsing ``--profile`` flags.
    Tests call this directly to seed fixtures.
    """
    with _lock:
        _profile_registry.clear()
        _profile_registry.update(registry)


def get_profile_registry() -> Dict[str, ProfileEntry]:
    """Return a *copy* of the active profile registry.

    A copy keeps callers from mutating the live registry. The values
    themselves (``ProfileEntry`` instances) are frozen.
    """
    with _lock:
        return dict(_profile_registry)


def clear_profile_registry() -> None:
    """Drop every registered profile. Used by tests between cases."""
    with _lock:
        _profile_registry.clear()


# ---------------------------------------------------------------------------
# Per-session state
# ---------------------------------------------------------------------------

# Track 10.5 (#63) owns the full ``MCPSession`` shape (workspace_root,
# disconnect cleanup, etc.). We define just the surface ``select_profile``
# needs so its tests can exercise the binding without depending on #63.


@dataclass
class SessionState:
    """Minimal per-connection state for Track 10.3.

    Track 10.5 will generalize this into a full ``MCPSession`` with workspace
    + disconnect handling. Until then we hold only what binding the resolved
    config requires.
    """

    session_id: str
    bound_config: Optional[AshConfig] = None
    profile_name: Optional[str] = None
    patch_ops: Optional[List[Dict]] = field(default=None)
    override_yaml: Optional[str] = None


_session_lock = RLock()
_session_state: Dict[str, SessionState] = {}

# When no session id can be resolved (e.g. a stdio client that doesn't expose
# one), tools fall back to a single shared key. This matches the existing
# "single-tenant stdio" assumption in the rest of the MCP server.
DEFAULT_SESSION_ID = "__default__"


def get_session_state(session_id: Optional[str] = None) -> SessionState:
    """Return the SessionState for ``session_id``, creating it on first use.

    ``None`` resolves to :data:`DEFAULT_SESSION_ID` so callers without an
    explicit id (stdio transport, in-process tests) still get a stable slot.
    """
    sid = session_id or DEFAULT_SESSION_ID
    with _session_lock:
        state = _session_state.get(sid)
        if state is None:
            state = SessionState(session_id=sid)
            _session_state[sid] = state
        return state


def bind_session_config(
    session_id: Optional[str],
    *,
    config: AshConfig,
    profile_name: str,
    patch_ops: Optional[List[Dict]] = None,
    override_yaml: Optional[str] = None,
) -> SessionState:
    """Bind a resolved config to ``session_id``.

    ``patch_ops`` and ``override_yaml`` are stored verbatim for diagnostics
    so a future ``mcp__ash__get_session`` tool can show *how* the config was
    derived (static, inherit-and-patch, full-override).
    """
    sid = session_id or DEFAULT_SESSION_ID
    with _session_lock:
        state = SessionState(
            session_id=sid,
            bound_config=config,
            profile_name=profile_name,
            patch_ops=patch_ops,
            override_yaml=override_yaml,
        )
        _session_state[sid] = state
        return state


def clear_session_state(session_id: Optional[str] = None) -> None:
    """Drop the SessionState for ``session_id`` (or every state if None).

    Track 10.5 will hook this into ``on_disconnect``; for Track 10.3 it
    exists so tests can scrub between cases.
    """
    with _session_lock:
        if session_id is None:
            _session_state.clear()
        else:
            _session_state.pop(session_id, None)
