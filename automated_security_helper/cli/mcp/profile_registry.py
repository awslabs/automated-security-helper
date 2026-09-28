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
        raise ProfileRegistryError(f"--profile spec missing name before '=': {spec!r}")
    if not raw_path:
        raise ProfileRegistryError(f"--profile spec missing path after '=': {spec!r}")
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
        # Re-validate the *raw* YAML/JSON top-level keys against AshConfig
        # so operator typos in profile YAML fail at MCP boot rather than at
        # silently-ignored runtime. AshConfig.model_config has extra='ignore'
        # for end-user-config back-compat — operator-controlled profiles are
        # deployment artifacts and should be strict.
        #
        # Nested-segment typos (e.g. `scanners: { cdk_nag_typo: {...} }`)
        # are handled by Issue #82 — discriminated-union plugin config
        # validation — once that lands. Until then, a top-level gate
        # catches the common case (typos at the AshConfig root).
        try:
            with open(path, mode="r", encoding="utf-8") as f:
                if str(path).endswith(".json"):
                    import json as _json

                    raw = _json.load(f)
                else:
                    raw = yaml.safe_load(f)
            allowed = set(AshConfig.model_fields.keys())
            for finfo in AshConfig.model_fields.values():
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

    ``config_path`` is what makes a binding observable. ``bound_config`` is the
    resolved ``AshConfig``, and for a long time it was the only thing stored --
    which meant nothing could consume a binding, because the scan entry point
    takes a config *path*. The path here names a file
    :func:`materialize_session_config` wrote inside the session's own sandbox, so
    a scan can be handed it and the confinement boundary permits reading it.
    """

    session_id: str
    bound_config: Optional[AshConfig] = None
    profile_name: Optional[str] = None
    patch_ops: Optional[List[Dict]] = field(default=None)
    override_yaml: Optional[str] = None
    config_path: Optional[str] = None


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


#: Filename a bound config is materialized under, inside the session sandbox's
#: ``config/`` directory. Fixed rather than derived from the profile name: a
#: profile name is operator-supplied and would become a path component, and
#: re-binding should replace the previous file rather than accumulate one per
#: profile the session ever selected.
SESSION_CONFIG_FILENAME = "ash.yaml"


def materialize_session_config(session_id: Optional[str], config: AshConfig) -> str:
    """Write ``config`` into the session's sandbox and return the path.

    Why a file at all
    -----------------
    The scan entry point takes a config path, not a resolved ``AshConfig``, and
    ``ASHScanOrchestrator.__init__`` unconditionally overwrites its ``config``
    field by calling ``resolve_config`` itself -- so a caller cannot hand it a
    config object. Teaching it to accept one touches the single-project scan path
    for every caller; ``workspace/execution.py`` already records that as a larger
    job than this. Writing the resolved config out costs one file and keeps a
    single code path for loading it.

    Why inside the sandbox
    ----------------------
    Because ``cli/mcp/sandbox.py`` now confines config inputs, and the sandbox's
    ``config/`` directory is a config root for exactly this session. A file
    written anywhere else would be refused by the gate that protects it, and a
    file written to a shared location would be readable by a sibling session.

    Raises:
        RuntimeError: if the session has no resolvable sandbox -- a host with no
            home directory and no ``ASH_MCP_WORKSPACE_ROOT``. Raised rather than
            falling back to a temp file, because a temp file outside the boundary
            would be written successfully and then refused at scan time, which
            reports the failure at the wrong call.
    """

    from automated_security_helper.cli.mcp.sandbox import session_sandbox

    sandbox = session_sandbox(session_id or DEFAULT_SESSION_ID)
    if sandbox.root is None:
        raise RuntimeError(
            "cannot materialize a session config: no MCP workspace root could "
            "be resolved. Set ASH_MCP_WORKSPACE_ROOT."
        )
    config_dir = sandbox.config_dir
    config_dir.mkdir(parents=True, exist_ok=True)
    target = config_dir / SESSION_CONFIG_FILENAME
    config.save(target)
    return str(target)


def bind_session_config(
    session_id: Optional[str],
    *,
    config: AshConfig,
    profile_name: str,
    patch_ops: Optional[List[Dict]] = None,
    override_yaml: Optional[str] = None,
    config_path: Optional[str] = None,
) -> SessionState:
    """Bind a resolved config to ``session_id``.

    ``patch_ops`` and ``override_yaml`` are stored verbatim for diagnostics
    so a future ``mcp__ash__get_session`` tool can show *how* the config was
    derived (static, inherit-and-patch, full-override).

    ``config_path`` names the materialized file a scan will be handed. Passed in
    rather than written here so that a caller which fails to materialize -- no
    resolvable workspace root -- reports that as its own failure instead of
    binding a config nothing can reach.
    """
    sid = session_id or DEFAULT_SESSION_ID
    with _session_lock:
        state = SessionState(
            session_id=sid,
            bound_config=config,
            profile_name=profile_name,
            patch_ops=patch_ops,
            override_yaml=override_yaml,
            config_path=config_path,
        )
        _session_state[sid] = state
        return state


def resolve_session_config_path(session_id: Optional[str] = None) -> Optional[str]:
    """Return the config path bound to ``session_id``, or None.

    The one reader that closes the loop. Every MCP tool that accepts a config
    path calls this when the caller named none, which is what makes
    ``select_profile`` observable: without a reader the binding was a write to a
    field nothing consumed, and the tool returned success while changing nothing.

    None is returned for an unbound session rather than a default path, so a
    caller can tell "this session chose a profile" from "this session did not"
    and pass nothing in the second case -- letting ASH's own config discovery
    find an in-tree ``.ash.yaml`` as it always has.

    A recorded path that no longer exists on disk is also reported as None. The
    session workspace is removed by ``clear_source`` and by the disconnect hook,
    either of which can take the materialized config with it; returning a path to
    a deleted file would fail the scan with a missing-config error naming a path
    the client never supplied.
    """

    with _session_lock:
        state = _session_state.get(session_id or DEFAULT_SESSION_ID)
        recorded = state.config_path if state is not None else None
    if recorded is None:
        return None
    return recorded if Path(recorded).is_file() else None


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
