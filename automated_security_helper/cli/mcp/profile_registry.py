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
import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple, Union

import yaml

from automated_security_helper.config.ash_config import AshConfig

if TYPE_CHECKING:
    from automated_security_helper.config.client_config_policy import (
        ClientConfigRules,
    )


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
            from automated_security_helper.config.operator_paths import (
                not_delivered_by_a_client,
            )

            from automated_security_helper.config.config_sources import (
                load_config_with_references,
            )

            # The operator's file: a relative path in it is taken from its
            # directory, before the session's copy is written somewhere else
            # (config/operator_paths.py). Read as AshConfig.from_file reads it,
            # keeping what it read from the environment, so the session's copy
            # holds each such value as the file wrote it and the scan reads it
            # from the environment itself (materialize_session_config).
            cfg = load_config_with_references(
                path, anchor_relative_paths=not_delivered_by_a_client
            )
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
        #
        # Read by the loader's own reader, as from_file read it, so a profile that
        # uses !ENV or is TOML is checked rather than refused by a plain parser.
        try:
            from automated_security_helper.config.config_sources import (
                read_config_file,
            )

            raw = read_config_file(path)
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

    ``trusted_config_path`` names the registered profile as the operator
    registered it, materialized in the session's ``config/`` directory. It is
    ``config_path`` itself for a binding without a client patch. With one,
    ``config_path`` is the patched copy in ``client-config/``, which is the
    client's, and this is the trusted base it is resolved against.
    """

    session_id: str
    bound_config: Optional[AshConfig] = None
    profile_name: Optional[str] = None
    patch_ops: Optional[List[Dict]] = field(default=None)
    override_yaml: Optional[str] = None
    config_path: Optional[str] = None
    trusted_config_path: Optional[str] = None


_session_lock = RLock()
_session_state: Dict[str, SessionState] = {}

# When no session id can be resolved (e.g. a stdio client that doesn't expose
# one), tools fall back to a single shared key. This matches the existing
# "single-tenant stdio" assumption in the rest of the MCP server.
DEFAULT_SESSION_ID = "__default__"


def get_session_state(session_id: Optional[str] = None) -> Optional[SessionState]:
    """Return the SessionState bound to ``session_id``, or None if it has none.

    ``None`` as the id resolves to :data:`DEFAULT_SESSION_ID` so callers without
    an explicit id (stdio transport, in-process tests) still get a stable slot.

    A lookup creates nothing: an entry for an id with no workspace is one the TTL
    sweep and ``sessions.end_session`` never find. :func:`bind_session_config` is
    the way to record a binding.
    """
    with _session_lock:
        return _session_state.get(session_id or DEFAULT_SESSION_ID)


#: Filename a bound config is materialized under, inside the session sandbox's
#: ``config/`` directory. Fixed rather than derived from the profile name: a
#: profile name is operator-supplied and would become a path component, and
#: re-binding should replace the previous file rather than accumulate one per
#: profile the session ever selected.
SESSION_CONFIG_FILENAME = "ash.yaml"

#: Filename, in the session's ``config/`` directory, of a profile a workspace tool
#: was given for one call (``profile``). Not ``SESSION_CONFIG_FILENAME``: that file
#: is the profile the session bound, and the trusted base of a patched binding, so
#: a call that names another profile must not replace it. The prefix of
#: ``call_profile_filename``'s names.
CALL_PROFILE_FILENAME = "call-profile.yaml"

_CALL_PROFILE_STEM, _CALL_PROFILE_SUFFIX = os.path.splitext(CALL_PROFILE_FILENAME)
_CALL_PROFILE_DIGEST_LENGTH = 16
_CALL_PROFILE_NAME = re.compile(
    rf"{re.escape(_CALL_PROFILE_STEM)}-[0-9a-f]{{{_CALL_PROFILE_DIGEST_LENGTH}}}"
    rf"{re.escape(_CALL_PROFILE_SUFFIX)}"
)


def call_profile_filename(profile_name: str) -> str:
    """The file a workspace tool's ``profile`` is materialized under, one per profile.

    Named by a digest of the profile name, not the name itself, which the
    operator chose and would otherwise become a path component. One file per
    profile, so two calls in one session that name different profiles do not
    replace the file the other's plan recorded and its scan reads.
    """
    digest = hashlib.sha256(profile_name.encode("utf-8")).hexdigest()
    return (
        f"{_CALL_PROFILE_STEM}-{digest[:_CALL_PROFILE_DIGEST_LENGTH]}"
        f"{_CALL_PROFILE_SUFFIX}"
    )


def is_call_profile_filename(name: str) -> bool:
    """Whether ``name`` has the shape of a name ``call_profile_filename`` returns.

    By shape alone: the prefix, a dash, exactly 16 lowercase hex digits and the
    suffix, nothing before or after. Only the server writes in a session's
    ``config/`` directory (``sandbox._server_config_dir_refusal``), so a file
    there named so is one it wrote, and the registered profiles need not be
    looked up to tell.
    """
    return _CALL_PROFILE_NAME.fullmatch(name) is not None


def is_client_copy_of(config_path: Path | str, trusted_config_path: Path | str) -> bool:
    """Whether ``config_path`` is the copy of a profile a client patched, in a
    session's ``client-config/``, and ``trusted_config_path`` the operator's copy
    it was built from, in the same session's ``config/``
    (``materialize_session_binding``). Such a copy holds the values the profile
    read from the environment as their references, which ``resolve_config``
    fills from the operator's copy."""
    from automated_security_helper.cli.mcp.sandbox import (
        CLIENT_CONFIG_DIR_NAME,
        CONFIG_DIR_NAME,
    )

    client, trusted = Path(config_path), Path(trusted_config_path)
    if (
        client.name != SESSION_CONFIG_FILENAME
        or trusted.name != SESSION_CONFIG_FILENAME
    ):
        return False
    if (
        client.parent.name != CLIENT_CONFIG_DIR_NAME
        or trusted.parent.name != CONFIG_DIR_NAME
    ):
        return False
    try:
        return client.parent.parent.resolve() == trusted.parent.parent.resolve()
    except OSError:
        return False


def materialize_session_config(
    session_id: Optional[str],
    config: AshConfig,
    *,
    client_patched: bool = False,
    filename: str = SESSION_CONFIG_FILENAME,
) -> str:
    """Write ``config`` into the session's sandbox and return the path.

    Into ``config/``, which counts as the operator's, unless ``client_patched``:
    a profile after a client's ``patch_ops`` or ``override_yaml`` goes into
    ``client-config/``, which counts as the client's (``sandbox.CLIENT_CONFIG_DIR_NAME``).

    The operator's copy holds only the fields the registered profile sets
    (``AshConfig.save``'s ``exclude_unset``). It loads back as the same values,
    and the workspace tools layer it over a project's own config, where a field
    in the file is final (``workspace/resolver._resolve_project_config``): a copy
    holding every default would set every field and leave the project's config
    nothing to fill. The client's copy is written whole; it is never layered.

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

    Why the returned spelling is POSIX-shaped
    -----------------------------------------
    This is the only producer of the path a binding records, and the path is
    reported twice for one file: a workspace scan passes it as
    ``ProjectScanSettings.default_config_path`` *and* as ``resolve_workspace``'s
    ``default_config``, which the resolver turns into a project's
    ``ProjectPlan.config_source``. ``WorkspacePlan`` spells every path it reports
    POSIX-shaped -- ``ProjectPlan.path`` says so in its field description, and
    ``relative_path``, ``workspace_file``, ``workspace_root``,
    ``workspace_config_source`` and ``config_source`` are all built with
    ``as_posix()``.

    So returning ``str(target)`` gave one file two spellings on Windows: the plan
    reported ``C:/...`` and the settings ``C:\\...``. Both were valid paths and both
    opened the same file, so nothing failed -- a client comparing the dry-run plan
    against the config the scan reports simply saw two different files, which is
    the exact thing ``default_config`` and ``default_config_path`` being set from
    one variable exists to prevent.

    Normalized here rather than at either consumer because the consumers are the
    two sides of the comparison; a fix applied to one of them leaves the next
    consumer to rediscover the mismatch. ``as_posix()`` and not ``str()`` because
    the plan's convention is the older and the more widely asserted of the two, and
    because a POSIX-shaped absolute Windows path is accepted everywhere this value
    is consumed -- ``Path``, ``open`` and ``resolve_config`` all take it.

    Raises:
        RuntimeError: if the session has no resolvable sandbox -- a host with no
            home directory and no ``ASH_MCP_WORKSPACE_ROOT``. Raised rather than
            falling back to a temp file, because a temp file outside the boundary
            would be written successfully and then refused at scan time, which
            reports the failure at the wrong call.
    """

    from automated_security_helper.cli.mcp.sandbox import session_sandbox

    from automated_security_helper.cli.mcp.session_identity import (
        UNIDENTIFIED_SESSION_ID,
    )

    if session_id == UNIDENTIFIED_SESSION_ID:
        raise RuntimeError(
            "cannot materialize a session config: this caller has no session the "
            "server issued, so it has no session workspace to hold one"
        )
    sandbox = session_sandbox(session_id or DEFAULT_SESSION_ID)
    if sandbox.root is None:
        raise RuntimeError(
            "cannot materialize a session config: no MCP workspace root could "
            "be resolved. Set ASH_MCP_WORKSPACE_ROOT."
        )
    from automated_security_helper.cli.mcp.session_paths import (
        mark_session_workspace,
    )

    mark_session_workspace(sandbox.root)
    config_dir = sandbox.client_config_dir if client_patched else sandbox.config_dir
    config_dir.mkdir(parents=True, exist_ok=True)
    target = config_dir / filename
    # Written to the native path; only the recorded spelling is normalized.
    # Through a temporary file and a rename, so a scan reading the file while
    # another call writes it reads the old content or the new, never part of one.
    partial = config_dir / f".{filename}.{os.getpid()}.{threading.get_ident()}.tmp"
    try:
        # Each value the profile's files read from the environment is written as
        # the file wrote it, never the value. The operator's copy tags it !ENV,
        # and the scan reads it from the environment when it loads the copy. The
        # client's copy, in a directory where !ENV is not resolved
        # (config_sources), holds it as quoted text, which a scan fills from the
        # operator's copy (is_client_copy_of, resolve_config).
        if getattr(config, "_environment_references", ()):
            config.save(
                partial,
                exclude_unset=not client_patched,
                as_written=True,
                env_tags=not client_patched,
            )
        else:
            config.save(partial, exclude_unset=not client_patched)
        os.replace(partial, target)
    finally:
        partial.unlink(missing_ok=True)
    return target.as_posix()


def materialize_session_binding(
    session_id: Optional[str],
    registered: AshConfig,
    patched: Optional[AshConfig] = None,
) -> Tuple[str, str]:
    """Write a ``select_profile`` binding; return ``(config_path, trusted_config_path)``.

    ``registered`` is the profile as the operator registered it, written to
    ``config/``. ``patched`` is the profile after the client's ``patch_ops`` or
    ``override_yaml``, written to ``client-config/``; None for a binding without
    a patch, whose config is ``registered`` and whose previous patched copy, if
    any, is removed, so the session holds no client copy it is not bound to.

    The client's side changes first: the patched copy is written, or the old one
    removed, before the operator copy is replaced, so the operator copy is never
    replaced under an older client copy. The binding is recorded by the caller
    only after both, so a failure in between leaves the previous binding with a
    different client copy, still resolved as the client's against the previous
    profile, or with none, which leaves it unbound.

    Raises:
        RuntimeError: as ``materialize_session_config`` does.
        OSError: when a file cannot be written or removed.
    """
    from automated_security_helper.cli.mcp.sandbox import session_sandbox

    if patched is not None:
        # The client's copy is built from the registered profile, so it holds the
        # values that profile read from the environment where the client did not
        # change them; it records them as the profile wrote them.
        patched._environment_references = registered._environment_references
        config_path = materialize_session_config(
            session_id, patched, client_patched=True
        )
        return config_path, materialize_session_config(session_id, registered)
    sandbox = session_sandbox(session_id or DEFAULT_SESSION_ID)
    if sandbox.root is not None:
        (sandbox.client_config_dir / SESSION_CONFIG_FILENAME).unlink(missing_ok=True)
    trusted = materialize_session_config(session_id, registered)
    return trusted, trusted


def bind_session_config(
    session_id: Optional[str],
    *,
    config: AshConfig,
    profile_name: str,
    patch_ops: Optional[List[Dict]] = None,
    override_yaml: Optional[str] = None,
    config_path: Optional[str] = None,
    trusted_config_path: Optional[str] = None,
) -> SessionState:
    """Bind a resolved config to ``session_id``.

    ``patch_ops`` and ``override_yaml`` are stored verbatim for diagnostics
    so a future ``mcp__ash__get_session`` tool can show *how* the config was
    derived (static, inherit-and-patch, full-override).

    ``config_path`` names the materialized file a scan will be handed, and
    ``trusted_config_path`` the registered profile's copy it is resolved against
    (``materialize_session_binding`` returns both). Passed in rather than written
    here so that a caller which fails to materialize -- no resolvable workspace
    root -- reports that as its own failure instead of binding a config nothing
    can reach.
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
            trusted_config_path=trusted_config_path,
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


def session_config_was_patched(config_path: Union[str, Path]) -> bool:
    """Whether ``config_path`` is a session's profile after a client's patch.

    True for a file in a session's ``client-config/`` directory under the MCP
    workspace root, where ``materialize_session_binding`` writes a profile after
    ``patch_ops`` or ``override_yaml``. False for the registered profile in
    ``config/`` and for any path outside a session's ``client-config/``.

    Decided by where the file is, not by the recorded session state, so the
    answer is the same after the state is cleared, and it agrees with
    ``sandbox.config_is_client_supplied`` for a session's profiles. Judged as
    named and as resolved, as that function is: a link to a patched profile
    counts, wherever the link is. The unit is the file: a profile any client
    patch touched is the client's as a whole.

    Also True for a file a session's recorded binding names as its config when
    that binding carries ``patch_ops`` or ``override_yaml``, wherever the file
    is: a client's patch is in it, so a tool config path it names is not the
    operator's (``config/path_trust.py``).
    """
    from automated_security_helper.cli.mcp.sandbox import (
        CLIENT_CONFIG_DIR_NAME,
        _parts_below,
        shared_workspace_root,
    )

    shared = shared_workspace_root()
    if shared is not None:
        for candidate in (
            Path(os.path.abspath(config_path)),
            Path(config_path).resolve(),
        ):
            parts = _parts_below(candidate, shared)
            if (
                parts is not None
                and len(parts) >= 3
                and parts[1] == CLIENT_CONFIG_DIR_NAME
            ):
                return True
    try:
        target = Path(config_path).resolve()
    except OSError:
        return False
    with _session_lock:
        states = list(_session_state.values())
    for state in states:
        if state.config_path is None:
            continue
        try:
            if Path(state.config_path).resolve() != target:
                continue
        except OSError:
            continue
        if state.patch_ops is not None or state.override_yaml is not None:
            return True
    return False


def resolve_session_trusted_config_path(
    session_id: Optional[str] = None,
) -> Optional[str]:
    """The trusted base a config this session's client supplied is resolved against, or None.

    The registered profile the session bound, as the operator registered it: its
    copy in the session's ``config/`` directory, never the client-patched copy
    ``resolve_session_config_path`` returns for a patched binding. None for an
    unbound session, or when the file is gone, as for that function (the two
    files are removed together, with the session workspace); the caller then
    takes the server's default config as the trusted base, as for a client's
    config in an unbound session.
    """

    with _session_lock:
        state = _session_state.get(session_id or DEFAULT_SESSION_ID)
        recorded = state.trusted_config_path if state is not None else None
    if recorded is None:
        return None
    return recorded if Path(recorded).is_file() else None


def session_profile_entry(
    session_id: Optional[str] = None, profile: Optional[str] = None
) -> Optional[ProfileEntry]:
    """The registered profile a call runs under: ``profile``, else the session's bound one.

    None when neither applies. The entry is the operator's registered file as
    loaded at startup, never the session's materialized config, which holds the
    profile after the client's ``patch_ops`` or ``override_yaml``.

    Raises:
        ProfileRegistryError: The profile named, or the one bound, is not
            registered. Failing closed: running under some other policy would
            accept what the operator's denies.
    """
    name = profile
    if name is None:
        with _session_lock:
            state = _session_state.get(session_id or DEFAULT_SESSION_ID)
            name = state.profile_name if state is not None else None
    if name is None:
        return None
    entry = get_profile_registry().get(name)
    if entry is None:
        raise ProfileRegistryError(
            f"profile {name!r} is not registered, so the runtime-override policy "
            "it sets cannot be read"
        )
    return entry


def session_client_rules(
    session_id: Optional[str] = None, profile: Optional[str] = None
) -> "ClientConfigRules":
    """The rules a config this session's client delivers is checked against.

    The registered profile's (``session_profile_entry``), so a client allowed to
    change ``global_settings`` cannot rewrite the policy its own uploads are
    checked against. An unbound session gets the server's default config's. A
    bound profile that is no longer registered, or a default config that cannot
    be loaded, gives rules that refuse only a config with a client-delivered file,
    which is the one they would check; any other scan reports its own config
    error as it always has.
    """
    from automated_security_helper.config.client_config_policy import (
        rules_from,
        trusted_default_config,
        unreadable_rules,
    )

    try:
        entry = session_profile_entry(session_id, profile)
        trusted = entry.config if entry is not None else trusted_default_config()
    except Exception as exc:  # noqa: BLE001 -- held, and raised only where it applies
        rules = unreadable_rules(
            f"the trusted config could not be loaded: {type(exc).__name__}: {exc}"
        )
    else:
        rules = rules_from(trusted)
    # Which session's config/ directory holds the files set aside for this
    # client (ClientConfigRules.session_id).
    return rules.model_copy(update={"session_id": session_id})


def session_has_binding(session_id: str) -> bool:
    """Whether ``session_id`` has bound a profile.

    A state that exists without a profile or a config holds no binding.
    """
    with _session_lock:
        state = _session_state.get(session_id)
        return state is not None and (
            state.profile_name is not None or state.bound_config is not None
        )


def clear_session_state(session_id: Optional[str] = None) -> None:
    """Drop the SessionState for ``session_id`` (or every state if None).

    ``sessions.end_session`` calls this when a session ends, so its bound
    profile goes with its workspace; tests also use it to scrub between cases.
    """
    with _session_lock:
        if session_id is None:
            _session_state.clear()
        else:
            _session_state.pop(session_id, None)
