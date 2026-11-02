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

The session state here is the single source of truth for a session's bound
profile. The session lifecycle (``MCPSession``, disconnect cleanup, the TTL
sweep) lives in :mod:`automated_security_helper.cli.mcp.sessions`, and its
session model deliberately holds no binding fields, so do not grow a copy of
this state there. We expose enough surface (``bound_config``,
``profile_name``, ``patch_ops``, ``override_yaml``) for downstream tools
(``run_ash_scan``, ``mcp_validate_config``, etc.) to prefer a session-bound
config over an explicit ``config_path``.
"""

from __future__ import annotations

import copy
import hashlib
import os
import re
import sys
import contextlib
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import (
    TYPE_CHECKING,
    Dict,
    Iterator,
    List,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.config_sources import (
    describe_config_path,
    is_config_parse_error,
    original_of_scan_copy,
    parse_config_text_literally,
    read_config_file_literally,
    unparsed_config_reason,
)
from automated_security_helper.core.exceptions import ASHConfigUnparsedError
from automated_security_helper.utils.error_text import error_text

if TYPE_CHECKING:
    from automated_security_helper.cli.mcp.sandbox import SessionSandbox
    from automated_security_helper.config.client_config_policy import (
        ClientConfigRules,
    )
    from automated_security_helper.config.operator_only_options import (
        RepositorySettings,
    )


class ProfileRegistryError(ValueError):
    """Raised when a ``--profile`` spec cannot be parsed, loaded, or validated.

    Subclassing ``ValueError`` keeps the typer error path simple — the CLI
    layer turns a single ``ValueError`` into ``Validation Error: ...`` and
    exits with code 3.
    """


class BoundProfileUnavailableError(ProfileRegistryError, RuntimeError):
    """A session's bound profile cannot be read as the operator registered it.

    Raised by the session config path readers when the materialized file is
    gone and cannot be written again: the profile is no longer registered, or
    the session's workspace cannot be written. A ``ProfileRegistryError``, so a
    reader that handles the registry's refusals handles it; and a
    ``RuntimeError``, the type the workspace tools already map to exit 3 for a
    bound profile whose registered copy is missing (``_resolve_session_config``
    in ``cli/mcp/workspace.py``), so the raise lands in that handler rather than
    in a tool's catch-all.

    ``workspace_unwritable`` says which of the two causes it is: False when the
    profile is no longer registered (the caller's config to fix: bind a registered
    profile), True when the profile is still registered and the session's
    workspace could not be written (the server's failure, for its operator; the
    writer's error is the chained cause). Every answer that tells the two apart
    reads this, not whether a cause happens to be chained.
    """

    def __init__(self, message: str, *, workspace_unwritable: bool = False) -> None:
        super().__init__(message)
        self.workspace_unwritable = workspace_unwritable


class SessionIdentityRequiredError(RuntimeError):
    """A session config was asked for by a caller the server could not identify.

    Raised by :func:`materialize_session_config` for
    ``session_identity.UNIDENTIFIED_SESSION_ID``: such a caller is remote and
    owns no session workspace, so there is no directory to write the config
    into. A ``RuntimeError``, so a caller that maps ``RuntimeError`` to its
    config error keeps doing so; and its own type, so a tool can answer it as
    the session-identity refusal (``session_identity.session_identity_refusal``,
    ``error_type`` ``session_identity_required``) instead of as an invalid
    config, which is what the caller was told nothing about.
    """


@dataclass(frozen=True)
class ProfileEntry:
    """A single registered profile.

    Frozen so the registry can be safely shared across threads without a
    caller mutating the bound :class:`AshConfig` in place. ``path_sha256``
    is computed over the absolute path string (not the file content) — the
    point is to surface "did the operator point a profile at a different
    file" without leaking the file contents. It is an unsalted digest, so it
    hides the path only from a reader who cannot guess it: one who can checks
    a guess against the digest.
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


def _profile_kept_where_a_scan_may_rewrite_it(path: Path) -> Optional[str]:
    """Name the place a ``--profile`` is kept that makes it not the operator's alone.

    A profile is the operator's trusted base: a scan reads a copy of it as the
    configuration a client cannot override, and judges a client's config against
    it. The scan-time classification sees only the server's own copy, in the
    session's ``config/`` directory, so where the original lives is judged once,
    here, before anything is read from it. Two places are refused:

    - A file a client delivered: under a session workspace below the MCP
      workspace root, by the scan's own classifier
      (``sandbox.config_is_client_supplied``), which admits the profile files
      the server itself writes in a session's ``config/`` directory.
    - A git checkout a scan reaches: for a profile under a directory
      ``ASH_MCP_ALLOWED_ROOTS`` names, a ``.git`` entry among the profile's
      ancestors, up to the filesystem root. A checkout below the granted root
      is scanned, and one that holds the granted root (the root is a directory
      of a larger checkout) is the same tree: the checkout's owner can rewrite
      the profile between the server's start and the scan either way. A
      checkout outside every granted root, and a plain file under a granted
      root with no checkout above it, are not judged here.

    The git walk reads the resolved path, so a link into a checkout counts.
    ``register_profiles`` runs this on the profile before reading it, and on each
    base of its ``extends`` chain once the load has named them. Returns None when
    neither applies.
    """
    from automated_security_helper.cli.mcp.sandbox import (
        ASH_MCP_ALLOWED_ROOTS_ENV,
        config_is_client_supplied,
        operator_scan_roots,
    )

    if config_is_client_supplied(path):
        return (
            "a session workspace under the MCP workspace root, where clients "
            "deliver files"
        )
    resolved = Path(os.path.realpath(path))
    for root in operator_scan_roots():
        if resolved != root and not resolved.is_relative_to(root):
            continue
        # Past the granted root too: a root that is a directory of a checkout
        # has its .git above it, and the tree is scanned all the same.
        for ancestor in (resolved.parent, *resolved.parent.parents):
            if (ancestor / ".git").exists():
                where = (
                    f"inside the scan root {root}"
                    if ancestor == root or ancestor.is_relative_to(root)
                    else f"which holds the scan root {root}"
                )
                return (
                    f"the git checkout at {ancestor}, {where} "
                    f"({ASH_MCP_ALLOWED_ROOTS_ENV})"
                )
    return None


def _top_level_key_text(key: object) -> str:
    """How the refusal names an unknown top-level key of a profile.

    A string as it is. Any other value is one the file's format parsed from a
    bare word (YAML reads ``on:``, ``yes:`` and ``true:`` as a boolean, ``1:``
    as an integer), so it is shown with its type, which tells the operator the
    key is not a field name and needs quoting or correcting.
    """
    if isinstance(key, str):
        return key
    return f"{key!r} (a {type(key).__name__} key, not a field name)"


def register_profiles(specs: List[str]) -> Dict[str, ProfileEntry]:
    """Parse + load every ``--profile`` spec into a registry dict.

    Each profile is loaded as a run's configuration is
    (``resolve_config.load_config_file_for_run``), so the same YAML/JSON/!ENV
    resolution path the regular CLI uses is in effect here, and the profile knows
    which of its values were read from the environment and the reference each
    was written as: materialize_session_config writes those references, not the
    values.

    Raises:
        ProfileRegistryError: on duplicate name, missing file, a file kept where
            a scan may rewrite it (``_profile_kept_where_a_scan_may_rewrite_it``),
            malformed YAML, or AshConfig validation failure.
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
        # Before the file is read: a profile kept where a client's delivery or a
        # scanned checkout's owner can rewrite it would still be loaded and
        # trusted as the operator's, and the scan cannot tell later.
        kept_in = _profile_kept_where_a_scan_may_rewrite_it(path)
        if kept_in is not None:
            raise ProfileRegistryError(
                f"--profile {name!r} is kept at {path}, inside {kept_in}, so its "
                "content is not the operator's alone. Keep profiles outside the "
                "MCP workspace root and outside any checkout the server scans."
            )
        unparsed: Optional[str] = None
        # Each file of the profile's chain, by resolved path, as the text the
        # load parsed it from (resolve_config._cached_reader fills it): the
        # top-level key check below reads these, so it judges the files the
        # load read, not a second read of the disk that an edit in between
        # could have changed.
        texts: Dict[Path, str] = {}
        try:
            from automated_security_helper.config.operator_paths import (
                not_delivered_by_a_client,
            )

            from automated_security_helper.config.resolve_config import (
                load_config_file_for_run,
            )

            # The operator's file: a relative path in it is taken from its
            # directory, before the session's copy is written somewhere else
            # (config/operator_paths.py). Read as the run reads its
            # configuration, keeping what it read from the environment, so the
            # session's copy holds each such value as the file wrote it and the
            # scan reads it from the environment itself
            # (materialize_session_config). The one exception is a relative
            # path read from the environment: anchored here, it is written as
            # the path it now is (AshConfig.save), since the reference would
            # resolve against the copy's directory instead.
            document, cfg = load_config_file_for_run(
                path, texts=texts, anchor_relative_paths=not_delivered_by_a_client
            )
        except Exception as exc:
            if isinstance(exc, ASHConfigUnparsedError):
                # A TOML parse refusal arrives already formatted: its message is
                # the complete refusal and names the file, so the "failed to
                # load <path>" frame would name the path twice.
                unparsed = error_text(exc)
            elif not is_config_parse_error(exc):
                # ASHConfigValidationError (from_file's model refusal, described
                # and redacted, with no pydantic error chained), OSError, etc.
                raise ProfileRegistryError(
                    f"--profile {name!r} failed to load {path}: {error_text(exc)}"
                ) from exc
            else:
                # The parser's own words can quote the file
                # (unparsed_config_reason).
                unparsed = unparsed_config_reason(path, exc)
        if unparsed is not None:
            # Outside the handler, so the parser's error is not its context.
            raise ProfileRegistryError(f"--profile {name!r}: {unparsed}")
        # The profile's bases, named by the load: each is read into the profile
        # as the operator's, so one kept where a client's delivery or a scanned
        # checkout's owner can rewrite it (a base in a checkout nested under
        # the profile's directory, which the walk up from the profile never
        # meets) is the same gap as the profile itself kept there. Judged once
        # the load has named them, since nothing names a base before it is
        # read; the profile's own file was judged before the read above.
        for source in dict.fromkeys(document.chain):
            base = Path(source)
            if base.resolve() == path.resolve():
                continue
            kept_in = _profile_kept_where_a_scan_may_rewrite_it(base)
            if kept_in is not None:
                raise ProfileRegistryError(
                    f"--profile {name!r} extends {describe_config_path(base)}, "
                    f"kept inside {kept_in}, so its content is not the "
                    "operator's alone. Keep profiles and the bases they extend "
                    "outside the MCP workspace root and outside any checkout the "
                    "server scans."
                )
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
        # Read from the text the loader's own reader parsed, so a profile that
        # uses !ENV or is TOML is checked rather than refused by a plain parser.
        try:
            from automated_security_helper.config.config_validator import (
                ConfigValidator,
            )

            allowed = set(AshConfig.model_fields.keys())
            for finfo in AshConfig.model_fields.values():
                if finfo.alias:
                    allowed.add(finfo.alias)
            # And every top-level key the config validator accepts, so the two
            # cannot disagree about a file: "$schema", which a JSON config
            # carries for editors and a scan ignores, is one the model does
            # not declare.
            allowed |= set(ConfigValidator.VALID_TOP_LEVEL_FIELDS)
            # Every file the profile is built from: from_file follows its
            # `extends` chain, so a base's typo is the same mistake as the
            # profile's own and was ignored. The chain is the one the load
            # resolved (bases confined to the profile's directory, an error
            # naming no value read from the environment), and each file's own
            # keys are read from the text that load parsed, in its format
            # (YAML, JSON, TOML, a pyproject.toml's [tool.ash] table) as the
            # file writes them. A file the load's cache does not hold is read
            # from disk, as a reader with no cache would.
            for source in dict.fromkeys(document.chain):
                text = texts.get(Path(source))
                raw = (
                    parse_config_text_literally(Path(source), text)
                    if text is not None
                    else read_config_file_literally(Path(source))
                )
                # By their text, since a YAML key such as `on:` or `yes:` parses
                # as a boolean, and Python cannot order a boolean against a
                # string.
                unknown = sorted(set(raw or {}) - allowed, key=str)
                if unknown:
                    where = (
                        ""
                        if Path(source).resolve() == path.resolve()
                        else f" in its base {describe_config_path(Path(source))}"
                    )
                    named = ", ".join(_top_level_key_text(key) for key in unknown)
                    raise ProfileRegistryError(
                        f"--profile {name!r} has unknown top-level field(s)"
                        f"{where}: {named}"
                    )
        except ProfileRegistryError:
            raise
        except Exception as exc:
            raise ProfileRegistryError(
                f"--profile {name!r} re-validation against schema failed: "
                f"{error_text(exc)}"
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

# ``sessions.MCPSession`` owns the session's workspace and locks. What a client
# bound is stored here, keyed by session id, and is the only record of the
# selected profile: ``MCPSession`` has no profile, config or patch fields.


def client_values_present(
    patch_ops: Optional[Sequence[Dict]], override_yaml: Optional[str]
) -> bool:
    """Whether a binding made from these holds a change a client asked for.

    True for a non-empty ``patch_ops`` or any ``override_yaml``, an empty string
    included. An empty ``patch_ops`` changes nothing, so a binding made from it is
    the registered profile's own copy. This is the one reading: a stored binding
    answers it as ``SessionState.client_changed``, and ``mcp_select_profile`` writes
    the client's copy of the profile by it.
    """
    return bool(patch_ops) or override_yaml is not None


@dataclass
class SessionState:
    """The profile a session selected, with its resolved config.

    This is the source of truth for a session's binding; ``sessions.MCPSession``
    holds none of it.

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
    patch_ops: Optional[Tuple[Dict, ...]] = field(default=None)
    override_yaml: Optional[str] = None
    config_path: Optional[str] = None
    trusted_config_path: Optional[str] = None

    @property
    def client_changed(self) -> bool:
        """Whether a client's patch or override is in this binding's config.

        True for a non-empty ``patch_ops`` or any ``override_yaml``. An empty
        ``patch_ops`` is stored as an empty tuple, so the binding still records
        that the session chose inherit-and-patch, but it changes nothing:
        ``select_profile`` binds the registered profile's own copy for it. It reads
        the binding with :func:`client_values_present`, the reading
        ``select_profile`` writes the client's copy by, so the two cannot differ.
        """
        return client_values_present(self.patch_ops, self.override_yaml)


_session_lock = RLock()
_session_state: Dict[str, SessionState] = {}

#: One lock per session id around the writes of its binding's files: the
#: materialization ``select_profile`` does, and the one that writes a gone file
#: again (:func:`_rematerialize_binding`). The session's write hold
#: (``sessions.writing_session_state``) keeps the sweep off the workspace but
#: admits two writers at once, so a rewrite that read the binding before a
#: ``select_profile`` could land its files after it: both files then existed,
#: so nothing repaired them, and the session's config held one profile while its
#: state and rules said another. Taken inside the write hold, never around it.
#:
#: Re-entrant, so the thread that holds it can take it again. The rewrite and
#: ``select_profile`` each take it once today, and neither calls the other. A
#: writer that binds from inside the rewrite would meet the lock its own thread
#: holds: a lock that cannot be taken twice waits on itself, and the call never
#: returns. Another thread still waits for the holder.
#:
#: An entry exists only while a caller uses it (:class:`_BindingLock`), so a
#: server that sees one new session id per client does not keep a lock for each
#: id it has ever seen.
_binding_write_locks: Dict[str, "_BindingLock"] = {}


class _BindingLock:
    """One session's binding-write lock and how many callers are using it.

    ``users`` counts the callers that have taken a reference and not yet
    released it, waiting or holding, and is read and written under
    ``_session_lock``; the entry is dropped when it reaches zero.
    """

    __slots__ = ("lock", "users")

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.users = 0


@contextlib.contextmanager
def binding_writes(session_id: Optional[str]) -> Iterator[None]:
    """Hold the session's binding against another writer of its files.

    Every write of a session's ``config/`` and ``client-config/`` copies runs
    under this: ``select_profile``'s materialize-and-bind and the rewrite of a
    gone file. One lock per session id, so sessions never wait on each other,
    and none is kept for a session nobody is writing.
    """
    sid = DEFAULT_SESSION_ID if session_id is None else session_id
    with _session_lock:
        held = _binding_write_locks.get(sid)
        if held is None:
            held = _binding_write_locks[sid] = _BindingLock()
        held.users += 1
    try:
        with held.lock:
            yield
    finally:
        with _session_lock:
            held.users -= 1
            if held.users == 0 and _binding_write_locks.get(sid) is held:
                del _binding_write_locks[sid]


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

    A binding holds its own deep copies of the caller's patch ops and config
    (:func:`bind_session_config`), so the stored state cannot be edited through
    a reference the caller kept.
    """
    with _session_lock:
        return _session_state.get(
            DEFAULT_SESSION_ID if session_id is None else session_id
        )


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

    The digest also covers the file the name is registered for, when the name
    is registered: the entry's ``path_sha256``, the digest of the file's absolute
    path, not the path as the operator spelled it. Two stdio servers share the
    default session's ``config/`` directory, and each may register the same name
    for a different file; by the name alone the two would write one file for two
    profiles, and a plan recorded by one server would be scanned under the
    other's. Two servers that register the same name for the same file write the
    same content, so one file serves both, and that holds whatever spelling each
    gave the path (relative to its own working directory, through ``..``): by
    the spelling, one file under two spellings got two names, and two files that
    shared a relative spelling from different directories got one. An
    unregistered name, which the workspace tools refuse before writing, is
    digested alone.
    """
    with _lock:
        entry = _profile_registry.get(profile_name)
    digested = profile_name if entry is None else f"{profile_name}\n{entry.path_sha256}"
    digest = hashlib.sha256(digested.encode("utf-8")).hexdigest()
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
    fills from the operator's copy.

    A scan takes its own copy of the operator's copy and hands that over as the
    trusted base, named for the scan (``config_sources.SCAN_COPY_PREFIX``). The
    copy stands for the file it copies, so it is read as that file
    (``original_of_scan_copy``): only a copy a live scan registered maps, and a
    file that merely carries such a name does not."""
    from automated_security_helper.cli.mcp.sandbox import (
        CLIENT_CONFIG_DIR_NAME,
        CONFIG_DIR_NAME,
    )

    client = Path(config_path)
    trusted = Path(original_of_scan_copy(Path(trusted_config_path)))
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
        SessionIdentityRequiredError: if the caller is one the server could not
            identify (``session_identity.UNIDENTIFIED_SESSION_ID``), which owns
            no session workspace. A ``RuntimeError``, so a caller that maps that
            to its config error still does, and its own type so a tool can
            answer it as the session-identity refusal instead.
        RuntimeError: if the session has no resolvable sandbox -- a host with no
            home directory and no ``ASH_MCP_WORKSPACE_ROOT``. Raised rather than
            falling back to a temp file, because a temp file outside the boundary
            would be written successfully and then refused at scan time, which
            reports the failure at the wrong call.
    """

    partial, target, _sandbox = _stage_session_config(
        session_id, config, client_patched=client_patched, filename=filename
    )
    _replace_staged(partial, target)
    return target.as_posix()


def _stage_session_config(
    session_id: Optional[str],
    config: AshConfig,
    *,
    client_patched: bool = False,
    filename: str = SESSION_CONFIG_FILENAME,
) -> Tuple[Path, Path, "SessionSandbox"]:
    """Write ``config`` to a temporary file beside its place in the session's sandbox.

    Returns ``(partial, target, sandbox)``: the file written, the file it is to
    replace, and the session's sandbox. The first half of
    :func:`materialize_session_config`, on its own so that a caller writing two
    files (:func:`materialize_session_binding`) stages both before it replaces
    either: a failure to resolve the sandbox, make its directory or dump the
    config happens before any file a scan reads is touched, and leaves none of
    the partial behind. The caller moves the partial into place with
    :func:`_replace_staged`, which removes whatever is left of it.

    Raises: as :func:`materialize_session_config`.
    """

    from automated_security_helper.cli.mcp.sandbox import session_sandbox

    from automated_security_helper.cli.mcp.session_identity import (
        UNIDENTIFIED_SESSION_ID,
    )

    if session_id == UNIDENTIFIED_SESSION_ID:
        raise SessionIdentityRequiredError(
            "cannot materialize a session config: this caller has no session the "
            "server issued, so it has no session workspace to hold one"
        )
    sandbox = session_sandbox(DEFAULT_SESSION_ID if session_id is None else session_id)
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
        # the file wrote it, never the value, except a relative path the load
        # anchored to the operator's file's directory, which is written as the
        # path it now is (AshConfig.save): the reference would resolve against
        # this copy's directory. The operator's copy tags a reference !ENV, and
        # the scan reads it from the environment when it loads the copy. The
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
    except BaseException:
        partial.unlink(missing_ok=True)
        raise
    return partial, target, sandbox


#: How many times :func:`_replace_staged` tries the rename, and the pause
#: between tries. Bounded: half a second in all, longer than one load of the
#: file by a scan, which is the hold that makes Windows refuse the rename.
_REPLACE_ATTEMPTS = 10
_REPLACE_RETRY_SECONDS = 0.05


def _rename_waits_on_readers() -> bool:
    """Whether this platform refuses a rename while a reader holds the target.

    Windows does (``PermissionError`` for the length of one load of the file);
    a POSIX rename does not wait on readers, so a ``PermissionError`` there is
    the directory's and no retry changes it. Its own function so a test can
    stand in for the platform without changing ``sys.platform`` for the process.
    """
    return sys.platform == "win32"


def _replace_staged(partial: Path, target: Path) -> None:
    """Move a staged ``partial`` over ``target``, and remove what is left of it.

    One rename, so a scan reading ``target`` while it is written reads the old
    content or the new, never part of one. On Windows the rename is refused with
    ``PermissionError`` while a reader holds the target open (a scan loading the
    previous copy), and such a hold lasts one load, so there the rename is tried
    again a bounded number of times before the error is raised. On every other
    platform the error is the directory's and is raised at once: the retries
    would only delay it (half a second, with a scan waiting on the answer).
    Whatever the outcome, the partial is removed afterward.
    """
    try:
        for attempt in range(_REPLACE_ATTEMPTS):
            try:
                os.replace(partial, target)
                return
            except PermissionError:
                if not _rename_waits_on_readers() or attempt == _REPLACE_ATTEMPTS - 1:
                    raise
                time.sleep(_REPLACE_RETRY_SECONDS)
    finally:
        partial.unlink(missing_ok=True)


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

    Every copy is staged before any file is replaced (``_stage_session_config``):
    a sandbox that cannot be resolved, a directory that cannot be made or a
    config that cannot be dumped fails here with the previous binding's files as
    they were, so the session's next scan runs under the binding it holds, never
    under one profile's client copy against another profile's operator copy. Then
    the client's side moves first: the patched copy is moved into place, or the
    old one removed, before the operator copy is replaced, so the operator copy is
    never replaced under an older client copy. The binding is recorded by the
    caller only after both. A failure between the moves (a rename refused) leaves
    the previous binding recorded, and the client copy the first move already
    replaced is removed, so the session holds the previous binding's operator copy
    alone rather than one profile's client copy over another's trusted base; a
    previous binding that was patched then finds its client copy missing and
    writes both files again from itself on the next read (``_bound_config_paths``).

    Raises:
        RuntimeError: as ``materialize_session_config`` does,
            ``SessionIdentityRequiredError`` included.
        OSError: when a file cannot be written or removed.
    """
    if patched is not None:
        # The client's copy is built from the registered profile, so it holds the
        # values that profile read from the environment where the client did not
        # change them; it records them as the profile wrote them. A patch has
        # followed them already: one an op wrote over is the client's text, and
        # one an op moved is at its new entry.
        if not patched._references_followed:
            patched._environment_references = registered._environment_references
        client_partial, client_target, _sandbox = _stage_session_config(
            session_id, patched, client_patched=True
        )
        try:
            trusted_partial, trusted_target, _sandbox = _stage_session_config(
                session_id, registered
            )
        except BaseException:
            client_partial.unlink(missing_ok=True)
            raise
        try:
            _replace_staged(client_partial, client_target)
            try:
                _replace_staged(trusted_partial, trusted_target)
            except BaseException:
                # The client's copy is already the new profile's and the
                # operator's is still the old one's: a scan that read the pair
                # would resolve one profile's client values against another
                # profile's trusted base. Removing the client copy leaves the
                # session with the previous binding's operator copy alone, and a
                # previous binding that was patched finds its client copy gone
                # and writes both files again from itself on the next read.
                with contextlib.suppress(OSError):
                    client_target.unlink(missing_ok=True)
                raise
        finally:
            # A rename that failed leaves the other staged file behind.
            trusted_partial.unlink(missing_ok=True)
        return client_target.as_posix(), trusted_target.as_posix()
    partial, target, sandbox = _stage_session_config(session_id, registered)
    try:
        (sandbox.client_config_dir / SESSION_CONFIG_FILENAME).unlink(missing_ok=True)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise
    _replace_staged(partial, target)
    trusted = target.as_posix()
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

    The binding stores its own copies of the caller's objects: ``patch_ops``
    as a tuple of deep-copied ops and ``config`` as a deep model copy, so a
    caller that mutates the list or the config it passed after binding does
    not change what :func:`get_session_state` returns. ``override_yaml`` is an
    immutable string and is stored as given. The content is kept word for word
    for diagnostics, so a future ``mcp__ash__get_session`` tool can show *how*
    the config was derived (static, inherit-and-patch, full-override).

    ``config_path`` names the materialized file a scan will be handed, and
    ``trusted_config_path`` the registered profile's copy it is resolved against
    (``materialize_session_binding`` returns both). Passed in rather than written
    here so that a caller which fails to materialize -- no resolvable workspace
    root -- reports that as its own failure instead of binding a config nothing
    can reach.
    """
    sid = DEFAULT_SESSION_ID if session_id is None else session_id
    with _session_lock:
        state = SessionState(
            session_id=sid,
            bound_config=config.model_copy(deep=True),
            profile_name=profile_name,
            patch_ops=(
                tuple(copy.deepcopy(patch_ops)) if patch_ops is not None else None
            ),
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

    The binding is the source of truth, and the file is its materialization. A
    recorded path that is no longer on disk (``clear_source`` removes the whole
    session workspace, the materialized profile with it, and leaves the binding
    recorded) is written again from the binding before it is returned
    (:func:`_bound_config_paths`): a scan of a bound session runs under the
    profile the client selected, never silently under in-tree discovery while
    the profile's client rules stay in force.

    Raises:
        BoundProfileUnavailableError: the file is gone and cannot be written
            again (the profile is no longer registered, or the workspace cannot
            be written); failing closed, as ``select_profile`` does when it
            cannot write it. A ``ProfileRegistryError`` and a ``RuntimeError``
            both, so every caller's existing handling of either catches it.
        SessionWorkspaceBusyError: the file is gone and another request holds
            the session's workspace (the TTL sweep removing it, a
            ``clear_source``, the end of the session), so it is not written
            again under that removal; the caller answers the hold's refusal
            (``error_type`` ``session_workspace_busy``) and the request is sent
            again once the hold ends. A ``RuntimeError``, never a
            ``ProfileRegistryError``.
    """

    return _bound_config_paths(session_id)[0]


def _bound_config_paths(
    session_id: Optional[str],
) -> Tuple[Optional[str], Optional[str]]:
    """``(config_path, trusted_config_path)`` of the session's binding, on disk.

    ``(None, None)`` for an unbound session. When either recorded file is gone,
    both are written again from the stored binding (the registered profile's
    config and, for a client-patched binding, the patched config), and the
    binding records the new paths.

    Raises:
        ProfileRegistryError: as :func:`resolve_session_config_path`.
    """
    sid = DEFAULT_SESSION_ID if session_id is None else session_id
    with _session_lock:
        state = _session_state.get(sid)
        if state is None or state.config_path is None:
            return None, None
        config_path, trusted = state.config_path, state.trusted_config_path
    if _both_present(config_path, trusted):
        return config_path, trusted
    return _rematerialize_binding(sid)


def _both_present(config_path: str, trusted_config_path: Optional[str]) -> bool:
    """Whether a binding's recorded files are on disk (the trusted one, if any)."""
    return Path(config_path).is_file() and (
        trusted_config_path is None or Path(trusted_config_path).is_file()
    )


def _profile_no_longer_registered(profile_name: str) -> "BoundProfileUnavailableError":
    """The refusal for a bound profile whose registration and file are both gone."""
    return BoundProfileUnavailableError(
        f"this session's bound profile {profile_name!r} is no longer "
        "registered, and its materialized config is gone, so the scan cannot "
        "run under it. Bind a registered profile with select_profile."
    )


def _rematerialize_binding(sid: str) -> Tuple[Optional[str], Optional[str]]:
    """Write a bound session's profile files again and record the new paths.

    The write runs under the session's write hold (``writing_session_state``),
    the hold ``select_profile`` takes for the same files: the TTL sweep, a
    ``clear_source`` and the end of the session remove the workspace under a
    change that excludes writes, so this rewrite cannot recreate a workspace
    one of them is removing (an orphan the sweep would keep for a whole TTL),
    and is refused with ``SessionWorkspaceBusyError`` while one holds the
    session. The new paths are recorded on the binding that was read, by
    identity: a rebind meanwhile, to the same profile with another patch
    included, keeps its own paths; when its files are gone as well, it is
    written again from its own profile.
    """
    from automated_security_helper.cli.mcp.sessions import writing_session_state

    with _session_lock:
        state = _session_state.get(sid)
        if state is None or state.profile_name is None or state.bound_config is None:
            return None, None
        profile_name = state.profile_name
        patched = state.bound_config if state.client_changed else None
    entry = get_profile_registry().get(profile_name)
    if entry is None:
        raise _profile_no_longer_registered(profile_name)
    # The hold is taken outside the try: its own refusal is a RuntimeError too,
    # and inside it would be reported as a profile that cannot be written.
    with writing_session_state(sid), binding_writes(sid):
        # Read again under the binding lock, by identity, BEFORE anything is
        # written: a select_profile that landed between the read above and
        # here has written its own files and recorded its own paths, and
        # writing the binding read above would put that older profile's files
        # under the newer binding (both files present, so no later read
        # repairs them). The newer binding is the answer then, and not
        # unchecked: its files can be gone too (a clear_source between its
        # select_profile and here), and a path to a file that is not there
        # read as "config not found". It is rewritten from itself, under the
        # lock no other bind can take meanwhile.
        adopted = False
        with _session_lock:
            current = _session_state.get(sid)
            if current is not state:
                if current is None or current.config_path is None:
                    return None, None
                if _both_present(current.config_path, current.trusted_config_path):
                    return current.config_path, current.trusted_config_path
                if current.profile_name is None or current.bound_config is None:
                    # Not a profile binding: nothing to write it again from.
                    return current.config_path, current.trusted_config_path
                state = current
                profile_name = current.profile_name
                patched = current.bound_config if current.client_changed else None
                adopted = True
        if adopted:
            entry = get_profile_registry().get(profile_name)
            if entry is None:
                raise _profile_no_longer_registered(profile_name)
        try:
            config_path, trusted = materialize_session_binding(
                sid, entry.config, patched
            )
        except (OSError, RuntimeError) as exc:
            raise BoundProfileUnavailableError(
                f"this session's bound profile {profile_name!r} could not be "
                "written to the session's workspace again, so the scan cannot "
                f"run under it: {error_text(exc)}",
                workspace_unwritable=True,
            ) from exc
        with _session_lock:
            if _session_state.get(sid) is state:
                state.config_path = config_path
                state.trusted_config_path = trusted
    return config_path, trusted


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
    that binding carries a non-empty ``patch_ops`` or any ``override_yaml``,
    wherever the file is: a client's patch is in it, so a tool config path it
    names is not the operator's (``config/path_trust.py``). An empty
    ``patch_ops`` changes nothing, and ``select_profile`` binds the registered
    profile's own copy in ``config/`` for it, so that file is the operator's.
    """
    from automated_security_helper.cli.mcp.sandbox import (
        CLIENT_CONFIG_DIR_NAME,
        _parts_below,
        shared_workspace_root,
    )

    shared = shared_workspace_root()
    if shared is not None:
        candidates = [Path(os.path.abspath(config_path))]
        try:
            candidates.append(Path(config_path).resolve())
        except (OSError, RuntimeError):
            # A path that can't be resolved (a symlink loop) is judged as named.
            pass
        for candidate in candidates:
            parts = _parts_below(candidate, shared)
            if (
                parts is not None
                and len(parts) >= 3
                and parts[1] == CLIENT_CONFIG_DIR_NAME
            ):
                return True
    try:
        target = Path(config_path).resolve()
    except (OSError, RuntimeError):
        return False
    with _session_lock:
        states = list(_session_state.values())
    for state in states:
        if state.config_path is None:
            continue
        try:
            if Path(state.config_path).resolve() != target:
                continue
        except (OSError, RuntimeError):
            continue
        if state.client_changed:
            return True
    return False


def resolve_session_trusted_config_path(
    session_id: Optional[str] = None,
) -> Optional[str]:
    """The trusted base a config this session's client supplied is resolved against, or None.

    The registered profile the session bound, as the operator registered it: its
    copy in the session's ``config/`` directory, never the client-patched copy
    ``resolve_session_config_path`` returns for a patched binding. None for an
    unbound session. A file that is gone is written again from the binding, as
    for that function (the two files are removed together, with the session
    workspace, and are written again together).

    Raises:
        ProfileRegistryError: as :func:`resolve_session_config_path`.
    """

    return _bound_config_paths(session_id)[1]


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
            state = _session_state.get(
                DEFAULT_SESSION_ID if session_id is None else session_id
            )
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
    session_id: Optional[str] = None,
    profile: Optional[str] = None,
    *,
    repository: "Optional[RepositorySettings]" = None,
) -> "ClientConfigRules":
    """The rules a config this session's client delivers is checked against.

    The registered profile's (``session_profile_entry``), so a client allowed to
    change ``global_settings`` cannot rewrite the policy its own uploads are
    checked against. An unbound session gets the server's default config's. A
    bound profile that is no longer registered, or a default config that cannot
    be loaded, gives rules that refuse only a config with a client-delivered file,
    which is the one they would check; any other scan reports its own config
    error as it always has.

    ``repository`` is the settings the caller's load of the same chain uses; the
    server's default config is read with them (``trusted_default_config``), so a
    value the load leaves out never makes the rules unreadable.
    """
    from automated_security_helper.config.client_config_policy import (
        rules_from,
        trusted_default_config,
        unreadable_rules,
    )

    try:
        entry = session_profile_entry(session_id, profile)
        trusted = (
            entry.config if entry is not None else trusted_default_config(repository)
        )
    except Exception as exc:  # noqa: BLE001 -- held, and raised only where it applies
        # Described (error_text), never the raw text: the reason is returned to
        # the client with the refusal, and a validation error's own text quotes
        # the refused input, which here is the operator's configuration.
        rules = unreadable_rules(
            "the trusted config could not be loaded: "
            f"{type(exc).__name__}: {error_text(exc)}"
        )
    else:
        rules = rules_from(trusted)
    # Which session's config/ directory holds the files set aside for this
    # client (ClientConfigRules.session_id).
    return rules.model_copy(update={"session_id": session_id})


def session_has_binding(session_id: Optional[str] = None) -> bool:
    """Whether ``session_id`` has bound a profile.

    ``None`` is the stdio session (``DEFAULT_SESSION_ID``), as for the other
    accessors. A state exists only once ``bind_session_config`` created it, with a
    profile and a config, so a state in the map is a binding.
    """
    with _session_lock:
        return (
            DEFAULT_SESSION_ID if session_id is None else session_id
        ) in _session_state


def clear_session_state(session_id: Optional[str]) -> None:
    """Drop the SessionState for ``session_id``.

    The id is required: a call with no argument raises ``TypeError``, so a caller
    that meant to clear every session cannot clear one by accident. An explicit
    ``None`` is the stdio session (``DEFAULT_SESSION_ID``), as for the other
    accessors, and an empty string is not: it is an id of its own, distinct from
    the stdio session (``bind_session_config("")`` stores a binding under it), so
    clearing ``""`` drops the state bound under ``""`` and leaves the stdio
    session's. Dropping every session's state is :func:`clear_all_session_state`.
    ``sessions.end_session`` calls this when a session ends, so its bound profile
    goes with its workspace.
    """
    with _session_lock:
        _session_state.pop(
            DEFAULT_SESSION_ID if session_id is None else session_id, None
        )


def clear_all_session_state() -> None:
    """Drop every session's SessionState; tests use it to scrub between cases."""
    with _session_lock:
        _session_state.clear()
