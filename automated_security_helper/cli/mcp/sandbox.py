#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The per-session capability that bounds what one MCP caller may touch.

Why this module exists
----------------------
``ASH_MCP_ALLOWED_ROOTS`` bounded the scan surface for the *process*. That was
the right control in the wrong shape, and four things followed from the shape.

**The session allowance was configuration-dependent.** ``validate_scan_target``
did append this session's own workspace to the allowlist, and never a sibling's,
so with the variable SET two sessions were already isolated. But that logic lived
inside the ``if allowed:`` branch. With the variable UNSET -- the default -- the
branch was skipped and a six-entry system denylist was the only rule, and the MCP
workspace root is not one of the six. So on a default deployment every session
could name every other session's delivered source tree and ASH would scan it,
writing an output tree into the victim's sandbox on the way.

The fix is not "make the allowlist per-session"; it already was. It is an
explicit deny that does not depend on configuration: :func:`_sibling_refusal`
refuses any path under the shared workspace root that is not under *this*
session's own sandbox, on every transport and under every grant. A boundary that
exists only when a variable is set is not a boundary.

**Permissive when unset.** For a scanner reachable over HTTP, "everything except
/etc and /proc" is the wrong default. It is the right default for stdio, which
serves one client that launched the server itself in the tree the developer
meant, and where the caller already holds the server's own filesystem
privileges. So the default now depends on who is calling: deny-by-default for a
remote caller, unchanged for a local one. Flipping the local case too would refuse
every existing install and buy nothing, which is the most damaging way to get
confinement wrong -- ``test_an_unconfigured_policy_does_not_refuse_an_ordinary_workspace``
has pinned that since workspace mode landed.

"Remote" is decided per call by :func:`caller_is_remote`, from the session id
rather than from recorded server state. The session id is in turn decided by the
transport the call arrived on (``session_identity.resolve_caller_session_id``):
every network caller resolves to a server-issued id or to
``UNIDENTIFIED_SESSION_ID``, never to stdio's default, so it is remote whatever
headers it sends. That function carries the reasoning; the short version is that
process-wide transport state outlives the server object and would make the
answer depend on what ran earlier in the process.

**Ambient rather than capability.** Authority was whatever the launching process
happened to have. A :class:`SessionSandbox` is an object resolved for a named
session, which is what makes the two rules above expressible at all -- neither
can be written against a global.

**The trust boundary was split.** Scan targets were confined; config inputs were
not. So the ``.code-workspace`` file, which NAMES N scan targets, sat outside the
boundary its targets sat inside, and so did ``--workspace-config`` and
``config_path``. That is not a smaller hole than an unconfined target, it is a
file-read oracle: point ``workspace_file`` at any path on the server and the
parse error or the resolved plan reports something about its content. The read
happens during resolution, before any target exists, so confining the targets
does not help. :func:`validate_config_input` closes it.

The asymmetry was there for a real reason, though, and the reason survives: a
shared policy file governing several checkouts has to live outside the trees it
governs, and ``/etc/ash/default.yaml`` is a legitimate deployment. What was wrong
was serving that need by confining *nothing*. ``ASH_MCP_ALLOWED_CONFIG_ROOTS``
serves it by explicit grant and refuses everything else.

Migration: ``ASH_MCP_ALLOWED_ROOTS`` still works
------------------------------------------------
Unchanged meaning, unchanged spelling, no deprecation warning. It is now the
operator-grant layer feeding each session's sandbox rather than the whole
mechanism. The variable was never the defect -- the operator still needs some way
to say which of its own directories the server may scan, and this is that way.
Deprecating it would have broken every deployment that sets it in exchange for
nothing.

The one behavior change an existing deployment can observe: on a network
transport with the variable unset, targets outside the session's own sandbox are
now refused where they were accepted. That is the fix, not a side effect, and the
refusal message names the variable to set.

Failure modes and known limitations
-----------------------------------
* Isolation is only as strong as two callers' session ids differing. On sse and
  stateful streamable-HTTP the server issues the id; on a stateless server the id
  is the ``Mcp-Session-Id`` header only when the operator declared, with
  ``--trust-upstream-session-id``, that a platform in front issues and
  authenticates it, and then isolation is the platform's job. This module
  guarantees that an id names one directory and not a path, and that one id
  cannot reach another's.
* A network caller with no session identity resolves to
  ``UNIDENTIFIED_SESSION_ID``: remote, with no sandbox of its own, so the
  operator's grants are all it can reach.
* A caller that reaches these functions with no session id at all gets the local
  default. That is deliberate -- an in-process caller of the tool functions is not
  a server, and importing this module must not tighten behavior for it -- but it
  does mean a new MCP tool that forgets to resolve and pass its session id
  silently evaluates as local. ``_with_session`` echoing the id back is the
  cheapest way to notice from outside.
* A config input is more than the file named. Each base its ``extends`` chain
  names is checked with the same rule (:func:`config_base_gate`), passed into
  resolution by every MCP tool that resolves a config. ``config_sources`` on its
  own confines a chain to the parent of ``.ash/`` for a file in ``.ash/``, which
  is wider than a grant naming that ``.ash/`` directory. A new tool that resolves
  a config without passing the gate gets that wider rule.
* A path is compared after ``resolve()``, so a symlink is followed before
  containment is tested. A link inside a granted root pointing outside it is
  therefore refused, which is the intent. It also means a granted root that is
  itself a symlink is compared resolved, so the two sides agree.
"""

from __future__ import annotations

import errno
import os
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Any, Callable, List, Optional, Tuple

from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
)
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.utils.link_locations import link_locations
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.process_env import set_environ

_logger = ASH_LOGGER

#: Directories the server may scan and write an output tree into. Unchanged
#: spelling and meaning; see the module docstring on migration.
ASH_MCP_ALLOWED_ROOTS_ENV = "ASH_MCP_ALLOWED_ROOTS"

#: Directories the server may read a config input from -- an ``.ash.yaml``, a
#: ``.code-workspace`` definition, a ``--workspace-config`` policy file. Separate
#: from the scan roots because the two are different capabilities: a config
#: location is read from and never scanned or written into, so conflating them
#: would let an operator widen the scan surface by naming a config directory.
ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV = "ASH_MCP_ALLOWED_CONFIG_ROOTS"

#: The parent of every session workspace, read by ``source_delivery`` (its
#: resolution order is documented there). Named here so a refusal can tell the
#: caller which setting moves the workspace area.
ASH_MCP_WORKSPACE_ROOT_ENV = "ASH_MCP_WORKSPACE_ROOT"

#: Subdirectory of a session sandbox holding the delivered source tree. Matches
#: what ``source_delivery`` writes; the two must agree or a delivered tree is
#: refused by the boundary that exists to permit it.
SOURCE_DIR_NAME = "source"

#: Subdirectory of a session sandbox holding a config materialized for this
#: session -- currently a profile bound by ``select_profile``. Inside the sandbox
#: so one boundary covers the config and the source it configures.
CONFIG_DIR_NAME = "config"

#: Subdirectory of a session sandbox holding a profile after a client's
#: ``select_profile`` ``patch_ops`` or ``override_yaml``. The server writes it, but
#: the values the patch set are the client's, so it is outside ``config/`` and
#: ``config_is_client_supplied`` counts it as the client's like anything else in
#: the sandbox. The session's own sandbox root covers it for reading.
CLIENT_CONFIG_DIR_NAME = "client-config"

#: Transports that carry callers the server does not otherwise trust.
_NETWORKED_TRANSPORTS = frozenset({"streamable-http", "sse"})

#: Every value ``ASH_MCP_TRANSPORT`` may hold, once stripped and lower-cased.
KNOWN_TRANSPORTS = frozenset({"stdio"}) | _NETWORKED_TRANSPORTS

#: Which transport this process serves. Held in the environment rather than in a
#: module global, for two reasons that a global got wrong.
#:
#: A module global leaks. ``mcp_command`` sets the transport once, and a process
#: that builds a streamable-HTTP app and then does something else -- which is
#: exactly what the test suite does -- would leave every later call evaluated as
#: though it came from the network. The failure direction is deny, so it surfaces
#: as an unrelated refusal rather than as an unsafe accept, but it is still wrong:
#: ``test_mcp_get_scan_results`` started failing on a path it had every right to
#: read, and only because of a test that ran before it.
#:
#: The environment also carries across a fork or exec, which matters because a
#: deployment that launches the server as a subprocess should not silently get the
#: permissive default, and it puts this knob alongside the other two --
#: ``ASH_MCP_ALLOWED_ROOTS`` and ``ASH_MCP_WORKSPACE_ROOT`` -- rather than in a
#: different mechanism from them.
ASH_MCP_TRANSPORT_ENV = "ASH_MCP_TRANSPORT"

#: What an unset ``ASH_MCP_TRANSPORT`` means. stdio, deliberately, so that
#: importing this module cannot tighten behavior for an in-process caller that is
#: not a server at all -- a unit test, or a library consumer calling the tool
#: functions directly.
DEFAULT_TRANSPORT = "stdio"


def set_server_transport(name: str) -> None:
    """Record which transport this process serves.

    Called once from ``mcp_command`` before the server starts serving.
    """

    set_environ(ASH_MCP_TRANSPORT_ENV, name)


def get_server_transport() -> str:
    """Return ``ASH_MCP_TRANSPORT`` stripped and lower-cased, or the default if unset.

    Normalized because the variable is typed by an operator: ``Streamable-HTTP``
    or a trailing newline from a secrets file names the same transport.
    """

    return (os.environ.get(ASH_MCP_TRANSPORT_ENV) or "").strip().lower() or (
        DEFAULT_TRANSPORT
    )


def transport_is_networked() -> bool:
    """True unless ``ASH_MCP_TRANSPORT`` is unset or names stdio.

    An operator override, and the secondary signal. :func:`caller_is_remote` is
    the primary one, because it is request-scoped and this is not. A value that
    names no known transport counts as networked: the operator set the variable
    to say something about trust, and the safe reading of a typo is the
    stricter one. ``ash mcp`` refuses to start with such a value
    (:func:`unknown_transport_override`).
    """

    return get_server_transport() != DEFAULT_TRANSPORT


def unknown_transport_override() -> Optional[str]:
    """The raw ``ASH_MCP_TRANSPORT`` value when it names no known transport."""

    if get_server_transport() in KNOWN_TRANSPORTS:
        return None
    return os.environ.get(ASH_MCP_TRANSPORT_ENV)


def caller_is_remote(session_id: Optional[str]) -> bool:
    """True when this call came from a client the server did not launch.

    Keyed on the session id, which is the only *request-scoped* signal available
    at a synchronous boundary like this one, and which is exactly what
    distinguishes the two cases. A transport with sessions supplies an
    ``Mcp-Session-Id``; stdio has no headers and resolves to
    ``DEFAULT_SESSION_ID``, the sentinel ``session_identity`` returns when no
    header arrived. So a real id means somebody connected, and the sentinel -- or
    no id at all -- means the launching process is the caller.

    Why not the transport alone. It was, and process-wide state turned out to be
    the wrong shape for it: ``mcp_command`` sets the transport once and it outlives
    the server object, so a process that built a streamable-HTTP app and then did
    anything else evaluated every later call as remote. That is fail-closed, so it
    surfaced as an unrelated refusal rather than an unsafe accept --
    ``test_mcp_get_scan_results`` began refusing a path it had every right to read,
    and 31 other tests with it -- but it was still wrong, and a boundary whose
    answer depends on what ran earlier in the process is not one worth having.

    A network caller never resolves to the sentinel: the transport supplies a
    server-issued id or ``UNIDENTIFIED_SESSION_ID`` (see
    ``session_identity.resolve_caller_session_id``), and both are remote. The
    env var is kept as an operator override, ORed in, that makes every caller
    remote, in-process ones included.
    """

    from automated_security_helper.cli.mcp.profile_registry import (
        DEFAULT_SESSION_ID,
    )

    if transport_is_networked():
        return True
    return bool(session_id) and session_id != DEFAULT_SESSION_ID


# ---------------------------------------------------------------------------
# Grant parsing
# ---------------------------------------------------------------------------


def _parse_roots(raw: Optional[str]) -> Tuple[Path, ...]:
    """Parse an ``os.pathsep``-separated grant into resolved directories.

    ``os.pathsep``, not a literal ":". On Windows the separator is ";" and a
    colon appears inside ordinary paths, so splitting on ":" would cut "C:\\src"
    in half and yield a root of "C".

    An empty entry is dropped rather than resolved. ``"".split(os.pathsep)`` is
    ``[""]`` rather than ``[]``, and ``Path("").resolve()`` is the process
    working directory, so a trailing or doubled separator would quietly grant the
    cwd and everything beneath it.
    """

    if not raw:
        return ()

    roots: List[Path] = []
    for entry in raw.split(os.pathsep):
        entry = entry.strip()
        if not entry:
            continue
        roots.append(Path(entry).expanduser().resolve())
    return tuple(roots)


def operator_scan_roots() -> Tuple[Path, ...]:
    """The directories the operator granted for scanning, possibly none."""

    return _parse_roots(os.environ.get(ASH_MCP_ALLOWED_ROOTS_ENV))


def operator_config_roots() -> Tuple[Path, ...]:
    """The directories the operator granted for reading config, possibly none."""

    return _parse_roots(os.environ.get(ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV))


# ---------------------------------------------------------------------------
# Workspace-root geometry
# ---------------------------------------------------------------------------


def shared_workspace_root() -> Optional[Path]:
    """The parent of every session sandbox, resolved, or None if unavailable.

    None rather than raising: a host with no home directory cannot resolve one,
    and that must not take the operator's grant down with it. The caller treats
    None as "there are no sandboxes", which is true on such a host -- source
    delivery cannot work there either.
    """

    from automated_security_helper.cli.mcp.source_delivery import (
        resolve_workspace_root,
    )

    try:
        return resolve_workspace_root().expanduser().resolve()
    except (OSError, RuntimeError) as exc:
        _logger.debug("MCP sandbox: no resolvable workspace root (%s)", exc)
        return None


def config_is_client_supplied(config_path: str | Path) -> bool:
    """True when ``config_path`` is a file an MCP client delivered.

    Everything under the shared workspace root got there through a client: a
    delivered source tree, a zip upload and its staging. The exception is the
    profile files the server writes in each session's ``config/`` directory
    (``_is_server_written_config``): the operator's profile that
    ``select_profile`` materializes, a workspace tool's per-call profiles, and
    the copy of one of them that a live scan of that session loads in its place
    (``_is_a_live_scan_copy_of_this_sessions_file``; the session is the
    directory under the shared root). Any other file there is the client's, and
    no scan may write there (``_server_config_dir_refusal``). Any session's
    sandbox counts, not only the caller's, because a sibling session's upload is
    no more the operator's than the caller's own.

    A scan whose selected config is client-supplied resolves it with
    ``resolve_config(untrusted_config=True)``, which keeps its sandbox settings
    restrict-only, and ``config_sources.read_config_file`` refuses it if it uses
    ``!ENV``. The path is judged as named, at each symlink looking it up follows
    (``link_locations``), and as resolved, so a symlink counts by where it sits as
    well as by the file it reaches: a link a client delivered is the client's
    even when it points at a file elsewhere, a path elsewhere that passes through
    such a link reaches the file the client chose, and a link elsewhere that
    reaches into a sandbox reaches a file a client wrote. Ancestry is also
    checked by file identity (``os.path.samefile``), so a spelling of the root
    through a link, or one that differs only in case on a case-insensitive
    volume, is still the root.
    """

    shared = shared_workspace_root()
    if shared is None:
        return False
    # os.path.realpath rather than Path.resolve, as in validate_config_input: on
    # Python 3.12 and older, resolve raises RuntimeError for a link that leads
    # back to itself, and a scanned tree can hold one (a self-referencing
    # .semgrepignore made a scanner's construction raise here). realpath
    # resolves as far as it can and raises nothing.
    for candidate in (
        Path(os.path.abspath(config_path)),
        *link_locations(config_path),
        Path(os.path.realpath(config_path)),
    ):
        parts = _parts_below(candidate, shared)
        if parts is not None and not _is_server_written_config(
            parts[1:], session_key=parts[0] if parts else None, candidate=candidate
        ):
            return True
    return False


def _server_written_config_names() -> Tuple[str, ...]:
    """The fixed names the server writes in a session's ``config/`` directory.

    Read from ``profile_registry``, which writes them
    (``materialize_session_config``): the bound profile, and the name a workspace
    tool's per-call profile had before each profile got a file of its own. The
    per-profile names are matched by ``profile_registry.is_call_profile_filename``.
    """
    from automated_security_helper.cli.mcp.profile_registry import (
        CALL_PROFILE_FILENAME,
        SESSION_CONFIG_FILENAME,
    )

    return (SESSION_CONFIG_FILENAME, CALL_PROFILE_FILENAME)


def _is_a_server_written_name(name: str) -> bool:
    """Whether ``name`` is one of the file names the server writes in ``config/``:
    ``_server_written_config_names`` or a per-profile call profile's name
    (``is_call_profile_filename``)."""
    from automated_security_helper.cli.mcp.profile_registry import (
        is_call_profile_filename,
    )

    return name in _server_written_config_names() or is_call_profile_filename(name)


def _is_a_live_scan_copy_of_this_sessions_file(
    name: str, session_key: str, candidate: Path
) -> bool:
    """Whether ``name``, directly in a session's ``config/`` directory, is the copy
    of one of the server's own files that a live scan of that session made for
    itself (``mcp_tools._snapshot_profile_for_scan``).

    Every one of these holds, and none is enough alone: the name parses as a
    scan copy's, the prefix and then a scan id in the spelling a scan gives its
    ids (``config_sources.parse_scan_copy_name``); the file it copies is named
    as one the server writes; ``candidate`` is a path a live scan registered
    when it created the file (``is_registered_scan_copy``; only the code that
    creates the file registers it, after taking the name exclusively); and the
    scan id is one this session's registry holds. A client chooses the names it
    can write and knows the ids of its own scans, so the prefix, the directory
    or a name does not make a file the server's; a scan of another session, or
    a copy no scan holds any more, does not either.
    """
    from automated_security_helper.config.config_sources import (
        is_registered_scan_copy,
        parse_scan_copy_name,
    )
    from automated_security_helper.core.resource_management.scan_management import (
        session_holds_scan,
    )

    parsed = parse_scan_copy_name(name)
    if parsed is None:
        return False
    scan_id, copied_name = parsed
    if not _is_a_server_written_name(copied_name):
        return False
    if not is_registered_scan_copy(candidate):
        return False
    return session_holds_scan(scan_id, session_key)


def _is_server_written_config(
    parts: Tuple[str, ...],
    *,
    session_key: Optional[str] = None,
    candidate: Optional[Path] = None,
) -> bool:
    """Whether ``parts``, below a session's sandbox, name a file the server writes.

    Directly in ``config/``, under one of ``_server_written_config_names`` or a
    per-profile call profile's name (``is_call_profile_filename``). With
    ``session_key`` (the session's directory name, which is its id) and
    ``candidate`` (the path ``parts`` came from), also the copy of one of those
    files that a live scan of that session made for itself
    (``_is_a_live_scan_copy_of_this_sessions_file``): the scan loads the copy in
    place of the file, so it is the server's like the file. Without them only
    the files themselves are.
    """
    if len(parts) != 2 or parts[0] != CONFIG_DIR_NAME:
        return False
    if _is_a_server_written_name(parts[1]):
        return True
    return (
        session_key is not None
        and candidate is not None
        and _is_a_live_scan_copy_of_this_sessions_file(parts[1], session_key, candidate)
    )


def client_named_config_is_untrusted(
    config_path: str | Path, session_id: Optional[str] = None
) -> bool:
    """Whether a config path an MCP client named is the client's choice, not the operator's.

    A path a client names is the client's unless the operator set it aside: it is
    in a directory ``ASH_MCP_ALLOWED_CONFIG_ROOTS`` names, or it is one of the
    profile files the server writes in the ``config/`` directory of the calling
    session, ``session_id`` (``DEFAULT_SESSION_ID``'s when None, as
    ``select_profile`` writes it), or the copy of one of them that a live scan
    of that session loads in its place. Another file in that directory, and
    another session's profile files, are not set aside for this caller. A
    file a client delivered (``config_is_client_supplied``) is always the
    client's. So is a config in another repository under the allowed scan roots:
    the operator let the server scan it, not take its config as their own. Both
    the path as named and the file it resolves to must be set aside; a symlink
    on the way that a client delivered makes it the client's through
    ``config_is_client_supplied``.

    For a remote caller this is also which config files resolve no ``!ENV``,
    named or not (``config_sources.env_refused_for``).
    """
    from automated_security_helper.cli.mcp.profile_registry import (
        DEFAULT_SESSION_ID,
    )

    if config_is_client_supplied(config_path):
        return True
    config_roots = operator_config_roots()
    # Resolved as the gates resolve it, so an id that cannot name one directory
    # owns no config directory here either.
    own = _sandbox_for_gate(
        DEFAULT_SESSION_ID if session_id is None else session_id
    ).root

    def chosen_by_operator(candidate: Path) -> bool:
        if own is not None:
            parts = _parts_below(candidate, own)
            if parts is not None and _is_server_written_config(
                parts, session_key=own.name, candidate=candidate
            ):
                return True
        return any(_parts_below(candidate, root) is not None for root in config_roots)

    # os.path.realpath, as config_is_client_supplied above: Path.resolve raises
    # RuntimeError on Python 3.12 and older for a link that leads back to
    # itself, and a named config is judged, not raised on.
    return not all(
        chosen_by_operator(candidate)
        for candidate in (
            Path(os.path.abspath(config_path)),
            Path(os.path.realpath(config_path)),
        )
    )


def _parts_below(path: Path, root: Path) -> Optional[Tuple[str, ...]]:
    """``path``'s components below ``root``, matching ancestors by file identity."""
    try:
        return path.relative_to(root).parts
    except ValueError:
        pass
    if not root.exists():
        return None
    for ancestor in path.parents:
        try:
            if os.path.samefile(ancestor, root):
                return path.relative_to(ancestor).parts
        except OSError:
            continue
    return None


def _is_or_below(path: Path, root: Path) -> bool:
    """Whether ``path`` is ``root`` or inside it, by text and by file identity.

    ``_parts_below`` matches the ancestors of ``path``, never ``path`` itself, so
    ``path`` is compared with ``root`` here too: the root spelled in another case
    on a case-insensitive volume is still the root. A path that does not exist
    has only the text comparison.
    """
    if _parts_below(path, root) is not None:
        return True
    try:
        return os.path.samefile(path, root)
    except OSError:
        return False


def _validated_session_component(session_id: str) -> str:
    """Return ``session_id`` when it names one directory, else raise.

    Refused rather than sanitized, for the reason ``session_identity`` gives:
    sanitizing maps two distinct ids onto one directory and silently merges two
    callers' source trees. This is the second gate -- the transport edge already
    refuses these -- and it exists for a caller that reaches the sandbox
    directly.
    """

    # The one rule every builder of a session path applies
    # (session_paths.validated_path_component): the registry, source delivery
    # and the TTL sweep refuse an id by it, and a separator-only rule here
    # granted a sandbox root for ids they refuse (a control character, a name
    # over the length bound, the shape of a hidden delete name).
    from automated_security_helper.cli.mcp.session_paths import (
        validated_path_component,
    )

    return validated_path_component(session_id, "session_id")


# ---------------------------------------------------------------------------
# The capability
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SessionSandbox:
    """What one session may reach.

    Frozen so a caller cannot widen its own reach by mutating the object it was
    handed. Resolved fresh per call rather than cached, because the operator
    grant is read from the environment and a cached sandbox would keep serving a
    stale one.

    Attributes:
        session_id: The session this sandbox belongs to, or None for a caller
            that named none. A caller with no session owns no sandbox, so every
            sandbox is somebody else's and ``root`` is None.
        root: This session's own sandbox directory, or None when there is no
            session or no resolvable workspace root.
        scan_roots: Directories that may be scanned and written into.
        config_roots: Directories a config input may be read from.
        fall_back_to_denylist: True when no grant applies and the transport is
            local, selecting the legacy "everything except a few system
            directories" net rather than deny.
        confine_config: True when a caller-named config path must fall inside
            ``config_roots``. False on a local transport, where the caller
            launched the server and can already read any file the server can, so
            the oracle this closes gives it nothing it does not have -- and
            confining would break the documented deployment where a
            ``.code-workspace`` lives beside checkouts rather than inside one.
    """

    session_id: Optional[str]
    root: Optional[Path]
    scan_roots: Tuple[Path, ...]
    config_roots: Tuple[Path, ...]
    fall_back_to_denylist: bool
    confine_config: bool

    @property
    def source_dir(self) -> Path:
        """Where a delivered source tree lands. Raises if there is no sandbox."""

        if self.root is None:
            raise RuntimeError(
                "this caller has no session sandbox, so it has no source "
                "directory; pass a session_id resolved from the transport"
            )
        return self.root / SOURCE_DIR_NAME

    @property
    def config_dir(self) -> Path:
        """Where a config materialized for this session lands."""

        if self.root is None:
            raise RuntimeError(
                "this caller has no session sandbox, so it has no config "
                "directory; pass a session_id resolved from the transport"
            )
        return self.root / CONFIG_DIR_NAME

    @property
    def client_config_dir(self) -> Path:
        """Where a profile a client patched with ``select_profile`` lands."""

        if self.root is None:
            raise RuntimeError(
                "this caller has no session sandbox, so it has no client config "
                "directory; pass a session_id resolved from the transport"
            )
        return self.root / CLIENT_CONFIG_DIR_NAME

    def owns(self, resolved: Path) -> bool:
        """True when ``resolved`` is this session's own sandbox or inside it."""

        if self.root is None:
            return False
        return _is_or_below(resolved, self.root)

    def permits_scan(self, resolved: Path) -> bool:
        """True when ``resolved`` may be scanned and written into.

        The session's own sandbox is matched by file identity as well as by text
        (:meth:`owns`), as ``_sibling_refusal`` matches it, so its tree spelled in
        another case on a case-insensitive volume is still the caller's. A
        directory the operator granted is matched by text only: a respelling of
        one of those is refused.
        """

        return any(
            resolved == root or resolved.is_relative_to(root)
            for root in self.scan_roots
        ) or self.owns(resolved)

    def permits_config(self, resolved: Path) -> bool:
        """True when ``resolved`` may be read as a config input.

        A config input is a *file*, so its containing directory is what has to
        fall inside a root -- but the file path itself is tested, because
        ``is_relative_to`` on the file gives the same answer and testing the
        parent would accept a root that names the file's grandparent only by
        accident of how the caller spelled it.

        The session's own sandbox is matched by file identity as well as by text,
        as in :meth:`permits_scan`.
        """

        return any(
            resolved == root or resolved.is_relative_to(root)
            for root in self.config_roots
        ) or self.owns(resolved)


def session_sandbox(session_id: Optional[str] = None) -> SessionSandbox:
    """Resolve the capability for ``session_id``.

    Args:
        session_id: The session this call acts for, as resolved from the
            transport. None for a caller that named none.

    Returns:
        A :class:`SessionSandbox`.

    Raises:
        ValueError: if ``session_id`` is non-empty but could not name a single
            directory.
    """

    from automated_security_helper.cli.mcp.session_identity import (
        UNIDENTIFIED_SESSION_ID,
    )

    root: Optional[Path] = None
    # A caller the server could not identify owns no sandbox: it is remote, and
    # the operator's grant is all it may reach.
    if session_id and session_id != UNIDENTIFIED_SESSION_ID:
        _validated_session_component(session_id)
        shared = shared_workspace_root()
        if shared is not None:
            root = shared / session_id

    granted_scan = operator_scan_roots()
    granted_config = operator_config_roots()

    scan_roots: List[Path] = list(granted_scan)
    if root is not None:
        # The session's own sandbox, never the shared root that holds every
        # other session's source. ``_session_workspace`` in source_delivery
        # exists precisely to stop one session reaching a sibling's, and
        # granting the parent here would undo it.
        scan_roots.append(root)

    remote = caller_is_remote(session_id)

    # No grant and a local caller: keep the legacy net. See the module docstring
    # -- refusing every unconfigured local install is the more damaging failure,
    # and on stdio the caller already holds the server's own filesystem
    # privileges.
    fall_back = not granted_scan and not remote

    config_roots: List[Path] = list(granted_config)
    # A grant that permits scanning a tree has to permit reading the config that
    # lives in it, or every in-tree ``.ash.yaml`` becomes unreachable.
    config_roots.extend(scan_roots)
    if root is not None:
        config_roots.append(root / CONFIG_DIR_NAME)

    return SessionSandbox(
        session_id=session_id or None,
        root=root,
        scan_roots=tuple(scan_roots),
        config_roots=tuple(config_roots),
        fall_back_to_denylist=fall_back,
        confine_config=remote,
    )


def _sandbox_for_gate(session_id: Optional[str]) -> SessionSandbox:
    """Resolve a sandbox for a gate, degrading a bad session id to "no session".

    :func:`session_sandbox` raises on an id that could not name one directory,
    which is right for a programmatic caller asking for a capability by name. A
    gate must not turn that into a blanket refusal, because the operator's grant
    is not at fault: a client sending a malformed id would otherwise take down
    the roots the operator configured, and the transport edge already refuses
    those ids before a tool sees them.

    Degrading is safe rather than merely lenient. A sandbox with no root owns
    nothing, so :func:`_sibling_refusal` refuses every path under the shared
    workspace area -- including the one the malformed id was shaped to reach.
    What the caller loses is exactly the session allowance it failed to name.

    The degraded sandbox is a remote caller's: the operator's grant and nothing
    else. ``session_sandbox(None)`` is the local caller's, with the permissive
    denylist fallback and unconfined config reads, and a client that sent a
    malformed id is not the process that launched the server.
    """

    try:
        return session_sandbox(session_id)
    except ValueError as exc:
        _logger.debug("MCP sandbox: no session allowance for %r (%s)", session_id, exc)
        granted_scan = operator_scan_roots()
        return SessionSandbox(
            session_id=None,
            root=None,
            scan_roots=tuple(granted_scan),
            config_roots=tuple(operator_config_roots()) + tuple(granted_scan),
            fall_back_to_denylist=False,
            confine_config=True,
        )


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------


def _refusal(
    what: str,
    path: object,
    resolved: Path,
    remedy: str,
) -> MCPResourceError:
    """Build the refusal every gate in this module returns.

    One shape for both gates so a client can branch on ``error_category``
    regardless of which one refused, matching what ``create_error_response``
    sets on the ``mcp_tools`` side.
    """

    return MCPResourceError(
        f"{what} is outside the permitted roots: {_shown_path(path)}. {remedy}",
        context=_refusal_context(path, resolved),
    )


def _shown_path(path: object) -> object:
    """The caller's own spelling of ``path``, as every refusal shows it."""
    return path.as_posix() if isinstance(path, PurePath) else path


def _refusal_context(path: object, resolved: Path) -> dict[str, str]:
    """The context every refusal in this module carries; see ``_refusal``."""
    return {
        "cwd": str(Path.cwd()),
        "directory_path": str(path),
        "resolved_path": str(resolved),
        "error_category": ErrorCategory.INVALID_PATH.value,
    }


def _running_on_windows() -> bool:
    return os.name == "nt"


#: Links followed before a chain is given up on as unjudgeable, the bound
#: ``os.path.realpath`` applies to a chain of links before it stops following.
_LINK_HOPS = 40


def _names_a_windows_share(path: object) -> bool:
    """Whether the text of ``path`` names something other than a local volume path.

    True for a UNC path, ``\\\\server\\share`` or ``//server/share``, and for any
    path in the extended form, ``\\\\?\\...``, ``\\\\.\\...`` or the native ``\\??\\...``,
    whose device is not a drive letter: ``\\\\?\\UNC\\server\\share`` (a share),
    ``\\\\?\\GLOBALROOT\\...`` (the object namespace, through which a redirector or a
    mounted share is reached by another name) and ``\\\\.\\pipe\\...`` (a device, not
    a directory) are all refused by the callers, which open only directories on a
    local volume. Only ``\\\\?\\C:\\repo`` and ``\\\\.\\C:\\repo``, a drive letter and a
    separator after the prefix, are local; a drive-relative ``\\\\?\\C:repo`` is not,
    and neither is ``\\\\.\\C:`` with nothing after the colon, which names the
    volume's device rather than a directory. Forward slashes are read as separators first, so a
    mixed spelling is judged by what it names. ``os.readlink`` returns a junction's
    target in the extended form (its substitute name, since Python 3.8), so the
    form is read here rather than taken for a share by its two leading separators,
    and a junction to a local volume stays local.
    """
    text = os.fspath(path) if isinstance(path, (str, os.PathLike)) else str(path)
    text = text.replace("/", "\\")
    if text.startswith(("\\\\?\\", "\\\\.\\", "\\??\\")):
        rest = text[4:]
        if not _is_a_drive_spelling(rest):
            return True
        # Behind a device prefix a ``..`` component is not a step up a local
        # tree: Win32 normalizes a ``\\.\`` path before the object manager sees
        # it, so ``\\.\C:\..\UNC\server\share`` is the share and ``\\.\C:\..\pipe\x``
        # the pipe, each spelled with a drive letter in front. Such a spelling is
        # judged by what it reaches, whatever it reaches: a caller that means a
        # local directory names it without the step.
        return any(part == ".." for part in rest.split("\\"))
    return text.startswith("\\\\")


def _is_a_drive_spelling(text: str) -> bool:
    """Whether ``text`` is a drive letter, a colon and a separator: ``C:\\`` or ``C:\\repo``.

    A directory on a volume always has the separator (the volume's root is
    ``C:\\``), and so does the substitute name ``os.readlink`` gives for a
    junction. ``C:`` alone, behind the prefix, names the volume's device object
    (``\\\\.\\C:`` is how a raw volume is opened), not a directory on it, and the
    drive-relative ``C:repo`` names nothing the extended form resolves against a
    current directory; neither is a drive spelling here.
    """
    return (
        len(text) >= 3
        and text[0].isascii()
        and text[0].isalpha()
        and text[1] == ":"
        and text[2] == "\\"
    )


def _link_chain_names_a_windows_share(text: str) -> Optional[bool]:
    """Whether the link at ``text``, or a link it leads to, names a network share.

    Read with ``os.readlink`` one hop at a time: reading a reparse point's
    substitute name opens the link's own entry, never what it names, so a chain
    is judged without a connection to anything it leads to. A relative name is
    taken from the link's directory, as resolving would take it. The walk ends
    at the first name that is not a link, or that is not there: a local name is
    then all that resolving would open, and the answer is False.

    None when the chain cannot be judged: a reparse point whose name cannot be
    read (one that is no symbolic link or junction), a hop that cannot be
    examined (its directory cannot be searched: it may be a link to a share that
    nobody here can see), or a chain longer than ``_LINK_HOPS``. The caller
    refuses then, as it refused every link before, since what resolving would
    open cannot be told. Only a hop that is not there (no such file, or a path
    component that is not a directory) ends the walk as a local name: nothing
    is there to follow, so resolving opens nothing.
    """
    from automated_security_helper.utils.scanned_tree import _is_link_stat

    current = text
    for _ in range(_LINK_HOPS):
        try:
            target = os.readlink(current)
        except (OSError, ValueError):
            # OSError: the entry went away or cannot be opened. ValueError: on
            # Windows CPython raises "not a symbolic link" for a reparse point
            # that names a path but is neither a symbolic link nor a junction
            # (a WSL link), which ``_is_link_stat`` reads as a link.
            return None
        if _names_a_windows_share(target):
            return True
        if not os.path.isabs(target):
            target = os.path.join(os.path.dirname(current), target)
        target = os.path.normpath(target)
        try:
            is_link = _is_link_stat(os.lstat(target))
        except (FileNotFoundError, NotADirectoryError):
            # Not there: a local name that resolving would open nothing for.
            return False
        except OSError:
            # Cannot be examined (a directory the process cannot search): the
            # entry may itself be a link to a share, so the chain is unjudged.
            return None
        if not is_link:
            return False
        current = target
    return None


def _refusal_before_resolving(what: str, path: object) -> Optional[MCPResourceError]:
    """On Windows, refuse a client-named path whose resolution would open a connection.

    Resolving a UNC path, or a link whose target is one, makes Windows open a
    connection to the host the path names, before any gate has judged it.
    ``config_sources`` refuses a linked source unresolved for that reason
    (``_permitted``); the gates here resolved the caller's path first, so a UNC
    path, or a link to one, had the server reach the host it named and then be
    refused. A UNC spelling is refused as given. A link is read, not resolved
    (``_link_chain_names_a_windows_share``): one that leads to a share, or whose
    target cannot be read, is refused unresolved; one that leads to a local name
    goes on to the gates and is judged resolved, as on every other platform, so a
    linked checkout, a junction in a repository and a link to nothing are judged
    as the directory or file they name rather than refused for being links.
    Nothing is refused on other platforms, where resolving opens nothing.

    Every component of the path is read, not only its last: ``os.lstat`` on the
    whole path follows a link in a PARENT component (only the final one is left
    unfollowed), so ``C:\\granted\\lnk\\repo`` with ``lnk`` a link to a share
    opened the share at the check meant to prevent it. The walk goes from the
    anchor down; the first component that is a link is judged as the last one
    was, and a local link is followed to judge the components under it.
    """
    if not _running_on_windows():
        return None
    text = os.fspath(path) if isinstance(path, (str, os.PathLike)) else str(path)
    if _names_a_windows_share(path):
        return _refusal(
            what,
            path,
            Path(text),
            "It names a network share or a device path, which the MCP server does "
            "not open. Name a directory on a local volume.",
        )
    from automated_security_helper.utils.scanned_tree import _is_link_stat

    # Win32 collapses ``..`` lexically before any file access, so a spelling
    # like ``C:\granted\missing\..\lnk`` examines ``C:\granted\lnk`` and never
    # asks whether ``missing`` is there. The walk judges that collapsed spelling,
    # the one the OS will examine: walked as written, the missing component would
    # end the walk with nothing judged and the link under the ``..`` would then be
    # resolved by the gates. A ``..`` behind a device prefix was refused above.
    components = _components_down_to(os.path.normpath(text))
    for index, component in enumerate(components):
        try:
            is_link = _is_link_stat(os.lstat(component))
        except OSError:
            # Not there, or not examinable: nothing below it is either (the
            # spelling is already collapsed, so no later ``..`` steps back over
            # it), and the gates judge the path as they do on every other
            # platform.
            return None
        if not is_link:
            continue
        reaches_a_share = _link_chain_names_a_windows_share(component)
        if reaches_a_share is False:
            # A local link: what it names is local, so the components under it
            # are judged through it, as resolving would read them.
            continue
        where = (
            "It is a link"
            if index == len(components) - 1
            else f"Its component {_shown_path(component)} is a link"
        )
        if reaches_a_share:
            return _refusal(
                what,
                path,
                Path(text),
                f"{where} that leads to a network share or a device path, which "
                "the MCP server does not open. Name a directory on a local volume.",
            )
        return _refusal(
            what,
            path,
            Path(text),
            f"{where} whose target the MCP server cannot read, so it is not "
            "resolved on Windows: resolving one can open a connection to the host "
            "its target names. Name the directory itself.",
        )
    return None


def _components_down_to(text: str) -> List[str]:
    """``text``'s ancestors from its anchor down, then ``text`` itself.

    ``C:\\a\\b`` gives ``C:\\a`` and ``C:\\a\\b``; the anchor alone (a drive root
    or a share root) is not a component to judge. A relative path starts at its
    first component. The spelling is kept as given: nothing here resolves.
    """
    parsed = Path(text)
    parts = list(parsed.parts)
    if parsed.anchor and parts and parts[0] == parsed.anchor:
        current = parts[0]
        rest = parts[1:]
    else:
        current = ""
        rest = parts
    components: List[str] = []
    for part in rest:
        current = os.path.join(current, part) if current else part
        components.append(current)
    return components or [text]


def _sibling_refusal(
    sandbox: SessionSandbox, path: object, resolved: Path
) -> Optional[MCPResourceError]:
    """Refuse a path inside the shared workspace root but not inside this sandbox,
    and a path the shared workspace root is inside, on disk yet or not.

    Checked before anything that could allow, and independent of both the
    operator grant and the transport. That independence is the point: the
    pre-change hole was that isolation only existed when a variable happened to
    be set, so a rule that can be switched off is not the fix.

    Containment is judged by file identity as well as by text, as in
    ``_server_config_dir_refusal``, so a spelling that differs only in case on a
    case-insensitive volume is refused like the exact one.

    The message names neither the sibling's session id nor its path. Telling one
    tenant that another exists, and what it is called, is a disclosure the
    refusal does not need -- ``delivered_session_count`` exists for the one
    diagnostic that legitimately needs to know somebody else delivered
    something, and it returns a count for the same reason.
    """

    shared = shared_workspace_root()
    if shared is None:
        return None
    if _is_or_below(shared, resolved) and not _is_or_below(resolved, shared):
        # The target is an ancestor of the shared root: its parent, the home
        # directory, a granted tree above it. A scan of it walks every
        # session's delivered source, which is the same disclosure as scanning
        # a sibling directly, so it is refused on the same footing, before
        # any grant is consulted. Judged by path, whether or not the root is on
        # disk yet: a root created after the judgment changes nothing, and a
        # root that cannot be read does not read as absent.
        # The path shown is the caller's own, which names no other session.
        # No grant admits this target, so the remedy names the setting that
        # moves the workspace area rather than the one that grants roots.
        return MCPResourceError(
            f"Target {_shown_path(path)} contains the MCP session workspace "
            "area, so a scan of it would read every session's delivered source. "
            "Scan a tree this session delivered, or set "
            f"{ASH_MCP_WORKSPACE_ROOT_ENV} to a workspace area the granted "
            "directory does not contain.",
            context=_refusal_context(path, resolved),
        )
    inside_shared = _is_or_below(resolved, shared)
    if not inside_shared or sandbox.owns(resolved):
        return None
    return _refusal(
        "Target",
        path,
        # Deliberately not the resolved sibling path: it carries the other
        # session's id. The caller's own spelling is echoed above and is enough
        # to identify what it asked for.
        resolved=Path("<another session's workspace>"),
        remedy=(
            "It resolves inside the MCP session workspace area but not inside "
            "this session's own sandbox. Scan a tree this session delivered, or "
            "a directory the operator granted with "
            f"{ASH_MCP_ALLOWED_ROOTS_ENV}."
        ),
    )


def _server_config_dir_refusal(
    sandbox: SessionSandbox, path: object, resolved: Path
) -> Optional[MCPResourceError]:
    """Refuse this session's ``config/`` or ``client-config/`` as a scan target.

    A scan target is written into (``<target>/.ash``), and so is a workspace
    ``output_dir``, which this gate checks too. The server writes the session's
    profiles in those two directories, and the files it writes in ``config/`` are
    the operator's (``_is_server_written_config``), so no scan may write there,
    whatever the grants and the transport. Checked after ``_sibling_refusal``,
    which has already refused another session's.
    """
    if sandbox.root is None:
        return None
    for name in (CONFIG_DIR_NAME, CLIENT_CONFIG_DIR_NAME):
        server_dir = sandbox.root / name
        # By file identity too (_is_or_below), so a spelling that differs only in
        # case on a case-insensitive volume is refused: the directory itself as
        # well as a path below it. _parts_below matches ancestors alone, so the
        # directory's own respelling passed it, and then passed as a scan target.
        if _is_or_below(resolved, server_dir):
            return _refusal(
                "Scan target",
                path,
                resolved,
                f"The session's {name}/ directory holds the profiles the server "
                "writes for this session, so it is not a scan target or an output "
                "directory. Use the delivered source directory or one outside the "
                "session workspace.",
            )
    return None


def validate_scan_target_in_sandbox(
    directory_path: str | Path,
    session_id: Optional[str] = None,
    resolved_out: Optional[List[Path]] = None,
) -> Optional[MCPResourceError]:
    """Check a scan target against this session's capability.

    The target is resolved here rather than by the caller. Symlinks and ``..``
    components have to be collapsed before containment is tested, or a link
    sitting inside a permitted root would pass on the strength of its own
    location while pointing somewhere else entirely.

    Existence is not checked. That belongs to ``validate_directory_path``, which
    runs after this, and keeping the two apart is what lets a refusal be
    reported as a refusal even when the target also happens not to exist.

    Args:
        directory_path: Caller-supplied scan target, absolute or relative.
        session_id: The session this call acts for.
        resolved_out: When given, a permitted target appends to it the resolved
            path this check judged, so a caller that builds paths under the
            target builds them from the path that was permitted and not from a
            second resolution of the caller's text, which can lead elsewhere by
            then. Nothing is appended for a refusal.

    Returns:
        None if permitted, otherwise an :class:`MCPResourceError`.
    """

    unresolved = _refusal_before_resolving("Scan target", directory_path)
    if unresolved is not None:
        return unresolved
    # os.path.realpath rather than Path.resolve, as the config-input gate below:
    # on Python 3.12 and older, resolve raises RuntimeError for a symbolic link
    # that leads back to itself, which escaped this gate as an exception instead
    # of a judgment. Resolved as far as it can be, the path is judged here.
    resolved = Path(os.path.realpath(directory_path))
    refusal = _scan_target_refusal(directory_path, resolved, session_id)
    if refusal is None and resolved_out is not None:
        resolved_out.append(resolved)
    return refusal


def _scan_target_refusal(
    directory_path: str | Path, resolved: Path, session_id: Optional[str]
) -> Optional[MCPResourceError]:
    """The refusal of ``validate_scan_target_in_sandbox`` for ``resolved``, or None."""

    sandbox = _sandbox_for_gate(session_id)

    remedy = (
        f"Set {ASH_MCP_ALLOWED_ROOTS_ENV} to the directories the MCP server may "
        f"scan, or deliver the tree with set_source_git or "
        f"set_source_zip_finalize so it lands in this session's sandbox."
    )
    if _is_filesystem_root(resolved) and not sandbox.permits_scan(resolved):
        # Reached most often by omitting the directory entirely: the tool falls
        # back to the process working directory, and a server launched by an
        # editor or agent frequently has "/" for a cwd. Telling that caller to
        # configure an allowlist points at the wrong lever first. Judged before
        # the gates below, so the root keeps this remedy whatever they would say
        # of a directory that contains everything. A root the operator granted
        # (a second volume's drive root on Windows, "/" where no shared
        # workspace root sits under it) is not that caller: it passes to the
        # gates below as any granted directory does, and is permitted by them
        # when nothing else refuses it.
        return _refusal(
            "Scan target",
            directory_path,
            resolved,
            (
                "Pass the directory to scan explicitly; the default is the "
                "server's working directory, which here is the filesystem root. "
                f"{remedy}"
            ),
        )

    sibling = _sibling_refusal(sandbox, directory_path, resolved)
    if sibling is not None:
        return sibling

    server_owned = _server_config_dir_refusal(sandbox, directory_path, resolved)
    if server_owned is not None:
        return server_owned

    if sandbox.permits_scan(resolved):
        return None

    if sandbox.fall_back_to_denylist:
        return _legacy_denylist_refusal(directory_path, resolved)

    return _refusal("Scan target", directory_path, resolved, remedy)


def validate_config_input(
    config_path: str | Path,
    session_id: Optional[str] = None,
    identity_out: Optional[List[Optional[Tuple[int, int]]]] = None,
    resolved: Optional[Path] = None,
) -> Optional[MCPResourceError]:
    """Check a caller-named config input against this session's capability.

    A config input is an ``.ash.yaml``, a ``.code-workspace`` definition, or a
    ``--workspace-config`` policy file. Reading a caller-named path is a
    capability in its own right, which is why this exists at all: an unconfined
    one is a file-read oracle, and the read happens during resolution, before
    any scan target exists, so confining the targets does not cover it.

    Args:
        config_path: Caller-supplied path to a config file.
        session_id: The session this call acts for.
        identity_out: When given, a permitted path appends to it the identity
            ``(device, inode)`` of the file this check approved: the file at
            the path it resolved and judged (``config_sources.file_identity``;
            None when that path leads nowhere). A caller that reads the file
            afterwards holds the read to it (``read_config_bytes(expect=)``), so
            the file read is the one judged here, and not whichever file the
            name led to when the caller looked before the check: a name that
            led to one file, then another during the check, then the first
            again would otherwise read the first, which this check never saw.
            Nothing is appended for a refusal.
        resolved: The path to judge, when the caller already holds the file open
            and took the path from the descriptor
            (``config_sources.open_config_for_judgment``). The name is then not
            resolved a second time: a name resolved after the file was opened can
            lead somewhere else by then, and the verdict must be about the file
            the read will use. Without it the name is resolved here.

    Returns:
        None if permitted, otherwise an :class:`MCPResourceError`.
    """

    if resolved is None:
        unresolved = _refusal_before_resolving("Config input", config_path)
        if unresolved is not None:
            return unresolved
        # os.path.realpath rather than Path.resolve: on Python 3.12 and older,
        # resolve raises RuntimeError for a symbolic link that leads back to
        # itself, which would escape the tool as an exception. Resolved as far as
        # it can be, the path is judged here, and its read then fails as a file
        # that cannot be loaded.
        resolved = Path(os.path.realpath(config_path))
    refusal = _config_input_refusal(config_path, resolved, session_id)
    if refusal is None and identity_out is not None:
        from automated_security_helper.config.config_sources import file_identity

        identity_out.append(file_identity(resolved))
    return refusal


def _config_input_refusal(
    config_path: str | Path,
    resolved: Path,
    session_id: Optional[str],
) -> Optional[MCPResourceError]:
    """The refusal of ``validate_config_input`` for ``resolved``, the path
    ``config_path`` leads to, or None when it is permitted."""

    sandbox = _sandbox_for_gate(session_id)

    sibling = _sibling_refusal(sandbox, config_path, resolved)
    if sibling is not None:
        return sibling

    if sandbox.permits_config(resolved):
        return None

    if not sandbox.confine_config:
        # Local transport: apply only the system-directory net. See
        # ``SessionSandbox.confine_config`` -- the caller launched this server and
        # can already read whatever it can, so the read-oracle this gate closes is
        # not a capability it gains here, and confining would refuse the ordinary
        # arrangement where a workspace definition sits beside checkouts.
        return _legacy_denylist_refusal(config_path, resolved, what="Config input")

    return _refusal(
        "Config input",
        config_path,
        resolved,
        (
            f"Set {ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV} to the directories the MCP "
            f"server may read config from -- a shared policy file governing "
            f"several checkouts belongs there -- or keep the config inside a "
            f"directory already granted by {ASH_MCP_ALLOWED_ROOTS_ENV}."
        ),
    )


def config_base_gate(session_id: Optional[str] = None) -> Callable[[Path], bool]:
    """The check every ``extends`` base must pass for this session.

    The same rule as a config path the caller names directly, so a base is
    readable exactly when naming it as ``config_path`` would be. ``config_sources``
    still applies its own confinement root on top; this only narrows it. Without
    it, a grant naming a ``.ash/`` directory would confine the chain to that
    directory's parent, which is the CLI rule and not the grant.

    Passed into resolution explicitly rather than recomputed there, because
    resolution sees a path and not the session the grant belongs to.
    """

    def permit(path: Path, resolved: Optional[Path] = None) -> bool:
        # ``resolved`` is the path an open base leads to
        # (``config_sources._resolve_base_path``): judged as it is, and not
        # resolved again.
        return (
            validate_config_input(path, session_id=session_id, resolved=resolved)
            is None
        )

    return permit


def validate_config_chain(
    config_path: str | Path,
    session_id: Optional[str] = None,
    source_dir: Optional[str | Path] = None,
) -> Optional[MCPResourceError]:
    """Check a config input and every base its ``extends`` chain names.

    The file itself goes through :func:`validate_config_input`. The chain is then
    resolved under :func:`config_base_gate`, with the confinement root a scan of
    ``source_dir`` would use, so a refusal is reported before a scan starts rather
    than as a failed scan. Any other chain error (a cycle, a missing base, a
    malformed ``patch``) or a file that does not parse is left to
    :func:`config_load_error`, which reports it as a config that cannot be
    loaded rather than as a refusal.

    Args:
        config_path: Caller-supplied path to a config file.
        session_id: The session this call acts for.
        source_dir: The scan target the config will be resolved against, if any.

    Returns:
        None if permitted, otherwise an :class:`MCPResourceError`.
    """

    return check_config_input(config_path, session_id, source_dir).refusal


@dataclass(frozen=True)
class ConfigInputCheck:
    """What :func:`check_config_input` found: a refusal, a load error, or neither.

    ``env_error`` is the ``ASHConfigEnvNotResolvedError`` for a file that may
    not use ``!ENV`` and does (``config_sources.env_refused_for``), which a
    caller reports as ``config_env_not_resolved``. ``document`` is the chain the
    check read (a ``config_sources.ResolvedConfigDocument``) when it loaded, so
    a caller that checks what its files set does not read them again.
    """

    refusal: Optional[MCPResourceError] = None
    load_error: Optional[MCPResourceError] = None
    env_error: Optional[Exception] = None
    document: Optional[Any] = None


def check_config_input(
    config_path: str | Path,
    session_id: Optional[str] = None,
    source_dir: Optional[str | Path] = None,
) -> ConfigInputCheck:
    """:func:`validate_config_chain` and :func:`config_load_error`, reading the file once.

    The file goes through :func:`validate_config_input` first and is not read
    when that refuses it. Otherwise it and its ``extends`` chain are read and
    validated as the scan reads them (``resolve_config.load_config_file``), under
    :func:`config_base_gate` and against the confinement root a scan of
    ``source_dir`` would use. A base outside the grant is a ``refusal``; a file or
    chain that does not load, or does not validate, is a ``load_error``. Each
    check used to parse the file on its own, on the event loop every session
    shares. The chain read is kept as ``document`` when it was read, whether or
    not it validated, so the denied-fields check can run on it first.
    """

    from automated_security_helper.config.config_sources import (
        default_confinement_root,
        env_refused_for,
        is_config_parse_error,
        unparsed_config_reason,
    )
    from automated_security_helper.config.resolve_config import (
        CLIENT_FILE,
        REPOSITORY_FILE,
        _has_a_client_file,
        read_config_document,
        validate_config_document,
    )
    from automated_security_helper.config.sandbox_grants import repository_written
    from automated_security_helper.core.exceptions import (
        ASHConfigEnvNotResolvedError,
        ASHConfigInputNotPermittedError,
        ASHConfigValidationError,
    )

    refusal = validate_config_input(config_path, session_id=session_id)
    if refusal is not None:
        return ConfigInputCheck(refusal=refusal)
    path = Path(config_path)
    # Its values go back to the client, so only an operator's file has them
    # repeated: not a file the client named outside the config roots or
    # delivered, nor one in a checkout or the scanned directory (by path, before
    # the read; by the whole chain, before the validation).
    # A link that leads back to itself is told by its errno before any path is
    # resolved: Path.resolve raises RuntimeError for one on Python 3.12 and older.
    try:
        os.stat(path)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return ConfigInputCheck(
                load_error=_config_load_error(
                    config_path, "it is a symbolic link that leads back to itself"
                )
            )
    scan_root = Path(source_dir) if source_dir is not None else path.parent
    named_by_client = client_named_config_is_untrusted(path, session_id=session_id)
    document = None
    try:
        # Read as the scan reads it, so a file that may not use !ENV is refused
        # for that before an `extends` whose value !ENV would choose is followed:
        # the refusal must not depend on the server's environment.
        document = read_config_document(
            path,
            confine_to=default_confinement_root(
                path, Path(source_dir) if source_dir is not None else None
            ),
            permit_base=config_base_gate(session_id),
            refuse_env=env_refused_for(caller_is_remote(session_id), session_id),
            unquoted=named_by_client
            or bool(repository_written([path], scan_root, [path])),
        )
        if named_by_client or _has_a_client_file(document):
            unquoted: Optional[str] = CLIENT_FILE
        elif repository_written(document.chain, scan_root, document.named):
            unquoted = REPOSITORY_FILE
        else:
            unquoted = None
        validate_config_document(document, path, unquoted=unquoted)
    except ASHConfigInputNotPermittedError as exc:
        return ConfigInputCheck(refusal=config_chain_refusal(config_path, exc))
    except ASHConfigEnvNotResolvedError as exc:
        # Before the arm below, which would catch it: it is an
        # ASHConfigSourceError. Reported as config_env_not_resolved, not as a
        # file that does not load.
        return ConfigInputCheck(env_error=exc)
    except ASHConfigValidationError as exc:
        return ConfigInputCheck(
            load_error=_config_load_error(config_path, exc), document=document
        )
    except Exception as exc:
        # A parser's message can quote the file's text (an undefined alias, an
        # unknown tag), so a file that does not parse is reported through the
        # formatted reason, never the parser's words. Anything that is not a
        # parse refusal propagates.
        if not is_config_parse_error(exc):
            raise
        return ConfigInputCheck(
            load_error=_config_load_error(
                config_path, unparsed_config_reason(path, exc)
            ),
            document=document,
        )
    except BaseException as exc:
        # As resolve_config refuses it: pydantic-core reports a Rust panic as
        # pyo3's PanicException, a BaseException, which would otherwise reach
        # the event loop every session shares. Anything else propagates.
        if (
            type(exc).__name__ != "PanicException"
            or type(exc).__module__ != "pyo3_runtime"
        ):
            raise
        return ConfigInputCheck(
            load_error=_config_load_error(
                config_path,
                f"The configuration could not be resolved: {type(exc).__name__}: {exc}",
            ),
            document=document,
        )
    return ConfigInputCheck(document=document)


def _config_load_error(config_path: object, reason: object) -> MCPResourceError:
    """The error for a config file at ``config_path`` that does not load."""

    return MCPResourceError(
        f"Configuration file {config_path} cannot be loaded: {reason}",
        context={
            "config_path": str(config_path),
            "error_category": ErrorCategory.INVALID_FORMAT.value,
        },
    )


def validate_discovered_config(
    source_dir: str | Path,
    session_id: Optional[str] = None,
) -> Optional[MCPResourceError]:
    """Check the config a scan of ``source_dir`` discovers, as a named one is checked.

    A scan given no config file uses the one it finds in its target
    (``config_sources.discover_config_source``), and that file can be a link out
    of the permitted roots. Only its ``extends`` bases were checked, so for a
    remote caller the outside file was read: one that parsed configured the scan,
    and one that did not failed the scan on the outside file.

    Every name discovery looks at that is there is checked before discovery runs
    (``config_sources.discovery_candidates``): ``pyproject.toml``, which
    discovery reads to learn whether it configures ASH, and a link to a missing
    target, which discovery skips, so that it is refused as a link to a present
    file is and the answer does not say whether the target exists. The file
    discovery selects then goes through :func:`validate_config_chain`. A
    discovery that fails is left to the scan, which reports it as it always has.

    Args:
        source_dir: The scan target, already checked against the scan roots.
        session_id: The session this call acts for.

    Returns:
        None if permitted, otherwise an :class:`MCPResourceError`.
    """

    from automated_security_helper.config.config_sources import (
        discover_config_source,
        discovery_candidates,
    )

    source_dir = Path(source_dir)
    # Every name discovery looks at that is there, a link to a missing target
    # included, and the pyproject.toml discovery reads among them: refused the
    # same whether or not the target exists.
    for candidate in discovery_candidates(source_dir):
        refusal = validate_config_input(candidate, session_id=session_id)
        if refusal is not None:
            return refusal
    try:
        selected = discover_config_source(source_dir).selected
    except Exception as exc:  # noqa: BLE001 -- reported by the scan's own read
        # The type alone: a parser's message can quote the file's text, and
        # discovery has no one file to name here.
        _logger.debug(
            "MCP sandbox: config discovery not done here (%s)", type(exc).__name__
        )
        return None
    if selected is None:
        return None
    return validate_config_chain(
        selected.path, session_id=session_id, source_dir=source_dir
    )


def config_chain_refusal(config_path: object, exc: Exception) -> MCPResourceError:
    """The refusal for a config whose ``extends`` chain leaves the permitted roots.

    Carries the chain error's text, which names the ``extends`` entry as written
    and never what it resolved to.
    """

    return MCPResourceError(
        f"Config input is outside the permitted roots: {exc} Set "
        f"{ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV} to the directories the MCP server may "
        f"read config from, or keep every base inside a directory already granted.",
        context={
            "directory_path": str(config_path),
            "error_category": ErrorCategory.INVALID_PATH.value,
        },
    )


def config_load_error(
    config_path: str | Path,
    session_id: Optional[str] = None,
    source_dir: Optional[str | Path] = None,
) -> Optional[MCPResourceError]:
    """Why a scan could not load the config file at ``config_path``, or None.

    The file and its ``extends`` chain are read as the scan reads them
    (``resolve_config.read_config_document``), against the confinement root
    :func:`validate_config_chain` uses. A file that cannot be read or parsed, and
    a chain that does not resolve, are reported here, before a scan is
    registered: the scan's own resolution refuses them, so starting one would only
    turn a configuration error into a failed scan. Call it after
    :func:`validate_config_chain`, which reports a file or a base outside the
    session's grant as a refusal; that case is not reported again here, and a file
    the session may not read is not read here either, so its contents cannot
    shape this answer.

    Args:
        config_path: Caller-supplied path to a config file.
        session_id: The session this call acts for.
        source_dir: The scan target the config will be resolved against, if any.

    Returns:
        None if the config loads and validates, otherwise an
        :class:`MCPResourceError`.
    """

    return check_config_input(config_path, session_id, source_dir).load_error


# ---------------------------------------------------------------------------
# The legacy net, for a local transport with no grant
# ---------------------------------------------------------------------------


def _is_filesystem_root(path: Path) -> bool:
    """Return True if ``path`` is the top of a filesystem.

    Only a filesystem root is its own parent, which makes this true for ``/`` on
    POSIX and for a bare drive or UNC share root on Windows without having to
    enumerate drive letters. It has to be an equality case rather than a
    containment one: every path is beneath ``/``, so folding the root into a
    containment list would refuse the entire filesystem.
    """

    return path.parent == path


def _legacy_denylist_refusal(
    path: object,
    resolved: Path,
    what: str = "Scan target",
) -> Optional[MCPResourceError]:
    """Apply the pre-sandbox default: refuse a few system directories, allow the rest.

    Kept verbatim in behavior, and deliberately not widened. "/var" would refuse
    the documented container workspace root (/var/cache/ash-mcp), "/usr" would
    refuse tool installs, and "/home" would refuse the common case. A grant is
    the mechanism for narrowing beyond this; on a network transport the sandbox
    is, and this function is not reached there. An ancestor of the workspace
    root is refused earlier, by ``_sibling_refusal``, whether or not the root is
    on disk yet.
    """

    from automated_security_helper.cli.mcp.scan_target import _denied_roots

    remedy = (
        f"Set {ASH_MCP_ALLOWED_ROOTS_ENV} to the directories the MCP server may scan."
    )
    if _is_filesystem_root(resolved):
        return _refusal(
            what,
            path,
            resolved,
            (
                "Pass the directory to scan explicitly; the default is the "
                "server's working directory, which here is the filesystem root. "
                f"{remedy}"
            ),
        )
    for denied in _denied_roots():
        if resolved == denied or resolved.is_relative_to(denied):
            return _refusal(what, path, resolved, remedy)
    return None


__all__ = [
    "ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV",
    "ASH_MCP_ALLOWED_ROOTS_ENV",
    "ASH_MCP_WORKSPACE_ROOT_ENV",
    "ASH_MCP_TRANSPORT_ENV",
    "DEFAULT_TRANSPORT",
    "CLIENT_CONFIG_DIR_NAME",
    "CONFIG_DIR_NAME",
    "SOURCE_DIR_NAME",
    "ConfigInputCheck",
    "SessionSandbox",
    "check_config_input",
    "config_base_gate",
    "config_chain_refusal",
    "client_named_config_is_untrusted",
    "config_is_client_supplied",
    "config_load_error",
    "get_server_transport",
    "KNOWN_TRANSPORTS",
    "unknown_transport_override",
    "operator_config_roots",
    "operator_scan_roots",
    "session_sandbox",
    "set_server_transport",
    "shared_workspace_root",
    "transport_is_networked",
    "validate_config_chain",
    "validate_config_input",
    "validate_scan_target_in_sandbox",
]
