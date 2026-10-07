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
rather than from recorded server state. That function carries the reasoning; the
short version is that process-wide transport state outlives the server object and
made the answer depend on what ran earlier in the process.

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
* Isolation is only as strong as two callers' session ids differing. The id comes
  from a client-supplied header and is a namespace, never an identity assertion
  -- see ``session_identity.py``. On AgentCore that is the platform's job; on a
  self-hosted deployment it is the fronting proxy's. This module guarantees that
  an id names one directory and not a path, and that one id cannot reach
  another's, and nothing about who may claim an id.
* "Remote" is inferred from the session id, so a streamable-HTTP client that
  sends no ``Mcp-Session-Id`` at all is treated as local. The MCP spec has the
  server assign one at ``initialize`` and AgentCore injects one, so this is not
  the normal case; ``ASH_MCP_TRANSPORT=streamable-http`` closes it explicitly, and
  so does any ``ASH_MCP_ALLOWED_ROOTS`` grant.
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

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
)
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
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

#: Subdirectory of a session sandbox holding the delivered source tree. Matches
#: what ``source_delivery`` writes; the two must agree or a delivered tree is
#: refused by the boundary that exists to permit it.
SOURCE_DIR_NAME = "source"

#: Subdirectory of a session sandbox holding a config materialized for this
#: session -- currently a profile bound by ``select_profile``. Inside the sandbox
#: so one boundary covers the config and the source it configures.
CONFIG_DIR_NAME = "config"

#: Transports that carry callers the server does not otherwise trust.
_NETWORKED_TRANSPORTS = frozenset({"streamable-http", "sse"})

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
    """Return the transport this process serves, or the default if unset."""

    return os.environ.get(ASH_MCP_TRANSPORT_ENV) or DEFAULT_TRANSPORT


def transport_is_networked() -> bool:
    """True when ``ASH_MCP_TRANSPORT`` explicitly names a networked transport.

    An operator override, and the secondary signal. :func:`caller_is_remote` is
    the primary one, because it is request-scoped and this is not.
    """

    return get_server_transport() in _NETWORKED_TRANSPORTS


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

    The env var is kept as a second trigger, ORed in, for the gap this leaves: a
    streamable-HTTP client that sends no session header at all resolves to the
    sentinel and would otherwise get the local default. The MCP spec has the
    server assign an id at ``initialize`` and AgentCore injects one, so that
    combination is not the normal case -- but "not normal" is not "impossible", and
    an operator can close it explicitly.
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


def _validated_session_component(session_id: str) -> str:
    """Return ``session_id`` when it names one directory, else raise.

    Refused rather than sanitized, for the reason ``session_identity`` gives:
    sanitizing maps two distinct ids onto one directory and silently merges two
    callers' source trees. This is the second gate -- the transport edge already
    refuses these -- and it exists for a caller that reaches the sandbox
    directly.
    """

    if not session_id:
        raise ValueError("session_id must be a non-empty string")
    if "/" in session_id or "\\" in session_id or session_id in ("..", "."):
        raise ValueError(f"session_id contains path separators: {session_id!r}")
    return session_id


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

    def owns(self, resolved: Path) -> bool:
        """True when ``resolved`` is this session's own sandbox or inside it."""

        if self.root is None:
            return False
        return resolved == self.root or resolved.is_relative_to(self.root)

    def permits_scan(self, resolved: Path) -> bool:
        """True when ``resolved`` may be scanned and written into."""

        return any(
            resolved == root or resolved.is_relative_to(root)
            for root in self.scan_roots
        )

    def permits_config(self, resolved: Path) -> bool:
        """True when ``resolved`` may be read as a config input.

        A config input is a *file*, so its containing directory is what has to
        fall inside a root -- but the file path itself is tested, because
        ``is_relative_to`` on the file gives the same answer and testing the
        parent would accept a root that names the file's grandparent only by
        accident of how the caller spelled it.
        """

        return any(
            resolved == root or resolved.is_relative_to(root)
            for root in self.config_roots
        )


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

    root: Optional[Path] = None
    if session_id:
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
    """

    try:
        return session_sandbox(session_id)
    except ValueError as exc:
        _logger.debug("MCP sandbox: no session allowance for %r (%s)", session_id, exc)
        return session_sandbox(None)


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
        f"{what} is outside the permitted roots: {path}. {remedy}",
        context={
            "cwd": str(Path.cwd()),
            "directory_path": str(path),
            "resolved_path": str(resolved),
            "error_category": ErrorCategory.INVALID_PATH.value,
        },
    )


def _sibling_refusal(
    sandbox: SessionSandbox, path: object, resolved: Path
) -> Optional[MCPResourceError]:
    """Refuse a path inside the shared workspace root but not inside this sandbox.

    Checked before anything that could allow, and independent of both the
    operator grant and the transport. That independence is the point: the
    pre-change hole was that isolation only existed when a variable happened to
    be set, so a rule that can be switched off is not the fix.

    The message names neither the sibling's session id nor its path. Telling one
    tenant that another exists, and what it is called, is a disclosure the
    refusal does not need -- ``delivered_session_count`` exists for the one
    diagnostic that legitimately needs to know somebody else delivered
    something, and it returns a count for the same reason.
    """

    shared = shared_workspace_root()
    if shared is None:
        return None
    inside_shared = resolved == shared or resolved.is_relative_to(shared)
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


def validate_scan_target_in_sandbox(
    directory_path: str | Path,
    session_id: Optional[str] = None,
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

    Returns:
        None if permitted, otherwise an :class:`MCPResourceError`.
    """

    resolved = Path(directory_path).resolve()
    sandbox = _sandbox_for_gate(session_id)

    sibling = _sibling_refusal(sandbox, directory_path, resolved)
    if sibling is not None:
        return sibling

    if sandbox.permits_scan(resolved):
        return None

    if sandbox.fall_back_to_denylist:
        return _legacy_denylist_refusal(directory_path, resolved)

    remedy = (
        f"Set {ASH_MCP_ALLOWED_ROOTS_ENV} to the directories the MCP server may "
        f"scan, or deliver the tree with set_source_git or "
        f"set_source_zip_finalize so it lands in this session's sandbox."
    )
    if _is_filesystem_root(resolved):
        # Reached most often by omitting the directory entirely: the tool falls
        # back to the process working directory, and a server launched by an
        # editor or agent frequently has "/" for a cwd. Telling that caller to
        # configure an allowlist points at the wrong lever first.
        remedy = (
            "Pass the directory to scan explicitly; the default is the server's "
            f"working directory, which here is the filesystem root. {remedy}"
        )
    return _refusal("Scan target", directory_path, resolved, remedy)


def validate_config_input(
    config_path: str | Path,
    session_id: Optional[str] = None,
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

    Returns:
        None if permitted, otherwise an :class:`MCPResourceError`.
    """

    resolved = Path(config_path).resolve()
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

    def permit(path: Path) -> bool:
        return validate_config_input(path, session_id=session_id) is None

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
    malformed ``patch``) is left to the caller's own resolution, which reports it
    as it always has.

    Args:
        config_path: Caller-supplied path to a config file.
        session_id: The session this call acts for.
        source_dir: The scan target the config will be resolved against, if any.

    Returns:
        None if permitted, otherwise an :class:`MCPResourceError`.
    """

    refusal = validate_config_input(config_path, session_id=session_id)
    if refusal is not None:
        return refusal

    from automated_security_helper.config.config_sources import (
        default_confinement_root,
        resolve_config_document,
    )
    from automated_security_helper.core.exceptions import (
        ASHConfigInputNotPermittedError,
    )

    path = Path(config_path)
    if not path.is_file():
        return None
    try:
        resolve_config_document(
            path,
            confine_to=default_confinement_root(
                path, Path(source_dir) if source_dir is not None else None
            ),
            permit_base=config_base_gate(session_id),
        )
    except ASHConfigInputNotPermittedError as exc:
        return config_chain_refusal(config_path, exc)
    except Exception as exc:  # noqa: BLE001 -- reported by the caller's own read
        _logger.debug("MCP sandbox: config chain not resolved here (%s)", exc)
    return None


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
    is, and this function is not reached there.
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
    "ASH_MCP_TRANSPORT_ENV",
    "DEFAULT_TRANSPORT",
    "CONFIG_DIR_NAME",
    "SOURCE_DIR_NAME",
    "SessionSandbox",
    "config_base_gate",
    "config_chain_refusal",
    "get_server_transport",
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
