#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Root policy for MCP scan targets.

An MCP client names the directory it wants scanned, and ASH then writes an
output tree inside that directory (``<target>/.ash/ash_output``). Accepting a
target is therefore also a decision to write into it, so the server needs a way
for the operator to say which parts of its filesystem are in play.

``ASH_MCP_ALLOWED_ROOTS`` is that control. It holds an ``os.pathsep``-separated
list of directories; when it is set, a scan target must resolve to one of those
directories or something beneath it, and everything else is refused.

A caller that supplies a ``session_id`` additionally gets its own session
workspace, ``<workspace_root>/<session_id>``, because ``set_source_git`` and
``set_source_zip_finalize`` clone or extract into that workspace and hand the
caller the resulting path to scan -- an allowlist naming only the operator's own
repositories would otherwise refuse every uploaded tree. Only that one session's
directory is allowed, never the shared workspace root: the root holds every
other session's uploaded source, and ``_session_workspace`` exists in
``source_delivery`` precisely to stop one session reaching a sibling's. A caller
with no ``session_id`` gets no workspace allowance at all.

When ``ASH_MCP_ALLOWED_ROOTS`` is unset, a short fixed list of system
directories is refused instead. That default is a safety net, not a security
boundary, and the distinction matters: it declines the handful of directories
that hold host configuration and kernel interfaces rather than source code, and
it says nothing whatever about the rest of the filesystem. Home directories,
``/usr``, ``/var`` and everything else stay accepted, because that is where
code lives. An operator who wants the scan surface actually bounded has to set
``ASH_MCP_ALLOWED_ROOTS``; nothing else here does that job.

Setting the variable replaces the default list rather than adding to it, which
is also how a deliberate scan of a system directory is arranged: name it as a
root and it is allowed.

This policy is separate from :func:`validate_directory_path`, which checks that
a path exists and is a directory. That function is shared with output-directory
validation, including the per-poll validation on the progress path, so a root
rule does not belong inside it. The two run in sequence at the MCP entry
points: policy first, on the unresolved caller input, then existence.

THE TARGET IS CANONICALIZED; ITS CHILDREN ARE NOT
-------------------------------------------------
:func:`resolve_scan_target` resolves exactly one path, the target, which is what
makes a link inside a permitted root unable to smuggle the target elsewhere. It
says nothing about the target's children, and both consumers go on to create
``<target>/.ash/ash_output`` -- one of them deleting a file inside it. A
permitted target whose ``.ash`` child is a symlink therefore used to send that
mkdir, and that delete, wherever the link pointed. :func:`validate_output_tree`
is the check for that, and it is a separate call because it asks a different
question: not "may this target be scanned" but "is the tree I am about to create
really inside it". It refuses a symlinked component outright, the same call the
zip member handling in ``source_delivery`` makes for symlink entries.
"""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
)
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.path_containment import (
    validate_contained_path,
)

_logger = ASH_LOGGER

ASH_MCP_ALLOWED_ROOTS_ENV = "ASH_MCP_ALLOWED_ROOTS"

# Directories refused when no allowlist is configured. A target is refused if it
# is one of these or lives beneath one. Kept deliberately short: it covers host
# configuration and kernel interfaces only.
#
# Widening it is not free. "/var" would refuse the documented container
# workspace root (/var/cache/ash-mcp), "/usr" would refuse tool installs, and
# "/home" would refuse the common case, so none of them belong here. The
# allowlist is the mechanism for narrowing beyond this.
_POSIX_DENIED_ROOTS = (
    "/boot",
    "/dev",
    "/etc",
    "/proc",
    "/root",
    "/sys",
)

# Windows equivalents, read from the shell's own directory variables so the
# policy follows a system installed on a drive other than C:.
_WINDOWS_DENIED_ROOT_ENV_VARS = (
    ("SystemRoot", r"C:\Windows"),
    ("ProgramFiles", r"C:\Program Files"),
    ("ProgramFiles(x86)", None),
    # Under 32-bit Python on 64-bit Windows, WOW64 rewrites ProgramFiles to the
    # x86 directory, so the 64-bit one is only reachable through ProgramW6432.
    # Without this entry a 32-bit interpreter would leave C:\Program Files
    # unrefused.
    ("ProgramW6432", None),
    ("ProgramData", r"C:\ProgramData"),
)


def _is_filesystem_root(path: Path) -> bool:
    """Return True if ``path`` is the top of a filesystem.

    Only a filesystem root is its own parent, which makes this true for ``/``
    on POSIX and for a bare drive or UNC share root on Windows without having
    to enumerate drive letters.

    The filesystem root has to be treated as an equality case rather than a
    containment one. Every path is beneath ``/``, so folding the root into the
    containment list below would refuse the entire filesystem.
    """

    return path.parent == path


def _denied_root_values() -> List[str]:
    """Return the raw directory names refused when no allowlist is configured.

    Split out from :func:`_denied_roots` so that "which directories does the
    policy name" and "how are they compared to a target" stay separable, on this
    platform and in tests.
    """

    if platform.system() == "Windows":
        values = []
        for var, fallback in _WINDOWS_DENIED_ROOT_ENV_VARS:
            value = os.environ.get(var) or fallback
            if value:
                values.append(value)
        return values

    return list(_POSIX_DENIED_ROOTS)


def _denied_roots() -> List[Path]:
    """Return the directories refused when no allowlist is configured.

    A target is refused if it equals one of these or resolves beneath one. The
    filesystem root is handled separately by :func:`_is_filesystem_root`.

    The roots are resolved, because the target they are compared against is
    resolved too and a root that is itself a symlink would otherwise never
    match. macOS is the case that matters: /etc, /tmp and /var are symlinks into
    /private, so an unresolved "/etc" would be compared against a target that
    resolved to "/private/etc" and the directory the entry names would not
    actually be refused. Resolving a root that does not exist on this platform
    -- /proc on macOS, say -- leaves it unchanged, which is harmless.
    """

    roots = []
    for value in _denied_root_values():
        try:
            roots.append(Path(value).resolve())
        except OSError:
            roots.append(Path(value))
    return roots


def _allowed_roots() -> List[Path]:
    """Parse ``ASH_MCP_ALLOWED_ROOTS`` into resolved directories.

    An empty list means the variable is unset or held nothing usable, which
    selects the default refusal set rather than allowing everything.
    """

    raw = os.environ.get(ASH_MCP_ALLOWED_ROOTS_ENV)
    if not raw:
        return []

    roots: List[Path] = []
    # os.pathsep, not a literal ":". On Windows the separator is ";" and a colon
    # appears inside ordinary paths, so splitting on ":" would cut "C:\src" in
    # half and yield a root of "C".
    for entry in raw.split(os.pathsep):
        entry = entry.strip()
        if not entry:
            # A trailing or doubled separator produces an empty entry, and
            # "".split(os.pathsep) is [""] rather than []. Path("").resolve() is
            # the process working directory, so resolving an empty entry would
            # quietly allow the cwd and everything under it.
            continue
        roots.append(Path(entry).expanduser().resolve())
    return roots


def _refusal(directory_path: object, resolved: Path) -> MCPResourceError:
    remedy = (
        f"Set {ASH_MCP_ALLOWED_ROOTS_ENV} to the directories the MCP server may scan."
    )
    if _is_filesystem_root(resolved):
        # Reached most often by omitting the directory entirely: the tool falls
        # back to the process working directory, and a server launched by an
        # editor or agent frequently has "/" for a cwd. Telling that caller to
        # configure an allowlist points at the wrong lever.
        remedy = (
            "Pass the directory to scan explicitly; the default is the server's "
            f"working directory, which here is the filesystem root. {remedy}"
        )
    return MCPResourceError(
        f"Scan target is outside the permitted roots: {directory_path}. {remedy}",
        context={
            "cwd": str(Path.cwd()),
            "directory_path": str(directory_path),
            "resolved_path": str(resolved),
            "error_category": ErrorCategory.INVALID_PATH.value,
        },
    )


def _session_workspace_root(session_id: str) -> Optional[Path]:
    """Return this session's own workspace directory, or None if unavailable.

    Scoped to the single session rather than to the shared workspace root, which
    holds every other session's uploaded source.
    """

    from automated_security_helper.cli.mcp.source_delivery import (
        _session_workspace,
        resolve_workspace_root,
    )

    try:
        root = resolve_workspace_root().expanduser().resolve()
        return _session_workspace(root, session_id)
    except (OSError, RuntimeError, ValueError) as exc:
        # A workspace root that cannot be resolved (no home directory) or a
        # session id carrying path separators must not take the configured roots
        # down with it -- the allowlist still applies, this session just gets no
        # extra allowance. ValueError is _session_workspace rejecting the id.
        _logger.debug(
            "MCP scan-target policy: no workspace allowance for session %r (%s)",
            session_id,
            exc,
        )
        return None


@dataclass(frozen=True)
class ScanTargetResolution:
    """The outcome of checking one scan target. Exactly one field is set.

    ``resolved`` exists so that a caller which goes on to build paths under the
    target builds them from what the policy actually authorised. Re-deriving it
    from the caller's text is how a symlinked ``.ash`` child escaped: the policy
    had already canonicalized the target, and the consumers threw that away.
    """

    resolved: Optional[Path] = None
    error: Optional[MCPResourceError] = None

    def require(self) -> Path:
        """Return the canonical target, for a caller that has checked ``error``.

        Exists so the permitted path is a ``Path`` rather than an
        ``Optional[Path]`` at every call site. The alternative -- each consumer
        narrowing the Optional itself -- invites exactly the re-derivation from
        the caller's unresolved text that this type was introduced to stop.

        Raises:
            ValueError: if neither field is set, which the two constructors here
                cannot produce.
        """

        if self.resolved is None:
            raise ValueError(
                "scan target resolution carries neither a path nor a refusal; "
                "check .error before calling .require()"
            )
        return self.resolved


def resolve_scan_target(
    directory_path: str | Path,
    session_id: Optional[str] = None,
) -> ScanTargetResolution:
    """Check a scan target against the configured roots and return what resolved.

    Args:
        directory_path: Caller-supplied scan target, absolute or relative.
        session_id: MCP session id, when the call is made on behalf of one.
            Permits that session's own workspace directory in addition to the
            configured roots, so a source tree delivered over the protocol
            stays scannable. Sibling sessions' workspaces are not permitted.

    Returns:
        A :class:`ScanTargetResolution` carrying the canonical target on success
        or the refusal on failure.

    The target is resolved here rather than by the caller. Symlinks and ``..``
    components have to be collapsed before containment is tested, or a link
    sitting inside a permitted root would pass on the strength of its own
    location while pointing somewhere else entirely.

    Existence is not checked. That belongs to
    :func:`validate_directory_path`, which runs after this, and keeping the two
    apart is what lets a refusal be reported as a refusal even when the target
    also happens not to exist.
    """

    resolved = Path(directory_path).resolve()

    allowed = _allowed_roots()
    if allowed:
        roots = list(allowed)
        if session_id:
            session_root = _session_workspace_root(session_id)
            if session_root is not None:
                roots.append(session_root)

        if any(resolved == root or resolved.is_relative_to(root) for root in roots):
            return ScanTargetResolution(resolved=resolved)
        return ScanTargetResolution(error=_refusal(directory_path, resolved))

    if _is_filesystem_root(resolved):
        return ScanTargetResolution(error=_refusal(directory_path, resolved))

    for denied in _denied_roots():
        if resolved == denied or resolved.is_relative_to(denied):
            return ScanTargetResolution(error=_refusal(directory_path, resolved))

    return ScanTargetResolution(resolved=resolved)


def validate_scan_target(
    directory_path: str | Path,
    session_id: Optional[str] = None,
) -> Optional[MCPResourceError]:
    """Check a scan target against the configured roots; return only the refusal.

    Retained for the callers that ask nothing but yes-or-no -- the two that read
    a caller-named output directory, and the workspace resolver, which needs a
    refusal per project and no path. A caller that goes on to build a path under
    the target should use :func:`resolve_scan_target` instead and build it from
    ``resolved``.

    Returns:
        None if the target is permitted, otherwise an
        :class:`MCPResourceError` describing the refusal.
    """

    return resolve_scan_target(directory_path, session_id).error


def validate_output_tree(
    resolved_target: Path,
    *relative_parts: str,
) -> Optional[MCPResourceError]:
    """Check that an output directory really sits inside the resolved target.

    Args:
        resolved_target: The canonical target, as returned by
            :func:`resolve_scan_target`. Passing the caller's unresolved text
            here would defeat the point, since containment would then be decided
            against a path that may itself be a link.
        relative_parts: The components of the output directory relative to the
            target, outermost first -- ``".ash", "ash_output"``.

    Returns:
        None if every component is a real, contained path, otherwise an
        :class:`MCPResourceError` naming the component that failed. The context
        carries the same ``error_category`` as a root refusal, so one key
        identifies a path refusal from any entry point.

    Each prefix is checked, not just the full path, and the distinction is
    load-bearing twice over. A symlinked ``.ash`` pointing *outside* the target
    fails containment whichever way it is checked; a symlinked ``.ash`` pointing
    to a sibling *inside* the target resolves to a contained path and only the
    per-component symlink check refuses it. Both end with a write landing
    somewhere the caller did not name.

    Nothing is created here. Validation has to precede ``mkdir(parents=True)``,
    which is the call that follows the link.
    """

    relative = Path(".")
    for part in relative_parts:
        relative = relative / part
        result = validate_contained_path(relative, resolved_target)
        if result.error is None:
            continue
        return MCPResourceError(
            f"Scan output directory is not inside the scan target: "
            f"{result.error.message}",
            context={
                "scan_target": str(resolved_target),
                "output_component": str(relative),
                "violation": result.error.violation.value,
                "error_category": ErrorCategory.INVALID_PATH.value,
            },
        )
    return None
