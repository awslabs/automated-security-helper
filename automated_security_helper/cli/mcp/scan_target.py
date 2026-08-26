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
directories or something beneath it, and everything else is refused. The
per-session MCP workspace root is always allowed alongside it, because
``set_source_git`` and ``set_source_zip_finalize`` clone or extract into that
workspace and hand the caller the resulting path to scan -- an allowlist naming
only the operator's own repositories would otherwise refuse every uploaded
tree.

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
"""

from __future__ import annotations

import os
import platform
from pathlib import Path
from typing import List, Optional

from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
)
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)

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
    return MCPResourceError(
        f"Scan target is outside the permitted roots: {directory_path}. "
        f"Set {ASH_MCP_ALLOWED_ROOTS_ENV} to the directories the MCP server "
        f"may scan.",
        context={
            "cwd": str(Path.cwd()),
            "directory_path": str(directory_path),
            "resolved_path": str(resolved),
            "error_category": ErrorCategory.INVALID_PATH.value,
        },
    )


def validate_scan_target(
    directory_path: str | Path,
) -> Optional[MCPResourceError]:
    """Check a scan target against the configured roots.

    Args:
        directory_path: Caller-supplied scan target, absolute or relative.

    Returns:
        None if the target is permitted, otherwise an
        :class:`MCPResourceError` describing the refusal.

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
        from automated_security_helper.cli.mcp.source_delivery import (
            resolve_workspace_root,
        )

        roots = list(allowed)
        try:
            roots.append(resolve_workspace_root().expanduser().resolve())
        except (OSError, RuntimeError):
            # A workspace root that cannot be resolved (no home directory, for
            # instance) must not take the configured roots down with it.
            pass

        if any(resolved == root or resolved.is_relative_to(root) for root in roots):
            return None
        return _refusal(directory_path, resolved)

    if _is_filesystem_root(resolved):
        return _refusal(directory_path, resolved)

    for denied in _denied_roots():
        if resolved == denied or resolved.is_relative_to(denied):
            return _refusal(directory_path, resolved)

    return None
