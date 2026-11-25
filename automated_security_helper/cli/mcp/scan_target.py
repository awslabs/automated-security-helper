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

Where the decision now lives
----------------------------
:func:`validate_scan_target` is the entry point every MCP tool calls, and it
still is -- but the decision moved to ``config/mcp_sandbox.py``, which resolves a
per-session :class:`~automated_security_helper.config.mcp_sandbox.SessionSandbox`
and asks that. This module keeps the name and the signature; the system-directory
denylist the sandbox falls back to on a local transport is the sandbox's own
(``_denied_roots`` and the helpers re-exported below).

The move fixed a hole this docstring used to describe as though it were closed.
The claim was that only one session's own directory is allowed and never the
shared workspace root -- true, but only inside the ``if allowed:`` branch. With
``ASH_MCP_ALLOWED_ROOTS`` unset, which is the default, that branch was skipped
and the denylist below was the only rule; it names six system directories and the
MCP workspace root is not one of them. So on a default deployment one session
could name another's delivered source tree and ASH would scan it. The sandbox
refuses a sibling independent of the grant and of the transport, which is the
only arrangement in which the claim above is actually true.

The sandbox also confines *config inputs* -- ``validate_config_input`` -- which
nothing here ever did. See that module's docstring for why an unconfined
caller-named config path is a file-read oracle rather than a lesser hole.

The fall-back default, unchanged
--------------------------------
When no grant applies and the transport is local, a short fixed list of system
directories is refused and everything else is accepted. That default is a safety
net, not a security boundary, and the distinction matters: it declines the
handful of directories that hold host configuration and kernel interfaces rather
than source code, and it says nothing whatever about the rest of the filesystem.
Home directories, ``/usr``, ``/var`` and everything else stay accepted, because
that is where code lives, except an ancestor of the session workspace root,
whether or not that root is on disk yet. An operator who wants the scan surface
actually bounded sets ``ASH_MCP_ALLOWED_ROOTS``; on a network transport the
sandbox bounds it without one.

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
    PathContainmentViolation,
    validate_contained_path,
)

_logger = ASH_LOGGER

ASH_MCP_ALLOWED_ROOTS_ENV = "ASH_MCP_ALLOWED_ROOTS"

#: The exit code a scan tool reports when :func:`validate_output_tree` refuses its
#: output tree: 3, ASH's code for an input it will not use. The same from the
#: single-directory tools and the workspace tools, because a link in the output
#: tree is the same refusal whichever meets it, and not a workspace definition or
#: policy error (4).
OUTPUT_TREE_REFUSED_EXIT_CODE = 3

# The directories refused when no allowlist is configured (the POSIX list, the
# Windows variables, and the functions that resolve them) are defined in
# ``config.mcp_sandbox``, beside the sandbox rules that apply them, and are
# imported here so this module's names stay what they were.
from automated_security_helper.config.mcp_sandbox import (  # noqa: E402
    _POSIX_DENIED_ROOTS as _POSIX_DENIED_ROOTS,
    _WINDOWS_DENIED_ROOT_ENV_VARS as _WINDOWS_DENIED_ROOT_ENV_VARS,
    _denied_root_values as _denied_root_values,
    _denied_roots as _denied_roots,
    _is_filesystem_root as _is_filesystem_root,
)


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
    """Check a scan target against this session's sandbox and return what resolved.

    Args:
        directory_path: Caller-supplied scan target, absolute or relative.
        session_id: MCP session id, when the call is made on behalf of one. The
            sandbox permits that session's own workspace directory and refuses
            sibling sessions' workspaces; see ``config/mcp_sandbox.py``.

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

    from automated_security_helper.config.mcp_sandbox import (
        validate_scan_target_in_sandbox,
    )

    # The permit/refuse decision is the sandbox's (#665); this function adds only
    # the canonical path, so a caller building paths under the target builds them
    # from what was authorised rather than from the caller's text. The path
    # returned is the one the sandbox judged, taken from the sandbox itself: a
    # second Path.resolve() of the caller's text here could lead elsewhere than
    # the first by the time it ran (a link re-pointed between the two), and the
    # scan would then write under a target no gate permitted.
    judged: List[Path] = []
    error = validate_scan_target_in_sandbox(
        directory_path, session_id=session_id, resolved_out=judged
    )
    if error is not None:
        return ScanTargetResolution(error=error)
    return ScanTargetResolution(resolved=judged[0])


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
        if "/" in part or "\\" in part:
            # Each part is one component. The containment check reads a
            # backslash as a separator on every platform, so a part holding
            # one was checked as a nested path while the directory later made
            # from it on POSIX is one flat name holding the backslash: the
            # path checked was not the path created.
            return MCPResourceError(
                "Scan output directory is not inside the scan target: "
                f"component {part!r} contains a path separator",
                context={
                    "scan_target": str(resolved_target),
                    "output_component": str(relative / part),
                    "violation": PathContainmentViolation.PARENT_TRAVERSAL.value,
                    "error_category": ErrorCategory.INVALID_PATH.value,
                },
            )
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
