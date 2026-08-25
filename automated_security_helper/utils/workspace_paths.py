# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Move glob patterns between the project path space and the workspace space.

Why this module exists
----------------------
In workspace mode a scan has two coordinate systems. Each project's own config
writes patterns against that project's root (``src/x.py``), while aggregated
output, workspace-level policy and per-project attribution all live in
workspace-relative coordinates (``project-a/src/x.py``). Every place that
crosses between the two has to prefix or unprefix a pattern, and doing it with
string concatenation produces ``project-a//src/x.py`` the first time someone
writes a project-rooted pattern. Both directions live here, both go through
``PurePosixPath``, and neither concatenates.

Patterns are a POSIX-shaped namespace, not filesystem paths
-----------------------------------------------------------
ASH compares patterns against SARIF URIs and suppression paths, which are
always forward-slash separated regardless of host OS. So this module works in
``PurePosixPath`` throughout and normalises backslashes on input. That is what
makes the behaviour identical on Windows: the pattern space does not change
shape underfoot. ``PurePosixPath`` also leaves glob metacharacters alone --
``*``, ``**`` and ``[0-9]`` are ordinary components to it -- so joining cannot
corrupt a pattern.

Up-conversion: project-relative to workspace-relative
-----------------------------------------------------
* relative (``src/x.py``, ``tests/**/*.py``) -- prefixed with the project path.
* project-rooted (``/src/x.py``) -- the leading separator is stripped BEFORE
  the join. This ordering is load-bearing, and not for cosmetic reasons:
  ``PurePosixPath("project-a") / "/src/x.py"`` silently DISCARDS the prefix and
  evaluates to ``/src/x.py``. Getting it wrong does not produce a doubled
  separator, it produces a pattern that has escaped the project entirely.
* ``**``-anchored (``**/test_*.py``) -- prefixed, with ``**`` intact.
* containing ``..`` -- rejected.
* drive- or UNC-anchored (``C:/Windows``, ``//server/share``) -- rejected.

The one case the table above cannot decide
------------------------------------------
``/src/x.py`` (project-rooted, must be prefixed) and ``/etc/passwd``
(a filesystem path, nominally rejected) are textually identical in shape on
POSIX. No pure function can tell them apart, and resolving against the
filesystem is not an option: patterns routinely name files that do not exist,
and a pattern's meaning must not depend on the state of the disk.

So a leading separator is always read as project-rooted. ``/etc/passwd``
up-converts to ``project-a/etc/passwd`` rather than being rejected. The
security property the rejection was protecting -- a project cannot reach
outside itself -- is preserved by a stronger mechanism than rejection: after
prefixing, no up-converted pattern can address anything outside its project, so
escape is structurally impossible rather than merely refused. Drive and UNC
anchors are still rejected, because those are unambiguous and prefixing them
would yield nonsense like ``project-a/C:/Windows``.

One consequence of keeping the UNC rejection is worth knowing before someone
files it as a bug: a DOUBLED leading separator is rejected too.
``PureWindowsPath("//src/x.py").drive`` is ``\\\\src\\x.py``, so the Windows
flavour cannot tell ``//src/x.py`` -- most likely a project-rooted pattern with
a stray extra slash -- from a real ``//server/share``. Rejecting it with an
error the operator can act on beats silently choosing one reading. A single
leading separator is unaffected and is prefixed as described above.

Down-conversion: workspace-relative to project-relative
-------------------------------------------------------
Used to push a workspace-level policy into one project. Returns ``None`` when
the pattern cannot possibly match inside that project, so a caller only hands a
project the patterns that apply to it.

A pattern whose first component holds a glob metacharacter is not anchored to
any single project and is returned unchanged. That is deliberately conservative:
``*/src/x.py`` might match this project, so passing it through over-includes
rather than silently dropping a policy the operator wrote. Failure modes of a
too-broad suppression are visible; failure modes of a silently discarded one
are not.

Failure modes and known limitations
-----------------------------------
* Down-conversion compares the prefix case-insensitively, matching how
  ``file_path_matches`` and ``_path_pattern_matches`` compare paths elsewhere in
  ASH. On a case-sensitive filesystem two projects differing only in case would
  therefore both match; ASH has no such case elsewhere, and diverging from the
  rest of the codebase's comparison rule would be worse.
* A pattern like ``project-*/src`` is returned unchanged by down-conversion even
  though the wildcard spans the prefix, so the receiving project sees a pattern
  still carrying a project-level component. Over-inclusion, per above.
* Up-conversion is purely textual. It does not check that the project prefix
  exists; that is :mod:`automated_security_helper.utils.path_containment`'s job.
"""

from __future__ import annotations

from pathlib import PurePosixPath, PureWindowsPath
from typing import Optional, Union

from automated_security_helper.core.exceptions import WorkspacePatternError

PathLike = Union[str, PurePosixPath]

_PARENT = ".."

# A pattern component containing any of these is a glob, not a literal name.
_GLOB_METACHARACTERS = frozenset("*?[]")

# What a down-converted pattern becomes when it names exactly the project root.
_WHOLE_PROJECT = "**"


def _normalise(value: PathLike, *, label: str) -> PurePosixPath:
    """Normalise separators and validate, returning a PurePosixPath.

    Rejects the empty value, any ``..`` component, and any drive or UNC anchor.
    Backslashes become forward slashes first, so a Windows-style pattern is
    validated on POSIX rather than being read as one long filename.
    """
    raw = str(value)
    if not raw.strip():
        raise WorkspacePatternError(f"{label} must not be empty")

    # Detect a drive or UNC anchor before normalising, using the Windows
    # flavour: PurePosixPath has no concept of a drive, so it would read
    # "C:/Windows" as an ordinary relative pattern with a component named "C:".
    windows_view = PureWindowsPath(raw)
    if windows_view.drive:
        raise WorkspacePatternError(
            f"{label} '{raw}' is an absolute filesystem path "
            f"(drive or UNC anchor '{windows_view.drive}'); "
            "patterns must be relative to a project or workspace root"
        )

    normalised = PurePosixPath(raw.replace("\\", "/"))
    if _PARENT in normalised.parts:
        raise WorkspacePatternError(
            f"{label} '{raw}' contains a '..' component; "
            "patterns must not traverse upward out of their root"
        )
    return normalised


def _relative_parts(path: PurePosixPath) -> tuple:
    """Return path components with any root anchor dropped.

    This is where a project-rooted pattern loses its leading separator, and it
    happens before any join for the reason in the module docstring: joining a
    root-anchored pattern onto a prefix discards the prefix.
    """
    parts = path.parts
    if parts and parts[0] in ("/", "//"):
        return parts[1:]
    return parts


def _is_glob_component(component: str) -> bool:
    return any(char in _GLOB_METACHARACTERS for char in component)


def to_workspace_pattern(pattern: PathLike, project_prefix: PathLike) -> str:
    """Rebase a project-relative *pattern* onto the workspace root.

    Args:
        pattern: A pattern written against the project root. May be relative,
            project-rooted (a leading separator), or ``**``-anchored.
        project_prefix: The project's workspace-relative path, e.g.
            ``project-a`` or ``apps/web``.

    Returns:
        The workspace-relative pattern, forward-slash separated.

    Raises:
        WorkspacePatternError: If either argument is empty, contains a ``..``
            component, or is anchored to a drive or UNC share.
    """
    prefix_parts = _relative_parts(_normalise(project_prefix, label="project prefix"))
    if not prefix_parts:
        raise WorkspacePatternError("project prefix must name at least one component")

    pattern_parts = _relative_parts(_normalise(pattern, label="pattern"))
    if not pattern_parts:
        raise WorkspacePatternError("pattern must name at least one component")

    return PurePosixPath(*prefix_parts, *pattern_parts).as_posix()


def to_project_pattern(pattern: PathLike, project_prefix: PathLike) -> Optional[str]:
    """Rebase a workspace-relative *pattern* onto one project's root.

    The inverse of :func:`to_workspace_pattern`, for pushing a workspace-level
    policy down into a single project.

    Args:
        pattern: A workspace-relative pattern.
        project_prefix: The project's workspace-relative path.

    Returns:
        The project-relative pattern, or ``None`` when the pattern cannot match
        inside this project. A pattern naming exactly the project root becomes
        ``**``, the whole project. A pattern whose first component is a glob is
        returned unchanged, since it is not anchored to any one project.

    Raises:
        WorkspacePatternError: On the same malformed inputs as
            :func:`to_workspace_pattern`.
    """
    prefix_parts = _relative_parts(_normalise(project_prefix, label="project prefix"))
    if not prefix_parts:
        raise WorkspacePatternError("project prefix must name at least one component")

    pattern_parts = _relative_parts(_normalise(pattern, label="pattern"))
    if not pattern_parts:
        raise WorkspacePatternError("pattern must name at least one component")

    # An unanchored pattern may match inside any project, so it passes through
    # untouched rather than being tested against this prefix.
    if _is_glob_component(pattern_parts[0]):
        return PurePosixPath(*pattern_parts).as_posix()

    if len(pattern_parts) < len(prefix_parts):
        return None

    # Component-wise comparison, case-insensitive to match how the rest of ASH
    # compares paths. A string prefix test would wrongly accept "project-abc"
    # as being inside "project-a".
    head = pattern_parts[: len(prefix_parts)]
    if [part.lower() for part in head] != [part.lower() for part in prefix_parts]:
        return None

    remainder = pattern_parts[len(prefix_parts) :]
    if not remainder:
        return _WHOLE_PROJECT
    return PurePosixPath(*remainder).as_posix()
