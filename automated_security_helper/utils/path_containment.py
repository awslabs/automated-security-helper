# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Validate that a candidate directory really sits inside a root directory.

Why this module exists
----------------------
Wherever ASH accepts a directory from somewhere other than its own argv -- a
workspace definition file, a config file, an MCP request -- it needs to prove
that directory is inside the tree the operator authorised before scanning it.
Getting that check right is fiddly enough, and wrong often enough, that it
belongs in one place with one set of tests rather than being re-derived per
call site.

The checks, and why each one is separate
----------------------------------------
1. ``..`` anywhere in the input is rejected on the raw text, before any
   resolution. This is deliberately stricter than "does it resolve to somewhere
   inside": ``project-a/../project-b`` lands inside the root and is still
   rejected, because a definition that walks out of one project and into
   another is not expressing containment whatever it happens to resolve to.
   Checking the text also means the rejection does not depend on what exists on
   disk at the moment of the call.
2. Both sides are canonicalised with ``Path.resolve()``, which follows
   symlinks, so a link in an intermediate component cannot smuggle the target
   outside the root.
3. The candidate itself must not be a symlink. This cannot be folded into the
   containment check: a symlink pointing at a sibling *inside* the root
   resolves to a contained path and would otherwise be accepted, so the
   containment check alone would not reject it.

   Note what this does NOT do. Only the final component is tested, via
   ``joined.is_symlink()``. With ``aliasdir`` linked to ``api``, the candidate
   ``aliasdir/sub`` is ACCEPTED and resolves to the same real path as
   ``api/sub`` -- so this check does not stop a workspace definition from
   scanning one tree twice under two names. That is deliberate: the RFC
   requires only that the entry itself be rejected. Aliasing is a different
   property and is caught separately, by overlap detection comparing the
   canonicalised real paths of all accepted projects against each other. The
   ``resolved`` field returned here is exactly the input that check needs.
4. Containment is decided by ``Path.is_relative_to``, which compares path
   components. The root itself is accepted -- "at-or-below" includes "at".
5. Existence and directory-ness are checked only when ``must_exist=True``.
   Containment is a question about the path; whether it exists is a separate
   question that only some callers care about, and a caller validating a path
   before creating it needs the default.

Absolute candidates need no special case. ``root / candidate`` discards the
root when the candidate is absolute, so an absolute path is resolved on its own
and then has to pass the same containment check as everything else -- allowed
only if it canonicalises to at-or-below the root.

Cross-platform notes -- this project has been bitten here repeatedly
-------------------------------------------------------------------
* Containment is never decided by comparing ``str(Path)`` values or by
  slash-joined string prefixes. ``str(Path)`` uses backslashes on Windows, and
  a prefix comparison accepts ``/ws-evil`` as being inside ``/ws``. There is a
  test for that sibling-prefix case.
* Nothing branches on ``Path("/x").is_absolute()``. That is ``False`` on
  Windows, because a Windows absolute path needs a drive. The join-then-resolve
  approach above needs no such branch. A root-anchored ``/src/x`` on Windows
  joins onto the root's drive as ``C:\\src\\x``, which fails containment for the
  same reason it does on POSIX.
* The ``..`` scan tokenises through ``PurePosixPath`` after normalising
  backslashes, so a Windows-style ``project-a\\..\\b`` is caught on POSIX too,
  where ``Path`` would otherwise read the whole string as one filename. It
  matches whole components only, so a legitimate name like ``a..b`` is not a
  false positive.

Failure modes and known limitations
-----------------------------------
* Validation is a point-in-time check. A path validated here can be replaced by
  a symlink before it is used; callers that care must re-check at use, or hold
  an open handle. This module cannot close that window.
* ``resolve()`` needs the filesystem. On a path whose parents do not exist it
  still returns an absolute path (non-strict mode), which is what makes
  ``must_exist=False`` usable, but it means containment for a nonexistent path
  is decided lexically after resolution rather than against real directories.
* Errors are returned, not raised. Callers are expected to turn them into exit
  code 2 and should not assume a raised exception on rejection. That includes a
  path ``resolve()`` cannot follow: a symlink loop in an intermediate component
  raises ``RuntimeError`` on CPython 3.10-3.12, which is returned as a
  ``SYMLINK`` rejection rather than propagated. CPython 3.13 raises nothing
  there: it resolves as far as it can and appends the rest unchecked, so the
  loop stayed in the answer, ``is_relative_to`` read the text as inside, and
  the path was accepted. The resolved path is therefore asked about once more
  with ``os.lstat`` (``_is_a_loop``), which the kernel answers with ``ELOOP``
  for a loop on any version, and that is the same ``SYMLINK`` rejection. A path
  that does not exist answers ``ENOENT`` there, not ``ELOOP``, so
  ``must_exist=False`` is unchanged. It also includes a candidate or
  root holding a NUL character, which no file system path can: ``os.lstat`` and
  ``resolve()`` raise ``ValueError`` for one, and it is returned as an
  ``EMBEDDED_NUL`` rejection before either is asked.
* On a file system that compares names without regard to case (macOS's default)
  a candidate spelled in another case than the root is the same directory, but
  ``is_relative_to`` compares the text. When the text says "outside", the
  candidate's ancestors are compared with the root by identity
  (``os.path.samefile``), so such a spelling is accepted where it names the same
  directory and still rejected on a case-sensitive volume, where it does not.
  The ``resolved`` field keeps the caller's spelling either way.
* A rejection message names the candidate and the root as given, never the real
  path the candidate resolves to: the workspace resolver echoes these messages to
  an MCP client, which would otherwise learn where a server-side link leads.
"""

from __future__ import annotations

import errno
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Optional, Union

PathLike = Union[str, Path]

_PARENT = ".."


class PathContainmentViolation(str, Enum):
    """Why a candidate path was rejected.

    The values reach users in error output, so they are stable strings.
    """

    PARENT_TRAVERSAL = "parent-traversal"
    OUTSIDE_ROOT = "outside-root"
    SYMLINK = "symlink"
    MISSING = "missing"
    EMBEDDED_NUL = "embedded-nul"


@dataclass(frozen=True)
class PathContainmentError:
    """A single rejection, naming the entry that caused it."""

    violation: PathContainmentViolation
    entry: str
    """The offending input, POSIX-shaped so it is comparable across platforms."""
    root: str
    message: str


@dataclass(frozen=True)
class PathContainmentResult:
    """The outcome of one validation. Exactly one of the fields is set."""

    resolved: Optional[Path] = None
    error: Optional[PathContainmentError] = None

    @property
    def ok(self) -> bool:
        """True when the candidate is contained and may be used."""
        return self.error is None


def _display(value: PathLike) -> str:
    """Render a path for error messages, preserving the offending text.

    Uses POSIX separators so messages are identical on every platform, and does
    not normalise the path -- a rejected ``a/../b`` should be echoed back as
    ``a/../b`` rather than as ``b``.
    """
    return PurePosixPath(str(value).replace("\\", "/")).as_posix()


def _has_parent_component(value: PathLike) -> bool:
    """True when any whole path component of *value* is ``..``.

    Tokenises through PurePosixPath after normalising backslashes, so a
    Windows-style separator is understood on POSIX as well, and through
    PureWindowsPath, which reads a drive-relative ``C:..\\b`` as the drive and
    then ``..``: read as POSIX text that is one component, ``C:..``, and the
    traversal passed. Whole components only: ``a..b`` is a legal filename, not
    traversal.
    """
    text = str(value)
    return (
        _PARENT in PurePosixPath(text.replace("\\", "/")).parts
        or _PARENT in PureWindowsPath(text).parts
    )


def _is_within(resolved: Path, resolved_root: Path) -> bool:
    """Whether *resolved* is at or below *resolved_root*.

    By text first (``is_relative_to``), then, when the text says no, by identity:
    *resolved* or one of its parents is the root's own directory
    (``os.path.samefile``). On a case-insensitive file system a candidate spelled
    in another case than the root names the same directory and the text alone
    rejected it; on a case-sensitive one the two are different directories and
    the identity check says so. A path that does not exist has no identity and
    is skipped, so a nonexistent candidate is decided by the text, as before.
    """
    if resolved.is_relative_to(resolved_root):
        return True
    for ancestor in (resolved, *resolved.parents):
        try:
            if os.path.samefile(ancestor, resolved_root):
                return True
        except OSError:
            continue
    return False


def _reject(
    violation: PathContainmentViolation,
    entry: PathLike,
    root: PathLike,
    message: str,
) -> PathContainmentResult:
    return PathContainmentResult(
        error=PathContainmentError(
            violation=violation,
            entry=_display(entry),
            root=_display(root),
            message=message,
        )
    )


def _is_a_loop(resolved: Path) -> bool:
    """Whether a component of *resolved* is a symlink loop ``resolve()`` left in.

    CPython 3.13's non-strict ``resolve()`` raises nothing on a loop: it keeps
    the looping component and appends what follows unchecked, so the text of
    the answer looks like a path below the root. ``os.lstat`` follows every
    component but the last, and the kernel answers ``ELOOP`` for a loop among
    them on every version; a path that merely does not exist answers ``ENOENT``
    and is not a loop. Any other error is left to the checks that follow.
    """
    try:
        os.lstat(resolved)
    except OSError as error:
        return error.errno == errno.ELOOP
    return False


def validate_contained_path(
    candidate: PathLike,
    root: PathLike,
    *,
    must_exist: bool = False,
) -> PathContainmentResult:
    """Validate that *candidate* is a directory at or below *root*.

    Args:
        candidate: The directory to validate, relative to *root* or absolute.
            A relative candidate is interpreted against *root*, never against
            the process working directory.
        root: The tree the caller is authorised to read.
        must_exist: When True, also require that the resolved path exists and
            is a directory. Off by default, because containment is a question
            about the path rather than about the filesystem.

    Returns:
        A :class:`PathContainmentResult`. On success ``resolved`` holds the
        canonical absolute path; on failure ``error`` names the offending entry
        and the rule it broke. Callers turn a failure into exit code 2.
    """
    # Text-level checks first: they do not touch the filesystem. A NUL names no
    # file, and os.lstat and resolve() raise ValueError for one, which the
    # callers' except clauses (OSError, ValueError) do not all cover.
    for text, what in ((candidate, "candidate"), (root, "root")):
        if "\x00" in str(text):
            return _reject(
                PathContainmentViolation.EMBEDDED_NUL,
                text,
                root,
                f"the {what} '{_display(text)}' holds a NUL character; no path does",
            )
    # The one rule that must hold regardless of where the path would resolve to.
    if _has_parent_component(candidate):
        return _reject(
            PathContainmentViolation.PARENT_TRAVERSAL,
            candidate,
            root,
            f"'{_display(candidate)}' contains a '..' component; "
            "paths must be expressed without traversing upward",
        )
    if _has_parent_component(root):
        return _reject(
            PathContainmentViolation.PARENT_TRAVERSAL,
            root,
            root,
            f"root '{_display(root)}' contains a '..' component; "
            "the root must be expressed without traversing upward",
        )

    # resolve() raises RuntimeError on CPython 3.10-3.12 when a component on the
    # way is a symlink loop (and OSError for a few other unreadable shapes). The
    # module promises a returned rejection, never a raised one: the workspace
    # resolver catches only OSError and ValueError around this call. CPython
    # 3.13 raises nothing and leaves the loop in the answer (_is_a_loop).
    try:
        resolved_root = Path(root).resolve()
        unresolved = _is_a_loop(resolved_root)
    except (RuntimeError, OSError):
        unresolved = True
    if unresolved:
        return _reject(
            PathContainmentViolation.SYMLINK,
            root,
            root,
            f"root '{_display(root)}' cannot be resolved: a component on the way "
            "to it is a symlink loop or cannot be read",
        )

    # Joining handles relative and absolute candidates without a branch: an
    # absolute candidate discards the root and is then held to the same
    # containment check. See the module docstring on why not to test
    # is_absolute() here.
    joined = resolved_root / Path(str(candidate).replace("\\", "/"))

    # Before resolution, because resolve() follows the link and would hide it.
    # Not Path.is_symlink(), which is False for a Windows junction: one to a
    # directory inside the root resolved inside it and passed. A reparse point
    # counts only when it names another path, as a junction does; a OneDrive
    # placeholder is the directory it appears to be. Imported here, as this
    # module imports nothing of ASH's at load time.
    from automated_security_helper.utils.scanned_tree import _is_link_stat

    try:
        names_another_path = _is_link_stat(os.lstat(joined))
    except OSError:
        names_another_path = False
    # The root itself is accepted, and so is naming it by the spelling the caller
    # gave for it, link or not: an absolute candidate equal to a root reached
    # through a link was refused as a symlink while "." was accepted.
    if names_another_path and os.path.normcase(
        os.path.normpath(joined)
    ) == os.path.normcase(os.path.normpath(os.path.abspath(root))):
        names_another_path = False
    if names_another_path:
        return _reject(
            PathContainmentViolation.SYMLINK,
            candidate,
            root,
            f"'{_display(candidate)}' is a symlink; "
            "project directories must be real directories",
        )

    try:
        resolved = joined.resolve()
        unresolved = _is_a_loop(resolved)
    except (RuntimeError, OSError):
        unresolved = True
    if unresolved:
        return _reject(
            PathContainmentViolation.SYMLINK,
            candidate,
            root,
            f"'{_display(candidate)}' cannot be resolved: a component on the way "
            "to it is a symlink loop or cannot be read",
        )

    if not _is_within(resolved, resolved_root):
        return _reject(
            PathContainmentViolation.OUTSIDE_ROOT,
            candidate,
            root,
            f"'{_display(candidate)}' resolves outside '{_display(root)}'",
        )

    if must_exist and not resolved.is_dir():
        return _reject(
            PathContainmentViolation.MISSING,
            candidate,
            root,
            f"'{_display(candidate)}' does not exist as a directory "
            f"under '{_display(resolved_root)}'",
        )

    return PathContainmentResult(resolved=resolved)
