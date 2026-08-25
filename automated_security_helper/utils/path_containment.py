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
   resolves to a contained path and would otherwise be accepted, which would
   let a workspace definition scan the same tree twice under two names, or
   follow a link whose target changes between validation and use.
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
  code 2 and should not assume a raised exception on rejection.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
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
    Windows-style separator is understood on POSIX as well. Whole components
    only: ``a..b`` is a legal filename, not traversal.
    """
    return _PARENT in PurePosixPath(str(value).replace("\\", "/")).parts


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
    # Text-level check first: it does not touch the filesystem, and it is the
    # one rule that must hold regardless of where the path would resolve to.
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

    resolved_root = Path(root).resolve()

    # Joining handles relative and absolute candidates without a branch: an
    # absolute candidate discards the root and is then held to the same
    # containment check. See the module docstring on why not to test
    # is_absolute() here.
    joined = resolved_root / Path(str(candidate).replace("\\", "/"))

    # Before resolution, because resolve() follows the link and would hide it.
    if joined.is_symlink():
        return _reject(
            PathContainmentViolation.SYMLINK,
            candidate,
            root,
            f"'{_display(candidate)}' is a symlink; "
            "project directories must be real directories",
        )

    resolved = joined.resolve()

    if not resolved.is_relative_to(resolved_root):
        return _reject(
            PathContainmentViolation.OUTSIDE_ROOT,
            candidate,
            root,
            f"'{_display(candidate)}' resolves to '{_display(resolved)}', "
            f"which is outside '{_display(resolved_root)}'",
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
