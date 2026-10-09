# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Open a file from the scanned tree only if it really is inside that tree.

Why this module exists
----------------------
Some of what ASH writes is built from files in the tree it scans: converters extract
archives and convert notebooks into ``output_dir/converted``, and template parsing can
put part of a file into ``ash.log``. A symlink committed to the tree points wherever its
author chose, and a plain ``open()`` follows it. Without a check, a link named ``a.zip``
or ``nb.ipynb`` makes ASH copy a file from outside the tree into its output, which is
often uploaded as a CI artifact and, under the opt-in sandbox, is readable by every
scanner. This module is the one place that decides whether such a file may be read, so
every reader applies the same rule.

The rule
--------
A file is read only when all of these hold:

1. Its path is at or below the scan root, compared lexically against the root as
   given and, failing that, against the root's real path. The root itself is the
   operator's choice: it may be reached through a symlink (``/tmp`` on macOS is one)
   or spelled with ``..`` (``--source-dir ../proj``).
2. The part of its path below the root has no ``..`` component. Checked on the text,
   before anything is resolved.
3. No component below the root is a symlink or a Windows junction (a reparse point
   that names another path). This covers a symlinked parent directory as well as the
   file itself.
4. The file is a regular file: not a directory, FIFO, socket or device.
5. The file has exactly one hard link. A second link means its content is also
   reachable under another name, which may be outside the tree.

``follow_links_inside=True`` relaxes rules 3 and 5 for readers that look up a file a
scanner already reported: a link is followed when its target is inside the tree, and
a hard-linked file is read. See :func:`open_in_scanned_tree`.

How the check is made, and why that way
---------------------------------------
On platforms with ``O_NOFOLLOW`` and ``dir_fd`` support (Linux, macOS), the root is
opened and every component below it is opened relative to its parent's descriptor with
``O_NOFOLLOW``. A component that is a link fails the open instead of being followed,
and the regular-file and link-count checks are made with ``fstat`` on the descriptor
that is returned. There is no gap between checking and reading: the caller reads from
that same descriptor, so replacing a component with a link after the check cannot
redirect the read. ``sandbox/fs_guard.py`` opens directories for ASH's own writes the
same way.

Windows has neither primitive. There, each component is ``lstat``-ed from the root
down, the file is opened, and the opened handle's file id is compared with the one
``lstat`` saw. A component swapped between the two calls changes the id and the read
is refused.

Failure modes and known limitations
-----------------------------------
* A refusal is raised as :class:`TreeInputRefused`, which carries a path relative to
  the root and a short reason. Neither contains anything read from the file, so the
  refusal can be logged and written to results as is.
* Any other ``OSError`` (missing file, permission denied) propagates unchanged. Those
  are not decisions this module makes, and callers already handle them.
* Callers that hand the file to another process must give it the content read here,
  not the original path, or that process can still follow a link swapped in after the
  check. The Jupyter converter copies the notebook through the descriptor before
  nbconvert sees it, and cdk-nag gives ``CfnInclude`` a copy of the text it read.
  ``cfn_nag_scan`` is still given the template's path once the check has passed: its
  SARIF names findings by the path it was given, so a copy would move every finding.
  The check decides whether it runs at all; a file replaced between the check and
  cfn_nag's own read is the same exposure every scanner that walks the tree has.
* The root is trusted. A scan pointed at a directory through a symlink scans that
  directory.
"""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path
from typing import BinaryIO, Optional, Tuple, Union

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]

PathLike = Union[str, "os.PathLike[str]"]

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_BINARY = getattr(os, "O_BINARY", 0)

#: Whether components can be opened one at a time without following links. Both
#: ``O_NOFOLLOW`` and ``dir_fd`` support for ``os.open`` and ``os.stat`` are needed.
_DESCRIPTOR_WALK = (
    bool(_NOFOLLOW) and os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
)

_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
# Set in the reparse tag of every reparse point that redirects to another name:
# symlinks (IO_REPARSE_TAG_SYMLINK) and junctions (IO_REPARSE_TAG_MOUNT_POINT).
# OneDrive placeholders, deduplicated files and app execution aliases are reparse
# points without it, and they are the file they appear to be.
_NAME_SURROGATE = 0x20000000

REASON_PARENT_TRAVERSAL = "its path contains a '..' component"
REASON_OUTSIDE = "it is outside the scanned tree"
REASON_SYMLINK = "it is a symbolic link"
REASON_NOT_REGULAR = "it is not a regular file"
REASON_HARDLINK = "it has more than one hard link"
REASON_CHANGED = "it changed while it was being checked"
REASON_RESOLVES_OUTSIDE = "it is a symbolic link that resolves outside the scanned tree"


def _parent_symlink_reason(component: str) -> str:
    return f"its parent directory '{component}' is a symbolic link"


class TreeInputRefused(Exception):
    """A file in the scanned tree that ASH declined to read.

    Attributes:
        path: The file's path relative to the scan root, with ``/`` separators. When
            the file is not under the root, the path as given.
        reason: Why it was refused, as a short phrase ("it is a symbolic link").
    """

    def __init__(self, path: str, reason: str):
        self.path = path
        self.reason = reason
        super().__init__(f"{path}: {reason}")


def _absolute(path: PathLike) -> Path:
    """``path`` made absolute against the working directory, and nothing else.

    Not ``os.path.abspath``: that folds ``..`` away lexically, which is not what the
    operating system does when a component before the ``..`` is a symlink. ``Path``
    itself drops ``.`` components and repeated separators, which is harmless.
    """
    candidate = Path(path)
    return candidate if candidate.is_absolute() else Path.cwd() / candidate


def _below(path: PathLike, root: PathLike) -> Optional[Tuple[Path, Tuple[str, ...]]]:
    """The anchor ``path`` is under and its components below it, or None.

    First as spelled: ``scan_set`` builds every path by joining onto the root it was
    given, so the root's own components prefix the path's, whatever they are -- a
    root written with ``..`` included. The anchor is then the root as written, which
    the operating system resolves when it is opened. Failing that, against the root's
    real path, for a caller that spelled the path through the resolved root.
    """
    candidate = _absolute(path)
    for anchor in (_absolute(root), Path(os.path.realpath(root))):
        if _starts_with(candidate, anchor):
            return anchor, candidate.parts[len(anchor.parts) :]
    return None


def _starts_with(candidate: Path, anchor: Path) -> bool:
    """Whether ``anchor``'s components prefix ``candidate``'s.

    Compared through ``os.path.normcase``, which is the identity on POSIX and folds
    case on Windows, where ``C:`` and ``c:`` name the same drive.
    """
    head = candidate.parts[: len(anchor.parts)]
    if len(head) != len(anchor.parts):
        return False
    return all(
        os.path.normcase(a) == os.path.normcase(b) for a, b in zip(head, anchor.parts)
    )


def relative_display(path: PathLike, root: PathLike) -> str:
    """``path`` relative to ``root`` with ``/`` separators, or as given if outside it.

    Lexical only, so it is safe to call on a path that was just refused.
    """
    below = _below(path, root)
    if below is None or not below[1]:
        return Path(path).as_posix()
    return "/".join(below[1])


def _split_below_root(path: PathLike, root: PathLike) -> Tuple[Path, Tuple[str, ...]]:
    """The root to anchor at, and the components of ``path`` below it.

    Raises TreeInputRefused when the path is not below the root or has a ``..``
    component below it. Nothing here touches the file itself.
    """
    below = _below(path, root)
    if below is None:
        # Not under the root as spelled or as resolved. A '..' is reported as such,
        # by the text it was given in, since folding it away would name another file.
        if os.pardir in Path(path).parts:
            raise TreeInputRefused(Path(path).as_posix(), REASON_PARENT_TRAVERSAL)
        raise TreeInputRefused(Path(path).as_posix(), REASON_OUTSIDE)
    anchor, parts = below
    display = "/".join(parts)
    # Checked on the text below the root, before anything is opened. A '..' in the
    # root's own spelling is the operator's and is resolved with the root.
    if os.pardir in parts:
        raise TreeInputRefused(display, REASON_PARENT_TRAVERSAL)
    if not parts:
        # The root itself is a directory, never a file input.
        raise TreeInputRefused(Path(path).as_posix(), REASON_NOT_REGULAR)
    return anchor, parts


def _is_link_at(name: str, dir_fd: int) -> bool:
    try:
        return stat.S_ISLNK(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode)
    except OSError:
        return False


def _check_opened(fd: int, display: str, allow_hardlinks: bool = False) -> None:
    """Refuse an opened descriptor that is not a regular file, or has a second link."""
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise TreeInputRefused(display, REASON_NOT_REGULAR)
    if st.st_nlink > 1 and not allow_hardlinks:
        raise TreeInputRefused(display, REASON_HARDLINK)


def _open_by_descriptor_walk(
    anchor: Path, parts: Tuple[str, ...], display: str, allow_hardlinks: bool
) -> int:
    dir_fd = os.open(anchor, os.O_RDONLY | _DIRECTORY | _CLOEXEC)
    try:
        for index, part in enumerate(parts[:-1]):
            try:
                child = os.open(
                    part, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC, dir_fd=dir_fd
                )
            except OSError:
                if _is_link_at(part, dir_fd):
                    component = "/".join(parts[: index + 1])
                    raise TreeInputRefused(display, _parent_symlink_reason(component))
                raise
            previous, dir_fd = dir_fd, child
            os.close(previous)

        name = parts[-1]
        try:
            # O_NONBLOCK so a FIFO at the name cannot block the open; it is refused by
            # the regular-file check right after.
            fd = os.open(
                name,
                os.O_RDONLY | _NOFOLLOW | _NONBLOCK | _CLOEXEC | _BINARY,
                dir_fd=dir_fd,
            )
        except OSError as exc:
            # Linux reports a final-component link as ELOOP, and FreeBSD as EMLINK.
            # Asking lstat covers both and anything else a platform picks.
            if exc.errno in (errno.ELOOP, errno.EMLINK) or _is_link_at(name, dir_fd):
                raise TreeInputRefused(display, REASON_SYMLINK) from None
            raise
    finally:
        os.close(dir_fd)

    try:
        _check_opened(fd, display, allow_hardlinks)
        if _NONBLOCK and fcntl is not None:
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~_NONBLOCK)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _is_link_stat(st: os.stat_result) -> bool:
    """A symlink, or on Windows a reparse point that names another path."""
    if stat.S_ISLNK(st.st_mode):
        return True
    if not getattr(st, "st_file_attributes", 0) & _REPARSE_POINT:
        return False
    return bool(getattr(st, "st_reparse_tag", 0) & _NAME_SURROGATE)


def _open_by_checked_path(
    anchor: Path, parts: Tuple[str, ...], display: str, allow_hardlinks: bool
) -> int:
    current = anchor
    final: Optional[os.stat_result] = None
    for index, part in enumerate(parts):
        current = current / part
        st = os.lstat(current)
        if _is_link_stat(st):
            if index == len(parts) - 1:
                raise TreeInputRefused(display, REASON_SYMLINK)
            component = "/".join(parts[: index + 1])
            raise TreeInputRefused(display, _parent_symlink_reason(component))
        final = st

    if final is None or not stat.S_ISREG(final.st_mode):
        raise TreeInputRefused(display, REASON_NOT_REGULAR)

    fd = os.open(current, os.O_RDONLY | _BINARY)
    try:
        opened = os.fstat(fd)
        # st_ino is the file id on Windows. A zero on either side means the platform
        # did not report one, and the comparison would prove nothing.
        if (
            final.st_ino
            and opened.st_ino
            and ((opened.st_dev, opened.st_ino) != (final.st_dev, final.st_ino))
        ):
            raise TreeInputRefused(display, REASON_CHANGED)
        _check_opened(fd, display, allow_hardlinks)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _resolved_inside(
    path: PathLike, root: PathLike, display: str
) -> Tuple[Path, Tuple[str, ...]]:
    """Where ``path`` really is, as an anchor and components, if that is inside root."""
    real_root = Path(os.path.realpath(root))
    resolved = Path(os.path.realpath(_absolute(path)))
    if not _starts_with(resolved, real_root):
        raise TreeInputRefused(display, REASON_RESOLVES_OUTSIDE)
    parts = resolved.parts[len(real_root.parts) :]
    if not parts:
        raise TreeInputRefused(display, REASON_NOT_REGULAR)
    return real_root, parts


def open_in_scanned_tree(
    path: PathLike, root: PathLike, *, follow_links_inside: bool = False
) -> BinaryIO:
    """Open ``path`` for binary reading if it is a regular file inside ``root``.

    See the module docstring for the rule. Read from the returned file object; do not
    reopen ``path`` by name, which would undo the check.

    Args:
        path: The file to read, absolute or relative to the working directory, as
            ``scan_set`` returns it.
        root: The scan root, usually ``context.source_dir``.
        follow_links_inside: Accept a symlink, at any component, whose target is
            still inside the tree. For readers that look a file up by a path a
            scanner already reported -- inline suppressions, lockfiles -- where the
            file behind an in-tree link is tree content and refusing it would only
            change which findings are suppressed. The resolved file is then opened
            under the same rule with no link allowed, so a link swapped in after the
            resolution is still refused. Converters, templates and ignore files do
            not set this: their inputs are picked by walking the tree, which reaches
            the target of an in-tree link under its own name anyway. A file with
            more than one hard link is accepted too, for the same reason: the
            scanner already read it under this name, and installers that hard-link
            files (uv, pnpm, conda) would otherwise draw a warning per file.

    Returns:
        A binary file object positioned at the start of the file.

    Raises:
        TreeInputRefused: The file breaks the rule. Nothing has been read from it.
        OSError: The file could not be opened for some other reason.
    """
    anchor, parts = _split_below_root(path, root)
    display = "/".join(parts)
    if follow_links_inside:
        anchor, parts = _resolved_inside(path, root, display)
    if _DESCRIPTOR_WALK:
        fd = _open_by_descriptor_walk(anchor, parts, display, follow_links_inside)
    else:
        fd = _open_by_checked_path(anchor, parts, display, follow_links_inside)
    return os.fdopen(fd, "rb")


def refusal_reason(path: PathLike, root: PathLike) -> Optional[str]:
    """Why ``path`` would be refused, or None if it may be read.

    For callers that only need the verdict, such as counting candidate inputs. Makes
    the same check as :func:`open_in_scanned_tree`, by calling it, so the two cannot
    disagree. An ``OSError`` other than a refusal is not a refusal and returns None;
    the caller that opens the file for real will meet it there.
    """
    try:
        handle = open_in_scanned_tree(path, root)
    except TreeInputRefused as refused:
        return refused.reason
    except OSError:
        return None
    handle.close()
    return None
