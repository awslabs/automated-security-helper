# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Why a source or output directory a run was given cannot be used, in one wording.

A --source-dir that names no directory ASH can scan, and an --output-dir that
ASH cannot make or use, are usage errors: each surface refuses them with exit 5
and the same text, so a script or an operator reading ./ash, Invoke-ASH, the
Python CLI or the MCP server sees one message for one input. The texts name
which case it is and no flag, since the MCP server's parameter is
``directory_path``:

- ``Source directory does not exist: <path>``
- ``Source directory is not a directory: <path>``
- ``Source directory cannot be entered: <path>``
- ``Output directory is not a directory: <path>``
- ``Output directory cannot be entered: <path>``
- ``Output directory cannot be created: <path> (<reason>)``, where the reason is
  the system's own text for the error (its strerror), such as ``Not a
  directory`` for a file on the way to it
- ``Output directory cannot be written: <path> (<reason>)``, for one that is
  there and can be entered, when a file cannot be made in it (``Permission
  denied``, ``Read-only file system``)

./ash and Invoke-ASH write the same texts themselves, and the MCP server's
source_directory_error gives the same answer for each source directory case.
The path is the one given, and each surface shows it its own way (the CLI's
sinks show it once). A missing output directory is not refused: every surface
creates it, and refuses it only when that fails. Whether one that is there can
be written is found by making a file in it and removing it, on every surface,
before anything else is written there.

A source directory is checked in one order everywhere: whether the path can be
reached (stat), whether it is a directory, and whether its entries can be both
listed and entered (read and search permission). A path under a directory that
cannot be searched is not one that does not exist: stat answers EACCES for it,
whether or not it is there, so it "cannot be entered". os.path.exists answers
False for it, as bash's ``-e`` does, which is why the stat error is read here and
./ash looks at the nearest ancestor it can see.
"""

from __future__ import annotations

import contextlib
import errno
import os
import secrets
import stat
from typing import Optional, Union

PathLike = Union[str, "os.PathLike[str]"]

#: What a :class:`DirectoryRefusal` says went wrong with an output directory.
REFUSED_NOT_A_DIRECTORY = "not_a_directory"
REFUSED_CANNOT_BE_ENTERED = "cannot_be_entered"
REFUSED_CANNOT_BE_CREATED = "cannot_be_created"
REFUSED_CANNOT_BE_WRITTEN = "cannot_be_written"


class DirectoryRefusal(str):
    """The text of an output directory's refusal, which also says why.

    A ``str`` equal to the one-line message every surface shows, so each caller
    that prints, compares or joins it is unchanged. ``kind`` is one of the
    ``REFUSED_*`` words and ``error_number`` the errno of the system error behind
    it, or None when none was involved. A caller that must tell a full disk from
    a missing permission reads these; before them it could only look at the path
    again and guess, and ``ENOSPC`` on a directory that exists read as a refused
    permission.
    """

    kind: str
    error_number: Optional[int]

    def __new__(
        cls, text: str, kind: str, error_number: Optional[int] = None
    ) -> "DirectoryRefusal":
        refusal = super().__new__(cls, text)
        refusal.kind = kind
        refusal.error_number = error_number
        return refusal

    def __getnewargs__(self) -> tuple:  # type: ignore[override]
        # So a copy or a pickle of the refusal rebuilds it with its reason.
        return (str(self), self.kind, self.error_number)


def source_dir_refusal(source_dir: PathLike) -> Optional[str]:
    """Why *source_dir* cannot be scanned, or None when it can."""
    path = os.fspath(source_dir)
    try:
        mode = os.stat(path).st_mode
    except (FileNotFoundError, NotADirectoryError):
        return f"Source directory does not exist: {path}"
    except ValueError:
        # A path the OS cannot take at all (an embedded NUL) names nothing.
        return f"Source directory does not exist: {path}"
    except OSError as error:
        # A link that leads back to itself names nothing, as a link to nothing does.
        if error.errno == errno.ELOOP:
            return f"Source directory does not exist: {path}"
        return f"Source directory cannot be entered: {path}"
    if not stat.S_ISDIR(mode):
        return f"Source directory is not a directory: {path}"
    if not os.access(path, os.R_OK | os.X_OK):
        return f"Source directory cannot be entered: {path}"
    return None


def output_dir_refusal(output_dir: PathLike) -> Optional[str]:
    """Why *output_dir* cannot be written into, or None when it can or will be made.

    A directory that is there but cannot be entered (no search permission) is
    refused too, as ./ash's cd refuses it, and so is one that can be entered but
    that a file cannot be made in (:func:`_write_refused`). One that cannot be
    reached cannot be
    made either, and is refused with the reason stat gives, as mkdir would fail
    with it: a file on the way to it (``Not a directory``) or a directory on the
    way that cannot be searched (``Permission denied``). One that is simply not
    there is not checked further: whether it can be made is known only by making
    it, so the caller that makes it refuses it with :func:`output_dir_unmakeable`.
    An empty path is refused as mkdir refuses it (``No such file or directory``):
    stat answers the same, and nothing was about to make it, while the run that
    took it would have written into the current directory. A path the OS cannot
    take (an embedded NUL) is refused with the reason Python gives.
    """
    path = os.fspath(output_dir)
    try:
        mode = os.stat(path).st_mode
    except FileNotFoundError as error:
        if not path:
            return output_dir_unmakeable(
                path, error.strerror or "No such file", error.errno
            )
        return _link_to_nothing_on_the_way(path)
    except ValueError as error:
        return output_dir_unmakeable(path, str(error) or type(error).__name__)
    except OSError as error:
        return output_dir_unmakeable(
            path, error.strerror or type(error).__name__, error.errno
        )
    if not stat.S_ISDIR(mode):
        return DirectoryRefusal(
            f"Output directory is not a directory: {path}", REFUSED_NOT_A_DIRECTORY
        )
    if not os.access(path, os.X_OK):
        return DirectoryRefusal(
            f"Output directory cannot be entered: {path}",
            REFUSED_CANNOT_BE_ENTERED,
            errno.EACCES,
        )
    failed = _write_refused(path)
    if failed is not None:
        return output_dir_unwritable(
            path, failed.strerror or type(failed).__name__, failed.errno
        )
    return None


def _link_to_nothing_on_the_way(path: str) -> Optional[str]:
    """The refusal of *path*, which is not there, when making it would fail on a link
    to nothing: the path itself, or the nearest part of it that is there. mkdir
    cannot make a directory where a link is, and fails with EEXIST, as mkdir -p
    does in ./ash. None when there is no such link.

    The path is walked as written, made absolute with the working directory and
    no more: ``os.path.abspath`` folds a ``..`` lexically, so after a symbolic
    link to a directory it named a sibling of the link, not of the directory
    the link leads to, which is the one mkdir reaches. Each ``lexists`` here
    hands the path to the OS, which resolves such a ``..`` as mkdir does."""
    current = path if os.path.isabs(path) else os.path.join(os.getcwd(), path)
    while not os.path.lexists(current):
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent
    if os.path.islink(current) and not os.path.exists(current):
        return output_dir_unmakeable(path, os.strerror(errno.EEXIST), errno.EEXIST)
    return None


#: The start of the name of the file :func:`_write_refused` makes and removes. It is
#: none of the names a scan writes, reads back or counts as its output
#: (``core/previous_results.RESULT_ENTRIES``), so one left behind by a process
#: killed between the two steps is not taken for results. ./ash and Invoke-ASH name
#: theirs the same way.
WRITE_CHECK_PREFIX = ".ash-write-check."


def _write_refused(directory: str) -> Optional[OSError]:
    """Why a file cannot be made in *directory*, as the error, or None when one can.

    Made with ``O_CREAT | O_EXCL`` and not through a link, under a name of its own,
    and removed at once. ``os.access(W_OK)`` is not asked: it answers for the real
    user rather than the effective one, and knows nothing of ACLs or a read-only
    mount.
    """
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    for _ in range(3):
        probe = os.path.join(directory, WRITE_CHECK_PREFIX + secrets.token_hex(8))
        try:
            descriptor = os.open(probe, flags, 0o600)
        except FileExistsError:
            continue
        except OSError as error:
            return error
        try:
            os.close(descriptor)
        finally:
            with contextlib.suppress(OSError):
                os.unlink(probe)
        return None
    return None


def output_dir_unmakeable(
    output_dir: PathLike, reason: str, error_number: Optional[int] = None
) -> DirectoryRefusal:
    """The refusal for *output_dir* when making it failed with *reason*.

    *reason* is the error's strerror alone, never its message, which names the path
    again: ``Output directory cannot be created: blocker/out (Not a directory)``.
    *error_number* is the error's errno, kept on the refusal for a caller that
    sorts refusals (:class:`DirectoryRefusal`).
    """
    return DirectoryRefusal(
        f"Output directory cannot be created: {os.fspath(output_dir)} ({reason})",
        REFUSED_CANNOT_BE_CREATED,
        error_number,
    )


def output_dir_unwritable(
    output_dir: PathLike, reason: str, error_number: Optional[int] = None
) -> DirectoryRefusal:
    """The refusal for *output_dir* when no file could be made in it, *reason* being
    the error's strerror, such as ``Permission denied``, and *error_number* its
    errno (``ENOSPC`` for a full disk, which is not a permission)."""
    return DirectoryRefusal(
        f"Output directory cannot be written: {os.fspath(output_dir)} ({reason})",
        REFUSED_CANNOT_BE_WRITTEN,
        error_number,
    )


__all__ = [
    "REFUSED_CANNOT_BE_CREATED",
    "REFUSED_CANNOT_BE_ENTERED",
    "REFUSED_CANNOT_BE_WRITTEN",
    "REFUSED_NOT_A_DIRECTORY",
    "WRITE_CHECK_PREFIX",
    "DirectoryRefusal",
    "output_dir_refusal",
    "output_dir_unmakeable",
    "output_dir_unwritable",
    "source_dir_refusal",
]
