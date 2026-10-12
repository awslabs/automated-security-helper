# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Refuse an output directory that ASH would write, clear or mount through a link.

Before a scan ASH removes and recreates ``analysis``, ``reports``, ``scanners`` and
``converted`` under the output directory, writes its results and logs there, and a
sandboxed scan mounts the output directory. A link at the output directory, at one of
those four, or at one of the files ASH writes there by a fixed name sends the
deletions, the writes and the mount wherever it points. The default output
directory, ``.ash/ash_output``, is inside the scanned tree, so the repository being
scanned can commit such a link.

The check is the same whatever the sandbox mode and whatever the run mode: the
single-directory and workspace CLI, container and nix mode (whose host side clears
the same directories before the inner run), MCP scans, ``ash report`` and
``ash merge``. Components above the output directory that are outside ``root``,
compared by device and inode as well as by name, are the operator's own spelling
(macOS's ``/tmp``, a home directory that links elsewhere) and are not examined.

The write side of the same rule is ``utils/sandbox/fs_guard.open_for_write``, which
every write below the output directory goes through: it does not follow a link at
the name, or at a directory on the way to it, even if one appears after the check.
``open_no_follow`` is that function guarding the directory that holds the file.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import IO, Any, Optional, Tuple, Union

PathLike = Union[str, "os.PathLike[str]"]

#: The directories ASH clears and recreates under the output directory: the
#: orchestrator's ensure_directories and run_ash_scan's _discard_prior_run_artifacts.
OUTPUT_WORKING_DIRS = ("analysis", "reports", "scanners", "converted")

#: The files a scan writes at the top of the output directory, and removes first.
OUTPUT_RESULT_FILES = (
    "ash_aggregated_results.json",
    "ash-ignore-report.txt",
    "ash-scan-set-files-list.txt",
)

#: The logs utils/log.py writes there for the "ash" logger.
OUTPUT_LOG_FILES = ("ash.log", "ash.log.jsonl")

#: Workspace mode's own directories under the workspace output directory: each
#: project's output tree, and the aggregator's spool (workspace/aggregation.py).
WORKSPACE_OUTPUT_DIRS = ("projects", ".workspace-spool")

WHY = (
    "ASH does not write to, clear or mount its output directory through a link, "
    "whatever the sandbox mode."
)

#: The remedy for a command-line run. MCP callers pass their own; see
#: refuse_linked_output_dir.
REMEDY = (
    f"{WHY} Pass --output-dir with a directory that is not a link, or replace the "
    "link with a directory."
)

# Values from the Windows SDK. The stat module defines both on every platform; the
# literals are only the fallback for an interpreter that does not.
_FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_IO_REPARSE_TAG_MOUNT_POINT = getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003)


class OutputDirLinkRefused(ValueError):
    """The output directory, or something ASH writes under it, is reached through a link.

    ``found`` describes the link; the message adds the remedy for the caller.

    The base of every link refusal for ASH's output: fs_guard's OutputLinkRefused
    and OutputHardLinkRefused, raised by a write below the output directory, derive
    from it as well as from OSError, so ``except OutputDirLinkRefused`` sees a
    refused write as well as a refused output directory.
    """

    def __init__(self, found: str, remedy: str = REMEDY):
        self.found = found
        self.remedy = remedy
        super().__init__(f"{found[0].upper()}{found[1:]}. {remedy}")

    def __reduce__(self) -> Tuple[type, Tuple[Any, ...]]:
        # Rebuilt from its own arguments, not from the formatted message.
        return (type(self), (self.found, self.remedy))


def is_junction(path: PathLike) -> bool:
    """Whether ``path`` is a Windows directory junction.

    os.path.isjunction exists from Python 3.12. Before that, a junction is a reparse
    point whose tag is IO_REPARSE_TAG_MOUNT_POINT, read from lstat; the fields are
    absent off Windows, which answers False.
    """
    isjunction = getattr(os.path, "isjunction", None)
    if isjunction is not None:
        return bool(isjunction(path))
    try:
        found = os.lstat(path)
    except OSError:
        return False
    attributes = getattr(found, "st_file_attributes", 0)
    tag = getattr(found, "st_reparse_tag", 0)
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT) and (
        tag == _IO_REPARSE_TAG_MOUNT_POINT
    )


def is_link(path: PathLike) -> bool:
    """Whether ``path`` is a symlink or a directory junction."""
    return Path(path).is_symlink() or is_junction(path)


def _kind(path: Path) -> str:
    return "a symlink" if path.is_symlink() else "a directory junction"


def _identity(path: PathLike) -> Optional[Tuple[int, int]]:
    """``(st_dev, st_ino)`` of what ``path`` names, links followed, or None.

    None too on a filesystem that reports no inode numbers, which would otherwise
    make every directory on it the same one.
    """
    try:
        found = os.stat(path)
    except OSError:
        return None
    if not found.st_ino:
        return None
    return (found.st_dev, found.st_ino)


def _is_below(path: Path, root: Path, root_identity: Optional[Tuple[int, int]]) -> bool:
    """Whether ``root`` is one of ``path``'s parents, by name or by identity.

    Compared by device and inode as well as by name, so the answer is the same
    however either path is spelled. A parent that does not exist has no identity
    and is compared by name.
    """
    named_root = os.path.normcase(root)
    if any(os.path.normcase(parent) == named_root for parent in path.parents):
        return True
    if root_identity is None:
        return False
    return any(_identity(parent) == root_identity for parent in path.parents)


def linked_output_component(
    root: Optional[PathLike], output_dir: PathLike, *, workspace: bool = False
) -> Optional[str]:
    """Describe the first link ASH would go through for ``output_dir``, or None.

    Checked, in order:

    - each component below ``root`` on the way to the output directory, walked as
      spelled with ``..`` included, so that a link a later ``..`` steps back out of
      is still seen; "below" is decided by name or by device and inode (_is_below),
      so the way either path is spelled does not matter;
    - the output directory itself, wherever it is;
    - for an output directory below ``root``, that its real path is below the real
      path of ``root`` too, which catches a redirection out of the tree that the
      walk cannot see;
    - each of OUTPUT_WORKING_DIRS, OUTPUT_RESULT_FILES and OUTPUT_LOG_FILES under
      it, and with ``workspace`` each of WORKSPACE_OUTPUT_DIRS.

    Args:
        root: The scanned tree for a scan; for a workspace project, the workspace's
            output directory, so that ``projects`` and ``projects/<key>`` are
            examined too. None examines no component above the output directory.
        output_dir: The output directory as the operator or the caller spelled it.
        workspace: The output directory is a workspace's.
    """
    spelled = Path(output_dir).absolute()
    root_path = Path(os.path.abspath(root)) if root is not None else None
    root_identity = _identity(root_path) if root_path is not None else None
    current = Path(spelled.anchor)
    for part in spelled.parts[1:]:
        if part == "..":
            current = current.parent
            continue
        if part in ("", "."):
            continue
        current = current / part
        if (
            root_path is not None
            and is_link(current)
            and _is_below(current, root_path, root_identity)
        ):
            return (
                f"{current.as_posix()} is {_kind(current)}, on the way to the "
                f"output directory {spelled.as_posix()}"
            )
    if is_link(spelled):
        return f"the output directory {spelled.as_posix()} is {_kind(spelled)}"
    lexical = Path(os.path.abspath(spelled))
    if root_path is not None and _is_below(lexical, root_path, root_identity):
        real_root = Path(os.path.realpath(root_path))
        actual = Path(os.path.realpath(lexical))
        if not _is_below(actual, real_root, root_identity):
            return (
                f"the output directory {lexical.as_posix()} resolves to "
                f"{actual.as_posix()}, outside {root_path.as_posix()}"
            )
    names: Tuple[str, ...] = (
        OUTPUT_WORKING_DIRS + OUTPUT_RESULT_FILES + OUTPUT_LOG_FILES
    )
    if workspace:
        names += WORKSPACE_OUTPUT_DIRS
    for name in names:
        entry = spelled / name
        if is_link(entry):
            return f"{entry.as_posix()} is {_kind(entry)}"
    return None


def refuse_linked_output_dir(
    root: Optional[PathLike],
    output_dir: PathLike,
    *,
    workspace: bool = False,
    remedy: str = REMEDY,
) -> None:
    """Raise OutputDirLinkRefused if ``output_dir`` is reached through a link.

    See linked_output_component for what is examined. The message names the link
    and ends with ``remedy``: by default the command-line one, ``--output-dir``.
    """
    found = linked_output_component(root, output_dir, workspace=workspace)
    if found is not None:
        raise OutputDirLinkRefused(found, remedy)


def open_no_follow(
    path: PathLike,
    *,
    append: bool = False,
    encoding: Optional[str] = "utf-8",
    errors: Optional[str] = None,
) -> IO[str]:
    """Open ``path`` for writing text without following a link at its name.

    Truncates, or appends with ``append``; creates the file when missing, with the
    mode open() would give it. This is ``fs_guard.open_for_write`` guarding the
    directory that holds ``path``, so it is ASH's one write path below an output
    directory: a link at the name raises OutputLinkRefused, an
    OutputDirLinkRefused, rather than being written through; a file another name
    refers to raises OutputHardLinkRefused, one too; and anything other than a
    regular file (a FIFO, a device) raises OSError. Below a registered root every
    component under that root is checked as well.
    """
    # Imported here, not at the top: fs_guard imports this module for the
    # exception family, so a module-level import is a cycle. Do not hoist.
    from automated_security_helper.utils.sandbox import fs_guard

    target = Path(os.path.abspath(path))
    return fs_guard.open_for_write(
        target,
        encoding=encoding,
        errors=errors,
        append=append,
        root=target.parent,
    )
