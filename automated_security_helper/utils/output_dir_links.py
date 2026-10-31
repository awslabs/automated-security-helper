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

from automated_security_helper.utils.link_locations import without_extended_prefix

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

#: The ignore file ASH writes in an output directory inside the scanned tree; see
#: ignore_output_dir_in_git.
OUTPUT_GITIGNORE = ".gitignore"

#: Its text: one rule that ignores everything in the directory, itself included.
OUTPUT_GITIGNORE_TEXT = "# ASH's output directory, not part of the scanned tree.\n*\n"

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
        try:
            return bool(isjunction(path))
        except ValueError:  # a NUL in the path: no file has that name
            return False
    try:
        found = os.lstat(path)
    except (OSError, ValueError):
        return False
    attributes = getattr(found, "st_file_attributes", 0)
    tag = getattr(found, "st_reparse_tag", 0)
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT) and (
        tag == _IO_REPARSE_TAG_MOUNT_POINT
    )


def is_link(path: PathLike) -> bool:
    """Whether ``path`` is a symlink or a directory junction.

    Read from ``os.lstat`` directly, with every ``OSError`` answering False: on
    CPython 3.10-3.12 ``Path.is_symlink`` lets a ``PermissionError`` from an
    unsearchable parent through, which turned the pre-run link checks into
    tracebacks where no link was there to refuse. A ``ValueError`` answers
    False too: ``os.lstat`` raises it for a path holding a NUL character, which
    no file has, and the report command's output-directory arm reached this
    call with one from a ``--cli-json-input`` document and traced back.
    """
    try:
        found = os.lstat(path)
    except (OSError, ValueError):
        return False
    return stat.S_ISLNK(found.st_mode) or is_junction(path)


def _kind(path: Path) -> str:
    try:
        is_symlink = stat.S_ISLNK(os.lstat(path).st_mode)
    except (OSError, ValueError):
        is_symlink = False
    return "a symlink" if is_symlink else "a directory junction"


def _identity(path: PathLike) -> Optional[Tuple[int, int]]:
    """``(st_dev, st_ino)`` of what ``path`` names, links followed, or None.

    None too on a filesystem that reports no inode numbers, which would otherwise
    make every directory on it the same one, and for a path holding a NUL
    character (``ValueError`` from ``os.stat``), which names no file.
    """
    try:
        found = os.stat(path)
    except (OSError, ValueError):
        return None
    if not found.st_ino:
        return None
    return (found.st_dev, found.st_ino)


def _real_path(path: PathLike) -> Path:
    """``os.path.realpath`` of ``path``, without the Win32 extended-length prefix.

    On Windows, realpath of a path that does not exist yet can come back as
    ``\\\\?\\C:\\dir`` while the same call on its existing parent does not. The two
    spellings do not compare equal, so a not-yet-created output directory below the
    tree was taken for one that resolves outside it.
    """
    real = os.path.realpath(path)
    return Path(without_extended_prefix(real) if os.name == "nt" else real)


def _is_below(path: Path, root: Path, root_identity: Optional[Tuple[int, int]]) -> bool:
    """Whether ``root`` is one of ``path``'s parents, by name, by real path or by identity.

    Compared by device and inode as well as by name, so the answer is the same
    however either path is spelled. A parent that does not exist has no identity
    and is compared by name. The parent is also compared with every link
    resolved: an operator link above the tree that lands in a subdirectory of
    ``root`` (``/opt/link`` to ``<root>/sub``) puts everything spelled below it
    inside the tree, so a repository link at a later component is examined,
    where by name and by identity alone only a parent that IS ``root`` counted.
    """
    named_root = os.path.normcase(root)
    if any(os.path.normcase(parent) == named_root for parent in path.parents):
        return True
    real_root = os.path.normcase(_real_path(root))
    real_parent = _real_path(path.parent)
    if os.path.normcase(real_parent) == real_root or any(
        os.path.normcase(parent) == real_root for parent in real_parent.parents
    ):
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
      so the way either path is spelled does not matter. A ``..`` is applied as
      the kernel applies it, to the directory the components before it lead to
      with their links followed: a link below ``root`` is refused the moment it is
      reached, so the links a ``..`` steps back from are the operator's own, above
      the tree, and stepping back from one lexically examined the components
      after it at paths the lookup never uses, while a repository link at the
      path it does use (``/opt/link/../x`` with ``/opt/link`` leading into the
      tree is ``<root>/x``, not ``/opt/x``) went unexamined;
    - the output directory itself, wherever it is, as that walk reaches it;
    - for an output directory below ``root``, that its real path is below the real
      path of ``root`` too, which catches a redirection out of the tree that the
      walk cannot see;
    - each of OUTPUT_WORKING_DIRS, OUTPUT_RESULT_FILES and OUTPUT_LOG_FILES under
      it, and with ``workspace`` each of WORKSPACE_OUTPUT_DIRS;
    - for an output directory below ``root``, OUTPUT_GITIGNORE, which
      ignore_output_dir_in_git writes there.

    Args:
        root: The scanned tree for a scan; for a workspace project, the workspace's
            output directory, so that ``projects`` and ``projects/<key>`` are
            examined too. None examines no component above the output directory.
        output_dir: The output directory as the operator or the caller spelled it.
        workspace: The output directory is a workspace's.
    """
    spelled = Path(output_dir).absolute()
    # A NUL names no file: os.lstat, os.stat and os.path.realpath raise
    # ValueError for it, which the callers' except clauses (OSError) do not
    # cover, so the report command traced back on a --cli-json-input document
    # whose output directory held one. Refused here, before any of them is asked.
    if "\x00" in str(spelled):
        return (
            f"the output directory {spelled.as_posix()!r} holds a NUL character, "
            "which no path can"
        )
    root_path = Path(os.path.abspath(root)) if root is not None else None
    root_identity = _identity(root_path) if root_path is not None else None
    current = Path(spelled.anchor)
    for part in spelled.parts[1:]:
        if part == "..":
            current = _real_path(current).parent
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
    # The output directory as the lookup reaches it: the spelling with every
    # ``.`` and ``..`` applied. The same path as the spelling when it holds none.
    reached = current
    # ASH's writers open the output directory as written, with ``..`` applied by
    # text (``os.path.abspath``: ``open_no_follow``, ``ignore_output_dir_in_git``,
    # ``scan_output_dirs``). When that names another directory than the one the
    # lookup reaches (``/opt/link/../x`` with ``/opt/link`` leading elsewhere
    # is ``<link's target>/x`` to the kernel and ``/opt/x`` as text), vetting
    # either would leave the other unexamined, so the spelling is refused. One
    # directory under two names (``/tmp/../x`` on macOS, where ``/tmp`` is a
    # link) is compared with both resolved and passes.
    written = Path(os.path.abspath(spelled))
    if os.path.normcase(_real_path(written)) != os.path.normcase(_real_path(reached)):
        return (
            f"the output directory {spelled.as_posix()} steps back through a "
            f"link with ..: the lookup reaches {reached.as_posix()} while the "
            f"path as written names {written.as_posix()}; spell it without .. or "
            "as the directory it reaches"
        )
    where = _shown(spelled, reached)
    if is_link(reached):
        return f"the output directory {where} is {_kind(reached)}"
    inside_root = root_path is not None and _is_below(reached, root_path, root_identity)
    if root_path is not None and inside_root:
        real_root = _real_path(root_path)
        actual = _real_path(reached)
        if not _is_below(actual, real_root, root_identity):
            return (
                f"the output directory {reached.as_posix()} resolves to "
                f"{actual.as_posix()}, outside {root_path.as_posix()}"
            )
    names: Tuple[str, ...] = (
        OUTPUT_WORKING_DIRS + OUTPUT_RESULT_FILES + OUTPUT_LOG_FILES
    )
    if workspace:
        names += WORKSPACE_OUTPUT_DIRS
    if inside_root:
        names += (OUTPUT_GITIGNORE,)
    for name in names:
        entry = reached / name
        if is_link(entry):
            return f"{entry.as_posix()} is {_kind(entry)}"
    return None


def _shown(spelled: Path, reached: Path) -> str:
    """``spelled`` for a message, with the path the lookup reaches when it differs."""
    if os.path.normcase(os.path.abspath(spelled)) == os.path.normcase(reached):
        return spelled.as_posix()
    return f"{spelled.as_posix()} (reached as {reached.as_posix()})"


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


def ignore_output_dir_in_git(source_dir: PathLike, output_dir: PathLike) -> bool:
    """Write OUTPUT_GITIGNORE, ignoring everything, in an output directory in the tree.

    A tool that reads the scanned tree itself and honors the ``.gitignore`` files in
    it then leaves ASH's output out: an earlier run's reports and logs, and the
    converted files. ``snyk code test`` is one (read from snyk's sources, not
    measured): it uploads the files it reads and has no option that leaves out a
    path, and the default output directory, ``.ash/ash_output``, is inside the tree.
    ``ash config init`` writes ``.ash/.gitignore`` for the same reason, but a tree
    that never had one sent ASH's output with the source. ASH's own scan set leaves
    the output directory out whatever the ignore files say.

    Nothing is written when the output directory is not below ``source_dir`` or does
    not exist, or when something is already at the name: a ``.gitignore`` there is
    the repository's or an earlier run's, and is left as it is. Nothing is written
    either when git lists files committed under the output directory
    (``scan_output_dirs.git_index_below``): the directory is then partly the
    repository's, and an ignore-everything rule there would make git ignore every
    new file a developer adds beside the committed ones. A link at the name is
    refused, never followed: linked_output_component names it before the run, and
    the write itself is fs_guard.open_for_write with the output directory as its
    root and O_EXCL, which refuses one made since with OutputLinkRefused. Any other
    failure of the write (a read-only output directory, say) answers False: the
    file is a courtesy to tools that read the tree themselves, and a scan is not
    aborted over it.

    Returns:
        Whether it wrote the file.
    """
    source = Path(os.path.abspath(source_dir))
    output = Path(os.path.abspath(output_dir))
    try:
        is_dir = output.is_dir()
    except OSError:
        return False
    if not is_dir or not _is_below(output, source, _identity(source)):
        return False
    # Imported here: fs_guard imports this module (see open_no_follow), and
    # scan_output_dirs is above it.
    from automated_security_helper.utils.sandbox import fs_guard
    from automated_security_helper.utils.scan_output_dirs import git_index_below

    if git_index_below(output).names:
        return False
    try:
        with fs_guard.open_for_write(
            output / OUTPUT_GITIGNORE, root=output, exclusive=True
        ) as handle:
            handle.write(OUTPUT_GITIGNORE_TEXT)
    except OutputDirLinkRefused:
        raise
    except FileExistsError:
        return False
    except OSError:
        return False
    return True


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
