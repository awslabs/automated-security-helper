# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Where a scan looked, as the scan records it on its results.

``metadata.scan_source`` is the scanned directory relative to the root of the git
repository it is in. The aws-security-hub reporter records it on every finding
(``ash/scope``) and archives a stored finding only when it was found under the
same one, so a scan of ``services/api`` does not archive what a scan of the whole
repository found. It is recorded at scan time, while the directory exists, so a
report made where it does not, such as ``ash merge`` on a collector without the
checkout or ``ash report`` on another host, does not work it out there, where it
would get an absolute path, not the shards' ``.``, and archive nothing.

None, which archives nothing, is recorded wherever the label could name two
different directories:

- Inside a repository that sits below another one: a git submodule, a clone in
  another repository's work tree, or any repository under an enclosing one (a
  home directory kept in git). git answers with the innermost repository, so its
  root was labeled ``.`` like the outer one's, and a scan of ``vendor/lib``
  shared a scope with a scan of the whole repository. A linked worktree of the
  same repository inside the checkout is not nested, but only one the outer
  repository's ``git worktree list`` names, that shares its git directory, and
  that its admin dir records: a ``.git`` file or symlink planted in a
  subdirectory and pointing at the outer git dir is, and so is another
  repository made where a listed worktree was (``repository_is_nested``).
  GIT_CEILING_DIRECTORIES hides the outer repository only when that repository
  neither tracks the inner one nor lists it as untracked: a ceiling does not
  make a submodule or a nested clone a root.
- In a scan the container launcher started, when the host could not work the
  label out. There the scanned directory is always ``/src``, and git sees only
  the mount: a subdirectory mount has no ``.git``, a linked worktree's ``.git``
  file names a host path, git refuses a mount it does not own, and a nested
  clone's mount looks like a repository with nothing above it. The launcher
  therefore works the label out on the host (``host_scan_source_label``) and
  always passes it as ``ASH_SCAN_SOURCE``, empty when it has none.
- When the label is not UTF-8. The results file is, and a label that is not
  made its write fail.
- In a scan the legacy ``./ash`` or ``Invoke-ASH`` (``ash_helpers.ps1``)
  wrapper started, or a hand-written ``docker run -v "$PWD:/src"``. These mount
  the directory at ``/src`` or set ``ASH_ACTUAL_SOURCE_DIR``, like the launcher,
  but pass no ``ASH_SCAN_SOURCE``, and git in the container cannot tell a nested
  clone's mount from a repository's root.

The ASH image run any other way (as a CI job image, for example) scans its own
directory and records it as a scan on a host would.
"""

from __future__ import annotations

import errno
import os
import re
import stat
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Callable, Mapping, Optional

from automated_security_helper.utils.get_scan_set import (
    git_absolute_git_dir,
    git_common_dir,
    git_index_paths_below,
    git_untracked_paths_below,
    git_worktree_paths,
)
from automated_security_helper.utils.output_dir_links import same_by_identity
from automated_security_helper.utils.scanned_tree import _is_link_stat

#: Set by the container launcher (run_ash_container) to the label it worked out
#: on the host, "" when it has none. Read only in a scan the launcher started.
SCAN_SOURCE_ENV = "ASH_SCAN_SOURCE"

#: Set by the ASH image itself (Dockerfile: ``ENV ASH_IN_CONTAINER="YES"``).
_IN_CONTAINER_ENV = "ASH_IN_CONTAINER"

#: Set by the container launcher on every run it starts (run_ash_container), and
#: by the legacy wrappers.
_LAUNCHER_SOURCE_ENV = "ASH_ACTUAL_SOURCE_DIR"

#: Where the launcher, and the legacy wrappers, mount the scanned directory.
_CONTAINER_SOURCE_MOUNT = "/src"

# One path segment: no separator, no ";" (which separates the parts of
# ash/scope), no control character: neither a C0 control or DEL nor a C1 control
# (U+0080 to U+009F, NEL among them). Matched whole (``fullmatch``): a ``$``
# anchor matches before a final newline, so a segment ending in one passed.
_SEGMENT = re.compile(r"[^/\\;\x00-\x1f\x7f\x80-\x9f]+")

FindRoot = Callable[[Path], Optional[Path]]
IsNested = Callable[[Path], bool]


def scan_source_label(source_dir: Path | str, repository_root: Optional[Path]) -> str:
    """*source_dir* relative to *repository_root*, or its absolute path.

    Args:
        source_dir: The scanned directory. A relative path is resolved against
            the current directory.
        repository_root: The root of the git repository containing it, as
            ``get_scan_set.git_repository_root`` returns it, or None when it is
            not inside a repository or git could not say.

    Returns:
        ``.`` for the repository root, ``services/api`` for a directory below it,
        and the resolved absolute path with ``/`` separators when there is no
        root or the root does not contain the directory. Whether the root
        contains the directory is decided by the text first and then by
        identity (``_relative_by_identity``): on a volume that compares names
        without regard to case, a directory spelled in another case than git's
        toplevel is inside it, and the text alone fell back to the absolute path.
    """
    resolved = Path(source_dir).resolve()
    if repository_root is not None:
        relative = _relative_by_identity(resolved, Path(repository_root).resolve())
        if relative is not None:
            return relative
    return resolved.as_posix()


def _relative_by_identity(path: Path, root: Path) -> Optional[str]:
    """*path* below *root* with ``/`` separators, ``.`` for *root* itself, or None.

    By text (``relative_to``) first; when the text says *path* is not below
    *root*, each of *path* and its parents is compared with *root* by identity
    (``same_by_identity``: device and inode), and the parts below the one that is
    *root* are the answer. A path that does not exist has no identity, so a
    nonexistent directory is decided by the text, as before. A mount that reports
    inode 0 for every file gives no identity either: ``os.path.samefile`` read
    every directory on it as *root*, and an outside directory was labeled as
    inside the repository.
    """
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        pass
    for ancestor in (path, *path.parents):
        if same_by_identity(ancestor, root):
            rest = path.parts[len(ancestor.parts) :]
            return PurePosixPath(*rest).as_posix() if rest else "."
    return None


def _is_utf8(label: str) -> bool:
    try:
        label.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def is_relative_scan_source(label: object) -> bool:
    """Whether *label* is ``.`` or a plain relative path below a repository root.

    ``/`` separators, no empty, ``.`` or ``..`` segment, no ``;`` or control
    character, no Windows drive (a first segment such as ``C:`` or ``a:b``), and
    UTF-8. The only labels the container launcher passes, and the only ones a
    scan it started accepts from it.
    """
    if not isinstance(label, str) or not _is_utf8(label):
        return False
    if label == ".":
        return True
    if PureWindowsPath(label).drive:
        return False
    segments = label.split("/")
    return all(
        _SEGMENT.fullmatch(segment) and segment not in (".", "..")
        for segment in segments
    )


def _ceiling_entries() -> list[str]:
    """GIT_CEILING_DIRECTORIES as git reads it, each entry as git compares it.

    git (setup.c, ``canonicalize_ceiling_entry``) splits the variable on the path
    separator and drops empty and relative entries. An entry before the first
    empty one is resolved to its real path, and dropped when that fails (a
    missing directory before a ``..``, a symlink loop); an entry after an empty
    one is kept as written, and so matches only a directory spelled exactly
    that way. A resolved entry is returned with ``/`` separators, the way the
    walk spells a directory; one kept as written is returned unchanged.

    Read from the process environment, not from the mapping
    ``recorded_scan_source`` is given: git, which found the root the nesting
    walk starts from, reads it there, and a walk that honored a different
    ceiling would disagree with that root. Where this cannot match git, it
    honors fewer ceilings, never more: an entry it cannot resolve is dropped,
    and the comparison is case-sensitive.
    """
    value = os.environ.get("GIT_CEILING_DIRECTORIES", "")
    entries: list[str] = []
    after_empty = False
    for entry in value.split(os.pathsep) if value else []:
        if not entry:
            after_empty = True
            continue
        if not os.path.isabs(entry):
            continue
        if after_empty:
            entries.append(entry)
            continue
        try:
            entries.append(Path(os.path.realpath(entry, strict=True)).as_posix())
        except (OSError, ValueError):
            continue
    return entries


def _is_ceiling(directory: Path, entries: list[str]) -> bool:
    """Whether git does not move up into *directory* (setup.c,
    ``longest_ancestor_length``): an entry names it exactly, one trailing ``/``
    on either side aside (so ``/`` names the root)."""
    name = directory.as_posix().removesuffix("/")
    return any(entry.removesuffix("/") == name for entry in entries)


class _WorktreeCheck:
    """Whether *root* is a linked worktree of an ancestor's repository.

    It takes all of these:

    - *root* is one of the worktrees ``git worktree list`` names for the
      ancestor, compared as git printed it (``git_worktree_paths``). With
      absolute worktree paths, git's default, this tells a worktree from a
      ``.git`` file planted in a subdirectory and pointing at the outer git dir
      or at a real worktree's admin dir, or a symlink put where a listed
      worktree was: those share the common dir.
    - *root*'s ``--git-common-dir`` is the ancestor's (``git_common_dir``). This
      tells a worktree from another repository made at a listed path that was
      deleted without ``git worktree prune``: git still lists it.
    - *root* is the worktree the ancestor registered (``_registered_worktree``):
      its git dir is an admin dir in the ancestor's ``worktrees/``, and that
      admin dir's ``gitdir`` names *root*. With relative worktree paths
      (``worktree.useRelativePaths``, git 2.48+), git resolves the recorded
      path when it lists it, so the list follows a symlink put at or above a
      listed path; this check reads the record without resolving it. It also
      tells a worktree from a git dir of its own put at a listed path whose
      ``commondir`` names the outer git dir, which passes the other two.

    When git cannot give an answer, it is not a worktree. *root*'s own common
    dir is asked for once. The ancestor's comes from the caller, which asked for
    it before checking the admin dirs under it.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self._own: Optional[Path] = None
        self._own_known = False

    def own_common(self) -> Optional[Path]:
        """*root*'s own common dir (``git_common_dir``), asked for once."""
        if not self._own_known:
            self._own = git_common_dir(self.root)
            self._own_known = True
        return self._own

    def of(self, ancestor: Path, common: Path) -> bool:
        """Whether *root* is a linked worktree of *ancestor*, whose common dir is
        *common*."""
        worktrees = git_worktree_paths(ancestor)
        if worktrees is None or self.root not in worktrees:
            return False
        own = self.own_common()
        if own is None:
            return False
        return common == own and _registered_worktree(self.root, common)


#: What a gitfile starts with. git's own rule (setup.c, ``read_gitfile_gently``)
#: is ``"gitdir: "`` with a trailing space; this prefix is deliberately one
#: byte looser, so ``gitdir:/x``, which git refuses, still counts -- the side
#: that errs toward "nested". Do not tighten it to git's exact form on the
#: belief that it already matches git. A file without it marks nothing.
_GITFILE_PREFIX = b"gitdir:"


def _gitfile_shaped(entry: Path) -> bool:
    """Whether the regular file at *entry* starts the way a gitfile does.

    One that cannot be opened or read counts: a repository marker cannot be
    ruled out there, and for nesting the walk fails closed. Opened with
    ``_RECORD_OPEN_FLAGS`` and re-checked with ``fstat``, in the order its
    sibling ``_read_gitdir_record`` uses: where O_NOFOLLOW and O_NONBLOCK
    exist, the open neither follows a link nor waits for a FIFO's writer,
    and whatever a swap put there after the caller's ``lstat`` that is not
    a regular file counts without being read. On Windows, where those flags
    are 0, the ``fstat`` refusal is what keeps a swapped-in symlink to a
    named pipe from reaching the read, which could wait on the pipe's
    server; the open itself still connects, as the sibling documents.
    """
    try:
        fd = os.open(entry, _RECORD_OPEN_FLAGS)
    except OSError:
        return True
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return True
        head = os.read(fd, len(_GITFILE_PREFIX))
    except OSError:
        return True
    finally:
        os.close(fd)
    return head == _GITFILE_PREFIX


def _marks_a_checkout(entry: Path) -> bool:
    """Whether the ``.git`` at *entry* is shaped like a marker git's own
    discovery reads.

    Like the shape test of ``sandbox_grants._git_shaped``, asked of a scan
    root's ancestors, with one deliberate difference: a regular file counts
    only in git's gitfile format (``_gitfile_shaped``), where ``_git_shaped``
    counts any regular file. For a regular file the checkout boundary errs
    toward confining --
    counting a stray non-gitfile ``.git`` there only widens what is read as
    the untrusted repository's -- while this walk follows git's own
    repository discovery, because a wrong "nested" costs a real repository
    its scan source. What counts: a gitfile (as a
    submodule's or a linked worktree's ``.git`` is), a symlink or a junction
    (``_is_link_stat``, counted even dangling: placed content, and wrongly
    answering "not nested" is the unsafe direction), or a directory holding
    ``HEAD`` (git itself also wants objects and refs, so a bare ``HEAD``
    errs toward "nested"). A bare empty ``.git`` directory -- what a
    stray mkdir or a transient mount point leaves -- an unrelated regular
    file, a ``HEAD``-less directory with other content, or a special file is
    none of these: git opens none of them, and counting one would call every
    repository below that ancestor nested and cost it its scan source.

    An entry that cannot be judged (a directory whose ``HEAD`` lookup is
    refused, a file whose first bytes cannot be read) counts: nesting cannot
    be ruled out there. The trust half of ``_git_shaped``
    (``sandbox_grants._left_by_a_trusted_user``) stays out of this walk on
    purpose: a stranger's repository above *root* still covers *root* in its
    own scans, so for nesting a stranger's entry counts too.
    """
    try:
        looked_up = os.lstat(entry)
    except OSError as error:
        # Only proof of absence answers False. A lookup refused or failing
        # any other way (EACCES, EIO, ESTALE) leaves the entry unjudged,
        # and the walk fails closed, as the HEAD lookup below does.
        return error.errno not in (errno.ENOENT, errno.ENOTDIR)
    if _is_link_stat(looked_up):
        return True
    if stat.S_ISREG(looked_up.st_mode):
        return _gitfile_shaped(entry)
    if not stat.S_ISDIR(looked_up.st_mode):
        return False
    try:
        os.lstat(os.path.join(entry, "HEAD"))
    except OSError as error:
        return error.errno != errno.ENOENT
    return True


def _hidden_repository_holds(
    root: Path, ceiling: Path, worktree: _WorktreeCheck
) -> bool:
    """Whether a repository a ceiling hides would count *root* as its own.

    Every repository at or above *ceiling* -- a git-shaped ``.git``
    (``_marks_a_checkout``) -- is asked (``_repository_holds``),
    not only the nearest one, which is the one git finds without the ceiling:
    the nearest can ignore *root* while one above it tracks a gitlink between
    them, or lists the nearest one's checkout as untracked and so covers it in
    its own scans. *root* is held when any of them holds it.
    """
    return any(
        _marks_a_checkout(candidate / ".git")
        and _repository_holds(root, candidate, worktree)
        for candidate in (ceiling, *ceiling.parents)
    )


def _repository_holds(root: Path, hidden: Path, worktree: _WorktreeCheck) -> bool:
    """Whether the repository at *hidden*, above *root*, counts *root* as its own.

    It holds *root* when it tracks *root*, a path between them (a gitlink, or a
    file where *root* now has a directory), or anything below *root*; or when it
    lists *root*, or a directory between, as untracked and not ignored. A scan of
    that repository then covers *root*'s files under its own ``.``, so *root*'s
    ``.`` would collide with it. A linked worktree of the repository is not held.
    Any other root whose common dir is the repository's is held, whatever the
    index says: a ``.git`` file or symlink naming that git dir, or one of its
    admin dirs, in a directory the repository ignores. When git cannot answer for
    the repository or for *root*, it holds *root*, and so it does when the
    repository's worktree admin dirs hold anything but regular files and
    directories (``_admin_dirs_are_plain``), which git would wait on; that check
    is made only when the worktree listing it guards is needed, which is when
    *root*'s own common dir is the repository's or is unknown. The repository's
    ``.git`` entry itself is checked the same way before git is started on it
    (``_git_entry_is_plain``): git reads HEAD and config there first.
    """
    if not _git_entry_is_plain(hidden / ".git"):
        return True
    common = git_common_dir(hidden)
    if common is None:
        return True
    own = worktree.own_common()
    if own is None or own == common:
        if not _admin_dirs_are_plain(common):
            return True
        if worktree.of(hidden, common):
            return False
        # Not one of its worktrees, yet sharing its git dir (a .git file or
        # symlink naming it or one of its admin dirs, in a directory it ignores):
        # a scan of *root* reads the hidden repository's index.
        return True
    parts = root.relative_to(hidden).parts
    relative = "/".join(parts)
    between = ["/".join(parts[:depth]) for depth in range(1, len(parts))]
    # Each listing covers *root* and what is below it, and each path between
    # exactly: a listing of parts[0] would read every path beside *root* too.
    tracked = git_index_paths_below(hidden, relative, exactly=between)
    untracked = git_untracked_paths_below(hidden, relative, exactly=between)
    if tracked is None or untracked is None:
        return True
    below = relative + "/"
    tracked_between = set(between)
    # git lists an untracked directory with a trailing "/".
    untracked_between = {path + "/" for path in between}
    return any(
        path == relative or path.startswith(below) or path in tracked_between
        for path in tracked
    ) or any(
        path == relative or path.startswith(below) or path in untracked_between
        for path in untracked
    )


def repository_is_nested(root: Path) -> bool:
    """Whether the repository at *root* sits below another repository.

    Decided on the filesystem: a proper ancestor of *root* holds a git-shaped
    ``.git`` entry (``_marks_a_checkout``; a bare empty ``.git`` directory or
    a stray file without the gitfile format nests nothing). Asking git about
    the parent instead would fail open wherever git
    refuses to read it (safe.directory). The one exception to an ancestor's
    ``.git`` is
    a linked worktree of its repository inside its own checkout
    (``_WorktreeCheck``).

    GIT_CEILING_DIRECTORIES is read as git reads it (``_ceiling_entries``), and
    git does not look at a listed directory or above it. The walk stops there
    too, but only when the repository the ceiling hides would not count *root*
    as its own (``_hidden_repository_holds``): it does not track *root* or a path
    between them, as a submodule's gitlink, and does not list *root* as
    untracked and not ignored. Otherwise the ceiling changes nothing, as if it
    were not set: a submodule, a nested clone or a planted gitfile below a
    ceiling recorded ``.`` like its superproject, and archiving could mark the
    superproject's active findings archived. The ceiling stays an opt-out for a
    checkout under an enclosing repository that ignores it (a home directory
    kept in git).

    An ancestor whose worktree admin dirs hold anything but regular files and
    directories (``_admin_dirs_are_plain``) counts as nesting too, which is
    decided before git lists them; so does one whose ``.git`` entry holds such a
    thing where git reads it first, its HEAD, config or commondir
    (``_git_entry_is_plain``), decided before git is started on it at all. git
    was asked for the common dir first, and a FIFO HEAD in an ancestor's
    ``.git`` held that call, and the scan, for git's 30-second timeout.
    """
    resolved = Path(root).resolve()
    ceilings = _ceiling_entries()
    worktree = _WorktreeCheck(resolved)
    # Every check below depends on the ancestor only through its common dir: its
    # worktree list is the repository's. So an ancestor that shares a common dir
    # already verified (a chain of worktrees nested inside one another) gives the
    # same answer, and is not listed and checked again.
    verified: set[Path] = set()
    for ancestor in resolved.parents:
        if _is_ceiling(ancestor, ceilings):
            return _hidden_repository_holds(resolved, ancestor, worktree)
        if not _marks_a_checkout(ancestor / ".git"):
            continue
        if not _git_entry_is_plain(ancestor / ".git"):
            return True
        common = git_common_dir(ancestor)
        if common is not None and common in verified:
            continue
        if common is None or not _admin_dirs_are_plain(common):
            return True
        if worktree.of(ancestor, common):
            verified.add(common)
            continue
        return True
    return False


#: What git itself requires a gitfile to start with (setup.c,
#: ``read_gitfile_gently``): the word, the colon and one space. The path is
#: everything after it. ``_GITFILE_PREFIX`` above is the looser test for
#: "marks a checkout"; this one decides which directory git opens.
_GITFILE_RECORD_PREFIX = "gitdir: "


def _git_entry_is_plain(entry: Path) -> bool:
    """Whether git can start on the repository whose ``.git`` is *entry* without
    waiting on what it reads first: the git dir's HEAD, config and commondir,
    and the common dir's config.

    *entry* is a ``.git`` directory, a gitfile naming the git dir, or a symlink
    to either (``_marks_a_checkout`` counted it). Each of the three files must be
    plain (``_plain_entry``) in the git dir the entry leads to, and so must
    ``config`` in the common dir that git dir's ``commondir`` names
    (``_common_dir_named``): git's repository-format check reads it next, and
    for a linked worktree that is ``<common>/config``, which the admin dir does
    not hold, so a FIFO there held ``git_common_dir`` for git's timeout while
    the admin dir's own three files read plain.

    A gitfile is parsed as git parses it: the exact prefix ``gitdir: ``, then
    everything after it with only trailing carriage returns and newlines
    dropped (as ``_registered_worktree`` reads a ``gitdir`` record). Stripping
    the rest read ``gitdir: /x `` as ``/x`` while git opens ``/x `` (trailing
    space), so the directory checked was not the one git would wait in. A
    record without the exact prefix is one git refuses ("invalid gitfile
    format"), so git starts on nothing through it; it counts as not plain, the
    side that errs toward nested, as ``_marks_a_checkout`` counts it. A gitfile
    whose record cannot be read, or that names something that is not a
    directory, counts as not plain too: the entry marked a checkout, and what
    git would read there cannot be ruled out. Asked before ``git_common_dir``
    runs on the directory, which read those files and waited on a FIFO there
    for git's 30-second timeout.
    """
    try:
        looked_up = os.lstat(entry)
    except OSError:
        return False
    if _is_link_stat(looked_up):
        git_dir = Path(os.path.realpath(entry))
    elif stat.S_ISREG(looked_up.st_mode):
        record = _read_gitdir_record(entry)
        if record is None:
            return False
        text = record.rstrip("\r\n")
        if not text.startswith(_GITFILE_RECORD_PREFIX):
            return False
        named = text[len(_GITFILE_RECORD_PREFIX) :]
        if not named:
            return False
        git_dir = Path(os.path.normpath(os.path.join(entry.parent, named)))
    else:
        git_dir = entry
    try:
        if not stat.S_ISDIR(os.lstat(git_dir).st_mode):
            return False
    except OSError:
        return False
    if not all(
        _plain_entry(git_dir / name) for name in ("HEAD", "config", "commondir")
    ):
        return False
    common = _common_dir_named(git_dir)
    if common is None:
        return False
    return common == git_dir or _plain_entry(common / "config")


def _common_dir_named(git_dir: Path) -> Optional[Path]:
    """The common dir of the repository whose git dir is *git_dir*, read as git
    reads it (setup.c, ``get_common_dir_noenv``): *git_dir* itself when no
    ``commondir`` file is there; otherwise the file's text with trailing carriage
    returns and newlines dropped, joined under *git_dir* unless absolute. None
    when something is at the name that is not a record ``_read_gitdir_record``
    can read: what git would open there cannot be told.
    """
    path = git_dir / "commondir"
    try:
        os.lstat(path)
    except FileNotFoundError:
        return git_dir
    except OSError:
        return None
    record = _read_gitdir_record(path)
    if record is None:
        return None
    return Path(os.path.normpath(os.path.join(git_dir, record.rstrip("\r\n"))))


def _admin_dirs_are_plain(common: Path) -> bool:
    """Whether ``git worktree list`` can read what it reads under *common*
    without waiting.

    It reads every admin dir under ``worktrees/`` (its gitdir, its HEAD and the
    rest), each worktree's HEAD target, packed-refs when a ref is packed, and the
    reftable stack when the repository keeps its refs there. It follows a symlink
    and waits on a FIFO there: a FIFO as a peer's gitdir or HEAD, as the branch a
    HEAD names, or as packed-refs held the listing, and so the scan, for git's
    30-second timeout (git 2.50). So each of those must be a regular file, a
    directory or a socket (``_plain_mode``), checked down every level of each
    admin dir. Other loose refs are not read, so they are not checked. With no
    ``worktrees`` directory there are no admin dirs to read, and a regular file
    at that name is the same: git lists no linked worktree and waits on nothing,
    where this once read the failed listing of it as not plain.
    """
    if not _plain_entry(common / "packed-refs"):
        return False
    if not _optional_tree_is_plain(common / "reftable"):
        return False
    if not _head_target_is_plain(common / "HEAD", common):
        return False
    worktrees = common / "worktrees"
    try:
        mode = os.lstat(worktrees).st_mode
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if not _plain_mode(mode):
        return False
    if not stat.S_ISDIR(mode):
        return True
    try:
        with os.scandir(worktrees) as entries:
            admin_dirs = [Path(entry.path) for entry in entries]
    except FileNotFoundError:
        return True
    except OSError:
        return False
    for admin_dir in admin_dirs:
        if not (
            _tree_is_plain(admin_dir)
            and _head_target_is_plain(admin_dir / "HEAD", common, admin=admin_dir)
        ):
            return False
    return True


def _optional_tree_is_plain(top: Path) -> bool:
    """``_tree_is_plain`` of *top*, True when there is nothing at *top*."""
    try:
        os.lstat(top)
    except (FileNotFoundError, NotADirectoryError):
        return True
    except (OSError, ValueError):
        return False
    return _tree_is_plain(top)


def _plain_mode(mode: int) -> bool:
    """Whether git reads an entry of *mode*, or fails on it, without waiting.

    A regular file or a directory, or a socket: git cannot open a socket
    (ENXIO), and macOS's builtin fsmonitor keeps one in a linked worktree's
    admin dir. Not a FIFO or a device, which git waits on, and not a symlink,
    which it follows.
    """
    return stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISSOCK(mode)


def _plain_entry(path: Path) -> bool:
    """Whether the entry at *path* is plain (``_plain_mode``), or is not there:
    a path below a file is not there either."""
    try:
        return _plain_mode(os.lstat(path).st_mode)
    except (FileNotFoundError, NotADirectoryError):
        return True
    except (OSError, ValueError):  # ValueError: a NUL in the path
        return False


def _tree_is_plain(top: Path) -> bool:
    """Whether *top* and everything below it is plain (``_plain_mode``).

    Walked without following a symlink or, on Windows, a directory junction
    (``_is_link_stat``; the mode alone read a junction as a directory and the
    walk went through it), and without recursion, so a deep tree cannot exhaust
    the stack. An entry that is gone between the listing and its stat (a lock
    file git wrote and renamed meanwhile, a worktree pruned) is nothing git
    would wait on, and is skipped; read as not plain, a concurrent git operation
    in another worktree cost this one its scan source."""
    if not _plain_entry(top):
        return False
    pending = [top]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    if _is_link_stat(info):
                        return False
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(Path(entry.path))
                    elif not _plain_mode(info.st_mode):
                        return False
        except (NotADirectoryError, FileNotFoundError):
            continue
        except OSError:
            return False
    return True


#: How many symbolic refs git follows from a HEAD (SYMREF_MAXDEPTH).
_SYMREF_DEPTH = 5

#: What git takes as whitespace around a ref file's contents: space, tab,
#: carriage return and newline, and not a vertical tab or form feed.
_GIT_SPACE = " \t\r\n"

#: The ref namespaces git keeps per worktree, in a linked worktree's admin dir
#: rather than under the common dir (refs.c, ``is_per_worktree_ref``).
_PER_WORKTREE_REFS = ("worktree", "bisect", "rewritten")

#: The most of a HEAD or ref file that is read to follow it. git reads the whole
#: file; one past this size is counted as not plain rather than read.
_REF_RECORD_LIMIT = 1 << 20


def _head_target_is_plain(
    head: Path, common: Path, *, admin: Optional[Path] = None
) -> bool:
    """Whether the refs *head* names under *common*, one symbolic ref after
    another, are plain.

    *admin* is the admin dir of the linked worktree whose HEAD *head* is, when it
    is one: a name in a per-worktree namespace (``_PER_WORKTREE_REFS``) is looked
    up there, as git looks it up, and not under *common*, where it is not. The
    common dir's own HEAD has no admin dir, and its per-worktree refs are its
    own. A HEAD that is not there, holds a commit id, or names a ref with no
    loose file names nothing to wait on. A name with an empty, ``.`` or ``..``
    part, which git refuses, is not followed out of the refs and counts as not
    plain.

    A HEAD that is a symlink (``core.preferSymlinkRefs``) is read as git reads
    it: the link's text, when it starts with ``refs/``, is the ref name, and the
    link is not followed as a file. Any other symlink is one git opens through,
    and counts as not plain. A HEAD or ref file larger than
    ``_REF_RECORD_LIMIT`` counts as not plain too: git reads it whole, so the
    name it holds after any amount of padding is followed, where a bounded read
    once took it for a file naming nothing.

    Each file is read as git reads it (measured with git 2.50): whitespace at
    the end (``_GIT_SPACE``) is dropped, a symbolic ref is ``ref:``, then any
    run of it, then the name, and the name ends at a NUL, since git reads the
    rest as a C string. Dropping only a final newline followed a CRLF HEAD to a
    name ending in a carriage return, a file that is not there, and did not
    follow ``ref:`` with no space at all, while git read the branch.
    """
    path = head
    for _ in range(_SYMREF_DEPTH):
        try:
            looked_up = os.lstat(path)
        except (FileNotFoundError, NotADirectoryError):
            return True
        except (OSError, ValueError):  # ValueError: a NUL in the path
            return False
        if stat.S_ISLNK(looked_up.st_mode):
            try:
                text = os.readlink(path)
            except OSError:
                return False
            if not text.startswith("refs/"):
                return False
            parts = text.split("/")
        else:
            if not _plain_mode(looked_up.st_mode):
                return False
            if looked_up.st_size > _REF_RECORD_LIMIT:
                return False
            record = _read_gitdir_record(path, limit=_REF_RECORD_LIMIT)
            if record is None:
                return True
            text = record.rstrip(_GIT_SPACE).split("\0", 1)[0]
            if not text.startswith("ref:"):
                return True
            parts = text[len("ref:") :].lstrip(_GIT_SPACE).split("/")
        if parts[0] != "refs" or any(part in ("", ".", "..") for part in parts):
            return False
        base = common
        if admin is not None and len(parts) > 2 and parts[1] in _PER_WORKTREE_REFS:
            base = admin
        path = base.joinpath(*parts)
    return _plain_entry(path)


def _registered_worktree(root: Path, common: Path) -> bool:
    """Whether *root* is the linked worktree registered under *common*.

    *root*'s git dir (``git_absolute_git_dir``) is ``<common>/worktrees/<id>``,
    and the ``gitdir`` file there names ``<root>/.git``. That file holds an
    absolute path, or one relative to the admin dir under
    ``worktree.useRelativePaths``; it is joined and normalized as text, not
    resolved, so a symlink at or above the recorded path does not make it name
    whatever the symlink now points at. *root* is already resolved.
    """
    git_dir = git_absolute_git_dir(root)
    if git_dir is None or git_dir.parent != common / "worktrees":
        return False
    recorded = _read_gitdir_record(git_dir / "gitdir")
    if recorded is None:
        return False
    # git ends the line with a newline. Reading it back, it trims any run of
    # carriage returns and newlines at the end, and no other whitespace (measured
    # with git 2.50), so this trims the same: what is left is the path git lists.
    recorded = recorded.rstrip("\r\n")
    if not recorded:
        return False
    named = os.path.normpath(os.path.join(git_dir, recorded))
    # Compared as the platform compares paths (``os.path.normcase``: without
    # regard to case on Windows), as ``_WorktreeCheck.of`` compares the listed
    # worktree paths; a text comparison refused a record spelled in another case
    # than the resolved root there.
    return os.path.normcase(named) == os.path.normcase(os.path.join(root, ".git"))


#: PATH_MAX on Linux. A gitdir record holds one path and a newline.
_GITDIR_RECORD_LIMIT = 4096

#: How a gitdir record is opened. O_NOFOLLOW and O_NONBLOCK are 0 where the
#: platform has none (Windows), so there the open follows a symlink; Windows has
#: no FIFO for it to wait on.
_RECORD_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_BINARY", 0)
)


def _read_gitdir_record(
    path: Path, *, limit: int = _GITDIR_RECORD_LIMIT
) -> Optional[str]:
    """The text of a worktree admin dir's ``gitdir`` file, or None.

    Read only when the entry itself is a regular file of at most *limit* bytes
    (``_GITDIR_RECORD_LIMIT``, the size of one path, by default; a HEAD or ref
    file is read up to ``_REF_RECORD_LIMIT``). A FIFO there blocked the scan for good, and a
    symlink was followed to whatever it named. The entry is checked before the
    open: where O_NOFOLLOW is 0 (Windows), the open follows a symlink and fstat
    then sees its target. Where the flags exist, the open does not follow a
    symlink or wait for a writer, and fstat checks again what was opened, in
    case the entry was replaced in between. Anything else, or any error, is
    None: not a record.

    On Windows a race remains between the entry check and the open: an entry
    swapped in between for a symlink to a regular file holding a valid record
    is followed, and fstat passes it. The size limit still holds, and the answer
    is one yes or no. Only a writer of the outer git dir's ``worktrees/<id>/``
    can make that swap, and that writer can put a regular record there
    directly, which ``git worktree list`` follows as well, with no race. An
    entry swapped in for a symlink to a named pipe is opened too, which connects
    to the pipe's server, before fstat refuses it.
    """
    if not _is_regular_file(path):
        return None
    try:
        fd = os.open(path, _RECORD_OPEN_FLAGS)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        data = b""
        # One byte past the limit tells a file that fits from a longer one.
        while len(data) <= limit:
            chunk = os.read(fd, limit + 1 - len(data))
            if not chunk:
                break
            data += chunk
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(data) > limit:
        return None
    # git writes the path as the bytes of its name, so the record is decoded as
    # Python decodes that name (os.fsdecode). On Windows, where that is strict
    # UTF-8, a record that isn't UTF-8 is not a record.
    try:
        return os.fsdecode(data)
    except UnicodeDecodeError:
        return None


def _is_regular_file(path: Path) -> bool:
    """Whether the entry at *path*, not a symlink's target, is a regular file."""
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except (OSError, ValueError):  # ValueError: a NUL in the path
        return False


def _repository_root(
    source_dir: Path | str, find_root: FindRoot, is_nested: Optional[IsNested]
) -> tuple[Optional[Path], bool]:
    """The repository root *find_root* reports for *source_dir*, and whether that
    repository is nested (see ``repository_is_nested``)."""
    root = find_root(Path(source_dir))
    if root is None:
        return None, False
    # Looked up when called, not bound as a default, so a test can stand in for it.
    check = is_nested if is_nested is not None else repository_is_nested
    return root, check(Path(root))


def host_scan_source_label(
    source_dir: Path | str,
    find_root: FindRoot,
    *,
    is_nested: Optional[IsNested] = None,
) -> Optional[str]:
    """The label the container launcher passes for *source_dir*, or None.

    Only a plain relative label below the root of a repository that is not
    nested: None outside a repository, inside a submodule, a nested clone or a
    repository under an enclosing one, and for a label
    ``is_relative_scan_source`` refuses. The launcher passes None as ``""``.
    """
    root, nested = _repository_root(source_dir, find_root, is_nested)
    if root is None or nested:
        return None
    label = scan_source_label(source_dir, root)
    return label if is_relative_scan_source(label) else None


def _in_container(environ: Mapping[str, str]) -> bool:
    return environ.get(_IN_CONTAINER_ENV, "NO").upper() in ("YES", "1", "TRUE")


def _started_by_the_launcher(
    source_dir: Path | str, environ: Mapping[str, str]
) -> bool:
    """A scan inside the ASH image that the container launcher started.

    The image sets ASH_IN_CONTAINER whoever runs it, so that alone does not say
    the launcher did: the launcher always sets ASH_ACTUAL_SOURCE_DIR, and it and
    the legacy wrappers mount the scanned directory at /src. A directory below
    /src counts as well: a workspace project, or a hand-written ``docker run`` of
    the image scanning a subdirectory of the mount, is inside the same mount, and
    git there sees only the mount, so its label would be the container's, not the
    repository's.
    """
    if not _in_container(environ):
        return False
    if environ.get(_LAUNCHER_SOURCE_ENV):
        return True
    resolved = PurePosixPath(Path(source_dir).resolve().as_posix())
    mount = PurePosixPath(_CONTAINER_SOURCE_MOUNT)
    return resolved == mount or resolved.is_relative_to(mount)


def _a_git_entry_may_exist(source_dir: Path | str, environ: Mapping[str, str]) -> bool:
    """Whether git could find a repository for *source_dir* at all.

    True with a ``.git`` entry (of any kind: directory, file, symlink) in the
    directory or one of its parents, with GIT_DIR in *environ*, which points git
    at a repository wherever it runs, or whenever the walk cannot
    be sure: a directory that cannot be resolved, or a parent whose ``.git``
    entry cannot be checked, is no proof that there is none, and git is asked as
    before. Only a walk that saw every level and found nothing returns False, and
    then there is no repository for git to report, so it is not started.

    The walk stops where git's own discovery stops: at a GIT_CEILING_DIRECTORIES
    entry (``_ceiling_entries``; git does not look at a listed proper ancestor
    or above it). An entry there is not one git could find, so git is not
    started only to answer that *source_dir* is not inside a repository. An
    entry ``_ceiling_entries`` cannot resolve is dropped, which hides fewer
    levels here too and errs toward starting git, never past it.
    """
    # GIT_DIR points git at a repository wherever it runs (alone, or with the work
    # tree it names). GIT_WORK_TREE alone does not: the root lookup drops it and
    # git discovers from the directory, so the walk below is what decides.
    if "GIT_DIR" in environ:
        return True
    try:
        current = Path(source_dir).resolve()
    except OSError:
        return True
    ceilings = _ceiling_entries()
    for directory in (current, *current.parents):
        if directory != current and _is_ceiling(directory, ceilings):
            return False
        try:
            os.lstat(directory / ".git")
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError:
            # Unreadable, a loop, a name too long: not proof there is no entry.
            return True
        except ValueError:
            # A NUL in the path: no file system entry has one.
            continue
        return True
    return False


def recorded_scan_source(
    source_dir: Path | str,
    find_root: FindRoot,
    environ: Mapping[str, str],
    *,
    workspace_project: bool = False,
    is_nested: Optional[IsNested] = None,
) -> Optional[str]:
    """The ``scan_source`` a scan records, or None when it cannot know it.

    In a scan the container launcher started, which passes ASH_SCAN_SOURCE
    (empty when the host had no label):

    - single-directory mode: that label if it is a plain relative one, else None;
    - a workspace project: the label git in the container gives it, only when the
      mount's label is ``.`` (the mount is a repository's root); else None.

    Git in the container is not asked otherwise: it sees only the mount, and
    calls a nested clone's root ``.``.

    In a launched scan without ASH_SCAN_SOURCE (the legacy wrappers): None, for
    the same reason. ``why_no_scan_source`` says so.

    Anywhere else, the ASH image included: ``scan_source_label`` of
    *source_dir* and the root *find_root* reports, or its absolute path outside
    a repository, whatever ASH_SCAN_SOURCE says.

    Always None inside a nested repository, and for a label that is not UTF-8.

    Args:
        source_dir: The scanned directory.
        find_root: ``get_scan_set.git_repository_root``, or a stand-in.
        environ: The process environment.
        workspace_project: True for a workspace project, which the launcher's
            label (the workspace mount's) does not name.
        is_nested: ``repository_is_nested``, or a stand-in.
    """
    launched = _started_by_the_launcher(source_dir, environ)
    if launched:
        if SCAN_SOURCE_ENV not in environ:
            # The legacy wrappers. Git here sees only the mount, which for a
            # nested clone reads as a repository's root, so it is not asked.
            return None
        mount_label = environ[SCAN_SOURCE_ENV]
        if not workspace_project:
            return mount_label if is_relative_scan_source(mount_label) else None
        if mount_label != ".":
            return None
    if not _a_git_entry_may_exist(source_dir, environ):
        # No .git entry anywhere up the tree and nothing in the environment
        # pointing git at a repository: there is no repository for git to
        # report, so it is not started, and the label is the one git would
        # give, the absolute path outside a repository.
        root, nested = None, False
    else:
        root, nested = _repository_root(source_dir, find_root, is_nested)
    if nested or (launched and root is None):
        return None
    label = scan_source_label(source_dir, root)
    return label if _is_utf8(label) else None


def why_no_scan_source(source_dir: Path | str, environ: Mapping[str, str]) -> str:
    """Why results made in this process record no ``scan_source``, as sentences.

    Specific when this process is a scan the legacy wrappers started (the
    usual cause, and the one an operator can change); otherwise every case
    ``recorded_scan_source`` and ``ash merge`` record None for, since results
    read here may have been made elsewhere.
    """
    if _started_by_the_launcher(source_dir, environ) and SCAN_SOURCE_ENV not in environ:
        return (
            "This scan ran in the ASH container as the legacy ./ash and Invoke-ASH "
            "wrappers start it, without ASH_SCAN_SOURCE, and git there sees only "
            "the mounted directory, so it cannot tell which directory of which "
            "repository it is."
        )
    return (
        "The scan could not tell which directory of which repository it scanned: "
        f"{NO_SCAN_SOURCE_CASES}."
    )


#: Every way results come to record no ``scan_source``, as one sentence's
#: clauses: the cases above, the same ones the aws-security-hub reporter's page
#: lists, and an ``ash merge`` whose shards disagree. Both the reporter's notice
#: and its receipt's ``archive_skipped`` name them.
NO_SCAN_SOURCE_CASES = (
    "the legacy ./ash or Invoke-ASH wrapper, or another run of the ASH image with "
    "the directory at /src or ASH_ACTUAL_SOURCE_DIR set and no ASH_SCAN_SOURCE, "
    "started the scan; the directory is in a submodule, in a clone nested in "
    "another repository, or in a repository under an enclosing one; it is in a "
    "linked worktree, and the repository's git directory holds a FIFO or a "
    "symlink where git reads its worktrees (a worktree's admin dir, a HEAD or a "
    "ref one names, or packed-refs); its path is "
    "not UTF-8; a container scan's directory was outside a git repository, git on "
    "the host refused its repository, or its label was refused; a workspace "
    "project's container mount was not a repository's root; the shards of a merge "
    "recorded different directories; or an older ASH made the results"
)
