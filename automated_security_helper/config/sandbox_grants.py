# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Sandbox grants a config file the scanned repository could have written may not make.

The repository being scanned is untrusted. Anyone who can commit to it can write a
config file there, and ASH picks up ``.ash/.ash.yaml`` from the scan root without
being asked. These sandbox settings grant scanners access:

* ``sandbox.network_scanners`` gives the scanners it names a network.
* ``sandbox.extra_read_paths`` mounts host paths into every sandbox.
* ``sandbox.read_path_scanners`` and ``sandbox.env_scanners`` let the scanners they
  name have the read paths and environment variables their own options ask for
  (see ``SandboxRequirements.read_paths_require_grant`` and ``env_requires_grant``).
* ``sandbox.environment`` is the list of environment variables every sandboxed
  scanner is passed; a ``NAME=value`` entry sets a variable (``LD_PRELOAD``) in all of
  them, so it is a grant like the others.

A config file can't make these grants if it is inside any git checkout, meaning a
directory at or above it, by its own path or its resolved path, holds a git-shaped
``.git`` entry (a directory with ``HEAD``, a link, or the file a submodule or
linked worktree has; a bare empty ``.git`` directory bounds nothing -- see
``_git_shaped``). The rule
doesn't ask how the scan root is named, because symlinks, workspace files and the
shell's working directory give one tree many names, and every rule that depended on
them had a way around it. A checkout is what someone else can push to. For a scan
root outside any checkout, a config file inside the scan root can't grant either,
by any of the root's names: as given, resolved, or through ``$PWD``.

If any file the config was built from (the root config, any ``extends`` base, or
the file ``ASH_CONFIG`` names when no other config is used) is such a file, the
grants are taken from the trusted base plus ``--config-overrides`` instead. The
trusted base is the operator's config file when it is outside every checkout, else
``ASH_CONFIG``'s when that is, else the defaults. Comparing against that resolution,
and not against override key names, is what makes ``key+=[...]``, the dashed
spelling, and a whole-``sandbox`` override behave the same as a plain ``key=value``.

The untrusted ``network_scanners`` is kept as a limit (``SandboxConfig.network_limit``):
a scanner it does not name gets no network. A repository can still take network
away from its own scan, which is what the docs recommend for detect-secrets. It just
can't add network.

``sandbox.mode`` is a restriction, so it is honored from any source, as a floor. When
``--sandbox``, ``ASH_CONFIG`` or the operator's config file turns the sandbox on, an
untrusted file can't turn it off or switch it to another backend. The operator's
mode counts wherever the operator's file lives, even inside a checkout, because a
mode other than ``off`` never grants access. Only ``--sandbox off`` or a
``sandbox.mode`` override turns it back off. When no operator source turns the
sandbox on, an untrusted mode applies, because a sandbox the repository asks for only
takes access away.

The scanned tree is the outermost directory at or above the scan root that holds a
git-shaped ``.git`` entry (a directory with ``HEAD``, a link, or the file a
submodule or linked worktree has; a bare empty ``.git`` directory bounds nothing --
see ``_git_shaped``), or the
scan root itself outside a repository. Outermost, so a ``.git`` file inside the
repository can't make the superproject look like it is outside. The repository being
scanned controls all of it, not only the part being scanned. The root is looked up
from the scan root as given, from its resolved path, and, when the scan root is the
working directory or below it, from the shell's logical working directory
(``$PWD``). That way a scan root that is a symlink out of the repository still counts
the repository, including after ``cd vendor && ash scan``, where the operating system
reports only the physical directory. ``$PWD`` is used only when it names the working
directory, and it can only add a tree, never remove one. The check looks for the
entry on disk and does not run git, which reads configuration from the repository.

Whether a file is in the tree is decided with ``os.path.samefile`` on each of the
file's parents, not by comparing path strings. A symlink, a ``..`` segment, or a
case-only difference on a case-insensitive filesystem therefore can't make an
in-tree file look like it is outside. A file reached through a symlink inside the
tree counts as in the tree wherever the link points, because the repository wrote
the link: a ``.ash/.ash.yaml`` that links to a file elsewhere is held to the same
limits as one written in place (``files_inside``).

The rule is any git checkout, not only the one scanned: a config file kept in a
checkout of its own (an ops or dotfiles repository) can't grant either, since ASH
can't tell who wrote it. Its grants are dropped with a warning that names the file
and the setting and says how to keep them: pass them with ``--config-overrides``,
or keep the config file outside every git checkout and the scanned directory.
"""

import errno
import os
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Collection,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from automated_security_helper.config.ash_config import SandboxConfig
from automated_security_helper.config.config_sources import describe_config_path
from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING
from automated_security_helper.config.environment_record import (
    ENVIRONMENT_VALUE_SHOWN,
)
from automated_security_helper.config.untrusted_source import UntrustedSource
from automated_security_helper.utils.log import (
    ASH_LOGGER,
    NO_MARKUP,
    current_run_log_scope,
)
from automated_security_helper.utils.scanned_tree import _is_link_stat
from automated_security_helper.utils.terminal_text import shown_on_one_line


def described(
    paths: Iterable[Path], environment_paths: Collection[Path] = frozenset()
) -> str:
    """The config files in a confinement warning, named as they are.

    A file in *environment_paths* (``ResolvedConfigDocument.environment_paths``:
    a base an ``extends`` entry named with a value read from the environment,
    and every base below it) is named ``<value>``, as the source chain and the
    chain's own errors name it: its path holds the value. *paths* can hold a
    base as its ``extends`` entry named it as well as resolved (``files_inside``),
    and that name (``x/../x/base.yaml``, a link in the tree) holds the value too,
    so a path is compared by where it resolves to as well.

    The names are the scanned repository's, so the warning shows its whole
    message, these included, with ``shown_on_one_line`` and logs it with
    ``NO_MARKUP``: a carriage return, an escape sequence or a bidirectional
    override would write over or reorder the warning's line, a newline would
    start a forged one, and a ``[/`` is a closing Rich tag. Shown here as well,
    each escape in a name would be shown twice.
    """
    chosen = {Path(path) for path in environment_paths}
    return ", ".join(
        ENVIRONMENT_VALUE_SHOWN
        if _chosen_by_environment(Path(path), chosen)
        else describe_config_path(path)
        for path in paths
    )


def _chosen_by_environment(path: Path, chosen: Collection[Path]) -> bool:
    """Whether *path*, or the file it resolves to, is in *chosen*."""
    if not chosen:
        return False
    if path in chosen:
        return True
    try:
        # strict: a link loop raises on every Python version, where
        # Path.resolve() raises on some and returns the name unresolved on others.
        return Path(os.path.realpath(path, strict=True)) in chosen
    except (FileNotFoundError, NotADirectoryError):
        # A name with nothing at the end of it (the config_overrides stand-in,
        # a file that is gone) is not a link loop. It is the file the
        # environment chose only when the place it leads to is one of them.
        try:
            return Path(os.path.realpath(path)) in chosen
        except OSError:
            # A relative name with no working directory to join it to.
            return True
    except (OSError, RuntimeError):
        # A name that does not resolve (a link loop) may name a file the
        # environment chose, so it is shown as `<value>`.
        return True


def is_within(path: Path, root: Path) -> bool:
    """True when ``path``, or a directory above it, is the same file as ``root``."""
    real = Path(os.path.realpath(path))
    for candidate in (real, *real.parents):
        try:
            if os.path.samefile(candidate, root):
                return True
        except OSError:
            continue
    return False


def _examination_error(path: Path) -> Optional[OSError]:
    """The error ``lstat`` of *path* raises, or None when it can be examined or
    is provably absent (the same two answers ``_link_state`` reads as "no")."""
    try:
        os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as error:
        return error
    return None


def _git_shaped(entry: Path) -> bool:
    """Whether ``entry`` marks a checkout.

    What counts: a gitfile (a regular file, as a linked worktree's ``.git``
    is); a link, meaning a symlink or a Windows junction
    (``_names_another_path``), counted even dangling -- placed content, so
    the conservative answer stands; a directory holding ``HEAD``, the
    nearest shape to what git's own discovery opens (git also wants objects
    and refs, so a bare ``HEAD`` errs toward counting); and a directory
    whose ``HEAD`` lookup cannot
    be answered (one the scanning user cannot search), because failing open
    there would hand the repository's own files the operator's trust -- with
    a logged warning naming the entry. An entry that cannot be examined at
    all (``lstat`` fails for a reason other than the entry being absent, as
    when the directory holding it cannot be searched) gets the same answer
    and the same warning.

    Each of those shapes counts only when ``_left_by_a_trusted_user`` says
    so: in a directory that other users can write (the system temp
    directory, a world- or group-writable share), a ``.git`` someone else
    left must not move the checkout boundary to the shared parent for every
    scan under it, whether or not its contents can be read.

    What does not: a bare empty searchable ``.git`` directory -- what a
    stray mkdir or a transient mount point leaves in a shared parent -- a
    ``HEAD``-less directory with other content, a FIFO or other special
    file, and any ``.git`` a stranger left in a directory others can write.
    git would open none of the former, and counting any of them moves the
    checkout boundary to a directory the scanned repository never
    controlled.

    A regular file counts whatever its content, where the nesting walk
    (``scan_source._marks_a_checkout``) reads the gitfile format. That
    asymmetry is deliberate: for a regular file this boundary errs toward
    confining -- a stray
    non-gitfile ``.git`` here only widens what is read as the untrusted
    repository's, never trust -- while the nesting walk follows git's own
    repository discovery."""
    unverifiable = None
    if _names_another_path(entry) or os.path.isfile(entry):
        pass
    elif not os.path.isdir(entry):
        # isfile and isdir answer False for an entry that cannot be examined
        # (a parent the scanning user cannot search, a name too long to look
        # up) as they do for one that is not there. Only an entry that is
        # absent bounds nothing; one nobody could examine is the same
        # unverifiable boundary as a .git directory nobody could search.
        unverifiable = _examination_error(entry)
        if unverifiable is None:
            return False
    else:
        try:
            os.lstat(os.path.join(entry, "HEAD"))
        except OSError as error:
            if error.errno == errno.ENOENT:
                # No HEAD is not a repository git would open.
                return False
            # Everything else is the fail-closed side: a .git the scanning
            # user cannot search (EACCES), and the race where .git becomes a
            # file between the isdir above and this lstat (ENOTDIR; a file
            # .git would count as a gitfile anyway; unreachable from a
            # static tree, so no cell pins it). The boundary then rests on
            # an entry nobody could verify, so the warning below names it.
            unverifiable = error
    if not _left_by_a_trusted_user(entry):
        return False
    if unverifiable is not None:
        _warn_unverifiable_git(entry, unverifiable)
    return True


def _left_by_a_trusted_user(entry: Path) -> bool:
    """Whether whoever left ``entry`` may place a checkout boundary there.

    In a directory that group members or other users can write, anyone can
    have left a ``.git`` -- readable or not -- and counting a stranger's
    would move the checkout boundary to the shared parent for every scan
    under it. There, ``entry`` counts only when ``lstat`` says it belongs
    to the scanning user, to root, or to the directory's own owner, whose
    directory it is to arrange. In a directory nobody else can write, the
    entry's shape alone decides.

    The directory is read with ``stat``, not ``lstat``, so one reached
    through a symlink is judged by the directory it is, not by the link.
    A directory that cannot be stat'ed keeps the shape rule.

    On Windows ``stat`` reports every owner as uid 0, so any entry reads as
    root's and counts. That is the confining side: a ``.git`` another user
    left in a shared writable directory moves the boundary there, as it
    would for the entry of the scanning user.

    The accepted cost: in a group-writable shared checkout whose ``.git``
    belongs to a teammate who is neither the scanning user nor the
    directory's owner, the entry is not counted and the boundary falls back
    toward the scan root, so that checkout's own config can read as the
    operator's. The shape is narrow -- a checkout's ``.git`` and its root
    directory normally share an owner -- and the alternative re-opens the
    shared-parent widening. The undo is reverting to the mode-bit rule this
    replaced, which dropped only what sat unverifiable under a sticky,
    world-writable directory."""
    try:
        holder = os.stat(os.path.dirname(os.fspath(entry)))
    except OSError:
        return True
    if not holder.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return True
    try:
        owner = os.lstat(entry).st_uid
    except OSError:
        # The entry cannot be attributed to anyone, in a directory where
        # anyone could have left it.
        return False
    if owner == 0 or owner == holder.st_uid:
        return True
    return hasattr(os, "geteuid") and owner == os.geteuid()


#: The warnings already printed, each keyed by the run log scope whose log saw
#: it, the kind of warning and the name it was about. Two kinds share the
#: store: ``"git"`` for an unverifiable .git entry a checkout boundary rests
#: on, and ``"link-walk"`` for a name whose link walk stopped undecided. A
#: scan walks the same parents and names many times, and the reason should
#: print once per name and kind -- but once per RUN, not per process, since
#: concurrent runs in one process (the MCP server's scans) each need their
#: own log to name the entry their boundary rests on. Keys of finished runs go
#: unused; past _WARNED_BOUND the next warning keeps only its own run's keys,
#: and when that prune removes nothing -- every key shares the caller's scope,
#: as with no run log scope open -- the set is cleared outright, so a
#: long-lived process stays bounded either way (a run that loses its window
#: this way can warn again, the safe direction).
_UNVERIFIABLE_WARNED: Set[Tuple[Optional[str], str, str]] = set()

#: Guards every read and write of the warned set: hosted runs warn and
#: forget from concurrent executor threads, and iterating the shared set
#: against a concurrent add raises "Set changed size during iteration" --
#: and forget is a scan's first call, so that scan would die at start.
_UNVERIFIABLE_WARNED_LOCK = threading.Lock()

_WARNED_BOUND = 1024


def forget_unverifiable_warnings() -> None:
    """Start a new once-per-name window for the calling run's warnings.

    Covers both kinds the store holds, the unverifiable .git entries and the
    names whose link walk stopped undecided.

    Called at the top of a scan run. It has something to clear only for a
    run that joins a scope that has warned before (the hosting server's
    runner rescanning in one scope) or for a caller outside every run
    scope, whose window is otherwise the process's; a run in a fresh scope
    starts empty either way. Not called by the per-path trust checks, which
    run many times inside one scan and stay deduplicated. Another run's
    window is left alone."""
    scope = current_run_log_scope()
    with _UNVERIFIABLE_WARNED_LOCK:
        _UNVERIFIABLE_WARNED.difference_update(
            {key for key in _UNVERIFIABLE_WARNED if key[0] == scope}
        )


def _first_warning(key: Tuple[Optional[str], str, str]) -> bool:
    """Record *key* as warned about; whether this is the first time in its window.

    *key* is (run log scope, kind, name); see ``_UNVERIFIABLE_WARNED``."""
    with _UNVERIFIABLE_WARNED_LOCK:
        if key in _UNVERIFIABLE_WARNED:
            return False
        if len(_UNVERIFIABLE_WARNED) >= _WARNED_BOUND:
            _UNVERIFIABLE_WARNED.intersection_update(
                {kept for kept in _UNVERIFIABLE_WARNED if kept[0] == key[0]}
            )
            if len(_UNVERIFIABLE_WARNED) >= _WARNED_BOUND:
                # Every kept key shares this caller's scope (with no run log
                # scope open the prune keeps everything), so start the window
                # over.
                _UNVERIFIABLE_WARNED.clear()
        _UNVERIFIABLE_WARNED.add(key)
    return True


def _warn_undecided_link_walk(named: Path, stopped_at: Path, reason: str) -> None:
    """Say, once per name, that a link walk stopped before it reached the end.

    An undecided name is judged the repository's, which removes grants, and
    the sentence that explains the removal speaks of a location. Without
    this line nothing says the location was never established.
    """
    name = Path(os.fspath(named)).as_posix()
    if not _first_warning((current_run_log_scope(), "link-walk", name)):
        return
    ASH_LOGGER.warning(
        shown_on_one_line(
            f"The link walk for {name} stopped at "
            f"{Path(os.fspath(stopped_at)).as_posix()} ({reason}), so the name "
            "cannot be ruled out as the scanned repository's and is treated as "
            "inside it."
        ),
        extra=NO_MARKUP,
    )


def _warn_unverifiable_git(entry: Path, error: OSError) -> None:
    name = Path(os.fspath(entry)).as_posix()
    if not _first_warning((current_run_log_scope(), "git", name)):
        return
    # An OSError the operating system raised always carries both fields; a
    # hand-built one can leave either None, and then the text falls back.
    reason = error.strerror or (
        errno.errorcode.get(error.errno, "unreadable")
        if error.errno is not None
        else "unreadable"
    )
    ASH_LOGGER.warning(
        shown_on_one_line(
            f"Treating {name} as a checkout boundary although its contents "
            f"cannot be read ({reason}): the conservative answer stands "
            "when the lookup cannot be made."
        ),
        extra=NO_MARKUP,
    )


def _outermost_checkout(start: Path) -> Path:
    found = start
    for candidate in (start, *start.parents):
        if _git_shaped(candidate / ".git"):
            found = candidate
    return found


#: Config files the host marked as repository-written for the scan inside a
#: container, by resolved path; see ``marked_repository_written`` and
#: ``marked_files_repository_written``.
_MARKED: List[Path] = []
#: The marked files whose whole chain is marked with them.
_MARKED_CHAINS: List[Path] = []
#: Config files the host marked as inside a git checkout other than the scanned
#: tree, by resolved path; see ``marked_files_in_another_checkout``.
_MARKED_ELSEWHERE: List[Path] = []

#: Why a marked config file is not the operator's, for ``untrusted_reason``.
#: A host sends this mark for a file in the scanned directory or the git checkout
#: that holds it, and for a file that only a link in either leads to.
MARKED_REASON = (
    "the host that started this scan in a container found it in, or reached it "
    "through a link in, the scanned directory or the git checkout that holds it"
)
#: The same for a file marked as in another checkout. The host also sends this mark
#: for a file that only a link in such a checkout leads to, so the reason keeps the
#: link clause that the host's own reason for such a file has (``untrusted_reason``:
#: "reached through <link>, a link inside the git checkout"). The host does not send
#: it for a file whose name it could not walk to the end: the launcher, ``./ash`` and
#: ``Invoke-ASH`` refuse such a given name, and the scanned tree's mark claims any
#: other (``_another_checkout_marks`` in ``run_ash_container``), so the reason has no
#: clause for that state. A name whose walk did not finish has a reason of its own
#: (``UNFINISHED_WALK_REASON``). The reason names no link and no option: how the host
#: got there is not part of it.
MARKED_ELSEWHERE_REASON = (
    "the host that started this scan in a container found it in, or reached it "
    "through a link in, a git checkout other than the scanned directory"
)


@contextmanager
def marked_repository_written(config: Path) -> Iterator[None]:
    """Treat ``config``, and every file a chain rooted at it extends, as
    repository-written while the block runs.

    For the scan inside a container, over one directory or a workspace. The host
    found the ``--config`` it mounted at ``/ash-config`` in the scanned tree, or
    reached it through a link there, and passed
    ``--config-from-scanned-repository``; the mounted
    copy is in no checkout inside the container, so the mark carries the host's
    verdict to every resolution of that config: the scan's, or in a workspace each
    project's and the plan's. ``untrusted_reason``, ``repository_written``,
    ``in_a_checkout`` and ``files_inside`` read it, so every step that decides what
    a repository-written file may not choose
    sees it, as the any-checkout rule does on the host. The scanned-tree rule
    (``in_tree_reason``, ``files_inside``) does not: on the host a file in another
    checkout is outside the scanned tree, so a workspace may still layer it over
    its projects (``resolve_config.check_operator_config``), and here it is outside
    ``/src`` as well. Files outside the chain, the projects' own included, are
    judged as before. A mark only takes grants away.
    """
    marked = Path(os.path.realpath(config))
    _MARKED.append(marked)
    _MARKED_CHAINS.append(marked)
    try:
        yield
    finally:
        _MARKED.remove(marked)
        _MARKED_CHAINS.remove(marked)


@contextmanager
def marked_files_repository_written(files: Iterable[Path]) -> Iterator[None]:
    """Treat each of ``files``, and only those, as repository-written while the
    block runs.

    For the scan inside a container, when the host found some of the files the
    ``--config`` extends in a git checkout but not the config itself, and passed
    each with ``--config-file-from-scanned-repository``. A root config outside
    every checkout then keeps the sandbox settings it writes itself
    (``resolve_config``'s own-sandbox rule), as it does on the host, and the
    marked bases grant nothing.
    """
    marked = [Path(os.path.realpath(path)) for path in files]
    _MARKED.extend(marked)
    try:
        yield
    finally:
        for path in marked:
            _MARKED.remove(path)


@contextmanager
def marked_files_in_another_checkout(files: Iterable[Path]) -> Iterator[None]:
    """Treat each of ``files`` as inside a git checkout other than the scanned tree
    while the block runs.

    For the scan inside a container, when the host found some files of the
    ``--config`` chain, or of the chain of the file ``ASH_CONFIG`` names, in a git
    checkout that does not hold the scanned directory, and passed each with
    ``--config-file-from-another-checkout``. The mounted copy is in no checkout
    inside the container, so the mark carries the host's verdict to the two
    predicates that answer for a file in any checkout: ``checkout_judgment`` (and
    so ``in_a_checkout`` and ``resolve_config``'s any-checkout leg) and
    ``untrusted_reason`` (and so ``repository_written``, which the tool-path and
    own-sandbox rules read). It does not make the file a member of the scanned
    tree: ``confined_files`` and ``files_inside`` do not see it, which is how
    ``resolve_config`` tells the two places apart. A file there cannot grant, and
    an ``ASH_CONFIG`` or operator file there still sets what only restricts
    (``config/restrictions_kept``), read from the mounted file itself. No value of
    the file travels in the mark, so a mark cannot carry a grant. A file marked
    here and as the scanned tree's (``marked_files_repository_written``) is the
    scanned tree's: that reading keeps nothing.
    """
    marked = [Path(os.path.realpath(path)) for path in files]
    _MARKED_ELSEWHERE.extend(marked)
    try:
        yield
    finally:
        for path in marked:
            _MARKED_ELSEWHERE.remove(path)


def _marked(path: Path) -> bool:
    return bool(_MARKED) and Path(os.path.realpath(path)) in _MARKED


def _marked_elsewhere(path: Path) -> bool:
    return bool(_MARKED_ELSEWHERE) and Path(os.path.realpath(path)) in _MARKED_ELSEWHERE


def _marked_chain(path: Path) -> bool:
    return bool(_MARKED_CHAINS) and Path(os.path.realpath(path)) in _MARKED_CHAINS


@dataclass(frozen=True)
class WalkJudgment:
    """A membership verdict together with whether a walk established it.

    ``verdict`` is the fail-closed answer the boolean API returns. ``decided``
    is False when the verdict rests on a walk that never finished (the link
    bound, an unreadable component, a name ``os.path.realpath`` raises on)
    rather than on anything found: the judgment is unchanged either way, but a
    sentence that explains it must then say the walk stopped instead of
    claiming a location the walk never established. ``client_delivered`` is True
    when the judgment is True only because an MCP client delivered the path
    (``path_trust.scanned_tree_judgment``): it sits in no tree the walk found, so
    a sentence must say a client delivered it, not that it is in the scanned
    tree. Not a bool on purpose: a truth test would silently read every judgment
    as True, so a caller states which field it reads.
    """

    verdict: bool
    decided: bool
    client_delivered: bool = False

    def __bool__(self) -> bool:
        raise TypeError(
            "a WalkJudgment is not a bool: read .verdict (the fail-closed "
            "answer) or .decided explicitly"
        )


@dataclass(frozen=True)
class ConfinedFiles:
    """``files_inside``'s members, with the ones only an unfinished walk added.

    ``members`` is the fail-closed membership the list API returns.
    ``undecided`` holds the members whose membership rests on nothing found --
    a name whose link walk stopped before the end -- so a sentence naming the
    members' location must say the walk stopped for those instead of claiming
    one. Not iterable and not a bool on purpose, so a caller cannot silently
    treat it as the plain list and drop the undecided half.
    """

    members: Tuple[Path, ...]
    undecided: Tuple[Path, ...] = field(default=())

    def __bool__(self) -> bool:
        raise TypeError(
            "a ConfinedFiles is not a bool: read .members (the fail-closed "
            "membership) or .undecided explicitly"
        )


def in_a_checkout(path: Path) -> bool:
    """Whether ``path``, as named or with its symlinks resolved, is in a checkout,
    or is reached through a symlink that sits in one.

    The fail-closed collapse of :func:`checkout_judgment`: an undecided walk
    reads as in one. A judgment that feeds a sentence uses
    ``checkout_judgment`` instead, so the sentence can say when the walk never
    decided it.
    """
    return checkout_judgment(path).verdict


def checkout_judgment(path: Path) -> WalkJudgment:
    """:func:`in_a_checkout`'s verdict, with whether a walk established it.

    The verdict is whether ``path`` or a directory above it holds a git-shaped
    ``.git`` entry (``_git_shaped``), which is where ``scanned_trees`` would
    take a scan of it to start. A link resolving
    ``path`` follows (``links_followed``) that sits in a checkout counts too:
    that checkout chose where the link points, as in ``checkout/lnk/../x.yaml``,
    whose name with ``..`` applied and whose target are both outside it.
    A file the host marked (``marked_repository_written``,
    ``marked_files_in_another_checkout``) counts wherever it is: the mounted copy
    sits in no checkout inside the container, and the mark is the host's own
    checkout verdict.
    A walk cut short at the link bound or at an unreadable component never saw
    the remaining links, so it cannot rule out a link sitting in a checkout, and
    the undecided case is judged as in one, the same rule as ``files_inside`` --
    returned with ``decided=False``, so the sentence that explains the judgment
    can say so. A name ``os.path.realpath`` raises on is treated the same way:
    with no resolved start to clear it, the name cannot be ruled out either.
    """
    if _marked(path):
        return WalkJudgment(verdict=True, decided=True)
    if _marked_elsewhere(path):
        return WalkJudgment(verdict=True, decided=True)
    links, decided = _walk_links(path)
    starts = [_as_named(path)]
    try:
        starts.append(Path(os.path.realpath(path)))
    except OSError as error:
        decided = False
        named = Path(path).absolute()
        _warn_undecided_link_walk(
            named, named, error.strerror or "it could not be resolved"
        )
    starts.extend(link.parent for link in links)
    for start in starts:
        if any(_git_shaped(entry / ".git") for entry in (start, *start.parents)):
            return WalkJudgment(verdict=True, decided=True)
    return WalkJudgment(verdict=not decided, decided=decided)


def as_named(path: Path) -> Path:
    """``path`` made absolute, with ``..`` applied the way the kernel applies it.

    Every other component stays as spelled, so a symlink is judged by where it
    sits. A ``..`` steps up from what the path before it resolves to: in
    ``link/..`` the kernel follows ``link`` first, which a plain textual fold of the
    path would not, and in ``src/../ops`` the result is no longer inside ``src``.
    Where the platform removes each ``..`` before it looks at any link
    (``_applies_parent_steps_lexically``) the path is folded textually instead,
    as that platform opens it.
    """
    absolute = Path(path).absolute()
    if _applies_parent_steps_lexically():
        absolute = Path(os.path.normpath(absolute))
    named = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        if part == "..":
            named = Path(os.path.realpath(named)).parent
        elif part not in ("", "."):
            named = named / part
    return named


def checkout_containing(path: Path) -> Optional[Path]:
    """The nearest directory at or above ``path`` holding a git-shaped ``.git``
    entry (``_git_shaped``), or None.

    Looked up from the path as given and from its resolved path, so a symlink into
    or out of a checkout counts either way.
    """
    for start in (as_named(path), Path(os.path.realpath(path))):
        for candidate in (start, *start.parents):
            if _git_shaped(candidate / ".git"):
                return candidate
    return None


def in_any_checkout(path: Path) -> bool:
    """True when ``path`` is inside a git checkout, by its own or its resolved path."""
    return checkout_containing(path) is not None


#: Symlinks followed before resolution gives up, as the kernel's ELOOP limit does.
_MAX_LINKS = 40


def _applies_parent_steps_lexically() -> bool:
    """Whether this platform removes each ``..`` before it looks at any link.

    Windows does (ntpath.realpath normalizes the path first), so there
    ``ops/j/../repo`` opens ``ops/repo`` whatever ``j`` is. POSIX follows ``j``
    first and steps up from where it leads.
    """
    return os.name == "nt"


def _names_another_path(path: Path) -> bool:
    """Whether resolving ``path`` follows it elsewhere: a symlink, or a reparse
    point that names another path, such as a junction.

    Not any reparse point (``config_sources._is_a_link``): a OneDrive placeholder
    or a deduplicated file is one without the name-surrogate bit, and it is the
    file or directory it appears to be (``scanned_tree._is_link_stat``).
    """
    return _link_state(path) is True


def _link_state(path: Path) -> Optional[bool]:
    """Whether ``path`` names another path: True, False, or None when unknown.

    False only when the component provably is not a followable link: it is
    absent (``FileNotFoundError``) or sits under something that is not a
    directory (``NotADirectoryError``). Any other failure to ``lstat`` it, such
    as a parent directory the process cannot search, leaves it unjudged and
    returns None: the component may be a link nobody here can see.
    """
    try:
        return _is_link_stat(os.lstat(path))
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        return None


def links_followed(path: Path) -> List[Path]:
    """Every symlink resolving ``path`` follows, by the link's own location.

    Resolves one component at a time, as the kernel does, so a link reached only
    through another link is found too: ``ops/cur.yaml -> repo/.ash/.ash.yaml ->
    ../../other.yaml`` follows ``repo/.ash/.ash.yaml``, which neither the name
    ``ops/cur.yaml`` nor the resolved ``other.yaml`` shows. Whoever can write the
    directory a link sits in chooses where it points. Each location is returned
    with its directory resolved. A walk cut short (see ``_walk_links``) returns
    the links found so far.
    """
    return _walk_links(path)[0]


def _walk_links(path: Path) -> Tuple[List[Path], bool]:
    """The links ``links_followed`` lists, and whether the walk reached the end.

    A walk past the link bound (``_MAX_LINKS``), through a link that cannot
    be read, or to a component that cannot be examined (a directory the process
    cannot search) stops there and is undecided: links beyond that point were never
    seen, so the list cannot rule out a link in a tree. Each stop is logged
    once per name and run, naming where it happened.
    """
    absolute = Path(path).absolute()
    if _applies_parent_steps_lexically():
        absolute = Path(os.path.normpath(absolute))
    resolved = Path(absolute.anchor)
    rest = list(absolute.parts[1:])
    links: List[Path] = []
    while rest:
        part = rest.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            resolved = resolved.parent
            continue
        candidate = resolved / part
        # Not os.path.islink(), which is False for a Windows junction: one was
        # stepped through as a directory, so "<junction>/.." stepped up from its
        # name, and the directory it sits in was not counted.
        state = _link_state(candidate)
        if state is None:
            # A component that cannot be judged may be a link: the rest of
            # the walk is unknown.
            _warn_undecided_link_walk(absolute, candidate, "it could not be examined")
            return links, False
        if not state:
            resolved = candidate
            continue
        if len(links) >= _MAX_LINKS:
            _warn_undecided_link_walk(
                absolute, candidate, f"more than {_MAX_LINKS} links to follow"
            )
            return links, False
        links.append(candidate)
        try:
            target = Path(os.readlink(candidate))
        except (OSError, ValueError) as error:
            # ValueError: a reparse point readlink cannot read as a link.
            reason = (
                error.strerror
                if isinstance(error, OSError) and error.strerror
                else "not readable as a link"
            )
            _warn_undecided_link_walk(absolute, candidate, reason)
            return links, False
        if _applies_parent_steps_lexically():
            # A target's own `..` is removed before any link in it is looked at,
            # as the name's was above.
            target = Path(os.path.normpath(target))
        if target.is_absolute():
            resolved = Path(target.anchor)
            rest = list(target.parts[1:]) + rest
        else:
            rest = list(target.parts) + rest
    return links, True


def _as_named(path: Path) -> Path:
    """``path`` made absolute, with ``..`` applied the way the kernel applies it.

    Every other component stays as spelled, so a symlink is judged by where it
    sits. A ``..`` steps up from what the path before it resolves to: in
    ``link/..`` the kernel follows ``link`` first. Where the platform removes
    each ``..`` before it looks at any link
    (``_applies_parent_steps_lexically``) the path is folded textually instead.
    """
    absolute = Path(path).absolute()
    if _applies_parent_steps_lexically():
        absolute = Path(os.path.normpath(absolute))
    named = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        if part == "..":
            named = Path(os.path.realpath(named)).parent
        elif part not in ("", "."):
            named = named / part
    return named


def _named_within(path: Path, trees: Iterable[Path]) -> bool:
    """Whether ``path``, as spelled, sits inside one of ``trees``.

    Walks the unresolved parents, so a file that is a symlink out of a tree still
    counts as inside it.
    """
    trees = list(trees)
    named = _as_named(path)
    for candidate in (named, *named.parents):
        for tree in trees:
            try:
                if os.path.samefile(candidate, tree):
                    return True
            except OSError:
                continue
    return False


def _logical_paths(scan_root: Path) -> List[Path]:
    """``scan_root`` as the shell names it, when it is the working directory or below.

    ASH builds an absolute scan root from the physical working directory, so a root
    whose text starts with it is rejoined to ``$PWD`` from the rest of its text,
    ``..`` and symlinks included. A root reached some other way is matched by its
    resolved path.
    """
    pwd = os.environ.get("PWD")
    if not pwd or not os.path.isabs(pwd):
        return []
    try:
        cwd = os.getcwd()
        if not os.path.samefile(pwd, cwd):
            return []
    except OSError:
        return []
    root = os.fspath(scan_root)
    if not os.path.isabs(root):
        return [Path(os.path.normpath(os.path.join(pwd, root)))]
    names: List[Path] = []
    prefix = cwd.rstrip(os.sep) + os.sep
    if root == cwd or root.startswith(prefix):
        names.append(Path(os.path.normpath(os.path.join(pwd, root[len(prefix) :]))))
    real_cwd = os.path.realpath(cwd)
    real_root = os.path.realpath(root)
    try:
        if os.path.commonpath([real_cwd, real_root]) == real_cwd:
            relative = os.path.relpath(real_root, real_cwd)
            name = Path(os.path.normpath(os.path.join(pwd, relative)))
            if name not in names:
                names.append(name)
    except ValueError:  # different drives on Windows
        pass
    return names


def working_directory() -> Optional[Path]:
    """The process's working directory, or None when it no longer exists.

    A directory deleted while the process runs makes ``Path.cwd()`` raise
    FileNotFoundError. Every load that judged files by the trees scanned from
    it failed on that, so a scan, `ash config validate` and the MCP tools
    exited 3 over a directory nothing was read from. Such a directory holds no
    file, so no file of a chain can be inside it: ``scanned_trees(None)`` is no
    tree, as for a scan root outside every checkout, and a debug line says so.
    """
    try:
        return Path.cwd()
    except FileNotFoundError:
        ASH_LOGGER.debug(
            "The working directory no longer exists: no scanned tree is taken from it"
        )
        return None


def scan_root_names(scan_root: Path) -> List[Path]:
    """Every name the scan root has: as given, resolved, and through ``$PWD``."""
    names: List[Path] = []
    for name in (
        as_named(scan_root),
        Path(os.path.realpath(scan_root)),
        *_logical_paths(scan_root),
    ):
        if name not in names:
            names.append(name)
    return names


#: The reason ``confine_sandbox_grants`` gives by default: why a file may not grant.
REPOSITORY_WRITTEN = (
    "the file is inside a git checkout or the scanned directory, so someone other "
    "than the operator may have written it"
)

#: The reason ``untrusted_reason`` gives for a name whose link walk did not reach
#: its end (``_walk_links``): no link in a tree was found, but the walk could not
#: say there is none.
UNFINISHED_WALK_REASON = (
    "resolving its name stopped before the walk finished, so it cannot be ruled "
    "out as inside a git checkout or the scanned directory"
)


def untrusted_reason(path: Path, scan_root: Path) -> Optional[str]:
    """Why the scanned repository could have written ``path``, or None if it could not.

    Inside any git checkout, by the path as given or as resolved, or inside the
    scan root by any of the root's names; or reached through a symlink that sits
    in one (``_walk_links``). Pass the path as it was named, not resolved: every
    spelling is checked here, and resolving first would hide a symlink's own
    location. A config file a host marked (``marked_repository_written``,
    ``marked_files_in_another_checkout``) is repository-written wherever it is.

    A name whose link walk did not reach its end has links beyond the point it
    stopped at that were never seen, so it cannot be ruled out as reached through a
    link in a tree, and it is the repository's too, with a reason of its own
    (``UNFINISHED_WALK_REASON``). The links the walk did find are judged first, so a
    link in a tree is still named as the reason when there is one.
    """
    if _marked(path):
        return MARKED_REASON
    if _marked_elsewhere(path):
        return MARKED_ELSEWHERE_REASON
    checkout = checkout_containing(path)
    if checkout is not None:
        return f"it is inside the git checkout at {checkout.as_posix()}"
    names = scan_root_names(scan_root)
    if any(is_within(path, name) for name in names) or _named_within(path, names):
        return f"it is inside the scanned directory {Path(scan_root).as_posix()}"
    links, decided = _walk_links(path)
    for link in links:
        checkout = checkout_containing(link.parent)
        if checkout is not None:
            return (
                f"it is reached through {link.as_posix()}, a link inside the git "
                f"checkout at {checkout.as_posix()}"
            )
        if any(is_within(link.parent, name) for name in names):
            return (
                f"it is reached through {link.as_posix()}, a link inside the "
                f"scanned directory {Path(scan_root).as_posix()}"
            )
    if not decided:
        return UNFINISHED_WALK_REASON
    return None


def scanned_checkouts(scan_root: Path) -> List[Path]:
    """The outermost git checkout holding ``scan_root``, by its own and resolved path.

    The tree the scanned repository wrote: for a submodule or a vendored checkout,
    the superproject around it too. Empty for a scan root outside every checkout.
    """
    found: List[Path] = []
    # Every name the scan root has, as ``scanned_trees`` takes them: as given,
    # resolved, and through ``$PWD``; without the shell's name, ``cd vendor &&
    # ash scan`` found no superproject above the root the kernel names, and a
    # path inside it that the other trust checks count as the scanned tree was
    # honored as the operator's.
    for start in (
        as_named(scan_root),
        Path(os.path.realpath(scan_root)),
        *_logical_paths(scan_root),
    ):
        outermost = None
        for candidate in (start, *start.parents):
            if _git_shaped(candidate / ".git"):
                outermost = candidate
        if outermost is not None and outermost not in found:
            found.append(outermost)
    return found


def in_tree_reason(path: Path, scan_root: Path) -> Optional[str]:
    """Why ``path`` is inside the scanned tree itself, or None.

    Narrower than ``untrusted_reason``: inside the scan root, or the outermost
    checkout holding it, by any of their names, or reached through a link inside
    them. Another checkout, such as an operator's ops repository, is not the
    scanned tree. Used for a path the operator named
    (``config/path_trust.py``), which the operator may keep in a checkout of their
    own; a path a repository's config names follows ``untrusted_reason``.

    A name whose link walk did not reach its end has links beyond the point it
    stopped at that were never seen, so it cannot be ruled out as reached through a
    link in the scanned tree, and it is refused with ``UNFINISHED_WALK_REASON``, as
    ``untrusted_reason`` does. The links the walk did find are judged first. This is
    what the walk's own warning means by treating the name as inside the tree.
    """
    names = scan_root_names(scan_root)
    roots = [*scanned_checkouts(scan_root), *names]
    label = Path(scan_root).as_posix()
    if any(is_within(path, root) for root in roots) or _named_within(path, roots):
        return f"it is inside the scanned tree at {label}"
    links, decided = _walk_links(path)
    for link in links:
        if any(is_within(link.parent, root) for root in roots):
            return (
                f"it is reached through {link.as_posix()}, a link inside the "
                f"scanned tree at {label}"
            )
    if not decided:
        return UNFINISHED_WALK_REASON
    return None


def untrusted_path(path: Path, scan_root: Path) -> bool:
    """Whether the scanned repository could have written ``path``.

    The one per-path rule: config files (``repository_written``) and the files
    scanner options name (``config/path_trust.py``) are both judged by it. See
    ``untrusted_reason``.
    """
    return untrusted_reason(path, scan_root) is not None


def repository_written(
    chain: Iterable[Path],
    scan_root: Path,
    lexical: Iterable[Path] = (),
    *,
    all_untrusted: bool = False,
) -> List[Path]:
    """The files of a config ``chain`` that may not grant sandbox access.

    Args:
        chain: The files a config was built from, as resolved paths, in merge
            order with the root config last (``ResolvedConfigDocument.chain``; in a
            workspace, the operator's config layered over a project's comes last).
            When that last file is one a host marked with its chain
            (``marked_repository_written``), every file of the chain is returned;
            a file marked on its own (``marked_files_repository_written``) is
            returned as one inside a checkout is.
        scan_root: The directory being scanned.
        lexical: The same files as they were named, where that is known (the
            config path the operator passed or ASH discovered). A file whose name
            is in a checkout counts even when its resolved path is not.
        all_untrusted: Every file of the chain, wherever it is: for a config a
            caller other than the operator supplied (an MCP client's upload).
    """
    chain = list(chain)
    if all_untrusted or (chain and _marked_chain(chain[-1])):
        return chain or [Path(path) for path in lexical]
    untrusted = [path for path in chain if untrusted_path(path, scan_root)]
    for path in lexical:
        path = Path(path)
        if path not in untrusted and untrusted_path(path, scan_root):
            untrusted.append(path)
    return untrusted


def scanned_trees(scan_root: Optional[Path]) -> List[Path]:
    """The trees the scanned repository controls, from every name the scan root
    has; none for no scan root (``working_directory`` gave None)."""
    if scan_root is None:
        return []
    trees = []
    for start in (
        as_named(scan_root),
        Path(os.path.realpath(scan_root)),
        *_logical_paths(scan_root),
    ):
        tree = _outermost_checkout(start)
        if tree not in trees:
            trees.append(tree)
    return trees


def files_inside(
    chain: Iterable[Path], trees: Iterable[Path], named: Iterable[Path] = ()
) -> List[Path]:
    """The files of ``chain`` that the scanned repository can write.

    The fail-closed collapse of :func:`confined_files`: an undecided name is a
    member. A caller whose answer feeds a sentence uses ``confined_files``
    instead, so the sentence can say which members only an unfinished walk
    added.
    """
    return list(confined_files(chain, trees, named).members)


def confined_files(
    chain: Iterable[Path], trees: Iterable[Path], named: Iterable[Path] = ()
) -> ConfinedFiles:
    """:func:`files_inside`'s members, with the ones only an unfinished walk added.

    ``chain`` holds resolved paths, judged by where they resolve to. ``named``
    holds the same files as they were named, where that is known (the config path
    the caller passed or discovery found, ASH_CONFIG's value, each ``extends``
    base as its ref names it), judged by where the name sits (``_named_within``):
    a ``.ash/.ash.yaml`` that is a symlink to a file outside the scan root is still
    a file the repository put there. A name is also judged by every link resolving
    it follows (``links_followed``): one that sits in a tree means the repository
    chose where the name leads, as in ``repo/lnk/../x.yaml``. A walk past the
    link bound, or through a link that cannot be read, is undecided, and an
    undecided name is judged the repository's, because the alternative hands out
    grants on a walk that never finished; a mark only takes grants away. Such a
    member is also listed in ``undecided``, since nothing was found to claim a
    location with: a name a seen link already puts in a tree is a found member,
    whatever the rest of its walk, and is not listed there.
    """
    trees = list(trees)
    chain = list(chain)
    named = [Path(path) for path in named]
    # The host's verdict for a config mounted into a container: a chain whose
    # root the host marked (--config-from-scanned-repository) is the
    # repository's whole, and a file marked on its own
    # (--config-file-from-scanned-repository) joins the members as one inside
    # a tree does. Only a root is ever chain-marked, so any chain member
    # carrying the chain mark is that chain's own root.
    if any(_marked_chain(path) for path in (*chain, *named)):
        inside = list(chain)
        inside.extend(path for path in named if path not in inside)
        return ConfinedFiles(members=tuple(inside))
    inside = [
        path
        for path in chain
        if _marked(path) or any(is_within(path, tree) for tree in trees)
    ]
    undecided: List[Path] = []
    for path in named:
        if path in inside:
            continue
        if _marked(path) or _named_within(path, trees):
            inside.append(path)
            continue
        links, decided = _walk_links(path)
        if any(is_within(link.parent, tree) for link in links for tree in trees):
            inside.append(path)
        elif not decided:
            inside.append(path)
            undecided.append(path)
    return ConfinedFiles(members=tuple(inside), undecided=tuple(undecided))


def tree_holding(
    path: Path,
    trees: Iterable[Path],
    names: Optional[Mapping[Path, Sequence[Path]]] = None,
) -> Optional[Path]:
    """The tree of ``trees`` that ``path`` is inside or was reached through, or None.

    The membership test for one file that names the tree, so a refusal can
    say which tree to move the file out of. The file is judged by its own path
    and by each path in ``names`` it was reached by
    (``config_sources.ResolvedConfigDocument.names``), and each of those at
    every link on the way, found by this module's own walk (``_walk_links``),
    which counts a Windows junction as the link it is and says so once when it
    stops before the end; ``Path.is_symlink`` is False for a junction, and a
    walk that stepped through one as a directory never saw the tree it sits in.
    """
    trees = list(trees)
    for name in (path, *(names or {}).get(path, ())):
        links, _decided = _walk_links(name)
        places = [name, *(link.parent for link in links)]
        for tree in trees:
            if any(is_within(place, tree) for place in places):
                return tree
    return None


def membership_clause(
    *,
    checkout_membership: bool,
    client_supplied: bool = False,
    mixed: bool = False,
    given_root: bool = False,
    undecided: bool = False,
    outside: bool = False,
) -> str:
    """The location half of a confinement sentence, shared by every voice.

    The sandbox and settle warnings append their consequence through
    ``confinement_membership``; the plugin-module warning appends its own
    judgment tail. One head for all of them, so the location claims cannot
    drift apart. Each flag names the membership that actually put the file
    under the confinement. *client_supplied* wins -- an uploaded file is
    confined because the session's client sent its content, wherever the
    file sits, and the checkout wording would claim a location it need not
    have. Then *undecided* -- a file is on the line because resolving its
    name stopped before the walk finished (``confined_files``'s or
    ``checkout_judgment``'s undecided answer), so every location claim
    would state as found what the walk never established; with *mixed*
    beside it the line also names files whose location WAS found, and the
    sentence says each file's own reason. Then *outside* -- some file is on
    the line because it sits in a git checkout other than the scanned tree,
    or because an MCP client delivered it, so neither location claim below
    fits it, and the one sentence names every membership a file can have. A
    load with no scanned tree (*given_root*, or *checkout_membership* from the
    rootless reading) leaves the scanned tree out of that sentence: it never
    claims one the load does not have.
    Then *mixed* -- the line names files of BOTH located memberships, so a
    sentence claiming either one for every file would be false for the
    other's -- then *checkout_membership*, the any-checkout rule's; then
    *given_root*, files_inside's own membership under a no-tree load whose
    trees are known; otherwise the plain scanned-tree one.

    The checkout head is root-aware: under known trees (*given_root* beside
    it) the checkout file is read as the repository's, since the load
    declared no scanned tree for it to be read as; only the rootless load
    keeps the scanned-tree reading. No production load produces a mixed
    line (a chain's bases stay inside one confinement root, and everything
    inside a root that is its own tree is files_inside's); the one load
    that does is the API shape whose operator config sits outside the given
    root and extends a base of each membership, so the flag keeps that
    caller, and a direct caller holding both groups, honest. The mixed
    sentence is root-aware like the checkout one: with *given_root* -- set
    when the load's trees are known: a root given, or also_scanned's -- it
    speaks the given root's trees; without it, it speaks the host's mark
    and the checkout reading, and never claims a root, or a scanned tree,
    the load does not have. The rootless mixed shape is a direct caller's
    alone: resolve_config words a rootless line as the checkout one.
    """
    if client_supplied:
        return (
            "the file's content is the session client's, which is read as "
            "the repository's"
        )
    if undecided and mixed:
        return (
            "each file is the repository's -- by where it sits, or because "
            "resolving its name stopped before the walk finished, which is "
            f"read as the repository's {_MIXED_HEAD_CLOSING}"
        )
    if undecided:
        return (
            "whether the file is the repository's could not be decided "
            "(resolving its name stopped before the walk finished), which "
            "is read as the repository's"
        )
    if outside:
        # A load that has no scanned tree (a root given but declared not
        # scanned, or no working directory) must never claim one.
        if given_root or checkout_membership:
            return "the file is inside a git checkout, or an MCP client delivered it"
        return (
            "the file is inside the scanned tree or a git checkout, or an MCP "
            "client delivered it"
        )
    if mixed and given_root:
        return (
            "each file is the repository's -- inside the given root's trees, "
            "or in a checkout, which with no scanned tree is read as the "
            f"repository's {_MIXED_HEAD_CLOSING}"
        )
    if mixed:
        return (
            "each file is the repository's -- by the host's mark (a checkout "
            "verdict), or in a checkout, which with no working directory is "
            f"read as the scanned tree {_MIXED_HEAD_CLOSING}"
        )
    if checkout_membership and given_root:
        return (
            "the file is in a checkout, which with no scanned tree is read "
            "as the repository's"
        )
    if checkout_membership:
        return (
            "the file is in a checkout, which with no working directory is "
            "read as the scanned tree"
        )
    if given_root:
        return "the file is inside the given root's trees"
    return "the file is inside the scanned tree"


#: The mixed membership head closes its parenthetical with this dash, and
#: ``joined_membership`` keys its punctuation on the same constant, so a
#: rewording of the mixed sentence cannot silently flip how every joined
#: sentence is punctuated.
_MIXED_HEAD_CLOSING = "--"


def joined_membership(head: str, tail: str) -> str:
    """``head`` and ``tail`` as one sentence: the mixed head carries its own
    dash (``_MIXED_HEAD_CLOSING``), every other head takes a comma."""
    if head.endswith(_MIXED_HEAD_CLOSING):
        return f"{head} {tail}"
    return f"{head}, {tail}"


def confinement_membership(
    *,
    checkout_membership: bool,
    client_supplied: bool = False,
    mixed: bool = False,
    given_root: bool = False,
    undecided: bool = False,
    outside: bool = False,
) -> str:
    """The one sentence a sandbox or settle warning explains its drop with.

    Keyword-only: the first flag's meaning changed when it was renamed from
    the old no-scanned-tree parameter, so a positional call written against
    the old meaning must fail with a TypeError instead of binding silently
    to the new one. The location half and the flags' meaning are
    ``membership_clause``'s; this adds the sandbox and settle consequence.
    """
    head = membership_clause(
        checkout_membership=checkout_membership,
        client_supplied=client_supplied,
        mixed=mixed,
        given_root=given_root,
        undecided=undecided,
        outside=outside,
    )
    if client_supplied:
        return joined_membership(head, "so that content wrote it")
    if undecided:
        # The walk found no location, so no one is said to have written it.
        return joined_membership(head, "so that repository may have written it")
    if outside:
        return joined_membership(
            head, "so someone other than the operator may have written it"
        )
    if mixed or checkout_membership or given_root:
        return joined_membership(head, "so that repository wrote it")
    return joined_membership(head, "so the repository being scanned wrote it")


def confine_sandbox_grants(
    sandbox: SandboxConfig,
    trusted: SandboxConfig,
    in_tree: List[Path],
    environment_paths: Collection[Path] = frozenset(),
    *,
    # The four wording flags carry no defaults, like confine_plugin_modules':
    # a default is a guess about the caller's membership, and every
    # caller stating them feeds the three warning voices the same values.
    checkout_membership: bool,
    client_supplied: bool = False,
    mixed_membership: bool,
    given_root_membership: bool,
    undecided_membership: bool,
    outside_membership: bool = False,
    network_limit_kept: Optional[List[str]] = None,
    source: Optional[UntrustedSource] = None,
) -> None:
    """Replace the grants in ``sandbox`` with ``trusted``'s, keeping its list as a limit.

    Args:
        sandbox: The resolved settings, from the config files plus the overrides.
        trusted: The same settings resolved from the trusted base plus the
            overrides. Must be a separate resolution: comparing ``sandbox`` with
            itself, or with a copy of itself, would keep every grant.
        in_tree: The config files that may not grant. Named in the warning.
        environment_paths: Those of them the environment chose, named
            ``<value>`` (``described``).
        checkout_membership: The *in_tree* files are in a checkout: the
            any-checkout rule added them (the caller knows no tree is
            scanned; trees may still resolve from its source directory), or
            the load has no tree at all and each file is there by the
            host's mark, which is the host's checkout verdict
            (``resolve_config``'s ``rootless_wording``). The warning then
            explains the drop by the checkout rule -- the scanned-tree
            wording would contradict it, the same keying the operator-only
            settle warnings use. The
            plugin-module drop warning keys its own arms on its own judgment
            (root-based when a root is given), and agrees on the membership
            half of the sentence.
        client_supplied: The *in_tree* files are there because the session's
            client supplied their content, not by any checkout or tree
            membership, so the warning says so (``confinement_membership``);
            either location wording could be false for an uploaded file.
        mixed_membership: *in_tree* holds files of BOTH memberships (some
            added by files_inside, some by the any-checkout rule), so the
            one line names each file's own membership
            (``confinement_membership``'s mixed sentence) instead of
            claiming either for all of them.
        given_root_membership: The load declared no scanned tree but gave a
            root, and files_inside added the *in_tree* files against that
            root's trees, so the warning speaks the given root
            (``confinement_membership``): the scanned-tree wording would
            claim a tree the caller said does not exist, the same reason
            the plugin-module line speaks the given root there. Yields to
            every flag above -- the checkout and mixed rules name what put
            the files under the confinement, and the client one what wrote
            them.
        undecided_membership: Some of *in_tree* are there only because
            resolving their name stopped before the walk finished
            (``confined_files``'s or ``checkout_judgment``'s undecided
            answer), so the warning says the walk stopped
            (``confinement_membership``) instead of stating a location it
            never established. The judgment is unchanged: an undecided file
            is confined exactly as a located one is.
        outside_membership: Some of *in_tree* are there because they sit in
            a git checkout other than the scanned tree, on a load that has a
            scanned tree, or because an MCP client delivered them
            (``resolve_config``'s outside files), so the warning names every
            membership instead of the scanned-tree or no-working-directory
            sentence, either of which would be false for them. Wording only.
        network_limit_kept: The scanners a ``network_scanners`` list in the
            operator's file in another git checkout allows a network, which that
            file may keep as a limit although it may not grant
            (``restrictions_kept``). Joins the limit the config's own list gives,
            so a scanner outside either gets no network. None adds no limit.
        source: Why those files are not the operator's, and the fix, for the
            warning's tail (``untrusted_source.UntrustedSource``): its
            ``scanner_steps_note`` replaces the tail where no scanner runs
            (``ash merge``), and its ``remedy`` ends the warning otherwise.
            None keeps the in-tree-or-delivered tail.
    """
    if trusted is sandbox:
        raise ValueError("the trusted sandbox settings must not be the subject")
    ignored = []
    if sandbox.network_scanners != trusted.network_scanners:
        ignored.append("sandbox.network_scanners")
    for key in (
        "extra_read_paths",
        "read_path_scanners",
        "env_scanners",
        "environment",
    ):
        if list(getattr(sandbox, key)) != list(getattr(trusted, key)):
            ignored.append(f"sandbox.{key}")
    if trusted.mode != "off" and sandbox.mode != trusted.mode:
        ignored.append("sandbox.mode")
        sandbox.mode = trusted.mode
    limit = sandbox.network_scanners
    if network_limit_kept is not None:
        limit = (
            list(network_limit_kept)
            if limit is None
            else [name for name in limit if name in network_limit_kept]
        )
    sandbox.network_scanners = (
        list(trusted.network_scanners) if trusted.network_scanners is not None else None
    )
    sandbox.extra_read_paths = list(trusted.extra_read_paths)
    sandbox.read_path_scanners = list(trusted.read_path_scanners)
    sandbox.env_scanners = list(trusted.env_scanners)
    sandbox.environment = list(trusted.environment)
    sandbox.network_limit = list(limit) if limit is not None else None
    if ignored:
        if source is not None and not source.located:
            # A config that is no file in a tree (ash merge's shard record):
            # the location clause would claim a place it has none of, so the
            # source's own reason is the head, as the plugin-module step says it.
            membership = source.reason
        else:
            membership = confinement_membership(
                checkout_membership=checkout_membership,
                client_supplied=client_supplied,
                mixed=mixed_membership,
                given_root=given_root_membership,
                undecided=undecided_membership,
                outside=outside_membership,
            )
        if source is not None and source.scanner_steps_note:
            tail = f"{source.scanner_steps_note}."
        else:
            tail = (
                "A network_scanners list there still removes network from "
                "scanners it does not name, and a sandbox mode there still applies "
                "when nothing else turns the sandbox on. "
                + (
                    source.remedy
                    if source is not None
                    # A file in another checkout is already outside the tree, so
                    # "outside the tree" is no way to keep a setting from it.
                    else KEEP_A_SETTING
                    if outside_membership
                    else "Set these with --config-overrides or a config file "
                    "outside the tree."
                )
            )
        ASH_LOGGER.warning(
            shown_on_one_line(
                f"Ignoring {', '.join(ignored)} from "
                f"{described(in_tree, environment_paths)}: {membership}. {tail}"
            ),
            extra=NO_MARKUP,
        )
