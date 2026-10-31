"""Keep ASH's own writes inside its output directory and a scanner's results directory.

ASH writes files below its output directory itself, unsandboxed: worker request
files, stream logs, ASH.ScanResults.json, the SARIF a scanner override assembles.
Something other than ASH can leave a symlink there. The default output directory is
inside the scanned tree, so the repository can commit one, and a sandboxed scanner
may write anything under its results directory, links included. A plain open()
follows such a link, and the write would land wherever it points. Two measures close
that:

* :func:`open_for_write` is what ASH uses for those writes. Below a registered root
  (the output directory of every :class:`PluginContext`, and each sandboxed
  scanner's results directory) it opens every component without following a link,
  and refuses a link at any of them, the file name included, with
  :class:`OutputLinkRefused`. The link is left where it is. A file that another
  name also refers to (a hard link) is refused with :class:`OutputHardLinkRefused`
  before it is truncated. :func:`open_for_atomic_write` is the same guard for a
  file a reader may open while it is written: it writes a staging file and renames
  it over the name, and ``atomic_write.write_text_atomically`` calls it.
* :func:`sweep_writable` runs after every sandboxed spawn and removes every entry
  under the writable directories that is not a regular file or a directory.

A root itself must not be a link. ``_open_dir_beneath`` opens the root by name and
follows a link at it, so every check below it would then be made in wherever the
link points. register_writable_root, and open_for_write for a root its caller
names, refuse a root that is a symlink or a junction with OutputLinkRefused. The
output directory checks in ``utils/output_dir_links`` refuse a linked output
directory before any root is registered; this is the guard for a caller that
skipped them.
"""

from __future__ import annotations

import collections
import contextvars
import errno
import os
import secrets
import stat
import threading
import weakref

try:
    import fcntl
except ImportError:  # Windows, where no sandbox backend exists
    fcntl = None  # type: ignore[assignment]
from contextlib import closing, contextmanager
from pathlib import Path
from typing import (
    IO,
    Any,
    Callable,
    Dict,
    FrozenSet,
    Generator,
    Iterable,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.output_dir_links import (
    OutputDirLinkRefused,
    is_link,
)

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
# O_BINARY on Windows, so the CRT does not translate newlines a second time under
# the text wrapper; open() does the same.
_BINARY = getattr(os, "O_BINARY", 0)


class OutputLinkRefused(OSError, OutputDirLinkRefused):
    """A write below a guarded root met a symlink, and was not made.

    An ``OSError`` (``errno.ELOOP``), so a caller that handles a failed write
    handles this one, and an ``OutputDirLinkRefused`` (a ``ValueError``), so a
    caller that handles a link refused at the output directory handles this one
    too. The message names the path ASH was writing and the link; ``found``
    describes the link as ``OutputDirLinkRefused`` does.
    """

    def __init__(
        self,
        path: Union[str, Path],
        link: Union[str, Path],
        where: str = "below its output directory",
    ) -> None:
        found = f"{Path(link).as_posix()} is a symlink"
        # OSError's own __init__, named rather than reached through super(): it is
        # the next __init__ in the MRO, and OutputDirLinkRefused's is not called;
        # its attribute is set below.
        OSError.__init__(
            self,
            errno.ELOOP,
            f"{Path(path).as_posix()} was not written: {found}, and ASH does not "
            f"write through a symlink {where}",
        )
        self.found = found
        # The base class's attribute, which its __init__ would have set: a reader
        # of any OutputDirLinkRefused shows it.
        self.remedy = (
            "Remove the link, or use an output directory the scanned repository "
            "does not write to."
        )
        self.path = Path(path)
        self.link = Path(link)
        self.where = where

    def __reduce__(self) -> Tuple[type, Tuple[Any, ...]]:
        # Rebuilt from its own arguments: the default rebuilds from OSError's args,
        # which this __init__ does not take.
        return (type(self), (self.path, self.link, self.where))


class OutputHardLinkRefused(OSError, OutputDirLinkRefused):
    """A write below a guarded root met a file that another name also refers to.

    A hard link, as an extracted archive can hold, to a file anywhere on the same
    filesystem: writing it would change that file. An ``OSError``
    (``errno.EMLINK``) and an ``OutputDirLinkRefused``, as OutputLinkRefused is.
    Nothing is written, and the file is not truncated.
    """

    def __init__(self, path: Union[str, Path], links: int) -> None:
        found = f"{links} names refer to {Path(path).as_posix()}"
        # OSError's own __init__, as in OutputLinkRefused.
        OSError.__init__(
            self,
            errno.EMLINK,
            f"{Path(path).as_posix()} was not written: {links} names refer to it, and "
            "ASH does not write to a file below its output directory that another "
            "name refers to",
        )
        self.found = found
        self.remedy = (
            "Remove the file's other names, or use an output directory the scanned "
            "repository does not write to."
        )
        self.path = Path(path)
        self.links = links

    def __reduce__(self) -> Tuple[type, Tuple[Any, ...]]:
        return (type(self), (self.path, self.links))


_roots_lock = threading.Lock()
#: Each registered root, with how many holders registered it.
_writable_roots: Dict[Path, int] = {}
#: Releases queued by garbage-collection finalizers, applied under the lock by the
#: next registry call. A finalizer can run inside any allocation, including one made
#: while this thread holds _roots_lock, so it must not take the lock itself.
_pending_releases: "collections.deque[Path]" = collections.deque()


def _apply_pending_releases() -> None:
    """Apply queued releases; the caller holds _roots_lock."""
    while True:
        try:
            root = _pending_releases.popleft()
        except IndexError:
            return
        _decrement(root)


def _decrement(root: Path) -> None:
    count = _writable_roots.get(root, 0) - 1
    if count > 0:
        _writable_roots[root] = count
    else:
        _writable_roots.pop(root, None)


def register_writable_root(path: Union[str, Path]) -> Path:
    """Record that ASH writes beneath ``path`` and must not follow a link there.

    A run's output directory (run_ash_scan), the output directory of each
    PluginContext while it exists, and a sandboxed scanner's results and writable
    directories while its scope or spawn lasts. open_for_write then opens every
    component below it without following a link, and refuses one. Registrations
    are counted: each holder releases its own with release_writable_root, or uses
    writable_root, and the root stays until the last holder has. Returns the root.

    A root that is a link is refused with OutputLinkRefused and not registered; see
    the module docstring.
    """
    root = Path(os.path.abspath(path))
    _refuse_linked_root(root)
    with _roots_lock:
        _apply_pending_releases()
        _writable_roots[root] = _writable_roots.get(root, 0) + 1
    return root


def release_writable_root(path: Union[str, Path]) -> None:
    """Release one registration of ``path``; a root never registered is ignored."""
    root = Path(os.path.abspath(path))
    with _roots_lock:
        _apply_pending_releases()
        _decrement(root)


def release_writable_root_later(root: Path) -> None:
    """Queue one release of ``root``, for a ``weakref.finalize`` callback.

    Takes no lock: a finalizer may run while this thread is inside the registry.
    The next registry call applies it.
    """
    _pending_releases.append(root)


#: The releases of the objects that registered a root inside the current
#: run_roots() block, so the block can make them when it ends. A ContextVar: the
#: scan phase runs scanners through contextvars.copy_context(), so an object made in
#: a worker thread is the run's too.
_RUN_RELEASES: "contextvars.ContextVar[Optional[List[weakref.finalize[..., Any]]]]" = (
    contextvars.ContextVar("ash_fs_guard_run_releases", default=None)
)


def release_with_holder(holder: object, root: Path) -> None:
    """Release ``root``'s registration when ``holder`` is gone, or the run ends.

    For a registration an object makes for itself (a PluginContext's output
    directory, a scanner's sandbox scope). The release is a ``weakref.finalize`` on
    ``holder``, and inside run_roots() the block makes it when it ends, whether or
    not ``holder`` has been collected: an object in a reference cycle can outlive
    its scan until the collector runs. A finalize runs once, so a holder collected
    later releases nothing twice.
    """
    release = weakref.finalize(holder, release_writable_root_later, root)
    releases = _RUN_RELEASES.get()
    if releases is not None:
        releases.append(release)


@contextmanager
def run_roots() -> Iterator[None]:
    """One scan: every release_with_holder made inside is made when the block ends."""
    releases: List[weakref.finalize[..., Any]] = []
    token = _RUN_RELEASES.set(releases)
    try:
        yield
    finally:
        _RUN_RELEASES.reset(token)
        for release in releases:
            release()


@contextmanager
def writable_root(path: Union[str, Path]) -> Iterator[Path]:
    """``path`` registered for the block, and released after it."""
    root = register_writable_root(path)
    try:
        yield root
    finally:
        release_writable_root(root)


def registered_roots() -> FrozenSet[Path]:
    """The roots registered now."""
    with _roots_lock:
        _apply_pending_releases()
        return frozenset(_writable_roots)


def _root_anchor(path: Path, roots: Iterable[Path]) -> Optional[Tuple[Path, Path]]:
    """The outermost of ``roots`` that ``path`` is below, with its spelling in ``path``.

    Returns ``(root, anchor)``: the root as registered, and the ancestor of
    ``path`` that is that root. By spelling first (the root is one of ``path``'s
    parents); else by identity: an ancestor of ``path`` that resolves to the
    same directory as the root, as when the root is registered as ``/home/me/out``
    and the write is spelled ``/local/home/me/out/x`` through a link above the
    root. Only the ancestors are resolved, never the components below the root,
    which the guard examines one by one without following a link.

    The outermost root wins. With the output directory and a scanner's results
    directory inside it both registered, choosing the deepest opened the results
    directory by name, so a link planted at a component between the two was
    followed; from the outermost root every component below it is opened without
    following one.

    The identity match is made outermost ancestor first, and only over the
    ancestors ABOVE the outermost root matched by spelling. Two ancestors can
    resolve to one root when a scanner plants a link below the root that points
    back at it (``out/sub/back -> out``): the outer spelling is the anchor and
    ``back`` is then a component the guard refuses, where taking the deeper one
    opened the planted link by name. Below a root matched by spelling nothing is
    resolved at all, which is also what spares most writes the resolution.
    """
    found: List[Tuple[Path, Path]] = []
    unmatched: List[Path] = []
    for root in roots:
        if root in path.parents:
            found.append((root, root))
        else:
            unmatched.append(root)
    if unmatched:
        above: List[Path] = list(path.parents)
        if found:
            outermost = min(found, key=lambda pair: len(pair[1].parts))[1]
            above = [p for p in above if len(p.parts) < len(outermost.parts)]
        # path.parents runs from the deepest ancestor up; reversed, the outermost
        # spelling of each real directory is the one kept.
        real_ancestors: Dict[str, Path] = {}
        for ancestor in reversed(above):
            real_ancestors.setdefault(os.path.realpath(ancestor), ancestor)
        for root in unmatched:
            anchor = real_ancestors.get(os.path.realpath(root))
            if anchor is not None:
                found.append((root, anchor))
    if not found:
        return None
    return min(found, key=lambda pair: len(pair[1].parts))


def _writable_root_for(path: Path) -> Optional[Path]:
    """The outermost registered root ``path`` is below, by spelling or identity, or None."""
    anchored = _registered_anchor(path)
    return anchored[0] if anchored is not None else None


def _registered_anchor(path: Path) -> Optional[Tuple[Path, Path]]:
    """``_root_anchor`` over the registered roots."""
    with _roots_lock:
        _apply_pending_releases()
        roots = list(_writable_roots)
    return _root_anchor(path, roots)


def _refuse_linked_root(root: Path) -> None:
    """Raise OutputLinkRefused if ``root`` is a symlink or a junction."""
    if is_link(root):
        raise OutputLinkRefused(root, root, where="at a directory it writes below")


def _guard_root(
    path: Path, root: Optional[Union[str, Path]]
) -> Optional[Tuple[Path, Path]]:
    """The root open_for_write checks ``path`` below, and its spelling in ``path``.

    See open_for_write's ``root`` argument. Returns ``(root, anchor)`` as
    ``_root_anchor`` does, or None when nothing guards ``path``.
    """
    registered = _registered_anchor(path)
    if root is None:
        return registered
    named = Path(os.path.abspath(root))
    anchored = _root_anchor(path, [named])
    if anchored is None:
        raise ValueError(f"{path.as_posix()} is not below {named.as_posix()}")
    _refuse_linked_root(named)
    if registered is not None and len(registered[1].parts) < len(anchored[1].parts):
        return registered
    return anchored


def _sweep_warning(
    text: str, value_free: str, values: Iterable[str], values_unread: bool
) -> str:
    """Log a sweep failure, redacted with the sweep's values; return the line logged.

    ``text`` names the entry or root and the OS error; ``value_free`` says the
    same with nothing a tool or an option chose. When the caller could not read
    its redaction values (``values_unread``) nothing in ``text`` can be hidden, so
    the value-free line is logged instead. The returned line is the one a caller
    may put in an exception: it carries nothing the log does not.
    """
    if values_unread:
        # The values to hide could not be read, so nothing here can be redacted:
        # no entry name, root or OS error.
        ASH_LOGGER.warning(value_free)
        return value_free
    # The entry's name and the root are paths a tool or an option chose, so
    # either can hold an env-read value: redacted with the sweep's values, and
    # the scope's, before it is logged.
    from automated_security_helper.utils.sandbox.scope import scope_shown_text

    shown = scope_shown_text(text, tuple(values))
    ASH_LOGGER.warning(shown)
    return shown


#: What the walks report through their ``refuse`` callback for a directory they
#: could not open or list, an entry they could not examine, and a directory they
#: did not enter because of the depth limit.
_REFUSE_LIST = "list"
_REFUSE_EXAMINE = "examine"
_REFUSE_DESCEND = "sweep below"


def _below(relative: str, name: str) -> str:
    """``name``'s path relative to the root, given its directory's."""
    return name if relative == "." else f"{relative}/{name}"


def _walk_descriptors(
    root: Path, refuse: "Callable[[str, str, OSError], None]"
) -> Generator[Tuple[str, int, Dict[str, os.stat_result], List[str]], None, None]:
    """Walk ``root`` top-down through directory descriptors, never following a link.

    For each directory reached this yields ``(relative, dir_fd, statuses,
    dirnames)``: its path relative to ``root`` (``"."`` for the root itself), its
    open descriptor, the lstat of every entry in it by name, and the names of its
    subdirectories, which the caller may remove from the list to keep the walk
    out of them. Entries are examined and subdirectories opened relative to the
    descriptor, so a component replaced by a link while the walk runs is not
    followed.

    Nothing here raises for what the tree holds. A directory that cannot be
    opened or listed (the root included), an entry whose lstat fails with
    anything but ENOENT, and a directory with more directories below it at
    _SWEEP_DEPTH_LIMIT (``_too_deep``) are each reported once through
    ``refuse(what, relative, error)``, with ``what`` one of _REFUSE_LIST,
    _REFUSE_EXAMINE and _REFUSE_DESCEND and ``relative`` the full path below
    the root, and the walk goes on with the next entry or sibling. An entry or
    directory that vanished between the listing and its examination is passed
    over. A missing root yields nothing.

    Written here rather than over os.fwalk because fwalk reports an unopenable
    subdirectory to ``onerror`` by its bare name, with no parent to tell ``a/cache``
    from ``b/cache``, raises for the root itself without calling ``onerror`` at all,
    and ends the whole walk when ``onerror`` raises, siblings unvisited.
    """
    try:
        fd = os.open(root, _DIR_WALK_FLAGS)
    except FileNotFoundError:
        return
    except OSError as error:
        refuse(_REFUSE_LIST, ".", error)
        return
    try:
        yield from _walk_descriptor(root, fd, (), refuse)
    finally:
        os.close(fd)


def _walk_descriptor(
    root: Path,
    fd: int,
    parts: Tuple[str, ...],
    refuse: "Callable[[str, str, OSError], None]",
) -> Iterator[Tuple[str, int, Dict[str, os.stat_result], List[str]]]:
    """One directory of ``_walk_descriptors``: its entries, then its subdirectories."""
    relative = "/".join(parts) if parts else "."
    try:
        names = os.listdir(fd)
    except OSError as error:
        refuse(_REFUSE_LIST, relative, error)
        return
    statuses: Dict[str, os.stat_result] = {}
    dirnames: List[str] = []
    for name in names:
        try:
            status = os.lstat(name, dir_fd=fd)
        except FileNotFoundError:
            continue
        except OSError as error:
            # A directory the process can read but not search lists its entries
            # and refuses their lstat (EACCES): a link there would otherwise be
            # passed over, the hole the sweep and the pre-check exist to close.
            refuse(_REFUSE_EXAMINE, _below(relative, name), error)
            continue
        statuses[name] = status
        if stat.S_ISDIR(status.st_mode):
            dirnames.append(name)
    yield relative, fd, statuses, dirnames
    if not dirnames:
        return
    try:
        _too_deep(root, os.path.join(root, *parts), dirnames)
    except OSError as error:
        refuse(_REFUSE_DESCEND, relative, error)
        return
    for name in dirnames:
        try:
            child = os.open(name, _DIR_WALK_FLAGS, dir_fd=fd)
        except FileNotFoundError:
            continue
        except OSError as error:
            # EACCES for a mode the scanner set; ELOOP or ENOTDIR for a directory
            # replaced by a link since its lstat, which O_NOFOLLOW refuses to
            # follow and this walk does not remove.
            refuse(_REFUSE_LIST, _below(relative, name), error)
            continue
        try:
            yield from _walk_descriptor(root, child, parts + (name,), refuse)
        finally:
            os.close(child)


def _relative_skips(root: Path, skip: Iterable[Union[str, Path]]) -> FrozenSet[str]:
    """The paths in ``skip`` below ``root``, relative to it in the walks' form.

    Compared by name and never resolved: the walk reaches a directory under the
    name the backend made it with, and a link a scanner planted at that name is not
    a directory, so the walk removes and counts it as it does any other link. A
    path that is the root, above it, beside it or on another drive names nothing
    here.
    """
    base = os.path.abspath(root)
    below: Set[str] = set()
    for path in skip:
        candidate = os.path.abspath(path)
        if candidate == base:
            continue
        try:
            if os.path.commonpath([base, candidate]) != base:
                continue
        except ValueError:  # different drives, Windows
            continue
        below.add(os.path.relpath(candidate, base).replace(os.sep, "/"))
    return frozenset(below)


def _sweep_tree(
    root: Path,
    values: Iterable[str] = (),
    values_unread: bool = False,
    refusals: Optional[List[OSError]] = None,
    skip: Iterable[Union[str, Path]] = (),
) -> int:
    """Remove non-regular, non-directory entries under ``root``; return how many.

    The walk (``_walk_descriptors``) descends through directory file descriptors
    and never follows a symlink, so a directory replaced by a link while it runs
    is not entered, and entries are removed relative to their directory's
    descriptor for the same reason. Platforms without directory descriptors
    (Windows, where no sandbox backend exists) fall back to os.walk, with the
    same decisions made by name.

    What the walk cannot do is refused, never skipped: a directory it cannot open
    or list (a mode the scanner set, a descriptor limit), an entry it cannot
    examine (a directory readable but not searchable), an entry it cannot remove
    (a directory the scanner made read-only around its link), a tree nested past
    _SWEEP_DEPTH_LIMIT. Skipped, every link below the spot would survive for a
    reader that opens paths by name to follow. Each refusal is logged as a removal
    failure is (``_sweep_warning``: redacted with the sweep's values, value-free
    when they could not be read) and the sweep GOES ON: the siblings of a refused
    directory are still swept, and so is the rest of the tree, so a scanner cannot
    shield one link with one unlistable directory. The refusals are collected as
    OSErrors whose text is the logged line and nothing more, so the exception that
    reaches the executor's failure handler (which can only redact with the plugin's
    own values, the ones that could not be read) names no tool-chosen path when
    the warning did not. With ``refusals`` given they are appended there for the
    caller to raise once over every root (sweep_writable); without it, the first is
    raised when this tree is done, with the others counted.

    The one thing passed over by design is a directory named in ``skip``: ASH's
    own private directories for the spawn (``SpawnPlan.private_dirs``, the cache
    ``backends._private_caches`` makes under the results directory before the
    scanner runs). The backend's own cleanup step removes each of them whole in the
    same run (shutil.rmtree follows no link), and what they hold is ASH's, not
    something the scanner left: uv fills its cache with links, which a sweep that
    walked the directory counted and removed as a scanner's. The match is by the
    name the backend made the directory under, relative to the root
    (``_relative_skips``); a link a scanner planted at that name is removed and
    counted like any other, and nothing beside or above the named directory is
    passed over.

    A missing root has nothing below it and sweeps as empty: a sandboxed scanner
    that wrote nothing never created its results directory.
    """
    values = tuple(values)
    collected: List[OSError] = [] if refusals is None else refusals
    skipped = _relative_skips(root, skip)

    def refuse(what: str, relative: str, error: OSError) -> None:
        shown = _sweep_warning(
            f"Could not {what} {relative} under {root}: {error}",
            f"Could not {what} an entry of a scanner's results directory; it is not "
            "named because the plugin's redaction values could not be read",
            values,
            values_unread,
        )
        collected.append(OSError(_errno_of(error), shown))

    def remove(name: str, dir_fd: Optional[int], path: Union[str, Path]) -> int:
        # A removal that fails is a refusal like a directory that cannot be
        # listed: the link stays where a reader that opens paths by name would
        # follow it (a scanner can plant one and take the directory's write bit
        # away), so it is logged, kept with the other refusals, and the sweep
        # goes on to the next entry so nothing else is shielded by it.
        try:
            if dir_fd is None:
                os.unlink(path)
            else:
                os.unlink(name, dir_fd=dir_fd)
        except OSError as e:
            shown = _sweep_warning(
                f"Could not remove {name} under {root}: {e}",
                "Could not remove an entry a scanner left in its results "
                "directory; it is not named because the plugin's redaction "
                "values could not be read",
                values,
                values_unread,
            )
            collected.append(OSError(_errno_of(e), shown))
            return 0
        return 1

    removed = 0
    if not hasattr(os, "fwalk"):
        removed = _sweep_by_name(root, refuse, remove, skipped)
    else:
        # closing(): a consumer that leaves the loop early (an exception) closes
        # the walk's open directory descriptors at once, not when the generator
        # is finalized, which another interpreter can defer.
        with closing(_walk_descriptors(root, refuse)) as walk:
            for relative, dir_fd, statuses, dirnames in walk:
                for name, status in statuses.items():
                    if _is_special(status.st_mode):
                        removed += remove(name, dir_fd, name)
                if skipped:
                    # The walk descends into what is left in this list once it
                    # resumes; a named directory's entries are the backend's to
                    # remove. A link at the name was removed and counted above.
                    dirnames[:] = [
                        name
                        for name in dirnames
                        if _below(relative, name) not in skipped
                    ]
    if refusals is None and collected:
        raise _sweep_refused(collected) from None
    return removed


def _sweep_by_name(
    root: Path,
    refuse: "Callable[[str, str, OSError], None]",
    remove: "Callable[[str, Optional[int], Union[str, Path]], int]",
    skipped: FrozenSet[str] = frozenset(),
) -> int:
    """``_sweep_tree`` over os.walk, for a platform without directory descriptors.

    The same refusals as the descriptor walk, reported through ``refuse`` with the
    directory's path relative to ``root``: os.walk hands ``onerror`` the full path
    of the directory it could not list, the root included, and goes on with the
    siblings when ``onerror`` returns. ``skipped`` is the descriptor walk's: the
    directories, relative to ``root``, that are not descended into.
    """
    removed = 0

    def relative_to_root(path: Union[str, bytes, None]) -> str:
        if path is None:
            return "."
        return os.path.relpath(os.fsdecode(path), root).replace(os.sep, "/")

    def unlistable(error: OSError) -> None:
        if error.errno == errno.ENOENT:
            # Removed while the walk ran, or never created: nothing is below it.
            return
        refuse(_REFUSE_LIST, relative_to_root(error.filename), error)

    for dirpath, dirnames, filenames in os.walk(
        root, onerror=unlistable, followlinks=False
    ):
        relative = relative_to_root(dirpath)
        for name in list(dirnames) + filenames:
            path = os.path.join(dirpath, name)
            try:
                mode = os.lstat(path).st_mode
            except FileNotFoundError:
                continue
            except OSError as error:
                refuse(_REFUSE_EXAMINE, _below(relative, name), error)
                continue
            if not _is_special(mode):
                continue
            removed += remove(name, None, path)
            if name in dirnames:
                dirnames.remove(name)
        if skipped:
            dirnames[:] = [
                name for name in dirnames if _below(relative, name) not in skipped
            ]
        try:
            _too_deep(root, dirpath, dirnames)
        except OSError as error:
            refuse(_REFUSE_DESCEND, relative, error)
            dirnames.clear()
    return removed


def _errno_of(error: OSError) -> int:
    """``error``'s errno, or EIO for an OSError raised without one."""
    return error.errno if error.errno is not None else errno.EIO


def _sweep_refused(refusals: List[OSError]) -> OSError:
    """One OSError for a sweep's refusals, saying no more than their warnings did.

    The first refusal's errno (so EACCES is a PermissionError, as before) and its
    logged line, with the others counted: each was logged in full as it was met,
    so the exception, which travels into ash.log, the scanner's row and its
    results file, repeats nothing and names nothing the warnings kept back. The
    caller raises it ``from None``: the OSErrors the walk met carry the raw paths.
    """
    first = refusals[0]
    more = (
        ""
        if len(refusals) == 1
        else f"; and {len(refusals) - 1} more, each logged as a warning"
    )
    return OSError(first.errno, f"{first.strerror}{more}")


def _is_special(mode: int) -> bool:
    return not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))


#: How many directory levels below a root the walks descend. CPython's fwalk and
#: walk recurse once per level, and the interpreter's recursion limit is about a
#: thousand frames; a sweep that met a chain that deep raised RecursionError
#: (3.10-3.12) or stopped at the descriptor limit (3.13+) and reported nothing.
_SWEEP_DEPTH_LIMIT = 200


def _too_deep(root: Path, dirpath: Union[str, bytes], dirnames: List[str]) -> None:
    """Raise OSError when ``dirpath`` holds directories past the depth limit.

    Called by the walks at each directory before they descend: a directory at the
    limit that still has subdirectories ends the walk with ELOOP and a message,
    so the caller fails the scanner rather than passing over what lies below.
    """
    if not dirnames:
        return
    depth = len(Path(os.fsdecode(dirpath)).relative_to(root).parts)
    if depth >= _SWEEP_DEPTH_LIMIT:
        raise OSError(
            errno.ELOOP,
            f"{os.fsdecode(dirpath)} under {root} is nested {depth} directories "
            f"deep, past the {_SWEEP_DEPTH_LIMIT} the sweep descends, so what lies "
            "below it could not be examined",
        )


def refuse_links_below(root: Union[str, Path]) -> None:
    """Raise for the first symlink, or file another name refers to, below ``root``.

    For a sandboxed scanner's results directory before the scanner runs: the sweep
    after each spawn removes links the scanner made, and would also remove one that
    was there before it ran (committed with the scanned tree) without saying so. A
    regular file with more than one name is refused too (OutputHardLinkRefused):
    the scanner can write the results directory, and a write to that file changes
    every name it has. The walk never follows a link. A missing ``root`` has nothing
    below it; a root that is itself a link is refused as a link at it (the sweep
    after the spawn would remove it without a word), and one that is not a
    directory raises NotADirectoryError. The root is read with os.lstat, not
    ``Path.is_dir``, which since Python 3.14 reads every OSError as False and would
    pass a root the process cannot check over in silence. A directory below
    ``root`` that cannot be opened or listed, and an entry that cannot be examined
    (a directory readable but not searchable), are refused too, as the OSError
    the walk met: skipped, a link there would be neither refused here nor removed
    by the sweep.
    """
    root = Path(os.path.abspath(root))
    if not hasattr(os, "fwalk"):
        return
    try:
        status = os.lstat(root)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(status.st_mode):
        raise OutputLinkRefused(root, root, where="at a directory it writes below")
    if not stat.S_ISDIR(status.st_mode):
        raise NotADirectoryError(
            errno.ENOTDIR,
            f"{root} is not a directory, so what a scanner would write below it "
            "cannot be checked",
        )

    def refuse(what: str, relative: str, error: OSError) -> None:
        raise OSError(
            _errno_of(error),
            f"could not {what} {relative} under {root} ({error}), so a link below "
            "it could not be refused",
        ) from error

    # closing(): the raises below leave the walk early, and its open directory
    # descriptors are then closed here rather than when the generator is
    # finalized, which another interpreter can defer.
    with closing(_walk_descriptors(root, refuse)) as walk:
        for relative, _dir_fd, statuses, _dirnames in walk:
            where = root if relative == "." else root / relative
            for name in sorted(statuses):
                status = statuses[name]
                if stat.S_ISLNK(status.st_mode):
                    link = where / name
                    raise OutputLinkRefused(link, link)
                if stat.S_ISREG(status.st_mode) and status.st_nlink > 1:
                    raise OutputHardLinkRefused(where / name, status.st_nlink)


def sweep_writable(
    roots: Iterable[Union[str, Path]],
    values: Iterable[str] = (),
    *,
    values_unread: bool = False,
    skip: Iterable[Union[str, Path]] = (),
) -> int:
    """Remove symlinks and special files under ``roots``; return how many.

    ``values`` are the caller's env-read values: a removal failure's warning
    names the entry and the root, and either can hold one. ``values_unread``
    says the caller could not read them (the plugin's hook raised or gave no
    value set): ``values`` is then empty without meaning "none", and the
    warning is value-free instead. ``skip`` names the directories the sweep
    passes over, ASH's own private directories for the spawn
    (``SpawnPlan.private_dirs``), which the backend removes whole in its own
    cleanup step and whose contents are ASH's, not a scanner's; see
    ``_sweep_tree`` for what is and is not passed over.

    Every root is swept whatever happened at the others, and the whole of each
    tree whatever a directory in it refused (``_sweep_tree``): a refusal is logged
    where it is met and the sweep goes on, the count of removals is logged as
    usual, and then one OSError is raised for all the refusals, its text the first
    refusal's logged line (so it names no tool-chosen path the warning did not)
    with the others counted, chained to nothing. The post-scan sweep fails the
    scanner on it; the spawn cleanup records it at DEBUG and runs its release step
    regardless (SpawnPlan.run_cleanup).
    """
    removed = 0
    values = tuple(values)
    refusals: List[OSError] = []
    for root in roots:
        root = Path(root)
        try:
            # os.lstat, not Path.is_symlink: since Python 3.14 is_symlink is
            # os.path.islink, which reads every OSError as "not a link", so a
            # root that cannot be checked would pass through here in silence.
            mode = os.lstat(root).st_mode
            if stat.S_ISLNK(mode):
                root.unlink()
                removed += 1
                continue
            if not stat.S_ISDIR(mode):
                # A regular or special file given as a root (the policy builds
                # only directories; a caller may not) has nothing below it, and
                # opening it as a directory would read as a refusal. It is said,
                # not refused: a sandboxed scanner cannot put a file at its own
                # root (that needs write on the root's parent, which the policies
                # grant only on the results directory itself), so this is an
                # operator-side oddity that should not fail the scan.
                _sweep_warning(
                    f"The results directory root {root} is not a directory; "
                    "nothing is swept below it",
                    "A scanner's results directory root is not a directory and "
                    "nothing is swept below it; it is not named because the "
                    "plugin's redaction values could not be read",
                    values,
                    values_unread,
                )
                continue
        except FileNotFoundError:
            # A sandboxed scanner that wrote nothing created no results
            # directory, the common case; or the root went since it was planned.
            # Nothing is below it to remove, and the sweep creates nothing.
            continue
        except OSError as e:
            # The root could not be checked (a parent the process cannot search,
            # a link loop) or a link at the root could not be removed. Passing it
            # over would leave whatever is there for a reader that opens paths by
            # name to follow, so it is refused as an unlistable directory is; the
            # other roots are still swept.
            shown = _sweep_warning(
                f"Could not check or remove the root {root}: {e}",
                "Could not check or remove a scanner's results directory root; it "
                "is not named because the plugin's redaction values could not be "
                "read",
                values,
                values_unread,
            )
            refusals.append(OSError(_errno_of(e), shown))
            continue
        removed += _sweep_tree(root, values, values_unread, refusals, skip)
    if removed:
        ASH_LOGGER.warning(
            f"Scanner sandbox: removed {removed} symlink(s) or special file(s) a "
            "scanner left in its results directory"
        )
    if refusals:
        raise _sweep_refused(refusals) from None
    return removed


_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
#: How the sweep and the pre-check open each directory they walk: a directory
#: only, never through a link at the name, and without blocking on a FIFO put
#: where a directory was.
_DIR_WALK_FLAGS = os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _NONBLOCK
# No O_TRUNC: the file is truncated only after fstat shows it is a regular file
# that no other name refers to (_open_regular).
_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | _NOFOLLOW | _NONBLOCK | _BINARY
#: Whether paths can be opened relative to a directory descriptor without
#: following a link (POSIX). Without it (Windows) each component is checked by
#: name before the open; see _check_beneath_by_name.
_HAS_DIR_FD = hasattr(os, "fwalk")
#: FILE_ATTRIBUTE_REPARSE_POINT: Windows symlinks, junctions and mount points.
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _lstat(path: Path) -> os.stat_result:
    return os.lstat(path)


def _is_link_status(status: os.stat_result) -> bool:
    return stat.S_ISLNK(status.st_mode) or bool(
        getattr(status, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _check_beneath_by_name(
    root: Path,
    relative: Tuple[str, ...],
    target: Path,
) -> Optional[os.stat_result]:
    """Without directory descriptors: refuse a link on the way to ``target``.

    Each directory component below ``root`` is examined with lstat and created
    when missing; a symlink or reparse point (a junction, say) raises
    OutputLinkRefused, and so does one at the file name. A regular file at the
    name that another name refers to raises OutputHardLinkRefused. This refuses a
    link that is already there, as one committed with the scanned tree is. A link
    made between this check and the caller's open is not caught. Returns the
    file's lstat, or None when nothing is at the name.
    """
    os.makedirs(root, exist_ok=True)
    current = root
    for part in relative[:-1]:
        current = current / part
        try:
            status = _lstat(current)
        except FileNotFoundError:
            try:
                os.mkdir(current)
            except FileExistsError:
                # Another writer put something there between the lstat and the
                # mkdir: examined as any component is, a link there included.
                status = _lstat(current)
            else:
                continue
        if _is_link_status(status):
            raise OutputLinkRefused(target, current)
        if not stat.S_ISDIR(status.st_mode):
            raise NotADirectoryError(errno.ENOTDIR, f"not a directory: {current}")
    try:
        status = _lstat(target)
    except FileNotFoundError:
        return None
    if _is_link_status(status):
        raise OutputLinkRefused(target, target)
    if stat.S_ISREG(status.st_mode) and status.st_nlink > 1:
        raise OutputHardLinkRefused(target, status.st_nlink)
    return status


def _is_link(name: str, dir_fd: int) -> bool:
    try:
        return stat.S_ISLNK(os.lstat(name, dir_fd=dir_fd).st_mode)
    except FileNotFoundError:
        return False


def _anchor_is_root(fd: int, root: Path) -> bool:
    """Whether the directory ``fd`` was opened at is ``root`` itself, now.

    A guarded write or read opens its anchor by name, and that name may reach
    the root through a link above it (the identity match in ``_root_anchor``); a
    link re-pointed between the match and the open would put every check below
    in another tree, which is the root-link hazard the module docstring names.
    So the descriptor is compared with the root as it is at this moment: the
    same device and inode, and the root not itself a link (a link put at the root
    since its registration is read as one found there).
    """
    opened = os.fstat(fd)
    try:
        expected = os.lstat(root)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(expected.st_mode):
        return False
    return (opened.st_dev, opened.st_ino) == (expected.st_dev, expected.st_ino)


def _open_dir_beneath(
    root: Path,
    relative_parts: Tuple[str, ...],
    target: Path,
    identity_of: Optional[Path] = None,
) -> int:
    """A descriptor for ``root/relative_parts``, never following a link below root.

    Each component is opened relative to the previous one with O_NOFOLLOW, and
    created when missing. A component that is a symlink, whoever put it there,
    raises OutputLinkRefused for ``target``; so does one replaced by a link between
    the check and the open, which O_NOFOLLOW reports as ELOOP, or, with
    O_DIRECTORY on Linux, as ENOTDIR: an ENOTDIR is read again with lstat, and a
    link there is the same refusal. A component another writer creates between
    the failed open and the mkdir is used as it is. A missing root is created
    first; links above it are not examined, except that with ``identity_of`` (the
    registered or named root ``root`` is a spelling of) the directory opened at
    ``root`` must be that root itself (``_anchor_is_root``), or OutputLinkRefused
    is raised for ``target`` and nothing below is opened.
    """
    try:
        fd = os.open(root, os.O_RDONLY | _DIRECTORY)
    except FileNotFoundError:
        os.makedirs(root, exist_ok=True)
        fd = os.open(root, os.O_RDONLY | _DIRECTORY)
    if identity_of is not None and not _anchor_is_root(fd, identity_of):
        os.close(fd)
        raise OutputLinkRefused(target, root, where="at a directory it writes below")
    current = root
    try:
        for part in relative_parts:
            current = current / part
            if _is_link(part, fd):
                raise OutputLinkRefused(target, current)
            flags = os.O_RDONLY | _DIRECTORY | _NOFOLLOW
            try:
                try:
                    child = os.open(part, flags, dir_fd=fd)
                except FileNotFoundError:
                    try:
                        os.mkdir(part, 0o777, dir_fd=fd)
                    except FileExistsError:
                        pass
                    child = os.open(part, flags, dir_fd=fd)
            except OSError as error:
                if error.errno == errno.ELOOP or (
                    error.errno == errno.ENOTDIR and _is_link(part, fd)
                ):
                    raise OutputLinkRefused(target, current) from error
                raise
            previous, fd = fd, child
            os.close(previous)
        return fd
    except BaseException:
        os.close(fd)
        raise


def unlink_beneath(root: Union[str, Path], relative_parts: Tuple[str, ...]) -> bool:
    """Remove ``root/relative_parts`` without following a link below ``root``.

    For removing a file ASH itself writes beneath ``root``, with the refusal
    open_for_write applies on the write: a directory component that is missing,
    not a directory, or a symlink ends the walk and nothing is removed, so a
    planted link cannot lead the removal outside ``root``. A missing file is
    fine; a symlink at the final name is removed as the link it is. A directory
    at the final name raises IsADirectoryError, on every platform, for the
    caller to decide about.

    Returns False when a directory component was refused (a symlink, or not a
    directory), so whatever sits at the name through it was left in place for
    the caller to report; True otherwise, removed or with nothing there.

    Unlike _open_dir_beneath this never creates a missing component: a cleanup
    has nothing to remove where the path does not exist.
    """
    root = Path(root)
    *dirs, name = relative_parts
    if not hasattr(os, "fwalk"):
        # Windows, where no sandbox backend exists: the same refusals from
        # lstat checks, between which a component can in principle change. A
        # link is a symlink or a junction (is_link), as the rest of the module
        # reads it: Path.is_symlink is False for a junction, which the walk then
        # passed through.
        current = root
        for part in dirs:
            current = current / part
            if not is_link(current) and not current.exists():
                return True
            if is_link(current) or not current.is_dir():
                return False
        target = current / name
        try:
            if target.is_symlink():
                target.unlink()
            elif target.is_dir():
                raise IsADirectoryError(
                    errno.EISDIR, os.strerror(errno.EISDIR), str(target)
                )
            else:
                target.unlink()
        except FileNotFoundError:
            return True
        except PermissionError as e:
            if target.is_dir():
                raise IsADirectoryError(
                    errno.EISDIR, os.strerror(errno.EISDIR), str(target)
                ) from e
            raise
        return True
    _REFUSED = (errno.ELOOP, errno.EMLINK, errno.ENOTDIR)
    try:
        fd = os.open(root, os.O_RDONLY | _DIRECTORY)
    except FileNotFoundError:
        return True
    try:
        for part in dirs:
            try:
                child = os.open(part, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                return True
            except OSError as e:
                if e.errno in _REFUSED:
                    return False
                raise
            previous, fd = fd, child
            os.close(previous)
        try:
            os.unlink(name, dir_fd=fd)
        except FileNotFoundError:
            return True
        except PermissionError as e:
            # macOS unlinks a directory with EPERM where Linux says EISDIR;
            # give the caller the one exception for both.
            if stat.S_ISDIR(os.lstat(name, dir_fd=fd).st_mode):
                raise IsADirectoryError(
                    errno.EISDIR, os.strerror(errno.EISDIR), name
                ) from e
            raise
        return True
    finally:
        os.close(fd)


def _refuse_link_at(name: str, dir_fd: int, target: Path) -> Optional[os.stat_result]:
    """Raise if ``name`` in ``dir_fd`` is a symlink, or a file another name refers to.

    Returns the entry's lstat, or None when nothing is at the name.
    """
    try:
        status = os.lstat(name, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(status.st_mode):
        raise OutputLinkRefused(target, target)
    if stat.S_ISREG(status.st_mode) and status.st_nlink > 1:
        raise OutputHardLinkRefused(target, status.st_nlink)
    return status


def _open_regular(
    name: str,
    dir_fd: Optional[int],
    target: Path,
    append: bool,
    mode: int,
    exclusive: bool = False,
) -> int:
    """Open ``name`` for writing; refuse anything but a file of its own.

    Opened without O_TRUNC, then checked on the descriptor: it must be a regular
    file and its only name must be this one (``st_nlink == 1``), or
    OutputHardLinkRefused is raised for ``target`` and the file is left as it was.
    Only then is it truncated, unless ``append``. O_NONBLOCK so a FIFO left at the
    name cannot block the open; the flag is cleared again once the target is known
    to be a regular file. With ``exclusive`` the file must not exist yet
    (O_EXCL), and FileExistsError is raised if it does.
    """
    flags = _FILE_FLAGS | (os.O_APPEND if append else 0)
    if exclusive:
        flags |= os.O_EXCL
    if dir_fd is None:
        fd = os.open(name, flags, mode)
    else:
        fd = os.open(name, flags, mode, dir_fd=dir_fd)
    try:
        status = os.fstat(fd)
        if not stat.S_ISREG(status.st_mode):
            raise OSError(errno.EINVAL, f"not a regular file: {name}")
        if status.st_nlink != 1:
            raise OutputHardLinkRefused(target, status.st_nlink)
        if _NONBLOCK:
            current = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, current & ~_NONBLOCK)
        if not append:
            os.ftruncate(fd, 0)
        return fd
    except BaseException:
        os.close(fd)
        raise


def replace_without_following(
    path: Union[str, Path],
    content: str,
    encoding: str = "utf-8",
    newline: Optional[str] = None,
) -> None:
    """Write ``content`` to ``path`` as a new file renamed over it, never through a link.

    For a destination the operator names, outside every output directory, such as
    ``ash get-genai-guide --output``. A symlink (or reparse point) at ``path``
    raises OutputLinkRefused and is left in place. The content goes to a file
    created exclusively beside ``path`` (O_EXCL, and O_NOFOLLOW where it exists, so
    nothing already at that name is opened), which then replaces ``path``: a file
    another name refers to is replaced as an entry, and that other name keeps its
    content. A link that appears at ``path`` between the check and the rename is
    replaced, not followed.

    ``newline`` is open()'s: None translates ``\\n`` to the platform's line ending
    on write, so a caller that wants the file's bytes the same on every platform
    (a guide shipped with LF endings) passes ``"\\n"``, as it would to open().
    """
    path = Path(os.path.abspath(path))
    try:
        status = _lstat(path)
    except FileNotFoundError:
        status = None
    if status is not None and _is_link_status(status):
        raise OutputLinkRefused(path, path, where="at a destination it writes")
    staging = path.with_name(_staging_name(path.name, path.parent))
    fd = os.open(
        staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _BINARY, 0o666
    )
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline=newline) as handle:
            handle.write(content)
        os.replace(staging, path)
    except BaseException:
        staging.unlink(missing_ok=True)
        raise


#: A staging file: created, never opened if anything is already at its name.
_STAGING_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _BINARY
#: The longest entry name the filesystems ASH writes to accept, in bytes (NAME_MAX
#: on Linux and macOS; NTFS counts 255 characters, which is never fewer bytes).
#: The ceiling, and the figure used where the directory's own limit cannot be read.
_NAME_MAX = 255


def _name_max(
    directory: Optional[Union[str, Path]], dir_fd: Optional[int] = None
) -> int:
    """The longest entry name the directory's filesystem accepts, in bytes.

    ``os.fpathconf(dir_fd, "PC_NAME_MAX")`` when the caller holds the directory
    open (the guarded atomic writer, whose descriptor is the directory the
    staging file goes into, created a moment ago if it was missing), else
    ``os.pathconf(directory, ...)`` by name; either because a filesystem can
    accept fewer than NAME_MAX bytes (eCryptfs accepts 143), and a target whose
    name a plain open there accepts would otherwise fail with ENAMETOOLONG at the
    staging open. _NAME_MAX when there is nothing to ask, no pathconf (Windows),
    the call fails (a directory not there yet, asked by name) or the answer is
    not a positive number; never more than _NAME_MAX.
    """
    try:
        if dir_fd is not None and hasattr(os, "fpathconf"):
            limit = os.fpathconf(dir_fd, "PC_NAME_MAX")
        elif directory is not None and hasattr(os, "pathconf"):
            limit = os.pathconf(directory, "PC_NAME_MAX")
        else:
            return _NAME_MAX
    except (OSError, ValueError):
        return _NAME_MAX
    if not isinstance(limit, int) or limit <= 0:
        return _NAME_MAX
    return min(limit, _NAME_MAX)


def _staging_name(
    name: str,
    directory: Optional[Union[str, Path]] = None,
    dir_fd: Optional[int] = None,
) -> str:
    """The name of the staging file open_for_atomic_write writes ``name`` through.

    A dot, the target's name, the pid and 32 hex digits of randomness, then
    ``.tmp``. The target's name is shortened, from its end, until the whole fits
    in the name limit of the directory's filesystem (``_name_max``, asked through
    ``dir_fd`` when given, else by ``directory``'s name; _NAME_MAX bytes without
    either): the suffix alone is about 46 bytes, so a target whose name a plain
    open accepts could otherwise fail with ENAMETOOLONG at the staging open.
    Uniqueness is the pid and the random digits, which are always kept. secrets,
    not uuid.uuid4: the snapshot tests pin uuid.uuid4 to a counter that report
    ids are built from, and a staging name only has to be unique.
    """
    limit = _name_max(directory, dir_fd)
    suffix = f".{os.getpid()}.{secrets.token_hex(16)}.tmp"
    stem = name
    while stem and len(os.fsencode(f".{stem}{suffix}")) > limit:
        stem = stem[:-1]
    return f".{stem}{suffix}"


@contextmanager
def open_for_atomic_write(
    path: Union[str, Path],
    encoding: Optional[str] = "utf-8",
    errors: Optional[str] = "strict",
    *,
    binary: bool = False,
    newline: Optional[str] = None,
    root: Optional[Union[str, Path]] = None,
) -> Iterator[IO[Any]]:
    """Write ``path`` through a staging file that replaces it when the block ends.

    ``with open_for_atomic_write(path) as handle:`` yields a handle, text unless
    ``binary``, on a new file created exclusively in ``path``'s directory, with the
    permissions a plain open gives (0o666 less the umask). ``encoding``, ``errors``
    and ``newline`` are open()'s, for text, as they are for open_for_write; the
    staging handle is the one they shape, so the bytes renamed over ``path`` are
    the bytes open() would have written there. When the block ends
    without an exception the file is renamed over ``path``, so a reader of ``path``
    opens the old complete file or the new complete one and never a partial write.
    When the block raises, the staging file is removed and ``path`` is left as it
    was. The staging file is in the same directory because a rename is only atomic
    within one filesystem.

    Guarded as open_for_write is: below a registered root, or below ``root`` when
    the caller names one, each directory component is opened without following a
    link and created when missing; a link at any of them, or at the file name,
    raises OutputLinkRefused. A regular file at the name that another name refers
    to (a hard link) raises OutputHardLinkRefused and is left as it was, as
    open_for_write refuses it: the rename would not write through the other name,
    but a hard link planted at a results path is a tamper signal, and the output
    tree's contract is that no writer accepts one (refuse_links_below reads the
    same way). The name is checked again just before the rename, so a link made there
    while the block ran is refused and left in place rather than replaced. The
    staging file is created and renamed relative to the directory's descriptor.
    Outside every root the rename replaces whatever entry is at the name, a link
    included, without following it.

    A regular file already at the name keeps its read, write and execute bits:
    the staging file is given them before the rename, where a fresh file would
    otherwise have replaced a 0o600 file with a 0o644 one. Its setuid, setgid and
    sticky bits are not carried over. Outside every root, where no hard-link
    refusal runs, a file another name refers to is replaced and lends nothing:
    the new file keeps its umask-derived mode.

    On a platform without directory descriptors (Windows) the components below a
    root are checked by name before the staging file is created and again before
    the rename, and the rename is retried for a bounded time while a reader holds
    the file open (atomic_write._replace).
    """
    # Not at the top: atomic_write imports this module when it writes.
    from automated_security_helper.utils.atomic_write import _replace

    open_mode = "wb" if binary else "w"
    text: Dict[str, Any] = (
        {} if binary else {"encoding": encoding, "errors": errors, "newline": newline}
    )
    path = Path(os.path.abspath(path))
    guard = _guard_root(path, root)
    anchor = guard[1] if guard is not None else None
    relative = path.relative_to(anchor).parts if anchor is not None else ()
    dir_fd: Optional[int] = None
    if anchor is not None and _HAS_DIR_FD:
        dir_fd = _open_dir_beneath(
            anchor,
            relative[:-1],
            path,
            identity_of=guard[0] if guard is not None else None,
        )
    # After the directory is open (and created, when it was missing): its own
    # filesystem's name limit is asked through the descriptor, where asking the
    # spelled path before it existed fell back to the ceiling.
    try:
        staging = _staging_name(path.name, path.parent, dir_fd=dir_fd)
    except BaseException:
        if dir_fd is not None:
            os.close(dir_fd)
        raise

    def refuse_a_link_at_the_name() -> Optional[os.stat_result]:
        if dir_fd is not None:
            return _refuse_link_at(path.name, dir_fd, path)
        if anchor is not None:
            return _check_beneath_by_name(anchor, relative, path)
        try:
            status = _lstat(path)
        except FileNotFoundError:
            return None
        return None if _is_link_status(status) else status

    def remove_staging() -> None:
        try:
            if dir_fd is not None:
                os.unlink(staging, dir_fd=dir_fd)
            else:
                os.unlink(path.parent / staging)
        except FileNotFoundError:
            pass

    try:
        existing = refuse_a_link_at_the_name()
        if dir_fd is not None:
            fd = os.open(staging, _STAGING_FLAGS, 0o666, dir_fd=dir_fd)
        else:
            fd = os.open(path.parent / staging, _STAGING_FLAGS, 0o666)
        try:
            try:
                if (
                    existing is not None
                    and stat.S_ISREG(existing.st_mode)
                    and existing.st_nlink == 1
                    and hasattr(os, "fchmod")
                ):
                    # The read, write and execute bits of the file being
                    # replaced, and only those: a setuid, setgid or sticky bit
                    # on an entry a scanner put at the name is not carried onto
                    # the results file. Below a root a file another name refers
                    # to was refused above; outside every root it is replaced
                    # and lends nothing: the new file keeps the umask-derived
                    # mode it was created with.
                    os.fchmod(fd, stat.S_IMODE(existing.st_mode) & 0o777)
                handle = os.fdopen(fd, open_mode, **text)
            except BaseException:
                os.close(fd)
                raise
            with handle:
                yield handle
            refuse_a_link_at_the_name()
            if dir_fd is not None:
                os.replace(staging, path.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            else:
                _replace(path.parent / staging, path)
        except BaseException:
            remove_staging()
            raise
    finally:
        if dir_fd is not None:
            os.close(dir_fd)


def open_for_write(
    path: Union[str, Path],
    encoding: Optional[str] = "utf-8",
    errors: Optional[str] = "strict",
    *,
    append: bool = False,
    binary: bool = False,
    mode: int = 0o666,
    newline: Optional[str] = None,
    make_parents: bool = False,
    root: Optional[Union[str, Path]] = None,
    exclusive: bool = False,
) -> IO[Any]:
    """Open ``path`` for writing, text unless ``binary``, truncated unless ``append``.

    Below a registered root (the output directory of a PluginContext, or a
    sandboxed scanner's results directory; see register_writable_root), or below
    ``root`` when the caller names the directory it writes in, no symlink is
    followed: a link at any component, the file name included, raises
    OutputLinkRefused and nothing is written. The target must be a regular file
    that no other name refers to, or OutputHardLinkRefused is raised before it is
    changed, and missing directories are created. Anywhere else it is exactly
    open(path, "w") ("a", "wb" or "ab" as asked), except that with a ``mode`` other
    than the default the file is opened with O_NOFOLLOW, as the callers that pass
    one always did. Permissions are ``mode`` less the umask, 0o666 by default as
    open() uses. ``newline`` is open()'s, for text. With ``make_parents``, missing
    directories are created there too, as ``mkdir(parents=True)`` creates them.

    ``root`` guards this open only and registers nothing, for a writer that knows
    its output directory but may run where no PluginContext registered it (the
    log files, the scan-set lists, the workspace spool). ``path`` must be below it.
    When a registered root also holds ``path``, the outer of the two is used, so
    every component below either one is checked.

    With ``exclusive`` the file is created and must not exist yet (O_EXCL, open()'s
    "x"), guarded or not; FileExistsError is raised if something is at the name.

    On a platform without directory descriptors (Windows) the components below a
    root are checked by name first, symlinks and reparse points such as junctions
    included, and then the file is opened by name: a link already there is
    refused, one made between the check and the open is not.
    """
    if exclusive and append:
        raise ValueError("exclusive creates the file; it cannot also append")
    open_mode = ("x" if exclusive else "a" if append else "w") + ("b" if binary else "")
    text: Dict[str, Any] = (
        {} if binary else {"encoding": encoding, "errors": errors, "newline": newline}
    )
    path = Path(os.path.abspath(path))
    guard = _guard_root(path, root)
    anchor = guard[1] if guard is not None else None
    if anchor is not None and not _HAS_DIR_FD:
        _check_beneath_by_name(anchor, path.relative_to(anchor).parts, path)
    if anchor is None or not _HAS_DIR_FD:
        if make_parents:
            path.parent.mkdir(parents=True, exist_ok=True)
        if mode == 0o666:
            return open(path, open_mode, **text)
        flags = os.O_WRONLY | os.O_CREAT | _NOFOLLOW | _BINARY
        if exclusive:
            flags |= os.O_EXCL
        else:
            flags |= os.O_APPEND if append else os.O_TRUNC
        return os.fdopen(os.open(path, flags, mode), open_mode, **text)
    relative = path.relative_to(anchor).parts
    dir_fd = _open_dir_beneath(
        anchor,
        relative[:-1],
        path,
        identity_of=guard[0] if guard is not None else None,
    )
    try:
        name = relative[-1]
        if _is_link(name, dir_fd):
            raise OutputLinkRefused(path, path)
        try:
            fd = _open_regular(name, dir_fd, path, append, mode, exclusive)
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise OutputLinkRefused(path, path) from error
            raise
    finally:
        os.close(dir_fd)
    return os.fdopen(fd, open_mode, **text)


def open_for_write_bytes(path: Union[str, Path], mode: int = 0o666) -> IO[bytes]:
    """:func:`open_for_write`, for bytes: the same rule, opened in binary mode."""
    return open_for_write(path, binary=True, mode=mode)


_READ_FLAGS = os.O_RDONLY | _NOFOLLOW | _NONBLOCK | _BINARY
#: The most bytes read_bytes_at_most asks a read for at once.
_READ_CHUNK = 1 << 20


def _guarded_read_fd(path: Path) -> int:
    """A read descriptor for ``path`` under the reader's guard.

    Below a writable root no symlink is followed at any component, as
    open_for_write does for the write; elsewhere the last component is still
    not followed. O_NONBLOCK keeps a FIFO at the name from blocking the open;
    the regular-file check is the caller's, made on the opened descriptor.
    """
    anchored = _registered_anchor(path) if hasattr(os, "fwalk") else None
    if anchored is None or path == anchored[1]:
        return os.open(path, _READ_FLAGS)
    root, anchor = anchored
    relative = path.relative_to(anchor).parts
    dir_fd = os.open(anchor, os.O_RDONLY | _DIRECTORY)
    try:
        if not _anchor_is_root(dir_fd, root):
            # The anchor was opened by name and reached another directory than
            # the root (a link above it re-pointed, or a link put at the root):
            # nothing below is read from there.
            raise OSError(
                errno.ELOOP,
                f"{path} was not read: {anchor} does not lead to the directory "
                f"{root} is registered as",
            )
        for part in relative[:-1]:
            child = os.open(part, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = child
        return os.open(relative[-1], _READ_FLAGS, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)


def open_for_read(path: Union[str, Path]) -> IO[bytes]:
    """A binary reader for the regular file at ``path``, under the guard.

    The same open semantics as :func:`read_bytes_at_most`, for a caller that
    reads in its own chunks (plugin_base.log_says): no symlink is followed as
    that function's docstring says, a FIFO at the name cannot block the open,
    and anything but a regular file is refused with OSError. The caller owns
    closing the returned handle.
    """
    path = Path(os.path.abspath(path))
    fd = _guarded_read_fd(path)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, f"not a regular file: {path}")
    except BaseException:
        os.close(fd)
        raise
    return os.fdopen(fd, "rb")


def read_bytes_at_most(path: Union[str, Path], limit: int) -> bytes:
    """Up to ``limit`` bytes of the regular file at ``path``.

    For reading back a file ASH wrote under a scanner's results directory: a
    process the sandboxed scanner left running may have replaced it, or a
    directory above it, with a link to one of the host's files since. Below a
    writable root no symlink is followed at any component, as open_for_write
    does for the write; elsewhere the last component is still not followed.
    Anything but a regular file is refused with OSError, and O_NONBLOCK keeps a
    FIFO at the name from blocking the open.
    """
    path = Path(os.path.abspath(path))
    fd = _guarded_read_fd(path)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise OSError(errno.EINVAL, f"not a regular file: {path}")
        # In chunks: BufferedReader.read(n) allocates n bytes before it reads,
        # so one read of a large limit cost that much memory for any file,
        # a MemoryError under an address-space limit. The chunks hold what
        # the file has, up to the limit, however it grows meanwhile.
        chunks = []
        remaining = limit
        while remaining > 0:
            chunk = handle.read(min(remaining, _READ_CHUNK))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
