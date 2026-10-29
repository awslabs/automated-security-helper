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
from contextlib import contextmanager
from pathlib import Path
from typing import (
    IO,
    Any,
    Dict,
    FrozenSet,
    Iterable,
    Iterator,
    List,
    Optional,
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


def _writable_root_for(path: Path) -> Optional[Path]:
    """The deepest registered root ``path`` is below, or None."""
    with _roots_lock:
        _apply_pending_releases()
        roots = list(_writable_roots)
    inside = [r for r in roots if r in path.parents]
    return max(inside, key=lambda r: len(r.parts)) if inside else None


def _refuse_linked_root(root: Path) -> None:
    """Raise OutputLinkRefused if ``root`` is a symlink or a junction."""
    if is_link(root):
        raise OutputLinkRefused(root, root, where="at a directory it writes below")


def _guard_root(path: Path, root: Optional[Union[str, Path]]) -> Optional[Path]:
    """The root open_for_write checks ``path`` below: see its ``root`` argument."""
    registered = _writable_root_for(path)
    if root is None:
        return registered
    named = Path(os.path.abspath(root))
    if named not in path.parents:
        raise ValueError(f"{path.as_posix()} is not below {named.as_posix()}")
    _refuse_linked_root(named)
    if registered is not None and len(registered.parts) < len(named.parts):
        return registered
    return named


def _sweep_tree(
    root: Path, values: Iterable[str] = (), values_unread: bool = False
) -> int:
    """Remove non-regular, non-directory entries under ``root``.

    os.fwalk descends through directory file descriptors and never follows a
    symlink, so a directory replaced by a link while the walk runs is not entered.
    Entries are removed relative to their directory's descriptor for the same
    reason. Platforms without fwalk (Windows, where no sandbox backend exists)
    fall back to os.walk.

    A directory the walk cannot open for listing (a mode the scanner set, a
    descriptor limit) is refused rather than skipped: both walks would otherwise
    pass over it without a word, and every link below it would survive for a
    reader that opens paths by name to follow. The refusal is logged as a removal
    failure is, and raised as the OSError the walk met, so the post-scan sweep
    fails the scanner and the spawn cleanup records it.
    """
    removed = 0

    def warn(text: str, value_free: str) -> None:
        if values_unread:
            # The values to hide could not be read, so nothing here can be
            # redacted: no entry name, root or OS error.
            ASH_LOGGER.warning(value_free)
            return
        # The entry's name and the root are paths a tool or an option chose, so
        # either can hold an env-read value: redacted with the sweep's values,
        # and the scope's, before it is logged.
        from automated_security_helper.utils.sandbox.scope import scope_shown_text

        ASH_LOGGER.warning(scope_shown_text(text, tuple(values)))

    def unlistable(error: OSError) -> None:
        if error.errno == errno.ENOENT:
            # Removed while the walk ran: nothing is below it any more.
            return
        warn(
            f"Could not list {error.filename} under {root}: {error}",
            "Could not list a directory a scanner left in its results directory; "
            "it is not named because the plugin's redaction values could not be "
            "read",
        )
        raise OSError(
            error.errno,
            f"could not list {error.filename} under {root}, so the links a "
            "scanner may have left below it could not be removed",
        ) from error

    if not hasattr(os, "fwalk"):
        for dirpath, dirnames, filenames in os.walk(
            root, onerror=unlistable, followlinks=False
        ):
            for name in list(dirnames) + filenames:
                path = os.path.join(dirpath, name)
                if _is_special(os.lstat(path).st_mode):
                    os.unlink(path)
                    removed += 1
        return removed
    for _, dirnames, filenames, dir_fd in os.fwalk(
        root, onerror=unlistable, follow_symlinks=False
    ):
        for name in list(dirnames) + filenames:
            try:
                mode = os.lstat(name, dir_fd=dir_fd).st_mode
            except OSError:
                continue
            if not _is_special(mode):
                continue
            try:
                os.unlink(name, dir_fd=dir_fd)
                removed += 1
            except OSError as e:
                warn(
                    f"Could not remove {name} under {root}: {e}",
                    "Could not remove an entry a scanner left in its results "
                    "directory; it is not named because the plugin's redaction "
                    "values could not be read",
                )
            if name in dirnames:
                dirnames.remove(name)
    return removed


def _is_special(mode: int) -> bool:
    return not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))


def refuse_links_below(root: Union[str, Path]) -> None:
    """Raise for the first symlink, or file another name refers to, below ``root``.

    For a sandboxed scanner's results directory before the scanner runs: the sweep
    after each spawn removes links the scanner made, and would also remove one that
    was there before it ran (committed with the scanned tree) without saying so. A
    regular file with more than one name is refused too (OutputHardLinkRefused):
    the scanner can write the results directory, and a write to that file changes
    every name it has. The walk never follows a link. A missing ``root`` has nothing
    below it. A directory below ``root`` that cannot be opened for listing is
    refused too, as the OSError the walk met: skipped, the links below it would be
    neither refused here nor removed by the sweep.
    """
    root = Path(os.path.abspath(root))
    if not hasattr(os, "fwalk") or not root.is_dir():
        return

    def unlistable(error: OSError) -> None:
        if error.errno == errno.ENOENT:
            # Removed while the walk ran: nothing is below it any more.
            return
        raise OSError(
            error.errno,
            f"could not list {error.filename} under {root}, so a link below it "
            "could not be refused",
        ) from error

    for dirpath, dirnames, filenames, dir_fd in os.fwalk(
        root, onerror=unlistable, follow_symlinks=False
    ):
        for name in sorted(list(dirnames) + filenames):
            try:
                status = os.lstat(name, dir_fd=dir_fd)
            except OSError:
                continue
            if stat.S_ISLNK(status.st_mode):
                link = Path(dirpath) / name
                raise OutputLinkRefused(link, link)
            if stat.S_ISREG(status.st_mode) and status.st_nlink > 1:
                raise OutputHardLinkRefused(Path(dirpath) / name, status.st_nlink)


def sweep_writable(
    roots: Iterable[Union[str, Path]],
    values: Iterable[str] = (),
    *,
    values_unread: bool = False,
) -> int:
    """Remove symlinks and special files under ``roots``; return how many.

    ``values`` are the caller's env-read values: a removal failure's warning
    names the entry and the root, and either can hold one. ``values_unread``
    says the caller could not read them (the plugin's hook raised or gave no
    value set): ``values`` is then empty without meaning "none", and the
    warning is value-free instead.
    """
    removed = 0
    values = tuple(values)
    for root in roots:
        root = Path(root)
        try:
            if root.is_symlink():
                root.unlink()
                removed += 1
                continue
        except OSError:
            continue
        removed += _sweep_tree(root, values, values_unread)
    if removed:
        ASH_LOGGER.warning(
            f"Scanner sandbox: removed {removed} symlink(s) or special file(s) a "
            "scanner left in its results directory"
        )
    return removed


_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
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


def _check_beneath_by_name(root: Path, relative: Tuple[str, ...], target: Path) -> None:
    """Without directory descriptors: refuse a link on the way to ``target``.

    Each directory component below ``root`` is examined with lstat and created
    when missing; a symlink or reparse point (a junction, say) raises
    OutputLinkRefused, and so does one at the file name. A regular file at the
    name that another name refers to raises OutputHardLinkRefused. This refuses a
    link that is already there, as one committed with the scanned tree is. A link
    made between this check and the caller's open is not caught.
    """
    os.makedirs(root, exist_ok=True)
    current = root
    for part in relative[:-1]:
        current = current / part
        try:
            status = _lstat(current)
        except FileNotFoundError:
            os.mkdir(current)
            continue
        if _is_link_status(status):
            raise OutputLinkRefused(target, current)
        if not stat.S_ISDIR(status.st_mode):
            raise NotADirectoryError(errno.ENOTDIR, f"not a directory: {current}")
    try:
        status = _lstat(target)
    except FileNotFoundError:
        return
    if _is_link_status(status):
        raise OutputLinkRefused(target, target)
    if stat.S_ISREG(status.st_mode) and status.st_nlink > 1:
        raise OutputHardLinkRefused(target, status.st_nlink)


def _is_link(name: str, dir_fd: int) -> bool:
    try:
        return stat.S_ISLNK(os.lstat(name, dir_fd=dir_fd).st_mode)
    except FileNotFoundError:
        return False


def _open_dir_beneath(root: Path, relative_parts: Tuple[str, ...], target: Path) -> int:
    """A descriptor for ``root/relative_parts``, never following a link below root.

    Each component is opened relative to the previous one with O_NOFOLLOW, and
    created when missing. A component that is a symlink, whoever put it there,
    raises OutputLinkRefused for ``target``; so does one replaced by a link between
    the check and the open, which O_NOFOLLOW reports as ELOOP. A missing root is
    created first; links at or above it are not examined.
    """
    try:
        fd = os.open(root, os.O_RDONLY | _DIRECTORY)
    except FileNotFoundError:
        os.makedirs(root, exist_ok=True)
        fd = os.open(root, os.O_RDONLY | _DIRECTORY)
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
                    os.mkdir(part, 0o777, dir_fd=fd)
                    child = os.open(part, flags, dir_fd=fd)
            except OSError as error:
                if error.errno == errno.ELOOP:
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
        # lstat checks, between which a component can in principle change.
        current = root
        for part in dirs:
            current = current / part
            if not current.is_symlink() and not current.exists():
                return True
            if current.is_symlink() or not current.is_dir():
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


def _refuse_link_at(name: str, dir_fd: int, target: Path) -> None:
    """Raise if ``name`` in ``dir_fd`` is a symlink, or a file another name refers to."""
    try:
        status = os.lstat(name, dir_fd=dir_fd)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(status.st_mode):
        raise OutputLinkRefused(target, target)
    if stat.S_ISREG(status.st_mode) and status.st_nlink > 1:
        raise OutputHardLinkRefused(target, status.st_nlink)


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
    path: Union[str, Path], content: str, encoding: str = "utf-8"
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
    """
    path = Path(os.path.abspath(path))
    try:
        status = _lstat(path)
    except FileNotFoundError:
        status = None
    if status is not None and _is_link_status(status):
        raise OutputLinkRefused(path, path, where="at a destination it writes")
    # secrets, not uuid.uuid4: the snapshot tests pin uuid.uuid4 to a counter that
    # report ids are built from, and a staging name only has to be unique.
    staging = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(16)}.tmp")
    fd = os.open(
        staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _BINARY, 0o666
    )
    try:
        with os.fdopen(fd, "w", encoding=encoding) as handle:
            handle.write(content)
        os.replace(staging, path)
    except BaseException:
        staging.unlink(missing_ok=True)
        raise


#: A staging file: created, never opened if anything is already at its name.
_STAGING_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _BINARY


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
    permissions a plain open gives (0o666 less the umask). When the block ends
    without an exception the file is renamed over ``path``, so a reader of ``path``
    opens the old complete file or the new complete one and never a partial write.
    When the block raises, the staging file is removed and ``path`` is left as it
    was. The staging file is in the same directory because a rename is only atomic
    within one filesystem.

    Guarded as open_for_write is: below a registered root, or below ``root`` when
    the caller names one, each directory component is opened without following a
    link and created when missing; a link at any of them, or at the file name,
    raises OutputLinkRefused, and a file at the name that another name refers to
    raises OutputHardLinkRefused. The name is checked again just before the rename,
    so a link made there while the block ran is refused and left in place rather
    than replaced. The staging file is created and renamed relative to the
    directory's descriptor. Outside every root the rename replaces whatever entry
    is at the name, a link included, without following it.

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
    relative = path.relative_to(guard).parts if guard is not None else ()
    # secrets, not uuid.uuid4: the snapshot tests pin uuid.uuid4 to a counter that
    # report ids are built from, and a staging name only has to be unique.
    staging = f".{path.name}.{os.getpid()}.{secrets.token_hex(16)}.tmp"
    dir_fd: Optional[int] = None
    if guard is not None and _HAS_DIR_FD:
        dir_fd = _open_dir_beneath(guard, relative[:-1], path)

    def refuse_a_link_at_the_name() -> None:
        if dir_fd is not None:
            _refuse_link_at(path.name, dir_fd, path)
        elif guard is not None:
            _check_beneath_by_name(guard, relative, path)

    def remove_staging() -> None:
        try:
            if dir_fd is not None:
                os.unlink(staging, dir_fd=dir_fd)
            else:
                os.unlink(path.parent / staging)
        except FileNotFoundError:
            pass

    try:
        refuse_a_link_at_the_name()
        if dir_fd is not None:
            fd = os.open(staging, _STAGING_FLAGS, 0o666, dir_fd=dir_fd)
        else:
            fd = os.open(path.parent / staging, _STAGING_FLAGS, 0o666)
        try:
            try:
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
    root = _guard_root(path, root)
    if root is not None and not _HAS_DIR_FD:
        _check_beneath_by_name(root, path.relative_to(root).parts, path)
    if root is None or not _HAS_DIR_FD:
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
    relative = path.relative_to(root).parts
    dir_fd = _open_dir_beneath(root, relative[:-1], path)
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
    root = _writable_root_for(path) if hasattr(os, "fwalk") else None
    if root is None or path == root:
        return os.open(path, _READ_FLAGS)
    relative = path.relative_to(root).parts
    dir_fd = os.open(root, os.O_RDONLY | _DIRECTORY)
    try:
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
