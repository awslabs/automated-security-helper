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
  before it is truncated.
* :func:`sweep_writable` runs after every sandboxed spawn and removes every entry
  under the writable directories that is not a regular file or a directory.
"""

from __future__ import annotations

import collections
import errno
import os
import stat
import threading

try:
    import fcntl
except ImportError:  # Windows, where no sandbox backend exists
    fcntl = None  # type: ignore[assignment]
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Dict, FrozenSet, Iterable, Iterator, Optional, Tuple, Union

from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.output_dir_links import OutputDirLinkRefused

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

    def __init__(self, path: Union[str, Path], link: Union[str, Path]) -> None:
        found = f"{Path(link).as_posix()} is a symlink"
        # OSError's own __init__: OutputDirLinkRefused's is not called, and its
        # attribute is set below.
        super().__init__(
            errno.ELOOP,
            f"{Path(path).as_posix()} was not written: {found}, and ASH does not "
            "write through a symlink below its output directory",
        )
        self.found = found
        self.path = Path(path)
        self.link = Path(link)

    def __reduce__(self):
        # Rebuilt from its own arguments: the default rebuilds from OSError's args,
        # which this __init__ does not take.
        return (type(self), (self.path, self.link))


class OutputHardLinkRefused(OSError, OutputDirLinkRefused):
    """A write below a guarded root met a file that another name also refers to.

    A hard link, as an extracted archive can hold, to a file anywhere on the same
    filesystem: writing it would change that file. An ``OSError``
    (``errno.EMLINK``) and an ``OutputDirLinkRefused``, as OutputLinkRefused is.
    Nothing is written, and the file is not truncated.
    """

    def __init__(self, path: Union[str, Path], links: int) -> None:
        found = f"{links} names refer to {Path(path).as_posix()}"
        super().__init__(
            errno.EMLINK,
            f"{Path(path).as_posix()} was not written: {links} names refer to it, and "
            "ASH does not write to a file below its output directory that another "
            "name refers to",
        )
        self.found = found
        self.path = Path(path)
        self.links = links

    def __reduce__(self):
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
    """
    root = Path(os.path.abspath(path))
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


def _guard_root(path: Path, root: Optional[Union[str, Path]]) -> Optional[Path]:
    """The root open_for_write checks ``path`` below: see its ``root`` argument."""
    registered = _writable_root_for(path)
    if root is None:
        return registered
    named = Path(os.path.abspath(root))
    if named not in path.parents:
        raise ValueError(f"{path.as_posix()} is not below {named.as_posix()}")
    if registered is not None and len(registered.parts) < len(named.parts):
        return registered
    return named


def _sweep_tree(root: Path) -> int:
    """Remove non-regular, non-directory entries under ``root``.

    os.fwalk descends through directory file descriptors and never follows a
    symlink, so a directory replaced by a link while the walk runs is not entered.
    Entries are removed relative to their directory's descriptor for the same
    reason. Platforms without fwalk (Windows, where no sandbox backend exists)
    fall back to os.walk.
    """
    removed = 0
    if not hasattr(os, "fwalk"):
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            for name in list(dirnames) + filenames:
                path = os.path.join(dirpath, name)
                if _is_special(os.lstat(path).st_mode):
                    os.unlink(path)
                    removed += 1
        return removed
    for _, dirnames, filenames, dir_fd in os.fwalk(root, follow_symlinks=False):
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
                ASH_LOGGER.warning(f"Could not remove {name} under {root}: {e}")
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
    below it.
    """
    root = Path(os.path.abspath(root))
    if not hasattr(os, "fwalk") or not root.is_dir():
        return
    for dirpath, dirnames, filenames, dir_fd in os.fwalk(root, follow_symlinks=False):
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


def sweep_writable(roots: Iterable[Union[str, Path]]) -> int:
    """Remove symlinks and special files under ``roots``; return how many."""
    removed = 0
    for root in roots:
        root = Path(root)
        try:
            if root.is_symlink():
                root.unlink()
                removed += 1
                continue
        except OSError:
            continue
        removed += _sweep_tree(root)
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


def open_parent_beneath(path: Union[str, Path]) -> Optional[Tuple[int, str]]:
    """``(directory descriptor, file name)`` for ``path``, or None when not guarded.

    For a writer that creates its own file in ``path``'s directory, such as a
    staging file renamed over ``path``. Below a registered root every directory
    component is opened without following a link and created when missing; a link
    at one, or at the file name, raises OutputLinkRefused, and a file at the name
    that another name refers to raises OutputHardLinkRefused. The caller closes the
    descriptor. None when ``path`` is below no registered root, and the caller
    writes as it otherwise would. None as well on a platform without directory
    descriptors (Windows), after the same refusals were checked by name
    (_check_beneath_by_name).
    """
    path = Path(os.path.abspath(path))
    root = _writable_root_for(path)
    if root is None:
        return None
    relative = path.relative_to(root).parts
    if not _HAS_DIR_FD:
        _check_beneath_by_name(root, relative, path)
        return None
    dir_fd = _open_dir_beneath(root, relative[:-1], path)
    try:
        _refuse_link_at(relative[-1], dir_fd, path)
    except BaseException:
        os.close(dir_fd)
        raise
    return dir_fd, relative[-1]


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
) -> IO:
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
    text = (
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
