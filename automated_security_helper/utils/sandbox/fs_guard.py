"""Keep ASH's own writes inside a sandboxed scanner's results directory.

A sandboxed scanner may write anything under its results directory, including
symlinks. ASH itself, which is not sandboxed, writes files there afterwards (stream
logs, ASH.ScanResults.json, the SARIF a scanner override assembles). A plain open()
follows a symlink the scanner left behind, so those writes would land wherever it
points. Two measures close that:

* :func:`sweep_writable` runs after every sandboxed spawn and removes every entry
  under the writable directories that is not a regular file or a directory.
* :func:`open_for_write` is what ASH uses for its own writes there. It removes a
  symlink at the target and opens with ``O_NOFOLLOW``, so a link created after the
  sweep (by a process that outlived the scanner) is still not followed.
"""

from __future__ import annotations

import errno
import os
import stat
import threading

try:
    import fcntl
except ImportError:  # Windows, where no sandbox backend exists
    fcntl = None  # type: ignore[assignment]
from pathlib import Path
from typing import IO, Iterable, Optional, Set, Tuple, Union

from automated_security_helper.utils.log import ASH_LOGGER

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
# O_BINARY on Windows, so the CRT does not translate newlines a second time under
# the text wrapper; open() does the same.
_BINARY = getattr(os, "O_BINARY", 0)


_roots_lock = threading.Lock()
_writable_roots: Set[Path] = set()


def register_writable_root(path: Union[str, Path]) -> None:
    """Record that a sandboxed scanner can write beneath ``path``.

    open_for_write then opens every component below it without following links.
    """
    with _roots_lock:
        _writable_roots.add(Path(os.path.abspath(path)))


def _writable_root_for(path: Path) -> Optional[Path]:
    """The deepest registered root ``path`` is inside, or None."""
    with _roots_lock:
        roots = list(_writable_roots)
    inside = [r for r in roots if path == r or r in path.parents]
    return max(inside, key=lambda r: len(r.parts)) if inside else None


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
_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _NOFOLLOW | _NONBLOCK | _BINARY


def _open_dir_beneath(root: Path, relative_parts: Tuple[str, ...]) -> int:
    """A descriptor for ``root/relative_parts``, never following a link below root.

    Each component is opened relative to the previous one with O_NOFOLLOW, and
    created when missing, so a component a scanner replaced with a symlink makes
    the open fail rather than lead elsewhere.
    """
    fd = os.open(root, os.O_RDONLY | _DIRECTORY)
    try:
        for part in relative_parts:
            try:
                child = os.open(part, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(part, 0o777, dir_fd=fd)
                child = os.open(part, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=fd)
            previous, fd = fd, child
            os.close(previous)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_regular(name: str, dir_fd: Optional[int]) -> int:
    """Open ``name`` for writing; refuse anything but a regular file.

    O_NONBLOCK so a FIFO left at the name cannot block the open; the flag is
    cleared again once the target is known to be a regular file.
    """
    if dir_fd is None:
        fd = os.open(name, _FILE_FLAGS, 0o666)
    else:
        fd = os.open(name, _FILE_FLAGS, 0o666, dir_fd=dir_fd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, f"not a regular file: {name}")
        if _NONBLOCK:
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~_NONBLOCK)
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_for_write(
    path: Union[str, Path],
    encoding: Optional[str] = "utf-8",
    errors: Optional[str] = "strict",
) -> IO[str]:
    """Open ``path`` for writing text.

    Below a root a sandboxed scanner could write (register_writable_root), no
    symlink is followed at any component and the target must be a regular file.
    Anywhere else, which is every write when no sandbox is in use, it is exactly
    open(path, "w"): the guard changes nothing for a scan that did not ask for a
    sandbox. Permissions are the same as open(): 0o666 less the umask.
    """
    path = Path(os.path.abspath(path))
    root = _writable_root_for(path) if hasattr(os, "fwalk") else None
    if root is None:
        return open(path, "w", encoding=encoding, errors=errors)
    else:
        relative = path.relative_to(root).parts
        dir_fd = _open_dir_beneath(root, relative[:-1])
        try:
            name = relative[-1]
            try:
                if stat.S_ISLNK(os.lstat(name, dir_fd=dir_fd).st_mode):
                    os.unlink(name, dir_fd=dir_fd)
            except FileNotFoundError:
                pass
            fd = _open_regular(name, dir_fd)
        finally:
            os.close(dir_fd)
    return os.fdopen(fd, "w", encoding=encoding, errors=errors)
