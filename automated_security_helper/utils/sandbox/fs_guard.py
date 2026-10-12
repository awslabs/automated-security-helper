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


class OutputLinkRefused(OSError):
    """A write below a guarded root met a symlink, and was not made.

    An ``OSError`` (``errno.ELOOP``), so a caller that handles a failed write
    handles this one. The message names the path ASH was writing and the link.
    """

    def __init__(self, path: Union[str, Path], link: Union[str, Path]) -> None:
        super().__init__(
            errno.ELOOP,
            f"{Path(path).as_posix()} was not written: {Path(link).as_posix()} is a "
            "symlink, and ASH does not write through a symlink below its output "
            "directory",
        )
        self.path = Path(path)
        self.link = Path(link)


class OutputHardLinkRefused(OSError):
    """A write below a guarded root met a file that another name also refers to.

    A hard link, as an extracted archive can hold, to a file anywhere on the same
    filesystem: writing it would change that file. An ``OSError``
    (``errno.EMLINK``). Nothing is written, and the file is not truncated.
    """

    def __init__(self, path: Union[str, Path], links: int) -> None:
        super().__init__(
            errno.EMLINK,
            f"{Path(path).as_posix()} was not written: {links} names refer to it, and "
            "ASH does not write to a file below its output directory that another "
            "name refers to",
        )
        self.path = Path(path)
        self.links = links


_roots_lock = threading.Lock()
_writable_roots: Set[Path] = set()


def register_writable_root(path: Union[str, Path]) -> None:
    """Record that ASH writes beneath ``path`` and must not follow a link there.

    A sandboxed scanner's results directory, and the output directory of every
    PluginContext. open_for_write then opens every component below it without
    following a link, and refuses one.
    """
    with _roots_lock:
        _writable_roots.add(Path(os.path.abspath(path)))


def _writable_root_for(path: Path) -> Optional[Path]:
    """The deepest registered root ``path`` is below, or None."""
    with _roots_lock:
        roots = list(_writable_roots)
    inside = [r for r in roots if r in path.parents]
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
    the check and the open, which O_NOFOLLOW reports as ELOOP.
    """
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


def _open_regular(name: str, dir_fd: Optional[int], target: Path) -> int:
    """Open ``name`` for writing, truncated; refuse anything but a file of its own.

    Opened without O_TRUNC, then checked on the descriptor: it must be a regular
    file and its only name must be this one (``st_nlink == 1``), or
    OutputHardLinkRefused is raised for ``target`` and the file is left as it was.
    Only then is it truncated. O_NONBLOCK so a FIFO left at the name cannot block
    the open; the flag is cleared again once the target is known to be a regular
    file.
    """
    if dir_fd is None:
        fd = os.open(name, _FILE_FLAGS, 0o666)
    else:
        fd = os.open(name, _FILE_FLAGS, 0o666, dir_fd=dir_fd)
    try:
        status = os.fstat(fd)
        if not stat.S_ISREG(status.st_mode):
            raise OSError(errno.EINVAL, f"not a regular file: {name}")
        if status.st_nlink != 1:
            raise OutputHardLinkRefused(target, status.st_nlink)
        if _NONBLOCK:
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~_NONBLOCK)
        os.ftruncate(fd, 0)
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

    Below a registered root (the output directory of a PluginContext, or a
    sandboxed scanner's results directory; see register_writable_root), no symlink
    is followed: a link at any component, the file name included, raises
    OutputLinkRefused and nothing is written. The target must be a regular file,
    and missing directories are created. Anywhere else it is exactly
    open(path, "w"). Permissions are the same as open(): 0o666 less the umask.
    """
    path = Path(os.path.abspath(path))
    root = _writable_root_for(path) if hasattr(os, "fwalk") else None
    if root is None:
        return open(path, "w", encoding=encoding, errors=errors)
    else:
        relative = path.relative_to(root).parts
        dir_fd = _open_dir_beneath(root, relative[:-1], path)
        try:
            name = relative[-1]
            if _is_link(name, dir_fd):
                raise OutputLinkRefused(path, path)
            try:
                fd = _open_regular(name, dir_fd, path)
            except OSError as error:
                if error.errno == errno.ELOOP:
                    raise OutputLinkRefused(path, path) from error
                raise
        finally:
            os.close(dir_fd)
    return os.fdopen(fd, "w", encoding=encoding, errors=errors)
