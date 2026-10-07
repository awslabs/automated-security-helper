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

import os
import stat
from pathlib import Path
from typing import IO, Iterable, Union

from automated_security_helper.utils.log import ASH_LOGGER

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
# O_BINARY on Windows, so the CRT does not translate newlines a second time under
# the text wrapper; open() does the same.
_BINARY = getattr(os, "O_BINARY", 0)


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
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            for name in list(dirnames) + filenames:
                path = os.path.join(dirpath, name)
                try:
                    mode = os.lstat(path).st_mode
                except OSError:
                    continue
                if stat.S_ISREG(mode) or stat.S_ISDIR(mode):
                    continue
                try:
                    os.unlink(path)
                    removed += 1
                except OSError as e:
                    ASH_LOGGER.warning(f"Could not remove {path}: {e}")
                if name in dirnames:
                    dirnames.remove(name)
    if removed:
        ASH_LOGGER.warning(
            f"Scanner sandbox: removed {removed} symlink(s) or special file(s) a "
            "scanner left in its results directory"
        )
    return removed


def open_for_write(
    path: Union[str, Path], encoding: str = "utf-8", errors: str = "strict"
) -> IO[str]:
    """Open ``path`` for writing text without following a symlink at it."""
    path = Path(path)
    if path.is_symlink():
        path.unlink()
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _NOFOLLOW | _BINARY, 0o644
    )
    return os.fdopen(fd, "w", encoding=encoding, errors=errors)
