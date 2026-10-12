# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Record every write a test process makes under the real user's ``~/.ash``.

tests/conftest.py gives each session a private HOME, so anything that finds the home
through ``$HOME`` or ``Path.home()`` -- install receipts, the default ASH_BIN_PATH --
lands in a directory the session removes. What a private HOME cannot stop is code
that finds the home some other way: ``pwd.getpwuid()``, ``expanduser("~user")``, a
path computed before the session moved HOME, or a literal. That is the class this
watches for. An audit hook records each write under the guarded roots, and
tests/conftest.py fails the test it happened in.

Recorded rather than raised. The receipt writer catches ``OSError`` on purpose
(receipts are best-effort), so an exception raised from here would be swallowed and
the test would pass.

Limits, stated so nobody reads a green run as covering them: audit hooks do not reach
child processes, a write through a file descriptor opened relative to a directory fd
(``dir_fd``) is not resolved, and only the events listed in ``_PATH_ARGS`` are seen.
"""

from __future__ import annotations

import contextlib
import os
import sys
import threading
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Tuple

try:  # POSIX only; Windows has no passwd database.
    import pwd
except ImportError:  # pragma: no cover - Windows
    pwd = None  # type: ignore[assignment]

#: Audit event -> indexes of the arguments that name a path being written.
_PATH_ARGS = {
    "os.mkdir": (0,),
    "os.rename": (0, 1),  # os.replace raises this event too
    "os.remove": (0,),
    "os.rmdir": (0,),
    "os.chmod": (0,),
    "os.chown": (0,),
    "os.symlink": (1,),
    "os.link": (1,),
    "os.truncate": (0,),
    "os.utime": (0,),
    "shutil.copyfile": (1,),
    "shutil.copytree": (1,),
    "shutil.rmtree": (0,),
}
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC

_roots: List[str] = []
_writes: List[Tuple[str, str]] = []
_lock = threading.Lock()
_installed = False
_inside = threading.local()


def passwd_home() -> Optional[Path]:
    """The home directory the passwd database names for this uid, or None."""
    if pwd is None:
        return None
    try:
        return Path(pwd.getpwuid(os.getuid()).pw_dir)
    except KeyError:
        return None


def guarded_roots(homes: Iterable[Optional[Path]]) -> List[str]:
    """``<home>/.ash`` for each home, in both its given and its resolved spelling."""
    roots = set()
    for home in homes:
        if home is None or not str(home):
            continue
        ash = Path(home) / ".ash"
        roots.add(os.path.abspath(ash))
        roots.add(os.path.realpath(ash))
    return sorted(roots)


def _under_a_root(raw: object) -> Optional[str]:
    if not isinstance(raw, (str, bytes, os.PathLike)):
        return None
    try:
        path = os.path.abspath(os.fsdecode(raw))
    except (TypeError, ValueError):
        return None
    for root in _roots:
        if path == root or path.startswith(root + os.sep):
            return path
    return None


def _is_a_write_open(args: tuple) -> bool:
    mode = args[1] if len(args) > 1 else None
    flags = args[2] if len(args) > 2 else 0
    if isinstance(mode, str) and any(c in mode for c in "wax+"):
        return True
    return isinstance(flags, int) and bool(flags & _WRITE_FLAGS)


def _hook(event: str, args: tuple) -> None:
    if event == "open":
        if not args or not _is_a_write_open(args):
            return
        indexes: Tuple[int, ...] = (0,)
    else:
        indexes = _PATH_ARGS.get(event, ())
        if not indexes:
            return
    if getattr(_inside, "active", False):
        return
    _inside.active = True
    try:
        for index in indexes:
            if index < len(args):
                hit = _under_a_root(args[index])
                if hit is not None:
                    with _lock:
                        _writes.append((event, hit))
    finally:
        _inside.active = False


def install(roots: Iterable[str]) -> None:
    """Start watching ``roots``. Idempotent; an audit hook cannot be removed."""
    global _installed
    with _lock:
        for root in roots:
            if root not in _roots:
                _roots.append(root)
    if not _installed:
        sys.addaudithook(_hook)
        _installed = True


def drain() -> List[Tuple[str, str]]:
    """Return and clear the writes recorded so far."""
    with _lock:
        recorded = list(_writes)
        _writes.clear()
    return recorded


@contextlib.contextmanager
def watching(root: Path) -> Iterator[None]:
    """Also watch ``root`` for the body of the block (for the guard's own control)."""
    extra = [os.path.abspath(root), os.path.realpath(root)]
    with _lock:
        added = [r for r in extra if r not in _roots]
        _roots.extend(added)
    try:
        yield
    finally:
        with _lock:
            for r in added:
                _roots.remove(r)
