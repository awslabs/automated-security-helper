# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Record every write a test process makes under the real user's ``~/.ash`` or XDG dirs.

tests/conftest.py gives each session a private HOME, and points XDG_CONFIG_HOME,
XDG_DATA_HOME and XDG_STATE_HOME inside it, so anything that finds those directories
through the environment -- install receipts, the default ASH_BIN_PATH, uv's tool
environments -- lands in a directory the session removes. What that cannot stop is
code that finds them some other way: ``pwd.getpwuid()``, ``expanduser("~user")``, a
path computed before the session moved them, or a literal. That is the class this
watches for. An audit hook records each write under the guarded roots, except under
the excluded paths (the interpreter's own installation, the shared caches, the
checkout), and tests/conftest.py fails the test it happened in.

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
_excluded: List[str] = []
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


def both_spellings(path: Path) -> List[str]:
    """``path`` as given (made absolute) and resolved, so a symlinked home matches."""
    return sorted({os.path.abspath(path), os.path.realpath(path)})


def guarded_roots(homes: Iterable[Optional[Path]]) -> List[str]:
    """``<home>/.ash`` for each home, in both its given and its resolved spelling."""
    roots = set()
    for home in homes:
        if home is None or not str(home):
            continue
        roots.update(both_spellings(Path(home) / ".ash"))
    return sorted(roots)


def _within(path: str, roots: Iterable[str]) -> bool:
    return any(path == root or path.startswith(root + os.sep) for root in roots)


def _under_a_root(raw: object) -> Optional[str]:
    if not isinstance(raw, (str, bytes, os.PathLike)):
        return None
    try:
        path = os.path.abspath(os.fsdecode(raw))
    except (TypeError, ValueError):
        return None
    if _within(path, _roots) and not _within(path, _excluded):
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


def install(roots: Iterable[str], exclude: Iterable[str] = ()) -> None:
    """Start watching ``roots``, except under ``exclude``.

    Idempotent; an audit hook cannot be removed.
    """
    global _installed
    with _lock:
        for root in roots:
            if root not in _roots:
                _roots.append(root)
        for path in exclude:
            if path not in _excluded:
                _excluded.append(path)
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
def watching(root: Path, exclude: Iterable[Path] = ()) -> Iterator[None]:
    """Also watch ``root``, except under ``exclude``, for the body of the block.

    For the guard's own controls.
    """
    with _lock:
        added = [r for r in both_spellings(root) if r not in _roots]
        _roots.extend(added)
        skipped = [
            p for path in exclude for p in both_spellings(path) if p not in _excluded
        ]
        _excluded.extend(skipped)
    try:
        yield
    finally:
        with _lock:
            for r in added:
                _roots.remove(r)
            for p in skipped:
                _excluded.remove(p)


@contextlib.contextmanager
def allowing(paths: Iterable[Path]) -> Iterator[None]:
    """Do not record writes to exactly ``paths`` (and anything under them) in the block.

    For a test whose purpose is to plant a file in the account's real home, such as the
    passwd-home escape test: the files it plants and the directories it makes for them
    are named by the caller and nothing else is let through. The exclusions are removed
    when the block ends, so a later write to the same place is recorded again.
    """
    with _lock:
        skipped = [
            p
            for path in paths
            for p in both_spellings(Path(path))
            if p not in _excluded
        ]
        _excluded.extend(skipped)
    try:
        yield
    finally:
        with _lock:
            for p in skipped:
                _excluded.remove(p)
