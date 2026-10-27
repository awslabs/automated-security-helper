# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Record every write a test process makes under the real user's ``~/.ash``.

tests/conftest.py gives the run and each test a home of their own, so anything that
finds the home through ``$HOME`` or ``Path.home()`` -- install receipts, the default
ASH_BIN_PATH -- lands in a temporary directory. What a moved HOME cannot stop is code
that finds the home some other way: ``pwd.getpwuid()``, ``expanduser("~user")``, a path
computed before the run moved HOME, or a literal. That is the class this watches for.
An audit hook records each write under the guarded roots, ``~/.ash`` of the passwd
home and of the home the run started with, except under the excluded paths a caller
names (the interpreter's own installation, the shared caches, the checkout), refuses
it, and tests/conftest.py fails the test it happened in.

Refused, so nothing lands: a fixture binary and its receipt left in the real ~/.ash are
what a later real run would trust. Recorded first, because the refusal alone is not
enough: the receipt writer catches ``OSError`` on purpose (receipts are best-effort),
so the PermissionError raised here can be swallowed, and the record is what fails the
test.

A path is compared as written and with its links resolved, both case-folded where the
platform folds case, so a write through a link into ~/.ash is caught. tests/conftest.py
also drains the record at the end of the session and fails it, for writes after the
last test's teardown or in the xdist controller; an xdist worker sends its own to the
controller, which reports them.

Limits, stated so nobody reads a green run as covering them: audit hooks do not reach
child processes (tests/conftest.py checks those where they start, in
``subprocess.Popen``: an installer, or any Python or ASH child, needs a home of its
own); a write through a file descriptor opened relative to a directory fd (``dir_fd``)
is not resolved, nor is a call given a file descriptor where a path goes (``os.chmod``
of a directory fd changes its mode unseen); os.mkfifo and os.mknod raise no audit
event; a file sqlite3.connect creates, and an AF_UNIX socket's bind, are not seen
either; a hard link made before the run, from outside into ~/.ash, is written through
by a path outside the roots; a write after the session ends (config cleanup, an atexit
handler) or in an xdist worker that crashed is refused but never reported; and only the
events listed in ``_PATH_ARGS`` are seen. A hard link
made during the run out of ~/.ash is refused (``os.link`` checks both of its ends).
"""

from __future__ import annotations

import contextlib
import errno
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
    # Both ends: a hard link out of a root is the same file under another name.
    "os.link": (0, 1),
    "os.truncate": (0,),
    "os.utime": (0,),
    "shutil.copyfile": (1,),
    "shutil.copytree": (1,),
    "shutil.rmtree": (0,),
    "os.setxattr": (0,),
    "os.removexattr": (0,),
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


def _spellings(path: Path) -> List[str]:
    """``path`` as written and resolved, case-folded where the platform folds case."""
    return [
        os.path.normcase(os.path.abspath(path)),
        os.path.normcase(os.path.realpath(path)),
    ]


def both_spellings(path: Path) -> List[str]:
    """``path`` as the guard compares it: as written and resolved, case-folded.

    For a caller that adds roots or exclusions of its own (tests/conftest.py does), so
    what it adds is spelled as the guard spells what it checks against them.
    """
    return _spellings(path)


def guarded_roots(homes: Iterable[Optional[Path]]) -> List[str]:
    """``<home>/.ash`` for each home, in both its given and its resolved spelling."""
    roots = set()
    for home in homes:
        if home is None or not str(home):
            continue
        roots.update(_spellings(Path(home) / ".ash"))
    return sorted(roots)


def _within(path: str, roots: Iterable[str]) -> bool:
    return any(path == root or path.startswith(root + os.sep) for root in roots)


def is_guarded(path: object) -> bool:
    """Whether a write to ``path`` would be refused."""
    return _under_a_root(path) is not None


def watched_roots() -> List[str]:
    """The roots being watched now."""
    with _lock:
        return list(_roots)


def _under_a_root(raw: object) -> Optional[str]:
    """``raw`` as written, if it or its resolved path is under a guarded root."""
    if not isinstance(raw, (str, bytes, os.PathLike)):
        return None
    try:
        written = os.path.abspath(os.fsdecode(raw))
        spellings = _spellings(Path(written))
    except (TypeError, ValueError, OSError):
        return None
    if any(_within(path, _excluded) for path in spellings):
        return None
    for root in _roots:
        for path in spellings:
            if path == root or path.startswith(root + os.sep):
                return written
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
    refused = None
    try:
        for index in indexes:
            if index < len(args):
                hit = _under_a_root(args[index])
                if hit is not None:
                    with _lock:
                        _writes.append((event, hit))
                    refused = refused or hit
    finally:
        _inside.active = False
    if refused is not None:
        raise PermissionError(
            errno.EACCES,
            "write under the real ~/.ash refused by the test guard",
            refused,
        )


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
    extra = _spellings(Path(root))
    with _lock:
        added = [r for r in dict.fromkeys(extra) if r not in _roots]
        _roots.extend(added)
        skipped = [
            p for path in exclude for p in _spellings(Path(path)) if p not in _excluded
        ]
        _excluded.extend(dict.fromkeys(skipped))
    try:
        yield
    finally:
        with _lock:
            for r in added:
                _roots.remove(r)
            for p in dict.fromkeys(skipped):
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
