# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Doubles the MCP source-delivery tests share.

The Windows rule for a read-only file (it cannot be deleted until its read-only
bit is cleared) is stood in for by two doubles that go together. ``windows_unlink``
refuses a file whose owner-write bit is clear. ``rmtree_calling_windows_unlink``
deletes with it and reports a failure to the handler the way ``shutil.rmtree``
does, naming ``windows_unlink`` as the function that failed. ``_remove_tree``
retries only a call that is ``os.unlink``, ``os.remove`` or ``os.rmdir`` in its own
module, so the pair is applied to ``source_delivery``'s ``os`` and ``shutil``
together (the ``windows_semantics`` fixture): with only the rmtree double in
place, the reported function would not be ``source_delivery``'s ``os.unlink`` and
the retry would be skipped.

Every double works on trees under a test's ``tmp_path`` and replaces a name inside
``source_delivery`` only, never the global module, so pytest's own cleanup of
``tmp_path`` keeps the real functions. Nothing here runs git, signals a process or
touches a path outside the tree it is given.
"""

from __future__ import annotations

import contextlib
import errno
import os
import shutil
import stat
from pathlib import Path
from typing import Any

import pytest

from automated_security_helper.cli.mcp import source_delivery


class ModuleWith:
    """A stand-in for a module in which some names are replaced.

    Every other name reads through to the real module, so a new call the code
    under test makes on it (``os.path``, ``shutil.move``) does not raise
    ``AttributeError`` in a test that never meant to replace it.
    """

    def __init__(self, real: Any, **replaced: Any) -> None:
        self._real = real
        self.__dict__.update(replaced)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


#: A file name the doubles never delete, as if another account owned it.
UNDELETABLE = "owned-by-another-account"


def windows_unlink(path: str) -> None:
    """``os.unlink`` with Windows semantics for a read-only file.

    A file whose owner-write bit is clear cannot be deleted, and a file whose name
    starts with ``UNDELETABLE`` cannot be deleted at all. The check reads the mode
    bits and the name, so it behaves the same for every user, root included.
    """

    if os.path.basename(path).startswith(UNDELETABLE):
        raise PermissionError(errno.EACCES, "another account owns the file", path)
    if not os.stat(path).st_mode & stat.S_IWUSR:
        raise PermissionError(errno.EACCES, "the file is read-only", path)
    os.unlink(path)


def rmtree_calling_windows_unlink(path, ignore_errors=False, onerror=None, **kwargs):
    """A ``shutil.rmtree`` that deletes with ``windows_unlink``.

    A failed delete goes to the handler as ``shutil.rmtree`` reports it: the
    function that failed, the path, and the error (the ``onexc`` keyword) or its
    exc_info triple (``onerror``). With ``ignore_errors`` the entry is left and the
    walk goes on; a handler that raises ends the call, as it does there.
    ``source_delivery`` passes the ``onexc`` keyword from Python 3.12 and ``onerror``
    before it, so this takes the keywords it is called with and reads ``onexc`` from
    them: its signature does not name a keyword the oldest supported Python lacks.
    """

    exc_handler = kwargs.get("onexc")
    handler = exc_handler or onerror
    for directory, _subdirectories, names in os.walk(path, topdown=False):
        for name in sorted(names):
            candidate = os.path.join(directory, name)
            try:
                windows_unlink(candidate)
            except OSError as error:
                if ignore_errors:
                    continue
                if handler is None:
                    raise
                argument = error if exc_handler else (type(error), error, None)
                handler(windows_unlink, candidate, argument)
        with contextlib.suppress(OSError):
            os.rmdir(directory)
    if os.path.lexists(path) and not ignore_errors:
        raise OSError(errno.ENOTEMPTY, "directory not empty", str(path))


@pytest.fixture
def windows_semantics(monkeypatch):
    """Returns a function that applies the two doubles to ``source_delivery``.

    Call it after a test has built its trees and uploads, so only the call under
    test sees them.
    """

    def apply() -> None:
        monkeypatch.setattr(
            source_delivery, "os", ModuleWith(os, unlink=windows_unlink)
        )
        monkeypatch.setattr(
            source_delivery,
            "shutil",
            ModuleWith(shutil, rmtree=rmtree_calling_windows_unlink),
        )

    return apply


@pytest.fixture
def read_only_files():
    """Plant read-only bits on test-owned files; restore the modes at teardown."""

    planted: list[Path] = []

    def plant(path: Path) -> Path:
        os.chmod(path, 0o444)
        planted.append(path)
        return path

    yield plant
    for path in planted:
        with contextlib.suppress(OSError):
            os.chmod(path, 0o644)
