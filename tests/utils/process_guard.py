# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Refuse every process start a test makes, by every route Python has.

For a test that runs code in this process and must reach no real program. Each
route records the start and raises, so a start fails where it happens, and a test
can also read the record. The routes, each pinned by a case in
tests/unit/cli/test_usage_error_exit_code.py (TestTheProcessGuardSeesEveryStart):

- subprocess.Popen, replaced by a subclass that refuses to be made, so code that
  only names the class still works (``subprocess.Popen[bytes]``, isinstance);
- subprocess._fork_exec, which a Popen imported by name before the patch still
  calls (subprocess binds it at import);
- _posixsubprocess.fork_exec, which multiprocessing's spawn calls directly;
- the functions in PROCESS_STARTERS, in os and in posix, which os copies them from
  (os.system is posix.system, and patching one leaves the other);
- a multiprocessing Process started through a forkserver. The server forks the
  child itself, so once a server is running (an earlier test in the worker can
  start one; it is 3.14's default start method on Linux) no primitive above is
  called in this process.

Not covered: a name bound before the patch (``from os import system`` at import
time), ctypes calling libc, and a C extension that starts a process itself.
"""

from __future__ import annotations

import os
import subprocess
from typing import Callable, List, NoReturn, Optional

import pytest

#: The os functions, and their posix originals, that start or replace a process
#: without subprocess.Popen.
PROCESS_STARTERS = (
    "system",
    "posix_spawn",
    "posix_spawnp",
    "fork",
    "forkpty",
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "execv",
    "execve",
    "execvp",
    "execvpe",
)


def _refused_by_default(route: str, start: object) -> BaseException:
    return AssertionError(f"the test started a process ({route}): {start!r}")


def _refused_popen(refuse: Callable[..., object]) -> type:
    """subprocess.Popen as a class that refuses to be made.

    A subclass of the Popen in place now, whose ``__new__`` calls ``refuse`` (which
    records the start and raises) before any instance exists, so there is no
    half-made Popen for ``__del__`` to finish. Code that only names the class keeps
    working under the guard: ``subprocess.Popen[bytes]`` in an annotation, which
    Python evaluates where it is written before 3.14 (mcp's Windows helpers have
    one, and a config load imports them), and an isinstance check, which asks the
    Popen in place now about a process made before the guard."""
    popen = subprocess.Popen

    class _PopenType(type(popen)):  # type: ignore[misc]
        def __instancecheck__(cls, instance: object) -> bool:
            return isinstance(instance, popen)

    class _RefusedPopen(popen, metaclass=_PopenType):  # type: ignore[misc,valid-type]
        def __new__(cls, *args: object, **kwargs: object) -> NoReturn:
            refuse(*args, **kwargs)
            raise AssertionError("the process guard's refusal did not raise")

    _RefusedPopen.__name__ = _RefusedPopen.__qualname__ = popen.__name__
    return _RefusedPopen


def refuse_process_starts(
    monkeypatch: pytest.MonkeyPatch,
    refusal: Optional[Callable[[str, object], BaseException]] = None,
) -> List[object]:
    """Patch every route above to record the start and raise.

    Args:
        monkeypatch: The test's MonkeyPatch, which undoes every patch afterwards.
        refusal: Builds what a start raises, from the route and the start. By
            default an AssertionError that names the route.

    Returns:
        The starts, in order: each call's first argument (its argv, or the command
        line os.system was given).
    """
    started: List[object] = []
    refused = refusal or _refused_by_default

    def _refuse(route: str):
        def _refusing(*args, **kwargs):
            started.append(args[0] if args else kwargs.get("args", route))
            raise refused(route, started[-1])

        return _refusing

    monkeypatch.setattr(
        subprocess, "Popen", _refused_popen(_refuse("subprocess.Popen"))
    )
    if hasattr(subprocess, "_fork_exec"):
        monkeypatch.setattr(subprocess, "_fork_exec", _refuse("subprocess._fork_exec"))
    if os.name != "nt":
        import _posixsubprocess
        import posix
        from multiprocessing import popen_forkserver

        monkeypatch.setattr(
            _posixsubprocess, "fork_exec", _refuse("_posixsubprocess.fork_exec")
        )
        monkeypatch.setattr(
            popen_forkserver.Popen, "_launch", _refuse("multiprocessing forkserver")
        )
        for name in PROCESS_STARTERS:
            if hasattr(posix, name):
                monkeypatch.setattr(posix, name, _refuse(f"posix.{name}"))
    for name in PROCESS_STARTERS:
        if hasattr(os, name):
            monkeypatch.setattr(os, name, _refuse(f"os.{name}"))
    return started
