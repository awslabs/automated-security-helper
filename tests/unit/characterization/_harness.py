# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Characterization harness: pins how ASH launches each tool, exactly.

Developer note
==============

What this package is for
------------------------
Every test here records each process ASH starts -- argv, environment, working
directory, stdio dispositions, the timeout it waits with, the files it hands the tool
and the files it reads back -- and compares that record with a committed golden under
``__snapshots__/<module>/<test>.json``. The goldens describe ASH as it is today. A
commit that only moves code (the tool-executor migration is the reason this exists)
must leave every golden byte-identical. A golden that changes in such a commit means
the commit changed behavior: fix the commit, or move the behavior change into a
commit of its own that says why.

No real process starts. ``subprocess.Popen`` is replaced by :class:`FakePopen`, which
resolves the executable the way the OS would, hands the call to a registered tool
double, and records everything. The real ``Popen`` cannot start a child either:
``_execute_child`` raises, and it is the real backstop, because CPython 3.14's
subprocess binds ``_posixsubprocess.fork_exec`` by name at import (the module
attribute is still replaced, for multiprocessing's ``spawnv_passfds``).
``os.system``, ``os.popen``, ``os.exec*``, ``os.spawn*``, ``os.posix_spawn*``,
``os.fork``, ``os.forkpty``, asyncio's subprocess functions and multiprocessing's
process start fail the test.

Signals stay inside the test too. Fake pids start above PID_MAX_LIMIT, so no real
process can have one. ``os.kill``, ``os.killpg``, ``os.getpgid``, ``os.getsid`` and
``os.waitpid`` on a fake pid or process group reach that FakePopen and are recorded
in its ``calls``. On any other pid they fail the test, and so do ``os.wait*``,
``os.pidfd_open`` and ``signal.pidfd_send_signal``. Each test's signal mask and
handlers are put back when it ends.

One audit hook per worker backstops all of it, whatever route reaches the C call
(``posix.*`` aliases, a module that bound a function before the guards went in,
``_socket``). While a test runs it refuses these events:

* any write, create, delete, rename, link, chmod, chown or utime outside pytest's
  basetemp and the package's ``__snapshots__``, after symlinks and ``dir_fd`` are
  resolved (``sys.dont_write_bytecode`` is set, so imports write nothing): builtin ``open`` and ``os.open``, ``os.*``, ``shutil.*``,
  ``tempfile.mkstemp``/``mkdtemp``, and ``sqlite3.connect``, whose file SQLite
  opens in C (the C dbm backends raise no event, so their ``open`` is wrapped).
  ``os.open`` is guarded as a function too, because its event omits ``dir_fd``;
  a relative write through an ``os.open`` bound before the guard is refused.
  ``os.mkfifo`` and ``os.mknod`` raise no event, so they are guarded as functions;
* every socket connect, bind, addressed send and name lookup, AF_UNIX included;
* ``ctypes`` loading a library or looking up a function in one, and on Python
  3.14 and later, where the call itself raises an event, calling one (before
  that, a function looked up before the test began can still be called);
* every process start and every real ``kill``/``killpg``.

ctypes handles that ASH modules hold (``landlock_exec.libc``) are replaced by an
object that refuses every call, so prctl and seccomp cannot reach the worker. A
module that creates one during the test is refused at ``dlopen``. Tests without
``char`` get all of the above except the hermetic environment.

No lookup reads the host either. Every directory ASH searches for a tool is a
harness directory: PATH is ``<BIN>:<SYSBIN>`` (``<SYSBIN>`` stands in for /usr/bin and
/bin, and for ``os.defpath`` and ``CS_PATH`` when PATH is unset);
``path_independent_dirs()`` is the product's own function with /usr/local/bin
replaced by ``<USRLOCALBIN>``; ASH's own environment (the interpreter's directory
and scripts directory, where pip and uv put the console scripts of its packages,
and the uv that came with ASH) is ``<PYENVBIN>``, where the product looks it up;
the import-time ``ASH_BIN_PATH`` default is ``<HOME>/.ash/bin``. A ``shutil.which`` or exec that would search any other
directory, and any ``os.stat``/``lstat``/``access``/``listdir``/``scandir`` inside
a host executable directory (``HOST_EXEC_DIRS``, which includes the interpreter's
own bin directory), fails the test, so an image that ships uv or a scanner in
/usr/local/bin cannot change a golden.

Adding a scanner
----------------
1. Write ``tests/unit/characterization/test_<scanner>.py``.
2. In it, write a :class:`ToolDouble` for the scanner's tool. Parse argv with an
   :class:`ArgvGrammar` so that any flag it does not know fails the test, and write
   the files the tool would write (``--output`` and friends) from a small fixture
   under ``fixtures/<tool>/`` with ``call.write_fixture(name, path)``, so ASH's
   parse path runs. ``call.write(path, data)`` is for content the double makes up
   and takes bytes only: a test written against an earlier harness that passed a
   fixture's name to it gets a TypeError, and switches to ``write_fixture``. Read
   a file ASH handed the double with ``call.read(path)``, or resolve a path with
   ``call.confined(path)``; both refuse anything outside the test's directory.
3. In each test, declare the tools and run the scanner::

       def test_default(char, snapshot):
           char.tool("uv", UvDouble(installed=["bandit"]))   # stand-in on PATH
           char.tool("bandit", BanditDouble(), on=None)      # reached via uv only
           char.write_source({"app.py": "assert True\\n"})
           outcome = char.run_scanner(BanditScanner, BanditScannerConfig())
           assert char.golden(outcome) == snapshot

   ``char.tool(name, double, on=...)`` is the whole declaration of an expected launch:
   it puts a stand-in executable where lookups find it (``on="path"`` is ``<BIN>``,
   ``"sysbin"`` is ``<SYSBIN>``, ``"usrlocalbin"`` is ``<USRLOCALBIN>``, ``"ashbin"``
   is ``ASH_BIN_PATH``, ``"pyenvbin"`` is ``<PYENVBIN>``, ASH's own environment,
   ``None`` makes none) and registers the double that answers
   when it is run. Anything else ASH runs fails the test. Use ``char.absent(name)``
   to state that a scenario needs a tool missing; it checks harness directories
   only, so it holds on any host. A scenario whose golden holds a time or an age
   (a content-database record, a suppression's expiry) calls ``char.fix_clock()``
   and sets its own dates relative to ``FIXED_INSTANT``; see "Pitfalls".
4. End the module with the two checks every module runs, after its last snapshot
   test (``test_bandit.py`` has them)::

       SCENARIOS = golden_scenarios(globals())

       @pytest.mark.parametrize("scenario", SCENARIOS, ids=str)
       def test_no_golden_depends_on_path_lengths_or_host_tools(tmp_path, scenario):
           check_scenario_isolation(scenario, tmp_path, tools=("<tool>", "uv"))

       def test_the_scenarios_are_the_committed_goldens(request):
           check_scenarios_match_goldens(globals(), __file__, request)

   The first reruns each scenario in memory under an 18-character and a
   96-character root and on a host that ships the tools, and requires the same
   golden text; the second
   requires the scenario list to be exactly the committed goldens and everything
   pytest collected, so neither can pass by shrinking.

A converter is driven the same way with ``char.run_converter(ConverterClass,
config)``, which mirrors ConvertPhase: construct, validate, the filter's second
validate, then ``convert()``.

Re-baselining
-------------
When the base branch moves, regenerate and review::

    pytest tests/unit/characterization -n 8 --no-cov -p no:cacheprovider --snapshot-update

Read the diff. Commit it on its own with a ``Snapshot-Update: <what and why>``
trailer. Never re-baseline inside a migration commit.

What is normalized
------------------
Only known roots, substituted where they occur at a path boundary: the test's own
directories (``<SRC>``, ``<OUT>``, ``<WORK>``, ``<HOME>``, ``<BIN>``, ``<ASHBIN>``,
``<PYENVBIN>``, ``<TMPDIR>``, ``<SYSBIN>``, ``<USRLOCALBIN>``, the XDG and uv
directories, and
``<TMP>`` for anything else under the test's tmp path, each also as resolved);
the interpreter as ``<PY>`` (``sys.executable``), ``<PYREAL>`` (that path
resolved) and ``<PYBASE>`` (``sys._base_executable``), which stay distinct because
they are different launches; ``<PYPREFIX>`` and ``<PYBASEPREFIX>``; ``<PKG>`` (the
``automated_security_helper`` package) and ``<REPO>``. A root that is the tail
of a longer path (``/var/tmp/x`` against ``/tmp/x``) is left alone. A module
whose tool writes a root without its leading ``/`` opts in with
``char.allow_root_relative(char.src)``, which records it as ``<SRC:relative>``.
No regexes and no wildcards. A pipe a launch passes in ``pass_fds`` is recorded by a
token counted per test (``<PASS_FD0>``, ``<PASS_FD1>``, ...) rather than by its
descriptor number, and an argv element that is exactly ``"<fd>:<inode>"`` for it (the
sandbox wrapper's ``--start-report``) as ``"<PASS_FD0>:<PASS_FD0_INODE>"``; a test
whose golden holds other text that quotes argv (a ``TimeoutExpired`` message) passes
it through ``char.passed_pipes_text``, which replaces those exact spellings.
One environment key is dropped: ``PYTEST_CURRENT_TEST``, which pytest
writes into ``os.environ`` at each test phase and which ASH copies into every child
environment. Keys sorted, JSON indented by two, ASCII only, which is also what the
repository's pretty-format-json hook writes.

Two encodings keep goldens short without losing anything. Each launch's
environment is stored as ``set``/``unset`` against the golden's ``parent_env`` (the
process environment at ``begin()``), which is exact. A file a double wrote with
``write_fixture`` is stored as ``{"fixture": "<tool>/<name>"}`` while its bytes are
still the fixture's; every other file is stored by its content, even one that
happens to match a fixture.

No golden may depend on how long a path is. Each test's harness lives in
``<TMPDIR>/char-<8 hex digits>`` (``short_root``), where TMPDIR is the one the run
started with (/tmp when unset), and a root longer than 96 characters is refused.
ASH cuts a failed scan's stderr excerpt at 2000 characters before anything is
normalized, so an excerpt that is exactly the scanner's own errors, which the
golden records in full under ``scanner.errors``, or exactly the tool's stderr log,
which it records in its tree, is recorded as a marker that names it
(``fold_stderr_excerpts``). A golden that still holds ASH's ``...[truncated]``
marker, or a raw ``char-<hex>`` root, is refused. ``check_scenario_isolation``
reruns every scenario under an 18-character and a 96-character root and requires
the same golden. Each session first removes ``char-<hex>`` roots that a killed run
left behind, which it tells from other directories by the marker file each root
holds (``sweep_stale_short_roots``).

Pitfalls
--------
* Call ``char.begin()`` after arranging fixture files and before driving a launcher
  directly. Files under ``<TMP>`` that exist at ``begin()`` (and everything under
  ``<SRC>``) are the test's own and are not captured from argv; ``run_scanner`` and
  ``run_converter`` call it for you. An argv path is judged where a process would open
  it: only files that land inside ``<TMP>`` are captured, and a symlink is recorded as
  a symlink, never read through. A ``..`` after a link is the parent of the link's
  target, as the kernel has it: with ``<TMP>/work/link`` leading to
  ``<TMP>/work/deep/target``, ``<TMP>/work/link/../x`` is ``<TMP>/work/deep/x``, and
  that is the file judged and recorded, not ``<TMP>/work/x``. The links are followed
  with the kernel's own answers, so a link that leads into a host directory takes no
  probe of it.
* ``tempfile`` names are made deterministic per test (``char0000``, ``char0001``, ...),
  so a temporary path ASH creates and passes is stable. ``uuid.uuid4`` is counted the
  same way (``00000000-0000-4000-8000-000000000000``, then ``...-000000000001``), but
  only when an ASH module calls it directly; a library or a test gets a real one.
* The clock runs for real unless the test calls ``char.fix_clock()``, so timestamps
  ASH writes into results files are stable. It is opt-in because some code measures
  an age against now (content-database staleness, suppression expiry).
  ``FIXED_INSTANT`` is 2026-01-01T00:00:00Z, in the past. In every ASH module that
  imported the class by name, including one first imported after the call, exactly
  four clocks read it: ``datetime.now()``, ``datetime.utcnow()``,
  ``datetime.today()`` and ``date.today()``. These stay real:

  - ``time.time()`` and ``time.monotonic()``, which timeouts depend on;
  - file mtimes;
  - a module that holds the ``datetime`` module rather than the classes.

  So a test of an age or an expiry sets its own dates relative to ``FIXED_INSTANT``,
  as in ``os.utime(path, (FIXED_INSTANT.timestamp() - age,) * 2)``, or passes ``now``
  where ASH takes it. ``datetime.fromtimestamp()`` and ``utcfromtimestamp()``
  convert as usual, except that a naive result is in UTC, like the naive ``now()``,
  so an age does not depend on the host's time zone. A timestamp later than
  ``FIXED_INSTANT`` fails the test: it can only have come from the real clock. That
  check cannot see two things. One is a real-clock date set further back than
  ``FIXED_INSTANT``. The other is an age ASH works out from raw floats without
  converting them. ``isinstance`` and ``issubclass`` against the replaced names
  answer as they do against the real classes, so a datetime that pydantic or
  ``fromisoformat`` built still passes ASH's checks.
* A SARIF invocation's ``properties`` and ``toolConfigurationNotifications`` are
  in the golden when ASH wrote them. The properties hold the content-database age
  records, so a scenario that reaches one calls ``char.fix_clock()``: a record
  measured at any time but ``FIXED_INSTANT`` is refused.
* ASH memoizes executable lookups, uv probes and content-database refreshes. The
  harness clears every cache it knows of before and after each test; register a
  new one with ``register_cache_reset``.
* Retries sleep for real unless the test calls ``char.skip_sleeps()``, which also
  counts them.
* A double writes through ``call.write_fixture(name, path)`` or
  ``call.write(path, data)``, which refuse any path outside the test's tree. Never
  copy to wherever argv says.
* ``pwd`` answers with a harness account whose home is ``<HOME>``, so a test that
  unsets HOME still cannot reach the real account's home.
* Import a module that holds a ctypes handle at collection, not inside a test: a
  ``dlopen`` during a test is refused.
* Imports at collection run before any per-test guard, so they are watched
  instead: a test module whose import starts a process, sends a signal or opens a
  socket fails to collect. A third-party module that does one of those on import
  is pre-imported in conftest, with only that effect allowed (urllib3's IPv6
  probe is the one allowed today). Add a new one there rather than importing it
  unwatched. The per-test guards allow urllib3's probe too, and nothing else of
  the kind: ASH imports detect-secrets, and through it urllib3, only when it builds
  that scanner, so urllib3's first import in a worker can come inside a test.
* ASH starting a tool through ``sys.executable`` and a wrapper the harness does not
  know (it knows ``-m``, landlock_exec and the setsid helper): teach it with
  ``char.unwrap_python(handler)``. A landlock_exec ``--start-report`` that names no
  pipe the launch passed in ``pass_fds`` fails the test.
* ``run_scanner`` validates once, as ScanPhase does, in ``plugin_probe_scope`` (phase
  ``validate``). Each launch records the sandbox scope it ran under.
* A click command built from a typer app before the test began keeps the default it
  had then; the harness patches typer's ``OptionInfo`` defaults, and the audit hook
  refuses a write to the real ASH bin directory either way.
* The harness holds every ``FakePopen`` until the test ends, so that a signal, a
  wait or a group kill on its pid still finds it after ASH drops the object. A
  ``weakref.finalize`` that ASH registers on one therefore does not fire when ASH
  lets go of it. A scenario about such cleanup calls the finalizer itself.
* A golden's tree records a FIFO as ``{"fifo": true}`` and a socket as
  ``{"socket": true}`` without opening them.
* POSIX only. The package is skipped on Windows.
"""

from __future__ import annotations

import collections
import contextlib
import ctypes
import dataclasses
import datetime as _datetime
import difflib
import enum
import errno
import hashlib
import importlib
import inspect
import io
import itertools
import json
import logging
import operator
import os
import pathlib
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import sysconfig
import tempfile
import threading
import time
import types
import urllib.parse
import uuid
import warnings
from pathlib import Path
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

import pytest
from rich.logging import RichHandler
from syrupy.extensions.single_file import SingleFileSnapshotExtension, WriteMode
from typing_extensions import Self

from automated_security_helper.core import constants as _constants
from automated_security_helper.utils import subprocess_utils as _subprocess_utils
from automated_security_helper.utils import uv_tool_runner as _uv_tool_runner

#: The real class, captured before anything is patched.
REAL_POPEN = subprocess.Popen
_POPEN_SIGNATURE = inspect.signature(REAL_POPEN.__init__)

#: How a caller that polls a hanging double is held to account. The real
#: ``communicate(timeout=t)`` blocks for ``t`` seconds; the double raises
#: ``TimeoutExpired`` at once, so a poll loop with no deadline and no cancel spins at
#: CPU speed and ``LaunchRecord.calls`` grows with every poll. Up to
#: ``HANG_POLLS_FREE`` timed-out polls on one process cost nothing (the cells that
#: step a fake clock make at most a few thousand). Past that each poll waits
#: ``HANG_POLL_WAIT_S`` for real, and past ``HANG_POLL_CAP`` the next poll is a
#: ``LaunchViolation``: the real call would never return. Read at each poll, so a
#: control cell can lower them.
HANG_POLLS_FREE = 20_000
HANG_POLL_CAP = 100_000
HANG_POLL_WAIT_S = 0.001
#: ``time.sleep`` as it was at import. ``Harness.skip_sleeps`` replaces
#: ``time.sleep`` for the rest of a test, which must not turn the wait above off.
_REAL_SLEEP = time.sleep
_POPEN_RECORDED_PARAMS = frozenset(
    {
        "args",
        "stdin",
        "stdout",
        "stderr",
        "shell",
        "cwd",
        "env",
        "universal_newlines",
        "text",
        "encoding",
        "errors",
    }
)

#: The product's lookup seam and the import-time ASH_BIN_PATH, captured before any
#: harness replaces them.
REAL_PATH_INDEPENDENT_DIRS = _subprocess_utils.path_independent_dirs
REAL_ASH_BIN_PATH = _constants.ASH_BIN_PATH
#: The product's lookups of ASH's own environment, where it has them (None where
#: it does not): the directories of the interpreter running ASH, where pip and uv
#: put the console scripts of its packages, and where the uv package ASH imports
#: is installed, from which its layout gives the uv executable's directory.
REAL_OWN_ENVIRONMENT_DIRS = getattr(_subprocess_utils, "own_environment_dirs", None)
REAL_UV_PACKAGE_DIRECTORY = getattr(_uv_tool_runner, "_uv_package_directory", None)


def _own_environment_host_dirs() -> List[str]:
    """The host directories of the interpreter running the tests that hold its
    commands: its own directory and its scripts directory."""
    dirs = [os.path.dirname(sys.executable), sysconfig.get_path("scripts")]
    return list(
        dict.fromkeys(os.path.normpath(d) for d in dirs if d and os.path.isabs(d))
    )


#: Directories whose contents differ from one host or image to the next. A probe of
#: anything inside one fails the test (see ``_probe_guard``); ``sys.executable``
#: itself is the one entry allowed.
HOST_EXEC_DIRS = frozenset(
    {
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/opt/local/bin",
        "/snap/bin",
        *_own_environment_host_dirs(),
    }
)

#: ``sys.executable`` with its symlinks resolved, read here once, before any guard is
#: armed. Resolving it later would ``lstat`` each link of a venv's chain
#: (``bin/python -> python3 -> /usr/bin/python3``), and a link in a host executable
#: directory is a probe the guards refuse.
_INTERPRETER_REAL_PATH = os.path.realpath(sys.executable)

FIXTURES_DIR = Path(__file__).with_name("fixtures")
REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGE_DIR = REPO_ROOT / "automated_security_helper"


def _interpreter_roots() -> Dict[str, str]:
    """A token for each distinct spelling of the interpreter and its prefixes.

    ``<PY>`` is ``sys.executable`` as Python spells it (a venv's ``bin/python``),
    ``<PYREAL>`` the same path with its symlinks resolved, and ``<PYBASE>``
    ``sys._base_executable``, the interpreter a venv was made from, each where it
    differs from those before it. Launching each of them is a different launch.
    ``<PYPREFIX>`` is ``sys.prefix`` and ``<PYBASEPREFIX>`` ``sys.base_prefix``
    where it differs.
    """
    roots: Dict[str, str] = {}
    for token, path in (
        ("<PY>", sys.executable),
        ("<PYREAL>", _INTERPRETER_REAL_PATH),
        ("<PYBASE>", getattr(sys, "_base_executable", None) or sys.executable),
        ("<PYPREFIX>", sys.prefix),
        ("<PYBASEPREFIX>", sys.base_prefix),
    ):
        if path and path not in roots.values():
            roots[token] = path
    return roots


#: Fake pids start above PID_MAX_LIMIT (2**22 on 64-bit Linux, the most the kernel
#: can ever hand out), so a signal that reaches a real ``kill`` by a route the
#: guards miss finds no process (ESRCH) rather than a live one.
FAKE_PID_BASE = 2**22 + 1000

#: Where a characterization test may write besides pytest's basetemp: its goldens.
SNAPSHOT_ROOT = Path(__file__).with_name("__snapshots__")

#: Dropped from every recorded environment; see "What is normalized" above.
PYTEST_ENV_KEY = "PYTEST_CURRENT_TEST"

#: Text files up to this size are recorded whole; anything larger or binary as sha256.
TEXT_LIMIT = 64 * 1024

#: The most entries recorded for one directory handed to a tool.
DIR_ENTRY_LIMIT = 200

STAND_IN_BODY = """# Characterization stand-in. The harness intercepts every launch, so this
# script running means a process really started.
echo "characterization stand-in $0 was executed" >&2
exit 97
"""

#: A stand-in naming the host's /bin/sh, for the files ``host_image`` plants. A
#: harness stand-in names ``<SYSBIN>/sh`` instead (see ``Harness.tool``).
STAND_IN_SCRIPT = "#!/bin/sh\n" + STAND_IN_BODY

#: ``Harness.tool``'s default interpreter: the ``<SYSBIN>/sh`` stand-in.
_SYSBIN_SH = object()


def stand_in_script(interpreter: Union[str, os.PathLike, None]) -> str:
    """A stand-in's text: ``#!<interpreter>`` and the body, or no ``#!`` line."""
    if interpreter is None:
        return STAND_IN_BODY
    return f"#!{os.fspath(interpreter)}\n{STAND_IN_BODY}"


# Characters that continue a file name. A root followed by one of them is a
# different path (``/tmp/test_a0`` inside ``/tmp/test_a01``), so it is not replaced.
_NAME_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-+~@"
)

#: The letters of a JSON or C escape (``\n``, ``\t``, ``\0``...). After an odd run of
#: backslashes one of them ends the text before it rather than continuing a name.
_ESCAPE_LETTERS = frozenset("nrtbf0")


def _continues_a_name(value: str, index: int) -> bool:
    """Whether ``value[index - 1]`` is part of a file name, so a path starting at
    ``index`` is the tail of a longer one. ``"a\\n/tmp/x"`` (an escaped newline, as
    JSON text read back from a tool's output holds it) starts a path at the slash."""
    if index == 0 or value[index - 1] not in _NAME_CHARS:
        return False
    if value[index - 1] in _ESCAPE_LETTERS:
        backslashes = 0
        while index - 2 - backslashes >= 0 and value[index - 2 - backslashes] == "\\":
            backslashes += 1
        if backslashes % 2 == 1:
            return False
    return True


class LaunchViolation(pytest.fail.Exception):
    """A launch, lookup or connection the test did not declare.

    A subclass of pytest's own failure outcome, so ``except Exception`` in product
    code does not swallow it. The violation is also recorded, and the package's
    autouse fixture fails the test at teardown if any were recorded, for code that
    catches ``BaseException``.
    """


# ---------------------------------------------------------------------------
# Normalization and serialization
# ---------------------------------------------------------------------------


class Normalized:
    """A value already normalized at capture time; ``Normalizer.data`` keeps it."""

    __slots__ = ("value",)

    def __init__(self, value: Any) -> None:
        self.value = value


class Normalizer:
    """Replaces known roots with tokens. Nothing else is rewritten.

    A root in ``resolved`` (every root, when it is None) is also replaced where it
    is spelled through its symlinks resolved. The others are replaced only as
    given: a venv's ``bin/python`` and the interpreter it links to are different
    launches, and must not serialize the same. ``allow_relative`` opts one root in
    to being replaced where it is spelled without its leading ``/``.
    """

    def __init__(
        self,
        roots: Mapping[str, Union[str, Path]],
        resolved: Optional[Sequence[str]] = None,
    ) -> None:
        tokens_by_spelling: Dict[str, str] = {}
        for token, root in roots.items():
            spellings = {os.fspath(root)}
            if resolved is None or token in resolved:
                spellings.add(os.path.realpath(os.fspath(root)))
            for spelling in spellings:
                if not spelling.startswith("/") or spelling == "/":
                    raise ValueError(f"root {token} must be an absolute POSIX path")
                spelling = spelling.rstrip("/")
                other = tokens_by_spelling.setdefault(spelling, token)
                if other != token:
                    raise ValueError(f"{spelling} is both {other} and {token}")
        # Longest first, so a nested root wins over the root that contains it.
        self._roots = sorted(
            tokens_by_spelling.items(), key=lambda pair: (-len(pair[0]), pair[0])
        )
        self._relative: List[Tuple[str, str]] = []

    def allow_relative(self, token: str) -> str:
        """Also replace root ``token`` where it is spelled without its leading ``/``.

        Such a spelling (``tmp/char-1a2b3c4d/src/app.py``, as some tools write a
        file's URI) becomes ``<TOKEN:relative>``, so it stays distinct from the
        absolute one. It is matched exactly, at path boundaries, and never right
        after a ``/``, where it would be the tail of some longer absolute path.
        Returns the token used.
        """
        spellings = [s for s, t in self._roots if t == token]
        if not spellings:
            raise ValueError(f"{token} is not a root of this normalizer")
        relative = f"{token[:-1]}:relative>"
        for spelling in spellings:
            bare = spelling.lstrip("/")
            # A URI quotes the root too: a "+" or "@" in it becomes %2B or %40.
            for form in (bare, urllib.parse.quote(bare)):
                if (form, relative) not in self._relative:
                    self._relative.append((form, relative))
        self._relative.sort(key=lambda pair: (-len(pair[0]), pair[0]))
        return relative

    def text(self, value: str) -> str:
        if "/" not in value:
            return value
        value = self._absolute(value)
        return self._root_relative(value) if self._relative else value

    def _root_relative(self, value: str) -> str:
        out: List[str] = []
        start = index = 0
        while index < len(value):
            if index and (value[index - 1] == "/" or _continues_a_name(value, index)):
                index += 1
                continue
            for spelling, token in self._relative:
                end = index + len(spelling)
                if value.startswith(spelling, index) and (
                    end == len(value) or value[end] not in _NAME_CHARS
                ):
                    out.append(value[start:index])
                    out.append(token)
                    start = index = end
                    break
            else:
                index += 1
        out.append(value[start:])
        return "".join(out)

    def _absolute(self, value: str) -> str:
        out: List[str] = []
        start = search = 0
        while True:
            slash = value.find("/", search)
            if slash < 0:
                break
            if _continues_a_name(value, slash):
                # The tail of a longer path (/var/tmp/x is not /tmp/x).
                search = slash + 1
                continue
            for root, token in self._roots:
                if value.startswith(root, slash):
                    end = slash + len(root)
                    if end == len(value) or value[end] not in _NAME_CHARS:
                        out.append(value[start:slash])
                        out.append(token)
                        start = search = end
                        break
            else:
                search = slash + 1
        out.append(value[start:])
        return "".join(out)

    def data(self, obj: Any) -> Any:
        if isinstance(obj, Normalized):
            return obj.value
        if isinstance(obj, str):
            return self.text(obj)
        if obj is None or isinstance(obj, (bool, int, float)):
            return obj
        if isinstance(obj, os.PathLike):
            return self.text(os.fspath(obj))
        if isinstance(obj, enum.Enum):
            return self.data(obj.value)
        if isinstance(obj, Mapping):
            result: Dict[str, Any] = {}
            for key, value in obj.items():
                if not isinstance(key, (str, os.PathLike)):
                    raise TypeError(f"golden keys must be strings, got {key!r}")
                normalized_key = self.text(os.fspath(key))
                if normalized_key in result:
                    # Two raw keys becoming one would erase a difference.
                    raise ValueError(f"two keys normalize to {normalized_key!r}")
                result[normalized_key] = self.data(value)
            return result
        if isinstance(obj, (list, tuple)):
            return [self.data(item) for item in obj]
        raise TypeError(
            f"cannot put a {type(obj).__name__} in a golden; convert it first: {obj!r}"
        )


#: ``base/scanner_plugin``'s stderr excerpt: cut at ``_STDERR_EXCERPT_LIMIT`` raw
#: characters, before any normalization, with this marker appended. Restated here,
#: not imported, so a change to either changes a golden.
STDERR_EXCERPT_LIMIT = 2000
TRUNCATION_MARKER = " ...[truncated]"
_STDERR_LEAD = ". Stderr: "


def stderr_excerpt_marker(count: int) -> str:
    """What a stderr excerpt that is exactly the scanner's first ``count`` errors is
    recorded as."""
    return (
        f"<scanner.errors[:{count}] joined by newlines, cut at 2000 characters when "
        "longer>"
    )


#: A ``short_root`` directory name, wherever it appears.
_RAW_SHORT_ROOT = re.compile(r"(?<![0-9A-Za-z])char-[0-9a-f]{8}(?![0-9A-Za-z])")


def serialize(normalizer: Normalizer, data: Any) -> str:
    """The golden text for ``data``: normalized, sorted keys, indent 2, ASCII.

    Refuses text that holds ASH's truncation marker: the cut was made before
    normalization, so what survived depends on how long the test's paths are, and
    a host path cut in half is not normalized at all. Also refuses a harness root
    (``.../char-<8 hex digits>``) that survived normalization.
    """
    text = (
        json.dumps(normalizer.data(data), indent=2, sort_keys=True, ensure_ascii=True)
        + "\n"
    )
    leaked = _RAW_SHORT_ROOT.search(text)
    if leaked:
        raise AssertionError(
            f"a golden holds the harness root {leaked.group(0)!r} raw: the normalizer "
            "did not recognize this spelling of it"
        )
    if TRUNCATION_MARKER.strip() in text:
        raise AssertionError(
            f"a golden holds ASH's {TRUNCATION_MARKER.strip()!r} marker. The text was "
            "cut before normalization, so the golden would depend on path lengths; "
            "shorten the scenario's output, or collapse the excerpt as "
            "fold_stderr_excerpts does"
        )
    return text


def _excerpt(text: str) -> str:
    """``text`` cut the way ``_describe_scan_failure`` cuts its excerpt."""
    if len(text) > STDERR_EXCERPT_LIMIT:
        return text[:STDERR_EXCERPT_LIMIT] + TRUNCATION_MARKER
    return text


def fold_stderr_excerpts(
    outcome: Dict[str, Any], logs: Optional[Mapping[str, str]] = None
) -> Dict[str, Any]:
    """Record each failed-scan stderr excerpt that the golden holds in full
    elsewhere as a fixed marker.

    ``_describe_scan_failure`` ends its message with ``. Stderr: `` and either the
    scanner's errors so far, joined by newlines, or, when there are none, the
    stripped text of the tool's ``<Scanner>.stderr.log``, cut at 2000 raw
    characters either way. The golden records the errors under ``scanner.errors``
    and the log in its tree, so an excerpt that is exactly one of them cut that way
    carries nothing more than which one it is. An excerpt of the first k errors
    becomes ``stderr_excerpt_marker(k)``, which keeps k: the executor appends errors
    after the message is built, so any prefix can match, and a message that quoted
    fewer errors must not read the same. A log's excerpt becomes ``<the stripped
    text of PATH, cut at 2000 characters when longer>``. Either is replaced by its
    marker whether or not it was cut, because whether it was cut depends on path
    lengths.

    A cut excerpt is the same text for every k from the first whose join passes the
    limit, so it is recorded with the largest such k. That is the k an uncut
    excerpt of the same scenario gets when every error was quoted, so a shorter
    root does not change the golden. It also means a cut excerpt cannot show that
    a later error was left out. ``logs`` maps each log's path to its text. Any
    other excerpt is left as it is, and ``serialize`` refuses one that still ends in
    the cut's marker.
    """
    errors = [str(error) for error in outcome["scanner"]["errors"]]
    markers: Dict[str, str] = {}
    for count in range(1, len(errors) + 1):
        joined = "\n".join(errors[:count]).strip()
        if joined:
            # Counts are ascending, so the largest one that gives this text wins.
            markers[_STDERR_LEAD + _excerpt(joined)] = stderr_excerpt_marker(count)
    for path, text in sorted((logs or {}).items()):
        if text.strip():
            markers.setdefault(
                _STDERR_LEAD + _excerpt(text.strip()),
                f"<the stripped text of {path}, cut at 2000 characters when longer>",
            )
    by_length = sorted(markers, key=len, reverse=True)

    def collapse(value: Any, path: Tuple[str, ...]) -> Any:
        if path == ("scanner", "errors"):
            return value
        if isinstance(value, str):
            for excerpt in by_length:
                if value.endswith(excerpt):
                    return value[: -len(excerpt)] + _STDERR_LEAD + markers[excerpt]
            return value
        if isinstance(value, dict):
            return {
                key: collapse(item, (*path, str(key))) for key, item in value.items()
            }
        if isinstance(value, list):
            return [collapse(item, path) for item in value]
        return value

    return collapse(outcome, ())


class CharacterizationJSONExtension(SingleFileSnapshotExtension):
    """One JSON golden per test, so a change diffs line by line."""

    _write_mode = WriteMode.TEXT
    file_extension = "json"
    normalizer: ClassVar[Normalizer]

    def serialize(self, data: Any, **kwargs: Any) -> str:
        return serialize(self.normalizer, data)


def _special_file(path: Path) -> Optional[str]:
    """``"fifo"`` or ``"socket"`` for a file a golden's tree must not open: reading
    a FIFO blocks until something writes to it, and a socket cannot be read."""
    import stat as _stat

    mode = path.lstat().st_mode
    if _stat.S_ISFIFO(mode):
        return "fifo"
    if _stat.S_ISSOCK(mode):
        return "socket"
    return None


def _content(data: bytes, normalizer: Normalizer) -> Dict[str, Any]:
    """A file's content for a golden.

    UTF-8 text up to ``TEXT_LIMIT`` is recorded line by line, normalized, and
    anything else as the sha256 and size of its normalized text or raw bytes.
    ``Harness._file_content`` records a fixture a double wrote by its name.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    text = normalizer.text(text)
    if len(data) > TEXT_LIMIT:
        encoded = text.encode("utf-8")
        return {"sha256": hashlib.sha256(encoded).hexdigest(), "size": len(encoded)}
    return {"text": text.splitlines(keepends=True)}


# ---------------------------------------------------------------------------
# Tool doubles
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Exit:
    """The tool ran and exited with ``returncode``.

    Until something waits for it, it is in the state a real child is in once it has
    exited: ``os.waitid`` with ``WNOWAIT`` reports the exit and changes nothing, and
    the Popen's own ``communicate``, ``wait``, ``poll``, ``kill``, ``terminate``,
    ``send_signal`` or ``__exit__`` sets ``returncode``. A reap from outside the Popen
    leaves ``returncode`` None, as for a ``Hang`` that leaves a zombie.
    """

    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


@dataclasses.dataclass(frozen=True)
class Hang:
    """The tool never exits on its own; only a timeout ends the wait.

    ``stdout``/``stderr`` are what it printed before the caller gave up. It exits on
    SIGTERM unless ``ignores_sigterm``, and always on SIGKILL.

    By default the signal that ends it also sets the fake's ``returncode`` at once, as
    if the exit had been waited for. With ``leaves_zombie`` the exit is the one a real
    child has: the process has exited and nobody has waited for it, so ``returncode``
    stays None, ``os.waitid`` with ``WNOWAIT`` reports the exit without reaping it, a
    later signal to its group still reaches it, and the first ``communicate``,
    ``wait``, ``poll``, ``kill``, ``terminate``, ``send_signal`` or ``__exit__`` reaps
    it and sets the code (``kill``, ``terminate`` and ``send_signal`` poll first, as
    CPython's do, and send nothing to a child that has exited). An outside
    ``os.waitpid``, or ``os.waitid`` without ``WNOWAIT``, also reaps it but leaves
    ``returncode`` None, as in CPython, which is not told of it (bpo-15756): the next
    of those calls that waits meets ECHILD and records 0, never the real code. This
    is a state of the stand-in: no real process or signal is involved.
    """

    stdout: str = ""
    stderr: str = ""
    ignores_sigterm: bool = False
    leaves_zombie: bool = False


Outcome = Union[Exit, Hang]


@dataclasses.dataclass
class ToolCall:
    """One launch as a double sees it, after the wrappers ASH uses are unwrapped."""

    tool: str
    args: List[str]
    via: Tuple[str, ...]
    argv: List[str]
    env: Optional[Dict[str, str]]
    cwd: Optional[str]
    harness: "Harness"
    record: Optional["LaunchRecord"] = None

    def reject(self, reason: str) -> "LaunchViolation":
        """The exception to raise for an argv the double does not understand."""
        return _GUARDS.violation(
            f"{self.tool} double does not understand this launch ({reason}): "
            f"{self.argv}"
        )

    def dispatch(self, tool: str, args: Sequence[str], via: str) -> Outcome:
        """Run the double registered for ``tool``, as a wrapper does."""
        return self.harness._run_double(
            ToolCall(
                tool=tool,
                args=list(args),
                via=self.via + (via,),
                argv=self.argv,
                env=self.env,
                cwd=self.cwd,
                harness=self.harness,
                record=self.record,
            )
        )

    def exec(self, argv: Sequence[str], via: str) -> Outcome:
        """Resolve and run ``argv`` the way exec would, as a sandbox wrapper does."""
        return self.harness._exec(
            list(argv), self.env, self.cwd, self.via + (via,), self.record
        )

    def write(self, path: Union[str, os.PathLike], data: bytes) -> Path:
        """Write ``data`` where the tool would, as its argv says, in the test's tree.

        A path outside the test's tmp tree, after symlinks are resolved, is a
        violation: a double must never write where a mistaken or hostile argv
        points. Relative paths are taken from the launch's cwd. The file is
        recorded by its content; ``write_fixture`` writes a committed fixture.
        """
        if not isinstance(data, bytes):
            raise TypeError(
                "ToolCall.write() takes bytes; write a committed fixture with "
                "write_fixture(name, path)"
            )
        target = self._resolve(path)
        if not self.harness._confined(target):
            raise _GUARDS.violation(
                f"the {self.tool} double was told to write {target}, outside the "
                f"test's directory: {self.argv}"
            )
        target.write_bytes(data)
        return target

    def _resolve(self, path: Union[str, os.PathLike]) -> Path:
        target = Path(path)
        return (
            target if target.is_absolute() else Path(self.cwd or os.getcwd()) / target
        )

    def confined(self, path: Union[str, os.PathLike]) -> Path:
        """``path`` as the tool would resolve it, if it is in the test's tree.

        Relative paths are taken from the launch's cwd. Anything outside the
        test's tree, after symlinks are resolved, is a violation, so a double must
        pass every argv path through this before it reads, walks or even
        ``is_dir()``s it: an argv that names a host file must never get that
        file's content into a golden.
        """
        target = self._resolve(path)
        if not self.harness._confined(target):
            raise _GUARDS.violation(
                f"the {self.tool} double was handed {target}, outside the test's "
                f"directory: {self.argv}"
            )
        return target

    def read(self, path: Union[str, os.PathLike]) -> bytes:
        """The bytes of ``path`` (see ``confined``), as the tool would read them."""
        return self.confined(path).read_bytes()

    def write_fixture(self, name: str, path: Union[str, os.PathLike]) -> Path:
        """Copy the committed ``fixtures/<name>`` to ``path``, as ``write`` does.

        A golden records the file as ``{"fixture": name}`` for as long as its bytes
        are the fixture's. Only a file written this way is recorded so: a file that
        merely has the same bytes as some fixture is recorded by its content.
        """
        source = (FIXTURES_DIR / name).resolve()
        if not source.is_relative_to(FIXTURES_DIR.resolve()) or not source.is_file():
            raise ValueError(f"{name!r} is not a file under {FIXTURES_DIR}")
        data = source.read_bytes()
        target = self.write(path, data)
        self.harness._fixture_writes[os.path.realpath(target)] = (
            name,
            hashlib.sha256(data).hexdigest(),
        )
        return target


class ToolDouble:
    """Answers for one tool. Subclasses implement ``run``.

    ``run`` returns :class:`Exit` or :class:`Hang` and writes whatever files the
    tool would write. It must raise ``call.reject(...)`` for any argv it does not
    understand rather than guess.
    """

    def run(self, call: ToolCall) -> Outcome:
        raise NotImplementedError

    def __call__(self, call: ToolCall) -> Outcome:
        return self.run(call)


@dataclasses.dataclass
class ParsedArgv:
    flags: Dict[str, List[Optional[str]]]
    positionals: List[str]

    def last(self, flag: str) -> Optional[str]:
        values = self.flags.get(flag)
        return values[-1] if values else None

    def has(self, flag: str) -> bool:
        return flag in self.flags


@dataclasses.dataclass(frozen=True)
class ArgvGrammar:
    """A strict description of the argv a tool accepts.

    ``value_flags`` take the next element; ``bool_flags`` take none; ``glued_flags``
    are accepted only as ``--flag=value``. Anything else that starts with ``-`` is
    rejected, and so is a positional count outside the bounds.
    """

    value_flags: frozenset = frozenset()
    bool_flags: frozenset = frozenset()
    glued_flags: frozenset = frozenset()
    min_positionals: int = 0
    max_positionals: Optional[int] = None

    def parse(self, call: ToolCall, args: Optional[Sequence[str]] = None) -> ParsedArgv:
        args = list(call.args if args is None else args)
        flags: Dict[str, List[Optional[str]]] = {}
        positionals: List[str] = []
        index = 0
        while index < len(args):
            element = args[index]
            if element.startswith("-") and element != "-":
                name, glued, value = element.partition("=")
                if glued and name in self.glued_flags:
                    flags.setdefault(name, []).append(value)
                elif not glued and element in self.value_flags:
                    if index + 1 >= len(args):
                        raise call.reject(f"{element} needs a value")
                    index += 1
                    flags.setdefault(element, []).append(args[index])
                elif not glued and element in self.bool_flags:
                    flags.setdefault(element, []).append(None)
                else:
                    raise call.reject(f"unknown flag {element!r}")
            else:
                positionals.append(element)
            index += 1
        if len(positionals) < self.min_positionals or (
            self.max_positionals is not None and len(positionals) > self.max_positionals
        ):
            raise call.reject(f"unexpected positionals {positionals}")
        return ParsedArgv(flags, positionals)


class UvDouble(ToolDouble):
    """``uv`` as ASH drives it.

    ``installed`` is what ``uv tool list`` reports; an ``install`` that exits 0 adds
    the package to it, as a real install would. ``uv tool run`` hands the inner tool
    to its own double unless ``tool_run`` is set, which stands for uv failing before
    the tool starts (a resolve failure, for example). ``uv tool run --offline`` of a
    package that is neither installed nor in ``cached`` fails to resolve, as uv
    does with nothing to resolve it from. ``install``, ``version`` and
    ``tool_list`` are the outcomes of ``uv tool install``, ``uv --version`` and (in
    place of the listing) ``uv tool list``. ``dry_run`` is the outcome of
    ``uv pip install --dry-run``: one for every requirement, or a mapping from
    requirement to outcome, where a requirement it does not name is rejected.
    """

    _TOOL_INSTALL = ArgvGrammar(
        value_flags=frozenset({"--with"}),
        bool_flags=frozenset({"--offline"}),
        min_positionals=1,
        max_positionals=1,
    )
    _DRY_RUN = ArgvGrammar(
        value_flags=frozenset({"--python", "--target"}),
        bool_flags=frozenset(
            {"--dry-run", "--offline", "--no-cache", "--no-config", "--no-deps"}
        ),
        min_positionals=1,
        max_positionals=1,
    )

    def __init__(
        self,
        installed: Sequence[str] = (),
        *,
        tool_run: Optional[Outcome] = None,
        install: Outcome = Exit(0, stderr="Installed 1 executable\n"),
        dry_run: Union[Outcome, Mapping[str, Outcome]] = Exit(
            0, stderr="Would make no changes\n"
        ),
        version: Outcome = Exit(0, stdout="uv 0.9.5\n"),
        tool_list: Optional[Outcome] = None,
        cached: Sequence[str] = (),
    ) -> None:
        self.installed = list(installed)
        self.tool_run = tool_run
        self.install = install
        self.dry_run = dry_run
        self.version = version
        self.tool_list = tool_list
        self.cached = list(cached)

    @staticmethod
    def _package(spec: str) -> str:
        """The package a requirement names: ``bandit[sarif]>=1.7`` is ``bandit``."""
        for index, char in enumerate(spec):
            if char in "[]<>=!~;, ":
                return spec[:index]
        return spec

    def run(self, call: ToolCall) -> Outcome:
        args = call.args
        if args == ["--version"]:
            return self.version
        if args == ["tool", "list"] and self.tool_list is not None:
            return self.tool_list
        if args == ["tool", "list"]:
            if not self.installed:
                return Exit(0, stderr="No tools installed\n")
            return Exit(
                0,
                stdout="".join(f"{t} v1.0.0\n- {t}\n" for t in self.installed),
            )
        if args == ["cache", "dir"]:
            return Exit(0, stdout=f"{(call.env or os.environ)['UV_CACHE_DIR']}\n")
        if args == ["cache", "clean"]:
            return Exit(0)
        if args[:2] == ["tool", "install"]:
            parsed = self._TOOL_INSTALL.parse(call, args[2:])
            if isinstance(self.install, Exit) and self.install.returncode == 0:
                name = self._package(parsed.positionals[0])
                if name not in self.installed:
                    self.installed.append(name)
            return self.install
        if args[:2] == ["pip", "install"]:
            parsed = self._DRY_RUN.parse(call, args[2:])
            if not parsed.has("--dry-run") or not parsed.has("--python"):
                raise call.reject("only dry runs against a named interpreter")
            if not isinstance(self.dry_run, Mapping):
                return self.dry_run
            requirement = parsed.positionals[0]
            if requirement not in self.dry_run:
                raise call.reject(f"no dry-run outcome for {requirement!r}")
            return self.dry_run[requirement]
        if args[:2] == ["tool", "run"]:
            return self._tool_run(call, args[2:])
        raise call.reject("not a uv command ASH uses")

    def _tool_run(self, call: ToolCall, args: List[str]) -> Outcome:
        index = 0
        options: List[str] = []
        while index < len(args) and args[index].startswith("-"):
            if args[index] == "--offline":
                options.append("--offline")
                index += 1
            elif args[index] == "--quiet":
                # A flag without a value; it changes nothing the double records.
                index += 1
            elif args[index] == "--from" and index + 1 < len(args):
                if "--from" in options:
                    raise call.reject("two --from options")
                options.extend(args[index : index + 2])
                index += 2
            else:
                raise call.reject(f"unknown uv tool run option {args[index]!r}")
        if index >= len(args):
            raise call.reject("uv tool run without a tool")
        if self.tool_run is not None:
            return self.tool_run
        source = options[options.index("--from") + 1] if "--from" in options else None
        package = self._package(source or args[index])
        if "--offline" in options and package not in self.installed + self.cached:
            return Exit(
                1,
                stderr="  x No solution found when resolving tool dependencies:\n"
                f"  `-> Because {package} was not found in the cache and you require "
                f"{package}, we can conclude that your requirements are "
                "unsatisfiable.\n",
            )
        return call.dispatch(
            args[index], args[index + 1 :], " ".join(["uv tool run", *options])
        )


class SandboxWrapperDouble(ToolDouble):
    """A sandbox wrapper (bwrap, firejail) that runs everything after ``--``."""

    def run(self, call: ToolCall) -> Outcome:
        if "--" not in call.args:
            raise call.reject("a wrapper launch without --")
        inner = call.args[call.args.index("--") + 1 :]
        if not inner:
            raise call.reject("nothing after --")
        return call.exec(inner, call.tool)


# ---------------------------------------------------------------------------
# The fake Popen
# ---------------------------------------------------------------------------


def _disposition(value: Any) -> str:
    if value is None:
        return "inherit"
    if value == subprocess.PIPE:
        return "PIPE"
    if value == subprocess.STDOUT:
        return "STDOUT"
    if value == subprocess.DEVNULL:
        return "DEVNULL"
    if isinstance(value, int):
        # 0-2 by number; any other descriptor by what it is open on, because its
        # number depends on what else the worker has open.
        if value in (0, 1, 2):
            return f"fd:{value}"
        # A pipe or a socket by its type, which fstat gives on every POSIX host;
        # there is no /proc on macOS, and F_GETPATH names only files.
        import stat as _stat

        try:
            mode = os.fstat(value).st_mode
        except OSError:
            return "fd"
        if _stat.S_ISFIFO(mode):
            return "fd:pipe"
        if _stat.S_ISSOCK(mode):
            return "fd:socket"
        target = _fd_path(value)
        if target is None:
            return "fd"
        return f"fd:{target if target.startswith('/') else target.split(':')[0]}"
    name = getattr(value, "name", None)
    return f"file:{name}" if isinstance(name, str) else "file"


def _option_value(value: Any) -> Any:
    if callable(value):
        return "<callable>"
    if isinstance(value, (list, tuple, set, frozenset)):
        return sorted(value) if isinstance(value, (set, frozenset)) else list(value)
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return repr(value)


@dataclasses.dataclass
class LaunchRecord:
    """One launch, raw. ``as_golden`` turns it into the golden's shape."""

    index: int
    phase: Optional[str]
    api: str
    argv: List[str]
    argv_type: str
    shell: bool = False
    cwd: Optional[str] = None
    #: The child's environment: the one passed, or for ``env=None`` the process
    #: environment at launch time, with ``env_inherited`` set.
    env: Optional[Dict[str, str]] = None
    env_inherited: bool = False
    stdin: str = "inherit"
    stdout: str = "inherit"
    stderr: str = "inherit"
    text: bool = False
    encoding: Optional[str] = None
    errors: Optional[str] = None
    options: Dict[str, Any] = dataclasses.field(default_factory=dict)
    files: Dict[str, Any] = dataclasses.field(default_factory=dict)
    calls: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    executable: Optional[str] = None
    dispatch: Optional[Dict[str, Any]] = None
    outcome: Optional[Dict[str, Any]] = None
    #: The sandbox scope active for the launch (``sandbox.scope.active_scope()``),
    #: by type name, or None outside any.
    scope: Optional[str] = None
    #: Each pipe the launch passed in ``pass_fds``, as ``"<fd>:<inode>"``: what the
    #: sandbox wrapper's ``--start-report`` may name. Not in the golden.
    passed_pipes: frozenset = frozenset()

    def as_golden(self, parent_env: Mapping[str, str]) -> Dict[str, Any]:
        """The golden shape, with the environment as an exact diff from ``parent_env``.

        ``env`` is ``{"set": {...}, "unset": [...]}`` relative to the golden's
        ``parent_env``, so ``parent_env`` minus ``unset`` plus ``set`` is the
        child's environment, key for key. For ``env=None`` it is
        ``{"inherit": {"set": ..., "unset": ...}}``: the same diff, of the process
        environment the child inherited when it was launched.
        """
        env: Optional[Dict[str, Any]] = None
        if self.env is not None:
            passed = {k: v for k, v in self.env.items() if k != PYTEST_ENV_KEY}
            env = {
                "set": {k: v for k, v in passed.items() if parent_env.get(k) != v},
                "unset": sorted(k for k in parent_env if k not in passed),
            }
            if self.env_inherited:
                env = {"inherit": env}
        golden = {
            "api": self.api,
            "phase": self.phase,
            "argv": self.argv,
            "argv_type": self.argv_type,
            "shell": self.shell,
            "cwd": self.cwd,
            "env": env,
            "stdio": {
                "stdin": self.stdin,
                "stdout": self.stdout,
                "stderr": self.stderr,
            },
            "text": self.text,
            "encoding": self.encoding,
            "errors": self.errors,
            "options": self.options,
            "files": self.files,
            "calls": self.calls,
            "executable": self.executable,
            "dispatch": self.dispatch,
            "scope": self.scope,
            "outcome": self.outcome,
        }
        return golden


class FakePopen:
    """Stands in for ``subprocess.Popen`` while the guards are installed.

    Resolves the executable as exec would (PATH from the ``env`` passed, else the
    process environment), raises the OSError a real spawn would raise for a missing
    or non-executable file or working directory, and otherwise hands the launch to
    the double registered for the stand-in it resolved to. Records the launch, and
    every ``communicate``/``wait``/``kill``/``terminate``/``send_signal`` call with
    its timeout.
    """

    __class_getitem__ = classmethod(types.GenericAlias)

    def __new__(cls, *args: Any, **kwargs: Any) -> Any:
        if not _GUARDS.installed:
            # A module that bound this class while the guards were up keeps it after
            # they come down; outside a characterization test it is the real thing.
            return REAL_POPEN(*args, **kwargs)
        return super().__new__(cls)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        bound = _POPEN_SIGNATURE.bind(None, *args, **kwargs)
        bound.apply_defaults()
        params = dict(bound.arguments)
        params.pop("self")
        harness = _GUARDS.harness
        raw_args = params["args"]
        self.args = raw_args
        self.pid = 0
        self.returncode: Optional[int] = None
        self.stdin: Any = None
        self.stdout: Any = None
        self.stderr: Any = None
        self._outcome: Optional[Outcome] = None
        self._alive = False
        self._reaped = False
        #: The code of a child that has exited and has not been waited for (a zombie),
        #: set by a signal to a ``Hang(leaves_zombie=True)`` and by looking at an ``Exit``
        #: double with ``os.waitid`` and ``WNOWAIT``; None otherwise.
        self._unreaped_code: Optional[int] = None
        #: Timed-out polls (communicate or wait with a timeout) of this hanging double.
        self._hang_polls = 0
        # The process group a real child would be in: its own when it starts a
        # session or asks for group 0, the one it names, or (None) the parent's.
        self._session_leader = bool(params["start_new_session"])
        group = params.get("process_group")  # Python 3.11 and later
        self._group: Optional[int] = None
        self._text = bool(
            params["text"]
            or params["universal_newlines"]
            or params["encoding"]
            or params["errors"]
        )
        self._encoding = params["encoding"] or "utf-8"
        if isinstance(raw_args, (str, bytes, os.PathLike)):
            argv = [os.fsdecode(raw_args)]
            argv_type = "str"
        else:
            argv = [os.fsdecode(a) for a in raw_args]
            argv_type = type(raw_args).__name__
        env = params["env"]
        recorded_env = {
            os.fsdecode(k): os.fsdecode(v)
            for k, v in (os.environ if env is None else env).items()
        }
        cwd = os.fsdecode(params["cwd"]) if params["cwd"] is not None else None
        options = {}
        for name, parameter in _POPEN_SIGNATURE.parameters.items():
            if name == "self" or name in _POPEN_RECORDED_PARAMS:
                continue
            value = params[name]
            if value is not parameter.default and value != parameter.default:
                options[name] = _option_value(value)
        if harness is None:
            raise _GUARDS.violation(
                f"subprocess.Popen({argv}) outside a characterization harness; "
                "request the `char` fixture"
            )
        recorded_argv = argv
        passed_pipes: Dict[str, str] = {}
        if params["pass_fds"]:
            options["pass_fds"], passed_pipes = harness._passed_descriptors(
                params["pass_fds"]
            )
            recorded_argv = [passed_pipes.get(element, element) for element in argv]
        record = harness._new_record(
            "subprocess.Popen",
            recorded_argv,
            passed_pipes=frozenset(passed_pipes),
            argv_type=argv_type,
            shell=bool(params["shell"]),
            cwd=cwd,
            env=recorded_env,
            env_inherited=env is None,
            stdin=_disposition(params["stdin"]),
            stdout=_disposition(params["stdout"]),
            stderr=_disposition(params["stderr"]),
            text=self._text,
            encoding=params["encoding"],
            errors=params["errors"],
            options=options,
        )
        self._record = record
        self.pid = FAKE_PID_BASE + record.index
        if self._session_leader or group == 0:
            self._group = self.pid
        elif group is not None and group > 0:
            self._group = group
        record.files = harness._capture_argv_files(argv, cwd)
        exec_argv = ["/bin/sh", "-c", *argv] if params["shell"] else list(argv)
        executable = params["executable"]
        if executable is not None:
            exec_argv = [os.fsdecode(executable), *exec_argv[1:]]
        try:
            outcome = harness._exec(
                exec_argv, None if env is None else dict(env), cwd, (), record
            )
        except OSError as error:
            record.outcome = {
                "spawn_error": harness.normalizer.text(
                    f"{type(error).__name__}: {error}"
                )
            }
            raise
        self._outcome = outcome
        self._alive = True
        harness._processes[self.pid] = self
        if isinstance(outcome, Hang):
            record.outcome = {"hang": {"ignores_sigterm": outcome.ignores_sigterm}}
        else:
            record.outcome = {"returncode": outcome.returncode}
        stdout_text, stderr_text = outcome.stdout, outcome.stderr
        if params["stderr"] == subprocess.STDOUT:
            stdout_text, stderr_text = stdout_text + stderr_text, ""
        if params["stdout"] == subprocess.PIPE:
            self.stdout = self._stream(stdout_text)
        if params["stderr"] == subprocess.PIPE:
            self.stderr = self._stream(stderr_text)
        if params["stdin"] == subprocess.PIPE:
            self.stdin = io.StringIO() if self._text else io.BytesIO()

    def _stream(self, text: str) -> Any:
        return io.StringIO(text) if self._text else io.BytesIO(text.encode("utf-8"))

    def _call(self, name: str, **arguments: Any) -> None:
        self._record.calls.append({name: arguments})

    def _hanging(self) -> bool:
        return self._alive and isinstance(self._outcome, Hang)

    def _finish(self) -> None:
        if self._alive and isinstance(self._outcome, Exit):
            self.returncode = self._outcome.returncode
            self._alive = False

    def _collect(self) -> None:
        """Reap the process if it has exited, as a returning wait or poll does.

        Every Popen call that waits for the child comes here, because CPython's all
        do: ``poll`` and ``wait`` directly, ``communicate`` and ``__exit__`` through
        ``wait``, and ``kill``, ``terminate`` and ``send_signal`` through ``poll``. A
        child that something else reaped (``_reap_outside``) gives that wait ECHILD,
        and CPython records 0 for it, the real code being gone (bpo-15756)."""
        self._finish()
        if not self._alive:
            self._reaped = True
            if self._unreaped_code is not None:
                self.returncode, self._unreaped_code = self._unreaped_code, None
            elif self.returncode is None:
                self.returncode = 0

    def _exit_code(self) -> int:
        """The code of an exited child, read or not yet read (a zombie's)."""
        if self._unreaped_code is not None:
            return self._unreaped_code
        return self.returncode or 0

    def _exit_unreaped(self) -> None:
        """Put an ``Exit`` double in the state of a child that has exited and that
        nothing has waited for: not running, its code not yet read, ``returncode``
        None. That is the state a signal leaves a ``Hang`` that leaves a zombie in, and
        the one ``os.waitid`` with ``WNOWAIT`` finds a real child in; looking at the
        child that way does not wait for it, so it must not set ``returncode``."""
        if self._alive and isinstance(self._outcome, Exit):
            self._unreaped_code = self._outcome.returncode
            self._alive = False

    def _reap_outside(self) -> int:
        """What ``os.waitpid`` and ``os.waitid`` without ``WNOWAIT`` do to this child,
        for the harness's guarded calls.

        It reaps the child and answers its code, and does not write ``returncode``: a
        real reap from outside the Popen does not update it (bpo-15756), and the Popen's
        next wait of any kind finds nothing to wait for and records 0 (``_collect``).
        The child has exited: it is a zombie, or an ``Exit`` double nothing has
        collected yet."""
        self._exit_unreaped()
        code = self._exit_code()
        self._alive = False
        self._reaped = True
        self._unreaped_code = None
        return code

    def _partial(self, text: str, disposition: Any) -> Optional[bytes]:
        if disposition is None or not text:
            return None
        return text.encode("utf-8")

    def _poll_timed_out(self, call: str, timeout: float) -> None:
        """Count a timed-out poll of the hanging double, wait for real once the
        count passes ``HANG_POLLS_FREE``, and refuse the poll past ``HANG_POLL_CAP``."""
        self._hang_polls += 1
        if self._hang_polls > HANG_POLL_CAP:
            raise _GUARDS.violation(
                f"{call}() polled {self._record.argv}, whose double hangs, "
                f"{self._hang_polls - 1} times and nothing ended it: the real call "
                "would never return"
            )
        if self._hang_polls > HANG_POLLS_FREE:
            _REAL_SLEEP(min(HANG_POLL_WAIT_S, max(timeout, 0.0)))

    def communicate(
        self,
        input: Any = None,  # noqa: A002 - Popen.communicate's own parameter name
        timeout: Optional[float] = None,
    ) -> Tuple[Any, Any]:
        arguments: Dict[str, Any] = {"timeout": timeout}
        if input is not None:
            arguments["input"] = (
                input
                if isinstance(input, str)
                else {"sha256": hashlib.sha256(input).hexdigest()}
            )
        self._call("communicate", **arguments)
        if self._hanging():
            if timeout is None:
                raise _GUARDS.violation(
                    f"communicate() without a timeout on {self._record.argv}, whose "
                    "double hangs: the real call would never return"
                )
            assert isinstance(self._outcome, Hang)
            self._poll_timed_out("communicate", timeout)
            raise subprocess.TimeoutExpired(
                self.args,
                timeout,
                output=self._partial(self._outcome.stdout, self.stdout),
                stderr=self._partial(self._outcome.stderr, self.stderr),
            )
        out = self.stdout.read() if self.stdout is not None else None
        err = self.stderr.read() if self.stderr is not None else None
        self._collect()
        return out, err

    def wait(self, timeout: Optional[float] = None) -> int:
        self._call("wait", timeout=timeout)
        if self._hanging():
            if timeout is None:
                raise _GUARDS.violation(
                    f"wait() without a timeout on {self._record.argv}, whose double "
                    "hangs: the real call would never return"
                )
            self._poll_timed_out("wait", timeout)
            raise subprocess.TimeoutExpired(self.args, timeout)
        self._collect()
        assert self.returncode is not None
        return self.returncode

    def poll(self) -> Optional[int]:
        if self._hanging():
            return None
        self._collect()
        return self.returncode

    def _deliver(self, signum: int) -> None:
        """What a signal does to this process. Signal 0 only tests that it exists.

        A tool that exits on its own has already exited when a signal reaches it, whether
        or not anything has looked: it is a zombie, which a signal changes nothing
        about, and its code is the one it exited with. The signal therefore finds an
        ``Exit`` double in that state first (``_exit_unreaped``), as ``os.waitid`` with
        ``WNOWAIT`` leaves it, instead of ending it with the signal."""
        if signum == 0:
            return
        self._exit_unreaped()
        if not self._alive:
            return
        if (
            isinstance(self._outcome, Hang)
            and self._outcome.ignores_sigterm
            and signum != signal.SIGKILL
        ):
            return
        if isinstance(self._outcome, Hang) and self._outcome.leaves_zombie:
            self._unreaped_code = -signum
        else:
            self.returncode = -signum
        self._alive = False

    def _signal(self, signum: int, name: str) -> None:
        if name == "send_signal":
            self._call(name, signal=signum)
        else:
            self._call(name)
        # ``Popen.send_signal`` (so ``kill`` and ``terminate``) polls first and sends
        # nothing once the child has exited (bpo-38630). That poll reaps a zombie, so
        # a group signal after it names a freed id, as it does for a real child.
        self._collect()
        if not self._alive:
            return
        self._deliver(signum)

    def kill(self) -> None:
        self._signal(9, "kill")

    def terminate(self) -> None:
        self._signal(15, "terminate")

    def send_signal(self, sig: int) -> None:
        self._signal(int(sig), "send_signal")

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        for stream in (self.stdout, self.stderr, self.stdin):
            if stream is not None:
                stream.close()
        if self._hanging():
            raise _GUARDS.violation(
                f"{self._record.argv} left running when its Popen context closed: the "
                "real __exit__ would wait for it forever"
            )
        self._collect()


# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------


class _Guards:
    def __init__(self) -> None:
        self.installed = False
        self.harness: Optional["Harness"] = None
        self.violations: List[str] = []
        self.permits: Dict[str, Callable[..., Any]] = {}
        self.host_image: Optional[Dict[str, Path]] = None
        self.host_probes: List[str] = []
        self.lock = threading.Lock()

    def violation(self, message: str) -> LaunchViolation:
        with self.lock:
            self.violations.append(message)
        return LaunchViolation(message)


_GUARDS = _Guards()

_OS_LAUNCHERS = (
    "system",
    "popen",
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "posix_spawn",
    "posix_spawnp",
    "fork",
    "forkpty",
)

_SOCKET_FUNCTIONS = (
    "create_connection",
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname_ex",
    "gethostbyaddr",
)


def _guard(api: str) -> Callable[..., Any]:
    def guarded(*args: Any, **kwargs: Any) -> Any:
        handler = _GUARDS.permits.get(api)
        if handler is None or _GUARDS.harness is None:
            raise _GUARDS.violation(f"{api}{args!r} was called; it is not declared")
        # A non-string argument is recorded by its type: the repr of a Process or a
        # socket carries pids and addresses that differ from run to run.
        _GUARDS.harness._new_record(
            api,
            [
                os.fsdecode(a)
                if isinstance(a, (str, bytes))
                else f"<{type(a).__name__}>"
                for a in args
            ],
            argv_type="call",
        )
        return handler(*args, **kwargs)

    guarded.__name__ = f"guarded_{api.replace('.', '_')}"
    return guarded


def _refuse_socket(api: str) -> Callable[..., Any]:
    def refused(*args: Any, **kwargs: Any) -> Any:
        raise _GUARDS.violation(f"{api} was called; characterization tests are offline")

    return refused


# ---------------------------------------------------------------------------
# Signals and reaping: a fake pid is routed to its FakePopen, any other pid fails
# ---------------------------------------------------------------------------

#: The real functions, captured before any guard replaces them. Windows has neither
#: sessions nor process groups, so its ``os`` has no ``getsid`` and no ``getpgrp``.
#: The conftest imports this module at collection, before its Windows skip runs, so
#: both are read with ``getattr``: a bare ``os.getsid`` there raised AttributeError
#: while the conftest loaded and failed the collection of every file in the shard.
#: The guards that fall back on them are installed only where ``os`` has the function
#: they replace (``_SIGNAL_GUARDS`` is applied under ``hasattr``), and on POSIX both
#: exist, so a None here is never called.
_REAL_GETSID = getattr(os, "getsid", None)
_REAL_GETPGRP = getattr(os, "getpgrp", None)


def _fake(pid: int) -> Optional["FakePopen"]:
    harness = _GUARDS.harness
    return harness._processes.get(pid) if harness is not None else None


def _not_a_fake(api: str, args: Tuple[Any, ...]) -> "LaunchViolation":
    return _GUARDS.violation(
        f"{api}{args!r} names a process that is not a characterization fake; a test "
        "must never signal, query or reap a real process"
    )


def _esrch() -> ProcessLookupError:
    return ProcessLookupError(errno.ESRCH, os.strerror(errno.ESRCH))


def _guarded_killpg(pgid: int, sig: int, api: str = "os.killpg") -> None:
    pgid, sig = int(pgid), int(sig)
    harness = _GUARDS.harness
    members = (
        [p for p in harness._processes.values() if p._group == pgid] if harness else []
    )
    owner = _fake(pgid)
    if not members and owner is None:
        raise _not_a_fake(api, (pgid, sig))
    live = [p for p in members if not p._reaped]
    if not live:
        # A fake that leads no group, or one already reaped: what killpg says.
        (owner or members[0])._call(api, signal=sig, error="ESRCH")
        raise _esrch()
    for process in live:
        process._call(api, signal=sig)
        process._deliver(sig)


def _guarded_kill(pid: int, sig: int) -> None:
    pid, sig = int(pid), int(sig)
    if pid < -1:
        return _guarded_killpg(-pid, sig, api="os.kill")
    process = _fake(pid) if pid > 0 else None
    if process is None:
        raise _not_a_fake("os.kill", (pid, sig))
    process._call("os.kill", signal=sig)
    if process._reaped:
        raise _esrch()
    process._deliver(sig)


def _guarded_getpgid(pid: int) -> int:
    process = _fake(int(pid)) if int(pid) > 0 else None
    if process is None:
        raise _not_a_fake("os.getpgid", (pid,))
    process._call("os.getpgid")
    if process._reaped:
        raise _esrch()
    return process._group if process._group is not None else _REAL_GETPGRP()


def _guarded_getsid(pid: int) -> int:
    process = _fake(int(pid)) if int(pid) > 0 else None
    if process is None:
        raise _not_a_fake("os.getsid", (pid,))
    process._call("os.getsid")
    if process._reaped:
        raise _esrch()
    return process.pid if process._session_leader else _REAL_GETSID(0)


def _guarded_waitpid(pid: int, options: int) -> Tuple[int, int]:
    process = _fake(int(pid)) if int(pid) > 0 else None
    if process is None:
        raise _not_a_fake("os.waitpid", (pid, options))
    process._call("os.waitpid", options=int(options))
    if process._reaped:
        raise ChildProcessError(errno.ECHILD, os.strerror(errno.ECHILD))
    if process._hanging():
        if options & os.WNOHANG:
            return 0, 0
        raise _GUARDS.violation(
            f"os.waitpid({pid}, {options}) on {process._record.argv}, whose double "
            "hangs: the real call would never return"
        )
    # Reap without touching ``returncode``: a real ``os.waitpid`` does not update
    # the Popen object (bpo-15756); its next wait of any kind answers 0 via ECHILD.
    code = process._reap_outside()
    status = (-code) & 0x7F if code < 0 else (code & 0xFF) << 8
    return process.pid, status


def _guarded_waitid(idtype: int, ident: int, options: int) -> Optional[Any]:
    """``os.waitid`` for a fake child: its exit observed, and reaped only without
    ``WNOWAIT``, as the real call does.

    Without ``WNOWAIT`` it is an outside reap like ``waitpid``'s: the code is read from
    the call and the Popen is not told, so ``returncode`` stays None. With it the
    child is left as it was, exited and not waited for, whatever kind of double it is.

    Answers None for a child still running under ``WNOHANG``, and ``ECHILD`` for one
    already reaped. A double that hangs under a blocking call is a violation, as for
    ``waitpid``.
    """
    process = _fake(int(ident)) if int(idtype) == os.P_PID and int(ident) > 0 else None
    if process is None:
        raise _not_a_fake("os.waitid", (idtype, ident, options))
    process._call("os.waitid", options=int(options))
    if process._reaped:
        raise ChildProcessError(errno.ECHILD, os.strerror(errno.ECHILD))
    if process._hanging():
        if options & os.WNOHANG:
            return None
        raise _GUARDS.violation(
            f"os.waitid({idtype}, {ident}, {options}) on {process._record.argv}, "
            "whose double hangs: the real call would never return"
        )
    if options & getattr(os, "WNOWAIT", 0):
        # Looking is not waiting: the code is read and nothing the Popen can see
        # changes, so a launcher that asks again finds a zombie and reaps it itself.
        process._exit_unreaped()
        code = process._exit_code()
    else:
        code = process._reap_outside()
    killed, exited = getattr(os, "CLD_KILLED", 2), getattr(os, "CLD_EXITED", 1)
    return types.SimpleNamespace(
        si_pid=process.pid,
        si_status=-code if code < 0 else code,
        si_code=killed if code < 0 else exited,
    )


_REAL_PIDFD_OPEN = getattr(os, "pidfd_open", None)


def _guarded_pidfd_open(pid: int, flags: int = 0) -> int:
    """A pidfd on the test worker itself only.

    asyncio opens one on ``os.getpid()`` whenever it builds an event loop
    (``unix_events.can_use_pidfd``). A handle on the worker cannot signal anything
    here, because ``signal.pidfd_send_signal`` is refused; any other pid, fake ones
    included, is a violation.
    """
    if int(pid) != os.getpid() or _REAL_PIDFD_OPEN is None:
        raise _not_a_fake("os.pidfd_open", (pid, flags))
    return _REAL_PIDFD_OPEN(pid, flags)


def _refuse_process_call(api: str) -> Callable[..., Any]:
    def refused(*args: Any, **kwargs: Any) -> Any:
        raise _not_a_fake(api, args)

    refused.__name__ = f"guarded_{api.replace('.', '_')}"
    return refused


_SIGNAL_GUARDS: Tuple[Tuple[Any, str, Callable[..., Any]], ...] = (
    (os, "kill", _guarded_kill),
    (os, "killpg", _guarded_killpg),
    (os, "getpgid", _guarded_getpgid),
    (os, "getsid", _guarded_getsid),
    (os, "waitpid", _guarded_waitpid),
    (os, "wait", _refuse_process_call("os.wait")),
    (os, "wait3", _refuse_process_call("os.wait3")),
    (os, "wait4", _refuse_process_call("os.wait4")),
    (os, "waitid", _guarded_waitid),
    (os, "pidfd_open", _guarded_pidfd_open),
    (signal, "pidfd_send_signal", _refuse_process_call("signal.pidfd_send_signal")),
)

#: Signals whose handlers a test could change for the whole worker; each test's
#: are put back when it ends, with the signal mask.
_RESTORED_SIGNALS = tuple(
    getattr(signal, name)
    for name in (
        "SIGTERM",
        "SIGINT",
        "SIGHUP",
        "SIGQUIT",
        "SIGCHLD",
        "SIGPIPE",
        "SIGALRM",
        "SIGUSR1",
        "SIGUSR2",
    )
    if hasattr(signal, name)
)


def _signal_state() -> Optional[Tuple[Any, Dict[int, Any]]]:
    if threading.current_thread() is not threading.main_thread():
        return None
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
    return mask, {sig: signal.getsignal(sig) for sig in _RESTORED_SIGNALS}


def _restore_signal_state(state: Optional[Tuple[Any, Dict[int, Any]]]) -> None:
    if state is None:
        return
    mask, handlers = state
    for sig, handler in handlers.items():
        if handler is not None and signal.getsignal(sig) is not handler:
            signal.signal(sig, handler)
    signal.pthread_sigmask(signal.SIG_SETMASK, mask)


# ---------------------------------------------------------------------------
# Confinement: an audit hook refuses writes outside the test, sockets, C calls
# and process starts, whatever route reached them
# ---------------------------------------------------------------------------


class _Confinement:
    """State for the one audit hook a worker process installs."""

    def __init__(self) -> None:
        self.installed = False
        self.active = False
        self.roots: Tuple[str, ...] = ()
        #: The ``short_root`` directories that exist now, in both spellings.
        self.short_roots: List[str] = []
        self.local = threading.local()
        #: Set while ``watched_imports`` lasts.
        self.import_watch: Optional["_ImportWatch"] = None


_CONFINE = _Confinement()

_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC

#: Writable wherever the test is.
_ALWAYS_WRITABLE = frozenset({"/dev/null"})


def _fd_path(fd: int) -> Optional[str]:
    """The directory an open descriptor names, for a ``dir_fd``-relative call."""
    try:
        return os.readlink(f"/proc/self/fd/{fd}")
    except OSError:
        pass
    try:
        import fcntl

        raw = fcntl.fcntl(fd, fcntl.F_GETPATH, bytes(4096))  # type: ignore[attr-defined]
        return os.fsdecode(raw.rstrip(b"\0"))
    except (ImportError, AttributeError, OSError):
        return None


def _within(path: str, roots: Sequence[str]) -> bool:
    return any(path == root or path.startswith(root + os.sep) for root in roots)


def _confinement_roots() -> Tuple[str, ...]:
    roots = list(_CONFINE.roots) + list(_CONFINE.short_roots)
    harness = _GUARDS.harness
    if harness is not None:
        roots += [str(harness.tmp), os.path.realpath(harness.tmp)]
    return tuple(roots)


def _escapes(path: Any, base_fd: Any = None, follow: bool = True) -> Optional[str]:
    """Where a write to ``path`` would land, when that is outside the test.

    ``base_fd`` is the descriptor of the directory a relative name is in, when the
    call names one.

    ``follow=False`` is for a call that acts on the name itself (unlink, rmdir,
    rename, mkdir, symlink): only the directories above it are resolved, because
    removing a symlink inside the test leaves the file it names alone.
    """
    if path is None or isinstance(path, int):
        return None  # a descriptor: the open that made it was checked
    try:
        text = os.fsdecode(os.fspath(path))
    except TypeError:
        return None
    if not os.path.isabs(text):
        if isinstance(base_fd, int):
            base = _fd_path(base_fd)
            if base is None:
                return f"<directory fd {base_fd}>/{text}"
            text = os.path.join(base, text)
        else:
            text = os.path.join(os.getcwd(), text)
    absolute = os.path.normpath(text)
    if absolute in _ALWAYS_WRITABLE:
        return None
    roots = _confinement_roots()
    if not _within(absolute, roots):
        return absolute
    if follow:
        real = os.path.realpath(absolute)
    else:
        parent, name = os.path.split(absolute)
        real = os.path.join(os.path.realpath(parent), name)
    return None if _within(real, roots) else real


def _refuse_write(
    event: str, path: Any, base_fd: Any = None, follow: bool = True
) -> None:
    landing = _escapes(path, base_fd, follow)
    if landing is not None:
        raise _GUARDS.violation(
            f"{event} would change {landing}, outside the test's directory and "
            "pytest's basetemp"
        )


_REAL_OS_OPEN = os.open

#: The os functions as they were before any guard, and the sets that describe them.
_REAL_OS_FUNCTIONS = {
    name: value for name, value in vars(os).items() if callable(value)
}
_OS_CAPABILITY_SETS = (
    "supports_dir_fd",
    "supports_fd",
    "supports_follow_symlinks",
    "supports_effective_ids",
)
_REAL_LSTAT = _REAL_OS_FUNCTIONS["lstat"]
_REAL_READLINK = _REAL_OS_FUNCTIONS["readlink"]
#: The most links one path may pass through before the kernel gives up on it (ELOOP).
_MAX_LINKS = 40


def _real_islink(path: str) -> bool:
    """Whether ``path`` is a symlink, asked of the real ``lstat``, not the guarded one."""
    import stat as _stat

    try:
        return _stat.S_ISLNK(_REAL_LSTAT(path).st_mode)
    except (OSError, ValueError):
        return False


def _real_path(path: str) -> str:
    """``os.path.realpath(path)`` for an absolute ``path``, made without the guards.

    ``realpath`` calls ``os.lstat`` on every component, and under the guards a call
    on a file inside a host executable directory is a probe that fails the test. A
    path inside the test's tree that a link sends there would then fail it for a probe
    the harness made itself. This one asks the real ``lstat`` and ``readlink``, and
    follows a link the way the kernel does: the link is replaced by its target before
    the next component, and a ``..`` after it is the parent of the target. A component
    that does not exist stays as written, as it does in ``realpath``; a path through
    more than ``_MAX_LINKS`` links is returned as written.
    """
    pending = [part for part in reversed(path.split("/")) if part]
    resolved: List[str] = []
    links = 0
    while pending:
        part = pending.pop()
        if part == ".":
            continue
        if part == "..":
            if resolved:
                resolved.pop()
            continue
        candidate = "/" + "/".join([*resolved, part])
        if not _real_islink(candidate):
            resolved.append(part)
            continue
        links += 1
        if links > _MAX_LINKS:
            return path
        try:
            target = _REAL_READLINK(candidate)
        except OSError:
            resolved.append(part)
            continue
        if target.startswith("/"):
            resolved.clear()
        pending.extend(reversed([piece for piece in target.split("/") if piece]))
    return "/" + "/".join(resolved)


def _argv_landing(path: str) -> str:
    """The path argv names, with a ``..`` resolved the way the kernel resolves it.

    A ``..`` is the parent of whatever the part in front of it leads to, so after a
    link it is the parent of the link's target, not of the link's directory. Where the
    path has a ``..`` it is resolved here with ``_real_path`` (real ``lstat``, so no
    probe of a host directory a link leads into), with the last part left as written: a
    link there stays a link, which the capture records and never follows. A path with
    no ``..`` comes back as ``os.path.normpath`` makes it, and a relative one is not
    resolved."""
    if not os.path.isabs(path) or ".." not in path.split("/"):
        return os.path.normpath(path)
    parent, name = os.path.split(path)
    if name == "..":
        return _real_path(path)
    return os.path.join(_real_path(parent), name)


def _guarded_os_open(path: Any, flags: int, mode: int = 0o777, **kwargs: Any) -> int:
    """``os.open`` that checks a write against the directory its ``dir_fd`` names.

    The keyword arguments are ``os.open``'s own (``dir_fd`` is the one read here, by
    its string key) and are passed on unchanged.

    The ``open`` audit event carries no ``dir_fd``, so the hook alone would resolve
    a relative name against the cwd (the test's own directory) wherever the
    descriptor points; ``fs_guard.open_for_write`` writes exactly this way. The
    call is checked here and marked, so the hook skips its event. ``flags`` is
    converted the way ``os.open`` converts it (``__index__``), and that int is what
    is checked and passed on.
    """
    flags = operator.index(flags)
    if _CONFINE.active and flags & _WRITE_FLAGS:
        _refuse_write("os.open", path, kwargs.get("dir_fd"))
    _CONFINE.local.open_checked = True
    try:
        return _REAL_OS_OPEN(path, flags, mode, **kwargs)
    finally:
        _CONFINE.local.open_checked = False


def _guarded_create(name: str, original: Callable[..., Any]) -> Callable[..., Any]:
    """``os.mkfifo``/``os.mknod``, which create a file but raise no audit event."""

    def guarded(path: Any, *args: Any, **kwargs: Any) -> Any:
        if _CONFINE.active:
            _refuse_write(f"os.{name}", path, kwargs.get("dir_fd"), follow=False)
        return original(path, *args, **kwargs)

    guarded.__name__ = f"guarded_{name}"
    return guarded


def _audit_open(event: str, args: Tuple[Any, ...]) -> None:
    path, mode, flags = (tuple(args) + (None, None, None))[:3]
    writing = isinstance(flags, int) and bool(flags & _WRITE_FLAGS)
    if isinstance(mode, str) and any(c in mode for c in "wax+"):
        writing = True
    if not writing or getattr(_CONFINE.local, "open_checked", False):
        return
    if mode is None and isinstance(path, (str, bytes, os.PathLike)):
        # os.open reached by an alias bound before the guard (posix.open): a
        # relative name may be relative to a dir_fd this event does not carry.
        if not os.path.isabs(os.fsdecode(os.fspath(path))):
            raise _GUARDS.violation(
                f"{event}({path!r}) for writing through an os.open the harness does "
                "not guard: its audit event does not say which directory a "
                "relative name is in"
            )
    _refuse_write(event, path)


def _refuse_descriptor_change(event: str, fd: int) -> None:
    """A change made through a descriptor (fchmod, futimens, ftruncate, ...): it
    may have been opened read-only, so the file it names is checked now."""
    target = _fd_path(fd)
    if target is None:
        raise _GUARDS.violation(
            f"{event} on descriptor {fd}, whose file the harness cannot resolve"
        )
    if target.startswith("/"):  # not a pipe, socket or anonymous inode
        _refuse_write(event, target)


def _audit_paths(
    *positions: int,
    fd_position: Optional[int] = None,
    descriptors: bool = False,
    follow: bool = True,
) -> Callable[..., None]:
    """Check the path arguments at ``positions``. ``fd_position`` is where the
    event carries the descriptor of the directory a relative name is in, when it
    does. ``follow=False`` is for a call that acts on the name itself (see
    ``_escapes``)."""

    def check(event: str, args: Tuple[Any, ...]) -> None:
        fd = (
            args[fd_position]
            if fd_position is not None and len(args) > fd_position
            else None
        )
        for position in positions:
            if len(args) <= position:
                continue
            target = args[position]
            if descriptors and isinstance(target, int) and not isinstance(target, bool):
                _refuse_descriptor_change(event, target)
            else:
                _refuse_write(event, target, fd, follow)

    return check


def _audit_move(event: str, args: Tuple[Any, ...]) -> None:
    """``shutil.move(src, dst)``: src is moved as a name, but a dst that is a
    directory (a symlink to one included) receives src inside it."""
    args = tuple(args) + (None, None)
    _refuse_write(event, args[0], follow=False)
    _refuse_write(event, args[1])


def _audit_pair(event: str, args: Tuple[Any, ...]) -> None:
    """``os.rename``: (src, dst, src_dir_fd, dst_dir_fd). Both act on the names:
    renaming a symlink moves the link, not the file it names."""
    args = tuple(args) + (None, None, None, None)
    _refuse_write(event, args[0], args[2], follow=False)
    _refuse_write(event, args[1], args[3], follow=False)


def _audit_link(event: str, args: Tuple[Any, ...]) -> None:
    """``os.link``: (src, dst, src_dir_fd, dst_dir_fd). ``dst`` is a new name. By
    default ``src`` is followed (``follow_symlinks=True``), and the new name is
    then a hard link to the file a symlink in the test names, so writes through
    it would land outside. The event does not say whether ``src`` is followed,
    so it is always checked as followed."""
    args = tuple(args) + (None, None, None, None)
    _refuse_write(event, args[0], args[2], follow=True)
    _refuse_write(event, args[1], args[3], follow=False)


def _audit_sqlite(event: str, args: Tuple[Any, ...]) -> None:
    """``sqlite3.connect(database)``: SQLite opens the file in C, which no other
    event sees.

    ``database`` is a file name, ``:memory:``, or with ``uri=True`` a ``file:`` URI.
    The event does not say which, so a ``file:`` name is checked both as a file
    name and as a URI's path. A URI opened read-only or in memory writes nothing.
    """
    database = args[0] if args else None
    if database is None or isinstance(database, int):
        return
    try:
        text = os.fsdecode(os.fspath(database))
    except TypeError:
        return
    if text in ("", ":memory:"):
        return
    _refuse_write(event, text)
    if not text.startswith("file:"):
        return
    rest, _, query = text[len("file:") :].partition("?")
    rest = rest.partition("#")[0]
    if urllib.parse.parse_qs(query).get("mode", [""])[-1] in ("ro", "memory"):
        return
    if rest.startswith("//"):
        _authority, slash, path = rest[2:].partition("/")
        rest = slash + path
    path = urllib.parse.unquote(rest)
    if path not in ("", ":memory:"):
        _refuse_write(event, path)


def _sqlite_authorizer(
    action: int, arg1: Any, arg2: Any, database: Any, source: Any
) -> int:
    """Refuse ``ATTACH`` (and ``VACUUM INTO``, which SQLite reports as one) of a
    database file outside the test. SQLite opens that file in C, with no audit
    event. The refusal is recorded, so the test fails even when the product
    catches the ``DatabaseError`` the statement then raises."""
    import sqlite3

    if action == sqlite3.SQLITE_ATTACH and _CONFINE.active:
        try:
            _audit_sqlite("sqlite3.attach", (arg1,))
        except LaunchViolation:
            return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def _guarded_sqlite_connect(original: Callable[..., Any]) -> Callable[..., Any]:
    """``sqlite3.connect`` that gives each connection ``_sqlite_authorizer``.

    The ``sqlite3.connect/handle`` event comes before the connection can take an
    authorizer, so ``connect`` itself is wrapped (``guarded`` replaces it in
    ``sqlite3`` and ``sqlite3.dbapi2``). A connection opened before the test, or
    through ``connect`` bound under another name before the guards, has no
    authorizer, and code that sets its own authorizer replaces this one.
    """

    def connect(*args: Any, **kwargs: Any) -> Any:
        connection = original(*args, **kwargs)
        connection.set_authorizer(_sqlite_authorizer)
        return connection

    connect.__name__ = "guarded_sqlite_connect"
    return connect


#: The C dbm backends. They open their files in C and raise no audit event, so their
#: ``open`` is wrapped instead (``guarded``). ``dbm.ndbm`` and ``dbm.gnu`` re-export
#: it, and are imported now so that they hold the function the guard replaces.
_C_DBM_MODULES: List[types.ModuleType] = []
for _dbm_module, _dbm_alias in (("_dbm", "dbm.ndbm"), ("_gdbm", "dbm.gnu")):
    try:
        _C_DBM_MODULES.append(importlib.import_module(_dbm_module))
        importlib.import_module(_dbm_alias)
    except ImportError:
        pass


def _guarded_dbm_open(name: str, original: Callable[..., Any]) -> Callable[..., Any]:
    def guarded_open(filename: Any, flag: str = "r", mode: int = 0o666) -> Any:
        if _CONFINE.active and not (isinstance(flag, str) and flag.startswith("r")):
            _refuse_write(name, filename)
        return original(filename, flag, mode)

    guarded_open.__name__ = f"guarded_{name.replace('.', '_')}"
    return guarded_open


def _audit_refuse(reason: str) -> Callable[..., None]:
    def check(event: str, args: Tuple[Any, ...]) -> None:
        raise _GUARDS.violation(f"{event}{tuple(args)!r}: {reason}")

    # would_refuse (below) reads this: a check that always raises refuses its event.
    check.always_refuses = True  # type: ignore[attr-defined]
    return check


_OFFLINE = "characterization tests are offline"
_NO_PROCESS = "a characterization test never starts or signals a real process"
_NO_C_CALLS = "a characterization test never calls into a C library"


def _audit_bind(event: str, args: Tuple[Any, ...]) -> None:
    """Refuse every bind but urllib3's IPv6 probe at its first import.

    ASH imports detect-secrets, and through it requests and urllib3, only when it
    builds that scanner, so the first test in a worker to build one imports urllib3
    under these guards. ``urllib3_ipv6_probe`` (below) says what passes.
    """
    if urllib3_ipv6_probe(event, args):
        return
    raise _GUARDS.violation(f"{event}{tuple(args)!r}: {_OFFLINE}")


#: Audit event -> check. The positions are the event's path arguments as CPython
#: raises them (see the audit events table in the sys module documentation).
_AUDIT_CHECKS: Dict[str, Callable[[str, Tuple[Any, ...]], None]] = {
    "open": _audit_open,
    # These act on the name, so a symlink at the name is not followed.
    "os.remove": _audit_paths(0, fd_position=1, follow=False),
    "os.rmdir": _audit_paths(0, fd_position=1, follow=False),
    "os.mkdir": _audit_paths(0, fd_position=2, follow=False),
    "os.rename": _audit_pair,
    "os.link": _audit_link,
    "os.symlink": _audit_paths(1, fd_position=2, follow=False),
    # These five also take a descriptor in place of the path (fchmod, futimens...).
    "os.truncate": _audit_paths(0, descriptors=True),
    "os.chmod": _audit_paths(0, fd_position=2, descriptors=True),
    "os.chown": _audit_paths(0, fd_position=3, descriptors=True),
    "os.utime": _audit_paths(0, fd_position=3, descriptors=True),
    "os.chflags": _audit_paths(0),
    "os.lchflags": _audit_paths(0),
    # os.mkfifo and os.mknod raise no event (measured on 3.14): they are guarded as
    # functions instead (_guarded_create).
    "os.setxattr": _audit_paths(0, descriptors=True),
    "os.removexattr": _audit_paths(0, descriptors=True),
    "shutil.rmtree": _audit_paths(0, fd_position=1, follow=False),
    "shutil.copyfile": _audit_paths(1),
    "shutil.copymode": _audit_paths(1),
    "shutil.copystat": _audit_paths(1),
    "shutil.copytree": _audit_paths(1),
    "shutil.move": _audit_move,
    "shutil.chown": _audit_paths(0),
    "shutil.make_archive": _audit_paths(0),
    "shutil.unpack_archive": _audit_paths(1),
    "tempfile.mkstemp": _audit_paths(0, follow=False),
    "tempfile.mkdtemp": _audit_paths(0, follow=False),
    "sqlite3.connect": _audit_sqlite,
    "socket.connect": _audit_refuse(_OFFLINE),
    "socket.bind": _audit_bind,
    "socket.sendto": _audit_refuse(_OFFLINE),
    "socket.sendmsg": _audit_refuse(_OFFLINE),
    "socket.getaddrinfo": _audit_refuse(_OFFLINE),
    "socket.getnameinfo": _audit_refuse(_OFFLINE),
    "socket.gethostbyname": _audit_refuse(_OFFLINE),
    "socket.gethostbyaddr": _audit_refuse(_OFFLINE),
    "socket.sethostname": _audit_refuse(_OFFLINE),
    "ctypes.dlopen": _audit_refuse(_NO_C_CALLS),
    # Before Python 3.14 a call through a library handle raises no event, but
    # looking up the symbol does.
    "ctypes.dlsym": _audit_refuse(_NO_C_CALLS),
    "ctypes.call_function": _audit_refuse(_NO_C_CALLS),
    "os.system": _audit_refuse(_NO_PROCESS),
    "os.exec": _audit_refuse(_NO_PROCESS),
    "os.fork": _audit_refuse(_NO_PROCESS),
    "os.forkpty": _audit_refuse(_NO_PROCESS),
    "os.posix_spawn": _audit_refuse(_NO_PROCESS),
    "os.spawn": _audit_refuse(_NO_PROCESS),
    "os.startfile": _audit_refuse(_NO_PROCESS),
    "subprocess.Popen": _audit_refuse(_NO_PROCESS),
    "os.kill": _audit_refuse(_NO_PROCESS),
    "os.killpg": _audit_refuse(_NO_PROCESS),
    # subprocess binds _posixsubprocess.fork_exec by name (as _fork_exec), so only
    # this event sees a direct call.
    "_posixsubprocess.fork_exec": _audit_refuse(_NO_PROCESS),
}


def _active_check(event: str) -> Optional[Callable[..., None]]:
    """The check ``_audit`` runs for ``event`` now: None when confinement is off,
    this thread is already inside a check, or the event has no entry."""
    if not _CONFINE.active or getattr(_CONFINE.local, "busy", False):
        return None
    return _AUDIT_CHECKS.get(event)


def would_refuse(event: str, args: Tuple[Any, ...] = ()) -> bool:
    """Whether the audit hook would refuse this event now, for a caller that must
    not count a start the hook stops (tests/utils/real_process_counter.py).

    True when an import watch refuses it, or when the check ``_audit`` would run
    always raises. It is evaluated from the caller's frame, so it is meant for events
    whose allowances do not depend on the calling frame: every process start (the
    urllib3 probe allows only ``socket.bind``).
    """
    watch = _CONFINE.import_watch
    if watch is not None and watch.refuses(event, args):
        return True
    return bool(getattr(_active_check(event), "always_refuses", False))


def _audit(event: str, args: Tuple[Any, ...]) -> None:
    """The process-wide audit hook. Inert unless a characterization test runs or a
    module is imported under ``watched_imports``."""
    watch = _CONFINE.import_watch
    if watch is not None:
        watch.check(event, args)
    check = _active_check(event)
    if check is None:
        return
    _CONFINE.local.busy = True
    try:
        check(event, args)
    finally:
        _CONFINE.local.busy = False


def _install_audit_hook() -> None:
    if not _CONFINE.installed:
        sys.addaudithook(_audit)
        _CONFINE.installed = True


# ---------------------------------------------------------------------------
# Imports at collection
# ---------------------------------------------------------------------------

#: Audit events an import must not raise: a process start, a signal, any socket.
_IMPORT_REFUSED_EVENTS = (
    "socket.",
    "subprocess.Popen",
    "os.system",
    "os.exec",
    "os.posix_spawn",
    "os.spawn",
    "os.fork",
    "os.forkpty",
    "os.startfile",
    "_posixsubprocess.fork_exec",
    "os.kill",
    "os.killpg",
    "signal.pthread_kill",
)


def _event_frame() -> Optional[types.FrameType]:
    """The frame whose call raised the audit event being checked: the first one
    outside this module (the audit hook and the checks it calls live here)."""
    here = _event_frame.__code__.co_filename
    frame: Optional[types.FrameType] = sys._getframe(1)
    while frame is not None and frame.f_code.co_filename == here:
        frame = frame.f_back
    return frame


#: The code that raises ``socket.__new__`` for a ``socket.socket(...)`` call.
_SOCKET_INIT_CODE = socket.socket.__init__.__code__


def _is_urllib3_first_import_probe(frame: Optional[types.FrameType]) -> bool:
    """``frame`` runs ``_has_ipv6`` of urllib3.util.connection, called by that
    module's own body: the call urllib3 makes once, while it is first imported."""
    if frame is None:
        return False
    code = frame.f_code
    caller = frame.f_back
    return (
        code.co_name == "_has_ipv6"
        and frame.f_globals.get("__name__") == "urllib3.util.connection"
        and code.co_filename.replace(os.sep, "/").endswith(
            "/urllib3/util/connection.py"
        )
        and caller is not None
        and caller.f_code.co_name == "<module>"
        and caller.f_globals is frame.f_globals
    )


def urllib3_ipv6_probe(event: str, args: Tuple[Any, ...]) -> bool:
    """urllib3's check for IPv6 when it is first imported.

    urllib3.util.connection's module body calls ``_has_ipv6("::1")``, which makes
    an IPv6 stream socket, binds it to ``("::1", 0)`` and closes it. Nothing
    listens on it and nothing leaves the host. Allowed only for that socket and
    that address, and only when the frame that raised the event is that call (for
    ``socket.__new__``, the ``socket.socket.__init__`` it calls): the same function
    called later, from anywhere else, is refused. Whether urllib3 is first imported
    at collection or inside a test, this decides.
    """
    frame = _event_frame()
    if event == "socket.__new__":
        if frame is None or frame.f_code is not _SOCKET_INIT_CODE:
            return False
        return tuple(args[1:]) == (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            0,
        ) and _is_urllib3_first_import_probe(frame.f_back)
    if event == "socket.bind" and len(args) == 2:
        sock, address = args
        return (
            getattr(sock, "family", None) == socket.AF_INET6
            and getattr(sock, "type", None) == socket.SOCK_STREAM
            and type(address) is tuple
            and address == ("::1", 0)
            and _is_urllib3_first_import_probe(frame)
        )
    return False


class _ImportWatch:
    def __init__(
        self, what: str, allowed: Sequence[Callable[[str, Tuple[Any, ...]], bool]]
    ) -> None:
        self.what = what
        self.allowed = tuple(allowed)
        self.refused: List[str] = []

    def refuses(self, event: str, args: Tuple[Any, ...]) -> bool:
        """Whether ``check`` would raise for this event; it changes nothing."""
        if not event.startswith(_IMPORT_REFUSED_EVENTS):
            return False
        return not any(allow(event, args) for allow in self.allowed)

    def check(self, event: str, args: Tuple[Any, ...]) -> None:
        if not self.refuses(event, args):
            return
        message = (
            f"{event}{_short_repr(args)} was raised while importing {self.what}, "
            "outside every per-test guard. An import at collection must not start a "
            "process, send a signal or open a socket. If a third-party module does "
            "that on import, pre-import it in this package's conftest and allow "
            "only that effect."
        )
        self.refused.append(message)
        raise LaunchViolation(message)


def _short_repr(args: Tuple[Any, ...]) -> str:
    text = repr(args)
    return text if len(text) <= 200 else text[:200] + "...)"


@contextlib.contextmanager
def watched_imports(
    what: str,
    allowed: Sequence[Callable[[str, Tuple[Any, ...]], bool]] = (),
) -> Iterator[List[str]]:
    """Refuse a process start, a signal or any socket while ``what`` is imported.

    The per-test guards are not installed while pytest collects, so an import at
    module level would otherwise run its side effects unconfined (``import
    aws_cdk`` starts jsii's node). Each refused event raises ``LaunchViolation``
    at the call, which ``except Exception`` cannot swallow, and is added to the
    list this yields. ``allowed`` names the events a known import needs, such as
    ``urllib3_ipv6_probe``. The watch covers every thread while it lasts.
    """
    _install_audit_hook()
    previous = _CONFINE.import_watch
    watch = _ImportWatch(what, allowed)
    _CONFINE.import_watch = watch
    try:
        yield watch.refused
    finally:
        _CONFINE.import_watch = previous


class _RefusingLibrary:
    """Stands in for a ctypes library handle; every call through it is a violation."""

    def __init__(self, name: str) -> None:
        self._name = name

    def __getattr__(self, attr: str) -> Any:
        if attr.startswith("__"):
            raise AttributeError(attr)
        name = self._name

        def refused(*args: Any, **kwargs: Any) -> Any:
            raise _GUARDS.violation(
                f"{name}.{attr}() would run C code in the test worker"
            )

        return refused


def _real_child_refused(self: Any, *args: Any, **kwargs: Any) -> None:
    raise _GUARDS.violation(
        f"the real subprocess.Popen tried to start {self.args!r}; a characterization "
        "test never starts a process"
    )


def _guarded_which(original: Callable[..., Optional[str]]) -> Callable[..., Any]:
    """``shutil.which`` that may search harness directories only.

    With PATH unset, ``shutil.which`` searches ``os.confstr("CS_PATH")`` (the
    system directories); here it searches ``<SYSBIN>``, which stands in for them.
    """

    def which(cmd: Any, mode: int = os.F_OK | os.X_OK, path: Any = None) -> Any:
        harness = _GUARDS.harness
        if harness is None:
            raise _GUARDS.violation(
                f"shutil.which({cmd!r}) outside a characterization harness"
            )
        text = os.fsdecode(cmd)
        if os.path.dirname(text):
            if text != sys.executable and not harness._is_harness_path(text):
                raise _GUARDS.violation(
                    f"shutil.which({cmd!r}) checks a file outside the harness"
                )
            return original(cmd, mode, path)
        if path is None:
            path = os.environ.get("PATH")
            if path is None:
                path = str(harness.sysbin)
        outside = [
            d
            for d in os.fsdecode(path).split(os.pathsep)
            if d and not harness._is_harness_path(d)
        ]
        if outside:
            raise _GUARDS.violation(
                f"shutil.which({cmd!r}) would search {outside}, outside the harness. "
                "A golden must not depend on what a host has installed: put the "
                "tool in a harness directory with char.tool()"
            )
        return original(cmd, mode, path)

    return which


def _host_entry(path: Any, listing: bool) -> Optional[str]:
    """The host path a probe of ``path`` would read, or None for any other path."""
    if path is None or isinstance(path, int):
        return None
    try:
        text = os.fsdecode(os.fspath(path))
    except TypeError:
        return None
    if not text.startswith("/"):
        return None
    text = os.path.normpath(text)
    if text == sys.executable:
        return None
    if os.path.dirname(text) in HOST_EXEC_DIRS or (listing and text in HOST_EXEC_DIRS):
        return text
    return None


def _probe_guard(name: str, original: Callable[..., Any], listing: bool) -> Any:
    """Wrap an ``os`` probe so it cannot read inside a host executable directory.

    Under ``host_image`` (self-tests only), such a probe reads a planted directory
    instead and is counted, which is how a test simulates an image that ships
    tools in /usr/local/bin.
    """

    def probe(*args: Any, **kwargs: Any) -> Any:
        if kwargs.get("dir_fd") is None:
            path = args[0] if args else kwargs.get("path")
            entry = _host_entry(path, listing)
            if entry is not None:
                image = _GUARDS.host_image
                directory = entry if listing and entry in HOST_EXEC_DIRS else None
                directory = directory or os.path.dirname(entry)
                if image is None or directory not in image:
                    raise _GUARDS.violation(
                        f"os.{name}({entry!r}) looked inside a host executable "
                        "directory. A golden must not depend on what a host has "
                        "installed there"
                    )
                with _GUARDS.lock:
                    _GUARDS.host_probes.append(entry)
                planted = Path(image[directory])
                if entry != directory:
                    planted = planted / Path(entry).name
                if args:
                    args = (str(planted), *args[1:])
                else:
                    kwargs["path"] = str(planted)
        return original(*args, **kwargs)

    probe.__name__ = f"guarded_{name}"
    return probe


@contextlib.contextmanager
def host_image(directories: Mapping[str, Path]) -> Iterator[List[str]]:
    """Simulate a host whose executable directories hold ``directories``' files.

    For self-tests. Inside the block a probe of, say, ``/usr/local/bin/uv`` reads
    ``directories["/usr/local/bin"] / "uv"`` instead of failing, and is appended to
    the yielded list. A correct harness makes no such probe at all.
    """
    _GUARDS.host_image = {k: Path(v) for k, v in directories.items()}
    _GUARDS.host_probes.clear()
    try:
        yield _GUARDS.host_probes
    finally:
        _GUARDS.host_image = None


@contextlib.contextmanager
def guarded(
    monkeypatch: pytest.MonkeyPatch, basetemp: Optional[Path] = None
) -> Iterator[_Guards]:
    """Install every guard for one test; fail it at teardown on any violation.

    ``basetemp`` is pytest's basetemp. Writes there and under the package's
    ``__snapshots__`` stay allowed; every other write is refused, with or without a
    harness. ``sys.dont_write_bytecode`` is set, so an import during a test writes
    no ``.pyc`` and no ``__pycache__`` needs an exception.
    """
    import asyncio
    import asyncio.base_events
    import asyncio.subprocess
    import multiprocessing.context
    import multiprocessing.process
    import multiprocessing.util
    import posix

    import _posixsubprocess

    _GUARDS.violations.clear()
    _GUARDS.permits.clear()
    _GUARDS.host_image = None
    _GUARDS.host_probes.clear()
    # ASH's detect-secrets worker calls set_start_method("fork", force=True). Put
    # the start method back after the test, so no later test in this worker (in
    # this package or not) forks a threaded pytest process.
    default_context = multiprocessing.context._default_context
    monkeypatch.setattr(
        default_context, "_actual_context", default_context._actual_context
    )
    monkeypatch.setattr(subprocess, "Popen", FakePopen)
    monkeypatch.setattr(REAL_POPEN, "_execute_child", _real_child_refused)
    for name in _OS_LAUNCHERS:
        if hasattr(os, name):
            monkeypatch.setattr(os, name, _guard(f"os.{name}"))
    for module, name in (
        (asyncio, "create_subprocess_exec"),
        (asyncio, "create_subprocess_shell"),
        (asyncio.subprocess, "create_subprocess_exec"),
        (asyncio.subprocess, "create_subprocess_shell"),
        (asyncio.base_events.BaseEventLoop, "subprocess_exec"),
        (asyncio.base_events.BaseEventLoop, "subprocess_shell"),
        (multiprocessing.process.BaseProcess, "start"),
        (multiprocessing.util, "spawnv_passfds"),
        (_posixsubprocess, "fork_exec"),
    ):
        monkeypatch.setattr(module, name, _guard(f"{module.__name__}.{name}"))
    for name in ("connect", "connect_ex", "sendto"):
        monkeypatch.setattr(
            socket.socket, name, _refuse_socket(f"socket.socket.{name}")
        )
    for name in _SOCKET_FUNCTIONS:
        monkeypatch.setattr(socket, name, _refuse_socket(f"socket.{name}"))
    monkeypatch.setattr(shutil, "which", _guarded_which(shutil.which))
    try:
        import sqlite3
        import sqlite3.dbapi2
    except ImportError:
        pass
    else:
        connect = _guarded_sqlite_connect(sqlite3.dbapi2.connect)
        monkeypatch.setattr(sqlite3, "connect", connect)
        monkeypatch.setattr(sqlite3.dbapi2, "connect", connect)
    for dbm_module in _C_DBM_MODULES:
        original = vars(dbm_module)["open"]
        wrapper = _guarded_dbm_open(f"{dbm_module.__name__}.open", original)
        for alias in (dbm_module.__name__, "dbm.ndbm", "dbm.gnu"):
            module = sys.modules.get(alias)
            if module is not None and vars(module).get("open") is original:
                monkeypatch.setattr(module, "open", wrapper)
    import _signal

    for owner, name, replacement in _SIGNAL_GUARDS:
        # The C modules hold the same functions under the same names, and most of
        # them (waitpid, pidfd_open, pidfd_send_signal) raise no audit event.
        alias = posix if owner is os else _signal
        for module in (owner, alias):
            if hasattr(module, name):
                monkeypatch.setattr(module, name, replacement)
    for module_name, module in list(sys.modules.items()):
        if module_name.startswith("automated_security_helper") and module is not None:
            for attr, value in list(vars(module).items()):
                if isinstance(value, ctypes.CDLL):
                    monkeypatch.setattr(
                        module, attr, _RefusingLibrary(f"{module_name}.{attr}")
                    )
    for name, listing in (
        ("stat", False),
        ("lstat", False),
        ("access", False),
        ("listdir", True),
        ("scandir", True),
    ):
        monkeypatch.setattr(os, name, _probe_guard(name, getattr(os, name), listing))
    monkeypatch.setattr(os, "open", _guarded_os_open)
    monkeypatch.setattr(posix, "open", _guarded_os_open)
    for name in ("mkfifo", "mknod"):
        if hasattr(os, name):
            creator = _guarded_create(name, getattr(os, name))
            monkeypatch.setattr(os, name, creator)
            monkeypatch.setattr(posix, name, creator)
    # Code that asks `os.open in os.supports_dir_fd` must get the answer it gets
    # without the guards (scanned_tree decides its walk that way).
    for set_name in _OS_CAPABILITY_SETS:
        capabilities = getattr(os, set_name, None)
        if capabilities is None:
            continue
        guards = {
            vars(os)[name]
            for name, real in _REAL_OS_FUNCTIONS.items()
            if real in capabilities and vars(os).get(name) is not real
        }
        if guards:
            monkeypatch.setattr(os, set_name, set(capabilities) | guards)
    # Python 3.10's pathlib bound os.stat and friends into _NormalAccessor when the
    # class was defined, so Path.exists() and Path.is_file() never see os.stat.
    accessor = getattr(pathlib, "_NormalAccessor", None)
    for name, listing in (
        ("stat", False),
        ("lstat", False),
        ("listdir", True),
        ("scandir", True),
    ):
        if accessor is not None and name in vars(accessor):
            original = vars(accessor)[name]
            monkeypatch.setattr(
                accessor, name, staticmethod(_probe_guard(name, original, listing))
            )
    for module_name, module in list(sys.modules.items()):
        if module_name.startswith("automated_security_helper") and module is not None:
            for attr, value in list(vars(module).items()):
                if value is REAL_POPEN:
                    monkeypatch.setattr(module, attr, FakePopen)
    roots = [os.path.realpath(SNAPSHOT_ROOT), str(SNAPSHOT_ROOT)]
    if basetemp is not None:
        roots += [os.path.realpath(basetemp), str(basetemp)]
    _install_audit_hook()
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    signals = _signal_state()
    _GUARDS.installed = True
    _CONFINE.roots = tuple(roots)
    _CONFINE.active = True
    try:
        yield _GUARDS
    finally:
        _CONFINE.active = False
        _GUARDS.installed = False
        _GUARDS.harness = None
        _restore_signal_state(signals)
        for module_name, module in list(sys.modules.items()):
            if (
                module_name.startswith("automated_security_helper")
                and module is not None
            ):
                for attr, value in list(vars(module).items()):
                    if value is FakePopen:
                        setattr(module, attr, REAL_POPEN)
    check_no_violations()


def _process_status() -> str:
    """The text of ``/proc/self/status``, or "" where there is none."""
    try:
        return Path("/proc/self/status").read_text(encoding="utf-8")
    except OSError:
        return ""


def _process_limit_exemption(uid: int, status: str) -> Optional[str]:
    """Why the kernel would not hold ``RLIMIT_NPROC`` for a process with this uid and
    this ``/proc/self/status`` text, or None where it holds.

    The kernel ignores the limit for root and for a process whose effective set has
    CAP_SYS_RESOURCE (capability 24) or CAP_SYS_ADMIN (21). Where the text has no
    ``CapEff`` line (no procfs) only the uid is known; a line that cannot be read
    counts as exempt, so a start with its guard removed is never left to a limit that
    may not hold.
    """
    if uid == 0:
        return "the process runs as root"
    for line in status.splitlines():
        if not line.startswith("CapEff:"):
            continue
        try:
            effective = int(line.split(":", 1)[1].strip(), 16)
        except ValueError:
            return "its effective capabilities cannot be read"
        for bit, name in ((24, "CAP_SYS_RESOURCE"), (21, "CAP_SYS_ADMIN")):
            if effective >> bit & 1:
                return f"the process holds {name}"
    return None


#: The environment variable that runs the cells which start a process even where
#: RLIMIT_NPROC does not bind (see ``require_process_limit``). Set it to 1 on a
#: disposable worker only.
UNPROTECTED_PROCESS_LIMIT_ENV = "ASH_TEST_RUN_PROCESS_CELLS_UNPROTECTED"

#: Whether the run opted in. Read once, at import: a test's environment is its own.
_RUN_UNPROTECTED = os.environ.get(UNPROTECTED_PROCESS_LIMIT_ENV) == "1"

#: Why each process cell that skipped for want of the limit did, in order.
_PROCESS_LIMIT_SKIPS: List[str] = []


def require_process_limit() -> None:
    """Skip the test where the kernel would not hold ``RLIMIT_NPROC`` for this process.

    ``no_new_processes()`` calls it. A test that starts something it must not leave
    behind if it skips (a thread that waits for the block to open, say) calls it
    first, before it starts that: a skip raised inside the block comes too late for
    it. Each skip is counted for ``process_limit_skip_summary``.

    A run that set ``UNPROTECTED_PROCESS_LIMIT_ENV`` to 1 runs these tests anyway.
    There a start with its guard removed would not be stopped by the limit, so do
    that on a disposable worker only.
    """
    exemption = _process_limit_exemption(os.getuid(), _process_status())
    if exemption is None or _RUN_UNPROTECTED:
        return
    _PROCESS_LIMIT_SKIPS.append(exemption)
    pytest.skip(
        f"RLIMIT_NPROC does not bind this process ({exemption}), so a start with "
        "its guard removed would not be stopped by the limit; set "
        f"{UNPROTECTED_PROCESS_LIMIT_ENV}=1 on a disposable run to run it anyway"
    )


def process_limit_skip_summary() -> Optional[str]:
    """One text naming how many cells ``require_process_limit`` skipped in this
    process and the variable that runs them, or None where it skipped none."""
    count = len(_PROCESS_LIMIT_SKIPS)
    if not count:
        return None
    reasons = ", ".join(sorted(set(_PROCESS_LIMIT_SKIPS)))
    noun = "cell" if count == 1 else "cells"
    return (
        f"{count} characterization {noun} skipped: they start a process under "
        f"no_new_processes(), and RLIMIT_NPROC does not bind this worker ({reasons}). "
        f"Set {UNPROTECTED_PROCESS_LIMIT_ENV}=1 on a disposable run to run them "
        "without that safety net"
    )


@contextlib.contextmanager
def no_new_processes() -> Iterator[None]:
    """Make every fork and clone fail with EAGAIN inside the block.

    For self-tests that start a process on purpose to show it is refused: if the
    guard they rely on were missing, the start fails instead of forking the test
    worker. It sets RLIMIT_NPROC to 1, so no thread can start inside the block
    either. The kernel does not hold that limit for root or for a process with
    CAP_SYS_RESOURCE or CAP_SYS_ADMIN, and there it is no safety net at all, so the
    test is skipped instead (see ``require_process_limit``), unless the run opted in
    with ``UNPROTECTED_PROCESS_LIMIT_ENV``, when the block runs without that net.
    """
    import resource

    require_process_limit()
    soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
    resource.setrlimit(resource.RLIMIT_NPROC, (1, hard))
    try:
        yield
    finally:
        resource.setrlimit(resource.RLIMIT_NPROC, (soft, hard))


def take_violations() -> List[str]:
    """Return and clear the violations recorded so far (for the self-tests)."""
    with _GUARDS.lock:
        found = list(_GUARDS.violations)
        _GUARDS.violations.clear()
    return found


def check_no_violations() -> None:
    """Fail the test if any violation was recorded, even one product code caught."""
    with _GUARDS.lock:
        found = list(_GUARDS.violations)
        _GUARDS.violations.clear()
    if found:
        pytest.fail(
            "undeclared launches, lookups or connections:\n  " + "\n  ".join(found),
            pytrace=False,
        )


def _run_tmpdir() -> str:
    """The TMPDIR this test run started with, else /tmp.

    tests/conftest.py points TMPDIR at a session directory of its own when the
    session starts, and records the value it found in
    ``ASH_TEST_PRE_SESSION_TEMP_ENV``; that record is read when present, so the
    parent is the same whether this module is imported before or after it.
    """
    recorded = os.environ.get("ASH_TEST_PRE_SESSION_TEMP_ENV")
    tmpdir = (
        json.loads(recorded).get("TMPDIR") if recorded else os.environ.get("TMPDIR")
    )
    return os.path.abspath(tmpdir) if tmpdir else "/tmp"


#: Where ``short_root`` makes each test's harness directory: the run's TMPDIR, so
#: scratch stays where the run put it, or /tmp when TMPDIR is unset.
SHORT_ROOT_PARENT = _run_tmpdir()
_SHORT_ROOT_PREFIX = "char-"
_SHORT_ROOT_NAME = re.compile(re.escape(_SHORT_ROOT_PREFIX) + "[0-9a-f]{8}")
#: The shortest ``short_root`` path, ``/tmp/char-<8 hex digits>``.
SHORT_ROOT_MIN_LENGTH = len("/tmp/" + _SHORT_ROOT_PREFIX) + 8
#: The longest one allowed. cfn-nag's scanner turns a template's whole path into a
#: directory name, which passed the 255-byte name limit under deep roots.
SHORT_ROOT_MAX_LENGTH = 96
#: How long an unlocked short root must have been left alone before a session
#: removes it as stale.
STALE_SHORT_ROOT_SECONDS = 3600
#: The file ``short_root`` writes in each root it makes while it holds the root's
#: lock, and its exact content. The sweep removes only a root that holds it.
_ROOT_MARKER = ".characterization-root"
_ROOT_MARKER_TOKEN = b"automated-security-helper characterization test root\n"


def _write_root_marker(root: str) -> None:
    """Write the marker in ``root``. It refuses a name that exists, link or not."""
    fd = os.open(
        os.path.join(root, _ROOT_MARKER),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.write(fd, _ROOT_MARKER_TOKEN)
    finally:
        os.close(fd)


def _has_root_marker(directory_fd: int, uid: int) -> bool:
    """Whether the directory open on ``directory_fd`` holds the marker: a regular
    file, not a symlink, owned by ``uid``, holding exactly the token."""
    import stat as _stat

    try:
        info = os.stat(_ROOT_MARKER, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        return False
    if (
        not _stat.S_ISREG(info.st_mode)
        or info.st_uid != uid
        or info.st_size != len(_ROOT_MARKER_TOKEN)
    ):
        return False
    try:
        fd = os.open(
            _ROOT_MARKER,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fd,
        )
    except OSError:
        return False
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            return False
        return os.read(fd, len(_ROOT_MARKER_TOKEN) + 1) == _ROOT_MARKER_TOKEN
    finally:
        os.close(fd)


def _check_short_root(root: str, parent: str) -> None:
    """Refuse to remove anything but a root ``short_root`` or the stale-root sweep
    registered: ``<parent>/char-<8 hex digits>``, a directory, not a symlink."""
    if (
        root not in _CONFINE.short_roots
        or os.path.dirname(root) != parent
        or not _SHORT_ROOT_NAME.fullmatch(os.path.basename(root))
        or os.path.islink(root)
    ):
        raise RuntimeError(f"refusing to remove {root}: it is not a short root")


def _chmod_and_remove(root: str, real_root: str) -> None:
    """Make every directory under ``root`` writable and remove the tree.

    Each directory is made writable from its parent's listing before it is
    listed itself, so one a test made mode 000 is still emptied. A directory whose
    real path is outside ``real_root`` (one swapped for a symlink, or reached
    through one) raises before it is changed. ``os.walk`` does not follow
    symlinks, a symlinked child is never changed, and ``shutil.rmtree`` removes a
    symlink without following it.
    """

    def make_writable(directory: str) -> None:
        if os.path.islink(directory) or not _within(
            os.path.realpath(directory), [real_root]
        ):
            raise RuntimeError(
                f"refusing to change {directory}: it is outside the short root {root}"
            )
        with contextlib.suppress(OSError):
            os.chmod(directory, 0o700)

    make_writable(root)
    for directory, children, _files in os.walk(root):
        make_writable(directory)
        for name in children:
            child = os.path.join(directory, name)
            if not os.path.islink(child):
                make_writable(child)
    shutil.rmtree(root, ignore_errors=True)


def _remove_tree(root: str, parent: str) -> None:
    """Remove a short root, whatever the test left in it.

    The first pass runs under the audit hook, so a write check that wrongly
    refuses it still fails the test. Whatever it leaves is removed by
    ``_remove_leftover_short_root``, so the root never stays behind.
    """
    _check_short_root(root, parent)
    real_root = os.path.realpath(root)
    try:
        _chmod_and_remove(root, real_root)
    finally:
        if os.path.lexists(root):
            _remove_leftover_short_root(root, parent)


def _remove_leftover_short_root(root: str, parent: str) -> None:
    """Remove what is left of a short root, with the audit hook held off for this
    thread.

    Only a root that ``_check_short_root`` accepts, and only what lies inside it:
    anything else is refused, not deleted, before anything there is changed.
    """
    _check_short_root(root, parent)
    real_root = os.path.realpath(root)
    busy = getattr(_CONFINE.local, "busy", False)
    _CONFINE.local.busy = True
    try:
        _chmod_and_remove(root, real_root)
    finally:
        _CONFINE.local.busy = busy


def _locked_directory(path: str, exclusive: bool) -> Optional[int]:
    """A descriptor on directory ``path`` holding an flock on it, or None when
    another process holds a conflicting one (exclusive) or ``path`` is not a plain
    directory. The lock lasts until the descriptor is closed or the process dies."""
    import fcntl

    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        fcntl.flock(fd, (fcntl.LOCK_EX | fcntl.LOCK_NB) if exclusive else fcntl.LOCK_SH)
    except OSError:
        os.close(fd)
        return None
    return fd


@contextlib.contextmanager
def short_root(parent: Optional[str] = None) -> Iterator[Path]:
    """A new directory ``<parent>/char-<8 hex digits>``, removed afterwards.

    ``parent`` is ``SHORT_ROOT_PARENT`` unless given. Each test's harness lives in
    one, so the paths ASH sees are short: ASH cuts some text before the harness can
    normalize it (a failed scan's stderr excerpt is cut at 2000 characters), and
    under pytest's basetemp whether and where that cut fell depended on the
    basetemp's length. A root longer than ``SHORT_ROOT_MAX_LENGTH`` is refused. The
    directory is mode 0700 and made with ``os.mkdir``, which refuses a name that
    exists, and this process holds a shared flock on it while it exists, which tells
    ``sweep_stale_short_roots`` in any other process that it is in use. Once the
    lock is held it writes the marker file ``.characterization-root``, which is how
    the sweep tells a harness root from any other directory with such a name; a
    root it could not lock gets no marker, so no sweep ever takes it. While it
    exists the audit hook allows writes inside it.
    """
    parent = SHORT_ROOT_PARENT if parent is None else parent
    longest = len(os.path.join(parent, _SHORT_ROOT_PREFIX)) + 8
    if longest > SHORT_ROOT_MAX_LENGTH:
        raise RuntimeError(
            f"a harness root in {parent} would be {longest} characters long, more "
            f"than {SHORT_ROOT_MAX_LENGTH}; run with a shorter TMPDIR"
        )
    real_parent = os.path.realpath(parent)
    for _attempt in range(100):
        name = _SHORT_ROOT_PREFIX + secrets.token_hex(4)
        spellings = [os.path.join(parent, name), os.path.join(real_parent, name)]
        _CONFINE.short_roots.extend(spellings)
        try:
            os.mkdir(spellings[0], 0o700)
        except FileExistsError:
            for spelling in spellings:
                _CONFINE.short_roots.remove(spelling)
            continue
        break
    else:
        raise RuntimeError(f"could not make a new directory in {parent}")
    lock = _locked_directory(spellings[0], exclusive=False)
    try:
        if lock is not None:
            _write_root_marker(spellings[0])
        yield Path(spellings[0])
    finally:
        try:
            _remove_tree(spellings[0], parent)
        finally:
            # Even when the removal was refused: a root left behind must not stay
            # writable for the rest of the worker.
            if lock is not None:
                os.close(lock)
            for spelling in spellings:
                _CONFINE.short_roots.remove(spelling)


def sweep_stale_short_roots(
    parents: Optional[Sequence[str]] = None, now: Optional[float] = None
) -> List[str]:
    """Remove the short roots a killed run left behind, and return their paths.

    A run killed by SIGKILL or a timeout never reaches ``short_root``'s cleanup,
    and pytest's basetemp removal cannot reach the root. This removes, from each of
    ``parents`` (``SHORT_ROOT_PARENT`` and /tmp unless given), each ``char-<8 hex
    digits>`` entry that is a plain directory (never a symlink), owned by this uid,
    left unchanged for ``STALE_SHORT_ROOT_SECONDS``, that no live process holds
    the flock of, and that holds ``short_root``'s marker (``_has_root_marker``,
    read through the locked directory). It removes it through the same checks as
    ``short_root``'s own cleanup, holding the flock exclusively so two sweepers
    never meet. Nothing else is touched: a directory without the marker, whether
    a user's own or a root from an older harness, which took no lock and may still
    be in use, is left in place.
    """
    import stat as _stat

    now = time.time() if now is None else now
    parents = sorted({SHORT_ROOT_PARENT, "/tmp"}) if parents is None else list(parents)
    removed: List[str] = []
    for parent in parents:
        try:
            entries = sorted(os.scandir(parent), key=lambda entry: entry.name)
        except OSError:
            continue
        for entry in entries:
            if not _SHORT_ROOT_NAME.fullmatch(entry.name):
                continue
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if (
                not _stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or now - info.st_mtime < STALE_SHORT_ROOT_SECONDS
            ):
                continue
            lock = _locked_directory(entry.path, exclusive=True)
            if lock is None:
                continue
            try:
                if not _has_root_marker(lock, info.st_uid):
                    continue
                _CONFINE.short_roots.append(entry.path)
                try:
                    _remove_tree(entry.path, parent)
                except RuntimeError as refused:
                    warnings.warn(
                        f"left {entry.path} in place: {refused}", stacklevel=2
                    )
                else:
                    if os.path.lexists(entry.path):
                        warnings.warn(
                            f"left {entry.path} in place: part of it could not be "
                            "removed",
                            stacklevel=2,
                        )
                    else:
                        removed.append(entry.path)
                finally:
                    _CONFINE.short_roots.remove(entry.path)
            finally:
                os.close(lock)
    return removed


# ---------------------------------------------------------------------------
# The harness
# ---------------------------------------------------------------------------


class _CountingNames:
    """Deterministic ``tempfile`` names, so a temporary path ASH passes is stable."""

    def __init__(self) -> None:
        self._count = 0
        self._lock = threading.Lock()

    def __iter__(self) -> "_CountingNames":
        return self

    def __next__(self) -> str:
        with self._lock:
            name = f"char{self._count:04d}"
            self._count += 1
        return name


#: Resets ``_clear_caches`` runs after its own, added with ``register_cache_reset``.
_CACHE_RESETS: List[Callable[[], None]] = []


def register_cache_reset(reset: Callable[[], None]) -> Callable[[], None]:
    """Call ``reset()`` before and after every characterization test.

    For a memo ASH keeps between calls that the harness does not reset yet, so no
    golden depends on which test ran before it in the same worker. Returns
    ``reset``, so it also works as a decorator.
    """
    if reset not in _CACHE_RESETS:
        _CACHE_RESETS.append(reset)
    return reset


@register_cache_reset
def _forget_prepared_content_databases() -> None:
    """content_db_refresh skips a refresh it already made for the same scan id."""
    module = sys.modules.get("automated_security_helper.utils.content_db_refresh")
    if module is not None:
        module.forget_prepared()


#: The containers fs_guard keeps at its module level in this tree: the roots a write
#: is confined below, and the releases queued by finalizers. The reset needs both;
#: a tree where one is gone has renamed it, and the reset says so.
_SANDBOX_CONTAINERS = ("_writable_roots", "_pending_releases")

#: Containers an older fs_guard also kept: the roots registered for good, and how many
#: blocks hold each root. Cleared when the module has them, never required.
_OLDER_SANDBOX_CONTAINERS = ("_permanent_roots", "_block_counts")


@register_cache_reset
def _forget_sandbox_writable_roots() -> None:
    """fs_guard keeps every results directory a sandbox scope registered; one test's
    roots must not stay writable for the next.

    Every container fs_guard keeps at its module level is cleared: each of
    ``_SANDBOX_CONTAINERS``, and each of ``_OLDER_SANDBOX_CONTAINERS`` it has. If one
    of the first is gone, or the lock is, this raises (an AttributeError naming it),
    and the harness records that as a violation rather than the reset passing over it.
    Any other module-level dict, set, list or deque is left as it is, since it may be
    a constant, and the reset raises an AssertionError naming it: it may be state
    that would stay filled between tests, and is to be added to the lists above (or
    judged not to be state) before the harness runs again."""
    module = sys.modules.get("automated_security_helper.utils.sandbox.fs_guard")
    if module is not None:
        with module._roots_lock:
            for name in _SANDBOX_CONTAINERS:
                getattr(module, name).clear()
            for name in _OLDER_SANDBOX_CONTAINERS:
                container = getattr(module, name, None)
                if container is not None:
                    container.clear()
            known = {*_SANDBOX_CONTAINERS, *_OLDER_SANDBOX_CONTAINERS}
            unknown = [
                name
                for name, value in vars(module).items()
                if name not in known
                and not name.startswith("__")
                and isinstance(value, (dict, set, list, collections.deque))
            ]
        if unknown:
            raise AssertionError(
                "fs_guard keeps module-level state this reset does not know: "
                + ", ".join(sorted(unknown))
                + "; add each to _SANDBOX_CONTAINERS (or _OLDER_SANDBOX_CONTAINERS)"
            )


class _CountingUuids:
    """Deterministic ``uuid.uuid4`` for ASH, counted per test like the ``tempfile`` names.

    Only a call made directly from an ``automated_security_helper`` module is
    counted. Anyone else gets a real one: a library drawing uuids when ASH first
    imports it (opentelemetry draws 5) would otherwise move every later count by an
    amount that depends on which test ran first in the worker.
    """

    def __init__(self, real: Callable[[], uuid.UUID]) -> None:
        self._real = real
        self._count = 0
        self._lock = threading.Lock()

    def __call__(self) -> uuid.UUID:
        caller = sys._getframe(1).f_globals.get("__name__") or ""
        if caller.partition(".")[0] != "automated_security_helper":
            return self._real()
        with self._lock:
            value = self._count
            self._count += 1
        return uuid.UUID(int=value, version=4)


#: The instant ``Harness.fix_clock`` stops ASH's clock at.
FIXED_INSTANT = _datetime.datetime(2026, 1, 1, tzinfo=_datetime.timezone.utc)


class _AnswersAsTheRealClass(type):
    """Metaclass for the fixed-clock classes: ``isinstance`` and ``issubclass``
    against one answer as they would against the real class it replaces, so a real
    datetime that ASH parsed or got from a library still passes the check."""

    _real: type

    def __instancecheck__(cls, instance: Any) -> bool:
        return isinstance(instance, cls._real)

    def __subclasscheck__(cls, subclass: type) -> bool:
        return issubclass(subclass, cls._real)


class _FixedDatetime(_datetime.datetime, metaclass=_AnswersAsTheRealClass):
    """``datetime`` whose clock reads ``FIXED_INSTANT``.

    What it returns is an instance of this class, which subclasses the real one, so
    ``isinstance`` holds against either name and arithmetic and serialization behave
    as they do for a real ``datetime``. A real datetime passes ``isinstance``
    against this class too (``_AnswersAsTheRealClass``).
    """

    _real = _datetime.datetime

    @classmethod
    def _at(cls, value: _datetime.datetime) -> "_FixedDatetime":
        return cls(
            value.year,
            value.month,
            value.day,
            value.hour,
            value.minute,
            value.second,
            value.microsecond,
            tzinfo=value.tzinfo,
        )

    @classmethod
    def now(cls, tz: Optional[_datetime.tzinfo] = None) -> "_FixedDatetime":
        if tz is None:
            return cls._at(FIXED_INSTANT.replace(tzinfo=None))
        return cls._at(FIXED_INSTANT.astimezone(tz))

    @classmethod
    def utcnow(cls) -> "_FixedDatetime":
        return cls._at(FIXED_INSTANT.replace(tzinfo=None))

    @classmethod
    def today(cls) -> "_FixedDatetime":
        return cls.utcnow()

    @classmethod
    def fromtimestamp(
        cls, timestamp: float, tz: Optional[_datetime.tzinfo] = None
    ) -> "_FixedDatetime":
        _refuse_real_clock_timestamp(timestamp)
        if tz is None:
            # Naive, in UTC like now(), so an age is the same in every time zone.
            return cls.utcfromtimestamp(timestamp)
        return super().fromtimestamp(timestamp, tz)

    @classmethod
    def utcfromtimestamp(cls, timestamp: float) -> "_FixedDatetime":
        _refuse_real_clock_timestamp(timestamp)
        return cls._at(
            _datetime.datetime.fromtimestamp(timestamp, _datetime.timezone.utc).replace(
                tzinfo=None
            )
        )


class _FixedDate(_datetime.date, metaclass=_AnswersAsTheRealClass):
    """``date`` whose ``today()`` is the date of ``FIXED_INSTANT``."""

    _real = _datetime.date

    @classmethod
    def today(cls) -> _datetime.date:
        return FIXED_INSTANT.date()


def _refuse_real_clock_timestamp(timestamp: float) -> None:
    """Fail the test when ASH converts a timestamp later than ``FIXED_INSTANT``.

    Under ``fix_clock`` such a timestamp can only have come from the real clock (a
    file the test wrote without setting its mtime, or ``time.time()``), and an age
    ASH measures from it against the fixed clock is negative.
    """
    if timestamp > FIXED_INSTANT.timestamp():
        when = _datetime.datetime.fromtimestamp(timestamp, _datetime.timezone.utc)
        raise _GUARDS.violation(
            f"ASH converted the timestamp {when.isoformat()} while the clock is fixed "
            f"at {FIXED_INSTANT.isoformat()}; it is later, so it came from the real "
            "clock (a file mtime or time.time()). Set the dates this test depends on "
            "relative to FIXED_INSTANT, as in "
            "os.utime(path, (FIXED_INSTANT.timestamp() - age,) * 2)"
        )


def _clear_caches() -> None:
    """Forget every memoized lookup and probe ASH keeps between calls."""
    from automated_security_helper.utils import pre_installed_tool, subprocess_utils
    from automated_security_helper.utils import uv_tool_runner

    subprocess_utils.clear_find_executable_cache()
    uv_tool_runner._reset_uv_tool_runner_caches()
    uv_tool_runner.reset_uv_tool_runner()
    pre_installed_tool.reset_pre_installed_tool_cache()
    scope = sys.modules.get("automated_security_helper.utils.sandbox.scope")
    if scope is not None:
        scope.clear_backend_cache()
    backends = sys.modules.get("automated_security_helper.utils.sandbox.backends")
    if backends is not None:
        backends._trust_roots_cache.clear()
    container = sys.modules.get(
        "automated_security_helper.interactions.run_ash_container"
    )
    if container is not None:
        container._BUILDX_SUPPORT_CACHE.clear()
    # Each registered reset on its own: one that raises must not leave the others
    # (or the rest of the harness's cleanup) undone for the rest of the worker. It
    # is recorded as a violation, which fails the test it ran around.
    for reset in list(_CACHE_RESETS):
        try:
            reset()
        except Exception as error:  # noqa: BLE001 - recorded, not swallowed
            _GUARDS.violation(
                f"the cache reset {getattr(reset, '__qualname__', reset)!s} raised "
                f"{type(error).__name__}: {error}"
            )


def _is_pytest_log_handler(handler: logging.Handler) -> bool:
    """One of pytest's own log handlers (caplog's, the report's, the log file's).

    pytest puts them on every non-propagating logger, the ``ash`` logger among them:
    caplog's and the report's for each phase of a test, the log file's for the whole
    run. They come off again when that phase or the run ends, so the harness leaves
    them alone in both directions: neither detached for a cell nor restored after it.
    test_harness.py checks that every handler pytest's logging plugin owns is
    recognized here.
    """
    return type(handler).__module__ == "_pytest.logging"


def _writes_to_the_console(handler: logging.Handler) -> bool:
    """``handler`` writes to the process's standard output or error.

    That is a Rich handler whose console writes there (a console made with no file
    of its own, as ``get_logger`` makes it, writes to whatever ``sys.stdout``, or
    ``sys.stderr``, is when a record arrives), or a ``StreamHandler`` over one of
    them. A handler over a closed stream counts as well: all it can write is
    logging's error report, which goes to ``sys.stderr``. Any other handler (a
    test's collector, a file, a console or stream over a buffer) writes where its
    owner reads, and nothing it writes reaches what a cell prints.
    """
    if isinstance(handler, RichHandler):
        stream = handler.console.file
    elif isinstance(handler, logging.StreamHandler):
        stream = handler.stream
    else:
        return False
    if getattr(stream, "closed", False):
        return True
    standard = (sys.stdout, sys.stderr, sys.__stdout__, sys.__stderr__)
    return any(stream is known for known in standard if known is not None)


def _cell_log_level(level: int, handlers: Sequence[logging.Handler]) -> int:
    """The ``ash`` logger's level in a cell, given its ``level`` and the ``handlers``
    left on it when the harness is entered.

    INFO, the level the goldens are recorded at: bandit and cfn_nag add ``--verbose``
    when the logger is at DEBUG, and the cdk-nag worker gets the logger's level, so
    a level left over from outside the cell must not reach a launch. The exception is
    a level a fixture set up before the harness lowered on purpose: the logger was
    set below INFO, and a handler on it asks for those records (a collector at a
    level below INFO, or at none; ``caplog`` lowered with ``set_level``). The cell
    then keeps that level, so the fixture gets what it gets when set up after the
    harness, whichever order the test lists them in. pytest's handlers at their
    default level ask for nothing: they are on the logger for every test.
    """

    def asks_for_less(handler: logging.Handler) -> bool:
        if _is_pytest_log_handler(handler):
            return logging.NOTSET < handler.level < logging.INFO
        return handler.level < logging.INFO

    if logging.NOTSET < level < logging.INFO and any(
        asks_for_less(handler) for handler in handlers
    ):
        return level
    return logging.INFO


def _restore_logger(
    logger: logging.Logger,
    handlers: Sequence[logging.Handler],
    filters: Sequence[Any],
) -> None:
    """Put ``logger``'s handlers and filters back to ``handlers`` and ``filters``,
    by identity. pytest's own handlers are not touched (_is_pytest_log_handler)."""
    for handler in list(logger.handlers):
        if not _is_pytest_log_handler(handler) and not any(
            handler is kept for kept in handlers
        ):
            logger.removeHandler(handler)
    for handler in handlers:
        if not _is_pytest_log_handler(handler) and not any(
            handler is present for present in logger.handlers
        ):
            logger.addHandler(handler)
    for log_filter in list(logger.filters):
        if not any(log_filter is kept for kept in filters):
            logger.removeFilter(log_filter)
    for log_filter in filters:
        if not any(log_filter is present for present in logger.filters):
            logger.addFilter(log_filter)


#: What ``_replaced_default`` returns for a default it leaves alone.
_NOT_REPLACED = object()


def _replaced_default(default: Any, old: Any, new: Any) -> Any:
    """What a function default or typer option default becomes when ``old`` is
    replaced by ``new``; ``_NOT_REPLACED`` when it stays.

    ``old`` itself becomes ``new``. When ``old`` is a path, a default that is its
    text becomes the text of ``new`` (``new`` itself when that is not a path, as
    when the product has no ``~/.ash/bin``): a default made as ``str(ASH_BIN_PATH)``
    at import holds the text, and never is ``old``.
    """
    if default is old:
        return new
    if (
        isinstance(old, os.PathLike)
        and isinstance(default, str)
        and default == os.fspath(old)
    ):
        return os.fspath(new) if isinstance(new, os.PathLike) else new
    return _NOT_REPLACED


class Harness:
    """One test's directories, environment, tool doubles and launch records."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = Path(tmp)
        self.src = self.tmp / "src"
        self.out = self.tmp / "out"
        self.work = self.tmp / "work"
        self.home = self.tmp / "home"
        self.bin = self.tmp / "bin"
        self.sysbin = self.tmp / "sysbin"
        self.usrlocalbin = self.tmp / "usr-local-bin"
        self.ashbin = self.tmp / "ashbin"
        # ASH's own environment: the interpreter's directory and its scripts
        # directory, where pip and uv put the console scripts of ASH's packages, and
        # the uv package ASH imports, whose layout puts its executable in bin/.
        self.pyenv = self.tmp / "py-env"
        self.pyenvbin = self.pyenv / "bin"
        self.uv_package_dir = self.pyenv / "lib" / "python3" / "site-packages" / "uv"
        self.ash_bin_default = self.home / ".ash" / "bin"
        self.tmpdir = self.tmp / "tmp"
        self.xdg = {
            name: self.tmp / "xdg" / name
            for name in ("config", "cache", "data", "state")
        }
        self.uv_tool_dir = self.tmp / "uv" / "tools"
        self.uv_cache_dir = self.tmp / "uv" / "cache"
        for directory in (
            self.src,
            self.out,
            self.work,
            self.home,
            self.bin,
            self.sysbin,
            self.usrlocalbin,
            self.ashbin,
            self.pyenvbin,
            self.tmpdir,
            *self.xdg.values(),
            self.uv_tool_dir,
            self.uv_cache_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        self.env: Dict[str, str] = {
            "PATH": os.pathsep.join([str(self.bin), str(self.sysbin)]),
            "HOME": str(self.home),
            "XDG_CONFIG_HOME": str(self.xdg["config"]),
            "XDG_CACHE_HOME": str(self.xdg["cache"]),
            "XDG_DATA_HOME": str(self.xdg["data"]),
            "XDG_STATE_HOME": str(self.xdg["state"]),
            "UV_TOOL_DIR": str(self.uv_tool_dir),
            "UV_CACHE_DIR": str(self.uv_cache_dir),
            "ASH_BIN_PATH": str(self.ashbin),
            "TMPDIR": str(self.tmpdir),
            "LANG": "C.UTF-8",
            "UV_OFFLINE": "1",
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_CONFIG_FILE": str(self.tmp / "none"),
            "AWS_SHARED_CREDENTIALS_FILE": str(self.tmp / "none"),
        }
        roots: Dict[str, Union[str, Path]] = {
            "<SRC>": self.src,
            "<OUT>": self.out,
            "<WORK>": self.work,
            "<HOME>": self.home,
            "<BIN>": self.bin,
            "<SYSBIN>": self.sysbin,
            "<USRLOCALBIN>": self.usrlocalbin,
            "<ASHBIN>": self.ashbin,
            "<PYENVBIN>": self.pyenvbin,
            "<TMPDIR>": self.tmpdir,
            "<XDG_CONFIG_HOME>": self.xdg["config"],
            "<XDG_CACHE_HOME>": self.xdg["cache"],
            "<XDG_DATA_HOME>": self.xdg["data"],
            "<XDG_STATE_HOME>": self.xdg["state"],
            "<UV_TOOL_DIR>": self.uv_tool_dir,
            "<UV_CACHE_DIR>": self.uv_cache_dir,
            "<TMP>": self.tmp,
        }
        # The test's own directories, which may be reached through a symlink
        # (/tmp on macOS), are also replaced as resolved, and so are the two
        # interpreter prefixes: on 3.10 here sys.base_prefix is spelled through a
        # symlinked home, and ASH resolves the interpreter to find it. The
        # interpreters themselves are not, because each spelling is its own launch.
        resolved = list(roots) + ["<PYPREFIX>", "<PYBASEPREFIX>"]
        roots.update(_interpreter_roots())
        roots["<PKG>"] = PACKAGE_DIR
        roots["<REPO>"] = REPO_ROOT
        self.normalizer = Normalizer(roots, resolved=resolved)
        self.snapshot_extension = type(
            "CharacterizationJSONExtension",
            (CharacterizationJSONExtension,),
            {"normalizer": self.normalizer},
        )
        self.doubles: Dict[str, Callable[[ToolCall], Outcome]] = {}
        self.stand_ins: Dict[str, str] = {}
        # Fake pid -> its FakePopen, held strongly for the harness's life, so a
        # signal, wait or group kill on the pid finds it after the product drops
        # the object (see "Pitfalls" for what that means for weakref.finalize).
        self._processes: Dict[int, "FakePopen"] = {}
        self._seam_function: Optional[Callable[[], List[Path]]] = None
        self.launches: List[LaunchRecord] = []
        #: Each pipe a launch passed in ``pass_fds``, by inode, numbered in the order
        #: the test first passed it (see ``_passed_descriptors``).
        self._passed_pipes: Dict[int, int] = {}
        #: Each ``"<fd>:<inode>"`` a launch passed, with the token it is recorded as.
        self._passed_spellings: Dict[str, str] = {}
        self.sleeps: List[float] = []
        self._phase: Optional[str] = None
        self._fixture_paths: set = set()
        self._source_state: Dict[str, str] = {}
        self._python_wrappers: List[Callable[[ToolCall], Optional[Outcome]]] = []
        # Resolved path -> (fixture name, sha256) for each ToolCall.write_fixture.
        self._fixture_writes: Dict[str, Tuple[str, str]] = {}
        self._parent_env: Dict[str, str] = dict(self.env)
        self._lock = threading.Lock()
        self._restore: List[Callable[[], None]] = []
        # The host directories path_independent_dirs() names, and the harness
        # directory each one is replaced by.
        self._host_exec_dirs: Dict[str, Path] = {"/usr/local/bin": self.usrlocalbin}
        for directory in _own_environment_host_dirs():
            self._host_exec_dirs.setdefault(directory, self.pyenvbin)
        self._own_environment_function: Optional[Callable[[], List[Path]]] = None
        self._uv_package_function: Optional[Callable[[], Optional[Path]]] = None
        # The interpreter every stand-in's #! line names (see tool()). It has no
        # double, so anything that runs it fails the test.
        self.tool("sh", on="sysbin", interpreter=None)
        self._refuse_marked_ancestors()

    #: Files that, in any directory above the test's tree, ASH or a tool would read
    #: as part of the scan: git finds the checkout, semgrep its ignore file.
    ANCESTOR_MARKERS = (".git", ".semgrepignore")

    def _refuse_marked_ancestors(self) -> None:
        for ancestor in Path(os.path.realpath(self.tmp)).parents:
            for marker in self.ANCESTOR_MARKERS:
                if os.path.lexists(ancestor / marker):
                    raise RuntimeError(
                        f"{ancestor / marker} exists above the harness root {self.tmp}; "
                        "git or a scanner would read it, so a golden would depend on "
                        "it. Run with a basetemp outside any checkout."
                    )

    # -- lifecycle ---------------------------------------------------------

    @contextlib.contextmanager
    def active(self) -> Iterator["Harness"]:
        """Make this the harness launches go to, with its hermetic environment.

        The ``ash`` logger is part of that environment. Inside, it logs at INFO
        unless a fixture set up before the harness lowered it for a collector
        (_cell_log_level), and a handler on it that writes to the console
        (_writes_to_the_console) is taken off: a CLI command an earlier test ran
        in-process leaves one that writes to whatever ``sys.stdout`` is at the time,
        and it must not write into a golden through ``capsys``. pytest's own
        handlers, and a handler that writes where its owner reads (a fixture that
        collects the warnings its test checks), stay on. On the way out the logger
        gets back the handlers, filters and level it had, and loses any the cell
        added.

        Requires the guards (the package's autouse fixture) to be installed.
        """
        if not _GUARDS.installed:
            raise RuntimeError("the characterization guards are not installed")
        if _GUARDS.harness is not None:
            raise RuntimeError("another characterization harness is active")
        from automated_security_helper.utils.log import ASH_LOGGER

        saved_env = dict(os.environ)
        saved_cwd = os.getcwd()
        saved_tempdir = tempfile.tempdir
        saved_names = getattr(tempfile, "_name_sequence", None)
        saved_level = ASH_LOGGER.level
        saved_handlers = list(ASH_LOGGER.handlers)
        saved_filters = list(ASH_LOGGER.filters)
        # Everything after the saves is undone by the finally, including when a
        # step of the setup itself raises.
        try:
            _clear_caches()
            os.environ.clear()
            os.environ.update(self.env)
            os.chdir(self.tmp)
            tempfile.tempdir = str(self.tmpdir)
            tempfile._name_sequence = _CountingNames()  # type: ignore[attr-defined]
            for handler in list(ASH_LOGGER.handlers):
                if not _is_pytest_log_handler(handler) and _writes_to_the_console(
                    handler
                ):
                    ASH_LOGGER.removeHandler(handler)
            ASH_LOGGER.setLevel(_cell_log_level(saved_level, ASH_LOGGER.handlers))
            _GUARDS.harness = self
            self._patch(uuid, "uuid4", _CountingUuids(uuid.uuid4))
            self._install_lookup_seam()
            self._install_account_seam()
            self.begin()
            yield self
        finally:
            _GUARDS.harness = None
            for undo in reversed(self._restore):
                undo()
            self._restore.clear()
            self._sweep_seam_leaks()
            _clear_caches()
            _restore_logger(ASH_LOGGER, saved_handlers, saved_filters)
            ASH_LOGGER.setLevel(saved_level)
            tempfile._name_sequence = saved_names  # type: ignore[attr-defined]
            tempfile.tempdir = saved_tempdir
            os.chdir(saved_cwd)
            os.environ.clear()
            os.environ.update(saved_env)

    def _patch(self, owner: Any, attr: str, value: Any) -> None:
        original = getattr(owner, attr)
        setattr(owner, attr, value)
        self._restore.append(lambda: setattr(owner, attr, original))

    def _passwd(self, uid: int, name: str) -> Any:
        import pwd

        return pwd.struct_passwd(
            (name, "x", uid, os.getgid(), "", str(self.home), "/bin/sh")
        )

    def _install_account_seam(self) -> None:
        """Answer ``pwd`` lookups with the harness account, home ``<HOME>``.

        ``os.path.expanduser``, ``Path.home()`` and ``getpass.getuser()`` fall back to
        ``pwd`` when HOME (or LOGNAME and USER) are unset, which would hand a test
        the real account's home. Every name and uid gets the harness account.
        """
        import pwd

        self._patch(pwd, "getpwuid", lambda uid: self._passwd(int(uid), "char"))
        self._patch(pwd, "getpwnam", lambda name: self._passwd(os.getuid(), str(name)))
        self._patch(pwd, "getpwall", lambda: [self._passwd(os.getuid(), "char")])

    def _patch_defaults(self, function: Any, old: Any, new: Any) -> None:
        """Replace ``old`` among ``function``'s defaults, and inside typer options.

        A default that is ``old`` itself becomes ``new``. When ``old`` is a path, a
        default that is its text (``str(ASH_BIN_PATH)`` at import) becomes the text
        of ``new`` (see ``_replaced_default``)."""
        defaults = getattr(function, "__defaults__", None)
        if defaults:
            replaced = [_replaced_default(d, old, new) for d in defaults]
            if any(r is not _NOT_REPLACED for r in replaced):
                self._patch(
                    function,
                    "__defaults__",
                    tuple(
                        d if r is _NOT_REPLACED else r
                        for d, r in zip(defaults, replaced)
                    ),
                )
        kwdefaults = getattr(function, "__kwdefaults__", None)
        if kwdefaults:
            replaced_by_name = {
                k: _replaced_default(d, old, new) for k, d in kwdefaults.items()
            }
            if any(r is not _NOT_REPLACED for r in replaced_by_name.values()):
                self._patch(
                    function,
                    "__kwdefaults__",
                    {
                        k: d
                        if replaced_by_name[k] is _NOT_REPLACED
                        else replaced_by_name[k]
                        for k, d in kwdefaults.items()
                    },
                )
        # A typer.Option/typer.Argument default holds its value in ``.default``.
        for default in list(defaults or ()) + list((kwdefaults or {}).values()):
            if hasattr(default, "param_decls"):
                replacement = _replaced_default(
                    getattr(default, "default", None), old, new
                )
                if replacement is not _NOT_REPLACED:
                    self._patch(default, "default", replacement)

    def _install_lookup_seam(self) -> None:
        """Put every directory ASH searches for tools inside the harness.

        * PATH is ``<BIN>:<SYSBIN>`` (set with the environment), and ``os.defpath``,
          which exec searches when an environment has no PATH, is ``<SYSBIN>``.
        * ``subprocess_utils.path_independent_dirs`` is the product's own function
          with ``/usr/local/bin`` replaced by ``<USRLOCALBIN>``, and the
          interpreter's own directory and scripts directory by ``<PYENVBIN>``. Any
          other host directory it ever returns is a violation, not a pass-through.
        * Where the product looks up ASH's own environment, those lookups answer
          with harness paths: ``own_environment_dirs()`` is ``[<PYENVBIN>]``, and
          the uv package's install directory (``_uv_package_directory()``) is
          ``<TMP>/py-env/lib/python3/site-packages/uv``, whose layout puts the uv
          executable in ``<PYENVBIN>``. Where the product has neither, nothing is
          patched in their place.
        * The import-time ``ASH_BIN_PATH`` (``core.constants``, and every module
          that imported it by name), which ``_bin_path`` falls back to when the
          variable is unset, is ``<HOME>/.ash/bin``: the product's default under
          the harness HOME.
        """
        real = REAL_PATH_INDEPENDENT_DIRS
        own_real = REAL_OWN_ENVIRONMENT_DIRS
        package_real = REAL_UV_PACKAGE_DIRECTORY

        def path_independent_dirs() -> List[Path]:
            return [self._lookup_dir(directory) for directory in real()]

        def own_environment_dirs() -> List[Path]:
            return [self.pyenvbin]

        def uv_package_directory() -> Optional[Path]:
            return self.uv_package_dir

        path_independent_dirs.__wrapped__ = real  # type: ignore[attr-defined]
        own_environment_dirs.__wrapped__ = own_real  # type: ignore[attr-defined]
        uv_package_directory.__wrapped__ = package_real  # type: ignore[attr-defined]
        self._seam_function = path_independent_dirs
        if own_real is not None:
            self._own_environment_function = own_environment_dirs
        if package_real is not None:
            self._uv_package_function = uv_package_directory
        for module_name, module in list(sys.modules.items()):
            if (
                not module_name.startswith("automated_security_helper")
                or module is None
            ):
                continue
            for attr, value in list(vars(module).items()):
                if value is real:
                    self._patch(module, attr, path_independent_dirs)
                elif own_real is not None and value is own_real:
                    self._patch(module, attr, own_environment_dirs)
                elif package_real is not None and value is package_real:
                    self._patch(module, attr, uv_package_directory)
                elif value is REAL_ASH_BIN_PATH:
                    self._patch(module, attr, self.ash_bin_default)
                elif (
                    isinstance(value, types.FunctionType)
                    and value.__module__ == module_name
                ):
                    # Defaults bound at import: dependencies install's
                    # typer.Option(str(ASH_BIN_PATH)) is one, bound as text.
                    self._patch_defaults(value, REAL_ASH_BIN_PATH, self.ash_bin_default)
        self._patch(os, "defpath", str(self.sysbin))

    def _sweep_seam_leaks(self) -> None:
        """Undo the seam in modules first imported during the test.

        A module imported while the seam was in place bound this test's
        ``<HOME>/.ash/bin`` (from core.constants) or its ``path_independent_dirs``
        closure, at module level, in a function default or in a typer option; the
        restore list does not know about it. Each such value goes back to the
        product's own before the next test runs.
        """
        replacements = (
            (self.ash_bin_default, REAL_ASH_BIN_PATH),
            (self._seam_function, REAL_PATH_INDEPENDENT_DIRS),
            (self._own_environment_function, REAL_OWN_ENVIRONMENT_DIRS),
            (self._uv_package_function, REAL_UV_PACKAGE_DIRECTORY),
        )
        for module_name, module in list(sys.modules.items()):
            if (
                not module_name.startswith("automated_security_helper")
                or module is None
            ):
                continue
            for attr, value in list(vars(module).items()):
                for leaked, product in replacements:
                    if leaked is not None and value is leaked:
                        setattr(module, attr, product)
                if isinstance(value, types.FunctionType):
                    for leaked, product in replacements:
                        if leaked is None:
                            continue
                        self._patch_defaults(value, leaked, product)
        # _patch_defaults queued restores of the leaked values; they must not run.
        self._restore.clear()

    def _lookup_dir(self, directory: Path) -> Path:
        text = os.fspath(directory)
        if not os.path.isabs(text) or self._is_harness_path(text):
            return Path(directory)
        mapped = self._host_exec_dirs.get(os.path.normpath(text))
        if mapped is None:
            raise _GUARDS.violation(
                f"path_independent_dirs() returned {text}, a host directory with no "
                "harness stand-in; add one to Harness._host_exec_dirs"
            )
        return Path(mapped)

    def _confined(self, path: Union[str, os.PathLike]) -> bool:
        """Whether ``path`` is in this test's tree, as written and after symlinks.

        The symlinks are followed with the real ``lstat`` (``_real_path``), so a path
        that a link sends into a host executable directory is judged as outside the
        tree without a probe of that directory."""
        text = os.fspath(path)
        absolute = text if os.path.isabs(text) else os.path.join(os.getcwd(), text)
        if not self._is_harness_path(absolute):
            return False
        real = Path(_real_path(absolute))
        return real.is_relative_to(os.path.realpath(self.tmp))

    def _is_harness_path(self, path: str) -> bool:
        """Whether ``path`` lies inside this test's tmp tree (relative paths do)."""
        if not os.path.isabs(path):
            return True
        normalized = Path(os.path.normpath(path))
        return normalized.is_relative_to(self.tmp) or normalized.is_relative_to(
            os.path.realpath(self.tmp)
        )

    def begin(self) -> None:
        """Start the scenario: what exists now is the test's own, and so is the env.

        Everything now under the tmp path counts as a fixture file, which argv
        capture leaves out, and the process environment now is the golden's
        ``parent_env``, which each launch's environment is recorded against.
        ``<SRC>`` is remembered as it is now: what ASH adds, changes or removes
        there afterwards is captured from argv and shows in the golden's tree.
        """
        self._fixture_paths = {str(p) for p in self.tmp.rglob("*")}
        self._fixture_paths.add(str(self.tmp))
        self._source_state = {
            str(path): self._entry_state(path)
            for path in [self.src, *self.src.rglob("*")]
        }
        self._parent_env = {k: v for k, v in os.environ.items() if k != PYTEST_ENV_KEY}

    @staticmethod
    def _entry_state(path: Path) -> str:
        if path.is_symlink():
            return f"symlink:{os.readlink(path)}"
        if path.is_dir():
            return "dir"
        special = _special_file(path)
        if special is not None:
            return special
        return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"

    def _source_changed(self, path: Path) -> bool:
        """Whether ``path``, under ``<SRC>``, is new or different since ``begin()``."""
        try:
            now = self._entry_state(path)
        except OSError:
            return False
        return self._source_state.get(str(path)) != now

    @contextlib.contextmanager
    def phase(self, label: str) -> Iterator[None]:
        """Label the launches made inside this block (``construct``, ``scan``, ...)."""
        previous, self._phase = self._phase, label
        try:
            yield
        finally:
            self._phase = previous

    # -- declaring the world ----------------------------------------------

    def tool(
        self,
        name: str,
        double: Optional[Callable[[ToolCall], Outcome]] = None,
        *,
        on: Union[str, Path, None] = "path",
        executable: bool = True,
        interpreter: Any = _SYSBIN_SH,
    ) -> Optional[Path]:
        """Declare a tool: a stand-in executable where ``on`` says, and its double.

        ``on``: ``"path"`` (``<BIN>``, first on PATH), ``"sysbin"`` (``<SYSBIN>``,
        second on PATH, where /usr/bin and /bin would be), ``"usrlocalbin"``
        (``<USRLOCALBIN>``, which stands in for /usr/local/bin), ``"ashbin"``
        (ASH_BIN_PATH), ``"pyenvbin"`` (``<PYENVBIN>``, which stands in for the
        directories of ASH's own environment), a directory, or None for a tool
        reached only through a wrapper such as ``uv tool run``. ``executable=False`` leaves the stand-in
        without its execute bit. Returns the stand-in's path.

        ``interpreter`` is what the stand-in's ``#!`` line names: by default
        ``<SYSBIN>/sh``, itself a stand-in that fails the test if anything runs it,
        so code that reads a shebang (the sandbox policy, pre_installed_tool) reads
        only harness files. ``None`` writes no ``#!`` line, as for a compiled tool
        such as grype or syft; any other path is written as given.
        """
        path: Optional[Path] = None
        if on is not None:
            if isinstance(on, str):
                directory = {
                    "path": self.bin,
                    "sysbin": self.sysbin,
                    "usrlocalbin": self.usrlocalbin,
                    "ashbin": self.ashbin,
                    "pyenvbin": self.pyenvbin,
                }[on]
            else:
                directory = Path(on)
                if not self._confined(directory):
                    raise ValueError(
                        f"tool({name!r}, on={on}) is outside the test's directory "
                        f"{self.tmp}"
                    )
            directory.mkdir(parents=True, exist_ok=True)
            path = directory / name
            if interpreter is _SYSBIN_SH:
                interpreter = self.sysbin / "sh"
            path.write_text(stand_in_script(interpreter), encoding="utf-8")
            path.chmod(0o755 if executable else 0o644)
            self.stand_ins[str(path)] = name
        if double is not None:
            self.doubles[name] = double
        return path

    def absent(self, *names: str) -> None:
        """Require that no lookup directory holds ``names``.

        Every directory ASH searches is a harness directory (see
        ``_install_lookup_seam``), so this states the scenario rather than reads
        the host. It fails only if the test itself put a stand-in there. ``sh``
        can never be absent: ``<SYSBIN>/sh`` is the interpreter every stand-in
        names (see ``tool``), so asking for it raises ValueError.
        """
        if "sh" in names:
            raise ValueError(
                "sh cannot be absent: <SYSBIN>/sh is the interpreter every stand-in "
                "names. A scenario that needs sh missing cannot be written with this "
                "harness."
            )
        dirs = [Path(d) for d in os.get_exec_path(os.environ)]
        dirs += _subprocess_utils.path_independent_dirs()
        for name in names:
            for directory in dirs:
                candidate = directory / name
                if candidate.exists():
                    pytest.fail(
                        f"{candidate} exists, so {name} is not absent",
                        pytrace=False,
                    )

    def write_source(
        self, files: Mapping[str, str], root: Optional[Path] = None
    ) -> None:
        """Write fixture files under ``<SRC>`` (or ``root``, inside the test's tree)."""
        base = self.src if root is None else Path(root)
        for relative, content in files.items():
            target = base / relative
            if not self._confined(target):
                raise ValueError(
                    f"write_source() target {target} is outside the test's directory "
                    f"{self.tmp}"
                )
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

    def set_env(self, **values: Optional[str]) -> None:
        """Change the hermetic environment for this scenario (None removes)."""
        for key, value in values.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def skip_sleeps(self) -> None:
        """Make ``time.sleep`` return at once, counting each call in ``sleeps``."""
        original = time.sleep

        def sleep(seconds: float) -> None:
            self.sleeps.append(seconds)

        time.sleep = sleep  # type: ignore[assignment]
        self._restore.append(lambda: setattr(time, "sleep", original))

    def fix_clock(self) -> None:
        """Stop ASH's clock at ``FIXED_INSTANT`` for the rest of the test.

        Replaces the ``datetime`` and ``date`` classes in every ASH module that
        imported them by name: those loaded now, and those ASH first imports later
        in the test, as each one finishes loading. "Pitfalls" in the module
        docstring lists exactly which clocks move and which stay real.
        """
        import importlib.machinery

        fixed = {_datetime.datetime: _FixedDatetime, _datetime.date: _FixedDate}

        def fix(module: types.ModuleType) -> None:
            for attr, value in list(vars(module).items()):
                if isinstance(value, type) and value in fixed:
                    self._patch(module, attr, fixed[value])

        for module_name, module in list(sys.modules.items()):
            if module_name.partition(".")[0] == "automated_security_helper" and (
                module is not None
            ):
                fix(module)
        loader = importlib.machinery.SourceFileLoader
        shadowed = vars(loader).get("exec_module")
        load = loader.exec_module

        def exec_module(self_: Any, module: types.ModuleType) -> None:
            load(self_, module)
            if module.__name__.partition(".")[0] == "automated_security_helper":
                fix(module)

        loader.exec_module = exec_module  # type: ignore[method-assign]
        if shadowed is None:
            self._restore.append(lambda: delattr(loader, "exec_module"))
        else:
            self._restore.append(lambda: setattr(loader, "exec_module", shadowed))

    def permit(self, api: str, handler: Callable[..., Any]) -> None:
        """Declare a guarded API such as ``os.system``: it is recorded, then handled."""
        _GUARDS.permits[api] = handler

    def plugin_context(self, **overrides: Any) -> Any:
        from automated_security_helper.base.plugin_context import PluginContext
        from automated_security_helper.config.default_config import get_default_config

        arguments = {
            "source_dir": self.src,
            "output_dir": self.out,
            "work_dir": self.work,
            "config": get_default_config(),
        }
        arguments.update(overrides)
        return PluginContext(**arguments)

    def take_violations(self) -> List[str]:
        """Return and clear the violations recorded so far (for the self-tests)."""
        return take_violations()

    def allow_root_relative(self, root: Union[str, os.PathLike]) -> str:
        """Also normalize ``root`` (one of this harness's directories, such as
        ``char.src``) where a tool spells it without its leading ``/``.

        Off by default. The spelling becomes ``<TOKEN:relative>``; see
        ``Normalizer.allow_relative``. Returns that token.
        """
        spelling = os.fspath(root).rstrip("/")
        for candidate, token in self.normalizer._roots:
            if candidate == spelling:
                return self.normalizer.allow_relative(token)
        raise ValueError(f"{root} is not one of this harness's roots")

    # -- running a scanner the way ScanPhase does --------------------------

    def run_scanner(
        self,
        scanner_cls: type,
        config: Any = None,
        *,
        targets: Sequence[str] = ("source",),
        global_ignore_paths: Sequence[Any] = (),
        context: Any = None,
    ) -> Dict[str, Any]:
        """``_run_scanner``, as one run (``sandbox_grants.dropped_ceilings_named_once``),
        as the scan it stands in for is: a warning ASH gives once in a run, such as a
        tool config path refused for being in the scanned tree, is given once for all
        of construct, validate and scan."""
        from automated_security_helper.config.sandbox_grants import (
            dropped_ceilings_named_once,
        )

        with dropped_ceilings_named_once():
            return self._run_scanner(
                scanner_cls,
                config,
                targets=targets,
                global_ignore_paths=global_ignore_paths,
                context=context,
            )

    def _run_scanner(
        self,
        scanner_cls: type,
        config: Any = None,
        *,
        targets: Sequence[str] = ("source",),
        global_ignore_paths: Sequence[Any] = (),
        context: Any = None,
    ) -> Dict[str, Any]:
        """Construct, validate, select and scan, each as ScanPhase and ScannerExecutor do.

        Construction and the dependency check run inside ``plugin_probe_scope``, as
        in ScanPhase; a scanner whose check fails is not scanned (ScanPhase records
        it MISSING). The dependencies are checked once. A satisfied scanner is
        selected without a second check (``outcome["select"]``, selected True). A
        selected scanner is run by
        ``ScannerExecutor._execute_scanner`` over the
        ``targets`` (``source`` is ``<SRC>``, ``converted`` is ``<WORK>``). Returns the
        outcome to put in the golden, with stderr excerpts replaced by their markers
        (``fold_stderr_excerpts``).
        """
        from automated_security_helper.core.phases.scanner_executor import (
            ScannerExecutor,
        )
        from automated_security_helper.utils.sandbox.scope import plugin_probe_scope

        context = context if context is not None else self.plugin_context()
        self.begin()
        with self.phase("construct"):
            with plugin_probe_scope(scanner_cls, context):
                scanner = scanner_cls(context=context, config=config)
        with self.phase("validate"):
            with plugin_probe_scope(scanner, context):
                satisfied = scanner.validate_plugin_dependencies()
            scanner.dependencies_satisfied = satisfied
        outcome: Dict[str, Any] = {
            "validate": {
                "satisfied": satisfied,
                "dependency_unavailable_reason": scanner.dependency_unavailable_reason,
                "use_uv_tool": scanner.use_uv_tool,
            }
        }
        selected = False
        if satisfied:
            # ScanPhase checks the dependencies once, in the probe scope above, and
            # applies only the Python-only filter after it (not applied here: the
            # harness scans every kind of scanner). A satisfied scanner is selected.
            selected = True
            outcome["select"] = {
                "selected": selected,
                "dependency_unavailable_reason": scanner.dependency_unavailable_reason,
                "use_uv_tool": scanner.use_uv_tool,
            }
        containers: List[Any] = []
        if selected:
            executor = ScannerExecutor(
                plugin_context=context, progress_display=None, scanner_tasks=[]
            )
            executor._global_ignore_paths = list(global_ignore_paths)
            paths = {"source": self.src, "converted": self.work}
            with self.phase("scan"):
                containers = executor._execute_scanner(
                    str(scanner.config.name),
                    scanner,
                    [{"path": paths[t], "type": t} for t in targets],
                )
        outcome["containers"] = [_container_summary(c) for c in containers]
        outcome["scanner"] = _scanner_summary(scanner)
        logs = {
            str(path): path.read_text(encoding="utf-8", errors="replace")
            for path in sorted(self.out.rglob("*.stderr.log"))
            if path.is_file()
        }
        return fold_stderr_excerpts(outcome, logs)

    # -- running a converter the way ConvertPhase does ---------------------

    def run_converter(
        self,
        converter_cls: type,
        config: Any = None,
        *,
        context: Any = None,
    ) -> Dict[str, Any]:
        """Construct, validate, filter and convert, each step as ConvertPhase does.

        ConvertPhase stores each converter's ``validate_plugin_dependencies()`` on
        ``dependencies_satisfied`` (an exception counts as False), then filters
        through ``filter_enabled_plugins``, which asks the same question again, and
        calls ``convert()`` only on a converter that survives. A dropped converter is
        asked for ``candidate_input_count()`` instead. No sandbox scope applies to a
        converter. Launches are labeled ``construct``, ``validate``, ``filter`` and
        ``convert``. An exception from ``convert()`` is recorded, as ConvertPhase
        records it, rather than raised. Returns the outcome to put in the golden.
        """
        from automated_security_helper.core.phases.convert_phase import ConvertPhase

        context = context if context is not None else self.plugin_context()
        self.begin()
        with self.phase("construct"):
            converter = converter_cls(context=context, config=config)
        with self.phase("validate"):
            try:
                satisfied = converter.validate_plugin_dependencies()
                validate_error = None
            except Exception as error:
                satisfied = False
                validate_error = f"{type(error).__name__}: {error}"
            converter.dependencies_satisfied = satisfied
        with self.phase("filter"):
            survivors = ConvertPhase(plugin_context=context).filter_enabled_plugins(
                plugin_instances=[converter], plugin_context=context, python_only=False
            )
        outcome: Dict[str, Any] = {
            "validate": {"satisfied": satisfied, "error": validate_error},
            "filtered_in": any(s is converter for s in survivors),
        }
        if outcome["filtered_in"]:
            with self.phase("convert"):
                try:
                    result = converter.convert()
                    outcome["failure"] = None
                except Exception as error:
                    result = None
                    outcome["failure"] = f"{type(error).__name__}: {error}"
            items = [] if result is None else result
            if not isinstance(items, list):
                items = [items]
            outcome["converted"] = [Path(item).as_posix() for item in items]
        else:
            with self.phase("filter"):
                outcome["candidate_inputs"] = converter.candidate_input_count()
        outcome["converter"] = _converter_summary(converter)
        return outcome

    # -- the golden ---------------------------------------------------------

    def golden(
        self, outcome: Any = None, *, trees: Optional[Sequence[Path]] = None
    ) -> Dict[str, Any]:
        """The environment, launches, outcome, and the files under ``<OUT>`` and
        ``<WORK>`` afterwards, with what changed under ``<SRC>`` since ``begin()``
        (a removed entry is ``{"removed": true}``)."""
        tree: Dict[str, Any] = {}
        for root in trees if trees is not None else (self.out, self.work):
            tree.update(self.tree(root))
        present = {str(path) for path in self.src.rglob("*")}
        for text in sorted(present):
            if self._source_changed(Path(text)):
                tree[text] = self._entry(Path(text))
        for text in sorted(set(self._source_state) - present - {str(self.src)}):
            tree[text] = {"removed": True}
        return {
            "parent_env": dict(self._parent_env),
            "launches": [
                record.as_golden(self._parent_env) for record in self.launches
            ],
            "outcome": outcome,
            "tree": tree,
        }

    def tree(self, root: Path) -> Dict[str, Any]:
        """Every file and directory under ``root``, with normalized content."""
        return {str(path): self._entry(path) for path in sorted(Path(root).rglob("*"))}

    def _entry(self, path: Path) -> Any:
        if path.is_symlink():
            return {"symlink": os.readlink(path)}
        if path.is_dir():
            return {"dir": True}
        special = _special_file(path)
        if special is not None:
            return {special: True}
        return Normalized(self._file_content(path))

    def _file_content(self, path: Path) -> Dict[str, Any]:
        """``{"fixture": name}`` for a file a double wrote with ``write_fixture``
        and nothing changed since; otherwise its content."""
        data = path.read_bytes()
        written = self._fixture_writes.get(os.path.realpath(path))
        if written is not None and hashlib.sha256(data).hexdigest() == written[1]:
            return {"fixture": written[0]}
        return _content(data, self.normalizer)

    def serialize(self, data: Any) -> str:
        """The text a golden of ``data`` would hold."""
        return serialize(self.normalizer, data)

    def passed_pipes_text(self, text: str) -> str:
        """``text`` with each ``"<fd>:<inode>"`` of a pipe this test passed as its token.

        For text a launch's argv reached without being recorded as argv, such as the
        message of the ``TimeoutExpired`` ``subprocess`` builds from the command. Only
        the exact spellings ``_passed_descriptors`` recorded are replaced, and only
        where no digit continues them on either side; no pattern is matched.
        """
        with self._lock:
            spellings = sorted(self._passed_spellings.items(), key=lambda p: -len(p[0]))
        for spelling, token in spellings:
            out: List[str] = []
            start = 0
            found = text.find(spelling)
            while found >= 0:
                end = found + len(spelling)
                bounded = (found == 0 or not text[found - 1].isdigit()) and (
                    end == len(text) or not text[end].isdigit()
                )
                if bounded:
                    out += [text[start:found], token]
                    start = end
                found = text.find(spelling, end if bounded else found + 1)
            text = "".join(out) + text[start:]
        return text

    # -- internals ------------------------------------------------------------

    def _passed_descriptors(
        self, descriptors: Sequence[int]
    ) -> Tuple[List[str], Dict[str, str]]:
        """``pass_fds`` as the golden records it, and the argv elements to replace.

        A descriptor's number depends on what else the worker has open, and a pipe's
        inode on the kernel, so neither may reach a golden. The n-th distinct pipe (by
        inode) this test passes is ``<PASS_FDn>``, counted per test as the ``tempfile``
        names are, and an argv element that is exactly ``"<fd>:<inode>"`` for it (the
        sandbox wrapper's ``--start-report`` value) is ``"<PASS_FDn>:<PASS_FDn_INODE>"``.
        Any other descriptor is recorded as a stdio descriptor is (``_disposition``).
        Returns the recorded list and ``{"<fd>:<inode>": its token}``.
        """
        import stat as _stat

        recorded: List[str] = []
        replace: Dict[str, str] = {}
        for fd in descriptors:
            try:
                status = os.fstat(fd)
            except OSError:
                recorded.append(_disposition(fd))
                continue
            if not _stat.S_ISFIFO(status.st_mode):
                recorded.append(_disposition(fd))
                continue
            with self._lock:
                number = self._passed_pipes.setdefault(
                    status.st_ino, len(self._passed_pipes)
                )
            token = f"<PASS_FD{number}>"
            recorded.append(token)
            spelling = f"{fd}:{status.st_ino}"
            replace[spelling] = f"{token}:<PASS_FD{number}_INODE>"
            with self._lock:
                self._passed_spellings[spelling] = replace[spelling]
        return recorded, replace

    def _new_record(self, api: str, argv: List[str], **fields: Any) -> LaunchRecord:
        scopes = sys.modules.get("automated_security_helper.utils.sandbox.scope")
        active = scopes.active_scope() if scopes is not None else None
        with self._lock:
            record = LaunchRecord(
                index=len(self.launches),
                phase=self._phase,
                api=api,
                argv=argv,
                scope=None if active is None else type(active).__name__,
                **fields,
            )
            self.launches.append(record)
        return record

    def _captured(self, path: Path) -> bool:
        """Whether a file named in argv goes in the golden: one the scenario did
        not arrange, inside the test's tree. Under ``<SRC>`` that is one ASH added
        or changed since ``begin()``.

        A ``..`` is resolved before the path is compared with the test's roots, and
        after a link it is the parent of the link's target (``_argv_landing``): with
        ``<TMP>/work/link`` leading to ``<TMP>/work/deep/target``,
        ``<TMP>/work/link/../x`` is judged as ``<TMP>/work/deep/x``, not as
        ``<TMP>/work/x``. What it names must also lie inside the tree after symlinks:
        a file is judged by where it resolves to, and a symlink by where the link is,
        never by where it points (a link is recorded as a link, see ``_entry``). The
        links are followed with the real ``lstat`` (``_real_path``), so a link into a
        host directory takes no probe."""
        text = _argv_landing(os.fspath(path))
        if not os.path.isabs(text):
            return False
        path = Path(text)
        if not path.is_relative_to(self.tmp):
            return False
        if _real_islink(text):
            parent = _real_path(os.path.dirname(text))
            if not Path(parent).is_relative_to(os.path.realpath(self.tmp)):
                return False
        elif not self._confined(text):
            return False
        if path.is_relative_to(self.src):
            return self._source_changed(path)
        return text not in self._fixture_paths and text not in self.stand_ins

    def _capture_argv_files(
        self, argv: List[str], cwd: Optional[str]
    ) -> Dict[str, Any]:
        files: Dict[str, Any] = {}
        for element in argv:
            candidates = [element]
            if element.startswith("-") and "=" in element:
                candidates.append(element.split("=", 1)[1])
            for candidate in candidates:
                if not candidate:
                    continue
                path = Path(candidate)
                if not path.is_absolute():
                    if cwd is None:
                        continue
                    path = Path(cwd) / path
                path = Path(_argv_landing(str(path)))
                try:
                    # _captured first: it reads no file and probes nothing the guards
                    # watch (it follows a link with the real lstat), so a host path in
                    # argv is never read or probed. A symlink is recorded as a
                    # symlink, even when it dangles, and never followed.
                    if not self._captured(path):
                        continue
                    if path.is_symlink():
                        files[str(path)] = self._entry(path)
                        continue
                    if not path.exists():
                        continue
                except (OSError, ValueError):
                    continue
                if path.is_dir():
                    listing: Dict[str, Any] = {}
                    for child in sorted(path.rglob("*")):
                        if len(listing) >= DIR_ENTRY_LIMIT:
                            listing["..."] = "truncated"
                            break
                        # A link is recorded as a link, so it is not stat-ed through:
                        # that would leave out a dangling one or one to a directory,
                        # and answer for a link to a host path by what the host has.
                        if self._captured(child) and (
                            child.is_symlink() or child.is_file()
                        ):
                            listing[str(child)] = (
                                self._entry(child)
                                if child.is_symlink()
                                else Normalized(self._file_content(child))
                            )
                    files[str(path)] = {"dir": listing}
                elif path.is_file():
                    files[str(path)] = Normalized(self._file_content(path))
        return files

    def _exec(
        self,
        argv: List[str],
        env: Optional[Dict[str, str]],
        cwd: Optional[str],
        via: Tuple[str, ...],
        record: Optional[LaunchRecord] = None,
    ) -> Outcome:
        if not argv:
            raise _GUARDS.violation("a launch with an empty argv")
        if cwd is not None and not os.path.isdir(cwd):
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), cwd)
        name = argv[0]
        if os.path.dirname(name):
            if name != sys.executable and not self._is_harness_path(name):
                raise _GUARDS.violation(
                    f"launch of {name}, which is not a characterization stand-in: "
                    f"{argv}"
                )
            candidates = [
                name if os.path.isabs(name) or cwd is None else os.path.join(cwd, name)
            ]
        else:
            dirs = os.get_exec_path(env)
            outside = [d for d in dirs if d and not self._is_harness_path(d)]
            if outside:
                raise _GUARDS.violation(
                    f"exec of {name!r} would search {outside}, outside the harness: "
                    f"{argv}"
                )
            candidates = [os.path.join(d, name) for d in dirs]
        resolved = None
        denied = False
        for candidate in candidates:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                resolved = candidate
                break
            if os.path.exists(candidate):
                denied = True
        if resolved is None:
            code = errno.EACCES if denied else errno.ENOENT
            error_type = PermissionError if denied else FileNotFoundError
            raise error_type(code, os.strerror(code), name)
        if record is not None and record.executable is None:
            record.executable = resolved
        if resolved in self.stand_ins:
            call = ToolCall(
                self.stand_ins[resolved], argv[1:], via, argv, env, cwd, self, record
            )
            return self._run_double(call)
        if resolved == sys.executable:
            call = ToolCall("python", argv[1:], via, argv, env, cwd, self, record)
            return self._python(call)
        raise _GUARDS.violation(
            f"launch of {resolved}, which is not a characterization stand-in: {argv}"
        )

    def _run_double(self, call: ToolCall) -> Outcome:
        if call.record is not None:
            # Set on the way in, so a wrapper's inner tool is what stays recorded.
            call.record.dispatch = {"tool": call.tool, "via": list(call.via)}
        double = self.doubles.get(call.tool)
        if double is None:
            raise _GUARDS.violation(
                f"no double declared for {call.tool!r} (via {list(call.via)}): "
                f"{call.argv}"
            )
        outcome = double(call)
        if not isinstance(outcome, (Exit, Hang)):
            raise _GUARDS.violation(
                f"the {call.tool} double returned {outcome!r}, not Exit or Hang"
            )
        return outcome

    def unwrap_python(self, handler: Callable[[ToolCall], Optional[Outcome]]) -> None:
        """Teach ``sys.executable`` launches another wrapper.

        ``handler(call)`` sees each launch of ``sys.executable`` before the built-in
        unwrapping (``-m MOD``, landlock_exec, the setsid helper) and returns the
        outcome, typically from ``call.dispatch`` or ``call.exec``, or None to pass.
        """
        self._python_wrappers.append(handler)

    def _python(self, call: ToolCall) -> Outcome:
        """``sys.executable``: unwrap ``-m MOD`` and the sandbox wrappers ASH uses."""
        from automated_security_helper.utils.sandbox import backends

        for handler in self._python_wrappers:
            outcome = handler(call)
            if outcome is not None:
                return outcome
        args = call.args
        if len(args) >= 2 and args[0] == "-m":
            return call.dispatch(args[1], args[2:], "python -m")
        if len(args) >= 2 and args[:2] == ["-I", str(backends.LANDLOCK_EXEC)]:
            rest = args[2:]
            if rest[:1] == ["--start-report"]:
                # The pipe the wrapper reports a failed exec on: one the launch passed,
                # or a primitive forgot pass_fds and the report could never arrive.
                passed = call.record.passed_pipes if call.record is not None else ()
                if len(rest) < 2 or rest[1] not in passed:
                    raise call.reject(
                        "landlock_exec --start-report names no pipe the launch passed "
                        "in pass_fds"
                    )
                rest = rest[2:]
            if rest[:1] in (["--policy"], ["--socket-filter"]) and len(rest) >= 3:
                if rest[2] != "--" or len(rest) < 4:
                    raise call.reject("landlock_exec without -- and a command")
                return call.exec(rest[3:], f"landlock_exec {rest[0]}")
            return call.dispatch("landlock_exec", rest, "python -I")
        if len(args) >= 6 and args[:3] == ["-I", "-c", backends._SETSID_EXEC]:
            wrapper, flag = args[4], args[5]
            if flag != "-p" or len(args) < 8:
                raise call.reject("sandbox-exec without -p and a command")
            return call.exec([wrapper, flag, *args[6:]], "setsid")
        return call.dispatch("python", args, "python")


# ---------------------------------------------------------------------------
# Outcome summaries
# ---------------------------------------------------------------------------

_INVOCATION_KEYS = (
    "commandLine",
    "arguments",
    "exitCode",
    "executionSuccessful",
    "exitCodeDescription",
    "workingDirectory",
)

#: Recorded only when not empty, so a scanner that writes neither keeps the golden
#: it had (the model defaults the notifications to []). The properties carry the
#: content-database age records.
_OPTIONAL_INVOCATION_KEYS = ("properties", "toolConfigurationNotifications")

#: How a content-database age record writes ``FIXED_INSTANT`` (``measured_at``).
_FIXED_INSTANT_RECORDED = "2026-01-01T00:00:00Z"


def _invocation_summary(invocation: Dict[str, Any]) -> Dict[str, Any]:
    summary = {key: invocation.get(key) for key in _INVOCATION_KEYS}
    for key in _OPTIONAL_INVOCATION_KEYS:
        if invocation.get(key):
            summary[key] = invocation[key]
    records = (summary.get("properties") or {}).get("ash_content_databases") or []
    for record in records:
        measured_at = record.get("measured_at")
        if measured_at != _FIXED_INSTANT_RECORDED:
            raise AssertionError(
                f"a content-database age record for {record.get('name')} was "
                f"measured at {measured_at}, so the golden would hold the time of "
                "the run. Call char.fix_clock() before the scan, and set the "
                "database's dates relative to FIXED_INSTANT."
            )
    return summary


def _sarif_summary(report: Any) -> Dict[str, Any]:
    dumped = report.model_dump(mode="json", by_alias=True, exclude_none=True)
    runs = []
    for run in dumped.get("runs") or []:
        results = []
        for result in run.get("results") or []:
            locations = []
            for location in result.get("locations") or []:
                physical = location.get("physicalLocation") or {}
                locations.append(
                    {
                        "uri": (physical.get("artifactLocation") or {}).get("uri"),
                        "startLine": (physical.get("region") or {}).get("startLine"),
                    }
                )
            results.append(
                {
                    "ruleId": result.get("ruleId"),
                    "level": result.get("level"),
                    "message": (result.get("message") or {}).get("text"),
                    "locations": locations,
                    "suppressions": result.get("suppressions"),
                }
            )
        runs.append(
            {
                "tool": ((run.get("tool") or {}).get("driver") or {}).get("name"),
                "results": results,
                "invocations": [
                    _invocation_summary(invocation)
                    for invocation in run.get("invocations") or []
                ],
            }
        )
    return {"sarif_runs": runs}


def _cyclonedx_summary(report: Any) -> Dict[str, Any]:
    # The generated model's own field types disagree with what it validates
    # (metadata.tools, scope), so pydantic would warn on every dump.
    dumped = report.model_dump(
        mode="json", by_alias=True, exclude_none=True, warnings=False
    )
    metadata = dumped.get("metadata") or {}
    tools = metadata.get("tools") or []
    if isinstance(tools, dict):
        tools = [*(tools.get("components") or []), *(tools.get("services") or [])]
    return {
        "cyclonedx": {
            "specVersion": dumped.get("specVersion"),
            "version": dumped.get("version"),
            # Made fresh by each run: recorded as present or not.
            "serialNumber": "serialNumber" in dumped,
            "timestamp": "timestamp" in metadata,
            "tools": [tool.get("name") for tool in tools if isinstance(tool, dict)],
            "components": [
                {key: component.get(key) for key in ("type", "name", "version", "purl")}
                for component in dumped.get("components") or []
            ],
            "dependencies": len(dumped.get("dependencies") or []),
        }
    }


def _raw_summary(raw: Any) -> Any:
    from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
        CycloneDXReport,
    )
    from automated_security_helper.schemas.sarif_schema_model import SarifReport

    if isinstance(raw, SarifReport):
        return _sarif_summary(raw)
    if isinstance(raw, CycloneDXReport):
        return _cyclonedx_summary(raw)
    if isinstance(raw, dict):
        return {k: v for k, v in raw.items() if k != "stack_trace"}
    return raw


def _container_summary(container: Any) -> Dict[str, Any]:
    return {
        "target": container.target,
        "target_type": container.target_type,
        "status": container.status,
        "exit_code": container.exit_code,
        "finding_count": container.finding_count,
        "severity_counts": container.severity_counts.model_dump(mode="json"),
        "dependencies_satisfied": container.dependencies_satisfied,
        "errors": list(container.errors),
        "exception": container.exception,
        "raw_results": _raw_summary(container.raw_results),
    }


def _scanner_summary(scanner: Any) -> Dict[str, Any]:
    return {
        "exit_code": scanner.exit_code,
        "errors": list(scanner.errors),
        "output": list(scanner.output),
        "use_uv_tool": scanner.use_uv_tool,
        "tool_version": scanner.tool_version,
        "dependencies_satisfied": scanner.dependencies_satisfied,
        "dependency_unavailable_reason": scanner.dependency_unavailable_reason,
        "scan_timed_out_after": scanner.scan_timed_out_after,
        "scan_spawn_failure": scanner.scan_spawn_failure,
    }


def _converter_summary(converter: Any) -> Dict[str, Any]:
    return {
        "exit_code": converter.exit_code,
        "errors": list(converter.errors),
        "output": list(converter.output),
        "use_uv_tool": converter.use_uv_tool,
        "tool_version": converter.tool_version,
        "dependencies_satisfied": converter.dependencies_satisfied,
        "refused_inputs": [
            refused.model_dump(mode="json") for refused in converter.refused_inputs
        ],
    }


# ---------------------------------------------------------------------------
# Checks every module runs over all of its snapshot scenarios
# ---------------------------------------------------------------------------

#: The type ``pytest.param`` returns.
_PARAMETER_SET = type(pytest.param(None))

# pytest's own escaping for an id (``_pytest.compat.ascii_escaped``).
_NON_PRINTABLE = {i: f"\\x{i:02x}" for i in range(128) if i not in range(32, 127)}
_NON_PRINTABLE.update({ord("\t"): "\\t", ord("\r"): "\\r", ord("\n"): "\\n"})


@dataclasses.dataclass(frozen=True)
class Scenario:
    """One snapshot test, or one parametrization of it, named as its golden is."""

    name: str
    function: Callable[..., Any]
    params: Mapping[str, Any]

    def __str__(self) -> str:
        return self.name


def _escaped(value: Union[str, bytes]) -> str:
    if isinstance(value, bytes):
        text = value.decode("ascii", "backslashreplace")
    else:
        text = value.encode("unicode_escape").decode("ascii")
    return text.translate(_NON_PRINTABLE)


def _value_id(value: Any) -> Optional[str]:
    """The id pytest derives from one value, or None where it falls back to
    ``<argname><index>`` (``IdMaker._idval_from_value``)."""
    if isinstance(value, (str, bytes)):
        return _escaped(value)
    if value is None or isinstance(value, (float, int, bool, complex)):
        return str(value)
    if isinstance(value, re.Pattern):
        return _escaped(value.pattern)
    if isinstance(value, enum.Enum):
        return str(value)
    name = getattr(value, "__name__", None)
    return name if isinstance(name, str) else None


def _unique_ids(ids: List[str]) -> List[str]:
    """pytest's suffixes for duplicate ids (``make_unique_parameterset_ids``)."""
    counts = collections.Counter(ids)
    if len(counts) == len(ids):
        return ids
    suffixes: Dict[str, int] = collections.defaultdict(int)
    for index, value in enumerate(ids):
        if counts[value] > 1:
            suffix = "_" if value and value[-1].isdigit() else ""
            new = f"{value}{suffix}{suffixes[value]}"
            while new in set(ids):
                suffixes[value] += 1
                new = f"{value}{suffix}{suffixes[value]}"
            ids[index] = new
            suffixes[value] += 1
    return ids


def _parametrize_cases(mark: Any) -> List[Tuple[str, Dict[str, Any], bool]]:
    """(id, arguments, skipped) for each parameter set of one parametrize mark."""
    arguments = dict(zip(("argnames", "argvalues"), mark.args))
    arguments.update(mark.kwargs)
    if arguments.get("indirect"):
        raise TypeError("an indirect parametrization cannot be run as a scenario")
    names = arguments["argnames"]
    if isinstance(names, str):
        names = [name.strip() for name in names.split(",") if name.strip()]
    names = list(names)
    ids = arguments.get("ids")
    id_function = ids if callable(ids) else None
    id_list = None if ids is None or callable(ids) else list(ids)
    resolved: List[str] = []
    cases: List[Tuple[Dict[str, Any], bool]] = []
    for index, raw in enumerate(arguments["argvalues"]):
        if isinstance(raw, _PARAMETER_SET):
            values, marks, explicit = tuple(raw.values), raw.marks, raw.id
        else:
            values = (raw,) if len(names) == 1 else tuple(raw)
            marks, explicit = (), None
        if len(values) != len(names):
            raise ValueError(f"{values!r} does not match the argument names {names}")
        if explicit is not None:
            case_id = _escaped(explicit)
        elif (
            id_list is not None and index < len(id_list) and id_list[index] is not None
        ):
            given = _value_id(id_list[index])
            if given is None:
                raise ValueError(f"ids holds an unsupported value {id_list[index]!r}")
            case_id = given
        else:
            parts = []
            for value, argname in zip(values, names):
                part = None
                if id_function is not None:
                    generated = id_function(value)
                    part = None if generated is None else _value_id(generated)
                if part is None:
                    part = _value_id(value)
                parts.append(part if part is not None else f"{argname}{index}")
            case_id = "-".join(parts)
        resolved.append(case_id)
        skipped = any(getattr(m, "name", None) == "skip" for m in marks)
        if any(getattr(m, "name", None) in ("skipif", "xfail") for m in marks):
            raise TypeError("a conditional skip or xfail cannot be run as a scenario")
        cases.append((dict(zip(names, values)), skipped))
    return [
        (case_id, params, skipped)
        for case_id, (params, skipped) in zip(_unique_ids(resolved), cases)
    ]


def golden_scenarios(namespace: Mapping[str, Any]) -> List[Scenario]:
    """Every snapshot test in a module, one per parametrization, as pytest names it.

    Pass the module's ``globals()`` after its last snapshot test. A snapshot test is
    a module-level ``test_*`` function that takes ``snapshot``. Stacked
    ``parametrize`` marks, ``pytest.param`` (with ``id=`` or a ``skip`` mark) and
    ``ids=`` lists or functions are named the way pytest names them; ``skip``
    cases are left out, because they write no golden. Indirect parametrization,
    ``skipif`` and ``xfail`` raise. ``check_scenarios_match_goldens`` checks the
    names against what pytest collected and against the committed goldens.
    """
    scenarios: List[Scenario] = []
    for name, function in sorted(namespace.items()):
        if not name.startswith("test_") or not inspect.isfunction(function):
            continue
        if "snapshot" not in inspect.signature(function).parameters:
            continue
        marks = list(getattr(function, "pytestmark", []))
        if any(m.name == "skip" for m in marks):
            continue
        if any(m.name in ("skipif", "xfail") for m in marks):
            raise TypeError(f"{name}: a conditional skip or xfail cannot be a scenario")
        combinations: List[Tuple[Optional[str], Dict[str, Any], bool]] = [
            (None, {}, False)
        ]
        # pytest joins stacked marks' ids in mark order, the last varying fastest.
        for mark in (m for m in marks if m.name == "parametrize"):
            combinations = [
                (
                    case if head is None else f"{head}-{case}",
                    {**params, **more},
                    skipped or skip_case,
                )
                for head, params, skipped in combinations
                for case, more, skip_case in _parametrize_cases(mark)
            ]
        for case_id, params, skipped in combinations:
            if not skipped:
                label = name if case_id is None else f"{name}[{case_id}]"
                scenarios.append(Scenario(label, function, params))
    return scenarios


def check_scenarios_match_goldens(
    namespace: Mapping[str, Any], module_file: str, request: Any
) -> None:
    """Fail unless a module's scenarios are exactly its committed goldens.

    Also fails if pytest collected a snapshot test of the module that
    ``golden_scenarios`` does not list, so the scenario checks can never shrink
    without a failure. While ``--snapshot-update`` rewrites the goldens only that
    second check runs.
    """
    names = [scenario.name for scenario in golden_scenarios(namespace)]
    if not names:
        pytest.fail(f"{module_file} has no snapshot scenarios", pytrace=False)
    duplicates = sorted(n for n, c in collections.Counter(names).items() if c > 1)
    if duplicates:
        pytest.fail(f"scenarios listed twice: {duplicates}", pytrace=False)
    module = Path(module_file).resolve()
    collected = {
        item.name
        for item in request.session.items
        if Path(str(getattr(item, "path", ""))).resolve() == module
        and "snapshot" in getattr(item, "fixturenames", ())
    }
    unlisted = sorted(collected - set(names))
    if unlisted:
        pytest.fail(
            f"pytest collected snapshot tests golden_scenarios does not list: {unlisted}",
            pytrace=False,
        )
    if request.config.getoption("update_snapshots", default=False):
        return
    directory = module.with_name("__snapshots__") / module.stem
    committed = {path.name[: -len(".json")] for path in directory.glob("*.json")}
    missing, orphaned = sorted(set(names) - committed), sorted(committed - set(names))
    if missing or orphaned:
        pytest.fail(
            f"scenarios without a committed golden: {missing}; committed goldens "
            f"without a scenario: {orphaned}",
            pytrace=False,
        )


class _CapturedGoldens:
    """Stands in for ``snapshot``: records each golden's text and always matches."""

    __hash__ = None  # type: ignore[assignment]

    def __init__(self, harness: "Harness") -> None:
        self.harness = harness
        self.texts: List[str] = []

    def __eq__(self, data: object) -> bool:
        self.texts.append(self.harness.serialize(data))
        return True

    def __repr__(self) -> str:
        return "<captured golden>"


def _run_scenario(
    scenario: Scenario,
    scratch: Path,
    fixtures: Mapping[str, Any],
    *,
    parent: Optional[str] = None,
    length: Optional[int] = None,
) -> Tuple[List[str], int]:
    """Run one scenario in a fresh harness in a short root (made in ``parent``,
    and padded with a subdirectory to ``length`` characters when given). Returns
    the text of each golden it compared with ``snapshot``, and the root's length."""
    scratch.mkdir(parents=True, exist_ok=True)
    with contextlib.ExitStack() as stack:
        directory = stack.enter_context(short_root(parent))
        if length is not None and length - len(str(directory)) - 1 > 0:
            directory = directory / ("l" * (length - len(str(directory)) - 1))
        harness = Harness(directory)
        captured = _CapturedGoldens(harness)
        arguments: Dict[str, Any] = dict(scenario.params)
        for name in inspect.signature(scenario.function).parameters:
            if name in arguments:
                continue
            if name == "char":
                arguments[name] = harness
            elif name == "snapshot":
                arguments[name] = captured
            elif name == "monkeypatch":
                arguments[name] = stack.enter_context(pytest.MonkeyPatch.context())
            elif name == "tmp_path":
                arguments[name] = scratch
            elif name in fixtures:
                arguments[name] = fixtures[name]
            else:
                raise TypeError(
                    f"{scenario} needs the fixture {name!r}; pass it in fixtures="
                )
        with harness.active():
            scenario.function(**arguments)
        root_length = len(str(directory))
    found = take_violations()
    if found:
        raise AssertionError(f"{scenario} recorded violations: {found}")
    if not captured.texts:
        raise AssertionError(f"{scenario} never compared a golden with snapshot")
    return captured.texts, root_length


def _same_goldens(
    scenario: Scenario, expected: List[str], got: List[str], why: str
) -> None:
    if got == expected:
        return
    diff: List[str] = [f"{len(expected)} goldens at baseline, {len(got)} {why}"]
    for want, have in itertools.zip_longest(expected, got, fillvalue=""):
        if want != have:
            diff = list(
                difflib.unified_diff(
                    want.splitlines(), have.splitlines(), "baseline", why, lineterm=""
                )
            )
            break
    shown = "\n".join(diff[:80])
    raise AssertionError(f"{scenario}: the golden changes {why}:\n{shown}")


def check_scenario_isolation(
    scenario: Scenario,
    tmp_path: Path,
    *,
    tools: Sequence[str],
    fixtures: Optional[Mapping[str, Any]] = None,
) -> None:
    """Fail if ``scenario``'s golden depends on anything outside the scenario.

    Runs it, in memory, and requires the same golden text each time:
    - in a short root, as the snapshot test runs;
    - in ``/tmp/char-<hex>``, ``SHORT_ROOT_MIN_LENGTH`` (18) characters long, the
      root of a run with TMPDIR unset (skipped when that is the baseline's length);
    - in a root ``SHORT_ROOT_MAX_LENGTH`` (96) characters long, the longest a
      TMPDIR may give;
    - on a simulated host whose /usr/local/bin, /usr/bin and /bin hold ``tools``
      (``host_image``), where it must also probe none of them.

    Nothing is read from or written to ``__snapshots__``, so this is safe while
    ``--snapshot-update`` rewrites them. A scenario's ``monkeypatch`` and
    ``tmp_path`` are fresh each run; any other fixture it takes comes from
    ``fixtures``.
    """
    fixtures = dict(fixtures or {})
    baseline, baseline_length = _run_scenario(scenario, tmp_path / "baseline", fixtures)
    if baseline_length != SHORT_ROOT_MIN_LENGTH:
        shortest, length = _run_scenario(
            scenario, tmp_path / "short-tmp", fixtures, parent="/tmp"
        )
        _same_goldens(scenario, baseline, shortest, f"under a root {length} long")
    longest, length = _run_scenario(
        scenario, tmp_path / "long-tmp", fixtures, length=SHORT_ROOT_MAX_LENGTH
    )
    _same_goldens(scenario, baseline, longest, f"under a root {length} long")
    image = tmp_path / "image"
    for directory in ("usr-local-bin", "usr-bin"):
        for tool in tools:
            planted = image / directory / tool
            planted.parent.mkdir(parents=True, exist_ok=True)
            planted.write_text(STAND_IN_SCRIPT, encoding="utf-8")
            planted.chmod(0o755)
    system = image / "usr-bin"
    with host_image(
        {"/usr/local/bin": image / "usr-local-bin", "/usr/bin": system, "/bin": system}
    ) as probes:
        on_host, _length = _run_scenario(scenario, tmp_path / "host-tmp", fixtures)
        probed = list(probes)
    if probed:
        raise AssertionError(f"{scenario} looked in host directories: {probed}")
    _same_goldens(scenario, baseline, on_host, f"on a host that ships {list(tools)}")
