# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Start ASH's own interpreter as a child that imports nothing from where it starts.

``python -m`` and ``python -c`` put the working directory first on ``sys.path``:
``-m`` as its full path, ``-c`` as ``''``, which follows a later ``os.chdir``. ASH
usually runs inside the repository it scans, ``ash dependencies install`` takes the
current directory as the source tree, and a scanner's subprocesses start in the
scanned tree by default. A ``pip/``, ``json.py`` or ``automated_security_helper/``
there was therefore imported in place of the real module.

Two measures, because neither covers every supported Python on its own:

* ``-P`` (Python 3.11 and later) stops Python adding the working directory at all.
  The flag rather than ``PYTHONSAFEPATH=1``: the variable is inherited by the child's
  own children, and pip runs ``setup.py`` builds that import modules beside
  ``setup.py`` through exactly that entry.
* The child starts in an empty directory created for it and removed afterwards, so
  on 3.10, which has no ``-P``, the entry Python adds names nothing.

``-I`` would cover both on every version, but it also ignores ``PYTHONPATH`` and the
user site-packages directory, which an install of ASH may depend on.

A child that changes directory after it starts should not rely on this: under 3.10
its ``''`` entry follows it. ``utils/cdk_nag_worker.py`` removes that entry itself
for that reason.

Limits: a ``PYTHONPATH`` entry that is relative is read against the child's working
directory, the empty one, so a module importable only through such an entry (ASH
itself, say) is not importable in the child. Name absolute entries in ``PYTHONPATH``.

:func:`empty_directory` is the start directory on its own, for a child that is not
Python. ``ash dependencies install`` starts every install command in one, so a
package manager that reads settings from its working directory (npm's project
``.npmrc``, the Gemfile ``gem install -g`` reads, Bundler's ``.bundle/config``) does
not read the scanned repository's. The user's own settings, in HOME or set
globally, still apply.

:func:`uv_child_overrides` is the environment a ``uv`` command needs on top, because
uv looks for a project and a ``.venv`` in every parent directory as well. Both the
installer and a scanner's own commands (``PluginBase._run_subprocess``) apply it.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

from automated_security_helper.utils.process_env import snapshot_environ

#: What makes the interpreter skip the working directory, where it can.
_SAFE_PATH_FLAGS: List[str] = ["-P"] if sys.version_info >= (3, 11) else []


@dataclass(frozen=True)
class PythonChild:
    """The argv to spawn and the directory to spawn it in."""

    argv: List[str]
    cwd: Path


@contextmanager
def empty_directory(parent: Optional[Path] = None) -> Iterator[Path]:
    """A new, empty directory for a child to start in, removed when the block ends.

    Created under ``parent`` when given (a sandboxed child can only see the
    directories its policy grants, so a caller under a sandbox passes one it can
    see), otherwise in the system's temporary directory.
    """
    directory = Path(
        tempfile.mkdtemp(prefix="ash-child-", dir=str(parent) if parent else None)
    ).absolute()
    try:
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


@contextmanager
def python_child(*args: str, parent: Optional[Path] = None) -> Iterator[PythonChild]:
    """ASH's interpreter with ``args``, and an empty directory to start it in.

    ``args`` is everything after the interpreter, such as ``"-m", "pip", "install"``.
    Spawn ``child.argv`` with ``cwd=child.cwd``. ``parent`` is as for
    :func:`empty_directory`.
    """
    with empty_directory(parent) as directory:
        yield PythonChild(
            argv=[sys.executable, *_SAFE_PATH_FLAGS, *args], cwd=directory
        )


#: The first statement of a ``-c`` child that has to start where its caller is. It
#: removes the ``''`` entry Python adds for ``-c`` before anything is imported;
#: ``import sys`` is built in and reads nothing from disk, and ``sitecustomize`` and
#: ``usercustomize`` are imported before that entry is added (measured on 3.10 and
#: 3.14). Under ``-P`` or ``PYTHONSAFEPATH`` the entry is not there, and the first,
#: real entry is kept. ``utils/cdk_nag_worker.py`` starts its child the same way.
#: Ends in a line break rather than ``; ``, so the source that follows may open
#: with a compound statement (``if``, ``for``, ``def``), which no ``;`` can precede.
DROP_WORKING_DIRECTORY = (
    "import sys; sys.path[:1] = [] if sys.path[:1] == [''] else sys.path[:1]\n"
)


def python_code_argv(source: str) -> List[str]:
    """ASH's interpreter running ``source`` with ``-c``, importing nothing from its cwd.

    For a child that cannot be given an empty start directory, such as the inner scan
    ``nix develop --command`` runs in the scan's own directory: ``-P`` where Python
    has it, and ``source`` behind :data:`DROP_WORKING_DIRECTORY` for Python 3.10.

    The dropping statement is the first statement executed, always. ``source`` runs
    behind it as its own compiled unit (``exec(compile(...))``), so a ``from
    __future__ import`` at the start of ``source`` is legal there as the first
    statement of that unit, and nothing of ``source`` is hoisted ahead of the drop:
    moving a leading future-import LINE ahead used to move the rest of that line
    with it, and a ``;``-joined source (the one caller writes one) then imported
    the package from the working directory before the drop, which is the import
    this function exists to prevent; the future import itself imports
    ``__future__`` with the working directory first on ``sys.path``.
    """
    code = DROP_WORKING_DIRECTORY + f"exec(compile({source!r}, '<ash>', 'exec'))\n"
    return [sys.executable, *_SAFE_PATH_FLAGS, "-c", code]


#: Interpreter options that take the next argument as their value.
_PYTHON_OPTIONS_WITH_A_VALUE = frozenset({"-X", "-W", "--check-hash-based-pycs"})


def runs_module_or_code(argv: Sequence[str]) -> bool:
    """Whether ``argv`` starts ASH's interpreter with ``-m`` or ``-c``.

    Only interpreter options may come before it, so ``python script.py -c`` is not
    one: a script's own directory is what Python adds for it, and ``-P`` would drop
    that too. The option is read as the interpreter reads it: on its own (``-m``),
    attached to its module or code (``-mpip``, ``-cCODE``), or combined with other
    short options (``-Bc``), and ``-X``, ``-W`` and ``--check-hash-based-pycs`` take a
    value, attached or as the next argument, that is never the module.

    Every argument is read as text the way subprocess reads it (``os.fsdecode``: a
    str, bytes or a path-like), so a ``Path`` in argv, which plugins put there, is
    a script and never an AttributeError out of the spawn.
    """
    if not argv or os.fspath(argv[0]) != sys.executable:
        return False
    options = iter(argv[1:])
    for raw in options:
        try:
            arg = os.fsdecode(raw)
        except TypeError:
            return False
        if not arg.startswith("-") or arg == "-" or arg.startswith("--"):
            if arg in _PYTHON_OPTIONS_WITH_A_VALUE:
                next(options, None)
                continue
            return False
        # A cluster of short options: each letter is one option, until a letter
        # that takes the rest of the argument as its value.
        letters = arg[1:]
        position = 0
        while position < len(letters):
            letter = letters[position]
            if letter in ("m", "c"):
                return True
            if letter in ("X", "W"):
                if position + 1 == len(letters):
                    next(options, None)
                break
            position += 1
    return False


#: The interpreter's single-letter options that take a value: the rest of their
#: argument, or the next argument when nothing follows the letter.
_PYTHON_LETTERS_WITH_A_VALUE = frozenset("cmWX")


def python_module_arguments(options: Sequence[str]) -> Optional[Tuple[str, List[str]]]:
    """The module ``options`` runs with ``-m`` and the arguments after it, or None.

    ``options`` are an interpreter's arguments after the program. Read the way
    CPython reads them: single-letter options cluster (``-Im uv``, ``-IXutf8``),
    and a letter that takes a value (``-c``, ``-m``, ``-W``, ``-X``) takes the rest
    of its argument (``-muv``) or, when nothing follows it, the next argument.
    ``-c``, a script, ``-`` or ``--`` means no module runs. A ``-m`` with no module
    after it is no module either. The one reader of a Python command line's
    module in ASH: ``cli/dependencies.py`` and :func:`uv_child_overrides` both ask
    it, so a spelling one of them accepts the other accepts too.
    """
    try:
        words = [os.fsdecode(option) for option in options]
    except TypeError:
        return None  # An argument subprocess would refuse too: no module runs.
    index = 0
    while index < len(words):
        arg = words[index]
        if arg in _PYTHON_OPTIONS_WITH_A_VALUE:
            index += 2
            continue
        if arg in ("-", "--") or not arg.startswith("-"):
            return None
        if arg.startswith("--"):
            index += 1
            continue
        for position in range(1, len(arg)):
            letter = arg[position]
            if letter not in _PYTHON_LETTERS_WITH_A_VALUE:
                continue
            value: Optional[str] = arg[position + 1 :]
            if not value:
                index += 1
                value = words[index] if index < len(words) else None
            if letter == "c" or value is None:
                return None
            if letter == "m":
                return value, words[index + 1 :]
            break  # -W or -X took the rest of this argument, or the next one.
        index += 1
    return None


#: uv options that come before the subcommand and take a value (uv 0.12).
_UV_OPTIONS_WITH_A_VALUE = frozenset(
    {
        "--allow-insecure-host",
        "--cache-dir",
        "--color",
        "--config-file",
        "--directory",
        "--project",
        "--python-preference",
    }
)

#: ``uv run`` options that take a value (uv 0.12), on top of the global ones: what
#: the scan of ``uv run``'s own options has to step over to find where the program
#: it runs begins. A hand-kept list, so it falls behind uv; the direction of a gap
#: is the safe one: an unlisted value-taking option makes the scan stop at its
#: value, read as the program, so a ``--project`` or ``--python`` after it is not
#: seen and the overrides are ADDED (``UV_NO_PROJECT``, ``UV_PYTHON``), never
#: dropped. Short forms are listed beside their long forms.
_UV_RUN_OPTIONS_WITH_A_VALUE = _UV_OPTIONS_WITH_A_VALUE | frozenset(
    {
        "--config-setting",
        "-C",
        "--default-index",
        "--env-file",
        "--exclude-newer",
        "--extra",
        "--extra-index-url",
        "--find-links",
        "-f",
        "--fork-strategy",
        "--group",
        "--index",
        "-i",
        "--index-strategy",
        "--index-url",
        "--keyring-provider",
        "--link-mode",
        "--no-binary-package",
        "--no-build-package",
        "--no-extra",
        "--no-group",
        "--only-group",
        "--package",
        "--prerelease",
        "--python",
        "-p",
        "--refresh-package",
        "--reinstall-package",
        "--resolution",
        "--upgrade-package",
        "-P",
        "--with",
        "--with-editable",
        "--with-requirements",
    }
)

#: The spellings a uv launcher goes by: the binary, and Windows' shims for it.
_UV_PROGRAM_NAMES = frozenset({"uv", "uv.exe", "uv.cmd", "uv.bat"})

#: The modules that run uv: ``python -m uv`` and ``python -m uv.__main__``.
_UV_MODULES = frozenset({"uv", "uv.__main__"})

#: uv's subcommands (uv 0.12), so a value of a global option this module does not
#: list (a new option, say) is not read as the subcommand: the first positional
#: argument that is a subcommand is it, and any other positional before it is a
#: value of the option before it.
_UV_SUBCOMMANDS = frozenset(
    {
        "add",
        "auth",
        "build",
        "cache",
        "export",
        "format",
        "generate-shell-completion",
        "help",
        "init",
        "lock",
        "pip",
        "publish",
        "python",
        "remove",
        "run",
        "self",
        "sync",
        "tool",
        "tree",
        "venv",
        "version",
    }
)

#: ``UV_SYSTEM_PYTHON`` values uv reads as true (clap's boolish parser, case
#: folded): only one of these is an operator's choice of interpreter. uv reads
#: ``0``, ``false``, ``f``, ``no``, ``n`` and ``off`` as false and refuses any other
#: value, so the complement was the wrong test: a ``UV_SYSTEM_PYTHON=f`` was counted
#: as a choice, UV_PYTHON was left out, and uv, reading the variable as false, ran
#: the scanned tree's ``.venv``.
_UV_TRUE = frozenset({"1", "true", "t", "yes", "y", "on"})

#: The subcommands that read ``UV_SYSTEM_PYTHON`` (uv 0.12): it is the environment
#: form of ``--system``, an option only the ``uv pip`` family has. Any other
#: subcommand, ``uv run`` first among them, ignores the variable, so for those it
#: is no choice of interpreter and ASH's own is still named: counting it there left
#: ``uv run bandit`` with no interpreter at all, and uv ran the ``.venv`` of the
#: scanned tree. A subcommand missing from this set gets the interpreter; a gap
#: adds the override, never drops it.
_UV_SYSTEM_PYTHON_SUBCOMMANDS = frozenset({"pip"})


def _uv_arguments(argv: Sequence[str]) -> Optional[List[str]]:
    """The arguments after the uv program in ``argv``, or None when it is not uv.

    uv is the binary by any of its names, or ASH's own interpreter running the
    ``uv`` module (``<python> -m uv ...``), which reads the same settings. The
    program may be a path-like, as subprocess accepts it. The module is read by
    :func:`python_module_arguments`, in every spelling the interpreter reads
    (``-muv``, ``-Im uv``, ``-m uv.__main__``): a loop here that looked for a
    separate ``-m`` then ``uv`` gave those spellings no overrides, so the uv they
    started found the scanned tree's project and ``.venv``, the hazard the
    overrides exist for.
    """
    if not argv:
        return None
    name = re.split(r"[\\/]", os.fspath(argv[0]))[-1].lower()
    if name in _UV_PROGRAM_NAMES:
        return list(argv[1:])
    if runs_module_or_code(argv):
        found = python_module_arguments(argv[1:])
        if found is not None and found[0] in _UV_MODULES:
            return found[1]
    return None


def _uv_own_options(subcommand: str, rest: Sequence[str], start: int) -> List[str]:
    """The arguments of ``rest`` from ``start`` that are uv's own, not the program's.

    For ``uv run`` the program begins at the first positional argument after the
    subcommand's own options (or at ``--``), and what follows belongs to that
    program: its ``-p`` or ``--system`` says nothing about uv's interpreter. The
    other subcommands run no program, so every argument is uv's.
    """
    if subcommand != "run":
        return list(rest[start:])
    own: List[str] = []
    index = start
    while index < len(rest):
        arg = rest[index]
        if arg == "--" or not arg.startswith("-"):
            break
        own.append(arg)
        index += 2 if arg in _UV_RUN_OPTIONS_WITH_A_VALUE else 1
    return own


def uv_child_overrides(
    argv: Sequence[str], env: Optional[Mapping[str, str]] = None
) -> Dict[str, str]:
    """The environment a uv command needs to find no project or ``.venv`` near it.

    Measured with uv 0.12.22: ``uv pip`` and ``uv run`` run the python of a ``.venv``
    in the directory they start in or any parent, and ``uv run`` builds a project it
    finds there, running the project's build backend. A scanner's commands start in
    the scanned tree, and the installer's empty start directory keeps uv out of it
    only while the system's temporary directory is outside it, so a uv command gets:

    - ``UV_NO_PROJECT=1``, unless it names a ``uv --project`` itself;
    - ``UV_PYTHON`` set to ASH's interpreter, unless it names one (``uv --python``,
      ``uv -p``, ``uv --system``) or the environment the child gets, ``env`` (this
      process's when None), already carries ``UV_PYTHON`` or, for the ``uv pip`` family
      only (no other subcommand reads it), a ``UV_SYSTEM_PYTHON`` uv reads as true.
      The caller merges the overrides over ``env``, so the
      choice is read from the mapping the merge would overwrite, never from
      somewhere else.

    ``uv tool`` commands and ``uvx`` get nothing: they read neither, and an
    interpreter there would change which Python the tool's environment is built on.
    Neither does ``UV_NO_CONFIG`` help, which only stops uv reading ``uv.toml``.
    """
    rest = _uv_arguments(argv)
    if rest is None:
        return {}
    # A locked copy, never the live mapping: another thread may be changing
    # it while this reads (utils/process_env.py).
    environment: Mapping[str, str] = snapshot_environ() if env is None else env
    subcommand = None
    first_positional = None
    index = 0
    while index < len(rest):
        arg = rest[index]
        if arg in _UV_OPTIONS_WITH_A_VALUE:
            index += 2
            continue
        if not arg.startswith("-"):
            if arg in _UV_SUBCOMMANDS:
                subcommand = arg
                break
            # The value of a global option this module does not list: not the
            # subcommand, which is the next positional that names one.
            if first_positional is None:
                first_positional = index
            index += 1
            continue
        index += 1
    if subcommand is None and first_positional is not None:
        # No listed name anywhere: a subcommand uv gained since the list was
        # written, or an alias it lacks. The first positional is it, and it gets
        # the overrides: a gap in the list adds them, never drops them, as a gap
        # in _UV_RUN_OPTIONS_WITH_A_VALUE does. Only ``tool`` is left out, and
        # only when it is named. Returning nothing here left such a command on
        # the scanned tree's project and ``.venv``.
        index = first_positional
        subcommand = rest[index]
    if subcommand in (None, "tool"):
        return {}
    # uv's own arguments: the global options before the subcommand and the
    # subcommand's own, never the arguments of a program ``uv run`` starts.
    own = rest[:index] + _uv_own_options(subcommand, rest, index + 1)
    overrides: Dict[str, str] = {}
    if not any(a == "--project" or a.startswith("--project=") for a in own):
        overrides["UV_NO_PROJECT"] = "1"
    names_interpreter = any(
        a in ("--python", "-p", "--system") or a.startswith("--python=") for a in own
    )
    operator_chose = bool(environment.get("UV_PYTHON")) or (
        subcommand in _UV_SYSTEM_PYTHON_SUBCOMMANDS
        and environment.get("UV_SYSTEM_PYTHON", "").strip().lower() in _UV_TRUE
    )
    if not names_interpreter and not operator_chose:
        overrides["UV_PYTHON"] = sys.executable
    return overrides
