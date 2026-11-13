# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The argv for every git command ASH runs itself.

ASH runs git inside the directory it scans, and that directory's ``.git/config``
is the repository's to write. Two of its settings make git start a program:

- ``core.fsmonitor``, which git runs whenever it refreshes the index. With git
  2.50.1, ``git status``, ``git ls-files`` and ``git diff`` against the working tree
  run it; ``git rev-parse --show-toplevel`` and ``git diff A...B`` do not.
- ``core.hooksPath``, the directory git runs hooks from: checkout, commit, merge
  and others run one.

A scan should start neither. ``-c`` on the command line outranks the repository's
config, so every command built here turns both off, whichever git subcommand it
runs. ``core.hooksPath=/dev/null`` names a path that holds no hook, so git finds
none and runs nothing.

Not covered: what the git binary on ``PATH`` is, and settings that only matter to
commands ASH does not run (``core.sshCommand`` for a fetch, a diff driver for a
patch). ``tests/unit/utils/test_git_command.py`` checks that every git argv in the
package is built here.

``core.fsmonitor=false`` is a boolean to a git that has the built-in file system
monitor. A git from before it reads the value as the name of a hook command, so
there it starts the program named ``false`` on each index read instead of turning
the monitor off. That program is found through the ``PATH`` git is given, which
the scan-set helpers reduce to its anchored entries (``get_scan_set._git_environ``),
so one planted in the scanned tree is not reached; its exit status of 1 makes git
treat every file as possibly changed, which costs time and nothing else. The
option stays as it is: the argv tests and the MCP tool-surface golden pin it.
"""

from __future__ import annotations

import sys
from typing import Optional, Sequence, Union

#: The program name every git command ASH runs starts from, before a caller resolves
#: it to an absolute path (:func:`resolved_git`).
GIT_PROGRAM = "git"


def resolved_git() -> Optional[str]:
    """The git to run, as an absolute path, or None when there is none on PATH.

    The one resolver every helper that starts git goes through. Not the bare
    name: on Windows a program started by name is looked for in the working
    directory before PATH, and ASH usually runs from the repository it scans, so
    a ``git.exe`` committed to that repository would run. ``find_executable``
    answers only from anchored PATH entries and ASH's own directories, never from
    the working directory or the scanned tree. Imported where it is called, since
    ``subprocess_utils`` is a heavier module than this one.
    """
    from automated_security_helper.utils.subprocess_utils import find_executable

    return find_executable(GIT_PROGRAM)


#: How the output of a git command is decoded. git prints a path as the bytes of
#: its name, and Python reads a file name with the filesystem encoding, so the
#: output is decoded the way ``os.fsdecode`` decodes a name. That is UTF-8 on
#: Windows, where the locale's encoding is a code page such as cp1252 that would
#: turn a non-ASCII name into one that names no file, and the host's filesystem
#: encoding on POSIX, which a legacy locale (ISO-8859-1, EUC-JP) makes something
#: other than UTF-8. On Windows the constant is UTF-8 outright and not
#: ``sys.getfilesystemencoding()``: git for Windows prints UTF-8, and
#: ``PYTHONLEGACYWINDOWSFSENCODING=1`` (the PEP 529 opt-out) makes the filesystem
#: encoding ``mbcs``, a code page.
GIT_OUTPUT_ENCODING = (
    "utf-8" if sys.platform == "win32" else sys.getfilesystemencoding()
)

#: A byte that does not decode is kept as a surrogate, as Python keeps it in a
#: file name, so the str still names the file.
GIT_OUTPUT_ERRORS = "surrogateescape"


def decode_git_output(output: Union[bytes, str]) -> str:
    """*output* of a git command as text: ``GIT_OUTPUT_ENCODING``, ``surrogateescape``.

    For a reader of git's file names outside ``get_scan_set``, which decodes its
    own lookups. A str is returned as it is.
    """
    if isinstance(output, str):
        return output
    return output.decode(GIT_OUTPUT_ENCODING, GIT_OUTPUT_ERRORS)


#: Put before the subcommand in every git command ASH runs; see the module docstring.
GIT_SAFETY_OPTIONS: tuple[str, ...] = (
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.hooksPath=/dev/null",
)


def git_argv(*args: str, program: Union[str, Sequence[str]] = GIT_PROGRAM) -> list[str]:
    """``[*program, *GIT_SAFETY_OPTIONS, *args]``: a git command for ``subprocess``.

    The options go before the subcommand, where git reads them and where they
    outrank the repository's config: ``-c core.fsmonitor=false``, so refreshing
    the index starts no fsmonitor command, and ``-c core.hooksPath=/dev/null``, so
    git finds no hook to run. Nothing else in *args* is changed or checked.

    ``program`` is the git to run: the absolute path :func:`resolved_git` gives a
    caller that starts the command itself, so that Windows does not look for git
    in the working directory first; or the bare name, for a caller whose spawn
    helper resolves ``argv[0]`` on its own (``subprocess_utils.spawn_run``). A
    sequence is the program followed by what must come before the options, such
    as a stand-in script run through its interpreter. This function only builds
    the argv; it resolves nothing, so it can be called where no git is installed.
    """
    prefix = [program] if isinstance(program, str) else list(program)
    return [*prefix, *GIT_SAFETY_OPTIONS, *args]
