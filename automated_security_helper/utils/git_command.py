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
"""

from __future__ import annotations

import sys
from typing import Sequence, Union

#: The program name every git command ASH runs starts from, before a caller resolves
#: it to an absolute path.
GIT_PROGRAM = "git"

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

    ``program`` is the git to run: the bare name, or the absolute path a caller
    resolved so that Windows does not look for git in the working directory first.
    A sequence is the program followed by what must come before the options, such
    as a stand-in script run through its interpreter.
    """
    prefix = [program] if isinstance(program, str) else list(program)
    return [*prefix, *GIT_SAFETY_OPTIONS, *args]
