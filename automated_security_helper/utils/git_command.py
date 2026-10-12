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

from typing import Sequence, Union

#: The program name every git command ASH runs starts from, before a caller resolves
#: it to an absolute path.
GIT_PROGRAM = "git"

#: Put before the subcommand in every git command ASH runs; see the module docstring.
GIT_SAFETY_OPTIONS: tuple[str, ...] = (
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.hooksPath=/dev/null",
)


def git_argv(*args: str, program: Union[str, Sequence[str]] = GIT_PROGRAM) -> list[str]:
    """``[*program, *GIT_SAFETY_OPTIONS, *args]``: a git command for ``subprocess``.

    ``program`` is the git to run: the bare name, or the absolute path a caller
    resolved so that Windows does not look for git in the working directory first.
    A sequence is the program followed by what must come before the options, such
    as a stand-in script run through its interpreter.
    """
    prefix = [program] if isinstance(program, str) else list(program)
    return [*prefix, *GIT_SAFETY_OPTIONS, *args]
