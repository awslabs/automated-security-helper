# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The safe.directory command in a refusal can be copied into a shell as written.

When git refuses a repository for its ownership, the refusal that stops a run over
files ASH cannot tell are committed (``unverified_output_files_error``) shows the
command that marks the repository safe. The repository's path went into it as it
was, so a path with a space split the command into two arguments, and a quote or a
``$`` was read as shell syntax. The path is shell-quoted now.

A path the message's sinks write as an escape (a control character, a line break,
a lone surrogate for a byte that is not UTF-8, a backslash before text that reads
as an escape) is not put in the command at all: shown as an escape it would not
name the directory, so a paste would mark another path safe. The message says
instead that the path cannot be written here as plain text.

The paths are built at run time and never created; the function reads none of them.
"""

from __future__ import annotations

import os
import re
import shlex
import sys
from pathlib import Path

import pytest

from automated_security_helper.core.committed_output import (
    unverified_output_files_error,
)
from automated_security_helper.utils.scan_output_dirs import GitIndexAnswer

pytestmark = pytest.mark.unit

#: An absolute directory every case's repository is below, on any platform.
ROOT = Path(os.path.abspath(os.sep + "srv"))

_OWNERSHIP = "fatal: detected dubious ownership in repository"

#: What the message says in place of the command for a path that cannot be copied.
_NO_COMMAND = (
    "git config --global --add safe.directory and the repository's path, "
    "which cannot be written here as plain text"
)


def _message(repository: Path, error: str = _OWNERSHIP) -> str:
    output = repository / "out"
    answer = GitIndexAnswer(output, repository=repository, error=error)
    return str(unverified_output_files_error(output, [output / "ash.log"], answer))


def _command_argument(message: str) -> str:
    """The text the message shows after ``safe.directory``, up to the closing
    parenthesis of the command."""
    match = re.search(
        r"git config --global --add safe\.directory (.*)\), or remove the old results",
        message,
    )
    assert match is not None, ascii(message)
    return match.group(1)


@pytest.mark.parametrize(
    "name",
    ["re po", "it's", "a$b", "x;y", "(x)"],
    ids=["space", "quote", "dollar", "semicolon", "parenthesis"],
)
def test_a_path_a_shell_would_split_is_quoted_so_the_command_names_one_argument(name):
    repository = ROOT / name

    message = _message(repository)

    argument = _command_argument(message)
    assert shlex.split(argument) == [repository.as_posix()], ascii(message)


def test_a_plain_path_is_shown_as_written():
    repository = ROOT / "repo"

    message = _message(repository)

    assert _command_argument(message) == repository.as_posix(), ascii(message)


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("re\x1bpo", id="escape"),
        pytest.param("re\npo", id="line-break"),
        pytest.param("r" + chr(0xDCE9) + "po", id="lone-surrogate"),
        pytest.param(
            "r\\x41",
            id="backslash-before-escape-text",
            marks=pytest.mark.skipif(
                sys.platform == "win32", reason="a Windows name cannot hold a backslash"
            ),
        ),
    ],
)
def test_a_path_shown_as_an_escape_is_left_out_of_the_command(name):
    repository = ROOT / name

    message = _message(repository)

    # The message is shown with ascii(): the path may hold a lone surrogate, which a
    # failure report that is written out as UTF-8 cannot carry.
    assert _NO_COMMAND in message, ascii(message)
    assert "(git config" not in message, ascii(message)
    assert f"safe.directory {repository.as_posix()}" not in message, ascii(message)


def test_another_error_keeps_its_own_way_out():
    message = _message(ROOT / "repo", error="fatal: not a git repository")

    assert "fix what stops git from reading the repository" in message, message
    assert "safe.directory" not in message, message
