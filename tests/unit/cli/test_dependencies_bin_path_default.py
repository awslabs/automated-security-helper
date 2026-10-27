# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash dependencies install --help` names the --bin-path default without a machine's home.

The default is ``core.constants.ASH_BIN_PATH``, computed at import from ``$ASH_BIN_PATH``
or ``Path.home()``. A help that printed it expanded, ``[default:
/home/<user>/.ash/bin]``, would carry the home directory of whoever produced it into the
help, its snapshot and any reference generated from it, wrap onto a second line once that
path was long enough, and show an unrelated directory when ``ASH_BIN_PATH`` was set. The
help shows ``[default: (~/.ash/bin)]`` (typer puts a descriptive default in
parentheses), and ``[env var: ASH_BIN_PATH]`` beside it says what overrides it.
"""

from __future__ import annotations

import os
import subprocess
import sys

from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core import constants
from tests.snapshot.support.normalize import pinned_terminal_env
from tests.utils.helpers import importing_this_checkout


def _help() -> str:
    result = CliRunner().invoke(
        app, ["dependencies", "install", "--help"], env={"COLUMNS": "200"}
    )
    assert result.exit_code == 0, result.output
    return " ".join(result.output.split())


def test_the_default_is_shown_as_the_documented_path():
    text = _help()
    assert "[default: (~/.ash/bin)]" in text, text
    assert "[env var: ASH_BIN_PATH]" in text, text


def test_the_help_does_not_contain_the_resolved_default():
    """The resolved path is this machine's; it has no place in the help text."""
    resolved = str(constants.ASH_BIN_PATH)
    assert resolved != "~/.ash/bin"
    assert resolved not in _help()


_RENDER_HELP = (
    "from typer.testing import CliRunner\n"
    "from automated_security_helper.cli.main import app\n"
    "result = CliRunner().invoke(\n"
    "    app, ['dependencies', 'install', '--help'], prog_name='ash'\n"
    ")\n"
    "print(result.output, end='')\n"
    "raise SystemExit(result.exit_code)\n"
)


def _help_with_home(directory, home: str) -> str:
    """The help as a process whose HOME is ``home`` renders it, in the snapshots' terminal.

    A child, because the default is computed from HOME when the CLI is imported. A
    relative HOME, taken from ``directory``, so its length is exactly the one asked for.
    """
    env = {k: v for k, v in os.environ.items() if k != "ASH_BIN_PATH"}
    env.update(pinned_terminal_env(), HOME=home, USERPROFILE=home)
    result = subprocess.run(
        [sys.executable, "-c", importing_this_checkout(_RENDER_HELP)],
        cwd=directory,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def test_the_help_does_not_depend_on_the_length_of_home(tmp_path):
    """The snapshots of this help failed once HOME was long enough to wrap the default.

    With a 43-character HOME, rich wrapped ``[default: <home>/.ash/bin]`` onto a second
    line before the snapshot normalizer could mask the home, and the shorter HOME of
    another machine or CI did not wrap. Rendered with a HOME of 19 and of 120
    characters, the help must be the same text.
    """
    short = _help_with_home(tmp_path, "h" * 19)
    long = _help_with_home(tmp_path, "h" * 120)
    assert "--bin-path" in short, short
    assert short == long
    assert "h" * 19 not in short, short


def test_the_option_defaults_to_the_resolved_path():
    """Only the displayed text is fixed; the value the command uses is unchanged."""
    from automated_security_helper.cli.dependencies import install_dependencies

    import inspect

    default = inspect.signature(install_dependencies).parameters["bin_path"].default
    # A str since the option stopped being a Path (Typer reads "" as Path(".")).
    assert default.default == str(constants.ASH_BIN_PATH)
