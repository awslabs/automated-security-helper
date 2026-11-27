# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash dependencies install --help`` shows the bin-path default as ``~/.ash/bin``.

It used to show the absolute default, ``Path.home() / ".ash" / "bin"`` or the value
of ASH_BIN_PATH, both read when the module is imported. A home directory of 36
characters or more made rich wrap that line, so the help snapshots changed with the
machine they ran on: the normalizer masks the home directory only after rich has
drawn the panel. The default is now shown as written in the documentation, in the
parentheses typer puts around a descriptive default (``[default: (~/.ash/bin)]``, as
tests/unit/cli/test_dependencies_bin_path_default.py also asserts), and the help
notes that ASH_BIN_PATH replaces it.

The help is rendered in a child process because the default is fixed at import.

The --bin-path row is read across its lines. Rich wraps every cell of the options
panel within its column, and the help column is narrow at the snapshots' 100
columns since #1140 gave the command options with long names and metavars
(``--providers <provider>[,<provider>...]`` among them): the golden in
tests/snapshot/cli/__snapshots__/test_snapshot_cli_help/ records the default as
``[default:`` above ``(~/.ash/bin)]``. A continuation line of a row holds that
row's cells and nothing else, so the row's words, joined across its lines with the
panel's borders dropped, are what the row says. The row is compared whole: a home
that reached it would change it, even where rich crops a word too long for the
column.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from tests.utils.helpers import importing_this_checkout

pytestmark = pytest.mark.integration

RENDER_HELP = (
    "from automated_security_helper.cli.main import app; "
    "app(['dependencies', 'install', '--help'], prog_name='ash')"
)

#: The --bin-path row of the options panel, its wrapped lines joined: the documented
#: default and the variable that replaces it.
BIN_PATH_ROW = (
    "--bin-path -b <path> Path to install binaries to. "
    "[env var: ASH_BIN_PATH] [default: (~/.ash/bin)]"
)


def _bin_path_row(output: str) -> str:
    """The --bin-path row of the help's options panel, its wrapped lines joined.

    A row starts with its option name; each line after it that does not start with
    another option's name is the row wrapped. The borders are dropped first: box
    drawing, or ``|`` where a legacy Windows console draws the panel in ASCII.
    """
    lines: list[str] = []
    for line in output.splitlines():
        cells = line.strip().strip("│|").strip()
        if cells.startswith("--bin-path"):
            lines = [cells]
        elif lines and cells and not cells.startswith("-"):
            lines.append(cells)
        elif lines:
            break
    return " ".join(" ".join(lines).split())


@pytest.mark.parametrize("bin_path_env", [None, "set"], ids=["unset", "set"])
@pytest.mark.parametrize("home_name", ["h", "h" * 60], ids=["short", "long"])
def test_the_help_default_is_the_same_for_any_home(tmp_path, home_name, bin_path_env):
    home = tmp_path / home_name
    home.mkdir()
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("ASH_BIN_PATH", "PYTHONSAFEPATH", "COLUMNS", "TERMINAL_WIDTH")
    }
    env.update(HOME=str(home), USERPROFILE=str(home), COLUMNS="100", NO_COLOR="1")
    if bin_path_env:
        env["ASH_BIN_PATH"] = str(home / "custom-bin")
    result = subprocess.run(
        [sys.executable, "-c", importing_this_checkout(RENDER_HELP)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=120,
    )
    output = result.stdout
    assert result.returncode == 0, result.stderr
    assert _bin_path_row(output) == BIN_PATH_ROW, output
    assert str(home) not in output, output
