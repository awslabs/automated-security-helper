# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash dependencies install --help`` shows the bin-path default as ``~/.ash/bin``.

It used to show the absolute default, ``Path.home() / ".ash" / "bin"`` or the value
of ASH_BIN_PATH, both read when the module is imported. A home directory of 36
characters or more made rich wrap that line, so the help snapshots changed with the
machine they ran on: the normalizer masks the home directory only after rich has
drawn the panel. The default is now shown as written in the documentation, and the
help notes that ASH_BIN_PATH replaces it.

The help is rendered in a child process because the default is fixed at import.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

RENDER_HELP = (
    "from automated_security_helper.cli.main import app; "
    "app(['dependencies', 'install', '--help'], prog_name='ash')"
)


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
        [sys.executable, "-c", RENDER_HELP],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    output = result.stdout
    assert result.returncode == 0, result.stderr
    assert "[default: ~/.ash/bin]" in output, output
    assert str(home) not in output, output
