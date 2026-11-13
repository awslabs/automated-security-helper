# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A usage error that names a path is one line, with each path whole.

The usage error's panel folds its text at the console's width, 80 columns off a
terminal, so a path longer than a line was split and no line held it. A usage
error that names a path is printed after the usage line and the help hint as
one ``Error:`` line:

* ``ash config get``, ``update`` and ``validate-plugin-dependencies`` given two
  different config files, one positional and one with ``--config``;
* an extra argument, which is usually a path typed without its option;
* click's own checks of a path option (typer's ``Path`` type), for an option
  that asks for them.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import typer
from typer.testing import CliRunner

from automated_security_helper.cli.main import AshTyperGroup, app
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

pytestmark = pytest.mark.unit


@pytest.fixture
def long_dir(tmp_path) -> Path:
    directory = tmp_path.joinpath("a-directory-name-long-enough" * 4)
    directory.mkdir()
    assert len(str(directory)) > 120, "the control: the path is longer than a line"
    return directory


def _error_lines(output: str) -> list[str]:
    return [line for line in output.splitlines() if line.startswith("Error: ")]


@pytest.mark.parametrize("command", ["get", "update", "validate-plugin-dependencies"])
def test_two_config_files_are_named_on_one_line(long_dir, command):
    first, second = long_dir / "first.yaml", long_dir / "second.yaml"
    for path in (first, second):
        path.write_text("{}\n", encoding="utf-8")
    result = CliRunner().invoke(
        app, ["config", command, str(first), "--config", str(second)]
    )
    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    lines = _error_lines(result.output)
    assert len(lines) == 1, result.output
    assert str(first) in lines[0] and str(second) in lines[0], result.output


def test_an_extra_argument_is_named_on_one_line(long_dir):
    extra = long_dir / "a-path-without-its-option"
    with patch("automated_security_helper.cli.scan.run_ash_scan") as run:
        result = CliRunner().invoke(app, ["scan", str(extra)])
    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert not run.called
    lines = _error_lines(result.output)
    assert len(lines) == 1, result.output
    assert str(extra) in lines[0], result.output


def test_a_path_option_s_own_check_is_named_on_one_line(long_dir):
    """typer's Path type with exists=True, under ASH's root group: no ash option
    asks for that check, so the cell builds one."""
    probe = typer.Typer(cls=AshTyperGroup)

    @probe.callback()
    def _root() -> None:
        pass

    @probe.command()
    def read(path: Path = typer.Option(..., exists=True)) -> None:
        pass

    missing = long_dir / "missing"
    result = CliRunner().invoke(probe, ["read", "--path", str(missing)])
    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    lines = _error_lines(result.output)
    assert len(lines) == 1, result.output
    assert str(missing) in lines[0], result.output
