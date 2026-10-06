# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Snapshots of every ``--help`` page, ``ashx --version`` and ``--generate-cli-skeleton``.

The command list is walked from the real Typer app, so a command added without a
snapshot fails here instead of shipping unreviewed help text, and
``test_every_command_has_a_help_snapshot`` fails if the walked set and the stored
snapshot files ever disagree.

How the help is made identical on every OS
------------------------------------------
- typer reads ``TERMINAL_WIDTH`` and the CI/color variables once, when
  ``typer.rich_utils`` is imported, which happens before the autouse fixture in
  tests/snapshot/conftest.py pins the environment. Under GitHub Actions that import
  sets ``FORCE_TERMINAL``. ``_pinned_rich_help`` re-pins both module attributes to
  the values that fixture pins.
- rich treats a Windows console without VT support as "legacy": it draws one column
  narrower and swaps the rounded box for a square one. Its detection asks the real
  console, so a Windows runner whose stdout is a pipe takes the legacy path. That is
  real user-visible output, so both variants are rendered on every OS by pinning the
  detection: ``test_help`` is a VT terminal (Linux, macOS, Windows Terminal) and
  ``test_help_legacy_windows_console`` is the legacy console.
- ``prog_name=CANONICAL_CLI_NAME`` (``ashx``) keeps the usage line from depending on how pytest was started.
- The one machine-dependent help default, ``dependencies install --bin-path``
  (``~/.ash/bin``), is masked as ``<HOME>`` by the shared normalizer, which also
  keeps the panel border where rich drew it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import rich.console
import typer.main
import typer.rich_utils
from typer.testing import CliRunner

from automated_security_helper.cli.deprecations import CANONICAL_CLI_NAME
from automated_security_helper.cli.json_input import CliJsonInputCommand
from automated_security_helper.cli.main import app
from tests.snapshot.support.normalize import pinned_terminal_env

_SNAPSHOT_DIR = Path(__file__).parent / "__snapshots__" / Path(__file__).stem


def _walk(command, path: tuple[str, ...] = ()):
    yield path, command
    for name in sorted(getattr(command, "commands", {})):
        yield from _walk(command.commands[name], (*path, name))


#: Every command in the tree, root first: (argv path, click command).
COMMANDS = list(_walk(typer.main.get_command(app)))
SKELETON_COMMANDS = [
    (path, command)
    for path, command in COMMANDS
    if isinstance(command, CliJsonInputCommand)
]


def _command_id(path: tuple[str, ...]) -> str:
    return " ".join((CANONICAL_CLI_NAME, *path))


@pytest.fixture(autouse=True)
def _pinned_rich_help(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        typer.rich_utils, "MAX_WIDTH", int(pinned_terminal_env()["TERMINAL_WIDTH"])
    )
    monkeypatch.setattr(typer.rich_utils, "FORCE_TERMINAL", False)
    monkeypatch.setattr(rich.console, "detect_legacy_windows", lambda: False)


def _invoke(args: list[str]) -> str:
    result = CliRunner().invoke(app, args, prog_name=CANONICAL_CLI_NAME)
    assert result.exit_code == 0, (result.output, result.exception)
    return result.output


@pytest.mark.parametrize(
    "path", [path for path, _ in COMMANDS], ids=[_command_id(p) for p, _ in COMMANDS]
)
def test_help(path, text_snapshot):
    assert _invoke([*path, "--help"]) == text_snapshot("txt")


@pytest.mark.parametrize(
    "path", [path for path, _ in COMMANDS], ids=[_command_id(p) for p, _ in COMMANDS]
)
def test_help_legacy_windows_console(path, text_snapshot, monkeypatch):
    monkeypatch.setattr(rich.console, "detect_legacy_windows", lambda: True)
    assert _invoke([*path, "--help"]) == text_snapshot("txt")


@pytest.mark.parametrize(
    "path",
    [path for path, _ in SKELETON_COMMANDS],
    ids=[_command_id(p) for p, _ in SKELETON_COMMANDS],
)
def test_generate_cli_skeleton(path, text_snapshot):
    assert _invoke([*path, "--generate-cli-skeleton"]) == text_snapshot("json")


def test_version(text_snapshot):
    assert _invoke(["--version"]) == text_snapshot("txt")


def _stored(test_name: str) -> set[str]:
    """The parametrize ids of ``test_name`` that have a stored snapshot file."""
    prefix = f"{test_name}["
    return {
        file.stem[len(prefix) : -1]
        for file in _SNAPSHOT_DIR.iterdir()
        if file.name.startswith(prefix) and file.stem.endswith("]")
    }


@pytest.mark.parametrize(
    ("test_name", "commands"),
    [
        ("test_help", COMMANDS),
        ("test_help_legacy_windows_console", COMMANDS),
        ("test_generate_cli_skeleton", SKELETON_COMMANDS),
    ],
)
def test_every_command_has_a_help_snapshot(test_name, commands):
    walked = {_command_id(path) for path, _ in commands}
    assert walked == _stored(test_name)


def test_the_walk_reaches_the_documented_tree():
    # A guard on the walk itself: if it stopped descending into groups, every test
    # above would still pass over a shorter list.
    walked = {_command_id(path) for path, _ in COMMANDS}
    assert {
        "ashx",
        "ashx scan",
        "ashx config validate-plugin-dependencies",
        "ashx dependencies install",
        "ashx inspect sarif-fields",
        "ashx plugin list",
    } <= walked
    assert {_command_id(path) for path, _ in SKELETON_COMMANDS} >= {
        "ashx scan",
        "ashx report",
    }
