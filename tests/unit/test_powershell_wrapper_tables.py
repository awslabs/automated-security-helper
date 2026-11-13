# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The tables in ``utils/ash_helpers.ps1`` that describe ash's own commands.

``Invoke-ASH`` puts the options it adds after the subcommand, and only when the
subcommand takes them, and reads past a root option's value when it looks for the
subcommand. Both depend on lists of ash's commands and options written out in the
PowerShell. These tests check those lists against the real commands. They read the
file as text and need no PowerShell, so they run wherever the unit tests run; the
tests of what the wrapper does with the lists are in
``test_powershell_wrapper_matches_ash.py``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import typer.main

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

HELPERS = Path(__file__).resolve().parents[2] / "utils" / "ash_helpers.ps1"


def _text() -> str:
    return HELPERS.read_text(encoding="utf-8")


def _ps1_table(name: str) -> dict[str, set[str]]:
    block = re.search(rf"\${name} = @{{\n(.*?)\n\s*}}", _text(), re.DOTALL)
    assert block, f"${name} not found in utils/ash_helpers.ps1"
    rows = re.findall(r"'(--[a-z-]+)'\s*=\s*'([^']*)'", block.group(1))
    assert rows, f"${name} has no rows"
    return {option: set(takers.split()) for option, takers in rows}


def _ps1_list(name: str) -> list[str]:
    listed = re.search(rf"\${name} = @\(([^)]*)\)", _text())
    assert listed, f"${name} not found in utils/ash_helpers.ps1"
    return re.findall(r"'([^']+)'", listed.group(1))


def _calls(text: str, opening: str) -> list[str]:
    """The text of every call that starts with ``opening``, up to its closing paren,
    however many lines it spans."""
    found = []
    start = text.find(opening)
    while start != -1:
        depth = 0
        for end in range(start + len(opening) - 1, len(text)):
            depth += {"(": 1, ")": -1}.get(text[end], 0)
            if depth == 0:
                break
        else:
            raise AssertionError(f"unbalanced {opening} at offset {start}")
        found.append(text[start : end + 1])
        start = text.find(opening, end)
    return found


def _options(command) -> set[str]:
    found = set()
    for param in command.params:
        found.update(getattr(param, "opts", None) or [])
        found.update(getattr(param, "secondary_opts", None) or [])
    return found


def test_the_subcommand_table_matches_the_real_commands():
    """The wrapper's lists of subcommands, and of which take each option it adds,
    checked against the real commands so they cannot drift from them."""
    root = typer.main.get_command(app)
    assert set(_ps1_list("ashSubcommands")) == set(root.commands)
    table = _ps1_table("ashOptionSubcommands")
    for option, takers in sorted(table.items()):
        assert option in _options(root), f"ash itself does not take {option}"
        assert takers == {
            name
            for name, command in root.commands.items()
            if option in _options(command)
        }, option


def test_every_option_the_wrapper_adds_has_a_table_row():
    """Read from every ``$ashCmdArgs.Add(`` call, a call written over several lines
    included, so an option cannot be added without saying which subcommands take it."""
    calls = _calls(_text(), "$ashCmdArgs.Add(")
    assert calls, "no $ashCmdArgs.Add( calls found"
    added = set(re.findall(r"'(--[a-z-]+)'", "\n".join(calls)))
    assert added, "the $ashCmdArgs.Add( calls name no options"
    table = _ps1_table("ashOptionSubcommands")
    assert added <= set(table), sorted(added - set(table))


def test_the_call_scan_reads_a_call_over_several_lines():
    text = "$ashCmdArgs.Add(@(\n    '--one'\n))\nx\n$ashCmdArgs.Add(@('--two', $v))\n"
    assert _calls(text, "$ashCmdArgs.Add(") == [
        "$ashCmdArgs.Add(@(\n    '--one'\n))",
        "$ashCmdArgs.Add(@('--two', $v))",
    ]


def test_the_options_that_take_a_value_are_the_roots():
    """The wrapper reads past the value of a root option that takes one when it looks
    for the subcommand. Its list, checked against the real root command so a new
    option's value cannot be read as a subcommand's name."""
    root = typer.main.get_command(app)
    takes_a_value = {
        spelling
        for param in root.params
        if param.param_type_name == "option" and not param.is_flag and not param.count
        for spelling in param.opts
    }
    assert set(_ps1_list("ashRootValueOptions")) == takes_a_value
    assert all(
        param.nargs == 1 for param in root.params if param.param_type_name == "option"
    )
