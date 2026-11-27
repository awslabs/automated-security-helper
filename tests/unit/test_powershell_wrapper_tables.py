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
from tests.utils.helpers import declared_params

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


def _options(command, name: str = "") -> set[str]:
    found = set()
    for param in declared_params(name, command):
        found.update(getattr(param, "opts", None) or [])
        found.update(getattr(param, "secondary_opts", None) or [])
    return found


def _group_only_commands(root) -> dict:
    """The commands of ``results`` that have no top-level spelling, by their own names.

    ``results diff`` and ``results trend`` are listed in the tables as ``diff`` and
    ``trend``: a command that takes an option the wrapper adds is named there by its
    own leaf, as ``results report`` is named ``report``.
    """
    return {
        leaf: command
        for leaf, command in root.commands["results"].commands.items()
        if leaf not in root.commands
    }


def test_the_subcommand_table_matches_the_real_commands():
    """The wrapper's lists of subcommands, and of which take each option it adds,
    checked against the real commands so they cannot drift from them."""
    root = typer.main.get_command(app)
    assert set(_ps1_list("ashSubcommands")) == set(root.commands)
    # Held to a literal, so an empty read of the group cannot pass: the two commands
    # no release had at the top level.
    assert set(_group_only_commands(root)) == {"diff", "trend"}
    takers_of = {**root.commands, **_group_only_commands(root)}
    table = _ps1_table("ashOptionSubcommands")
    for option, takers in sorted(table.items()):
        assert option in _options(root), f"ash itself does not take {option}"
        # A `container` word is followed by `build`, which takes what the root's
        # options are handed to (AshTyperGroup._options_for_subcommand).
        assert takers == {
            name
            for name, command in takers_of.items()
            if option
            in _options(
                command.commands["build"] if name == "container" else command, name
            )
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


def test_the_scan_subjects_and_their_value_options_are_the_real_ones():
    """``scan <subject> <path>`` is refused (the directory is -SourceDir here), and
    that refusal finds the subject and skips an option's value from these two lists,
    which are the CLI's: the subjects of ``scan``, and the options a subject takes a
    value for that the root does not."""
    root = typer.main.get_command(app)
    subjects = root.commands["scan"].commands
    root_value_options = {
        spelling
        for param in root.params
        if param.param_type_name == "option" and not param.is_flag and not param.count
        for spelling in param.opts
    }
    subject_value_options = {
        spelling
        for subject in subjects.values()
        for param in subject.params
        if param.param_type_name == "option" and not param.is_flag and not param.count
        for spelling in param.opts
    } - root_value_options
    assert set(_ps1_list("ashScanSubjects")) == set(subjects)
    assert set(_ps1_list("ashScanValueOptions")) == subject_value_options
    # Held to literals as well, so a subject that left the CLI cannot take its row
    # with it: workspace is a subject, and --archive is fs's own value option.
    assert set(subjects) == {"fs", "workspace"}
    assert subject_value_options == {"--archive", "--cli-json-input"}


def test_the_options_that_name_another_source_are_the_real_ones():
    """A scan that names a clone, an image or a ``--cli-json-input`` document is not
    given the mounted directory as its PATH argument: the CLI refuses a PATH beside a
    clone, and it does not count ASH_SOURCE_DIR as the only name of the directory then.
    The wrapper finds those scans from this list, written out here as well so a
    rename in the CLI fails this and not only the table."""
    root = typer.main.get_command(app)
    subjects = root.commands["scan"].commands
    declared = {
        spelling
        for subject in subjects.values()
        for param in subject.params
        if param.param_type_name == "option"
        for spelling in param.opts
    }
    other_source = {
        "--cli-json-input",
        "--image",
        "--image-archive",
        "--image-layout",
        "--source-git",
    }
    assert set(_ps1_list("ashScanOtherSourceOptions")) == other_source
    assert other_source <= declared


def test_the_completer_offers_what_the_wrapper_parses():
    """The argument completer is generated from the parser's tables: it names every
    subcommand, every subject and the option that takes a value."""
    text = _text()
    start = text.index("# BEGIN generated: ps1-completion")
    block = text[start : text.index("# END generated: ps1-completion", start)]
    root = typer.main.get_command(app)
    for name in root.commands:
        assert f"'{name}'" in block, name
    for subject in root.commands["scan"].commands:
        assert f"'{subject}'" in block, subject
    # The subjects are offered after `scan` and nothing else is: the words the
    # completer offers there are the CLI's subjects, workspace among them.
    assert "$subjects = @('fs', 'workspace')" in block
    # The options that take a value are left to the shell: the word after one is a
    # value, not an option or a subject.
    assert "'--cli-json-input'" in block
    assert "'--archive'" in block
    assert (
        "Register-ArgumentCompleter -CommandName Invoke-ASH -ParameterName 'AshArgs'"
        in block
    )
    assert (
        "Register-ArgumentCompleter -CommandName Invoke-ASH -ParameterName 'RemainingAshArgs'"
        in block
    )


def test_the_group_tables_are_the_contracts():
    """`container build` and `results report` take the options Invoke-ASH adds after
    the command word (`ash container --offline build` is a usage error), and the
    command decides which options apply. The groups and their commands are generated,
    not written in the loop, so they cannot name a group the CLI does not have."""
    from automated_security_helper.interactions.wrapper_contract import contract

    spec = contract()
    assert _ps1_list("ashOptionGroups") == list(spec.option_groups)
    assert _ps1_list("ashGroupLeafTakers") == list(spec.group_leaf_takers)
    assert set(spec.option_groups) == {"results", "container"}
    assert "container:build=container" in spec.group_leaf_takers
    assert "results:merge=merge" in spec.group_leaf_takers
    # Every command the group has, read from the real group and not from the
    # contract, is keyed by its own leaf: `results diff` and `results trend` have no
    # top-level spelling and are not left out for it, which would have the wrapper
    # name the group ("ash results does not take --offline") in its warning.
    root = typer.main.get_command(app)
    leaves = set(root.commands["results"].commands)
    assert leaves == {"report", "diff", "trend", "merge", "inspect"}
    assert {
        pair for pair in _ps1_list("ashGroupLeafTakers") if pair.startswith("results:")
    } == {f"results:{leaf}={leaf}" for leaf in leaves}
    text = _text()
    # The loop reads the tables, and names no group of its own.
    assert "$subcommand -cin $ashOptionGroups" in text
    assert "$ashGroupLeafTakers" in text
    assert "-ceq 'results'" not in text and "-ceq 'container'" not in text
