"""Every command that takes ``--output-formats`` has the note about its values.

scripts/generate_cli_docs.py adds a note to the ``--output-formats`` row of the CLI
reference: the values that write a report and the values that are accepted and write
nothing. The note was keyed to the command path ``scan``. When ``ash scan`` became a
group, with the subjects ``fs`` and ``workspace``, no command had that path any more, and
the generator went on exiting 0 with the note on no row: not on ``ash scan fs`` and
``ash scan workspace``, not on ``ash`` itself, which runs the same scan, and not on
``ash merge`` and ``ash results merge``, which check the values against the same list.

What is asserted:

* Every command that takes the option, found by the walk of the click tree that writes
  the page, has the note in its row of the page the generator renders.
* The note is one text, the same on every row.
* Every key of the generator's table of notes names an option of a command in the tree.
  A key that names nothing is silent, because the generator does not say that its note
  was never written, so the next move of a command would leave another one. The key
  that went dead here is planted to show that the check finds it.
"""

from __future__ import annotations

import pytest
import typer.main

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

#: The option, as one of the names it is declared under.
OPTION = "--output-formats"

#: The first words of the note, which is written after the help of the option.
NOTE_OPENS = "Values that write a report:"

#: The key the table of notes held when ``scan`` stopped taking the option: the path of
#: a command that exists, with an option that command does not have.
DEAD_KEY = (("scan",), OPTION)

#: A key whose path is no command at all.
ABSENT_KEY = (("no-such-command",), OPTION)


@pytest.fixture
def cli_docs(script_loader, monkeypatch):
    module = script_loader("generate_cli_docs")
    # The note lists the reporters this build has, which plugin discovery finds. What is
    # asserted does not depend on which they are, so the discovery is left out.
    monkeypatch.setattr(module, "_builtin_reporters", lambda: ["sarif"])
    return module


@pytest.fixture
def root():
    return typer.main.get_command(app)


def _first_long_name(param) -> str:
    """The name the generator keys a note to: the first of the option's long names."""
    longs = [name for name in param.opts if name.startswith("--")]
    return longs[0] if longs else ""


def _commands_taking_the_option(cli_docs, root) -> list:
    """``(path, param)`` of every ``--output-formats`` in the tree, found by the walk
    that writes the page."""
    return [
        (path, param)
        for path, command, _context in cli_docs.iter_commands(root)
        for param in command.params
        if OPTION in param.opts
    ]


def _row(page: str, anchor: str) -> str:
    marker = f'<a id="{anchor}"></a>'
    rows = [line for line in page.splitlines() if marker in line]
    assert len(rows) == 1, f"{anchor}: {len(rows)} rows"
    return rows[0]


def _dead_keys(cli_docs, root) -> list:
    """The keys of the table of notes that name no option of any command in the tree."""
    options = {
        tuple(path): {_first_long_name(param) for param in command.params}
        for path, command, _context in cli_docs.iter_commands(root)
    }
    return sorted(
        (path, name)
        for path, name in cli_docs.VALUE_NOTES
        if name not in options.get(path, set())
    )


def test_the_row_of_every_command_that_takes_the_option_has_the_note(cli_docs, root):
    taking = _commands_taking_the_option(cli_docs, root)
    # A walk that found too few commands would pass the check below without reading
    # their rows. These three are the commands that run a scan.
    found = {tuple(path) for path, _param in taking}
    assert found >= {(), ("scan", "fs"), ("scan", "workspace")}, found

    page, _stats = cli_docs.generate(root)

    without = [
        " ".join(["ash", *path])
        for path, param in taking
        if NOTE_OPENS not in _row(page, cli_docs.param_anchor(path, param))
    ]
    assert without == [], f"no note under {OPTION} of: {without}"


def test_the_note_is_one_text_on_every_row(cli_docs, root):
    notes = {
        cli_docs._value_note(path, param)
        for path, param in _commands_taking_the_option(cli_docs, root)
    }

    assert len(notes) == 1, notes
    assert next(iter(notes)).startswith(NOTE_OPENS), notes


def test_every_key_of_the_table_of_notes_names_an_option_of_a_command(cli_docs, root):
    assert _dead_keys(cli_docs, root) == []


def test_a_key_that_names_no_command_or_no_option_of_it_is_found(
    cli_docs, root, monkeypatch
):
    monkeypatch.setitem(cli_docs.VALUE_NOTES, DEAD_KEY, cli_docs._output_formats_note)
    monkeypatch.setitem(cli_docs.VALUE_NOTES, ABSENT_KEY, cli_docs._output_formats_note)

    assert _dead_keys(cli_docs, root) == sorted([DEAD_KEY, ABSENT_KEY])
