"""The help of ``--changed-files-only`` names only options that its command takes.

``--changed-files-only`` is declared once, in the signature of the scan engine, and every
command built from that signature prints the same help for it: bare ``ash``, ``ash scan``
with no subject, ``ash scan fs`` and ``ash scan workspace``. The help used to say that a
scan reports nothing "when nothing changed inside --source-dir". The workspace subject
has no ``--source-dir``: its scan root is the directory that holds the workspace file,
and it reads the changes of each project from that project's own repository. So the help
of ``ash scan workspace`` sent its reader to an option the command refuses, and the same
words named a deprecated option on the forms that scan one directory.

What is asserted:

* The help of the option, as ``--help`` prints it for each command that takes the
  option, names no ``--option`` that its command does not declare. The help is cut out of
  the printed page between its first and its last words, so a page that does not hold it
  fails the row, and a row cannot pass by reading nothing.
* The help of ``ash scan workspace`` says what the option does there: the changes are
  read for each project, and a project where nothing changed is skipped.
* ``ash scan workspace`` declares no ``--source-dir`` and ``ash scan fs`` does, which is
  what makes the first row able to tell the two apart.
"""

from __future__ import annotations

import re

import pytest
import typer.main
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

#: The commands that take the option, as the words after ``ash``.
COMMANDS = [
    pytest.param([], id="ash"),
    pytest.param(["scan"], id="ash-scan"),
    pytest.param(["scan", "fs"], id="ash-scan-fs"),
    pytest.param(["scan", "workspace"], id="ash-scan-workspace"),
]

#: The first and the last words of the help of the option.
HELP_STARTS = "Report only findings in files changed"
HELP_ENDS = "refuses it (exit 5)."

#: The side borders of the panel that holds the options. They stand inside a help that
#: wraps onto several lines, and a legacy console draws them as a bar.
_BORDER = re.compile(r"[│|]")
_LONG_OPTION = re.compile(r"(?<![\w-])--[a-z][\w-]*")


def _printed_help(words: list[str]) -> str:
    """What ``ash <words> --help`` prints, on one line and without the panel borders."""
    result = CliRunner().invoke(app, [*words, "--help"], prog_name="ash")
    assert result.exit_code == 0, result.output
    return " ".join(_BORDER.sub(" ", result.output).split())


def _help_of_the_option(words: list[str]) -> str:
    text = _printed_help(words)
    start = text.index(HELP_STARTS)
    return text[start : text.index(HELP_ENDS, start) + len(HELP_ENDS)]


def _command_of(words: list[str]):
    """The click command that ``ash <words>`` runs, and that prints the help."""
    command = typer.main.get_command(app)
    for word in words:
        command = command.commands[word]
    if words == ["scan"]:
        # With no subject the scan runs the group's legacy command, which takes every
        # option of the engine, and `ash scan --help` prints its help.
        return command.legacy_command()
    return command


def _declared_options(words: list[str]) -> set[str]:
    return {
        name
        for parameter in _command_of(words).params
        for name in (*parameter.opts, *parameter.secondary_opts)
    }


@pytest.mark.parametrize("words", COMMANDS)
def test_the_help_of_the_option_names_only_options_the_command_takes(words):
    named = set(_LONG_OPTION.findall(_help_of_the_option(words)))
    declared = _declared_options(words)

    assert "--base-ref" in named, named
    assert named <= declared, sorted(named - declared)


def test_the_workspace_help_of_the_option_describes_a_scan_of_projects():
    text = _help_of_the_option(["scan", "workspace"])

    assert "--source-dir" not in text
    assert "when nothing changed inside the scanned directory, nothing is" in text
    assert "A workspace scan reads the changes of each project" in text
    assert "skips a project where nothing changed" in text


def test_only_the_directory_subject_has_a_source_dir_option():
    """Were ``--source-dir`` an option of the workspace subject, its help could name
    it, and the first row would no longer tell the two subjects apart."""
    assert "--source-dir" not in _declared_options(["scan", "workspace"])
    assert "--source-dir" in _declared_options(["scan", "fs"])
