"""The note under ``--format`` of ``ash report`` and ``ash results report`` names the
exit that the command has.

scripts/generate_cli_docs.py adds a sentence to the ``--format`` row of both commands: a
value that no loaded reporter answers to is refused. The sentence said "Any other value
exits with code 1", typed by hand, while the command refuses a mistyped argument with
``ASH_EXIT_USAGE_ERROR``, which is 5. The row of ``ash results report`` carried no
sentence, because the note was keyed to the command path ``report`` alone, and
``results report`` is the same ``report_command`` under its new name.

For each of the two commands:

* the generator has a note for the ``--format`` row, found the way it finds the note of
  any row;
* the code that note names is the exit of ``ash <command> --format not-a-reporter`` when
  it runs. The command runs in an empty directory and refuses the name before it reads
  any results, so what it exits with is what a reader of the sentence meets;
* the note reads the code from ``ASH_EXIT_USAGE_ERROR``: with that constant changed, the
  sentence follows it.
"""

from __future__ import annotations

import re
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core import constants

pytestmark = pytest.mark.unit

#: The two spellings of the report command, as the words after ``ash``.
REPORT_COMMANDS = [
    pytest.param(["report"], id="ash-report"),
    pytest.param(["results", "report"], id="ash-results-report"),
]

#: A name that no reporter answers to.
NOT_A_REPORTER = "not-a-reporter"

_EXIT_SENTENCE = re.compile(r"exits with code (\d+)")
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_BOX = re.compile(r"[│╭╮╰╯─]")


@pytest.fixture
def cli_docs(script_loader, monkeypatch):
    module = script_loader("generate_cli_docs")
    # The sentence under test does not depend on which reporters this build has, so the
    # plugin discovery that lists them is left out.
    monkeypatch.setattr(module, "_builtin_reporters", lambda: ["sarif"])
    return module


@pytest.fixture
def in_tmp(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for name in ("ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_MODE", "ASH_SCANNERS"):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


def _plain(text: str) -> str:
    """The output without color codes, panel borders or line wrapping."""
    return " ".join(_BOX.sub(" ", _ANSI.sub("", text)).split())


def _exit_the_note_names(cli_docs, path: list[str]) -> int:
    """The code in the sentence the generator puts under the --format row of ``ash <path>``."""
    note = cli_docs._value_note(path, SimpleNamespace(opts=["--format", "-f"]))
    assert note, f"the --format row of `ash {' '.join(path)}` has no note"
    (named,) = _EXIT_SENTENCE.findall(note)
    return int(named)


@pytest.mark.parametrize("path", REPORT_COMMANDS)
def test_the_note_names_the_exit_the_command_exits_with(cli_docs, in_tmp, path):
    result = CliRunner().invoke(
        app, [*path, "--output-dir", "out", "--format", NOT_A_REPORTER]
    )

    # The refusal this note describes, not another one that happens to exit first.
    refusal = f"Reporter plugin '{NOT_A_REPORTER}' not found"
    assert refusal in _plain(result.output), result.output
    assert _exit_the_note_names(cli_docs, path) == result.exit_code, result.output


@pytest.mark.parametrize("path", REPORT_COMMANDS)
def test_the_note_reads_the_exit_from_the_constant(cli_docs, monkeypatch, path):
    monkeypatch.setattr(constants, "ASH_EXIT_USAGE_ERROR", 77)

    assert _exit_the_note_names(cli_docs, path) == 77
