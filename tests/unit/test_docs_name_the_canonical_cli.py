# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The user docs spell commands with `ashx`, the v4 entry point.

Why this exists
---------------
v4 renamed the command to `ashx` and kept `ash` as a deprecated alias that prints
a warning, and on Windows under MSYS2 or Git for Windows `ash` is the Almquist
shell. Text merged from main keeps arriving with v3's spelling: #780 added
"`cd vendor && ash scan`" to docs/content/docs/scanner-sandbox.md. A reader copies
these commands, so this reads every page under docs/content and refuses `ash`
followed by one of its subcommands where a shell would run it: at the start of a
line, after whitespace, a backtick, `(`, `&`, `;` or `|`.

Naming the alias itself ("the deprecated `ash` alias") is not a command and passes.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.utils.helpers import iter_repo_files

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[2]
DOCS = REPO / "docs" / "content"

#: Every top-level command, so text merged from main that spells one with v3's name
#: is refused like the older commands: main's ``container``, ``results`` and
#: ``suppress`` groups (``ashx container build``, ``ashx results report``, ``ashx
#: suppress add``) included. test_every_top_level_command_is_checked holds the list
#: to the commands the CLI registers; ``image`` is kept for older pages.
SUBCOMMANDS = (
    "scan",
    "config",
    "dependencies",
    "mcp",
    "report",
    "plugin",
    "inspect",
    "merge",
    "image",
    "get-genai-guide",
    "container",
    "results",
    "build-image",
    "diff",
    "trend",
    "suppress",
    "express",
)
V3_COMMAND = re.compile(
    r"(?:^|(?<=[\s`(&;|]))ash (?:" + "|".join(SUBCOMMANDS) + r")(?=[\s`]|$)",
    re.MULTILINE,
)


def v3_commands(text: str) -> list[int]:
    """Line numbers in ``text`` that spell a command with `ash`."""
    return [text.count("\n", 0, m.start()) + 1 for m in V3_COMMAND.finditer(text)]


def _pages() -> list[Path]:
    return sorted(p for p in iter_repo_files(DOCS) if p.suffix == ".md")


def test_the_walk_reads_the_docs():
    pages = {p.relative_to(REPO).as_posix() for p in _pages()}
    assert "docs/content/docs/scanner-sandbox.md" in pages
    assert len(pages) > 50


def test_no_page_spells_a_command_with_ash():
    hits = [
        f"{page.relative_to(REPO).as_posix()}:{line}"
        for page in _pages()
        for line in v3_commands(page.read_text(encoding="utf-8"))
    ]
    assert not hits, "spell these commands `ashx`:\n" + "\n".join(hits)


@pytest.mark.parametrize(
    "text",
    [
        "ash scan --source-dir .",
        "`cd vendor && ash scan`, where",
        "run `ash config lint` first",
        "$(ash report --format yaml)",
        "x | ash dependencies install",
        "`ash container build --offline`",
        "ash results report --format html",
        "create both with `ash suppress add`",
        "`ash express start` refuses",
    ],
)
def test_each_v3_spelling_is_reported(text):
    assert v3_commands(text) == [1]


def _root_commands() -> set[str]:
    """The top-level commands the CLI registers, read without building any."""
    import typer.main

    from automated_security_helper.cli.main import app

    return set(typer.main.get_command(app).commands.keys())


def test_every_top_level_command_is_checked():
    """A command missing here is not checked at all: ``suppress`` came from main
    with its pages spelled ``ash suppress ...`` while this list held only the
    commands it already had."""
    commands = _root_commands()
    assert "suppress" in commands and "scan" in commands
    assert commands <= set(SUBCOMMANDS), sorted(commands - set(SUBCOMMANDS))


def test_the_reference_generator_spells_every_top_level_command():
    """scripts/_reference_docs.py rewrites generated pages with the same list, so a
    command it leaves out reaches the reference pages spelled with v3's name."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_ash_reference_docs_for_canonical_cli", REPO / "scripts" / "_reference_docs.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    commands = _root_commands()
    assert commands <= set(module._CLI_SUBCOMMANDS), sorted(
        commands - set(module._CLI_SUBCOMMANDS)
    )
    assert module.canonical_cli("run `ash suppress add` first") == (
        "run `ashx suppress add` first"
    )


@pytest.mark.parametrize(
    "text",
    [
        "ashx scan --source-dir .",
        "the deprecated `ash` alias still works",
        "a flash scan of the tree",
        "the ash scanners",
        "automated-security-helper scan",
    ],
)
def test_v4_spellings_pass(text):
    assert v3_commands(text) == []
