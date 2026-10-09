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

REPO = Path(__file__).resolve().parents[2]
DOCS = REPO / "docs" / "content"

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
    ],
)
def test_each_v3_spelling_is_reported(text):
    assert v3_commands(text) == [1]


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
