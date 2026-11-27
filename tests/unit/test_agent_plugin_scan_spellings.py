# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The agent plugins name the command spellings of the release they pin.

Why this file exists
--------------------
Each plugin starts ASH's MCP server from a pinned release: the ``ash_version`` of the
transpiler's ``_base/manifest.json``, which ``[tool.commitizen] version_files`` moves at
a release, as it does the pin in ``_base/mcp.json`` and ``_base/commands/scan.md``. For a
container scan the plugin's text tells the user to run the ASH command line instead, and
that command line is the ASH the install pages pin to the same release.

The transpiler copies a ``_base`` body into each output as written and renders no
version into it, so the text cannot be spelled per release the way a docs template is.
It names the spelling of the release it pins, and this file holds it to that. While the
pin is a release before 3.9 the plugin text says ``ash scan --mode container`` and never
``ash scan fs``, which that release refuses: its ``scan`` takes no path argument and no
subject. A first round named both spellings, so the install pin still sat beside the one
its release cannot run.

The bump that moves the pin to 3.9 turns the check around. The text must then name the
subject spelling and no ``ash scan`` without one, so the sources change in the release's
own commit, and the plugin cannot ship the older command with a new pin.

What is asserted
----------------
In the transpiler's sources (``_base/`` and ``templates/``) and in every output it
generates (``plugins/`` and the repository's ``skills/``), the container-scan command is
spelled for the pinned release, and while that release is before 3.9 no text names the
scanner options ``--only-scanners`` and ``--add-scanners``, which only 3.9 reads. The
``tool-reference.md`` copies are left out: the MCP tool generator writes them. The
control is that the sources name the command at all.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
PLUGINS = REPO_ROOT / "ash-agent-plugins" / "agentic-coding"
TRANSPILER = PLUGINS / "transpiler"
SOURCE_ROOTS = [TRANSPILER / "_base", TRANSPILER / "templates"]
OUTPUT_ROOTS = [PLUGINS / "plugins", REPO_ROOT / "skills"]

#: The first release whose CLI reads the subject spellings.
SUBJECTS_RELEASE = (3, 9, 0)

#: A spelling that ASH 3.8 does not read.
NEWER_SPELLING = re.compile(
    r"(?<![\w./-])ash(?:v3)?[ \t]+(?:"
    r"scan[ \t]+(?:fs|workspace|image|git)(?![\w-])"
    r"|results[ \t]+(?:report|diff|trend|merge|inspect)(?![\w-])"
    r"|container[ \t]+build(?![\w-])"
    r")"
)

#: The scanner-selection options ASH 3.8 does not read. It has ``--scanners``, which 3.9
#: deprecates in favor of these two.
NEWER_OPTION = re.compile(r"(?<![\w-])--(?:only|add)-scanners(?![\w-])")

#: ``ash scan`` with no subject after it: the spelling 3.9 deprecates. The workspace and
#: image forms keep their option spellings until their subjects exist, so a command that
#: names one of those options is not this.
SUBJECTLESS_SCAN = re.compile(
    r"(?<![\w./-])ash(?:v3)?[ \t]+scan(?![\w-])"
    r"(?![ \t]+(?:fs|workspace|image|git)(?![\w-]))"
    r"(?![^\n`]*--(?:workspace|image|source-git))"
)

SUFFIXES = {".md", ".mdc", ".j2"}


def _pinned_release() -> tuple[int, int, int]:
    manifest = json.loads((TRANSPILER / "_base" / "manifest.json").read_text("utf-8"))
    major, minor, patch = (
        int(part) for part in manifest["ash_version"].lstrip("v").split(".")[:3]
    )
    return major, minor, patch


RELEASE = _pinned_release()
BEFORE_THE_SUBJECTS = RELEASE < SUBJECTS_RELEASE


def _texts(roots: list[Path]) -> dict[str, str]:
    texts = {}
    for root in roots:
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix not in SUFFIXES:
                continue
            if path.name.endswith("tool-reference.md"):
                continue
            texts[path.relative_to(REPO_ROOT).as_posix()] = path.read_text("utf-8")
    return texts


SOURCES = _texts(SOURCE_ROOTS)
TEXTS = {**SOURCES, **_texts(OUTPUT_ROOTS)}


def _lines(text: str, pattern: re.Pattern[str]) -> list[str]:
    found = []
    for match in pattern.finditer(text):
        number = text.count("\n", 0, match.start()) + 1
        found.append(f"line {number}: {text.splitlines()[number - 1].strip()}")
    return found


def test_the_sources_name_the_container_scan_command():
    """The control: sources that stopped naming the command would pass the tests
    below on nothing."""
    command = "ash scan --mode container" if BEFORE_THE_SUBJECTS else "ash scan fs"
    assert any(command in text for text in SOURCES.values()), (
        f"no plugin source names `{command}`, the container-scan command of a plugin "
        f"that pins ASH {'.'.join(map(str, RELEASE))}"
    )


@pytest.mark.skipif(
    not BEFORE_THE_SUBJECTS, reason="the pin is a release that reads every spelling"
)
@pytest.mark.parametrize("rel", sorted(TEXTS))
def test_a_plugin_pinned_before_3_9_names_no_spelling_that_release_refuses(rel):
    found = _lines(TEXTS[rel], NEWER_SPELLING) + _lines(TEXTS[rel], NEWER_OPTION)
    assert not found, (
        f"{rel} belongs to a plugin that pins ASH {'.'.join(map(str, RELEASE))}, which "
        "refuses these spellings; write `ash scan --mode container`, and `--scanners` "
        "for a scanner selection, which that release reads, until the bump that moves "
        "the pin to 3.9 changes the sources:\n  " + "\n  ".join(found)
    )


@pytest.mark.skipif(
    BEFORE_THE_SUBJECTS, reason="the pin is a release before the subjects"
)
@pytest.mark.parametrize("rel", sorted(TEXTS))
def test_a_plugin_pinned_at_3_9_or_later_names_no_scan_without_a_subject(rel):
    found = _lines(TEXTS[rel], SUBJECTLESS_SCAN)
    assert not found, (
        f"{rel} belongs to a plugin that pins ASH {'.'.join(map(str, RELEASE))}, which "
        "deprecates `ash scan` without a subject; write `ash scan fs --mode "
        "container` with the release's own commit:\n  " + "\n  ".join(found)
    )


ROWS = [
    # (text, the pattern, how many hits)
    ("the user runs `ash scan fs --mode container`", NEWER_SPELLING, 1),
    ("the user runs `ash results merge`", NEWER_SPELLING, 1),
    ("the user runs `ash container build`", NEWER_SPELLING, 1),
    ("the user runs `ash scan --mode container`", NEWER_SPELLING, 0),
    ("the user runs `ash report`", NEWER_SPELLING, 0),
    ("the user runs `dash scan fs`", NEWER_SPELLING, 0),
    ("the user runs `ash scan --only-scanners bandit`", NEWER_OPTION, 1),
    ("the user runs `ash scan --add-scanners bandit`", NEWER_OPTION, 1),
    ("the user runs `ash scan --scanners bandit`", NEWER_OPTION, 0),
    ("the user runs `ash scan --exclude-scanners bandit`", NEWER_OPTION, 0),
    ("the user runs `ash scan --mode container`", SUBJECTLESS_SCAN, 1),
    ("the user runs `ash scan`", SUBJECTLESS_SCAN, 1),
    ("the user runs `ash scan fs --mode container`", SUBJECTLESS_SCAN, 0),
    ("a workspace: `ash scan --workspace f.code-workspace`", SUBJECTLESS_SCAN, 0),
    ("an image: `ash scan --image app:1`", SUBJECTLESS_SCAN, 0),
    ("the user runs `dash scan --mode container`", SUBJECTLESS_SCAN, 0),
]


@pytest.mark.parametrize(
    ("text", "pattern", "count"),
    ROWS,
    ids=[f"row-{index}" for index in range(len(ROWS))],
)
def test_the_detectors_on_planted_text(text, pattern, count):
    assert len(_lines(text, pattern)) == count
