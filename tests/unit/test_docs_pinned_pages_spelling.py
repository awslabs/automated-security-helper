# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A hand-written page that pins a release before 3.9 names no command that release refuses.

Why this file exists
--------------------
The pages ``scripts/version_template_manager.py`` renders are spelled for the release
they pin (tests/unit/test_version_template_release_spellings.py): the template holds the
ASH 3.9 command spellings (``ash scan fs``, ``ash results <verb>``, ``ash container
build``) and a render for an earlier release writes the spellings that release reads.

A hand-written page has no template. Its install commands carry the release as a
literal, which ``[tool.commitizen] version_files`` moves at each release, and a page in
that list cannot also be a template target (tests/unit/test_agent_plugin_ash_version.py
holds the two lists apart). So nothing spelled these pages for the release they pin, and
two of them paired an ``@v3.8.0`` install with ``ash scan fs``: a job copied from the
Trivy page installed ASH 3.8, whose ``scan`` takes no path argument and no subject, and
then failed on the first command.

Each such page names the commands of the release it pins: ``ash scan``, and not ``ash
scan fs``, while the pin is a release before 3.9. The bump that moves the pin to 3.9
ends this test's reach for the page and starts the one in
tests/unit/test_docs_no_legacy_spellings.py, which no longer allows the older spellings
there, so the page cannot ship the old commands with a new pin.

What is asserted
----------------
Every hand-written page under ``docs/content/`` that pins a release before 3.9 holds no
spelling only 3.9 reads: a scan subject, a results verb, ``container build``, or one of
the scanner options ``--only-scanners`` and ``--add-scanners`` (3.8 has ``--scanners``,
which 3.9 deprecates). The scope is the page, except for the pages in ``BY_BLOCK``,
where it is each fenced block that holds a pin. The rows check the detector on planted
text, and the control checks that the two pages this was written for are still found.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

from tests.utils.release_spellings import (
    NEWER_OPTION,
    NEWER_SPELLING,
    SUBJECTS_RELEASE,
    release_tuple,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTENT = REPO_ROOT / "docs" / "content"
SCRIPT_PATH = REPO_ROOT / "scripts" / "version_template_manager.py"

#: The pages that pin a release in two CI jobs and give every other command as what
#: the reader runs with the ASH they have. For these the pin binds the fenced block it
#: sits in, not the page. Each entry says why.
BY_BLOCK = {
    "docs/content/docs/plugins/alpha/trivy-plugin.md": (
        "a scanner reference: its commands run on any ASH that has the plugin; only the "
        "GitHub Actions and GitLab CI jobs install a release, and each is one block"
    ),
}

#: Pages whose subject is the spellings themselves, written for readers who hold either
#: release. None pins a release today; an entry is how a page that does is excused.
BOTH_SPELLINGS: dict[str, str] = {}

#: The eight pages the reference generators write.
GENERATED_PAGES = frozenset(
    f"docs/content/reference/{name}.md"
    for name in (
        "cli",
        "configuration",
        "converters",
        "environment-variables",
        "scanner-facets",
        "mcp-tools",
        "reporters",
        "scanners",
    )
)

_FENCE = re.compile(r"^[ \t]*(?P<fence>`{3,}|~{3,})")


def _load_manager():
    spec = importlib.util.spec_from_file_location(
        "version_template_manager_pinned_pages", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.VersionTemplateManager(REPO_ROOT)


MANAGER = _load_manager()


def _pins_before_the_subjects(text: str) -> set[str]:
    """The ASH release pins in ``text`` that name a release before 3.9, the way
    ``convert`` and the docs checks read a pin (``ASH_PIN_PATTERNS``)."""
    return {
        pin
        for pin in MANAGER.release_pins(text)
        if release_tuple(pin) < SUBJECTS_RELEASE
    }


def _fenced_blocks(text: str) -> list[tuple[int, str]]:
    """(number of the first line inside, text inside) of each fenced block."""
    blocks: list[tuple[int, str]] = []
    opener = ""
    first = 0
    inside: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        found = _FENCE.match(line)
        if not opener:
            if found:
                opener, first, inside = found["fence"], number + 1, []
            continue
        closing = line.strip()
        if (
            found
            and closing
            and set(closing) == {opener[0]}
            and len(closing) >= len(opener)
        ):
            blocks.append((first, "\n".join(inside)))
            opener = ""
            continue
        inside.append(line)
    return blocks


def pairing_problems(text: str, *, by_block: bool = False) -> list[str]:
    """What ``text`` names that a release it pins before 3.9 does not read.

    The scope is the whole text, or each fenced block when ``by_block`` is set.
    """
    scopes = _fenced_blocks(text) if by_block else [(1, text)]
    problems = []
    for first, scope in scopes:
        pins = _pins_before_the_subjects(scope)
        if not pins:
            continue
        for pattern in (NEWER_SPELLING, NEWER_OPTION):
            for found in pattern.finditer(scope):
                line = first + scope.count("\n", 0, found.start())
                problems.append(
                    f"line {line}: `{found.group(0)}` beside a pin of "
                    f"{', '.join(sorted(pins))}"
                )
    return problems


def _hand_written_pages() -> dict[str, str]:
    pages = {}
    for path in sorted(CONTENT.rglob("*.md")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if path.with_name(path.name + MANAGER.template_suffix).is_file():
            continue  # rendered from a template, spelled by its render
        if rel in GENERATED_PAGES or rel in BOTH_SPELLINGS:
            continue
        pages[rel] = path.read_text(encoding="utf-8")
    return pages


PINNED = {
    rel: text
    for rel, text in _hand_written_pages().items()
    if _pins_before_the_subjects(text)
}


@pytest.mark.parametrize("rel", sorted(PINNED))
def test_a_page_pinned_before_the_subjects_names_no_spelling_that_release_refuses(rel):
    problems = pairing_problems(PINNED[rel], by_block=rel in BY_BLOCK)
    assert not problems, (
        f"{rel} pins an ASH release before 3.9 and names a command only 3.9 reads, so "
        "a reader who copies the install command and then the next one runs the second "
        "on a release that refuses it. Spell it the way that release reads it (`ash "
        "scan`, with `--source-dir` for a path and `--scanners` for the scanner "
        "selection; `ash <verb>` for the results commands; `ash build-image`), or move "
        "the page to a template so its render does:\n  " + "\n  ".join(problems)
    )


def test_the_pages_this_was_written_for_are_still_found():
    """The control: a page list that loses these two makes every test above pass on
    nothing."""
    assert {
        "docs/content/index.md",
        "docs/content/docs/plugins/alpha/trivy-plugin.md",
    } <= set(PINNED)


def test_every_by_block_page_is_pinned_and_reads_by_block():
    missing = sorted(set(BY_BLOCK) - set(PINNED))
    assert not missing, (
        f"{missing} no longer pins a release before 3.9; drop the entry from BY_BLOCK"
    )


INSTALL = "pip install git+https://github.com/awslabs/automated-security-helper.git@v{}"


def _page(pin: str | None, command: str) -> str:
    """A fenced block of ``command``, after an install of ``pin`` when one is given."""
    install = f"{INSTALL.format(pin)}\n" if pin else ""
    return f"```bash\n{install}{command}\n```\n"


ROWS = [
    # (text, by_block, how many problems)
    (f"```bash\n{INSTALL.format('3.8.0')}\nash scan fs --mode local\n```\n", False, 1),
    (f"```bash\n{INSTALL.format('3.8.0')}\nash scan fs --mode local\n```\n", True, 1),
    (
        f"```bash\n{INSTALL.format('3.8.0')}\n```\n\n```bash\nash results report\n```\n",
        False,
        1,
    ),
    (
        f"```bash\n{INSTALL.format('3.8.0')}\n```\n\n```bash\nash results report\n```\n",
        True,
        0,
    ),
    (f"{INSTALL.format('3.7.1')}\nthen `ash container build`\n", False, 1),
    ("```bash\nash scan fs --mode local\n```\n", False, 0),
    (f"```bash\n{INSTALL.format('3.9.0')}\nash scan fs --mode local\n```\n", False, 0),
    (f"```bash\n{INSTALL.format('3.8.0')}\nash scan --mode local\n```\n", False, 0),
    (f"```bash\n{INSTALL.format('3.8.0')}\nash report\n```\n", False, 0),
    (f"```bash\n{INSTALL.format('3.8.0')}\ndash scan fs\n```\n", False, 0),
    (
        f"````bash\n{INSTALL.format('3.8.0')}\n```\nash scan fs\n````\n",
        True,
        1,
    ),
    # The scanner options 3.8 has not got: only a pinned scope is held to them, and
    # ``--scanners``, the option 3.8 has, is never a problem.
    (_page("3.8.0", "ash scan --only-scanners bandit"), False, 1),
    (_page("3.8.0", "ash scan --add-scanners bandit"), True, 1),
    (_page("3.8.0", "ash scan --scanners bandit"), False, 0),
    (_page(None, "ash scan --only-scanners bandit"), False, 0),
    (_page("3.9.0", "ash scan --only-scanners bandit"), False, 0),
    (
        _page("3.8.0", "echo ok") + "\n" + _page(None, "ash scan --only-scanners x"),
        True,
        0,
    ),
    # A command on two lines joined by a backslash, and a list of arguments.
    (_page("3.8.0", "ash \\\n  scan fs ."), False, 1),
    (_page("3.8.0", "ash \\\n  results report"), True, 1),
    (_page("3.8.0", 'cmd = ["ash", "scan", "fs", "."]'), False, 1),
    (_page("3.8.0", 'cmd = ["ash", "container", "build"]'), True, 1),
    (_page("3.8.0", 'cmd = ["ash", "scan", "--mode", "local"]'), False, 0),
    (_page("3.9.0", 'cmd = ["ash", "scan", "fs", "."]'), False, 0),
]


@pytest.mark.parametrize(
    ("text", "by_block", "count"),
    ROWS,
    ids=[f"row-{index}" for index in range(len(ROWS))],
)
def test_the_detector_on_planted_text(text, by_block, count):
    assert len(pairing_problems(text, by_block=by_block)) == count
