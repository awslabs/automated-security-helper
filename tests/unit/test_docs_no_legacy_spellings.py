"""A hand-written page or template gives no command in a spelling ASH 3.9 deprecates.

Why this file exists
--------------------
ASH 3.9 gives each command one spelling and keeps the earlier one working for a
release, with a deprecation line on every run, until ASH 4.0 removes it:

* ``ash scan fs [PATH]`` replaces bare ``ash [options]`` and ``ash scan [options]``
  with no subject, and the PATH argument replaces ``--source-dir``;
* ``--only-scanners`` and ``--add-scanners`` replace ``--scanners``;
* ``ash results <verb>`` replaces ``ash report``, ``ash diff``, ``ash trend``,
  ``ash merge`` and ``ash inspect``;
* ``ash container build`` replaces ``ash build-image``.

The pages and templates were moved to the new spellings by hand, and nothing kept
them there. A page edited later from memory, or copied from an older one, brings an
old spelling back, and a reader who copies its command gets a deprecation line on
every run and a command that stops working in 4.0.

What is read
------------
Every command a source gives: in a fenced block, an inline code span or a list of
arguments, at the start of a line or in the middle of a sentence. Each source is one of:

* a template (``*.md.template`` under docs/content, and README.md.template), the
  source its page is rendered from, written for the newest release;
* a journey (docs/journeys), the source of a generated template;
* a hand-written page under docs/content: one with no template beside it, and not one
  of the eight pages the reference generators write.

The ``.md`` file beside a template is that template rendered for the release the page
documents (scripts/version_template_manager.py). A render for a release before 3.9
writes the spellings that release reads, so it is not read here; the template is.

What is allowed, and why
------------------------
* A hand-written page that pins a release before 3.9, in whole, or for the pages named
  in ``BY_BLOCK`` of tests/unit/test_docs_pinned_pages_spelling.py, in the fenced
  blocks that hold the pin: its install command gives a reader that release, which
  reads only the older spellings, and that test holds the page to them. The bump that
  moves the pin to 3.9 ends the exemption, so a page cannot ship the old commands
  with a new pin.
* A page whose subject is the old spelling, named in ``ABOUT_THE_OLD_SPELLINGS`` with
  its reason. No history page is among them: CHANGELOG.md and the release notes are
  outside docs/content, and the docs checks treat them as history already.
* The workspace, image and git scans, until their subject exists. ``ash scan
  workspace``, ``ash scan image`` and ``ash scan git`` are not commands yet: those
  scans are ``ash scan --workspace``, ``--image``, ``--image-archive``,
  ``--image-layout`` and ``--source-git``, and ``ash --workspace``. A command that
  carries one of those options may have no subject (``SUBJECT_OPTIONS``). It is still
  held to the other deprecations: ``--source-dir`` and ``--scanners`` are refused
  beside it. The day a subject lands, its option leaves ``SUBJECT_OPTIONS`` and the
  pages that use it fail here until they move.
* A command a page gives in a deprecated spelling on purpose, named in
  ``NAMED_ON_PURPOSE`` with the page and the reason: what an older release runs, or
  an example of how the old spelling fails. The entry is the command's text, so a
  second command on the same line is not excused with it.
* A page whose move another change owns, named in ``NOT_MOVED_HERE`` with the reason.
  An entry a page no longer needs fails its own test, so none stays behind.

Not read: a sample of what ASH prints (a message that names a command names it as
ASH does), a command named in prose with no option (``ash scan`` as the group), and
``./ash`` and ``Invoke-ASH``, which take ``--source-dir`` themselves. The rows at the
end check each of these on planted text.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from typing import NamedTuple

import pytest

from tests.utils.release_spellings import RESULTS_VERBS, SCAN_SUBJECTS

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTENT = REPO_ROOT / "docs" / "content"
JOURNEYS = REPO_ROOT / "docs" / "journeys"
PINNED_TEST = REPO_ROOT / "tests" / "unit" / "test_docs_pinned_pages_spelling.py"

#: What `ash scan` can be told to scan after the subjects.
SUBJECTS = SCAN_SUBJECTS

#: The scan options that choose something other than a directory. Their subject is not
#: a command yet, so a page spells those scans without one (see the docstring).
SUBJECT_OPTIONS = frozenset(
    {"--workspace", "--image", "--image-archive", "--image-layout", "--source-git"}
)

#: The top-level commands that moved: ``ash results <verb>`` and ``ash container build``.
LEGACY_VERBS = ("build-image", *RESULTS_VERBS)

#: What follows ``ash inspect``: a word that is a subcommand, not a word of prose.
INSPECT_VERBS = ("findings", "sarif-fields")

#: What bare ``ash`` still takes of its own.
ROOT_OPTIONS = frozenset(
    {"--version", "--help", "-h", "--install-completion", "--show-completion"}
)

#: Pages whose subject is the old spelling: each says how to move off it, or quotes it.
ABOUT_THE_OLD_SPELLINGS = {
    "docs/content/how-to/migrate-to-scan-subjects.md": (
        "the page that moves a reader from each deprecated spelling to its replacement"
    ),
}

#: Commands a page gives in a deprecated spelling on purpose: {page: {the command's
#: text: why}}. The text is what ``legacy_forms`` reports, from ``ash`` to the end of the
#: command. Each entry is dropped when the page stops giving the command.
NAMED_ON_PURPOSE = {
    "docs/content/how-to/aidlc-workflows.md": {
        "ash scan --mode precommit --no-progress": (
            "what the plugin runs on an ASH older than 3.9, which has no `ash scan fs`"
        ),
        "ash scan --no-progress": (
            "what the plugin runs on an ASH older than 3.9, which has no `ash scan fs`"
        ),
    },
    "docs/content/reference/exit-codes.md": {
        "ash --source-dir . config get": (
            "the page's example of an option typed before a subcommand, which is a "
            "usage error when that command does not take it"
        ),
    },
}

#: Pages another change moves. Each entry is dropped when its page needs none.
NOT_MOVED_HERE = {
    "docs/content/how-to/scale-large-repos.md.template": (
        "its examples pass --scanners; the change that owns the page moves them"
    ),
}

NO_SUBJECT = "ash scan with no subject"
BARE_WITH_OPTIONS = "ash with options and no subcommand"
BARE = "ash alone"

#: ``ash`` or ``ashv3`` as a word of its own: not ``./ash``, ``.ash/``, ``ash.yaml``,
#: ``ash_output``, ``kind=ash``, ``automated-security-helper`` or ``hash``; not the name
#: of the pre-commit hook (``pre-commit run ash``); and not the quoted first item of a
#: list of arguments, which ``_LIST`` reads.
_COMMAND = re.compile(
    r"""(?<![\w./$=-])(?<!pre-commit run )(?<!prek run )ash(?:v3)?(?![\w./"'-])"""
)
#: A command given as a list of strings: ``["ash", "scan", "--source-dir", "."]``.
_LIST = re.compile(
    r"""["']ash(?:v3)?["'][ \t]*,[ \t]*(?P<items>(?:["'][^"'\n]*["'][ \t]*,?[ \t]*)+)"""
)
_ITEM = re.compile(r"""["']([^"'\n]*)["']""")
#: Where a command in a line ends: an inline code span, a second command, a redirect,
#: a closing parenthesis or a comment.
_END = re.compile(r"[`;&|<>)]|[ \t]#")
#: What may come before ``ash`` on a line that starts a command: a prompt, a list dash,
#: a key that holds a command, an environment assignment, ``uv run``.
_AT_LINE_START = re.compile(
    r"^[ \t]*(?:[$>-][ \t]+)*"
    r"(?:(?:run|script|entry|command|cmd|args|exec|shell|scan):[ \t]+)?"
    r"(?:[A-Z_][A-Z0-9_]*=\S*[ \t]+)*(?:uv[ \t]+run[ \t]+)?$"
)


class Hit(NamedTuple):
    """A command in a deprecated spelling: its line, what is deprecated, its text."""

    line: int
    what: str
    command: str


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


#: The test that holds a page pinned before 3.9 to the older spellings, and so defines
#: which pages those are and which of them are read by block.
PINNED = _load("_docs_pinned_pages_for_no_legacy_spellings", PINNED_TEST)
MANAGER = PINNED.MANAGER


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """(number of the first physical line, the line) with each ``\\`` continuation joined."""
    lines = text.splitlines()
    joined: list[tuple[int, str]] = []
    index = 0
    while index < len(lines):
        number = index + 1
        line = lines[index]
        while line.rstrip().endswith("\\") and index + 1 < len(lines):
            index += 1
            line = line.rstrip()[:-1] + " " + lines[index].strip()
        joined.append((number, line))
        index += 1
    return joined


def _until_the_command_ends(tail: str) -> str:
    ended = _END.search(tail)
    return tail[: ended.start()] if ended else tail


def _words(items: str) -> list[str]:
    """The arguments in ``items``, without their quotes."""
    return [word for word in (w.strip("\"',") for w in items.split()) if word]


def _option(word: str) -> str:
    return word.split("=", 1)[0]


def _like_an_argument(word: str | None) -> bool:
    """An option, a path or an assignment: not a word of prose."""
    return word is not None and (word.startswith("-") or any(c in word for c in "/.="))


def _forms(words: list[str], at_line_start: bool) -> list[str]:
    """What is deprecated in the command whose words after ``ash`` are ``words``."""
    first = words[0] if words else None
    second = words[1] if len(words) > 1 else None
    options = {_option(word) for word in words if word.startswith("-")}
    other_subject = bool(options & SUBJECT_OPTIONS)
    forms: list[str] = []
    if first == "scan":
        if second in SUBJECTS:
            pass
        elif (second is None and at_line_start) or (second or "").startswith("-"):
            if not other_subject:
                forms.append(NO_SUBJECT)
        else:
            return []
    elif first is None:
        return [BARE] if at_line_start else []
    elif first.startswith("-"):
        if _option(first) in ROOT_OPTIONS or first == "--":
            return []
        if not other_subject:
            forms.append(BARE_WITH_OPTIONS)
    elif first in LEGACY_VERBS and (
        (second is None and at_line_start)
        or _like_an_argument(second)
        or (first == "inspect" and second in INSPECT_VERBS)
    ):
        return [f"ash {first}"]
    else:
        return []
    if "--source-dir" in options:
        forms.append("--source-dir")
    if "--scanners" in options:
        forms.append("--scanners")
    return forms


def legacy_forms(text: str) -> list[Hit]:
    """Each command in ``text`` spelled the way 3.9 deprecates, in the order read."""
    found: list[Hit] = []
    for number, line in _logical_lines(text):
        for match in _COMMAND.finditer(line):
            at_line_start = bool(_AT_LINE_START.match(line[: match.start()]))
            given = _until_the_command_ends(line[match.end() :])
            command = " ".join((match[0] + given).split())
            found += [
                Hit(number, what, command)
                for what in _forms(_words(given), at_line_start)
            ]
        for match in _LIST.finditer(line):
            command = " ".join(match[0].split())
            found += [
                Hit(number, what, command)
                for what in _forms(_ITEM.findall(match["items"]), True)
            ]
    return found


def _scoped(rel: str, text: str) -> str | None:
    """The part of a hand-written page this test reads, or None when it reads none.

    A page that pins a release before 3.9 is not read: the older spellings are the
    right ones for it. For a page read by block, only the blocks that hold the pin are
    left out, and their lines are blanked so the others keep their numbers.
    """
    if rel not in PINNED.PINNED:
        return text
    if rel not in PINNED.BY_BLOCK:
        return None
    lines = text.splitlines()
    for first, block in PINNED._fenced_blocks(text):
        if PINNED._pins_before_the_subjects(block):
            for number in range(first, first + block.count("\n") + 1):
                lines[number - 1] = ""
    return "\n".join(lines)


def _sources() -> dict[str, str]:
    sources: dict[str, str] = {}
    for rel, text in PINNED._hand_written_pages().items():
        if rel in ABOUT_THE_OLD_SPELLINGS:
            continue
        scoped = _scoped(rel, text)
        if scoped is not None:
            sources[rel] = scoped
    templates = [
        *sorted(CONTENT.rglob("*.md" + MANAGER.template_suffix)),
        REPO_ROOT / ("README.md" + MANAGER.template_suffix),
    ]
    for path in [*templates, *sorted(JOURNEYS.glob("*.journey.yaml"))]:
        sources[path.relative_to(REPO_ROOT).as_posix()] = path.read_text(
            encoding="utf-8"
        )
    return sources


SOURCES = _sources()


def _unexcused(rel: str) -> list[Hit]:
    on_purpose = NAMED_ON_PURPOSE.get(rel, {})
    return [hit for hit in legacy_forms(SOURCES[rel]) if hit.command not in on_purpose]


@pytest.mark.parametrize("rel", sorted(set(SOURCES) - set(NOT_MOVED_HERE)))
def test_a_page_or_template_gives_no_command_in_a_deprecated_spelling(rel):
    problems = [
        f"line {hit.line}: {hit.what}: {hit.command}" for hit in _unexcused(rel)
    ]
    assert not problems, (
        f"{rel} gives a command in a spelling ASH 3.9 deprecates, so a reader who "
        "copies it gets a deprecation line on every run and a command that stops "
        "working in 4.0. Spell it as 3.9 does (`ash scan fs [PATH]`, `--only-scanners`, "
        "`ash results <verb>`, `ash container build`), or, for a scan of a workspace, "
        "an image or a git repository, with the option that chooses it:\n  "
        + "\n  ".join(problems)
    )


def test_the_sources_this_was_written_for_are_still_read():
    """The control: a source list that loses these makes every test above pass on
    nothing."""
    assert {
        "README.md.template",
        "docs/content/getting-started/local.md.template",
        "docs/journeys/getting-started-local.journey.yaml",
        "docs/content/reference/exit-codes.md",
        "docs/content/how-to/configure.md",
    } <= set(SOURCES)
    assert len(SOURCES) > 40, len(SOURCES)


def test_a_rendered_twin_of_a_template_is_not_read():
    """The ``.md`` beside a template is the template for an older release."""
    assert "docs/content/getting-started/local.md" not in SOURCES
    assert "README.md" not in SOURCES


@pytest.mark.parametrize("rel", sorted(ABOUT_THE_OLD_SPELLINGS))
def test_a_page_about_the_old_spellings_exists_and_is_left_out(rel):
    assert (REPO_ROOT / rel).is_file(), f"{rel} is gone; drop it from the allowlist"
    assert rel not in SOURCES, rel


@pytest.mark.parametrize(
    ("rel", "command"),
    [
        (rel, command)
        for rel, commands in sorted(NAMED_ON_PURPOSE.items())
        for command in commands
    ],
)
def test_a_command_named_on_purpose_is_still_on_its_page(rel, command):
    """An entry for a command the page no longer gives is dropped."""
    assert rel in SOURCES, f"{rel} is not read; drop it from NAMED_ON_PURPOSE"
    given = [hit for hit in legacy_forms(SOURCES[rel]) if hit.command == command]
    assert given, f"{rel} no longer gives {command!r}: drop it from NAMED_ON_PURPOSE"


@pytest.mark.parametrize("rel", sorted(NOT_MOVED_HERE))
def test_an_entry_in_not_moved_here_exists_and_is_still_needed(rel):
    """An excuse a page no longer needs is dropped, so it cannot excuse a new one."""
    assert rel in SOURCES, f"{rel} is gone; drop it from NOT_MOVED_HERE"
    assert legacy_forms(SOURCES[rel]), (
        f"{rel} no longer gives a deprecated spelling: drop it from NOT_MOVED_HERE"
    )


def _page(*lines: str) -> str:
    return "\n".join(lines) + "\n"


#: (text, the deprecated spellings found in it, in order)
ROWS = [
    # What is refused.
    (_page("```bash", "ash scan --mode local", "```"), [NO_SUBJECT]),
    (_page("```bash", "ash", "echo $?", "```"), [BARE]),
    (_page("```bash", "$ ash --mode container", "```"), [BARE_WITH_OPTIONS]),
    (_page("Run `ash scan --offline` first."), [NO_SUBJECT]),
    (_page("Run ash --scanners bandit first."), [BARE_WITH_OPTIONS, "--scanners"]),
    (_page("ash scan fs . --scanners bandit"), ["--scanners"]),
    (_page("ash scan fs --source-dir ."), ["--source-dir"]),
    (_page("ash scan --source-dir . --only-scanners x"), [NO_SUBJECT, "--source-dir"]),
    (_page("ash --source-dir . scan fs"), [BARE_WITH_OPTIONS, "--source-dir"]),
    (_page("ash --source-dir . config get"), [BARE_WITH_OPTIONS, "--source-dir"]),
    (_page("ash report --format json"), ["ash report"]),
    (_page("```", "ash merge", "```"), ["ash merge"]),
    (_page("ash diff before.json after.json"), ["ash diff"]),
    (_page("ash build-image --no-run"), ["ash build-image"]),
    (_page("ash inspect findings"), ["ash inspect"]),
    (_page("  entry: ashv3 scan --mode=precommit --staged"), [NO_SUBJECT]),
    (_page("  run: ash scan --offline"), [NO_SUBJECT]),
    (_page("docker run --rm image ash scan --mode local"), [NO_SUBJECT]),
    (_page("ASH_OFFLINE=1 ash --offline"), [BARE_WITH_OPTIONS]),
    (_page("uv run ash scan --source-dir ."), [NO_SUBJECT, "--source-dir"]),
    (
        _page("ash scan --mode local \\", "  --scanners bandit"),
        [NO_SUBJECT, "--scanners"],
    ),
    (_page('cmd = ["ash", "--only-scanners", "trivy-repo"]'), [BARE_WITH_OPTIONS]),
    (_page("cmd = ['ash', 'scan', '--offline']"), [NO_SUBJECT]),
    (_page('cmd = ["ash", "scan", "--source-dir", "."]'), [NO_SUBJECT, "--source-dir"]),
    (_page('{"run": "ash scan --mode local"}'), [NO_SUBJECT]),
    # What is not.
    (_page("ash scan fs . --only-scanners bandit --offline"), []),
    (_page("ash scan fs --mode precommit --staged"), []),
    (_page("ash results report --format json"), []),
    (_page("ash results merge --results a.json"), []),
    (_page("ash results inspect findings"), []),
    (_page("ash container build --no-run"), []),
    (_page('cmd = ["ash", "scan", "fs", ".", "--only-scanners", "x"]'), []),
    (_page("ash --version", "ash --help", "ash -h"), []),
    (_page("ash config validate --source-dir ."), []),
    (_page("ash mcp --transport stdio"), []),
    (_page("claude mcp add ash -- ash mcp"), []),
    (_page("pre-commit run ash --all-files"), []),
    (_page("<!-- doctest: config kind=ash -->"), []),
    (_page("./ash --source-dir . --mode container"), []),
    (_page("Invoke-ASH -SourceDir . -Mode container"), []),
    (_page("ASH_SCANNERS is read as --scanners."), []),
    (_page("ash scan --exclude-scanners bandit"), [NO_SUBJECT]),
    (_page("ash scan fs . --exclude-scanners bandit"), []),
    # A command named in prose, or in a quoted message.
    (_page("The `ash scan` group has one subject, `fs`."), []),
    (_page("Press `ash scan <TAB>` to see the subjects."), []),
    (_page("Warning: ash merge cannot tell that config from the scanned tree"), []),
    (_page("ash report writes its log to standard error."), []),
    (_page("See [ash scan](#scan) for the codes."), []),
    (_page("automated-security-helper and ash.yaml and .ash/ash_output"), []),
    # The scans that have no subject yet.
    (_page("ash scan --workspace services.code-workspace --only-scanners x"), []),
    (_page("ash --workspace services.code-workspace"), []),
    (_page("ash scan --image alpine:3 --only-scanners trivy-image"), []),
    (_page("ash scan --image-archive app.tar"), []),
    (_page("ash scan --image-layout ./app-layout/"), []),
    (_page("ash scan --source-git https://example.com/r.git"), []),
    # ... which are still held to the other deprecations.
    (_page("ash scan --workspace w.code-workspace --scanners x"), ["--scanners"]),
    (_page("ash scan --image alpine:3 --source-dir ."), ["--source-dir"]),
]


@pytest.mark.parametrize(
    ("text", "expected"),
    ROWS,
    ids=[f"row-{index}" for index in range(len(ROWS))],
)
def test_the_detector_on_planted_text(text, expected):
    assert [hit.what for hit in legacy_forms(text)] == expected, text


def test_a_hit_names_the_command_and_not_the_line_around_it():
    hits = legacy_forms(_page("Run `ash scan --offline` first, then `ash scan fs .`."))
    assert [hit.command for hit in hits] == ["ash scan --offline"]


def test_a_continued_command_is_numbered_by_its_first_line():
    joined = legacy_forms(_page("ash scan \\", "--offline"))
    after_a_line = legacy_forms(_page("one", "ash scan --offline"))
    assert [hit.line for hit in joined] == [1]
    assert [hit.line for hit in after_a_line] == [2]
