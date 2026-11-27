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
spelling only 3.9 reads: a scan subject, a results verb, ``ash diff`` or ``ash trend``
(3.8 has neither, and no release has had them at the top level, so a page for it names
them in neither spelling), ``container build``, or one of the scanner options
``--only-scanners`` and ``--add-scanners`` (3.8 has ``--scanners``, which 3.9
deprecates). The scope is the page, except for the pages in ``BY_BLOCK``,
where it is each fenced block that holds a pin. The rows check the detector on planted
text, and the controls check that the two pages this was written for are still found.

The controls read the release the repository is at (``[tool.commitizen] version``, the
field the bump moves), so they hold on both sides of the bump that moves the pins to
3.9. Until then the pages are in the scope above and found by it. From then on they pin
the new release, the scope no longer reaches them, and the controls find them by their
pin instead. The rows hold that for the pins the bump leaves, and a row fails when a
control names a release of its own.
"""

from __future__ import annotations

import importlib.util
import inspect
import re
import sys
from collections.abc import Collection, Mapping
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


PAGES = _hand_written_pages()

PINNED = {rel: text for rel, text in PAGES.items() if _pins_before_the_subjects(text)}


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


#: The pages this test was written for. Each carries install commands of ASH, and
#: ``[tool.commitizen] version_files`` keeps their pins at the current release; neither
#: can be a template (tests/unit/test_agent_plugin_ash_version.py holds the two lists
#: apart). The first control reads them.
CONTROL_PAGES = frozenset(
    {
        "docs/content/index.md",
        "docs/content/docs/plugins/alpha/trivy-plugin.md",
    }
)


def _current_release() -> str:
    """The release the repository is at: the ``[tool.commitizen] version`` that the bump
    moves, read where the version manager reads it."""
    return MANAGER.packaged_release()


def control_problems(
    release: str,
    pages: Mapping[str, str],
    scoped: Collection[str],
    named: Collection[str],
) -> list[str]:
    """What is wrong with the pages ``named`` while the repository is at ``release``.

    ``pages`` are the hand-written pages by path and ``scoped`` the paths this test
    reads, those that pin a release before 3.9. A page named here pins ``release``,
    because the bump moves its pin with the version; one read by block holds a pin in a
    fenced block of its own; and it is in ``scoped`` exactly while ``release`` is
    before 3.9. So the answer is the same on both sides of the bump that moves the pins
    to 3.9: before it the pages are found by this test's scope, and after it they are
    found by their pin and out of the scope, which is where
    tests/unit/test_docs_no_legacy_spellings.py starts to read them.
    """
    before = release_tuple(release) < SUBJECTS_RELEASE
    problems = []
    for rel in sorted(named):
        text = pages.get(rel)
        if text is None:
            problems.append(f"{rel} is not a hand-written page of docs/content")
            continue
        pins = MANAGER.release_pins(text)
        if release not in pins:
            problems.append(
                f"{rel} pins {', '.join(sorted(pins)) or 'no release'}, and the "
                f"repository is at {release}"
            )
        if (rel in scoped) != before:
            problems.append(
                f"{rel} is {'not ' if before else ''}read by this test, and the "
                f"repository is at {release}, a release "
                f"{'before' if before else 'that is not before'} 3.9"
            )
        if rel in BY_BLOCK and not any(
            MANAGER.release_pins(block) for _first, block in _fenced_blocks(text)
        ):
            problems.append(f"{rel} is read by block, and no fenced block of it pins")
    return problems


def test_the_pages_this_was_written_for_are_still_found():
    """The control: a page list that loses these two makes every test above pass on
    nothing. It reads the release the repository is at, so it holds before the bump
    that moves the pins to 3.9 and after it."""
    problems = control_problems(_current_release(), PAGES, set(PINNED), CONTROL_PAGES)
    assert not problems, "\n  ".join(problems)


def test_every_by_block_page_is_pinned_and_reads_by_block():
    """Each page excused by block still pins a release in a block of its own, so the
    excuse has something to bind. It reads the release the repository is at, as the
    control above does; once the pins are at 3.9 the entry reads no block, and it can
    be dropped from BY_BLOCK in a later change."""
    problems = control_problems(_current_release(), PAGES, set(PINNED), set(BY_BLOCK))
    assert not problems, "\n  ".join(problems)


#: The install command that pins a release. Its pin is written ``<pin>``, one of the
#: placeholders tests/unit/test_agent_plugin_ash_version.py exempts: that guard reads
#: every pin after the repository name in the tree, this file included, as a release or
#: a placeholder, and a ``{}`` or a literal release written here would be a malformed or
#: a stale pin of its own. ``_install`` puts a release in its place.
INSTALL = (
    "pip install git+https://github.com/awslabs/automated-security-helper.git@v<pin>"
)


def _install(pin: str) -> str:
    """The install command pinned to the release ``pin``."""
    return INSTALL.replace("<pin>", pin)


def _page(pin: str | None, command: str) -> str:
    """A fenced block of ``command``, after an install of ``pin`` when one is given."""
    install = f"{_install(pin)}\n" if pin else ""
    return f"```bash\n{install}{command}\n```\n"


ROWS = [
    # (text, by_block, how many problems)
    (f"```bash\n{_install('3.8.0')}\nash scan fs --mode local\n```\n", False, 1),
    (f"```bash\n{_install('3.8.0')}\nash scan fs --mode local\n```\n", True, 1),
    (
        f"```bash\n{_install('3.8.0')}\n```\n\n```bash\nash results report\n```\n",
        False,
        1,
    ),
    (
        f"```bash\n{_install('3.8.0')}\n```\n\n```bash\nash results report\n```\n",
        True,
        0,
    ),
    (f"{_install('3.7.1')}\nthen `ash container build`\n", False, 1),
    ("```bash\nash scan fs --mode local\n```\n", False, 0),
    (f"```bash\n{_install('3.9.0')}\nash scan fs --mode local\n```\n", False, 0),
    (f"```bash\n{_install('3.8.0')}\nash scan --mode local\n```\n", False, 0),
    (f"```bash\n{_install('3.8.0')}\nash report\n```\n", False, 0),
    (f"```bash\n{_install('3.8.0')}\ndash scan fs\n```\n", False, 0),
    (
        f"````bash\n{_install('3.8.0')}\n```\nash scan fs\n````\n",
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
    # `diff` and `trend`: 3.8.0 has neither command, so a page that pins it names them
    # in neither spelling, as `ash results <verb>` or at the top level.
    (_page("3.8.0", "ash results diff a.json b.json"), False, 1),
    (_page("3.8.0", "ash results trend runs/a.json runs/b.json"), True, 1),
    (_page("3.8.0", "ash diff a.json b.json"), False, 1),
    (_page("3.8.0", "ash trend runs/a.json runs/b.json"), True, 1),
    (_page("3.8.0", 'cmd = ["ash", "diff", "a.json", "b.json"]'), False, 1),
    (_page("3.8.0", "ash \\\n  trend runs/a.json"), False, 1),
    (
        _page("3.8.0", "ash report\nash merge --results a\nash inspect findings"),
        False,
        0,
    ),
    (_page("3.9.0", "ash results diff a.json b.json"), False, 0),
    (_page(None, "ash diff a.json b.json"), False, 0),
]


@pytest.mark.parametrize(
    ("text", "by_block", "count"),
    ROWS,
    ids=[f"row-{index}" for index in range(len(ROWS))],
)
def test_the_detector_on_planted_text(text, by_block, count):
    assert len(pairing_problems(text, by_block=by_block)) == count


#: A page that is read by block (BY_BLOCK), for the rows of the controls below.
A_BY_BLOCK_PAGE = "docs/content/docs/plugins/alpha/trivy-plugin.md"

CONTROL_ROWS = [
    # (release the repository is at, the pin the page carries, whether this test reads
    # the page, the page, how many problems the control finds)
    #
    # Before the bump that moves the pins to 3.9: pinned before it, and read.
    ("3.8.0", "3.8.0", True, "docs/content/index.md", 0),
    ("3.8.0", "3.8.0", True, A_BY_BLOCK_PAGE, 0),
    # After it: pinned at the new release, and no longer read.
    ("3.9.0", "3.9.0", False, "docs/content/index.md", 0),
    ("3.9.0", "3.9.0", False, A_BY_BLOCK_PAGE, 0),
    ("3.10.2", "3.10.2", False, "docs/content/index.md", 0),
    # The bump left the pin where it was: the page pins another release, and is read.
    ("3.9.0", "3.8.0", True, "docs/content/index.md", 2),
    # What the controls asserted before: a page read by this test whatever the release.
    ("3.9.0", "3.9.0", True, "docs/content/index.md", 1),
    ("3.9.0", "3.9.0", True, A_BY_BLOCK_PAGE, 1),
    # And the reverse: a page the repository's release says is read, and is not.
    ("3.8.0", "3.8.0", False, "docs/content/index.md", 1),
]


@pytest.mark.parametrize(
    ("release", "pin", "read", "rel", "count"),
    CONTROL_ROWS,
    ids=[f"row-{index}" for index in range(len(CONTROL_ROWS))],
)
def test_the_control_on_planted_pages(release, pin, read, rel, count):
    pages = {rel: _page(pin, "echo ok")}
    problems = control_problems(release, pages, {rel} if read else set(), {rel})
    assert len(problems) == count, problems


def test_the_control_names_a_page_that_is_gone():
    problems = control_problems("3.8.0", {}, set(), {"docs/content/index.md"})
    assert problems == [
        "docs/content/index.md is not a hand-written page of docs/content"
    ]


def test_the_control_names_a_by_block_page_whose_pin_left_its_blocks():
    """The page still pins in a sentence, but no fenced block carries the pin, so the
    block it was excused by is gone."""
    prose = f"Install it with {_install('3.9.0')} and run it.\n"
    problems = control_problems(
        "3.9.0", {A_BY_BLOCK_PAGE: prose}, set(), {A_BY_BLOCK_PAGE}
    )
    assert problems == [
        f"{A_BY_BLOCK_PAGE} is read by block, and no fenced block of it pins"
    ]


def _moved_to(text: str, release: str) -> str:
    """``text`` with the pin of each ASH install command moved to ``release``: the number
    after the ``v``, as the bump writes it, and nothing else."""
    for pattern, _replacement in MANAGER.find_version_references(text):
        text = re.sub(pattern, rf"\g<1>{release}", text)
    return text


@pytest.mark.parametrize("release", ["3.7.1", "3.8.0", "3.9.0", "3.10.2", "4.0.0"])
def test_the_controls_hold_wherever_the_bump_leaves_the_pins(release):
    """The committed pages, with their pins moved to each release: the controls find
    nothing wrong before the bump that moves them to 3.9, after it, and at any release
    after that, so the release pull request does not fail on them."""
    named = CONTROL_PAGES | set(BY_BLOCK)
    pages = {rel: _moved_to(PAGES[rel], release) for rel in sorted(named)}
    scoped = {rel for rel, text in pages.items() if _pins_before_the_subjects(text)}

    assert control_problems(release, pages, scoped, CONTROL_PAGES) == []
    assert control_problems(release, pages, scoped, set(BY_BLOCK)) == []


@pytest.mark.parametrize(
    "control",
    [
        test_the_pages_this_was_written_for_are_still_found,
        test_every_by_block_page_is_pinned_and_reads_by_block,
    ],
    ids=lambda control: control.__name__,
)
def test_a_control_reads_the_release_the_repository_is_at(control):
    """A control that names a release by itself is red from the bump that moves the pins
    past it: both of these once asserted that two pages pin a release before 3.9, with
    no release read. They read the release the repository is at, and name none."""
    source = inspect.getsource(control)

    assert "_current_release()" in source
    assert re.findall(r"\d+\.\d+\.\d+", source) == []
