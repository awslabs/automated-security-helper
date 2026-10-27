# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The docs checks and the docs-example runner see the whole corpus, not part of it.

WHY THIS EXISTS
---------------
The corpus had guards against being empty and none against being smaller.
``collect_md_files`` raises when it finds no file, and test_docs_examples.py requires
one runnable page. Each of these regressions passed both, and every other test:

* fences indented under a list item or an admonition parsed as prose;
* ``load_pages`` keeping every other page;
* the runner skipping how-to/.

So this file counts the corpus a second time, without the docs parser, and requires
the two counts to agree: the files the gate collects, one page per file, the fences
on each page, and the pages and blocks the runner runs. The second count is written
here on purpose rather than imported. A shared helper would lose blocks on both sides
at once, and the test would agree with it.

The floors at the bottom are the other half. They pin what the runner executes today,
so a change that stops running examples, deliberately or not, has to lower a number
here in the same commit and say why.

WHAT THIS DOES NOT CHECK
------------------------
That a block is checked correctly, only that it reaches the checks. The fence and
marker rules below are the parser's rules restated, so a change to what counts as a
fence or a marker has to change both, which is the point. The languages the runner
executes and the marker keys it reads are taken from scripts/docs_checks.py, which
defines them, so the comparison cannot see one of those registries shrink. The floors
can.
"""

from __future__ import annotations

import importlib.util
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The runnable pages and the blocks the runner executes on them, measured on this
#: tree. Raise them when runnable blocks are added; lowering one is a decision to run
#: fewer examples, made in the commit that does it.
RUNNABLE_PAGES_FLOOR = 43
EXECUTED_BLOCKS_FLOOR = 151
#: The output samples the runner compares with their run block's output, measured the
#: same way. A sample marker the runner stops honoring would otherwise pass silently,
#: since an uncompared sample fails nothing. The floor in force is this or the count of
#: markers after a runnable block, whichever is higher, so each new marker raises it.
COMPARED_SAMPLES_FLOOR = 14

#: Directories collect_md_files leaves out, restated rather than imported, so that a
#: directory added to its list (or a page set the gate drops) shows up here.
EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "site",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        "test-results",
        "__pycache__",
        ".cache",
        "__snapshots__",
    }
)
#: Paths below the repository root collect_md_files leaves out, restated the same way.
EXCLUDED_PATHS = ("automated_security_helper/plugin_modules/ash_ferret_plugins/spec/",)

_MARKER = re.compile(r"^\s*<!--\s*doctest:(.*?)-->\s*$")


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# The runner's own test module: its pytest_generate_tests decides which pages run, and
# it holds the gate and docs_checks modules the runner uses.
examples = _load(
    "_ash_docs_examples",
    REPO_ROOT / "tests" / "integration" / "docs" / "test_docs_examples.py",
)
gate = examples.gate
checks = examples.checks
runner = examples.runner

# What a session handles, read from the registries that define it rather than copied:
# the languages the runner executes, the marker key that saves a block, and the one
# bare word a marker may hold.
RUNNABLE_LANGS = checks.RUNNER_SHELLS | checks.PYTHON_LANGS
SAVE_AS = checks.SAVE_AS
BARE_KEYS = checks.BARE_KEYS
OUTPUT_MODE = checks.OUTPUT_MODE
#: The languages an output sample may not be: the ones a marker on them means
#: something else for.
NOT_SAMPLE_LANGS = (
    checks.SHELL_LANGS
    | checks.CONFIG_LANGS
    | checks.PYTHON_LANGS
    | checks.DOCKERFILE_LANGS
)


# ---------------------------------------------------------------------------
# The second count
# ---------------------------------------------------------------------------


def _walk_md_files(root: Path) -> set[str]:
    """Every .md and .md.template file git lists under root (tracked, or untracked and
    not ignored), outside the excluded directories and paths.

    A listing, not a filesystem walk, as the gate's is: a walk of the checkout
    descends into tests/pytest-temp and the scan output, which other test workers
    create and remove while this one reads, and would count the markdown they write.
    The listing is still written here rather than imported from the gate, so the two
    counts stay independent.
    """
    listing = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "*.md",
            "*.md.template",
        ],
        capture_output=True,
        check=True,
    )
    found = set()
    for entry in listing.stdout.split(b"\0"):
        if not entry:
            continue
        rel = Path(os.fsdecode(entry)).as_posix()
        if (
            (root / rel).is_file()
            and not EXCLUDED_DIRS.intersection(Path(rel).parts[:-1])
            and not rel.startswith(EXCLUDED_PATHS)
        ):
            found.add(rel)
    return found


def _marker_above(lines: list[str], index: int) -> tuple[str, dict[str, str]] | None:
    """(mode, keys) of a well-formed doctest marker on the line above lines[index].

    A marker the parser rejects (bad quoting, a stray word, a repeated key, a blank
    line before the fence, an options marker) leaves the block unmarked, so it does
    here too.
    """
    if index == 0:
        return None
    match = _MARKER.match(lines[index - 1])
    if not match:
        return None
    try:
        words = shlex.split(match.group(1))
    except ValueError:
        return None
    if not words:
        return None
    mode, rest = ("", words) if "=" in words[0] else (words[0], words[1:])
    keys: dict[str, str] = {}
    for word in rest:
        key, sep, value = word.partition("=")
        if not sep:
            if key not in BARE_KEYS:
                return None
            keys[key] = ""
            continue
        if key in keys:
            return None
        keys[key] = value
    if mode == "options":
        return None
    return mode, keys


def _blocks(text: str) -> list[dict]:
    """Each fenced block of a page: its fence line, language, marker and whether it closes.

    A fence is three or more backticks or tildes after any indentation, so fences
    inside list items and admonitions count. A backtick fence whose info string holds a
    backtick is inline code. A fence closes at the first later line made only of at
    least as many of the same character.
    """
    lines = text.split("\n")
    blocks: list[dict] = []
    current = None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if current is not None:
            char, length = current["fence"]
            if stripped and set(stripped) == {char} and len(stripped) >= length:
                current["closed"] = True
                current = None
            continue
        opening = line.lstrip(" \t")
        for char in "`~":
            length = len(opening) - len(opening.lstrip(char))
            if length < 3:
                continue
            info = opening[length:]
            if char == "`" and "`" in info:
                break
            words = info.split()
            lang = words[0].strip("{}").lstrip(".").lower() if words else ""
            current = {
                "line": index + 1,
                "lang": lang,
                "marker": _marker_above(lines, index),
                "fence": (char, length),
                "closed": False,
            }
            blocks.append(current)
            break
    return blocks


def _runs(block: dict) -> bool:
    """The runner executes a closed shell or python block that is unmarked or ``run``."""
    marker = block["marker"]
    return (
        block["closed"]
        and block["lang"] in RUNNABLE_LANGS
        and (marker is None or marker[0] == "run")
    )


def _saves(block: dict) -> bool:
    """The runner writes a closed save-as block into the page's project."""
    marker = block["marker"]
    return (
        block["closed"]
        and marker is not None
        and bool(marker[1].get(SAVE_AS))
        and marker[0] != "illustrative"
    )


def _is_sample(block: dict) -> bool:
    """A closed block marked output, in a language a sample may be."""
    marker = block["marker"]
    return (
        block["closed"]
        and marker is not None
        and marker[0] == OUTPUT_MODE
        and block["lang"] not in NOT_SAMPLE_LANGS
    )


def _compared(blocks: list[dict]) -> list[int]:
    """Fence lines of the output samples the runner compares: each directly after a
    block it runs."""
    return [
        block["line"]
        for previous, block in zip(blocks, blocks[1:])
        if _is_sample(block) and _runs(previous)
    ]


def _read(rel: str) -> str:
    return (REPO_ROOT / rel).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# The two counts agree
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def corpus() -> list[Path]:
    return gate.collect_md_files()


@pytest.fixture(scope="module")
def pages(corpus):
    return checks.load_pages(corpus, gate.REPO_ROOT)


def test_the_gate_collects_every_markdown_file(corpus):
    collected = {path.relative_to(gate.REPO_ROOT).as_posix() for path in corpus}
    walked = _walk_md_files(REPO_ROOT)
    assert len(walked) > 100, f"the walk found {len(walked)} files; nothing to compare"
    assert collected == walked, (
        f"files the gate does not check: {sorted(walked - collected)}\n"
        f"files it checks that are not docs: {sorted(collected - walked)}"
    )


def test_every_collected_file_is_parsed_into_one_page(corpus, pages):
    assert len(pages) == len(corpus)
    assert [page.path for page in pages] == list(corpus)


def test_every_fence_on_every_page_is_a_block(pages):
    """Per page, the parser's blocks are the fences counted here, at the same lines."""
    differ = {}
    total = 0
    for page in pages:
        expected = [block["line"] for block in _blocks(_read(page.rel))]
        total += len(expected)
        got = [block.fence_line for block in page.blocks]
        if got != expected:
            differ[page.rel] = {
                "fences the parser missed": sorted(set(expected) - set(got)),
                "blocks with no fence": sorted(set(got) - set(expected)),
                "parsed": len(got),
                "counted": len(expected),
            }
    assert total > 500, f"{total} fences in the whole corpus; nothing to compare"
    assert not differ, differ


class _Config:
    @staticmethod
    def getoption(name, default=None):
        return default


class _Metafunc:
    """What pytest hands test_docs_examples.pytest_generate_tests, for the page fixture."""

    fixturenames = ["page"]
    config = _Config()

    def __init__(self):
        self.parametrized = None

    def parametrize(self, argname, values, ids=None):
        assert argname == "page"
        self.parametrized = (list(values), list(ids or []))


@pytest.fixture(scope="module")
def runner_pages():
    """The pages test_docs_examples.py turns into tests, from its own hook."""
    metafunc = _Metafunc()
    examples.pytest_generate_tests(metafunc)
    assert metafunc.parametrized is not None, "the hook parametrized nothing"
    pages, ids = metafunc.parametrized
    assert ids == [page.rel for page in pages]
    return pages


def _expected_runner_pages() -> dict[str, dict[str, list[int]]]:
    """Each .md page with a block to run or save -> the fence lines of those blocks, and
    of the output samples compared with them."""
    expected = {}
    for rel in sorted(_walk_md_files(REPO_ROOT)):
        if not rel.endswith(".md"):
            continue  # a template's rendered page runs instead
        blocks = _blocks(_read(rel))
        runs = [block["line"] for block in blocks if _runs(block)]
        compared = _compared(blocks)
        session = [
            block["line"]
            for block in blocks
            if _runs(block) or _saves(block) or block["line"] in compared
        ]
        if session:
            expected[rel] = {"runs": runs, "session": session}
    return expected


def test_the_runner_runs_every_page_with_an_example(runner_pages):
    expected = _expected_runner_pages()
    got = {page.rel for page in runner_pages}
    assert got == set(expected), (
        f"pages with examples the runner skips: {sorted(set(expected) - got)}\n"
        f"pages it runs with no example: {sorted(got - set(expected))}"
    )
    for page in runner_pages:
        assert [b.fence_line for b in runner.runnable_blocks(page)] == expected[
            page.rel
        ]["runs"], page.rel
        assert [b.fence_line for b in runner.session_blocks(page)] == expected[
            page.rel
        ]["session"], page.rel


def _compared_sample_problems(runner_pages, compared_samples) -> tuple[int, list[str]]:
    """How many samples ``compared_samples`` (the runner's) compares on the pages, and
    where that differs from the count here: a page whose compared samples are not the
    ones counted, or a total under the floor, which is COMPARED_SAMPLES_FLOOR or the
    number of samples counted, whichever is higher."""
    problems = []
    total = counted = 0
    for page in runner_pages:
        expected = _compared(_blocks(_read(page.rel)))
        samples = compared_samples(page)
        got = [b.fence_line for b in page.blocks if id(b) in samples]
        total += len(got)
        counted += len(expected)
        if got != expected:
            problems.append(
                f"{page.rel}: the runner compares the samples at lines {got}, but "
                f"the samples after a runnable block are at {expected}"
            )
    floor = max(COMPARED_SAMPLES_FLOOR, counted)
    if total < floor:
        problems.append(
            f"the runner compares {total} output samples, down from {floor}. If that "
            "is deliberate, lower COMPARED_SAMPLES_FLOOR or remove the markers in the "
            "same commit, and say which samples stopped being compared and why."
        )
    return total, problems


def test_the_runner_compares_every_output_sample(runner_pages):
    total, problems = _compared_sample_problems(runner_pages, runner.compared_samples)
    assert not problems, problems
    assert total >= COMPARED_SAMPLES_FLOOR


def test_a_sample_the_runner_stops_comparing_fails_the_count(runner_pages):
    """The planted defect for the count above: a runner that drops one sample, and one
    that compares none."""
    first = next(
        page for page in runner_pages if len(runner.compared_samples(page)) > 0
    )

    def drop_one(page):
        samples = dict(runner.compared_samples(page))
        if page is first:
            samples.pop(next(iter(samples)))
        return samples

    _total, problems = _compared_sample_problems(runner_pages, drop_one)
    assert any(problem.startswith(f"{first.rel}:") for problem in problems), problems
    assert any("output samples, down from" in problem for problem in problems)
    total, problems = _compared_sample_problems(runner_pages, lambda page: {})
    assert total == 0
    assert any("down from" in problem for problem in problems), problems


def test_every_output_marker_is_compared_or_reported(corpus, pages):
    """A sample marker the runner does not compare is reported by the marker check, so
    no marker can sit on a page without one of the two looking at it."""
    reported = {
        (finding.path, finding.line)
        for finding in checks.check_markers(corpus, gate.REPO_ROOT)
        if "marked output but follows no run block" in finding.message
    }
    unchecked = []
    marked = 0
    for page in pages:
        blocks = _blocks(_read(page.rel))
        compared = set(_compared(blocks))
        for block in filter(_is_sample, blocks):
            marked += 1
            # The marker is on the line above the fence.
            at_marker = (page.rel, block["line"] - 1)
            if block["line"] not in compared and at_marker not in reported:
                unchecked.append(f"{page.rel}:{block['line']}")
    assert not unchecked, (
        f"{len(unchecked)} of {marked} output samples are neither compared nor "
        f"reported: {unchecked}"
    )


def test_the_runner_runs_no_fewer_examples_than_it_did(runner_pages):
    executed = sum(len(runner.runnable_blocks(page)) for page in runner_pages)
    assert len(runner_pages) >= RUNNABLE_PAGES_FLOOR, (
        f"{len(runner_pages)} pages have a runnable example, down from "
        f"{RUNNABLE_PAGES_FLOOR}. If that is deliberate, lower RUNNABLE_PAGES_FLOOR in "
        "the same commit and say which examples stopped running and why."
    )
    assert executed >= EXECUTED_BLOCKS_FLOOR, (
        f"the runner executes {executed} blocks, down from {EXECUTED_BLOCKS_FLOOR}. If "
        "that is deliberate, lower EXECUTED_BLOCKS_FLOOR in the same commit and say "
        "which examples stopped running and why."
    )


# ---------------------------------------------------------------------------
# The second count can disagree
# ---------------------------------------------------------------------------


def test_the_fence_count_sees_what_the_parser_must_not_lose():
    """Indented fences, tildes and longer fences count; inline code and markers do not."""
    page = """\
# Page

1. A step:

    ```bash
    echo indented
    ```

!!! note "Admonition"
    <!-- doctest: illustrative reason="needs Docker" -->
    ```bash
    docker run x
    ```

~~~yaml
a: 1
~~~

<!-- doctest: run expect-exit=2 -->
````python
print('```')
````

```not a fence` because of the backtick

<!-- doctest: save-as=app.py -->
```python
print('saved')
```

```bash
never closed"""
    blocks = _blocks(page)
    assert [b["line"] for b in blocks] == [5, 11, 15, 20, 27, 31]
    assert [b["lang"] for b in blocks] == [
        "bash",
        "bash",
        "yaml",
        "python",
        "python",
        "bash",
    ]
    assert [_runs(b) for b in blocks] == [True, False, False, True, False, False]
    assert [_saves(b) for b in blocks] == [False, False, False, False, True, False]
    assert blocks[-1]["closed"] is False


SAMPLES_PAGE = """\
```bash
echo compared
```

<!-- doctest: output -->
```text
compared
```

<!-- doctest: output -->
```text
follows a sample, so not compared
```

<!-- doctest: illustrative reason="needs Docker" -->
```bash
docker ps
```

<!-- doctest: output -->
```text
follows a block that is not run
```

```python
print("compared too")
```

<!-- doctest: output -->
```console
a marker on a shell block is not a sample
```
"""


def test_the_sample_count_sees_only_samples_after_a_run_block():
    blocks = _blocks(SAMPLES_PAGE)
    assert [b["line"] for b in blocks if _is_sample(b)] == [6, 11, 21]
    assert _compared(blocks) == [6]


def test_the_runner_compares_the_samples_counted_here_on_that_page(tmp_path):
    """Control for the count above, through the docs parser and the runner, and the
    marker check reports the two samples that are not compared."""
    path = tmp_path / "page.md"
    path.write_text(SAMPLES_PAGE, encoding="utf-8")
    page = checks.parse_page(path, tmp_path)
    compared = runner.compared_samples(page)
    assert [b.fence_line for b in page.blocks if id(b) in compared] == [6]
    reported = [
        finding.line
        for finding in checks.check_markers([path], tmp_path)
        if "marked output but follows no run block" in finding.message
    ]
    assert reported == [10, 20]


def test_the_parser_agrees_with_the_fence_count_on_that_page(tmp_path):
    """Control for the comparison above: the same page, through the docs parser."""
    path = tmp_path / "page.md"
    path.write_text(
        "1. A step:\n\n    ```bash\n    echo indented\n    ```\n\n~~~yaml\na: 1\n~~~\n",
        encoding="utf-8",
    )
    page = checks.parse_page(path, tmp_path)
    assert (
        [b.fence_line for b in page.blocks]
        == [b["line"] for b in _blocks(path.read_text(encoding="utf-8"))]
        == [3, 7]
    )
