# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the docs journey twins share. Not a test module.

test_local_tutorial_twin.py runs a tutorial's own blocks through the docs runner and
holds each scan to the exit code the page prints. The twins of the other tutorials
(test_ci_tutorial_twin.py, test_agents_tutorial_twin.py,
test_platform_teams_tutorial_twin.py, test_suppress_findings_twin.py) do the same, and
this module holds the parts they have in common: finding a page's blocks by the heading
they sit under, building the twin page, running it, and reading what the session left
behind.

A twin page is a markdown page of ``run`` blocks, parsed by scripts/docs_checks.py and
run by docs_runner.PageRunner as any docs page is. Each block carries the exit code it
must end with, and the text its output must contain. One twin is one session: every
block runs on one fixture project, in order, so a later block sees what an earlier one
wrote. A block can copy a scan's results into ``$HOME/captures`` (the session's private
home), where the test reads them after the run.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
FENCE = "```"
SCAN_TIMEOUT_S = 300
#: The scan every twin narrows the page's scan to: bandit alone, which needs no network.
BANDIT_SCAN = "ash scan fs --only-scanners bandit --offline"


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


runner = _load("_ash_docs_runner", HERE / "docs_runner.py")
checks = runner.load_docs_checks()


def docs_root(config) -> Path:
    value = config.getoption("--docs-root", default=None)
    return Path(value).resolve() if value else REPO_ROOT


def require_bandit() -> None:
    """Fail, never skip, when bandit is not where a docs session looks for tools.

    A skip would be a green run that ran nothing.
    """
    session_path = runner.session_path()
    if shutil.which("bandit", path=session_path) is None:
        pytest.fail(
            "bandit is not installed where a docs session looks for tools "
            f"({session_path}), so this twin cannot run. Install it with `ash "
            "dependencies install --tool bandit`, or into this environment with the "
            "extras ASH's bandit scanner requires (`uv pip install "
            "'bandit[sarif,toml]'`); the integration-test job must install it before "
            "the docs examples step.",
            pytrace=False,
        )


def parse_page(rel: str, root: Path):
    return checks.parse_page(root / rel, root)


def blocks_under(page, heading: str) -> list:
    """The page's blocks between the heading matching ``heading`` and the next heading.

    ``heading`` is a regular expression matched at the start of the heading text, after
    its ``#`` marks: ``r"3\\."`` for ``## 3. Choose what fails the build``. A section
    runs to the next heading of its own level or a higher one. A page
    with no such heading, or a heading with no block under it, fails with the page and
    the heading named, so a renamed heading cannot turn a twin into one that checks
    nothing.
    """
    pattern = re.compile(rf"^(#{{2,4}})\s+{heading}")
    start, level = next(
        (
            (line, len(match.group(1)))
            for line, text in page.prose
            if (match := pattern.match(text))
        ),
        (None, 0),
    )
    assert start is not None, f"{page.rel} has no heading matching {heading!r}"
    # The section ends at the next heading of its own level or a higher one, so a
    # subsection's blocks belong to the section that holds it.
    end = min(
        (
            line
            for line, text in page.prose
            if line > start
            and (own := re.match(r"^(#{1,6})\s", text))
            and len(own.group(1)) <= level
        ),
        default=10**9,
    )
    found = [b for b in page.blocks if start < b.fence_line < end]
    assert found, f"{page.rel} has no block under the heading matching {heading!r}"
    return found


def only_block(
    blocks: list,
    *needles: str,
    lang: str | None = None,
    without: tuple[str, ...] = (),
):
    """The one block whose body holds every needle and none of ``without``.

    Zero or several fail the twin, naming what it looked for.
    """
    matches = [
        b
        for b in blocks
        if all(n in b.body for n in needles)
        and not any(n in b.body for n in without)
        and (lang is None or b.lang == lang)
    ]
    assert len(matches) == 1, (
        f"expected one block holding {needles!r} without {without!r}, found "
        f"{len(matches)} among {[(b.lang, b.fence_line) for b in blocks]}"
    )
    return matches[0]


def block_exit(block) -> str:
    """The exit code a page marks its block with (``expect-exit=N``), 0 when unmarked."""
    if block.marker is None:
        return "0"
    return str(block.marker.keys.get("expect-exit", "0"))


@dataclass
class Step:
    body: str
    exit: str
    prints: tuple[str, ...]
    absent: tuple[str, ...]


class Twin:
    """A twin page under construction: its steps, and how to run and check them."""

    def __init__(self, title: str, fixture: str = "empty"):
        self.title = title
        self.fixture = fixture
        self.steps: list[Step] = []

    def run(
        self,
        body: str,
        *,
        code: int | str = 0,
        prints: tuple[str, ...] = (),
        absent: tuple[str, ...] = (),
    ) -> None:
        """Add a block that must end with exit code ``code`` and print each ``prints``."""
        self.steps.append(Step(body.strip("\n"), str(code), prints, absent))

    def page_text(self) -> str:
        parts = [f"# Twin of {self.title}\n"]
        for step in self.steps:
            parts.append(
                f"<!-- doctest: run fixture={self.fixture} "
                f"expect-exit={step.exit} timeout={SCAN_TIMEOUT_S} -->\n"
                f"{FENCE}bash\n{step.body}\n{FENCE}\n"
            )
        return "\n".join(parts)

    def execute(self, tmp_path: Path, root: Path) -> Path:
        """Run the twin and return its session's directory.

        Fails, with the runner's report, when a block ends with another code than the
        one it was given, or does not print what it must.
        """
        twin_path = tmp_path / "twin.md"
        twin_path.write_text(self.page_text(), encoding="utf-8")
        twin = checks.parse_page(twin_path, tmp_path)
        scratch = tmp_path / "sessions"
        scratch.mkdir()
        results = runner.PageRunner(twin, scratch, docs_root=root).run()
        assert len(results) == len(self.steps), runner.failure_report(results)
        problems = []
        for result, step in zip(results, self.steps):
            if not result.ok:
                continue
            problems.extend(
                f"{result.page}:{result.line}: {result.command!r} did not print "
                f"{text!r}; its output ends:\n{result.output[-1500:]}"
                for text in step.prints
                if text not in result.output
            )
            problems.extend(
                f"{result.page}:{result.line}: {result.command!r} printed {text!r}, "
                f"which it must not; its output ends:\n{result.output[-1500:]}"
                for text in step.absent
                if text in result.output
            )
        if problems or not all(r.ok for r in results):
            pytest.fail(
                "\n\n".join([runner.failure_report(results), *problems]),
                pytrace=False,
            )
        sessions = sorted(scratch.glob("session-*"))
        assert len(sessions) == 1, f"the twin ran in {len(sessions)} sessions"
        return sessions[0]


def captured(session: Path, name: str) -> Path:
    """A file a twin block copied into ``$HOME/captures``."""
    path = session / "home" / "captures" / name
    assert path.is_file(), f"the twin captured no {name}"
    return path


def capture_scan(name: str) -> str:
    """A shell block that keeps the last scan's findings and aggregated results."""
    return (
        f'mkdir -p "$HOME/captures/{name}"\n'
        f'cp .ash/ash_output/reports/ash.flat.json "$HOME/captures/{name}/"\n'
        f'cp .ash/ash_output/ash_aggregated_results.json "$HOME/captures/{name}/"'
    )


def findings(session: Path, name: str) -> list[dict]:
    """The findings of the scan captured under ``name`` (ash.flat.json's ``findings``)."""
    import json

    flat = captured(session, f"{name}/ash.flat.json")
    return json.loads(flat.read_text(encoding="utf-8"))["findings"]
