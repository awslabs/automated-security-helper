# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The blocks each runner leg runs, from the docs checks' census.

scripts/docs_checks.py's ``ci_runner_census`` decides which CI blocks of the pages run
under which runner. The runner tests make one test per census entry and nothing else,
so a block that stops running drops out of the unit suite's census test, not out of
these runs unnoticed. Each run is named by its runner, its page and its ordinal among
the page's CI blocks, the numbering the census test uses.

Loaded at collection, so it only reads files: no runner, no network, no host check.
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[4]


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def docs_checks():
    """scripts/docs_checks.py, under the name every docs test shares."""
    return _load("_ash_docs_checks", REPO_ROOT / "scripts" / "docs_checks.py")


def docs_gate():
    """scripts/verify_docs_freshness.py, for the corpus of pages."""
    return _load(
        "_ash_docs_gate_for_runner", REPO_ROOT / "scripts" / "verify_docs_freshness.py"
    )


@dataclass(frozen=True)
class CensusRun:
    """One block one runner leg runs."""

    runner: str
    page: str
    ordinal: int
    line: int
    kind: str
    event: str | None
    changed_files: bool
    composed_from: int | None

    @property
    def id(self) -> str:
        return f"{self.runner}:{self.page}#{self.ordinal}"

    @property
    def out_name(self) -> str:
        """``<page stem>-<ordinal>``: the run's directory under --ci-runner-out."""
        return f"{PurePosixPath(self.page).stem}-{self.ordinal}"


_PAGES: dict[str, Any] = {}


def _pages() -> dict[str, Any]:
    if not _PAGES:
        checks = docs_checks()
        gate = docs_gate()
        for page in checks.load_pages(gate.collect_md_files(), gate.REPO_ROOT):
            _PAGES[page.rel] = page
    return _PAGES


def page(rel: str):
    """The parsed page ``rel``."""
    return _pages()[rel]


def ci_blocks(page_obj) -> list:
    checks = docs_checks()
    return [block for block in page_obj.blocks if checks.ci_marker(block) is not None]


def block(run: CensusRun):
    """The block ``run`` runs."""
    for candidate in page(run.page).blocks:
        if candidate.fence_line == run.line:
            return candidate
    raise LookupError(f"{run.page} has no block at line {run.line}")


def census_runs() -> list[CensusRun]:
    """Every census entry, leg by leg, in the census's order."""
    checks = docs_checks()
    if not hasattr(checks, "ci_runner_census"):
        raise RuntimeError("scripts/docs_checks.py defines no ci_runner_census")
    pages = _pages()
    census = checks.ci_runner_census(list(pages.values()))
    runs = []
    for (runner, rel), entries in census.legs.items():
        lines = [b.fence_line for b in ci_blocks(pages[rel])]
        for entry in entries:
            runs.append(
                CensusRun(
                    runner=runner,
                    page=rel,
                    ordinal=lines.index(entry.line) + 1,
                    line=entry.line,
                    kind=entry.kind,
                    event=entry.event,
                    changed_files=bool(entry.changed_files),
                    composed_from=entry.composed_from,
                )
            )
    return runs


def leg_runs(runner: str, page_rel: str) -> list[CensusRun]:
    """The census entries of one leg on one page."""
    return [r for r in census_runs() if r.runner == runner and r.page == page_rel]
