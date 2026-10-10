# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every runnable block in the docs runs, and exits the way its marker says.

One test per page that has a runnable block: an unmarked or ``run`` shell block in
bash, sh, shell or console, or an unmarked or ``run`` python block. The page's blocks
run in order in one session (see docs_runner.py). A failure names every failing block
with its line, the command, the exit code it got and the one it expected, and the end
of its output.

The pages are the docs corpus of scripts/verify_docs_freshness.py, so a page the
static checks see is a page this runs. ``.md.template`` files are left to the page
they render, which has the same blocks with the version filled in.

Here rather than in the unit suite because the examples run real commands, ``ash``
among them, and that belongs in the Linux integration-test job, not on every unit leg.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]


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
gate = _load(
    "_ash_docs_gate_for_runner", REPO_ROOT / "scripts" / "verify_docs_freshness.py"
)
checks = runner.load_docs_checks()


def _pages_with_examples():
    pages = []
    for path in gate.collect_md_files():
        if path.suffix != ".md":
            continue
        page = checks.parse_page(path, REPO_ROOT)
        if runner.runnable_blocks(page):
            pages.append(page)
    return pages


PAGES = _pages_with_examples()


def test_the_docs_have_runnable_examples():
    """No pages would mean no parametrized tests below, which passes by running nothing."""
    assert PAGES, (
        "no docs page has a runnable block; the parser or the corpus is broken"
    )


@pytest.mark.parametrize("page", PAGES, ids=[page.rel for page in PAGES])
def test_doc_examples_run(page, tmp_path):
    results = runner.PageRunner(page, tmp_path).run()
    assert results, f"{page.rel} was selected for a runnable block but none ran"
    if not all(result.ok for result in results):
        pytest.fail(runner.failure_report(results), pytrace=False)
