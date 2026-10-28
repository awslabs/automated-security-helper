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

To run a docs tree's examples against another tree's code, run this directory with
that tree's interpreter and name the docs tree (conftest.py adds the option):

    <code-tree>/.venv/bin/pytest <docs-tree>/tests/integration/docs \
        --run-integration --docs-root <docs-tree>
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


def docs_root_of(config) -> Path:
    """The docs tree: --docs-root (see conftest.py), or the checkout this file is in."""
    value = config.getoption("--docs-root", default=None)
    return Path(value).resolve() if value else REPO_ROOT


def pages_to_run(paths, docs_root: Path) -> list:
    """The pages with a block a session handles: one to run, or one to save.

    Templates (.md.template) are left out; the page each one renders is run instead.
    """
    pages = []
    for path in paths:
        if path.suffix != ".md":
            continue
        page = checks.parse_page(path, docs_root)
        if runner.session_blocks(page):
            pages.append(page)
    return pages


def pages_with_examples(docs_root: Path) -> list:
    if docs_root != gate.REPO_ROOT:
        gate._use_trees(docs_root)
    return pages_to_run(gate.collect_md_files(), docs_root)


def pytest_generate_tests(metafunc):
    if "page" in metafunc.fixturenames:
        pages = pages_with_examples(docs_root_of(metafunc.config))
        metafunc.parametrize("page", pages, ids=[page.rel for page in pages])


def test_the_docs_have_runnable_examples(request):
    """No pages would mean no parametrized tests below, which passes by running nothing."""
    assert pages_with_examples(docs_root_of(request.config)), (
        "no docs page has a runnable block; the parser or the corpus is broken"
    )


def test_doc_examples_run(page, tmp_path, request):
    results = runner.PageRunner(
        page, tmp_path, docs_root=docs_root_of(request.config)
    ).run()
    assert results, f"{page.rel} was selected for a block to run or save but none did"
    if not all(result.ok for result in results):
        pytest.fail(runner.failure_report(results), pytrace=False)
