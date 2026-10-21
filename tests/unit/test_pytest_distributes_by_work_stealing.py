# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""pytest.ini distributes tests across xdist workers by work stealing.

Why this file exists
--------------------
``-n auto`` with xdist's default ``--dist load`` hands each worker a fixed share of
the tests up front, so a worker that drew the slow tests (container snapshots, real
scans) runs alone at the end while the rest sit idle. ``--dist worksteal`` lets an
idle worker take queued tests from a busy one. It ignores xdist grouping
(``loadscope``, ``loadfile``, ``loadgroup``, ``xdist_group``), which is safe only while
no test relies on it; nothing in the suite or CI did when it was added.

What this asserts
-----------------
1. pytest.ini's addopts has ``--dist worksteal`` and still ``-n auto``: the worker
   count is left to the host, and no cap is committed (``--maxprocesses`` or a fixed
   ``-n``); a local cap belongs on the command line.
2. No test, conftest or CI invocation asks for grouping, which worksteal would
   silently ignore.
3. The pytest-xdist floor in pyproject.toml is at least 3.2, the first release with
   ``worksteal``.
"""

from __future__ import annotations

import configparser
import re
import shlex
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
THIS_FILE = Path(__file__).resolve()


def _addopts() -> list[str]:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(REPO_ROOT / "pytest.ini", encoding="utf-8")
    return shlex.split(parser["pytest"]["addopts"])


def test_addopts_steal_work_and_leave_the_worker_count_to_the_host():
    opts = _addopts()
    pairs = list(zip(opts, opts[1:]))
    assert ("--dist", "worksteal") in pairs, opts
    assert ("-n", "auto") in pairs, opts
    assert not any(o.startswith("--maxprocesses") for o in opts), opts
    assert [b for a, b in pairs if a in ("-n", "--numprocesses")] == ["auto"], opts


def test_nothing_asks_for_grouping_that_worksteal_ignores():
    # The grouping modes and the mark; plain `--dist load` groups nothing.
    grouping = re.compile(r"xdist_group|\bload(scope|file|group)\b")
    sources = [
        *sorted((REPO_ROOT / "tests").rglob("*.py")),
        *sorted((REPO_ROOT / ".github").rglob("*.yml")),
        REPO_ROOT / "pytest.ini",
        REPO_ROOT / "pyproject.toml",
    ]
    hits = [
        f"{path.relative_to(REPO_ROOT)}:{number}"
        for path in sources
        if path.resolve() != THIS_FILE
        for number, line in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
        )
        if grouping.search(line.split("#", 1)[0])
    ]
    assert not hits, (
        "these ask xdist for grouping, which --dist worksteal ignores: "
        + ", ".join(hits)
    )


def test_the_xdist_floor_has_worksteal():
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'"pytest-xdist>=(\d+)\.(\d+)', text)
    assert match, "pyproject.toml does not pin a pytest-xdist floor"
    assert (int(match.group(1)), int(match.group(2))) >= (3, 2), match.group(0)
