# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The configuration editor's node tests, run as one integration test.

The editor's DOM-free modules and the coverage census's ``node-test`` kind are tested
with ``node --test`` in docs/editor-tests, a package with no dependencies. The docs
examples job provides node through setup-node and runs this directory, so a red node
test fails the same required check as a red docs example.

A node that is not on PATH fails this test instead of skipping it. A skip would let the
job pass with none of the editor's node tests having run. The same goes for a run that
finds no test file, and for a skipped or unfinished node test: each fails here.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def docs_root(request) -> Path:
    option = request.config.getoption("--docs-root", default=None)
    return Path(option).resolve() if option else REPO_ROOT


def _count(report: str, name: str) -> int:
    """The number on node's TAP summary line ``# <name> <n>``."""
    match = re.search(rf"^# {name} (\d+)$", report, re.MULTILINE)
    assert match, f"node's TAP summary has no '# {name}' line:\n{report[-3000:]}"
    return int(match.group(1))


def test_the_editor_node_tests_pass(docs_root):
    node = shutil.which("node")
    assert node, (
        "node is not on PATH, so the editor's node tests cannot run. This test fails "
        "rather than skips: the docs examples job installs node with setup-node, and a "
        "missing node there is a broken job, not a reason to pass without the tests."
    )
    package = docs_root / "docs" / "editor-tests"
    assert (package / "package.json").is_file(), f"{package} holds no package.json"

    result = subprocess.run(
        [node, "--test", "--test-reporter=tap"],
        cwd=package,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )

    report = result.stdout
    tail = (
        f"\n--- stdout (tail) ---\n{report[-6000:]}"
        f"\n--- stderr (tail) ---\n{result.stderr[-3000:]}"
    )
    assert result.returncode == 0, f"node --test exited {result.returncode}{tail}"
    assert _count(report, "tests") > 0, f"node --test ran no test{tail}"
    assert _count(report, "fail") == 0, f"a node test failed{tail}"
    assert _count(report, "cancelled") == 0, f"a node test was cancelled{tail}"
    assert _count(report, "skipped") == 0, f"a node test was skipped{tail}"
    assert _count(report, "todo") == 0, f"a node test is marked todo{tail}"
