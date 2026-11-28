# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The configuration editor's node tests, run as one integration test.

The editor's DOM-free modules and the coverage census's ``node-test`` kind are tested
with ``node --test`` in docs/editor-tests, a package with no dependencies. The
integration tier collects this test in every operating system leg and runs it with the
node that leg has on PATH. The docs examples job sets node up with setup-node, and the
other legs use the one their runner image carries. A red node test fails the leg.

A node that is not on PATH fails this test instead of skipping it. A skip would let the
job pass with none of the editor's node tests having run. The same goes for a run that
finds no test file, and for a skipped or unfinished node test: each fails here.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
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


def _run(command: list[str], cwd: Path) -> subprocess.CompletedProcess:
    """The finished run of ``command`` in ``cwd``, with its output as text.

    The output is read as UTF-8, which is what node writes, and not with the host's
    code page: on Windows that is cp1252, which cannot read the non-ASCII test names
    and then leaves ``stdout`` as None. A byte that is not UTF-8 reads as the
    replacement character instead of failing the run.
    """
    return subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
        check=False,
    )


def test_a_report_with_non_ascii_names_and_stray_bytes_is_still_read(tmp_path):
    """A run's report is read as UTF-8 on every host, and a stray byte costs nothing.

    The stand-in prints a TAP summary, a fullwidth letter as UTF-8 (a test name in the
    spelling tests has one) and a byte that is not UTF-8. A host that decodes the run's
    output with its own code page, or that stops at the first byte it cannot decode,
    loses the whole report, and the test below then has nothing to check.
    """
    letter = "\N{FULLWIDTH LATIN SMALL LETTER A}"
    script = (
        "import sys;"
        "sys.stdout.buffer.write(b'# tests 1\\n# pass 1\\n# fail 0\\n'"
        " + '\\N{FULLWIDTH LATIN SMALL LETTER A}'.encode('utf-8') + b'\\xff\\n')"
    )
    result = _run([sys.executable, "-c", script], tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout is not None
    assert _count(result.stdout, "tests") == 1
    assert letter in result.stdout


def test_the_editor_node_tests_pass(docs_root):
    node = shutil.which("node")
    assert node, (
        "node is not on PATH, so the editor's node tests cannot run. This test fails "
        "rather than skips: a leg with no node is a broken leg, not a reason to pass "
        "without the tests."
    )
    package = docs_root / "docs" / "editor-tests"
    assert (package / "package.json").is_file(), f"{package} holds no package.json"

    result = _run([node, "--test", "--test-reporter=tap"], package)

    report = result.stdout or ""
    errors = result.stderr or ""
    tail = (
        f"\n--- stdout (tail) ---\n{report[-6000:]}"
        f"\n--- stderr (tail) ---\n{errors[-3000:]}"
    )
    assert result.returncode == 0, f"node --test exited {result.returncode}{tail}"
    assert _count(report, "tests") > 0, f"node --test ran no test{tail}"
    assert _count(report, "fail") == 0, f"a node test failed{tail}"
    assert _count(report, "cancelled") == 0, f"a node test was cancelled{tail}"
    assert _count(report, "skipped") == 0, f"a node test was skipped{tail}"
    assert _count(report, "todo") == 0, f"a node test is marked todo{tail}"
