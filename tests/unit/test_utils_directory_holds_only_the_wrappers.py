# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``utils/`` holds the two host wrappers and nothing else.

The ASH v2 in-container scanner scripts (``common.sh`` and the four
``*-docker-execute.sh`` files) were removed because nothing ran them: the v3 image
copies none of them and the scanners they drove are plugins under
``automated_security_helper/plugin_modules/ash_builtin/``. This test keeps them from
coming back by accident, and keeps the live code, the docs and the workflows from
naming them as something to run.

Recorded v2 output (``tests/test_data`` and ``tests/fixtures``) and the CHANGELOG
mention the old names as history; those are not callers and are not read here.

What the scan covers: every text file of the repository, whatever its name (an
extensionless Dockerfile or Makefile included), for a removed script's file name as a
whole name, so a path built with a variable in front (``"$UTILS_DIR"/common.sh``)
counts. What it cannot see: a name assembled at run time from pieces
(``"common" + ".sh"``), which no text scan can.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.utils.helpers import iter_repo_files

pytestmark = pytest.mark.unit

# iter_repo_files already prunes the per-run scratch tree; these are the trees that
# are not the repository's own files.
SKIP_DIRS = frozenset(
    {".git", ".venv", "node_modules", "__pycache__", ".ruff_cache", ".mypy_cache"}
)
REPO_ROOT = Path(__file__).resolve().parents[2]
UTILS = REPO_ROOT / "utils"

WRAPPERS = {"ash_helpers.sh", "ash_helpers.ps1"}
#: The removed scripts by file name. A name is matched as a whole file name wherever
#: it sits, so ``utils/common.sh``, ``"$UTILS_DIR"/common.sh`` and ``./common.sh`` all
#: count (the spelling the deleted scripts used for each other was the variable form),
#: while ``uncommon.sh`` and ``common.shell`` do not.
REMOVED_NAMES = (
    "common.sh",
    "git-docker-execute.sh",
    "grype-docker-execute.sh",
    "js-docker-execute.sh",
    "yaml-docker-execute.sh",
)
_REMOVED = re.compile(
    r"(?<![\w.-])(" + "|".join(re.escape(n) for n in REMOVED_NAMES) + r")(?![\w.-])"
)
# Places where the old names legitimately survive as history or recorded data.
HISTORY = ("CHANGELOG.md", ".github/release-notes", "tests/test_data", "tests/fixtures")
THIS_FILE = Path(__file__).resolve()
#: A file past this size is data, not a script or a doc that names a script.
MAX_READ_BYTES = 2_000_000


def _text_of(path: Path) -> str | None:
    """The file's text, or None for a binary, an oversize file or an unreadable one.

    Every file is read whatever its name: an extensionless Dockerfile or Makefile that
    copied a removed script is exactly what a suffix list would have skipped."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) > MAX_READ_BYTES or b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def _names_a_removed_script(text: str) -> list[str]:
    return sorted({match.group(1) for match in _REMOVED.finditer(text)})


def _offenders(root: Path, this_file: Path | None = None) -> list[str]:
    offenders = []
    for path in iter_repo_files(root, skip_dirs=SKIP_DIRS):
        rel = path.relative_to(root).as_posix()
        if (this_file and path.resolve() == this_file) or rel.startswith(HISTORY):
            continue
        text = _text_of(path)
        if text is None:
            continue
        offenders += [f"{rel}: {name}" for name in _names_a_removed_script(text)]
    return offenders


def test_utils_holds_only_the_two_wrappers():
    present = {p.name for p in UTILS.iterdir() if p.is_file()}
    assert present == WRAPPERS, (
        "utils/ must hold only the two host wrappers; unexpected: "
        f"{sorted(present - WRAPPERS)}, missing: {sorted(WRAPPERS - present)}"
    )
    assert not [p for p in UTILS.iterdir() if p.is_dir()]


def test_nothing_live_names_the_removed_scripts():
    offenders = _offenders(REPO_ROOT, THIS_FILE)
    assert not offenders, "\n".join(offenders)


@pytest.mark.parametrize(
    "line",
    [
        "COPY utils/git-docker-execute.sh /ash/",
        'source "$UTILS_DIR"/common.sh',
        "bash ./common.sh",
        "run: utils/js-docker-execute.sh",
    ],
)
def test_the_scan_flags_each_spelling_of_a_removed_script(line):
    assert _names_a_removed_script(line), line


@pytest.mark.parametrize(
    "line", ["uncommon.sh", "common.shell", "my-common.sh", "ash_helpers.sh"]
)
def test_the_scan_leaves_other_names_alone(line):
    assert not _names_a_removed_script(line), line


def test_the_scan_reads_a_file_with_no_extension(tmp_path):
    # The control the live scan's blind spot needed: an extensionless Dockerfile that
    # copies a removed script is found, a clean one is not, and a binary is skipped.
    (tmp_path / "Dockerfile").write_text("COPY utils/common.sh /x\n", encoding="utf-8")
    (tmp_path / "Makefile").write_text("all:\n\ttrue\n", encoding="utf-8")
    (tmp_path / "blob").write_bytes(b"\0common.sh")

    assert _offenders(tmp_path) == ["Dockerfile: common.sh"]
