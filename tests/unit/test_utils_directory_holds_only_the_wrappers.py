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
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.utils.helpers import iter_repo_files

pytestmark = pytest.mark.unit

# iter_repo_files already prunes the per-run scratch tree; these are the trees that
# are not the repository's own files.
SKIP_DIRS = frozenset({".git", ".venv", "node_modules", "__pycache__"})
REPO_ROOT = Path(__file__).resolve().parents[2]
UTILS = REPO_ROOT / "utils"

WRAPPERS = {"ash_helpers.sh", "ash_helpers.ps1"}
REMOVED_NAMES = (
    "utils/common.sh",
    "git-docker-execute.sh",
    "grype-docker-execute.sh",
    "js-docker-execute.sh",
    "yaml-docker-execute.sh",
)
# Places where the old names legitimately survive as history or recorded data.
HISTORY = ("CHANGELOG.md", ".github/release-notes", "tests/test_data", "tests/fixtures")
THIS_FILE = Path(__file__).resolve()
READ_SUFFIXES = {".py", ".sh", ".ps1", ".md", ".yml", ".yaml", ".toml", ".json", ".txt"}


def test_utils_holds_only_the_two_wrappers():
    present = {p.name for p in UTILS.iterdir() if p.is_file()}
    assert present == WRAPPERS, (
        "utils/ must hold only the two host wrappers; unexpected: "
        f"{sorted(present - WRAPPERS)}, missing: {sorted(WRAPPERS - present)}"
    )
    assert not [p for p in UTILS.iterdir() if p.is_dir()]


def test_nothing_live_names_the_removed_scripts():
    offenders = []
    for path in iter_repo_files(REPO_ROOT, skip_dirs=SKIP_DIRS):
        if path.suffix not in READ_SUFFIXES:
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        if path.resolve() == THIS_FILE or rel.startswith(HISTORY):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for name in REMOVED_NAMES:
            if name in text:
                offenders.append(f"{rel}: {name}")
    assert not offenders, "\n".join(offenders)
