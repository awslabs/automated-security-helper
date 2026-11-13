# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Instructions that run uv's installer must look for uv where it installs it.

uv's installer installs into ``$UV_INSTALL_DIR``, else ``$XDG_BIN_HOME``, else
``~/.local/bin``, and writes its ``env`` script there, not into ``~/.cargo``. So
``devfile.yaml`` (and DEVELOPMENT.md's copy of it) does not source ``~/.cargo/env``,
which would leave ``uv sync`` unrun, and the CI example in
docs/content/docs/uv-tool-installation-guide.md does not add ``~/.cargo/bin`` to
``GITHUB_PATH``, which would leave ``uv`` off PATH.

Every tracked text file that runs the installer is checked for a ``.cargo`` path.
"""

from __future__ import annotations

import subprocess  # nosec B404 - git ls-files lists the tracked files to check
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALLER = "astral.sh/uv/"
SUFFIXES = {".md", ".yaml", ".yml", ".template", ".sh", ".ps1", ".toml", ".txt"}


def _tracked_text_files() -> list[Path]:
    try:
        listed = subprocess.run(  # nosec B603 B607 - fixed git command
            ["git", "ls-files", "-z"],
            cwd=REPO_ROOT,
            capture_output=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout, so the tracked files cannot be listed")
    names = [name for name in listed.decode("utf-8").split("\0") if name]
    return [
        REPO_ROOT / name
        for name in names
        if Path(name).suffix in SUFFIXES and not name.startswith("tests/")
    ]


def test_no_instruction_that_installs_uv_names_a_cargo_path():
    files = _tracked_text_files()
    runners = []
    offenders = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            continue
        if INSTALLER not in text:
            continue
        runners.append(path)
        for number, line in enumerate(text.splitlines(), start=1):
            if ".cargo/env" in line or ".cargo/bin" in line:
                offenders.append(
                    f"{path.relative_to(REPO_ROOT)}:{number}: {line.strip()}"
                )
    assert runners, (
        "no tracked file runs uv's installer; the check found nothing to check"
    )
    assert offenders == [], (
        "uv's installer no longer uses ~/.cargo; look in ~/.local/bin (or pin "
        "UV_INSTALL_DIR) instead:\n" + "\n".join(offenders)
    )
