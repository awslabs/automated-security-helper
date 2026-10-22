# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every ``[tool.commitizen] version_files`` entry must be one the next bump can rewrite.

Why this file exists
--------------------
``cz bump`` reads each entry as ``<path>[:<regex>]``. It expands the path as a glob,
rewrites the current version on every line the regex matches, and, with
``--check-consistency`` (which ``.github/workflows/ash-create-release.yml`` passes),
refuses the bump when a file has no matching line that holds the current version.
Two of those outcomes are failures nothing reports before release day:

* A path that matches no file is skipped without a word, so its pin stops being
  rewritten and goes stale.
* A regex that matches no line, or matching lines that no longer hold the current
  version, stops the release at the bump step.

Both follow from an ordinary edit, a file moved or a line reworded, made in a pull
request that never runs ``cz bump``. This test reads the entries the way commitizen
does and asserts all three properties on every pull request, so the edit fails here.

What it does not check
----------------------
That the list is complete. A file that pins the version and is absent from
``version_files`` is invisible to this test; tests/unit/test_agent_plugin_ash_version.py
walks the tree for install refs to cover that direction.
"""

from __future__ import annotations

import glob
import os
import re
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = REPO_ROOT / "pyproject.toml"


def _commitizen() -> dict:
    with PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)["tool"]["commitizen"]


def _split(entry: str) -> tuple[str, str]:
    """``<path>[:<regex>]``, split as commitizen's _resolve_files_and_regexes does."""
    drive, tail = os.path.splitdrive(entry)
    path, _, regex = tail.partition(":")
    return drive + path, regex


def version_file_problems(entries: list[str], version: str, root: Path) -> list[str]:
    """Why each entry would be skipped or would fail the next ``cz bump``."""
    problems: list[str] = []
    for entry in entries:
        path, regex = _split(entry)
        files = sorted(glob.glob(path, root_dir=root))
        if not files:
            problems.append(f"{entry}: no file matches {path!r}")
            continue
        pattern = re.compile(regex or re.escape(version))
        for name in files:
            lines = (root / name).read_text(encoding="utf-8").splitlines()
            matching = [line for line in lines if pattern.search(line)]
            if not matching:
                problems.append(f"{entry}: no line of {name} matches {regex!r}")
            elif not any(version in line for line in matching):
                problems.append(
                    f"{entry}: no line of {name} that matches {regex!r} holds the "
                    f"current version {version}, so --check-consistency stops the bump"
                )
    return problems


def test_the_entries_are_populated():
    """Positive control: an empty list would pass the check below on nothing."""
    config = _commitizen()
    assert config["version"]
    assert len(config["version_files"]) >= 2, config["version_files"]


def test_every_version_file_entry_resolves_and_holds_the_version():
    config = _commitizen()
    problems = version_file_problems(
        config["version_files"], config["version"], REPO_ROOT
    )
    assert not problems, (
        "[tool.commitizen] version_files has entries the next release cannot "
        "rewrite:\n" + "\n".join(f"  - {p}" for p in problems)
    )


@pytest.mark.parametrize(
    "entry,expected",
    [
        ("missing/pins.txt", "no file matches 'missing/pins.txt'"),
        ("missing/pins.txt:tag:", "no file matches 'missing/pins.txt'"),
        ("pins.txt:^nothing-here", "no line of pins.txt matches '^nothing-here'"),
        ("pins.txt:^unrelated", "holds the current version 1.2.3"),
        ("pins.txt:^tag", ""),
        ("pins.txt", ""),
    ],
    ids=[
        "missing path",
        "missing path with a regex",
        "regex matches no line",
        "matching line lost the version",
        "control with a regex",
        "control without a regex",
    ],
)
def test_each_defect_is_reported(tmp_path, entry, expected):
    (tmp_path / "pins.txt").write_text(
        'tag: "v1.2.3"\nunrelated: 0.0.1\n', encoding="utf-8"
    )
    problems = version_file_problems([entry], "1.2.3", tmp_path)
    if expected:
        assert any(expected in p for p in problems), problems
    else:
        assert problems == []
