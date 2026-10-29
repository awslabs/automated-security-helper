# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Where Invoke-ASH's runner fallback is described, it is described in the code's order.

Invoke-ASH tries finch first, as ./ash and the CLI do, so its help text and the
CHANGELOG's entry for the fallback list finch first too. This reads the order from utils/ash_helpers.ps1 and compares the help text
and the CHANGELOG entry to it, without running PowerShell.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS = REPO_ROOT / "utils" / "ash_helpers.ps1"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
RUNNERS = ("finch", "docker", "nerdctl", "podman")


def _code_order() -> list[str]:
    text = HELPERS.read_text(encoding="utf-8")
    match = re.search(r"else \{\s*@\(((?:'[a-z]+',?\s*){4})\)", text)
    assert match, "the discovery list was not found in utils/ash_helpers.ps1"
    return re.findall(r"'([a-z]+)'", match.group(1))


def _named_order(passage: str) -> list[str]:
    return [name for name in re.findall(r"`([a-z]+)`", passage) if name in RUNNERS]


def test_the_code_tries_finch_first_like_ash_and_the_cli():
    assert _code_order() == list(RUNNERS)


def test_the_help_lists_the_code_order():
    text = HELPERS.read_text(encoding="utf-8")
    line = next(line for line in text.splitlines() if "otherwise the first of" in line)
    assert _named_order(line) == _code_order(), line


def test_the_changelog_entry_lists_the_code_order():
    text = CHANGELOG.read_text(encoding="utf-8")
    start = text.index("**The PowerShell `Invoke-ASH` finds an OCI runner")
    entry = text[start : text.index("\n\n", start)]
    assert _named_order(entry) == _code_order(), entry
    assert "ASH_OCI_RUNNER` unset" not in entry, entry


def test_the_behavior_changes_bullet_lists_the_code_order():
    text = CHANGELOG.read_text(encoding="utf-8")
    start = text.index("  - With no runner named it tries ")
    bullet = text[start : text.index("\n  - ", start + 1)]
    # The first sentence; the next one names the order it replaced.
    order = bullet.split("order.", 1)[0]
    assert _named_order(order) == _code_order(), bullet
