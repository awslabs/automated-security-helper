# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The self-scan runs GuardDog with no hit limit, and every GuardDog pin is one line.

Why this exists
---------------
GuardDog stops a rule after 1, 3 or 5 hits per package root unless
``scanners.guarddog.options.max_hits`` says otherwise. With the default, the
repository's own self-scan (``.ash/.ash_community_plugins.yaml``) stopped
threat-filesystem-read at its 5th hit, so matches past it were never reported or
reviewed. The self-scan sets ``max_hits: 0`` so every hit is visible, and each hit
it reports that is a test or fixture doing what the rule describes is suppressed
on its own line.

What this checks
----------------
* The self-scan config sets ``max_hits: 0`` for GuardDog.
* Every GuardDog suppression (``threat-*`` and ``capability-*`` rule ids) in either
  ``.ash`` config names one rule, one file and one line, so a new hit anywhere
  else, even in the same file, is still reported.
* Both configs carry the same GuardDog suppressions, as their comments say: the
  self-scan reads only the community config, and ``.ash/.ash.yaml`` keeps the
  same entries for a scan that lists the GuardDog module there.
"""

from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SELF_SCAN = REPO_ROOT / ".ash" / ".ash_community_plugins.yaml"
DEFAULT = REPO_ROOT / ".ash" / ".ash.yaml"
GLOB_CHARACTERS = set("*?[")


def _load(path: Path) -> Dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _guarddog_pins(path: Path) -> List[Dict[str, Any]]:
    entries = (_load(path).get("global_settings") or {}).get("suppressions") or []
    return [
        entry
        for entry in entries
        if str(entry.get("rule_id") or "").startswith(("threat-", "capability-"))
    ]


def _key(entry: Dict[str, Any]) -> Tuple[Any, ...]:
    return (
        entry["rule_id"],
        entry["path"],
        entry.get("line_start"),
        entry.get("line_end"),
    )


def test_the_self_scan_reports_every_guarddog_hit() -> None:
    guarddog = (_load(SELF_SCAN).get("scanners") or {}).get("guarddog") or {}
    assert (guarddog.get("options") or {}).get("max_hits") == 0


@pytest.mark.parametrize("config", [SELF_SCAN, DEFAULT], ids=lambda p: p.name)
def test_every_guarddog_suppression_is_one_rule_one_file_one_line(
    config: Path,
) -> None:
    pins = _guarddog_pins(config)
    assert pins, f"{config.name} has no GuardDog suppressions to check"
    for entry in pins:
        where = f"{config.name}: {entry}"
        assert not GLOB_CHARACTERS & set(entry["rule_id"]), where
        assert not GLOB_CHARACTERS & set(entry.get("path") or "*"), where
        assert isinstance(entry.get("line_start"), int), where
        assert entry.get("line_end") == entry["line_start"], where
        assert str(entry.get("reason") or "").strip(), where


def test_both_configs_carry_the_same_guarddog_suppressions() -> None:
    self_scan = sorted(_key(e) for e in _guarddog_pins(SELF_SCAN))
    default = sorted(_key(e) for e in _guarddog_pins(DEFAULT))
    assert self_scan == default
    assert len(set(self_scan)) == len(self_scan), "a GuardDog pin is listed twice"
