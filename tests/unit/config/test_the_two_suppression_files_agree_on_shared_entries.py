# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An entry both suppression files carry says the same thing in each.

Why this exists
---------------
``.ash/.ash.yaml`` and ``.ash/.ash_alpha_plugins.yaml`` are read by different scans,
and a suppression list is not inherited from one to the other, so entries that guard
the same finding are written in both ("kept in step", say the comments). Nothing held
them in step: an expiry moved in one file left the other file's entry to lapse, or to
outlive the decision, and a version or install path edited in one read as a different
entry in the other.

What this checks
----------------
An entry is shared when both files hold one with the same rule id, path, line range
and package path. Every shared entry carries the same expiry, package name and package
version in both files. Which entries are shared is read from the files, so no count of
them is written down here. The GuardDog pins have their own comparison in
``test_ci_guarddog_self_scan_pins.py``, which also covers an entry only one file holds.
"""

from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT = REPO_ROOT / ".ash.yaml"
ALPHA = REPO_ROOT / ".ash" / ".ash_alpha_plugins.yaml"

Key = Tuple[Any, ...]


def _entries(path: Path) -> List[Dict[str, Any]]:
    config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return (config.get("global_settings") or {}).get("suppressions") or []


def _key(entry: Dict[str, Any]) -> Key:
    return (
        entry.get("rule_id"),
        entry.get("path"),
        entry.get("line_start"),
        entry.get("line_end"),
        entry.get("package_path"),
    )


def _claims(entry: Dict[str, Any]) -> Tuple[Any, ...]:
    return (
        str(entry["expires"]) if entry.get("expires") is not None else None,
        entry.get("package_name"),
        entry.get("package_version"),
    )


def _by_key(entries: List[Dict[str, Any]]) -> Dict[Key, List[Tuple[Any, ...]]]:
    grouped: Dict[Key, List[Tuple[Any, ...]]] = {}
    for entry in entries:
        grouped.setdefault(_key(entry), []).append(_claims(entry))
    return {key: sorted(claims, key=str) for key, claims in grouped.items()}


def _shared() -> List[Key]:
    default, alpha = _by_key(_entries(DEFAULT)), _by_key(_entries(ALPHA))
    return sorted(set(default) & set(alpha), key=str)


def test_the_two_files_share_entries() -> None:
    assert _shared(), "no entry is shared, so the comparison below checks nothing"


@pytest.mark.parametrize("key", _shared(), ids=lambda k: f"{k[0]}-{k[1]}-{k[2]}")
def test_a_shared_entry_has_the_same_expiry_and_package_in_both_files(key: Key) -> None:
    default, alpha = _by_key(_entries(DEFAULT)), _by_key(_entries(ALPHA))
    assert default[key] == alpha[key], (
        f"{key}: .ash/.ash.yaml reads (expires, package, version) {default[key]}, "
        f".ash_alpha_plugins.yaml reads {alpha[key]}; the entry must say the same "
        "thing in both"
    )


def test_the_comparison_sees_a_difference_in_expiry() -> None:
    base = {"rule_id": "X", "path": "a", "expires": "2027-01-01"}
    moved = {**base, "expires": "2027-02-01"}
    assert _by_key([base]) != _by_key([moved])
    assert _by_key([base]) == _by_key([dict(base)])
