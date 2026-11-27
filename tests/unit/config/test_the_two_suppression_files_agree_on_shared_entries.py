# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An entry both suppression files carry says the same thing in each.

Why this exists
---------------
``.ash.yaml`` and ``.ash/.ash_alpha_plugins.yaml`` are read by different scans, and a
suppression list is not inherited from one to the other, so entries that guard the same
finding are written in both ("kept in step", say the comments). Nothing held them in
step: an expiry moved in one file left the other file's entry to lapse, or to outlive
the decision, and a line range, version or install path edited in one read as a
different entry in the other.

What this checks
----------------
An entry is shared when both files hold one with the same rule id, path, symbol,
resource id and package name. Those say what the entry is about. The rest says what it
decides, and every shared entry carries the same of it in both files: the expiry (only
``expires`` is read: ASH 4.0 removed the ``expiration`` spelling), the line range, the package path and
the package version. A line range or install path edited in one file is therefore a
disagreement, not a reason to stop comparing the pair. Which entries are shared is
read from the files, so no count of them is written down here. The GuardDog pins have
their own comparison in ``test_ci_guarddog_self_scan_pins.py``, which also covers an
entry only one file holds.
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
        entry.get("symbol"),
        entry.get("resource_id"),
        entry.get("package_name"),
    )


def _expiry(entry: Dict[str, Any]) -> Any:
    value = entry.get("expires")
    return str(value) if value is not None else None


def _claims(entry: Dict[str, Any]) -> Tuple[Any, ...]:
    return (
        _expiry(entry),
        entry.get("line_start"),
        entry.get("line_end"),
        entry.get("package_path"),
        entry.get("package_version"),
    )


def _by_key(entries: List[Dict[str, Any]]) -> Dict[Key, List[Tuple[Any, ...]]]:
    grouped: Dict[Key, List[Tuple[Any, ...]]] = {}
    for entry in entries:
        grouped.setdefault(_key(entry), []).append(_claims(entry))
    return {key: sorted(claims, key=str) for key, claims in grouped.items()}


def _disagreements(
    default: List[Dict[str, Any]], alpha: List[Dict[str, Any]]
) -> Dict[Key, Tuple[List[Tuple[Any, ...]], List[Tuple[Any, ...]]]]:
    """Each shared key whose claims differ, with the claims each file makes."""
    in_default, in_alpha = _by_key(default), _by_key(alpha)
    return {
        key: (in_default[key], in_alpha[key])
        for key in sorted(set(in_default) & set(in_alpha), key=str)
        if in_default[key] != in_alpha[key]
    }


def _shared() -> List[Key]:
    default, alpha = _by_key(_entries(DEFAULT)), _by_key(_entries(ALPHA))
    return sorted(set(default) & set(alpha), key=str)


def test_the_two_files_share_entries() -> None:
    assert _shared(), "no entry is shared, so the comparison below checks nothing"


@pytest.mark.parametrize("key", _shared(), ids=lambda k: f"{k[0]}-{k[1]}-{k[2] or ''}")
def test_a_shared_entry_has_the_same_claims_in_both_files(key: Key) -> None:
    default, alpha = _by_key(_entries(DEFAULT)), _by_key(_entries(ALPHA))
    assert default[key] == alpha[key], (
        f"{key}: .ash.yaml reads (expires, line_start, line_end, package_path, "
        f"package_version) {default[key]}, .ash_alpha_plugins.yaml reads "
        f"{alpha[key]}; the entry must say the same thing in both"
    )


# Controls: the comparison, fed entries whose answer is known.

_BASE = {"rule_id": "X", "path": "a", "line_start": 1, "line_end": 1}


@pytest.mark.parametrize(
    "field,left,right",
    [
        ("expires", "2027-01-01", "2027-02-01"),
        ("line_start", 1, 2),
        ("line_end", 1, 2),
        ("package_path", "deploy/a", "deploy/b"),
        ("package_version", "1.0.0", "1.0.1"),
    ],
)
def test_the_comparison_sees_a_difference_in_each_claim(
    field: str, left: Any, right: Any
) -> None:
    default = [{**_BASE, field: left}]
    alpha = [{**_BASE, field: right}]
    assert list(_disagreements(default, alpha)) == [_key(_BASE)]


def test_the_comparison_does_not_read_the_removed_expiration_spelling() -> None:
    """ASH 4.0 removed the ``expiration`` spelling, so an entry that still
    carries it has no expiry here, and the other file's ``expires`` differs."""
    default = [{**_BASE, "expires": "2027-01-01"}]
    alpha = [{**_BASE, "expiration": "2027-01-01"}]
    assert list(_disagreements(default, alpha)) == [_key(_BASE)]


def test_the_comparison_passes_entries_that_say_the_same_thing() -> None:
    entry = {**_BASE, "expires": "2027-01-01", "package_name": "p"}
    assert _disagreements([entry], [dict(entry)]) == {}


@pytest.mark.parametrize(
    "field,left,right",
    [
        ("symbol", "f", "g"),
        ("resource_id", "R1", "R2"),
        ("package_name", "p", "q"),
        ("path", "a", "b"),
        ("rule_id", "X", "Y"),
    ],
)
def test_entries_about_different_things_are_not_compared(
    field: str, left: Any, right: Any
) -> None:
    default = [{**_BASE, field: left, "expires": "2027-01-01"}]
    alpha = [{**_BASE, field: right, "expires": "2027-02-01"}]
    assert _disagreements(default, alpha) == {}
