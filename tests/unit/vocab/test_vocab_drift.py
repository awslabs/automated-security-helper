# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Runs every registered vocabulary through the two-mode drift gate.

A later enum unit registers its vocabulary in its own ``_entries_<unit>`` module
and adds the import below; it writes no gate of its own. See ``_drift_gate`` for
the modes and the planted-positive control.
"""

from __future__ import annotations

import pytest

from tests.unit.vocab import _entries_e1  # noqa: F401  (registers its entries)
from tests.unit.vocab import _entries_e12  # noqa: F401  (registers its entries)
from tests.unit.vocab._drift_gate import (
    VocabEntry,
    entries,
    forbidden_fragment_hits,
    planted_control,
    scan_collections,
    scan_constants,
    scan_entry,
)

pytestmark = pytest.mark.unit

ENTRIES = list(entries())


@pytest.mark.parametrize("entry", ENTRIES, ids=lambda e: e.name)
def test_no_stray_spelling_remains_in_the_cured_scope(entry: VocabEntry):
    hits = scan_entry(entry)
    assert not hits, "a cured vocabulary was re-spelled:\n" + "\n".join(
        f"  {h.path}:{h.line}: {h.text}" for h in hits
    )


@pytest.mark.parametrize("entry", ENTRIES, ids=lambda e: e.name)
def test_the_inventoried_copy_sites_stay_gone(entry: VocabEntry):
    assert not forbidden_fragment_hits(entry)


@pytest.mark.parametrize("entry", ENTRIES, ids=lambda e: e.name)
def test_the_derived_constants_are_derived(entry: VocabEntry):
    for what, check in entry.derivations.items():
        check()


@pytest.mark.parametrize("entry", ENTRIES, ids=lambda e: e.name)
def test_the_planted_stray_spelling_is_flagged(entry: VocabEntry, tmp_path):
    """The control: a scanner that cannot see a planted copy proves nothing."""
    assert planted_control(entry, tmp_path), (
        f"the scanner did not flag a planted spelling of {entry.name}"
    )


@pytest.mark.parametrize("entry", ENTRIES, ids=lambda e: e.name)
def test_the_forbidden_fragments_exist_in_the_scope(entry: VocabEntry):
    """A fragment naming a file outside the scope would never be read."""
    scope = set(entry.scope)
    for rel, _fragment in entry.forbidden_fragments:
        assert rel in scope, f"{rel} is pinned but not in {entry.name}'s scope"


def test_the_negative_mode_flags_a_distinctive_spelling_and_honors_the_allowlist(
    tmp_path,
):
    """No E1 vocabulary is distinctive, so the negative mode is exercised here on a
    stand-in enum: the mode every distinctive vocabulary of a later unit uses."""
    from enum import Enum

    class Tone(str, Enum):
        BELOW = "below-threshold"

    (tmp_path / "stray.py").write_text('X = "below-threshold"\n', encoding="utf-8")
    (tmp_path / "wire.py").write_text('Y = "below-threshold"\n', encoding="utf-8")
    (tmp_path / "clean.py").write_text(
        '"""below-threshold"""\nZ = 1\n', encoding="utf-8"
    )
    entry = VocabEntry(
        name="Tone",
        enum=Tone,
        scope=("stray.py", "wire.py", "clean.py"),
        allowlist={"wire.py": "asserts wire bytes"},
    )
    assert [h.path for h in scan_entry(entry, root=tmp_path)] == ["stray.py"]
    assert planted_control(entry, tmp_path / "control")


def test_an_allowlist_entry_without_a_reason_is_refused():
    from tests.unit.vocab._drift_gate import register

    entry = VocabEntry(
        name="NoReason",
        enum=ENTRIES[0].enum,
        scope=(),
        allowlist={"x.py": "  "},
    )
    with pytest.raises(ValueError):
        register(entry)


def test_a_docstring_is_prose_not_a_spelling():
    source = '"""The values are "LOW" and "HIGH"."""\nX = 1\n'
    assert scan_constants(source, "x.py", ("LOW", "HIGH")) == []
    code = 'X = "LOW"\n'
    assert len(scan_constants(code, "x.py", ("LOW", "HIGH"))) == 1


def test_a_collection_scan_flags_a_copied_ladder_and_a_rank_table():
    values = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    tuple_copy = 'T = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")\n'
    rank_copy = 'R = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2}\n'
    unrelated = 'U = ("LOW", "other")\n'
    assert scan_collections(tuple_copy, "x.py", values, 3)
    assert scan_collections(rank_copy, "x.py", values, 3)
    assert not scan_collections(unrelated, "x.py", values, 3)
