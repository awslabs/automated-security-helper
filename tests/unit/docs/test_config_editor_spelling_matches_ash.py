# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The configuration editor's plugin-section spelling vectors are ASH's own answers.

ASH reads any spelling of a declared plugin's section as that plugin's section: case and
the ``-``/``_`` separators are dropped, and one trailing Converter, Scanner or Reporter
word is ignored (automated_security_helper/config/plugin_section_names.py). The editor
folds a key the same way in the browser, so its port has to give the answer ASH gives
for every key.

docs/editor-tests/fixtures/spelling-vectors.json holds the keys and the expected
answers. This file runs ASH's own functions on them, with the declared section names
replaced by the lists in the same file, and requires every expected answer to be what
ASH gives. That includes the merges: a mapping with a variant spelling in it, and the
mapping ASH reads once the variant is merged into the declared section key by key. The
node test requires the port to give the same answers.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.config import plugin_section_names as names

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parents[3] / "docs" / "editor-tests" / "fixtures"
VECTORS = json.loads((FIXTURES / "spelling-vectors.json").read_text(encoding="utf-8"))
BLOCK = json.loads((FIXTURES / "editor-data.json").read_text(encoding="utf-8"))
CANONICAL = VECTORS["canonical"]
TARGETS = VECTORS["targets"]
SECTIONS = VECTORS["sections"]
MERGES = VECTORS["merges"]


def _declared_by_fold(kind: str) -> dict[str, str]:
    """The declared names of one kind by folded form, as ASH builds the mapping."""
    return {names.folded_section_name(name): name for name in CANONICAL[kind]}


@pytest.mark.parametrize(
    ("kind", "text", "expected"),
    TARGETS,
    ids=[f"{kind}-{text}" for kind, text, _ in TARGETS],
)
def test_a_key_names_the_declared_section_ash_names_or_none(kind, text, expected):
    assert names.declared_target(_declared_by_fold(kind), text) == expected


@pytest.mark.parametrize(
    "case",
    SECTIONS,
    ids=[f"{case['kind']}-{'-'.join(case['keys'])}" for case in SECTIONS],
)
def test_a_mapping_folds_to_the_declared_spellings_or_is_refused(case, monkeypatch):
    kind = case["kind"]
    monkeypatch.setattr(names, "declared_section_names", _declared_by_fold)
    data = {kind: {key: {"written": key} for key in case["keys"]}}
    expected = case["ambiguous"]
    if expected is None:
        folded = names.fold_known_plugin_sections(data)
        assert sorted(folded[kind]) == case["folded"]
    else:
        with pytest.raises(names.AmbiguousPluginSpellings) as refused:
            names.fold_known_plugin_sections(data)
        assert refused.value.segment_key == kind
        assert refused.value.first == expected["first"]
        assert refused.value.second == expected["second"]
        assert refused.value.target == expected["target"]


@pytest.mark.parametrize(
    "case",
    MERGES,
    ids=[f"{case['kind']}-{index}" for index, case in enumerate(MERGES)],
)
def test_a_variant_section_is_merged_into_the_declared_one_as_ash_merges_it(
    case, monkeypatch
):
    monkeypatch.setattr(names, "declared_section_names", _declared_by_fold)
    data = {case["kind"]: case["section"]}
    folded = names.fold_known_plugin_sections(data)
    assert folded[case["kind"]] == case["folded"]


def test_the_vectors_only_use_the_plugin_sections_of_ash():
    kinds = set(CANONICAL)
    assert kinds <= set(names.PLUGIN_SEGMENT_KEYS)
    assert {kind for kind, _, _ in TARGETS} <= kinds
    assert {case["kind"] for case in SECTIONS} <= kinds
    assert {case["kind"] for case in MERGES} <= kinds


def test_each_mapping_case_names_either_a_result_or_a_refusal():
    for case in SECTIONS:
        assert (case["folded"] is None) != (case["ambiguous"] is None), case["keys"]


def test_the_vectors_hold_a_match_a_miss_a_fold_and_a_refusal():
    assert any(expected is not None for _, _, expected in TARGETS)
    assert any(expected is None for _, _, expected in TARGETS)
    assert any(case["folded"] is not None for case in SECTIONS)
    assert any(case["ambiguous"] is not None for case in SECTIONS)


@pytest.mark.parametrize("kind", sorted(CANONICAL))
def test_the_declared_names_in_the_vectors_are_declared_by_ash(kind):
    declared = set(names.declared_section_names(kind).values())
    assert set(CANONICAL[kind]) <= declared


@pytest.mark.parametrize("kind", sorted(BLOCK["spelling"]["canonical"]))
def test_the_declared_names_in_the_data_block_are_declared_by_ash(kind):
    declared = set(names.declared_section_names(kind).values())
    assert set(BLOCK["spelling"]["canonical"][kind]) <= declared


def test_the_vectors_in_the_data_block_hold_under_ash():
    canonical = BLOCK["spelling"]["canonical"]
    assert BLOCK["spelling"]["vectors"], "the block holds no vector"
    for kind, text, expected in BLOCK["spelling"]["vectors"]:
        by_fold = {names.folded_section_name(name): name for name in canonical[kind]}
        assert names.declared_target(by_fold, text) == expected, (kind, text)
