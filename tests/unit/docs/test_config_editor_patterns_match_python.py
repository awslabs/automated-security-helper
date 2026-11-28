# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The configuration editor's JavaScript patterns are tested against Python's ``re``.

ASH checks a ``pattern`` of its schema with Python's ``re.search``, and the editor
checks the same value in the browser with a JavaScript regular expression. The two
dialects differ where the schema's patterns meet them: ``\\w`` is a word character in
any script in Python, ``$`` also matches before one trailing newline, and ``.`` accepts
a carriage return and a line separator. The data block therefore carries a
hand-written JavaScript translation of each pattern (``patterns`` and
``env.referencePattern``).

docs/editor-tests/fixtures/pattern-hazards.json lists, per pattern, sample texts and
whether Python's ``re.search`` finds the pattern in each. This file checks the Python
half: every sample's answer is what Python gives, every pattern of the schema is
covered and has a translation, and the samples are able to tell a careless translation
from a faithful one. The node test checks the translation against the same samples.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parents[3] / "docs" / "editor-tests" / "fixtures"
BLOCK = json.loads((FIXTURES / "editor-data.json").read_text(encoding="utf-8"))
HAZARDS = json.loads((FIXTURES / "pattern-hazards.json").read_text(encoding="utf-8"))
GROUPS = HAZARDS["groups"]
GROUP_IDS = [group["pattern"] for group in GROUPS]


def _dollar_matches_only_at_the_very_end(pattern: str) -> str:
    """The closing ``$`` anchor as a careless translation reads it: end of text only."""
    return re.sub(r"\$$", r"\\Z", pattern)


def _word_characters_are_ascii(pattern: str) -> str:
    """``\\w`` as a careless translation writes it, bare and inside a class."""
    return pattern.replace(r"[\w-]", "[a-zA-Z0-9_-]").replace(r"\w", "[a-zA-Z0-9_]")


def _dot_stops_at_line_breaks(pattern: str) -> str:
    """``.`` as JavaScript reads it: it refuses a carriage return and the separators."""
    return pattern.replace(".*", "[^\\n\\r\N{LINE SEPARATOR}\N{PARAGRAPH SEPARATOR}]*")


#: A careless translation of one construct, as a rewrite of the Python source. Each
#: changes what a pattern accepts, and the samples have to notice.
CARELESS = {
    "dollar matches only at the very end": _dollar_matches_only_at_the_very_end,
    "word characters are ASCII": _word_characters_are_ascii,
    "dot stops at line breaks": _dot_stops_at_line_breaks,
}


def _schema_patterns(node) -> set[str]:
    """Every ``pattern`` value anywhere in a schema."""
    found: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "pattern" and isinstance(value, str):
                found.add(value)
            else:
                found |= _schema_patterns(value)
    elif isinstance(node, list):
        for item in node:
            found |= _schema_patterns(item)
    return found


def _answers(pattern: str, group: dict) -> list[bool]:
    compiled = re.compile(pattern)
    return [compiled.search(sample["text"]) is not None for sample in group["samples"]]


@pytest.mark.parametrize("group", GROUPS, ids=GROUP_IDS)
def test_python_gives_the_answer_the_fixture_expects_for_every_sample(group):
    expected = [sample["match"] for sample in group["samples"]]
    assert _answers(group["pattern"], group) == expected


@pytest.mark.parametrize("group", GROUPS, ids=GROUP_IDS)
def test_each_group_has_samples_that_match_and_samples_that_do_not(group):
    answers = {sample["match"] for sample in group["samples"]}
    assert answers == {True, False}


@pytest.mark.parametrize("group", GROUPS, ids=GROUP_IDS)
def test_each_group_names_a_translation_in_the_block(group):
    if group["source"] == "patterns":
        translation = BLOCK["patterns"][group["pattern"]]
    else:
        assert group["source"] == "env.referencePattern"
        translation = BLOCK["env"]["referencePattern"]
    assert translation["python"] == group["pattern"]
    assert translation["js"]
    assert re.fullmatch("[dgimsuy]*", translation["flags"])


def test_every_pattern_of_the_schema_has_a_translation_and_a_group():
    used = _schema_patterns(BLOCK["validationSchema"])
    assert used, "the schema holds no pattern, so the check proves nothing"
    # The block's patterns map is exactly the schema's patterns.
    assert used == set(BLOCK["patterns"])
    missing = used - set(GROUP_IDS)
    assert not missing, f"no hazard group for {sorted(missing)}"
    assert BLOCK["env"]["referencePattern"]["python"] in GROUP_IDS


@pytest.mark.parametrize("name", sorted(CARELESS))
def test_the_samples_tell_a_careless_translation_from_the_pattern(name):
    """Rewrite each pattern the careless way. For every pattern the rewrite changes,
    at least one sample must answer differently, or the fixture could not catch that
    mistake. A rewrite that changes no pattern at all is a mistake in this test."""
    changed = 0
    for group in GROUPS:
        careless = CARELESS[name](group["pattern"])
        if careless == group["pattern"]:
            continue
        changed += 1
        expected = [sample["match"] for sample in group["samples"]]
        assert _answers(careless, group) != expected, group["pattern"]
    assert changed, f"the rewrite {name!r} changes none of the patterns"
