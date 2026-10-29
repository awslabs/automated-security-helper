# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""NoRecursiveAliasLoader refuses a document whose aliases expand past the bound.

The loader refused only a cyclic alias. A few hundred bytes of nested anchors,
each level aliasing the level below several times, loaded as a small shared
graph whose every later walk wrote out a tree exponential in the depth. The
loader now counts the nodes the document holds once each alias is written out in
its place, and refuses at the first node past MAX_EXPANDED_NODES, as a composer
error, so every caller refuses the file as one that does not parse.
"""

from __future__ import annotations

import pytest
import yaml
from yaml.composer import ComposerError

from automated_security_helper.utils.yaml_aliases import (
    MAX_EXPANDED_NODES,
    AliasExpansionError,
    NoRecursiveAliasLoader,
    RecursiveAliasError,
)

pytestmark = pytest.mark.unit


def _nested_aliases(levels: int, width: int) -> str:
    """A leaf mapping, then ``levels`` mappings each aliasing the one below
    ``width`` times: about ``width ** levels`` nodes once written out."""
    lines = ["a0: &a0 {leaf: 1}"]
    for level in range(1, levels + 1):
        refs = ", ".join(f"k{j}: *a{level - 1}" for j in range(width))
        lines.append(f"a{level}: &a{level} {{{refs}}}")
    return "\n".join(lines) + "\n"


def test_a_document_past_the_bound_is_refused_while_composing():
    text = _nested_aliases(levels=7, width=9)
    assert len(text) < 1000

    with pytest.raises(AliasExpansionError) as refused:
        yaml.load(text, Loader=NoRecursiveAliasLoader)
    assert isinstance(refused.value, ComposerError)
    assert str(MAX_EXPANDED_NODES) in str(refused.value)
    assert refused.value.problem_mark is not None


def test_a_shared_alias_under_the_bound_still_loads():
    text = _nested_aliases(levels=3, width=3) + "b: [*a3, *a3]\n"

    loaded = yaml.load(text, Loader=NoRecursiveAliasLoader)
    assert loaded["b"][0] is loaded["a3"]
    assert loaded["a3"]["k0"]["k0"]["k0"] == {"leaf": 1}


def test_a_cyclic_alias_is_still_refused_by_name():
    with pytest.raises(RecursiveAliasError):
        yaml.load("a: &a [*a]\n", Loader=NoRecursiveAliasLoader)


def test_a_plain_document_of_ordinary_size_still_loads():
    text = "items:\n" + "".join(f"  - {n}\n" for n in range(2000))

    loaded = yaml.load(text, Loader=NoRecursiveAliasLoader)
    assert len(loaded["items"]) == 2000
