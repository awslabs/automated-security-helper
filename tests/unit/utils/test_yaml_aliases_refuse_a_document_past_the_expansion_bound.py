# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""NoRecursiveAliasLoader refuses a document whose aliases expand past the bound.

The loader refused only a cyclic alias. A few hundred bytes of nested anchors,
each level aliasing the level below several times, loaded as a small shared
graph whose every later walk wrote out a tree exponential in the depth. The
loader now counts the nodes its aliases add once each is written out in its
place, and refuses at the first alias past MAX_EXPANDED_NODES, as a composer
error, so every caller refuses the file as one that does not parse. Only the
aliases' excess is counted: it used to be every node of the document, so a large
file with no alias at all was refused as one that does not parse.
"""

from __future__ import annotations

import pytest
import yaml
from yaml.composer import ComposerError

from automated_security_helper.utils import yaml_aliases
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


def _plain_items(count: int) -> str:
    """A mapping of one sequence of ``count`` scalars: ``count`` + 3 nodes."""
    return "items:\n" + "".join(f"  - {n}\n" for n in range(count))


def _aliased_items(aliases: int) -> str:
    """An anchored list of five scalars (six nodes) aliased ``aliases`` times:
    the aliases add ``6 * aliases`` nodes to the document as composed."""
    uses = ", ".join(["*base"] * aliases)
    return f"base: &base [1, 2, 3, 4, 5]\nuse: [{uses}]\n"


def test_the_bound_counts_each_document_of_a_stream_on_its_own(monkeypatch):
    """One loader composes every document of a yaml.load_all stream; the total
    used to carry over, so a stream of documents each under the bound was
    refused at the document that took the sum past it."""
    monkeypatch.setattr(yaml_aliases, "MAX_EXPANDED_NODES", 40)
    document = _aliased_items(5)  # the aliases add 30 nodes, per document

    loaded = list(
        yaml.load_all("---\n".join([document] * 3), Loader=NoRecursiveAliasLoader)
    )

    assert [len(found["use"]) for found in loaded] == [5, 5, 5]
    # The patched bound is live, and only the per-document count lets the stream
    # through: one document holding the three documents' aliases (90 nodes) is
    # refused under the same patch.
    with pytest.raises(AliasExpansionError):
        yaml.load(_aliased_items(15), Loader=NoRecursiveAliasLoader)


def test_only_what_the_aliases_add_is_counted(monkeypatch):
    """A document many times the bound in plain nodes loads when its aliases add
    little, and one whose aliases add past the bound is refused however small
    the rest of it is."""
    monkeypatch.setattr(yaml_aliases, "MAX_EXPANDED_NODES", 40)
    large = _plain_items(500) + _aliased_items(2)

    loaded = yaml.load(large, Loader=NoRecursiveAliasLoader)
    assert len(loaded["items"]) == 500
    assert loaded["use"][0] is loaded["base"]

    with pytest.raises(AliasExpansionError):
        yaml.load(_aliased_items(8), Loader=NoRecursiveAliasLoader)  # 48 added


def test_a_refusal_names_the_aliases_that_took_the_document_past_the_bound(
    monkeypatch,
):
    monkeypatch.setattr(yaml_aliases, "MAX_EXPANDED_NODES", 40)

    with pytest.raises(AliasExpansionError) as refused:
        yaml.load(_aliased_items(8), Loader=NoRecursiveAliasLoader)

    text = str(refused.value)
    assert "past 40 nodes" in text, text
    assert "each alias counted as the nodes it names" in text, text
    assert refused.value.problem_mark is not None


def test_a_large_document_with_no_alias_loads():
    """A plain file past the bound as a count of nodes: its cost is its read,
    and nothing in it is multiplied."""
    count = MAX_EXPANDED_NODES + 1
    text = "items:\n" + "".join(f"  - {n}\n" for n in range(count))

    loaded = yaml.load(text, Loader=NoRecursiveAliasLoader)

    assert len(loaded["items"]) == count
